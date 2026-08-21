//! Extra-file adoption: finding a missing slice's bytes in a file the
//! recovery set never named. Moved out of par2repair.rs bodily under the
//! size gate (TODO 106), same child-module shape as `reconstruct` - a
//! child of the defining module, so the parent's private types
//! (`Target`, `AdoptSrc`, `RollingCrc`) and `use` bindings stay in scope
//! exactly as they were inline.
//!
//! Candidates are INDEPENDENT files, so both passes fan out across them
//! (R2 / N11 - this was the last serial payload-sized pass in a file
//! where the syndrome feed, the hash verify and the patch write were all
//! parallelized already). The whole point of the parallel shape is that
//! it must not change a single adoption decision: `adopted_from`,
//! `consumed_sources` and the bytes a slice is read from are all
//! reported, so "first candidate in sorted order wins, at its first
//! matching offset" has to survive the fan-out exactly. How each pass
//! earns that is spelled out at [`sliding_scan`] and [`adopt_blocks`].

use super::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) fn md5_of_file(path: &Path, limit: Option<u64>) -> Result<[u8; 16], RepairError> {
    let mut f = File::open(path)?;
    let mut hasher = Md5::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut left = limit.unwrap_or(u64::MAX);
    while left > 0 {
        let want = buf.len().min(left.min(usize::MAX as u64) as usize);
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(hasher.finalize().into())
}

/// How many candidate files may be read at once. Both passes are a mix
/// of one sequential whole-file read and per-byte arithmetic over it
/// (MD5, or the rolling CRC32 plus MD5 on a hit), so the work is
/// CPU-shaped and the cap is really about not turning one repair into a
/// deep queue of concurrent whole-file reads on a spinning disk or a
/// network share - the same 8 the syndrome feed readers settled on.
fn adoption_workers(files: usize) -> usize {
    std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .min(8)
        .min(files)
        .max(1)
}

/// Hash the candidates named by `want` in parallel, filling the matching
/// `cache` slots. `limit` is [`md5_of_file`]'s.
///
/// Errors are DROPPED, deliberately: this is a prefetch for a decision
/// loop that is still free to hash anything it finds missing, and the
/// prefetch reads files the serial loop might never have opened. A
/// candidate that vanished between the directory walk and here must
/// therefore fail (or not) where it always did - inside the loop, on the
/// probe that actually needed it.
fn prefetch_md5s(
    cands: &[(PathBuf, u64)],
    want: &[usize],
    limit: Option<u64>,
    cache: &mut [Option<[u8; 16]>],
) {
    let want: Vec<usize> = want
        .iter()
        .copied()
        .filter(|&ci| cache[ci].is_none())
        .collect();
    if want.len() < 2 {
        if let Some(&ci) = want.first() {
            cache[ci] = md5_of_file(&cands[ci].0, limit).ok();
        }
        return;
    }
    let out: Mutex<Vec<Option<[u8; 16]>>> = Mutex::new(vec![None; want.len()]);
    let next = AtomicUsize::new(0);
    let workers = adoption_workers(want.len());
    std::thread::scope(|s| {
        for _ in 0..workers {
            let (want, out, next) = (&want, &out, &next);
            s.spawn(move || {
                loop {
                    let wi = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&ci) = want.get(wi) else { break };
                    let h = md5_of_file(&cands[ci].0, limit).ok();
                    out.lock_ok()[wi] = h;
                }
            });
        }
    });
    for (wi, h) in out
        .into_inner()
        .unwrap_or_else(|e| e.into_inner())
        .into_iter()
        .enumerate()
    {
        cache[want[wi]] = h;
    }
}

/// Locate missing blocks' content in the candidate files. Fast path
/// first: a candidate that is a missing file whole (same length + MD5,
/// prefiltered on md5_16k) adopts every slice at aligned offsets - the
/// common renamed-file case, no per-byte scan. Whatever is still missing
/// then goes through the sliding scan: roll the block-size CRC32 window
/// over each candidate (continuing with virtual zeros past end-of-file,
/// matching the spec's zero-padded tail checksums), confirm CRC hits by
/// block MD5, and record the first source found per slice.
///
/// The fast path's matching loop is UNCHANGED and still serial - it is
/// pure bookkeeping over two content-derived caches, so pre-filling
/// those caches in parallel cannot move a decision. What is prefetched
/// is chosen to be what the loop would have asked for anyway: heads for
/// every candidate whose length some unidentified target declares, and
/// whole-file MD5s for one head-matching candidate per target (the
/// greedy pairing the loop itself performs when a head match is a real
/// match, which is the case unless two candidates share a 16 KB prefix).
/// Anything the pairing guessed wrong about is simply hashed lazily by
/// the loop, exactly as before.
pub(super) fn adopt_blocks(
    dir: &Path,
    targets: &[Target],
    missing: &[usize],
    bs: usize,
    exclude: &HashSet<PathBuf>,
) -> Result<(Vec<(PathBuf, u64)>, HashMap<usize, AdoptSrc>), RepairError> {
    let cands = adoption_candidates(dir, targets, exclude)?;
    let mut adopted: HashMap<usize, AdoptSrc> = HashMap::new();
    if cands.is_empty() {
        return Ok((cands, adopted));
    }
    let missing_set: HashSet<usize> = missing.iter().copied().collect();

    let mut consumed = vec![false; cands.len()];
    // Each candidate is hashed at most once, however many targets probe
    // it (renamed multi-volume sets pair N missing files with N
    // candidates - without the cache that's N² hashing passes).
    let mut head_cache: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
    let mut md5_cache: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
    let probing: Vec<&Target> = targets
        .iter()
        .filter(|t| {
            let unidentified = !(t.exists && (t.intact || t.present.iter().any(|&p| p)));
            t.n_slices > 0 && t.file.length > 0 && unidentified
        })
        .collect();
    prefetch_heads(&cands, &probing, &mut head_cache);
    prefetch_wholes(&cands, &probing, &head_cache, &mut md5_cache);

    for t in targets {
        let unidentified = !(t.exists && (t.intact || t.present.iter().any(|&p| p)));
        if t.n_slices == 0 || t.file.length == 0 || !unidentified {
            continue;
        }
        for (ci, (p, len)) in cands.iter().enumerate() {
            if consumed[ci] || *len != t.file.length {
                continue;
            }
            let head = match head_cache[ci] {
                Some(h) => h,
                None => {
                    let h = md5_of_file(p, Some((*len).min(16384)))?;
                    head_cache[ci] = Some(h);
                    h
                }
            };
            if head != t.file.md5_16k {
                continue;
            }
            let whole = match md5_cache[ci] {
                Some(h) => h,
                None => {
                    let h = md5_of_file(p, None)?;
                    md5_cache[ci] = Some(h);
                    h
                }
            };
            if whole != t.file.md5 {
                continue;
            }
            for i in 0..t.n_slices {
                let g = t.first_slice + i;
                if missing_set.contains(&g) {
                    adopted.entry(g).or_insert(AdoptSrc {
                        cand: ci,
                        offset: i as u64 * bs as u64,
                    });
                }
            }
            consumed[ci] = true;
            break;
        }
    }

    let indices: Vec<usize> = (0..cands.len()).filter(|&ci| !consumed[ci]).collect();
    sliding_scan(&cands, &indices, targets, &missing_set, bs, &mut adopted)?;
    Ok((cands, adopted))
}

/// Prefetch: every candidate whose length some probing target declares
/// is a candidate the loop can reach, and a head is 16 KB - cheap enough
/// that hashing a few the loop skips costs less than the open latency
/// the fan-out hides.
fn prefetch_heads(
    cands: &[(PathBuf, u64)],
    probing: &[&Target],
    head_cache: &mut [Option<[u8; 16]>],
) {
    let lens: HashSet<u64> = probing.iter().map(|t| t.file.length).collect();
    let want: Vec<usize> = cands
        .iter()
        .enumerate()
        .filter(|(_, (_, len))| lens.contains(len))
        .map(|(ci, _)| ci)
        .collect();
    // The head limit is per-candidate (`min(len, 16384)`), but every
    // candidate here has a length some target declares and the target's
    // own hash16k covers `min(length, 16384)` too, so one limit serves.
    prefetch_md5s(cands, &want, Some(16384), head_cache);
}

/// Prefetch: the whole-file MD5s, which are the expensive half. Pair
/// each probing target with the first head-matching candidate no earlier
/// target has taken - the loop's own greedy walk, assuming a head match
/// holds up. At most one whole-file read per target, so the degenerate
/// "a directory of identical copies" shape stays at the serial count
/// instead of hashing every copy.
fn prefetch_wholes(
    cands: &[(PathBuf, u64)],
    probing: &[&Target],
    head_cache: &[Option<[u8; 16]>],
    md5_cache: &mut [Option<[u8; 16]>],
) {
    let mut taken = vec![false; cands.len()];
    let mut want: Vec<usize> = Vec::new();
    for t in probing {
        let hit = cands
            .iter()
            .enumerate()
            .find(|&(ci, (_, len))| {
                !taken[ci] && *len == t.file.length && head_cache[ci] == Some(t.file.md5_16k)
            })
            .map(|(ci, _)| ci);
        if let Some(ci) = hit {
            taken[ci] = true;
            want.push(ci);
        }
    }
    prefetch_md5s(cands, &want, None, md5_cache);
}

/// Sliding-scan the candidate slots named by `indices` for the content
/// of every slice in `missing_set` not already adopted. Slices without
/// IFSC data can only be found by the whole-file fast path.
///
/// One worker per candidate, each building its own adoption list, merged
/// afterwards in `indices` order. Three things keep the answer identical
/// to the serial walk it replaces:
///
/// * The merge is a first-writer-wins fold over the positions in order,
///   so the earliest candidate holding a slice's content still wins, at
///   the first offset it found it - and the fold stops the moment every
///   wanted slice is covered, which is the serial loop's own early exit.
///   A worker past that point simply has its list dropped, and its I/O
///   error with it: an error only propagates from a candidate the serial
///   walk would actually have opened.
/// * Workers publish each adoption into `best[ord]` (a monotone
///   `fetch_min` of the adopting position), so a worker at position `k`
///   can skip a CRC hit's MD5 confirmation, or stop reading altogether,
///   once every wanted slice reads `best <= k`. Monotonicity is what
///   makes that safe: a slice already held by an earlier position can
///   never come back to `k`, and one `k` holds itself was found at an
///   earlier offset than any later window.
/// * `best` is only consulted through those two skips. Nothing a worker
///   records depends on what another worker found, so the lists - and
///   therefore the merge - do not depend on the interleaving.
pub(super) fn sliding_scan(
    cands: &[(PathBuf, u64)],
    indices: &[usize],
    targets: &[Target],
    missing_set: &HashSet<usize>,
    bs: usize,
    adopted: &mut HashMap<usize, AdoptSrc>,
) -> Result<(), RepairError> {
    // Wanted slices get a dense ordinal in target-then-slice order, which
    // is the order the serial `by_crc` buckets were built in - so a CRC
    // bucket still confirms its slices in the same order, and the hot
    // loop indexes a Vec instead of hashing a slice number.
    let mut gs: Vec<usize> = Vec::new();
    let mut md5s: Vec<[u8; 16]> = Vec::new();
    let mut by_crc: HashMap<u32, Vec<usize>> = HashMap::new();
    for t in targets {
        for (i, c) in t.file.blocks.iter().enumerate() {
            let g = t.first_slice + i;
            if missing_set.contains(&g) && !adopted.contains_key(&g) {
                by_crc.entry(c.crc32).or_default().push(gs.len());
                gs.push(g);
                md5s.push(c.md5);
            }
        }
    }
    if by_crc.is_empty() {
        return Ok(());
    }
    // 65536-bit prefilter on the CRC's low 16 bits: the per-byte hot
    // path is one table probe, not a HashMap lookup.
    let mut filter = vec![0u64; 1024];
    for &crc in by_crc.keys() {
        filter[(crc & 0xFFFF) as usize >> 6] |= 1 << (crc & 63);
    }
    let roll = RollingCrc::new(bs);
    let shared = ScanShared {
        best: (0..gs.len())
            .map(|_| AtomicUsize::new(usize::MAX))
            .collect(),
        covered: AtomicUsize::new(0),
        stop_from: AtomicUsize::new(usize::MAX),
        next: AtomicUsize::new(0),
    };
    let ctx = ScanCtx {
        bs,
        roll: &roll,
        filter: &filter,
        by_crc: &by_crc,
        md5s: &md5s,
        shared: &shared,
    };
    let found: Mutex<Vec<Option<Result<Vec<(usize, u64)>, RepairError>>>> =
        Mutex::new((0..indices.len()).map(|_| None).collect());
    // Each worker holds a `bs`-byte ring; PAR2 block sizes run to
    // hundreds of MB, so cap the fan-out by that too rather than let a
    // wide machine turn one repair into gigabytes of window buffers.
    let workers = adoption_workers(indices.len()).min(((256 << 20) / bs.max(1)).max(1));
    if workers < 2 {
        run_scans(cands, indices, &ctx, &found);
    } else {
        std::thread::scope(|s| {
            for _ in 0..workers {
                let (ctx, found) = (&ctx, &found);
                s.spawn(move || run_scans(cands, indices, ctx, found));
            }
        });
    }

    let mut remaining = gs.len();
    for (pos, slot) in found
        .into_inner()
        .unwrap_or_else(|e| e.into_inner())
        .into_iter()
        .enumerate()
    {
        if remaining == 0 {
            break;
        }
        for (ord, offset) in slot.transpose()?.unwrap_or_default() {
            if let std::collections::hash_map::Entry::Vacant(v) = adopted.entry(gs[ord]) {
                v.insert(AdoptSrc {
                    cand: indices[pos],
                    offset,
                });
                remaining -= 1;
            }
        }
    }
    Ok(())
}

/// Cross-worker state for one [`sliding_scan`]. `best[ord]` is the
/// lowest position in `indices` known to hold slice `ord`'s content
/// (`usize::MAX` = nobody yet); it only ever decreases.
struct ScanShared {
    best: Vec<AtomicUsize>,
    /// How many ordinals have left `usize::MAX`, so the O(slices) sweep
    /// below only runs once everything has been found by somebody.
    covered: AtomicUsize,
    /// Lowest position that observed "every slice settled at or before
    /// me". The condition is monotone in position, so every later
    /// position inherits it without re-deriving it.
    stop_from: AtomicUsize,
    next: AtomicUsize,
}

impl ScanShared {
    /// Can a scan at `pos` still change any decision? False once every
    /// wanted slice is held by `pos` itself or by an earlier position.
    fn settled_at(&self, pos: usize) -> bool {
        if pos >= self.stop_from.load(Ordering::Relaxed) {
            return true;
        }
        if self.covered.load(Ordering::Relaxed) != self.best.len() {
            return false;
        }
        let all = self.best.iter().all(|b| b.load(Ordering::Relaxed) <= pos);
        if all {
            self.stop_from.fetch_min(pos, Ordering::Relaxed);
        }
        all
    }

    /// Record that `pos` holds `ord`'s content.
    fn claim(&self, ord: usize, pos: usize) {
        if self.best[ord].fetch_min(pos, Ordering::Relaxed) == usize::MAX {
            self.covered.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The read-only half of a [`sliding_scan`], shared by every worker.
struct ScanCtx<'a> {
    bs: usize,
    roll: &'a RollingCrc,
    filter: &'a [u64],
    by_crc: &'a HashMap<u32, Vec<usize>>,
    md5s: &'a [[u8; 16]],
    shared: &'a ScanShared,
}

/// Pull candidate positions off the shared cursor until they run out.
fn run_scans(
    cands: &[(PathBuf, u64)],
    indices: &[usize],
    ctx: &ScanCtx<'_>,
    found: &Mutex<Vec<Option<Result<Vec<(usize, u64)>, RepairError>>>>,
) {
    loop {
        let pos = ctx.shared.next.fetch_add(1, Ordering::Relaxed);
        if pos >= indices.len() {
            break;
        }
        if ctx.shared.settled_at(pos) {
            continue;
        }
        let (p, len) = &cands[indices[pos]];
        let r = scan_candidate(p, *len, ctx, pos);
        found.lock_ok()[pos] = Some(r);
    }
}

/// Slide the block-size window over one candidate file (plus `bs - 1`
/// virtual zero bytes so tail blocks match at end-of-file) and return
/// every still-wanted slice whose CRC32 and MD5 both match, as
/// `(ordinal, offset)` in the order found. `pos` is this candidate's
/// place in the scan order - see [`sliding_scan`] for what it is allowed
/// to skip on the strength of it.
fn scan_candidate(
    path: &Path,
    len: u64,
    ctx: &ScanCtx<'_>,
    pos: usize,
) -> Result<Vec<(usize, u64)>, RepairError> {
    let bs = ctx.bs;
    let mut mine: Vec<(usize, u64)> = Vec::new();
    let mut f = File::open(path)?;
    let mut ring = vec![0u8; bs];
    let mut rpos = 0usize; // ring slot of the window's oldest byte
    let mut reg = 0xFFFF_FFFFu32;
    let mut buf = vec![0u8; 1 << 18];
    let mut i: u64 = 0; // stream index: file bytes, then virtual zeros
    let total = len + bs as u64 - 1;
    'stream: while i < total {
        let n = if i < len {
            let want = buf.len().min((len - i) as usize);
            let got = f.read(&mut buf[..want])?;
            if got == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "candidate file shrank mid-scan",
                )
                .into());
            }
            got
        } else {
            let want = buf.len().min((total - i) as usize);
            buf[..want].fill(0);
            want
        };
        for &b in &buf[..n] {
            let old = ring[rpos];
            reg = if i < bs as u64 {
                ctx.roll.push(reg, b)
            } else {
                ctx.roll.roll(reg, old, b)
            };
            ring[rpos] = b;
            rpos += 1;
            if rpos == bs {
                rpos = 0;
            }
            i += 1;
            if i < bs as u64 {
                continue;
            }
            let crc = reg ^ 0xFFFF_FFFF;
            if ctx.filter[(crc & 0xFFFF) as usize >> 6] & (1 << (crc & 63)) == 0 {
                continue;
            }
            let Some(slices) = ctx.by_crc.get(&crc) else {
                continue;
            };
            if slices
                .iter()
                .all(|&o| ctx.shared.best[o].load(Ordering::Relaxed) <= pos)
            {
                continue;
            }
            let mut h = Md5::new();
            h.update(&ring[rpos..]);
            h.update(&ring[..rpos]);
            let md5: [u8; 16] = h.finalize().into();
            let offset = i - bs as u64;
            for &o in slices {
                if ctx.md5s[o] == md5 && ctx.shared.best[o].load(Ordering::Relaxed) > pos {
                    ctx.shared.claim(o, pos);
                    mine.push((o, offset));
                }
            }
        }
        // Checked per buffer refill, not per byte: the fast half is one
        // atomic load, and the O(slices) sweep behind it only runs once
        // every slice has been found by somebody.
        if ctx.shared.settled_at(pos) {
            break 'stream;
        }
    }
    Ok(mine)
}

#[cfg(test)]
mod tests;
