//! G1 of the Weaver parity tranche (TODO 358,
//! `research/PLAN-WEAVER-PARITY-2026-11-08.md` section 2): a
//! VOLUME-SIZE LADDER under a tight `--mem-limit`.
//!
//! WHY THIS EXISTS. Weaver 0.16.12 failed a real post because a fixed
//! budget sat between its downloader and its extractor: a store volume's
//! bytes cannot be placed until the chain of volumes before it is
//! linked, they waited in a holds budget nothing scaled to the post, and
//! on ~1 GB volumes fetched in parallel the budget breached in seconds
//! and the job reported success over a refused member
//! (`research/BENCH-WEAVER-01612-2026-11-07.md` section 3b). nzbfast has
//! budgets in the same place - the memory budget, spill, holds in the
//! direct store, the held-bytes cap - and until this file nothing ran
//! them against volumes bigger than the budget. Each rung posts one
//! store-mode RAR5 set of three volumes (two full, the last half full)
//! at 50 MiB, 500 MiB, 1 GiB and 4 GiB per volume, all under a 256 MiB
//! `--mem-limit`, serves it so the volumes complete OUT OF ORDER, and
//! asserts the extracted payload byte for byte and the child's peak RSS
//! against the limit plus a stated slack.
//!
//! THREE ROUTES per rung ([`Route`]), all with the NZB listing the
//! volumes LAST FIRST so they complete in reverse:
//! - `one_pass`: every header article served on demand. Weaver's shape:
//!   a volume is complete long before the volumes in front of it exist.
//!   Must stay one-pass with no volume on disk.
//! - `late_heads`: every volume but the last is posted the way a fully
//!   obfuscated poster posts it, its ladder shuffled with the offset-0
//!   article - the one carrying that volume's headers - dead LAST
//!   (`segments`). The last volume places off its own header
//!   (split-before plus the unpacked total anchor it from the end);
//!   each other volume's data arrives with nothing yet saying where it
//!   goes. On the 4 GiB rung that is a 4 GiB volume landing before a
//!   byte of it can be placed - the pile that breached Weaver's 1 GiB
//!   scratch ceiling - against a 256 MiB budget. Shipped settings; must
//!   deliver, route reported rather than asserted.
//! - `fallback`: `late_heads` with `NZBFAST_NO_HOLDS_PAGE=1`, so the
//!   relief valve is gone and the set MUST demote to materialized
//!   volumes and the disk post-pass - the route that, in Weaver, was
//!   where the job died. It must deliver exactly as well.
//!
//! WHAT `late_heads` DOES, AND WHY ITS ROUTE IS NOT ASSERTED. At 50 MiB
//! it stays one-pass (the pile fits the grace below). From 500 MiB up
//! it goes to the disk pass, every run, and that is the design rather
//! than a defect: `head_grace` in `crates/nzbkit/src/extract/holds.rs`
//! lets an unsniffed volume slot hold at most the holds slice (45% of
//! the budget, ~115 MiB here) waiting for its offset-0 article, and past
//! that `spill_unclassified_slot` flips the slot to Plain - the volume
//! materializes and the set is unpacked after download. Bounded memory,
//! correct output, one extra pass over the payload. Two of the lines it
//! prints say something else, and neither is a G1 failure but both
//! mislead a reader of the log: `held spans over the RAM cap - paging
//! to scratch, set stays one-pass` prints and then the set does NOT
//! stay one-pass; and the demote reason is `non-uniform store set`,
//! which is wrong for these sets - they are uniform, and what failed is
//! the settle-time `closed` test in `settle.rs`, because the two spilled
//! volumes never joined the group, so it holds one mapper of three.
//!
//! WHY THE MOCK GENERATES ARTICLES. The stored-map mock holds every
//! encoded body in the TEST process's RAM, so the 4 GiB rung would cost
//! ~10 GB before the client asked for anything. [`LazyArticles`] builds
//! each body per request instead, from a frame
//! ([`fixtures::rar5_store_frame`], pinned against the slice builder in
//! `rar::tests`) and a keyed counter-mode generator that is NOT
//! periodic - a misplaced article cannot land on identical bytes, which
//! the suite's `payload` (period 131,072) and benchserve's shared block
//! (period = one article) both would allow. The extracted file is
//! compared against the same generator in 8 MiB reads, so no rung ever
//! holds a payload either.
//!
//! MEASURED 9 Nov 2026 on the dev Mac (18 cores, shared, load1 19-74),
//! two runs per leg, `peak RSS` from the client's own `[mem]` line,
//! test wall = build + get + read-back as nextest reports it (the
//! per-push rungs with six legs in parallel, the heavy ones serially):
//!
//! | rung | route | went | peak RSS MB | get s | test s |
//! | --- | --- | --- | --- | --- | --- |
//! | 50 MiB | one_pass | one-pass | 40-50 | 0.4-0.5 | 0.7 |
//! | 50 MiB | late_heads | one-pass | 160 | 0.4 | 0.7 |
//! | 50 MiB | fallback | disk pass | 110-120 | 0.5-0.6 | 0.8 |
//! | 500 MiB | one_pass | one-pass | 50-70 | 1.6-1.7 | 3.4-3.5 |
//! | 500 MiB | late_heads | disk pass | 200 | 2.0-2.5 | 3.7-4.2 |
//! | 500 MiB | fallback | disk pass | 120-130 | 3.5-4.0 | 5.2-5.8 |
//! | 1 GiB | one_pass | one-pass | 60-70 | 2.9 | 6.3-7.7 |
//! | 1 GiB | late_heads | disk pass | 200-210 | 3.4-4.1 | 6.7-7.8 |
//! | 1 GiB | fallback | disk pass | 110-120 | 5.0-5.2 | 8.7 |
//! | 4 GiB | one_pass | one-pass | 90 | 10.9-13.7 | 26.5-28.8 |
//! | 4 GiB | late_heads | disk pass | 220-250 | 16.5-41.7 | 32.2-56.9 |
//! | 4 GiB | fallback | disk pass | 130-150 | 15.5-32.4 | 29.6-56.0 |
//!
//! RSS does not scale with the volume on any route: the highest peak in
//! the table is 250 MB, under the 268 MB limit itself, on a set 40x the
//! budget, and the one-pass route holds 40-90 MB from 50 MiB to 4 GiB.
//!
//! WHICH RUNGS RUN WHERE. 50 MiB and 500 MiB run per push: all six legs
//! are ~15 s of nextest wall here, the largest set is 1.25 GB, and 500
//! MiB is the first rung whose volumes are bigger than the whole budget,
//! so it is the one that makes the per-push run a G1 run at all. 1 GiB
//! and 4 GiB are `#[ignore]`d. Not for CPU - the six legs are ~2-3
//! minutes serially - but for DISK: a disk-pass leg holds the volumes
//! and the output at once, about 5 GB at 1 GiB and 20 GB at 4 GiB, on a
//! CI runner that shares its disk with every other test in the shard.
//! On demand, one leg at a time:
//! `TMPDIR=$PWD/target/tmp NZBFAST_NO_ENRICH=1 cargo nextest run -p nzbfast
//! --features heavy-tests --test e2e --run-ignored all -E 'test(/e2e_ladder::/)'
//! --test-threads 1 --no-capture`.
//! Every leg prints a `G1 ladder rung=...` summary line and the
//! extractor lines that name its mechanism; `G1_LADDER_DUMP_LOG=1`
//! prints the whole client log.

use super::*;
use nzbkit::mock::LazyArticles;
use std::io::Read;
use std::sync::Arc;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// The budget every rung runs under. Tight in the sense that matters
/// here: from the 500 MiB rung up every volume is bigger than the whole
/// budget (the top rung's is 16x it), so a late-head volume's pile
/// exceeds the 45% holds slice (~115 MiB) many times over.
const MEM_LIMIT: &str = "256M";
const MEM_LIMIT_BYTES: u64 = 256 * MIB;

/// Peak RSS may exceed `MEM_LIMIT` by this much. The budget governs the
/// TRACKED tiers (holds, verify partials, wire in-flight) and not the
/// process floor under them: thread stacks (the 64-thread blocking
/// pool alone measured 68.7 MB in audit round 35), the binary, rustls
/// and allocator retention sit outside it, and the 21 Aug 2026
/// `--mem-limit` ladder measured that floor insensitive to a 66x budget
/// change. What G1 asks is that RSS does not SCALE with the volume, so
/// the slack is one flat figure for every rung - a rung that needed a
/// bigger one would be the finding. 256 MiB rather than the ~150 MB the
/// measured peaks would allow on this Mac because the per-push rungs
/// also run on Linux and Windows CI, whose RSS accounting and allocator
/// floor this file has not measured; the bound is still an eighth of the
/// 4 GiB rung's volume, so a route that held one would fail it. The
/// measured peaks are in the module header's table.
const RSS_SLACK_BYTES: u64 = 256 * MIB;

/// Article size: a real poster's ~750 KB.
const ART: u64 = 768_000;

/// `G1_LADDER_DUMP_LOG=1` prints a PASSING rung's whole client log, for
/// reading which mechanism carried it and where its wall went.
fn dump_log() -> bool {
    std::env::var_os("G1_LADDER_DUMP_LOG").is_some()
}

/// One rung's set: `nvols` volumes, every one but the last carrying
/// `vol` bytes of data, the last carrying half that.
struct Ladder {
    tag: &'static str,
    vol: u64,
    nvols: u64,
    seed: u64,
}

/// One volume as the mock serves it: frame bytes around a generated
/// data area at `data_off` of the payload.
struct Vol {
    name: String,
    head: Vec<u8>,
    tail: Vec<u8>,
    data_off: u64,
    data_len: u64,
}

impl Vol {
    fn len(&self) -> u64 {
        self.head.len() as u64 + self.data_len + self.tail.len() as u64
    }

    fn parts(&self) -> u64 {
        self.len().div_ceil(ART)
    }

    /// Volume bytes `[at, at + buf.len())`.
    fn fill(&self, seed: u64, at: u64, buf: &mut [u8]) {
        let (h, d) = (self.head.len() as u64, self.data_len);
        let mut done = 0usize;
        while done < buf.len() {
            let o = at + done as u64;
            let rest = &mut buf[done..];
            let n = if o < h {
                let n = rest.len().min((h - o) as usize);
                rest[..n].copy_from_slice(&self.head[o as usize..o as usize + n]);
                n
            } else if o < h + d {
                let n = rest.len().min((h + d - o) as usize);
                gen_fill(seed, self.data_off + (o - h), &mut rest[..n]);
                n
            } else {
                let t = (o - h - d) as usize;
                let n = rest.len().min(self.tail.len() - t);
                rest[..n].copy_from_slice(&self.tail[t..t + n]);
                n
            };
            done += n;
        }
    }

    /// Part `part` (1-based), yEnc-encoded.
    fn article(&self, seed: u64, part: u64) -> Vec<u8> {
        let begin = (part - 1) * ART;
        let len = ART.min(self.len() - begin) as usize;
        let mut chunk = vec![0u8; len];
        self.fill(seed, begin, &mut chunk);
        nzbkit::yenc::encode(
            &self.name,
            self.len(),
            Some((part as u32, self.parts() as u32)),
            begin + 1,
            &chunk,
        )
    }
}

/// splitmix64: a keyed, counter-mode word per 8-byte offset. Fast,
/// seekable to any offset, and not periodic at any scale a rung reaches.
fn word(seed: u64, w: u64) -> u64 {
    let mut z = w
        .wrapping_add(seed)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Payload bytes `[off, off + buf.len())`.
fn gen_fill(seed: u64, off: u64, buf: &mut [u8]) {
    let mut i = 0usize;
    // Unaligned head, byte at a time.
    while i < buf.len() && !(off + i as u64).is_multiple_of(8) {
        let o = off + i as u64;
        buf[i] = (word(seed, o / 8) >> (8 * (o % 8))) as u8;
        i += 1;
    }
    let mut w = (off + i as u64) / 8;
    let (chunks, rem) = buf[i..].as_chunks_mut::<8>();
    for c in chunks {
        *c = word(seed, w).to_le_bytes();
        w += 1;
    }
    if !rem.is_empty() {
        let b = word(seed, w).to_le_bytes();
        let n = rem.len();
        rem.copy_from_slice(&b[..n]);
    }
}

impl Ladder {
    /// `(payload length, data length of every volume)` for an archiver's
    /// geometry: every volume but the last is EXACTLY `vol` bytes on
    /// disk (`rar -v`), so the first one, whose main header has no
    /// volume-number field, carries a byte or two more data than the
    /// rest - the constant-size shape the store gate's arithmetic
    /// placement keys on. The last volume carries half a volume of data.
    fn geometry(&self) -> (u64, Vec<u64>) {
        let name = self.name();
        let frame = |k: u64, total: u64| {
            let (h, t) = fixtures::rar5_store_frame(
                &name,
                total,
                self.vol,
                None,
                k > 0,
                true,
                k,
                self.nvols,
            );
            (h.len() + t.len()) as u64
        };
        // Two rounds settle it: the frame's length moves only with the
        // vint widths of `total` and the data length, and one round
        // moves `total` by a few dozen bytes.
        let mut total = (self.nvols - 1) * self.vol + self.vol / 2;
        let mut lens = Vec::new();
        for _ in 0..2 {
            lens = (0..self.nvols - 1)
                .map(|k| self.vol - frame(k, total))
                .collect();
            lens.push(self.vol / 2);
            total = lens.iter().sum();
        }
        (total, lens)
    }

    fn total(&self) -> u64 {
        self.geometry().0
    }

    fn name(&self) -> String {
        format!("G1.Ladder.{}.mkv", self.tag)
    }

    /// The whole payload's CRC32, the one an archiver stamps on the
    /// final fragment. One generator pass, in parallel.
    fn crc(&self, total: u64) -> u32 {
        let span = 64 * MIB;
        let spans = total.div_ceil(span);
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(8)) as u64;
        let mut parts: Vec<(u64, u32, u64)> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..threads)
                .map(|t| {
                    s.spawn(move || {
                        let mut out = Vec::new();
                        let mut buf = vec![0u8; span as usize];
                        let mut k = t;
                        while k < spans {
                            let at = k * span;
                            let n = span.min(total - at) as usize;
                            gen_fill(self.seed, at, &mut buf[..n]);
                            out.push((k, crc32fast::hash(&buf[..n]), n as u64));
                            k += threads;
                        }
                        out
                    })
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
        });
        parts.sort_unstable_by_key(|p| p.0);
        let mut h = crc32fast::Hasher::new();
        for (_, c, n) in parts {
            h.combine(&crc32fast::Hasher::new_with_initial_len(c, n));
        }
        h.finalize()
    }

    fn volumes(&self) -> Vec<Vol> {
        let (total, lens) = self.geometry();
        let (crc, name) = (self.crc(total), self.name());
        let mut off = 0u64;
        (0..self.nvols)
            .map(|k| {
                let data_len = lens[k as usize];
                let (head, tail) = fixtures::rar5_store_frame(
                    &name,
                    total,
                    data_len,
                    Some(crc),
                    k > 0,
                    k + 1 < self.nvols,
                    k,
                    self.nvols,
                );
                let v = Vol {
                    name: format!("g1.{}.part{}.rar", self.tag, k + 1),
                    head,
                    tail,
                    data_off: off,
                    data_len,
                };
                off += data_len;
                v
            })
            .collect()
    }
}

/// The id of volume `k`'s part `p`, WITH angle brackets.
fn art_id(tag: &str, k: u64, p: u64) -> String {
    format!("<g1-{tag}-v{k}-{p}@mock>")
}

/// `(k, p)` back out of an id `art_id` wrote.
fn parse_id(tag: &str, id: &str) -> Option<(u64, u64)> {
    let rest = id
        .strip_prefix(&format!("<g1-{tag}-v"))?
        .strip_suffix("@mock>")?;
    let (k, p) = rest.split_once('-')?;
    Some((k.parse().ok()?, p.parse().ok()?))
}

/// Encoded sizes of every part of every volume, for the NZB's
/// `bytes=` - exact, because a posted size is what the client clamps a
/// lying yEnc header against, so an estimate is one more thing a rung
/// could fail on that has nothing to do with the budget. One encode
/// pass, in parallel, keeping only the lengths.
fn encoded_sizes(vols: &[Vol], seed: u64) -> Vec<Vec<u64>> {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(8)) as u64;
    vols.iter()
        .map(|v| {
            let parts = v.parts();
            let mut sizes: Vec<(u64, u64)> = std::thread::scope(|s| {
                let hs: Vec<_> = (0..threads)
                    .map(|t| {
                        s.spawn(move || {
                            let mut out = Vec::new();
                            let mut p = 1 + t;
                            while p <= parts {
                                out.push((p, v.article(seed, p).len() as u64));
                                p += threads;
                            }
                            out
                        })
                    })
                    .collect();
                hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
            });
            sizes.sort_unstable_by_key(|s| s.0);
            sizes.into_iter().map(|s| s.1).collect()
        })
        .collect()
}

/// The NZB segment list of volume `k`: every part in posting order with
/// its declared number, or - `late_head` - the fully obfuscated poster's
/// shape: the ladder SHUFFLED with the offset-0 article forced to the
/// END and sequential numbers slapped on, so "segment 1" is not the
/// article carrying the headers and the client reaches those last.
///
/// A seeded shuffle and not a rotation on purpose: a rotation is the
/// shape the offset-0 probe's rotation guess undoes (see
/// `rotated_segment_numbering_offset0_promoted_one_pass` in `e2e.rs`),
/// so the head would be front-loaded and nothing would pile.
///
/// The lateness comes from the CLIENT'S OWN SCHEDULE, never from the
/// server going silent. This rig first held those articles at the mock
/// ([`nzbkit::mock::Hold`]) until the rest of the set was served, and on
/// the 4 GiB rung that was ~70 s of silence on one request: the client's
/// pre-byte stall budget tore the read down seven times, then booked
/// the article lost ("1 of 13983 segment(s) never arrived ... read
/// stall") and failed the job. That is the stall ladder answering a
/// server fault correctly, not a budget cliff - so it measured the
/// wrong thing, and it is not how a late header happens on a real post.
fn segments(tag: &str, k: u64, sizes: &[u64], late_head: bool) -> Vec<(String, u64, u32)> {
    let mut parts: Vec<u64> = (1..=sizes.len() as u64).collect();
    if late_head {
        let mut st = 0x61AD_E0A5u64 ^ (k << 17);
        for i in (2..parts.len()).rev() {
            st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
            // Shuffle parts[1..], keeping the head at index 0 for now.
            let j = 1 + (st >> 33) as usize % i;
            parts.swap(i, j);
        }
        parts.rotate_left(1);
    }
    parts
        .iter()
        .enumerate()
        .map(|(i, &p)| {
            let id = art_id(tag, k, p);
            (
                id[1..id.len() - 1].to_string(),
                sizes[p as usize - 1],
                i as u32 + 1,
            )
        })
        .collect()
}

/// Peak RSS out of the `[mem] peak RSS X.XX GB` summary line.
fn peak_rss(log: &str) -> Option<u64> {
    let at = log.find("peak RSS ")? + "peak RSS ".len();
    let gb: f64 = log[at..].split_whitespace().next()?.parse().ok()?;
    Some((gb * 1e9) as u64)
}

/// The largest `[holds-trace] holds N MB` sample (`NZBFAST_HOLDS_TRACE`).
fn holds_trace_max_mb(log: &str) -> u64 {
    log.lines()
        .filter_map(|l| l.split("[holds-trace] holds ").nth(1))
        .filter_map(|r| r.split_whitespace().next()?.parse::<f64>().ok())
        .fold(0.0f64, f64::max) as u64
}

/// Compare `path` against the generator, 8 MiB at a time.
fn assert_payload(path: &Path, seed: u64, total: u64) {
    let mut f = std::fs::File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let len = f.metadata().unwrap().len();
    assert_eq!(len, total, "extracted size differs");
    let span = 8 * MIB as usize;
    let (mut got, mut want) = (vec![0u8; span], vec![0u8; span]);
    let mut at = 0u64;
    while at < total {
        let n = span.min((total - at) as usize);
        f.read_exact(&mut got[..n]).unwrap();
        gen_fill(seed, at, &mut want[..n]);
        if got[..n] != want[..n] {
            let i = got[..n]
                .iter()
                .zip(&want[..n])
                .position(|(a, b)| a != b)
                .unwrap();
            panic!("extracted payload differs at byte {}", at + i as u64);
        }
        at += n as u64;
    }
}

/// How a rung is served, and which extractor route it must take.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Route {
    /// Volumes complete in REVERSE (the NZB lists them last first),
    /// every header article served on demand. Weaver's breach shape: a
    /// volume's data is complete long before the volumes in front of it
    /// exist. Must stay ONE-PASS - no volume touches disk.
    OnePass,
    /// Reversed AND every volume but the last posted with its header
    /// article dead last in a shuffled ladder ([`segments`]), so each
    /// volume's data lands before anything says where it goes. Paging
    /// on, the shipped configuration. Must DELIVER inside the RSS bound;
    /// the route is the extractor's call and is reported, not asserted -
    /// the module header says why it changes up the ladder.
    LateHeads,
    /// `LateHeads` with `NZBFAST_NO_HOLDS_PAGE=1`: the relief valve is
    /// gone, so the pile MUST demote the set to materialized volumes and
    /// the disk post-pass, and that route must deliver as well.
    Fallback,
}

/// Run one rung on one route and assert G1's acceptance: delivered,
/// byte-correct, and peak RSS under `MEM_LIMIT` plus `RSS_SLACK_BYTES`.
async fn rung(l: Ladder, route: Route) {
    let t0 = std::time::Instant::now();
    let tag = format!("g1-{}-{route:?}", l.tag).to_lowercase();
    let mut fx = Fixture::new(&tag);
    let vols = Arc::new(l.volumes());
    assert!(
        vols[..vols.len() - 1].iter().all(|v| v.len() == l.vol),
        "every volume but the last must be exactly {} bytes on disk",
        l.vol
    );
    let sizes = encoded_sizes(&vols, l.seed);
    // NZB order: LAST volume first, so the volumes complete in reverse.
    // The late-head routes post every volume but the last with its
    // header article dead last (see `segments`).
    let late = route != Route::OnePass;
    for k in (0..l.nvols).rev() {
        let late_head = late && k + 1 < l.nvols;
        let segs = segments(l.tag, k, &sizes[k as usize], late_head);
        fx.nzb_files.push((vols[k as usize].name.clone(), segs));
    }
    let late_heads: Vec<String> = if late {
        (0..l.nvols - 1).map(|k| art_id(l.tag, k, 1)).collect()
    } else {
        Vec::new()
    };
    let total_parts: u64 = vols.iter().map(Vol::parts).sum();
    let (gen_vols, seed, gtag) = (vols.clone(), l.seed, l.tag);
    let chaos = Chaos {
        lazy: Some(LazyArticles::new(move |id| {
            let (k, p) = parse_id(gtag, id)?;
            let v = gen_vols.get(k as usize)?;
            (p >= 1 && p <= v.parts()).then(|| v.article(seed, p))
        })),
        ..Chaos::default()
    };
    let srv = MockServer::start(HashMap::new(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let built = t0.elapsed();

    let mut env = vec![("NZBFAST_NO_ENRICH", "1"), ("NZBFAST_HOLDS_TRACE", "1")];
    if route == Route::Fallback {
        env.push(("NZBFAST_NO_HOLDS_PAGE", "1"));
    }
    let o = out.clone();
    let t1 = std::time::Instant::now();
    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(&cfg, &nzb, &o, &env, &["--mem-limit", MEM_LIMIT])
    })
    .await
    .unwrap();
    let wall = t1.elapsed();
    // How many bodies the client had asked for before its FIRST request
    // for each late header: the measure that the shape really happened.
    let head_asked: Vec<u64> = {
        let asked = srv.body_log.lock().unwrap();
        late_heads
            .iter()
            .map(|h| asked.iter().position(|id| id == h).unwrap_or(asked.len()) as u64)
            .collect()
    };
    assert!(ok, "rung {} {route:?} did not deliver:\n{log}", l.tag);

    let t2 = std::time::Instant::now();
    assert_payload(&out.join(l.name()), l.seed, l.total());
    let readback = t2.elapsed();
    let rss = peak_rss(&log).unwrap_or_else(|| panic!("no [mem] peak RSS line:\n{log}"));
    let holds = holds_trace_max_mb(&log);
    let went = if log.contains("direct extraction fell back") {
        "disk-pass"
    } else {
        "one-pass"
    };
    eprintln!(
        "G1 ladder rung={} route={route:?} went={went} vol_mib={} vols={} set_mib={} \
         mem_limit={MEM_LIMIT} peak_rss_mb={} holds_trace_max_mb={holds} \
         heads_asked_after={head_asked:?}/{total_parts} build_s={:.1} get_wall_s={:.1} \
         readback_s={:.1}",
        l.tag,
        l.vol / MIB,
        l.nvols,
        l.total() / MIB,
        rss / 1_000_000,
        built.as_secs_f64(),
        wall.as_secs_f64(),
        readback.as_secs_f64(),
    );
    if dump_log() {
        eprintln!("G1 ladder rung={} route={route:?} full log:\n{log}", l.tag);
    }
    // The lines that say which mechanism carried the rung, so a passing
    // run's record names it too.
    for line in log.lines().filter(|l| {
        (l.starts_with("[extract]") || l.starts_with("[mem]") || l.contains("scratch"))
            && !l.contains("[holds-trace]")
    }) {
        eprintln!("G1 ladder rung={} route={route:?} | {line}", l.tag);
    }

    // The late-head shape really happened: each header was first asked
    // for only after every volume listed ahead of it and at least half
    // of its own volume had been asked. A client that front-loaded it
    // anyway (a probe that learned to see through this ladder) would
    // show here rather than pass as a weaker rung.
    for (k, &asked) in head_asked.iter().enumerate() {
        let ahead: u64 = vols[k + 1..].iter().map(Vol::parts).sum();
        let floor = ahead + vols[k].parts() / 2;
        assert!(
            asked >= floor,
            "volume {k}'s header was asked after only {asked} bodies (floor {floor}) - \
             the late-head shape did not happen:\n{log}"
        );
    }
    match route {
        Route::OnePass => {
            assert!(
                log.contains("volumes never touched disk"),
                "a reversed set must stay one-pass:\n{log}"
            );
            assert!(went == "one-pass", "set demoted:\n{log}");
            for v in vols.iter() {
                assert!(
                    !out.join(&v.name).exists(),
                    "volume {} must not touch disk (one-pass)",
                    v.name
                );
            }
        }
        Route::LateHeads => {}
        Route::Fallback => {
            // Demoted, by whatever cause the extractor names: the route
            // under test is the disk pass, not one particular reason.
            assert!(
                went == "disk-pass",
                "the fallback route never fell back:\n{log}"
            );
            assert!(
                log.contains("partly on disk") || log.contains("unpacked after download"),
                "shape must say the set went to disk:\n{log}"
            );
        }
    }
    assert!(
        rss <= MEM_LIMIT_BYTES + RSS_SLACK_BYTES,
        "rung {} {route:?}: peak RSS {} MB is past the {MEM_LIMIT} limit plus {} MiB slack:\n{log}",
        l.tag,
        rss / 1_000_000,
        RSS_SLACK_BYTES / MIB
    );
}

const R50M: Ladder = Ladder {
    tag: "50m",
    vol: 50 * MIB,
    nvols: 3,
    seed: 0x6101,
};
const R500M: Ladder = Ladder {
    tag: "500m",
    vol: 500 * MIB,
    nvols: 3,
    seed: 0x6102,
};
const R1G: Ladder = Ladder {
    tag: "1g",
    vol: GIB,
    nvols: 3,
    seed: 0x6103,
};
const R4G: Ladder = Ladder {
    tag: "4g",
    vol: 4 * GIB,
    nvols: 3,
    seed: 0x6104,
};

#[tokio::test(flavor = "multi_thread")]
async fn ladder_50m_one_pass() {
    rung(R50M, Route::OnePass).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ladder_50m_late_heads() {
    rung(R50M, Route::LateHeads).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ladder_50m_fallback() {
    rung(R50M, Route::Fallback).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ladder_500m_one_pass() {
    rung(R500M, Route::OnePass).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ladder_500m_late_heads() {
    rung(R500M, Route::LateHeads).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ladder_500m_fallback() {
    rung(R500M, Route::Fallback).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "G1 heavy rung: on demand, see the module header"]
async fn ladder_1g_one_pass() {
    rung(R1G, Route::OnePass).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "G1 heavy rung: on demand, see the module header"]
async fn ladder_1g_late_heads() {
    rung(R1G, Route::LateHeads).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "G1 heavy rung: on demand, see the module header"]
async fn ladder_1g_fallback() {
    rung(R1G, Route::Fallback).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "G1 heavy rung: on demand, see the module header"]
async fn ladder_4g_one_pass() {
    rung(R4G, Route::OnePass).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "G1 heavy rung: on demand, see the module header"]
async fn ladder_4g_late_heads() {
    rung(R4G, Route::LateHeads).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "G1 heavy rung: on demand, see the module header"]
async fn ladder_4g_fallback() {
    rung(R4G, Route::Fallback).await;
}
