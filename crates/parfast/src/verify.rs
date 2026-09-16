//! Loading a recovery set the way par2cmdline loads one, verifying its
//! members through the engine, and printing the reference's lines.
//!
//! The arithmetic here is accounting, not coding theory: which blocks
//! are present, how many are owed, how many recovery blocks exist. Every
//! actual verification is `nzbkit::par2repair::verify_pass1`, and every
//! repair is `nzbkit::par2repair` - this module decides nothing about
//! bytes.
//!
//! WHICH ENGINE ENTRY POINT, AND WHY IT IS THIS ONE. The engine offers
//! two per-member verifiers and they cost very different amounts over
//! the SAME single read. `par2::verify_file_path` proves the FileDesc
//! MD5 *and* re-proves every block's IFSC MD5, so a clean member is
//! hashed by two full MD5 chains; `par2repair::verify_pass1` proves the
//! FileDesc MD5 and settles presence on the block CRC32 alone, which is
//! roughly free beside it. Measured 4 Sep 2026 on the published 1 GiB /
//! 21-volume corpus, retired instructions, output byte-identical and
//! `sha_ok 21/21` on every leg: 23.97 Gi through `verify_file_path`
//! against 12.28 Gi through `verify_pass1` - the CLI was doing 1.95x
//! the engine's work to reach the same verdict. On a quiet 32-core
//! machine that was the whole of a 0.199 s clean verify against the
//! 0.095 s the same engine takes for an entire `repair_dir` over the
//! same set; it reads 0.126 s through this entry point.
//!
//! So this is a COST constraint on `survey`, not a preference: whatever
//! else that function grows, the bytes of a clean member must be hashed
//! by one MD5 chain and not two. `verify_pass1` is also what the
//! engine's own `repair_dir_set_*` runs, so the CLI and the daemon now
//! reach one verdict through one function rather than two.
//!
//! `repair` shares the whole first half: par2cmdline verifies before it
//! repairs and prints the identical lines while doing so, so a second
//! copy of this would be a second answer to "is this file damaged".

use std::path::{Path, PathBuf};

use nzbkit::par2::{self, Par2Set};
use nzbkit::par2repair::{self, Pass1Out};

use crate::cli::Options;
use crate::out::{Level, Sink};

/// One member's verdict, in the form the `Target:` line needs.
pub enum Target {
    /// Whole-file MD5 matched.
    Found,
    /// Present, and some blocks did not.
    Damaged { have: usize, total: usize },
    /// Not on disk at all.
    Missing,
}

/// A loaded set plus where it came from.
pub struct Loaded {
    pub set: Par2Set,
    /// Where the recovery FILES are.
    pub dir: PathBuf,
    /// Where the DATA files are: `-B` when it was given, otherwise the
    /// same directory. The reference honours a relative `-B` on verify
    /// and repair (the captured `sweep/B` row is `-Bsweepdir` and every
    /// target comes back missing), and refuses one on create - see
    /// `create::within` for that half.
    pub data_dir: PathBuf,
    /// Every `.par2` file the load walked, so `-p` knows what to purge.
    pub par_files: Vec<PathBuf>,
    /// Recovery packets the load framed but did not verify, per file
    /// (a quiet verify defers them - see [`load_with`]); empty when the
    /// load verified everything. Settled by [`ensure_recovery`], once,
    /// when a verdict needs the count.
    pub deferred: Vec<Deferred>,
    /// The settled recovery block count, once [`ensure_recovery`] ran.
    pub recovery_validated: Option<usize>,
}

/// One file's deferred recovery packets: skipped on disk by the seeking
/// walk (the ordinary case - nothing of them was read), or framed in a
/// whole read kept resident (the fallback for a file the seeking walk
/// could not frame).
pub enum Deferred {
    OnDisk(PathBuf, Vec<(u64, u64)>),
    Resident(Vec<u8>, Vec<(usize, usize)>),
}

impl Loaded {
    /// Where a FileDesc name lands on disk - THE one place parfast turns
    /// a packet field into a path.
    ///
    /// A FileDesc name is wire data from an untrusted file, and a bare
    /// `data_dir.join(&name)` trusts it twice over. `Path::join` DROPS
    /// the base when the name is absolute and keeps `..` intact, so
    /// `/etc/passwd` or `../../x` reaches outside `data_dir` - and both
    /// `repair::back_up_damaged` (a copy) and [`purge`] (a delete) write
    /// through this resolution. Separately, the engine resolves the same
    /// name as `join_out_name(dir, sanitize_out_name(name))`
    /// (`par2repair.rs`, the target walk), so a raw join also disagrees
    /// with it about any name sanitizing touches: a FileDesc `movie.mkv.`
    /// is `movie.mkv.` here and `movie.mkv` there, and parfast then
    /// reports a member missing that the engine just repaired.
    ///
    /// Routing every parfast path through the engine's own rule closes
    /// both: it is the same function, so the two halves cannot drift,
    /// and sanitizing is what strips the traversal.
    pub fn data_path(&self, name: &str) -> PathBuf {
        nzbkit::disk::join_out_name(&self.data_dir, &nzbkit::disk::sanitize_out_name(name))
    }

    /// Every path the set PROTECTS, keyed for comparison - the guard
    /// that stops a member being mistaken for a disposable file.
    ///
    /// The key is case-folded because two member names that differ only
    /// in case are ONE file on macOS and Windows, so a byte-equal path
    /// test would miss the alias and hand the member to a delete. Over-
    /// matching on a case-sensitive filesystem is the safe direction:
    /// the only thing it can cost is a backup taking `.2` where `.1` was
    /// free, and the only thing under-matching costs is the payload.
    /// Sanitizing is already handled - the keys come out of
    /// [`Loaded::data_path`], which is the one place a FileDesc name
    /// becomes a path, so an alias two names share resolves to one key.
    pub fn protected_keys(&self) -> std::collections::HashSet<String> {
        self.set
            .files
            .iter()
            .map(|f| path_key(&self.data_path(&f.name)))
            .collect()
    }
}

/// How a path is compared against [`Loaded::protected_keys`].
pub fn path_key(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

/// The whole-set picture, once every member has been looked at.
pub struct Survey {
    pub targets: Vec<(String, Target)>,
    /// Data blocks the set declares, over every member.
    pub total_blocks: usize,
    /// Data blocks actually accounted for on disk.
    pub available_blocks: usize,
    /// Recovery blocks on hand.
    pub recovery_blocks: usize,
}

impl Survey {
    /// Blocks nothing on disk can supply.
    pub fn owed(&self) -> usize {
        self.total_blocks.saturating_sub(self.available_blocks)
    }

    /// Is anything wrong at all?
    pub fn damaged(&self) -> bool {
        self.targets
            .iter()
            .any(|(_, t)| !matches!(t, Target::Found))
    }

    /// Can the recovery data on hand cover what is owed?
    pub fn repairable(&self) -> bool {
        self.recovery_blocks >= self.owed()
    }
}

/// `-t`, defaulted the way the engine defaults it.
///
/// The default is `nzbkit::mem::cpu_workers()` and not the machine's raw
/// core count: that is the one place the whole workspace derives a pool
/// width from, it honours `NZBFAST_CPU_WORKERS`, and it is what every
/// other consumer of this engine hands the same functions. A CLI that
/// sized its pools by a private rule would measure differently from the
/// daemon running the identical code.
pub fn threads(opts: &Options) -> usize {
    opts.threads
        .filter(|&n| n > 0)
        .unwrap_or_else(nzbkit::mem::cpu_workers)
}

/// `-T`, the number of MEMBERS hashed at once, clamped to how many there
/// actually are.
///
/// This switch used to be parsed onto a field nothing read, and the cost
/// was not theoretical: `survey` walked the set one member at a time, so
/// a clean verify of a 1 GiB set in 21 files was a SERIAL chain of
/// whole-file MD5s - about 1.4 s at the measured 0.75 GB/s per core,
/// against par2cmdline-turbo's 0.30 s at `-T16`. Measured 4 Sep 2026 on
/// a 32-core desktop: 1.467 s here, 0.902 s for turbo's default and
/// 0.297 s for turbo at `-T16`, on the same corpus in the same round.
///
/// The engine's per-file entry point was already built for this: its
/// `threads` argument is documented as a hint "clamped to machine
/// parallelism, a hard thread ceiling, the block count and a byte
/// budget", explicitly so that it stays inside its budget "when nested
/// under file-parallel verification". Nothing nested it until now.
pub fn file_threads(opts: &Options, members: usize) -> usize {
    opts.file_threads
        .filter(|&n| n > 0)
        .unwrap_or_else(nzbkit::mem::cpu_workers)
        .max(1)
        .min(members.max(1))
}

/// Load the named recovery file and every sibling volume beside it,
/// printing the reference's `Loading` / `Loaded` pair per file.
///
/// par2cmdline loads the file it was NAMED first, then walks the
/// directory for `<stem>*.par2` and loads each of those - which reaches
/// the named file a second time, and is why every captured table shows
/// `Loading "set.par2".` twice with `No new packets found` under the
/// second. That is not a bug being reproduced: it is the observable
/// behaviour a script's output parser sees, and the harness compares it.
/// WHICH set, and WHERE - the cheap prologue [`load`] opens with, split
/// out so a caller can have the answer before the expensive part runs.
///
/// It reads only the NAMED file, which on any ordinary set is the 25 KB
/// index; the recovery volumes, which are all the bytes, are [`load`]'s
/// business. `repair` uses it to start the engine's own pass - which
/// needs nothing from us but a directory and a set id - CONCURRENTLY
/// with the load, instead of after it.
///
/// The `-a` fallback is the reference's and lives here rather than in
/// `load` so both callers get it: `-a` names the set to read, but the
/// reference falls back to the bare argument when that file is not
/// there rather than refusing - `sweep/a` is `v -asweeplist.txt
/// set.par2` on a shape holding no `sweeplist.txt.par2`, and the
/// reference verifies `set.par2` and exits 0. A candidate that refused
/// would fail the switch probe.
pub fn locate(opts: &Options, sink: &mut Sink) -> Result<(PathBuf, PathBuf, [u8; 16]), u8> {
    let named = match opts.archive.clone().filter(|p| p.exists()) {
        Some(a) => a,
        None => match opts.par2.clone() {
            Some(p) => p,
            None => {
                sink.err("You must specify a Recovery file.");
                return Err(crate::EXIT_INVALID_ARGS);
            }
        },
    };
    let dir = named
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let Ok(first) = std::fs::read(&named) else {
        sink.err("failed to set the main par file");
        return Err(crate::EXIT_INVALID_ARGS);
    };
    let Some(want) = Par2Set::set_id_of(&first) else {
        sink.err("You must specify a Recovery file.");
        return Err(crate::EXIT_INVALID_ARGS);
    };
    Ok((named, dir, want))
}

/// [`load_with`] verifying every packet: the repair path's load, whose
/// cost hides under the engine's own survey on another thread anyway.
pub fn load(opts: &Options, sink: &mut Sink) -> Result<Loaded, u8> {
    load_with(opts, sink, false)
}

/// `NZBFAST_PARFAST_LOAD=whole`: the A/B arm that holds the old
/// whole-read load reachable, for BOTH loads that replaced it - the
/// repair's scan-report load (TODO 334) and the verify's seeking one.
/// The property each of them rests on is that it prints the same bytes
/// as the whole read, and an arm is how a test says so.
///
/// ONE spelling, because a second copy is a second answer: a run with
/// the variable set must take the whole read in every command, or the
/// arm proves nothing about the command whose copy disagreed.
pub fn whole_load_forced() -> bool {
    std::env::var_os("NZBFAST_PARFAST_LOAD").as_deref() == Some(std::ffi::OsStr::new("whole"))
}

/// The set from the named file and its siblings. With `may_defer`, a
/// QUIET load leaves the recovery packets unverified (see below); the
/// verify command asks for that, the repair command does not.
pub fn load_with(opts: &Options, sink: &mut Sink, may_defer: bool) -> Result<Loaded, u8> {
    let (named, dir, want) = locate(opts, sink)?;

    let mut order = vec![named.clone()];
    order.extend(siblings(&dir, &named));
    let mut seen: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    // BORROWED from `read` below, never copied: these are the whole
    // recovery set's bytes - 108 MB on the published corpus - and
    // cloning them cost ~7.6 ms a run to fill a Vec the fast path never
    // reads at all.
    let mut members: Vec<&[u8]> = Vec::new();
    let mut par_files = Vec::new();
    let mut deferred_at: Vec<(usize, Vec<(usize, usize)>)> = Vec::new();
    // ONE scan of the candidate files, not two. Both `packet_census`
    // and `Par2Set::parse` walk through `scan_packets`, which
    // MD5-verifies every packet, so censusing each file for its
    // `Loaded N new packets` line and then parsing the set hashed the
    // recovery volumes TWICE - ~1.1G retired instructions over the
    // published corpus's 104 MB of them, measured 4 Sep 2026.
    //
    // The set is settled over EVERY candidate here, where the walk
    // below settles it over the filtered ones, so the two can disagree
    // about which set won on a directory holding more than one. That is
    // what `censused` being dropped on the guard below means: the fast
    // path is taken only where the answer is the set the named file
    // itself declares, and anything else re-parses the filtered blobs
    // exactly as before.
    // The candidate files read CONCURRENTLY, up to eight at a time: on a
    // Windows page cache a read is a ~2.9 GB/s kernel copy, so the
    // published corpus's 108 MB of volumes was ~37 ms read one after
    // another at the head of every verify and repair (i5-10600KF,
    // 5 Sep 2026, the parfast-overhead lane), against a 240 ms verify.
    // A VERIFY frames the volumes by SEEKING first: each packet's
    // header read at its offset, the recovery payloads (the bulk of
    // every volume) skipped and their spans kept, the critical packets
    // read whole - so a clean set never reads its parity at all, and a
    // damaged one reads it a PACKET at a time when its verdict asks
    // (`ensure_recovery`), rather than a volume at a time.
    // A file the walk cannot frame (a header out of place) sends the
    // whole load down the whole-read path below, which resyncs.
    //
    // The DEFAULT level takes the same door (10 Sep 2026). It cannot
    // defer - `Loaded N new packets including M recovery blocks` is a
    // count of packets that HASHED, and it prints before anything else
    // - so `load_sparse` checks each recovery span there and then; what
    // it stops doing is holding the volume while it does. Peak RSS on
    // the 2 GiB / 100%-parity fixture, damaged, M3 Ultra 10 Sep 2026:
    // 2.24 GB before at the default level and 2.30 GB under `-q`,
    // against 0.10 GB either way after - which is what a CLEAN quiet
    // verify of the same set already cost (0.09 GB), because holding
    // the volumes was the whole of the difference. Wall came down with
    // it, 0.55 s to 0.42 s and 0.66 s to 0.46 s, medians of three:
    // the bytes are read and hashed either way, so what went is the
    // page faults on 2.3 GB of heap.
    let defer = may_defer && !sink.shows(Level::Normal);
    let sparse: Option<Vec<Option<par2::SparseFrame>>> = if may_defer && !whole_load_forced() {
        let frames: Vec<Option<par2::SparseFrame>> = order
            .iter()
            .map(|p| {
                let f = std::fs::File::open(p).ok()?;
                let len = f.metadata().ok()?.len();
                par2::sparse_frame(&f, len)
            })
            .collect();
        // A missing sibling is "not present" on either path; a present
        // file that would not frame is the fallback's job.
        let framed_or_absent = order
            .iter()
            .zip(&frames)
            .all(|(p, fr)| fr.is_some() || !p.exists());
        framed_or_absent.then_some(frames)
    } else {
        None
    };
    if let Some(frames) = sparse {
        return load_sparse(opts, sink, dir, want, order, frames, defer);
    }
    let read: Vec<Option<Vec<u8>>> = {
        let fan = order.len().clamp(1, 8);
        let per = order.len().div_ceil(fan);
        std::thread::scope(|s| {
            let handles: Vec<_> = order
                .chunks(per)
                .map(|paths| {
                    s.spawn(move || -> Vec<Option<Vec<u8>>> {
                        paths.iter().map(|p| std::fs::read(p).ok()).collect()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().expect("parfast volume reader panicked"))
                .collect()
        })
    };
    let present: Vec<&[u8]> = read.iter().flatten().map(Vec::as_slice).collect();
    // A QUIET verify defers the recovery packets: nothing printed at
    // `-q` carries their count, and a clean set never needs it, so
    // their MD5s (the bulk of the volumes' bytes) are not computed
    // unless a verdict asks - `ensure_recovery`, from the bytes kept
    // here. At the default level the per-file `Loaded N new packets
    // including M recovery blocks` lines print before anything else and
    // need the verified count, so that path hashes everything as it
    // always did. i5-10600KF, a clean 10 GiB set with 1 GiB of parity,
    // round AV (6 Sep 2026): 2.00-2.16 s against 2.10-2.13, CPU 16.2
    // against 17.6-17.8; reading the volumes is the part that stays
    // (the index alone verifies in 1.61-1.67).
    let (parsed, censuses, deferred_spans) = if defer {
        par2::Par2Set::parse_deferred(&present)
    } else {
        let (parsed, censuses) = par2::Par2Set::parse_censused(&present);
        (parsed, censuses, Vec::new())
    };
    let censused = match &parsed {
        Ok(set) if set.recovery_set_id == want => Some(censuses),
        _ => None,
    };
    let mut nth = 0usize;
    for (path, bytes) in order.iter().zip(&read) {
        let Some(bytes) = bytes else {
            continue;
        };
        let at = nth;
        nth += 1;
        // A sibling that carries a DIFFERENT set is not ours, however
        // its name globbed. Two sets in one directory is the ordinary
        // shape of a season folder, and feeding both to `Par2Set::parse`
        // is two Main packets - `MixedRecoverySets`, which this caller
        // turns into "You must specify a Recovery file." over a set that
        // was perfectly repairable. The narrowed stem in `set_stem`
        // stops the common collision; this stops the rest, including a
        // genuine prefix collision the reference globs too.
        //
        // The test is MEMBERSHIP, not `set_id_of`: one `.par2` file can
        // carry two sets interleaved, and `set_id_of` answers with the
        // dominant one, which would drop a file that really does hold
        // packets we need. `Par2Set::parse` already takes only the
        // packets belonging to the set it settles on, so admitting a
        // mixed file costs nothing.
        //
        // The NAMED file is never dropped: it is the first entry and
        // `want` came out of it, so this only ever filters siblings.
        let census = match &censused {
            Some(all) => all[at].clone(),
            None => par2::packet_census(bytes),
        };
        if !census.iter().any(|p| p.set_id == want) {
            continue;
        }
        let name = display_name(&dir, path);
        sink.line(Level::Terse, &format!("Loading \"{name}\"."));
        let mut new = 0usize;
        let mut new_recovery = 0usize;
        for p in &census {
            if seen.insert(p.md5) {
                new += 1;
                if p.recovery_exponent.is_some() {
                    new_recovery += 1;
                }
            }
        }
        sink.line(
            Level::Normal,
            &if new == 0 {
                "No new packets found".to_string()
            } else if new_recovery == 0 {
                format!("Loaded {new} new packets")
            } else {
                format!("Loaded {new} new packets including {new_recovery} recovery blocks")
            },
        );
        par_files.push(path.clone());
        members.push(bytes.as_slice());
        if let Some(spans) = deferred_spans.get(at).filter(|v| !v.is_empty()) {
            deferred_at.push((at, spans.clone()));
        }
    }

    // The fast path already has the answer; only the fallback re-parses
    // - and a re-parse verifies everything, so it owes nothing.
    let (reparsed, deferred_at) = match censused {
        Some(_) => (parsed, deferred_at),
        None => (Par2Set::parse(&members), Vec::new()),
    };
    drop(members);
    // The deferred files' bytes move into the result (no copy); every
    // other file's are dropped here as before.
    let mut read = read;
    let deferred: Vec<Deferred> = deferred_at
        .into_iter()
        .filter_map(|(at, spans)| {
            read.iter_mut()
                .flatten()
                .nth(at)
                .map(|bytes| Deferred::Resident(std::mem::take(bytes), spans))
        })
        .collect();
    match reparsed {
        Ok(set) => Ok(Loaded {
            data_dir: opts.basepath.clone().unwrap_or_else(|| dir.clone()),
            set,
            dir,
            par_files,
            deferred,
            recovery_validated: None,
        }),
        Err(_) => {
            sink.err("You must specify a Recovery file.");
            Err(crate::EXIT_INSUFFICIENT_DATA)
        }
    }
}

/// The seeking load (see [`load_with`]): the same walk over the
/// candidates as the whole-read path - membership by census, the
/// `Loading` lines, `par_files` for `-p` - over each file's critical
/// packets, with the recovery packets never held.
///
/// `defer` is the `-q` half. Deferred, a recovery packet is censused
/// on its header's unverified CLAIMS and its span left on disk for
/// [`ensure_recovery`] to check if a verdict ever asks; nothing printed
/// at `-q` carries the count, so a clean set never reads its parity.
///
/// UNDEFERRED - the default level, whose `Loaded N new packets
/// including M recovery blocks` line is a count of packets that hashed
/// and prints before the first target is looked at - each span is read
/// and MD5-checked here, one packet at a time into a reused buffer
/// (`par2::verify_recovery_file`). The census is then the same packets
/// the whole read censused, minus the file order between criticals and
/// recovery, which no count on this walk reads: `new` and
/// `new_recovery` are first-seen-MD5 tallies over a file's packets as
/// a SET, and a duplicate inside one file is a duplicate whichever end
/// of the list it sits at.
///
/// The set's recovery block count cannot come from the parse here -
/// `members` is the criticals - so it is re-spelt from the verified
/// packets the same way [`load_scanned`] re-spells it: longest slice
/// per exponent over the admitted files' packets of THIS set, counted
/// where [`par2::slice_fits_block`] says the slice can serve. It lands
/// in `recovery_blocks_seen` AND in `recovery_validated`, so `survey`
/// and [`ensure_recovery`] read one number.
fn load_sparse(
    opts: &Options,
    sink: &mut Sink,
    dir: PathBuf,
    want: [u8; 16],
    order: Vec<PathBuf>,
    frames: Vec<Option<par2::SparseFrame>>,
    defer: bool,
) -> Result<Loaded, u8> {
    let present: Vec<&[u8]> = frames
        .iter()
        .flatten()
        .map(|fr| fr.bytes.as_slice())
        .collect();
    let (parsed, censuses) = par2::Par2Set::parse_censused(&present);
    let censused = match &parsed {
        Ok(set) if set.recovery_set_id == want => Some(censuses),
        _ => None,
    };
    let mut seen: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    let mut members: Vec<&[u8]> = Vec::new();
    let mut par_files = Vec::new();
    let mut deferred: Vec<Deferred> = Vec::new();
    // Exponent -> longest slice, over the admitted files' verified
    // recovery packets of THIS set; empty while deferring.
    let mut exps: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    let mut nth = 0usize;
    for (path, frame) in order.iter().zip(&frames) {
        let Some(frame) = frame else {
            continue;
        };
        let at = nth;
        nth += 1;
        let mut census = match &censused {
            Some(all) => all[at].clone(),
            None => par2::packet_census(&frame.bytes),
        };
        let spans: Vec<(u64, u64)> = frame.recovery.iter().map(|r| (r.offset, r.len)).collect();
        // The recovery packets. Deferred, as their headers CLAIM them,
        // verified later if ever; otherwise read span by span and
        // censused exactly as a whole read would have censused them,
        // the packets that fail their own MD5 simply absent.
        //
        // Before the membership test, because that is where the whole
        // read applies it: a file whose criticals name another set but
        // whose parity is ours is admitted by both, and a file admitted
        // by neither costs the same hashes on either path.
        let verified: Vec<par2::PacketInfo> = if defer {
            Vec::new()
        } else {
            par2::verify_recovery_file(path, &spans)
        };
        if defer {
            census.extend(frame.recovery.iter().map(|r| par2::PacketInfo {
                md5: r.md5,
                set_id: r.set_id,
                recovery_exponent: r.exponent,
                body_len: usize::try_from(r.len.saturating_sub(64)).unwrap_or(usize::MAX),
            }));
        } else {
            census.extend(verified.iter().copied());
        }
        if !census.iter().any(|p| p.set_id == want) {
            continue;
        }
        for p in &verified {
            let Some(e) = p.recovery_exponent.filter(|_| p.set_id == want) else {
                continue;
            };
            let v = exps.entry(e).or_insert(0);
            *v = (*v).max(p.body_len.saturating_sub(4));
        }
        let name = display_name(&dir, path);
        sink.line(Level::Terse, &format!("Loading \"{name}\"."));
        let mut new = 0usize;
        let mut new_recovery = 0usize;
        for p in &census {
            if seen.insert(p.md5) {
                new += 1;
                if p.recovery_exponent.is_some() {
                    new_recovery += 1;
                }
            }
        }
        sink.line(
            Level::Normal,
            &if new == 0 {
                "No new packets found".to_string()
            } else if new_recovery == 0 {
                format!("Loaded {new} new packets")
            } else {
                format!("Loaded {new} new packets including {new_recovery} recovery blocks")
            },
        );
        par_files.push(path.clone());
        members.push(frame.bytes.as_slice());
        if defer && !spans.is_empty() {
            deferred.push(Deferred::OnDisk(path.clone(), spans));
        }
    }
    let reparsed = match censused {
        Some(_) => parsed,
        None => Par2Set::parse(&members),
    };
    match reparsed {
        Ok(mut set) => {
            // The parse saw the criticals only, so its own count is 0
            // here whatever the volumes hold; undeferred, this walk has
            // the answer and both readers of it take the same number.
            let recovery_validated = if defer {
                None
            } else {
                let bs = usize::try_from(set.block_size).unwrap_or(usize::MAX);
                let n = exps
                    .values()
                    .filter(|slice| par2::slice_fits_block(**slice, bs))
                    .count();
                set.recovery_blocks_seen = n;
                Some(n)
            };
            Ok(Loaded {
                data_dir: opts.basepath.clone().unwrap_or_else(|| dir.clone()),
                set,
                dir,
                par_files,
                deferred,
                recovery_validated,
            })
        }
        Err(_) => {
            sink.err("You must specify a Recovery file.");
            Err(crate::EXIT_INSUFFICIENT_DATA)
        }
    }
}

/// The repair path's load since 10 Sep 2026 (TODO 334): the same walk,
/// the same lines and the same `Loaded` as [`load`], with the recovery
/// volumes' bytes READ AND HASHED BY NOBODY HERE. The engine's own
/// packet scan already validated every packet in the directory on the
/// repair thread, and `report` is what it found; this reads each
/// candidate file's critical packets through the seeking walk
/// (`par2::sparse_frame`, the quiet verify's path), parses the set from
/// those, and prints each file's `Loaded N new packets including M
/// recovery blocks` line from the report - first-seen by packet MD5 in
/// THIS walk's order, which is the reference's order and not the
/// catalog's.
///
/// WHY. `load` reads every volume whole and MD5s every packet to count
/// them, on the main thread, while the engine hashes the very same
/// bytes on the worker: 2 GiB read and hashed twice on a 2 GiB set with
/// 100% parity, and once the engine's catalog scan was overlapped with
/// its verify pass that duplicate was the entire critical path of the
/// CLI-versus-driver gap (~11% at m=1,500 on an M3 Ultra; Codex's
/// measurement; TODO 334).
/// The report is what the engine hashed, so printing from it is
/// printing what the reference prints: a corrupt packet is absent from
/// both.
///
/// THE COUNT is the parser's own rule, re-spelt from the same inputs:
/// distinct exponents among the admitted files' recovery packets of
/// THIS set, longest slice per exponent, counted where
/// [`par2::slice_fits_block`] says the slice can serve. That is
/// `Par2Set::recovery_blocks_seen` over the files `load` would have
/// admitted, and it lands in the same field so every reader downstream
/// is unchanged; `deferred` is empty and `recovery_validated` is set,
/// so [`ensure_recovery`] never hashes a byte.
///
/// FALLS BACK to [`load`] - the whole read, whose output is the pinned
/// one - whenever it cannot answer identically: a present candidate the
/// seeking walk cannot frame (a header out of place), or one the report
/// does not mention (the catalog skipped it, or it is not a packet file
/// at all). Both are exact conditions, not heuristics, so the fast path
/// never prints a line the slow one would not.
pub fn load_scanned(
    opts: &Options,
    sink: &mut Sink,
    report: &par2repair::ScanReport,
) -> Result<Loaded, u8> {
    let (named, dir, want) = locate(opts, sink)?;
    let mut order = vec![named.clone()];
    order.extend(siblings(&dir, &named));
    // By FILE NAME rather than path: the catalog lists `dir/<name>` and
    // the named file is spelt however argv spelt it, and every candidate
    // here lives in `dir` (the glob is one directory deep, and so is the
    // catalog's flat scope).
    let by_name: std::collections::HashMap<&std::ffi::OsStr, &par2repair::PacketFileScan> = report
        .files
        .iter()
        .filter_map(|f| f.path.file_name().map(|n| (n, f)))
        .collect();
    // WHICH FILES TO OPEN AT ALL. The bytes this loader needs for
    // itself are the CRITICAL packets, and only the first copy of each:
    // a volume repeats the index's Main/FileDesc/IFSC packets and adds
    // its recovery slices, and the report already names every one of
    // those slices. Until 10 Sep 2026 every present file was framed
    // (`sparse_frame`, two `pread`s per recovery packet, on this thread,
    // while the engine sat in `after_survey` waiting for the answer):
    // 65,000 seeks over a 2 GiB / 100%-parity set, 75 ms of a 1.5 s
    // repair, measured phase for phase against the bench driver
    // (`research/PARFAST-CLI-GAP-RESIDUE-2026-09-10.md`). A file is
    // framed only when the report shows a non-recovery packet whose MD5
    // no earlier admitted file carried; for an ordinary set that is the
    // index and nothing else. The frames the parser sees are the same
    // packets in the same order - a duplicate the parser would have
    // deduped by MD5 is simply never read.
    //
    // A present candidate the report does not mention, or one that must
    // be framed and cannot be, sends the whole load down `load`, before
    // a line is printed - the exact conditions the old check applied.
    let mut crit_seen: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    let mut frames: Vec<Option<par2::SparseFrame>> = Vec::with_capacity(order.len());
    for p in &order {
        if !p.exists() {
            frames.push(None);
            continue;
        }
        let Some(scan) = p.file_name().and_then(|n| by_name.get(n)) else {
            return load(opts, sink);
        };
        let admitted = scan.packets.iter().any(|q| q.set_id == want);
        let mut need = false;
        if admitted {
            for q in scan.packets.iter().filter(|q| q.recovery.is_none()) {
                if crit_seen.insert(q.md5) {
                    need = true;
                }
            }
        }
        if !need {
            frames.push(None);
            continue;
        }
        let framed = std::fs::File::open(p)
            .ok()
            .and_then(|f| f.metadata().ok().map(|m| (f, m.len())))
            .and_then(|(f, len)| par2::sparse_frame(&f, len));
        match framed {
            Some(fr) => frames.push(Some(fr)),
            None => return load(opts, sink),
        }
    }

    let present: Vec<&[u8]> = frames
        .iter()
        .flatten()
        .map(|fr| fr.bytes.as_slice())
        .collect();
    let (parsed, _censuses) = par2::Par2Set::parse_censused(&present);
    let on_named_set = matches!(&parsed, Ok(set) if set.recovery_set_id == want);
    let mut seen: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    let mut members: Vec<&[u8]> = Vec::new();
    let mut par_files = Vec::new();
    // Exponent -> longest slice, over the admitted files' packets of
    // THIS set: the parser's own tally, and judged below the same way.
    let mut exps: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for (path, frame) in order.iter().zip(&frames) {
        if !path.exists() {
            continue;
        }
        let scan = path
            .file_name()
            .and_then(|n| by_name.get(n))
            .expect("every present candidate was checked against the report above");
        // Membership is the same test the other two loaders apply: a
        // sibling carrying none of THIS set's packets is not ours,
        // however its name globbed (see `load_with`).
        if !scan.packets.iter().any(|p| p.set_id == want) {
            continue;
        }
        let name = display_name(&dir, path);
        sink.line(Level::Terse, &format!("Loading \"{name}\"."));
        let mut new = 0usize;
        let mut new_recovery = 0usize;
        for p in &scan.packets {
            if seen.insert(p.md5) {
                new += 1;
                if p.recovery.is_some() {
                    new_recovery += 1;
                }
            }
            if let Some(r) = p.recovery.filter(|_| p.set_id == want) {
                let slice = usize::try_from(r.slice_len).unwrap_or(usize::MAX);
                let e = exps.entry(r.exponent).or_insert(0);
                *e = (*e).max(slice);
            }
        }
        sink.line(
            Level::Normal,
            &if new == 0 {
                "No new packets found".to_string()
            } else if new_recovery == 0 {
                format!("Loaded {new} new packets")
            } else {
                format!("Loaded {new} new packets including {new_recovery} recovery blocks")
            },
        );
        par_files.push(path.clone());
        if let Some(frame) = frame {
            members.push(frame.bytes.as_slice());
        }
    }
    let reparsed = if on_named_set {
        parsed
    } else {
        Par2Set::parse(&members)
    };
    match reparsed {
        Ok(mut set) => {
            let bs = usize::try_from(set.block_size).unwrap_or(usize::MAX);
            let recovery_blocks = exps
                .values()
                .filter(|n| par2::slice_fits_block(**n, bs))
                .count();
            set.recovery_blocks_seen = recovery_blocks;
            Ok(Loaded {
                data_dir: opts.basepath.clone().unwrap_or_else(|| dir.clone()),
                set,
                dir,
                par_files,
                deferred: Vec::new(),
                recovery_validated: Some(recovery_blocks),
            })
        }
        Err(_) => {
            sink.err("You must specify a Recovery file.");
            Err(crate::EXIT_INSUFFICIENT_DATA)
        }
    }
}

/// The set's recovery block count, settled: what the load verified plus
/// every deferred packet that checks now, from the bytes the load kept,
/// hashed in parallel and then released. Runs once; a load that
/// deferred nothing answers from the parse.
/// Callers reach for this only when a verdict needs the count - a
/// damaged survey - which is the whole point of deferring.
pub fn ensure_recovery(loaded: &mut Loaded) -> usize {
    if let Some(n) = loaded.recovery_validated {
        return n;
    }
    let mut count = loaded.set.recovery_blocks_seen;
    if !loaded.deferred.is_empty() {
        let mut exps: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
        for d in std::mem::take(&mut loaded.deferred) {
            let found = match d {
                Deferred::Resident(bytes, spans) => par2::validate_recovery_spans(
                    &bytes,
                    &spans,
                    &loaded.set.recovery_set_id,
                    loaded.set.block_size,
                ),
                Deferred::OnDisk(path, spans) => par2::validate_recovery_file(
                    &path,
                    &spans,
                    &loaded.set.recovery_set_id,
                    loaded.set.block_size,
                ),
            };
            for (e, data) in found {
                let v = exps.entry(e).or_insert(0);
                *v = (*v).max(data);
            }
        }
        count += exps.len();
    }
    loaded.recovery_validated = Some(count);
    count
}

/// The base name a set's volumes share: the file name without `.par2`,
/// then without one trailing `.volNNN+NNN` component.
///
/// It used to be the name cut at its FIRST `.`, with a comment claiming
/// that was the reference's own rule. It is not. par2cmdline strips a
/// trailing `.par2`, then strips a trailing `.volNNN+NNN` component and
/// nothing else. The difference only shows on a DOTTED release name, and
/// there it refuses good sets: `Show.Name.S01E01.par2` cut at the first
/// dot is `Show`, which also prefix-matches `Show.Name.S01E02.par2`, so
/// a season folder loads two Main packets, [`Par2Set::parse`] returns
/// `MixedRecoverySets`, and parfast answers a repairable set with
/// "You must specify a Recovery file." and exit 4.
///
/// Both halves of the old rule mattered, so both are kept: this still
/// takes `set.vol00+1.par2` to `set`, which is what makes a volume named
/// on the command line find its own index.
fn set_stem(named: &Path) -> String {
    let name = named
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let base = name
        .len()
        .checked_sub(5)
        .filter(|_| name.to_ascii_lowercase().ends_with(".par2"))
        .map_or(name, |cut| &name[..cut]);
    // `.volNNN+NNN` / `.volNNN-NNN`, and only as the LAST component, so
    // a member called `vol2.of.3` in the middle of a name is untouched.
    match base.rsplit_once('.') {
        Some((head, tail)) if is_volume_component(tail) => head.to_string(),
        _ => base.to_string(),
    }
}

/// `volNNN+NNN` or `volNNN-NNN`, the volume component par2cmdline adds.
fn is_volume_component(tail: &str) -> bool {
    let Some(rest) = tail
        .get(..3)
        .filter(|p| p.eq_ignore_ascii_case("vol"))
        .map(|_| &tail[3..])
    else {
        return false;
    };
    let Some(at) = rest.find(['+', '-']) else {
        return false;
    };
    let (lo, hi) = (&rest[..at], &rest[at + 1..]);
    !lo.is_empty()
        && !hi.is_empty()
        && lo.bytes().all(|b| b.is_ascii_digit())
        && hi.bytes().all(|b| b.is_ascii_digit())
}

/// `<stem>*.par2` beside the named file, sorted, the named file
/// included - see [`load`] for why the duplicate matters.
fn siblings(dir: &Path, named: &Path) -> Vec<PathBuf> {
    let stem = set_stem(named);
    if stem.is_empty() {
        return Vec::new();
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let Some(n) = p.file_name().and_then(|s| s.to_str()) else {
                return false;
            };
            n.starts_with(&stem) && n.to_ascii_lowercase().ends_with(".par2")
        })
        .collect();
    out.sort();
    out
}

/// How a path is printed: relative to the set's directory, so the tables
/// carry `set.vol00+1.par2` and not an absolute path that would differ
/// on every box.
pub fn display_name(dir: &Path, path: &Path) -> String {
    path.strip_prefix(dir)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// Verify every member, printing the reference's `Opening` and `Target`
/// lines, and return the accounting.
pub fn survey(loaded: &Loaded, opts: &Options, sink: &mut Sink) -> Survey {
    survey_bits(loaded, opts, sink).0
}

/// What a LONG-LIVED caller is shown while the verify pass runs, and
/// the one point at which it may call the pass off.
///
/// The in-process caller needs neither: it reads its table when the
/// pass is done. A GUI needs both - a progress bar over a 200 GiB set
/// that says nothing for eleven minutes is indistinguishable from a
/// hang, and a Cancel button that cannot be honoured until the last
/// member is hashed is not a Cancel button. Since 12 Sep 2026 the binary
/// is a caller of the second kind too: `control::CliWatch` is Ctrl-C and
/// a `Scanning:` meter.
///
/// Both methods are called from the HASHING LANES, so an implementation
/// must be `Sync` and must not assume an order: `member_done` fires as
/// each member finishes, which is not the set's order. Blocking inside
/// [`should_continue`](Self::should_continue) is how a pause is
/// implemented and is safe HERE - a lane holds no engine scope between
/// members - but it parks a whole lane, so a paused verify is a stopped
/// verify and not a slowed one, which is what a Pause button means.
pub trait SurveyWatch: Sync {
    /// Before a lane picks up its next member. `false` abandons the
    /// pass: nothing has been written (a verify only reads), so the
    /// directory is untouched and [`survey_watched`] answers `None`.
    fn should_continue(&self) -> bool {
        true
    }
    /// One more member has been hashed. `done` counts members finished
    /// across every lane, out of `total` that exist on disk.
    fn member_done(&self, _done: usize, _total: usize) {}
}

/// The watch a caller that wants neither passes - the in-process one.
impl SurveyWatch for () {}

/// [`survey_bits`] that reports its progress and can be called off.
///
/// `None` is the caller's own refusal coming back, and it is the ONLY
/// thing it means: an I/O failure is a member verdict (`Missing`), not
/// an abandonment.
pub fn survey_watched(
    loaded: &Loaded,
    opts: &Options,
    sink: &mut Sink,
    watch: &dyn SurveyWatch,
) -> Option<(Survey, Vec<Vec<bool>>)> {
    let (survey, bits, stopped) = survey_inner(loaded, opts, sink, watch);
    (!stopped).then_some((survey, bits))
}

/// [`survey`], plus the per-block presence bitmap it already computed.
///
/// One pass, two answers. The bitmap is `scan_members_for_blocks`'s
/// output - the aligned grid reconciled with the engine's rolling scan -
/// indexed by the SET's file order and, within a file, by block index;
/// a missing member gets an empty row. It is what a block map DRAWS,
/// and until 12 Sep 2026 the only way to get it was to run the whole
/// verify a second time or to read `Pass1Out.present` (a `#[doc(hidden)]`
/// field whose tri-state a second reader would have to re-derive).
///
/// [`survey`] is this function with the bitmap dropped, deliberately:
/// two entry points that each decided a verdict would be two answers to
/// "is this file damaged", which is the thing this module exists not to
/// do.
pub fn survey_bits(loaded: &Loaded, opts: &Options, sink: &mut Sink) -> (Survey, Vec<Vec<bool>>) {
    let (survey, bits, _) = survey_inner(loaded, opts, sink, &());
    (survey, bits)
}

/// The one verify pass every entry above is a view of. The third
/// element is the watch's refusal.
fn survey_inner(
    loaded: &Loaded,
    opts: &Options,
    sink: &mut Sink,
    watch: &dyn SurveyWatch,
) -> (Survey, Vec<Vec<bool>>, bool) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let bs = loaded.set.block_size;
    let mut total_blocks = 0usize;

    // The plan, in the SET's own order, which is the order every line
    // below is printed in. Hashing happens off this order; printing
    // never does.
    let mut names: Vec<&str> = Vec::with_capacity(loaded.set.files.len());
    let mut counts: Vec<usize> = Vec::with_capacity(loaded.set.files.len());
    let mut paths: Vec<Option<PathBuf>> = Vec::with_capacity(loaded.set.files.len());
    for file in &loaded.set.files {
        let blocks = if bs == 0 {
            0
        } else {
            // `try_from`, not `as`: `file.length` is a wire-supplied
            // FileDesc length, and a usize is 32 bits on armv7 - so the
            // count truncated per member there, and the running sum
            // below then panicked under overflow checks or reported a
            // silently wrong "You have X out of Y data blocks". A count
            // that does not fit the address space is a set this host
            // cannot verify either way; saturating says so without
            // inventing a small number.
            usize::try_from(file.length.div_ceil(bs)).unwrap_or(usize::MAX)
        };
        total_blocks = total_blocks.saturating_add(blocks);
        let path = loaded.data_path(&file.name);
        names.push(&file.name);
        counts.push(blocks);
        paths.push(path.exists().then_some(path));
    }

    // Members that exist are hashed CONCURRENTLY. Whole-file MD5 is
    // serial within one member and independent across members, so this
    // is the only axis that was left on the table.
    // BIGGEST FIRST, which is both a tail guard and what makes the lane
    // plan below mean anything: it hands worker `w` the share of the
    // machine that member `w` deserves, so the two must agree about which
    // member that is. This walk used to be in set order, which is why the
    // survey measured this door spreading 3.71-5.58 s on the skewed corpus
    // where `verify_dir`, which already sorted, sat stably at 3.87.
    // PRINTING is unaffected - every line below reads `verdicts[i]`, in the
    // set's own order.
    let mut present: Vec<usize> = (0..paths.len()).filter(|&i| paths[i].is_some()).collect();
    present.sort_unstable_by_key(|&i| std::cmp::Reverse(loaded.set.files[i].length));
    // One lane budget, split BY SIZE rather than uniformly. `machine /
    // width` handed every member the same width, which on a set with at
    // least as many members as the box has cores is one lane for all of
    // them INCLUDING THE LARGEST - and it stayed one after every other lane
    // had gone idle. That cost 8.6x on a 3 GiB member beside twenty 50 MiB
    // ones; `nzbkit::par2::lane_plan` carries the rule, the model and the
    // measurements (entry 1 of
    // research/SERIAL-BOUND-SURVEY-2026-09-16.md). `-T` is still a ceiling
    // on the outer width, and `-T1` still hands one member at a time the
    // whole machine.
    let sizes: Vec<u64> = present
        .iter()
        .map(|&i| loaded.set.files[i].length)
        .collect();
    let lane_widths =
        nzbkit::par2::lane_plan(&sizes, threads(opts), file_threads(opts, present.len()));
    let width = lane_widths.len().max(1);

    // `block_size == 0` never reaches here - the Main-packet parser
    // refuses it (`par2/packet.rs`, the `block_size == 0` arm), so a set
    // that parsed has a slice size of at least 4. The guard is here
    // because the alternative to a dead branch is `verify_pass1`
    // dividing by a WIRE-SUPPLIED zero, and a panic on a crafted file is
    // worse than an unreachable arm. Zero slices means nothing is
    // verifiable, which is the verdict the `None` below already carries.
    let slice = usize::try_from(bs).ok().filter(|&n| n > 0);

    let cursor = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut verdicts: Vec<Option<Pass1Out>> = (0..paths.len()).map(|_| None).collect();
    if let Some(slice) = slice.filter(|_| !present.is_empty()) {
        // Each lane keeps its OWN results and hands them back through the
        // scope. No shared lock on the hot path, and so no question about
        // what a poisoned one would mean here.
        // Shared by reference into every lane: the `move` below carries
        // that lane's own width, not the queue.
        let (present, paths, cursor, done, stop) = (&present, &paths, &cursor, &done, &stop);
        let lanes: Vec<Vec<(usize, Option<Pass1Out>)>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..width)
                .map(|w| {
                    // This lane's share of the one budget, for every member
                    // it claims. A lane that started on the dominant member
                    // keeps its width for the short ones it picks up after.
                    let inner = lane_widths.get(w).copied().unwrap_or(1);
                    scope.spawn(move || {
                        let mut mine = Vec::new();
                        loop {
                            // The refusal is checked BEFORE the member is
                            // claimed, so a stopped pass leaves the
                            // remaining members unclaimed rather than
                            // claimed-and-unverified: the `verdicts`
                            // slot of anything this lane skips stays
                            // `None`, and a `None` slot is `Missing`,
                            // which is a verdict nobody should read off
                            // an abandoned pass. `survey_watched`
                            // answers `None` for exactly that reason.
                            if !watch.should_continue() {
                                stop.store(true, Ordering::Relaxed);
                                break;
                            }
                            let k = cursor.fetch_add(1, Ordering::Relaxed);
                            let Some(&i) = present.get(k) else { break };
                            let path = paths[i].as_ref().expect("present index has a path");
                            // An I/O error and a file that vanished
                            // between the `exists` probe above and
                            // this open are the same answer to the
                            // caller - nothing was verified - and
                            // that is what `None` means below. The
                            // engine reports the second as
                            // `exists: false` rather than an `Err`,
                            // so both are folded here.
                            let got =
                                par2repair::verify_pass1(path, &loaded.set.files[i], slice, inner)
                                    .ok()
                                    .filter(|p| p.exists);
                            mine.push((i, got));
                            watch.member_done(
                                done.fetch_add(1, Ordering::Relaxed) + 1,
                                present.len(),
                            );
                        }
                        mine
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| match h.join() {
                    Ok(mine) => mine,
                    // A lane that panicked must panic the run, exactly as
                    // the serial walk did. Swallowing it would report the
                    // members it never reached as MISSING, which is a
                    // wrong answer dressed as a verdict.
                    Err(payload) => std::panic::resume_unwind(payload),
                })
                .collect()
        });
        for lane in lanes {
            for (i, got) in lane {
                verdicts[i] = got;
            }
        }
    }

    // A REFUSED PASS PRINTS NOTHING AND DECIDES NOTHING. Everything
    // below this line - the rolling scan, the `Opening:` lines, the
    // per-member verdicts - reads `verdicts`, and a stopped pass left
    // part of it unvisited. Reporting from it would call every member a
    // lane never reached `Missing`.
    if stop.load(Ordering::Relaxed) {
        return (
            Survey {
                targets: Vec::new(),
                total_blocks,
                available_blocks: 0,
                recovery_blocks: loaded.set.recovery_blocks_seen,
            },
            Vec::new(),
            true,
        );
    }

    // THE ROLLING SCAN, over whatever the aligned pass above could not
    // prove. par2cmdline's default verify rolls a block-sized CRC32
    // window over every source file, so a member carrying a prefix or a
    // mid-file insertion still reports every block present at its real
    // offset; the aligned grid alone reported `Found 0 of 30 data
    // blocks` on a set the reference reads as `Found 30 of 30`, and the
    // repair behind it then refused work the reference completes
    // (`research/CLI-SUBSTITUTION-2026-09-03.md`, G4). It is the
    // ENGINE's scan - the same window `adopt::sliding_scan` runs for a
    // repair - and not a second spelling of it here.
    //
    // A CLEAN SET PAYS NOTHING: the engine's door opens no file when
    // every member is already proven whole, so the ordinary verify is
    // the same two passes it always was.
    let found = par2repair::scan_members_for_blocks(
        &loaded.set.files,
        &paths,
        &(0..names.len())
            .map(|i| match &verdicts[i] {
                Some(p) => proven_bits(p, counts[i]),
                None => Vec::new(),
            })
            .collect::<Vec<_>>(),
        usize::try_from(bs).unwrap_or(0),
    );

    // And the output is emitted in the set's order, which is what makes
    // this change invisible to a script and to the conformance table:
    // nothing is interleaved between these lines, so the same bytes come
    // out in the same sequence as the serial walk produced.
    let mut targets = Vec::with_capacity(names.len());
    let mut available = 0usize;
    for i in 0..names.len() {
        let name = names[i].to_string();
        if paths[i].is_none() {
            targets.push((name, Target::Missing));
            continue;
        }
        sink.line(Level::Normal, &format!("Opening: \"{}\"", names[i]));
        let blocks = counts[i];
        match &verdicts[i] {
            Some(p) => {
                let have = found[i].iter().filter(|&&ok| ok).count().min(blocks);
                available += have;
                targets.push((
                    name,
                    if p.intact {
                        Target::Found
                    } else {
                        Target::Damaged {
                            have,
                            total: blocks,
                        }
                    },
                ));
            }
            None => targets.push((name, Target::Missing)),
        }
    }
    (
        Survey {
            targets,
            total_blocks,
            available_blocks: available,
            recovery_blocks: loaded.set.recovery_blocks_seen,
        },
        found,
        false,
    )
}

/// [`survey`]'s answer built from the ENGINE's verify pass instead of a
/// second one of our own, for the repair path.
///
/// `repair` used to survey the whole set here and then hand the
/// directory to `par2repair`, which surveys it AGAIN before it folds -
/// two complete passes over every payload byte on every damaged repair,
/// where the engine's own harness pays one. Measured on the 1 GiB /
/// 21-member rig corpus in retired instructions (4 Sep 2026), the
/// duplicate pass was 26.0G of the 3-block leg's 40.4G and 29.2G of the
/// 101-block leg's 106.3G. `par2repair::repair_dir_set_surveyed` shows
/// us its pass instead, and this turns that report into the same
/// [`Survey`] the printing already speaks.
///
/// The lines are OURS and unchanged: emitted in the SET's order (which
/// the engine's Main-packet order need not match), an `Opening:` line
/// only for a member that is actually there, and the verdict rule
/// member for member as [`survey`] applies it - `intact` is the engine's
/// name for "the FileDesc whole-file MD5 matched at the declared
/// length", which is exactly this module's `Target::Found` - the same
/// `verify_pass1` verdict, EARLY STOP included, that [`survey`] itself
/// reads through [`present_blocks`]. The two must agree or one tool
/// prints two answers for one set, which is why neither decides the
/// withheld digest.
///
/// `None` when the report cannot be matched to the set one-for-one -
/// two FileDescs sharing a name, or a name the engine never described.
/// Both are answerable only by looking at the bytes ourselves, so the
/// caller falls back to [`survey`]. Guessing here would print a verdict
/// about the wrong member.
pub fn survey_from_engine(
    loaded: &Loaded,
    members: &[nzbkit::par2repair::MemberSurvey],
    sink: &mut Sink,
) -> Option<Survey> {
    let bs = loaded.set.block_size;
    let mut by_name: std::collections::HashMap<&str, &nzbkit::par2repair::MemberSurvey> =
        std::collections::HashMap::with_capacity(members.len());
    for m in members {
        // A duplicate name makes "which member is this line about"
        // unanswerable from the report alone.
        if by_name.insert(m.name.as_str(), m).is_some() {
            return None;
        }
    }
    // Resolve EVERY member before printing a line. Bailing part way
    // through would leave a half-printed `Opening:` run behind, and the
    // caller's fallback re-runs the whole survey and prints it again.
    let resolved: Vec<&nzbkit::par2repair::MemberSurvey> = loaded
        .set
        .files
        .iter()
        .map(|f| by_name.get(f.name.as_str()).copied())
        .collect::<Option<Vec<_>>>()?;
    // THE ROLLING SCAN, exactly as [`survey`] runs it and for the same
    // reason - the repair prints the SAME `Target:` lines and then
    // decides on them, so a count that stops at the aligned grid here
    // refuses work the reference completes (G4; see [`survey`]).
    //
    // WHY NOTHING IS DECLARED PROVEN for a member that is not intact,
    // where [`survey`] hands the scan its real bitmap: a
    // [`nzbkit::par2repair::MemberSurvey`] carries a COUNT and not a
    // map, and guessing WHICH slices that count refers to would put
    // the wrong slices in the scan's wanted set. It costs nothing to
    // be honest about it - the scan reads a candidate file whole
    // whatever is wanted from it, and the rolling window passes over
    // the aligned offsets too, so the blocks the engine's pass already
    // proved are re-found where they sit.
    let paths: Vec<Option<PathBuf>> = resolved
        .iter()
        .zip(&loaded.set.files)
        .map(|(m, f)| m.exists.then(|| loaded.data_path(&f.name)))
        .collect();
    let proven: Vec<Vec<bool>> = resolved
        .iter()
        .zip(&loaded.set.files)
        .map(|(m, f)| {
            let blocks = if bs == 0 {
                0
            } else {
                f.length.div_ceil(bs) as usize
            };
            if m.intact {
                vec![true; blocks]
            } else {
                Vec::new()
            }
        })
        .collect();
    let found = par2repair::scan_members_for_blocks(
        &loaded.set.files,
        &paths,
        &proven,
        usize::try_from(bs).unwrap_or(0),
    );

    let mut targets = Vec::with_capacity(loaded.set.files.len());
    let mut total_blocks = 0usize;
    let mut available = 0usize;
    for (i, (file, m)) in loaded.set.files.iter().zip(resolved).enumerate() {
        let blocks = if bs == 0 {
            0
        } else {
            // `try_from`, not `as`: `file.length` is a wire-supplied
            // FileDesc length, and a usize is 32 bits on armv7 - so the
            // count truncated per member there, and the running sum
            // below then panicked under overflow checks or reported a
            // silently wrong "You have X out of Y data blocks". A count
            // that does not fit the address space is a set this host
            // cannot verify either way; saturating says so without
            // inventing a small number.
            usize::try_from(file.length.div_ceil(bs)).unwrap_or(usize::MAX)
        };
        total_blocks = total_blocks.saturating_add(blocks);
        let name = file.name.clone();
        if !m.exists {
            targets.push((name, Target::Missing));
            continue;
        }
        sink.line(Level::Normal, &format!("Opening: \"{}\"", file.name));
        if m.intact {
            available += blocks;
            targets.push((name, Target::Found));
        } else {
            let have = found[i]
                .iter()
                .filter(|&&ok| ok)
                .count()
                .max(m.blocks_present)
                .min(blocks);
            available += have;
            targets.push((
                name,
                Target::Damaged {
                    have,
                    total: blocks,
                },
            ));
        }
    }
    Some(Survey {
        targets,
        total_blocks,
        available_blocks: available,
        recovery_blocks: loaded.set.recovery_blocks_seen,
    })
}

/// How many of a member's declared blocks the engine's pass found, and
/// the ONE place [`Pass1Out`]'s tri-state is read.
///
/// The three arms are not interchangeable and getting them wrong moves
/// a printed line:
///
/// * `intact` - the FileDesc MD5 matched over exactly the declared
///   length. This is the only verdict that prints `found.`, and it is
///   the exact condition `par2::verify_file_path`'s `md5_ok` carried,
///   which is why swapping the entry point left the table alone.
/// * `clean` without `intact` - a member LONGER than its declared
///   length whose declared prefix hashes correctly. Every declared
///   block IS present (the reference still calls it damaged and fixes
///   it by truncating), and the engine returns `present: None` there
///   precisely because the whole-file proof already answered for every
///   block. Counting the `None` as zero would report
///   `Found 0 of N data blocks` for a file that is entirely there.
/// * neither - `present` carries the per-block CRC32 verdicts. A set
///   with no IFSC packets has no bitmap at all and nothing is provable
///   block by block, which is zero.
fn present_blocks(pass: &Pass1Out, blocks: usize) -> usize {
    proven_bits(pass, blocks).iter().filter(|&&ok| ok).count()
}

/// The same three arms as [`present_blocks`], as a BITMAP rather than a
/// count, because the rolling scan needs to know WHICH slices are still
/// owed and not merely how many.
///
/// One rule, one place: [`present_blocks`] is this function counted, so
/// the tri-state above cannot be read two ways.
fn proven_bits(pass: &Pass1Out, blocks: usize) -> Vec<bool> {
    if pass.clean {
        return vec![true; blocks];
    }
    let mut bits = vec![false; blocks];
    if let Some(present) = pass.present.as_ref() {
        for (b, &ok) in bits.iter_mut().zip(present.iter()) {
            *b = ok;
        }
    }
    bits
}

/// Verify ONE member and print its `Opening` and `Target` lines. The
/// post-repair pass uses this rather than a second whole-set survey:
/// the reference re-opens only the files it wrote, so a full survey
/// would put an `Opening:` line under every clean member as well.
pub fn verify_one(loaded: &Loaded, opts: &Options, name: &str, sink: &mut Sink) -> Target {
    let Some(file) = loaded.set.files.iter().find(|f| f.name == name) else {
        return Target::Missing;
    };
    let bs = loaded.set.block_size;
    let blocks = if bs == 0 {
        0
    } else {
        // See the note at `plan_targets`: a wire length narrowed
        // with `as` truncates on a 32-bit host.
        usize::try_from(file.length.div_ceil(bs)).unwrap_or(usize::MAX)
    };
    let path = loaded.data_path(&file.name);
    if !path.exists() {
        return Target::Missing;
    }
    sink.line(Level::Normal, &format!("Opening: \"{}\"", file.name));
    // Same entry point as `survey`, for the same reason: one MD5 chain
    // over the member rather than two. This pass runs over the files the
    // repair just WROTE, so it is not the hot one, but a second verifier
    // here would be a second answer to "is this file damaged".
    let Some(slice) = usize::try_from(bs).ok().filter(|&n| n > 0) else {
        return Target::Missing;
    };
    match par2repair::verify_pass1(&path, file, slice, threads(opts)) {
        Ok(pass) if !pass.exists => Target::Missing,
        Ok(pass) if pass.intact => Target::Found,
        Ok(pass) => Target::Damaged {
            have: present_blocks(&pass, blocks),
            total: blocks,
        },
        Err(_) => Target::Missing,
    }
}

/// The `Target:` lines, in the set's own order. The harness sorts this
/// family before comparing, so the ORDER here is not load-bearing; the
/// SET of lines and their exact wording are.
pub fn print_targets(survey: &Survey, sink: &mut Sink) {
    for (name, t) in &survey.targets {
        let line = match t {
            Target::Found => format!("Target: \"{name}\" - found."),
            Target::Missing => format!("Target: \"{name}\" - missing."),
            Target::Damaged { have, total } => {
                format!("Target: \"{name}\" - damaged. Found {have} of {total} data blocks.")
            }
        };
        sink.line(Level::Terse, &line);
    }
}

/// The set summary par2cmdline prints before it starts verifying.
pub fn print_set_summary(loaded: &Loaded, sink: &mut Sink) {
    if !sink.shows(Level::Normal) {
        return;
    }
    let total_bytes: u64 = loaded.set.files.iter().map(|f| f.length).sum();
    let blocks: u64 = if loaded.set.block_size == 0 {
        0
    } else {
        loaded
            .set
            .files
            .iter()
            .map(|f| f.length.div_ceil(loaded.set.block_size))
            .sum()
    };
    sink.line(Level::Normal, "");
    sink.line(
        Level::Normal,
        &format!(
            "There are {} recoverable files and {} other files.",
            loaded.set.files.len(),
            loaded.set.nonrecovery.len()
        ),
    );
    sink.line(
        Level::Normal,
        &format!("The block size used was {} bytes.", loaded.set.block_size),
    );
    sink.line(
        Level::Normal,
        &format!("There are a total of {blocks} data blocks."),
    );
    sink.line(
        Level::Normal,
        &format!("The total size of the data files is {total_bytes} bytes."),
    );
    sink.line(Level::Normal, "");
    sink.line(Level::Normal, "Verifying source files:");
    sink.line(Level::Normal, "");
}

/// The verdict block a verify ends on, and the exit code that goes with
/// it. The ORDER is the reference's: the extra-file scan, then the
/// verdict sentence, then the census that explains it. `repair` prints the first half of the same block and then carries
/// on, which is why the tail is a separate function.
pub fn print_verdict(loaded: &Loaded, survey: &Survey, sink: &mut Sink) -> u8 {
    sink.line(Level::Terse, "");
    if !survey.damaged() {
        sink.line(
            Level::Terse,
            "All files are correct, repair is not required.",
        );
        return crate::EXIT_SUCCESS;
    }
    print_extra_scan(loaded, survey, sink);
    sink.line(Level::Terse, "Repair is required.");
    print_damage_detail(survey, sink);
    if survey.repairable() {
        sink.line(Level::Terse, "Repair is possible.");
        print_repairable_detail(survey, sink);
        crate::EXIT_REPAIR_POSSIBLE
    } else {
        sink.line(Level::Terse, "Repair is not possible.");
        sink.line(
            Level::Terse,
            &format!(
                "You need {} more recovery blocks to be able to repair.",
                survey.owed() - survey.recovery_blocks
            ),
        );
        crate::EXIT_REPAIR_NOT_POSSIBLE
    }
}

/// The per-file damage census.
///
/// DEFAULT level, not `-v`. The captured `sweep/B` row passes neither
/// `-q` nor `-v` and carries all five of these lines, and `verify-damaged`
/// passes `-q` and carries none of them, which fixes the rung exactly.
pub fn print_damage_detail(survey: &Survey, sink: &mut Sink) {
    if !sink.shows(Level::Normal) {
        return;
    }
    let damaged = survey
        .targets
        .iter()
        .filter(|(_, t)| matches!(t, Target::Damaged { .. }))
        .count();
    let ok = survey
        .targets
        .iter()
        .filter(|(_, t)| matches!(t, Target::Found))
        .count();
    let missing = survey
        .targets
        .iter()
        .filter(|(_, t)| matches!(t, Target::Missing))
        .count();
    if damaged > 0 {
        sink.line(
            Level::Normal,
            &format!("{damaged} file(s) exist but are damaged."),
        );
    }
    if missing > 0 {
        sink.line(Level::Normal, &format!("{missing} file(s) are missing."));
    }
    if ok > 0 {
        sink.line(Level::Normal, &format!("{ok} file(s) are ok."));
    }
    sink.line(
        Level::Normal,
        &format!(
            "You have {} out of {} data blocks available.",
            survey.available_blocks, survey.total_blocks
        ),
    );
    sink.line(
        Level::Normal,
        &format!(
            "You have {} recovery blocks available.",
            survey.recovery_blocks
        ),
    );
}

/// Files in the data directory that are not this set's own recovery
/// files and are not sitting at a FileDesc name - the engine's adoption
/// candidates, and what "Scanning extra files:" is a header for.
///
/// This is a NAME walk only. It answers "is there anything here the
/// engine could adopt", which is all its two callers need: whether to
/// let the engine decide, and what to print. Deciding whether a
/// candidate actually MATCHES is the engine's `adopt_blocks`, by
/// checksum, and duplicating that here would be a second answer to the
/// same question over the same bytes.
///
/// AND IT IS NOT THE ROLLING SCAN, which a reader has mistaken it for
/// once already: a member sitting AT its FileDesc name is claimed here
/// and so never a candidate, however far its bytes have been shifted
/// inside it. That question - "is this member's block anywhere in this
/// file" - belongs to [`survey`] and is answered by
/// `nzbkit::par2repair::scan_members_for_blocks`. Reading this walk as
/// the whole of parfast's misplaced-block story is what left G4 open
/// (`research/CLI-SUBSTITUTION-2026-09-03.md`).
pub fn extra_candidates(loaded: &Loaded, survey: &Survey) -> Vec<PathBuf> {
    let claimed: std::collections::HashSet<PathBuf> = survey
        .targets
        .iter()
        .map(|(name, _)| loaded.data_path(name))
        .collect();
    let par: std::collections::HashSet<&PathBuf> = loaded.par_files.iter().collect();
    let Ok(rd) = std::fs::read_dir(&loaded.data_dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| !claimed.contains(p) && !par.contains(p))
        // A `.par2` in the data directory belongs to some set, ours or a
        // neighbour's, and is never payload.
        .filter(|p| {
            !p.extension()
                .and_then(|s| s.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("par2"))
        })
        // The `<name>.1` copies a previous repair left are our own
        // backups, not somebody's stray payload.
        .filter(|p| {
            !p.file_name()
                .and_then(|s| s.to_str())
                .and_then(|n| n.rsplit_once('.'))
                .is_some_and(|(head, tail)| {
                    tail.len() == 1
                        && tail.bytes().all(|b| b.is_ascii_digit())
                        && claimed.contains(&loaded.data_path(head))
                })
        })
        .collect();
    out.sort();
    out
}

/// The extra-file scan announcement, which the reference prints only
/// when something is actually wrong - `verify-intact-verbose` runs at
/// the same level and has no such line.
///
/// It used to print this header over a walk of NOTHING. The header is
/// the reference's, and on the reference it is what an actual scan of
/// the working directory prints under - the scan that lets a payload
/// under a hash name be adopted. Printing the header while scanning
/// nothing made the drop-in claim something it did not do; the files
/// are now named under it.
pub fn print_extra_scan(loaded: &Loaded, survey: &Survey, sink: &mut Sink) {
    if !survey.damaged() || !sink.shows(Level::Normal) {
        return;
    }
    sink.line(Level::Normal, "Scanning extra files:");
    sink.line(Level::Normal, "");
    for path in extra_candidates(loaded, survey) {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        sink.line(Level::Normal, &format!("Opening: \"{name}\""));
    }
    sink.line(Level::Normal, "");
}

/// The excess/needed pair, `-v` only, printed between "Repair is
/// required." and "Repair is possible.".
fn print_repairable_detail(survey: &Survey, sink: &mut Sink) {
    if !sink.shows(Level::Normal) {
        return;
    }
    let owed = survey.owed();
    sink.line(
        Level::Normal,
        &format!(
            "You have an excess of {} recovery blocks.",
            survey.recovery_blocks.saturating_sub(owed)
        ),
    );
    if owed > 0 {
        sink.line(
            Level::Normal,
            &format!("{owed} recovery blocks will be used to repair."),
        );
    }
}

/// `-p`: remove the backup files a repair left and then the par files
/// themselves. Only ever called on a clean or repaired set.
///
/// `created` is the provenance list: the backup copies THIS run made
/// (`repair::back_up_damaged`), and nothing else. It used to be derived
/// instead - synthesise `<member>.1` through `<member>.9` for every
/// member of the set, keep whatever `exists()`, delete it - and a name
/// is not provenance. A set that legitimately protects both `payload.bin`
/// and `payload.bin.1` had its SECOND MEMBER deleted by `parfast r -p`
/// on a CLEAN set, the recovery volumes went in the same run, and every
/// step exited 0: unrecoverable data loss with no diagnostic. Any
/// pre-existing numbered file went the same way, member or not.
///
/// This is also what the reference does. par2cmdline's `-p` removes its
/// own `backuplist`, populated as it renames each damaged original
/// aside; it never walks the directory for things that look like
/// backups. So a second `-p` run over an already-repaired set leaves the
/// earlier `.1` alone on both, and the captured `repair-purge` row -
/// whose `rand.bin.1` this run made - is unchanged.
///
/// The protected-member screen below is belt to that braces. Provenance
/// alone would do it, but a delete list is the one place in this crate
/// where being wrong costs the payload, so a path that is a member's is
/// refused however it got here.
pub fn purge(loaded: &Loaded, created: &[PathBuf], sink: &mut Sink) {
    sink.line(Level::Terse, "");
    // The backup half is announced ONLY when there is a backup to
    // remove: the captured `sweep/p` row purges an intact set and prints
    // `Purge par files.` with no backup header above it, while
    // `repair-purge` has a `rand.bin.1` and prints both.
    let protected = loaded.protected_keys();
    let mut seen = std::collections::HashSet::new();
    let backups: Vec<(String, PathBuf)> = created
        .iter()
        .filter(|p| !protected.contains(&path_key(p)))
        .filter(|p| seen.insert(path_key(p)))
        .filter(|p| p.exists())
        .map(|p| (display_name(&loaded.data_dir, p), p.clone()))
        .collect();
    if !backups.is_empty() {
        sink.line(Level::Terse, "Purge backup files.");
        for (name, path) in &backups {
            if std::fs::remove_file(path).is_ok() {
                sink.line(Level::Terse, &format!("Remove \"{name}\"."));
            }
        }
        sink.line(Level::Terse, "");
    }
    sink.line(Level::Terse, "Purge par files.");
    for path in &loaded.par_files {
        let name = display_name(&loaded.dir, path);
        if path.exists() && std::fs::remove_file(path).is_ok() {
            sink.line(Level::Terse, &format!("Remove \"{name}\"."));
        }
    }
}

/// `v` / `verify`, and the first half of `r` / `repair`.
pub fn run(opts: &Options, sink: &mut Sink, repairing: bool) -> u8 {
    run_watched(opts, sink, repairing, &())
}

/// [`run`] with a [`SurveyWatch`] over the pass. A refusal comes back
/// as "repair possible" with nothing printed past the set summary: a
/// verify only reads, so the directory is as it was, and the caller
/// that refused (the binary's Ctrl-C, through `lib.rs`) says so.
pub fn run_watched(
    opts: &Options,
    sink: &mut Sink,
    _repairing: bool,
    watch: &dyn SurveyWatch,
) -> u8 {
    sink.set_level(opts.level);
    let mut loaded = match load_with(opts, sink, true) {
        Ok(l) => l,
        Err(code) => return code,
    };
    print_set_summary(&loaded, sink);
    let Some((mut survey, _bits)) = survey_watched(&loaded, opts, sink, watch) else {
        return crate::EXIT_REPAIR_POSSIBLE;
    };
    // The verdict on a damaged set reads the recovery count; a clean
    // one never does, and a quiet load deferred it - see `load`.
    if survey.damaged() {
        survey.recovery_blocks = ensure_recovery(&mut loaded);
    }
    print_targets(&survey, sink);
    let code = print_verdict(&loaded, &survey, sink);
    // A verify made no backups, so there is nothing but the par files
    // to purge. That is the reference's answer too: `-p` removes the
    // run's own backup list, and a run that repaired nothing has none.
    if opts.purge && code == crate::EXIT_SUCCESS {
        purge(&loaded, &[], sink);
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stem a set's volumes share. The old rule cut at the FIRST
    /// `.`, which made every dotted release name a prefix of its
    /// neighbours - `Show.Name.S01E01.par2` stemmed to `Show`, globbed
    /// `Show.Name.S01E02.par2` too, and the two Main packets made
    /// `Par2Set::parse` refuse a set that was perfectly repairable.
    #[test]
    fn the_set_stem_strips_par2_and_one_volume_component_and_stops() {
        let stem = |s: &str| set_stem(Path::new(s));
        // The volume component is the one thing that must still come
        // off, so a volume named on the command line finds its index.
        assert_eq!(stem("set.par2"), "set");
        assert_eq!(stem("set.vol00+1.par2"), "set");
        assert_eq!(stem("set.vol123+456.par2"), "set");
        assert_eq!(stem("set.vol07-6.par2"), "set");
        // A dotted release name keeps every one of its dots.
        assert_eq!(stem("Show.Name.S01E01.par2"), "Show.Name.S01E01");
        assert_eq!(stem("Show.Name.S01E01.vol00+1.par2"), "Show.Name.S01E01");
        // And so the neighbouring episode is no longer under the stem.
        assert!(!"Show.Name.S01E02.par2".starts_with(&stem("Show.Name.S01E01.par2")));
        // Case-insensitive on the extension, as the glob is.
        assert_eq!(stem("set.PAR2"), "set");
    }

    /// Only a trailing `volNNN+NNN` is a volume component. A name that
    /// merely contains the letters is not one.
    #[test]
    fn a_name_that_merely_looks_volume_shaped_is_not_stripped() {
        let stem = |s: &str| set_stem(Path::new(s));
        assert_eq!(stem("movie.vol2of3.par2"), "movie.vol2of3");
        assert_eq!(stem("movie.volume.par2"), "movie.volume");
        assert_eq!(stem("movie.vol+.par2"), "movie.vol+");
        assert_eq!(stem("movie.vol00+.par2"), "movie.vol00+");
        assert_eq!(stem("movie.vol+01.par2"), "movie.vol+01");
        // Only the LAST component, so an inner one survives.
        assert_eq!(stem("a.vol00+1.b.par2"), "a.vol00+1.b");
        assert!(is_volume_component("vol00+1"));
        assert!(!is_volume_component("vol"));
        assert!(!is_volume_component("volaa+bb"));
    }

    /// A FileDesc name is untrusted wire data, and parfast writes AND
    /// deletes through the path it resolves to (`repair::back_up_damaged`
    /// copies, [`purge`] unlinks). A bare `join` keeps `..` and drops the
    /// base entirely on an absolute name, so both escaped `data_dir`.
    #[test]
    fn a_hostile_filedesc_name_cannot_escape_the_data_directory() {
        let root = PathBuf::from("/work");
        for hostile in [
            "/etc/passwd",
            "../../../etc/passwd",
            "..",
            "sub/../../escape",
        ] {
            let p = nzbkit::disk::join_out_name(&root, &nzbkit::disk::sanitize_out_name(hostile));
            assert!(
                p.starts_with(&root),
                "{hostile:?} resolved to {p:?}, outside the data directory"
            );
        }
        // And it agrees with the engine on an ordinary name, which is
        // the other half: the two used to disagree about a trailing dot,
        // so a member the engine had just repaired read back as missing.
        assert_eq!(
            nzbkit::disk::join_out_name(&root, &nzbkit::disk::sanitize_out_name("movie.mkv")),
            root.join("movie.mkv")
        );
    }
}
