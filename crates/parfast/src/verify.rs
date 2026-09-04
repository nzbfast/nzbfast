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

pub fn load(opts: &Options, sink: &mut Sink) -> Result<Loaded, u8> {
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
    let read: Vec<Option<Vec<u8>>> = order.iter().map(|p| std::fs::read(p).ok()).collect();
    let present: Vec<&[u8]> = read.iter().flatten().map(Vec::as_slice).collect();
    let (parsed, censuses) = par2::Par2Set::parse_censused(&present);
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
    }

    // The fast path already has the answer; only the fallback re-parses.
    let reparsed = match censused {
        Some(_) => parsed,
        None => Par2Set::parse(&members),
    };
    match reparsed {
        Ok(set) => Ok(Loaded {
            data_dir: opts.basepath.clone().unwrap_or_else(|| dir.clone()),
            set,
            dir,
            par_files,
        }),
        Err(_) => {
            sink.err("You must specify a Recovery file.");
            Err(crate::EXIT_INSUFFICIENT_DATA)
        }
    }
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
            file.length.div_ceil(bs) as usize
        };
        total_blocks += blocks;
        let path = loaded.data_path(&file.name);
        names.push(&file.name);
        counts.push(blocks);
        paths.push(path.exists().then_some(path));
    }

    // Members that exist are hashed CONCURRENTLY. Whole-file MD5 is
    // serial within one member and independent across members, so this
    // is the only axis that was left on the table.
    let present: Vec<usize> = (0..paths.len()).filter(|&i| paths[i].is_some()).collect();
    let width = file_threads(opts, present.len());
    // Split the intra-file hint across the lanes rather than handing
    // every lane the whole machine: the two multiply.
    let inner = (threads(opts) / width).max(1);

    // `block_size == 0` never reaches here - the Main-packet parser
    // refuses it (`par2/packet.rs`, the `block_size == 0` arm), so a set
    // that parsed has a slice size of at least 4. The guard is here
    // because the alternative to a dead branch is `verify_pass1`
    // dividing by a WIRE-SUPPLIED zero, and a panic on a crafted file is
    // worse than an unreachable arm. Zero slices means nothing is
    // verifiable, which is the verdict the `None` below already carries.
    let slice = usize::try_from(bs).ok().filter(|&n| n > 0);

    let cursor = AtomicUsize::new(0);
    let mut verdicts: Vec<Option<Pass1Out>> = (0..paths.len()).map(|_| None).collect();
    if let Some(slice) = slice.filter(|_| !present.is_empty()) {
        // Each lane keeps its OWN results and hands them back through the
        // scope. No shared lock on the hot path, and so no question about
        // what a poisoned one would mean here.
        let lanes: Vec<Vec<(usize, Option<Pass1Out>)>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..width)
                .map(|_| {
                    scope.spawn(|| {
                        let mut mine = Vec::new();
                        loop {
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
                let have = present_blocks(p, blocks);
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
    Survey {
        targets,
        total_blocks,
        available_blocks: available,
        recovery_blocks: loaded.set.recovery_blocks_seen,
    }
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
    let mut targets = Vec::with_capacity(loaded.set.files.len());
    let mut total_blocks = 0usize;
    let mut available = 0usize;
    for (file, m) in loaded.set.files.iter().zip(resolved) {
        let blocks = if bs == 0 {
            0
        } else {
            file.length.div_ceil(bs) as usize
        };
        total_blocks += blocks;
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
            let have = m.blocks_present.min(blocks);
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
    if pass.clean {
        return blocks;
    }
    pass.present
        .as_ref()
        .map_or(0, |b| b.iter().filter(|&&ok| ok).count())
        .min(blocks)
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
        file.length.div_ceil(bs) as usize
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
pub fn purge(loaded: &Loaded, sink: &mut Sink) {
    sink.line(Level::Terse, "");
    // The backup half is announced ONLY when there is a backup to
    // remove: the captured `sweep/p` row purges an intact set and prints
    // `Purge par files.` with no backup header above it, while
    // `repair-purge` has a `rand.bin.1` and prints both.
    let backups: Vec<(String, PathBuf)> = loaded
        .set
        .files
        .iter()
        .flat_map(|f| (1..=9u32).map(move |n| format!("{}.{n}", f.name)))
        .map(|name| {
            let path = loaded.data_path(&name);
            (name, path)
        })
        .filter(|(_, p)| p.exists())
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
pub fn run(opts: &Options, sink: &mut Sink, _repairing: bool) -> u8 {
    sink.set_level(opts.level);
    let loaded = match load(opts, sink) {
        Ok(l) => l,
        Err(code) => return code,
    };
    print_set_summary(&loaded, sink);
    let survey = survey(&loaded, opts, sink);
    print_targets(&survey, sink);
    let code = print_verdict(&loaded, &survey, sink);
    if opts.purge && code == crate::EXIT_SUCCESS {
        purge(&loaded, sink);
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
