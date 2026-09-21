//! `c` / `create`: par2cmdline's create dialect over
//! `nzbkit::par2gen`.
//!
//! # What this module owes, and what it must not do
//!
//! It owes the reference's SELECTION rules - how `-b` / `-s` pick a
//! block size, how `-r` / `-c` pick a recovery block count, which files
//! `-R` walks, which are skipped - and the reference's volume file
//! NAMES. It owes none of the Reed-Solomon: `par2gen::create_into` does
//! every byte of that, and this module hands it a spec.
//!
//! # Why the selection rules are `pub`
//!
//! [`block_size`], [`legal_block_size`], [`slice_total`],
//! [`recovery_blocks`], [`percent_blocks`], [`create_plan`],
//! [`recovery_file_count`], [`volume_ceiling`], [`final_volume_names`]
//! and [`rename_volumes`] were private until
//! 12 Sep 2026 and are the arithmetic above, nothing else. The GUI's
//! Create pane has to show a poster the block size, the block count,
//! the padding, the efficiency and the volume layout BEFORE anything is
//! written, and every one of those numbers is one of these functions -
//! so `parfast-session`'s planner calls exactly these rather than
//! carrying a second reading of the reference's rules that would drift
//! from this one the first time a probe corrected either. What that
//! drift costs when it happens between two callers of one engine - two
//! plausible answers with nothing in the tree saying which is right -
//! was measured on this crate in September 2026; the write-up is in the
//! private tree, so it is not named here.
//!
//! Nothing MOVED for this: the definitions, their comments and their
//! tests are where they were, and `tools/conformance/run.py` is the
//! proof the CLI is unchanged.

use std::path::{Path, PathBuf};

use nzbkit::par2gen::{self, Member};

use crate::cli::{Options, Redundancy};
use crate::help;
use crate::out::{Level, Sink};

/// What a caller can see of a create, and how it calls one off.
///
/// The same shape as [`crate::repair::RepairWatch`] and for the same
/// reason: the engine grew a control for the create on 12 Sep 2026
/// (`nzbkit::par2gen::control`) and the two callers that want it - the
/// binary, for Ctrl-C, and `parfast-session`, for the GUI's Create
/// pane - reach it through one door. Defaulted, so every existing
/// caller of [`run`] is unchanged and opts in when it wants to.
pub trait CreateWatch {
    /// Progress out, cancel in, pause parked. Asked ONCE, before the
    /// first member is opened.
    fn control(&self) -> par2gen::control::CreateControl {
        par2gen::control::CreateControl::default()
    }
}

/// The watch that watches nothing and refuses nothing.
impl CreateWatch for () {}

/// `c` / `create`.
pub fn run(opts: &Options, sink: &mut Sink) -> u8 {
    run_watched(opts, sink, &())
}

/// [`run`] that hands the engine a control, so a caller sees the
/// create's phases and can stop it. See [`CreateWatch`].
pub fn run_watched(opts: &Options, sink: &mut Sink, watch: &dyn CreateWatch) -> u8 {
    sink.set_level(opts.level);
    let Some(par2) = opts.archive.clone().or_else(|| opts.par2.clone()) else {
        sink.err("You must specify a Recovery file.");
        return crate::EXIT_INVALID_ARGS;
    };
    // A WILDCARD IN THE RECOVERY-FILE NAME IS A REFUSAL, NOT A
    // FILENAME. Without this, `parfast c -b32 *.par2 text.txt` exited 0
    // on macOS and linux having written two files literally CALLED
    // `*.par2` and `*.vol0+1.par2` - a set the user never asked for,
    // under a name no later command can name back without quoting, and
    // exit 0 said it had worked. The reference refuses it outright.
    // See `cli::refuse_wildcard_set_name` for both lines, the exit
    // code, and why the check is posix-only.
    if let Some(code) = crate::cli::refuse_wildcard_set_name(&par2, sink) {
        return code;
    }
    let dir = par2
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    // The suffix comes off case-INSENSITIVELY, the way `-a`
    // (`cli::with_par2_suffix`) and verify's `set_stem` already read it.
    // A case-sensitive `strip_suffix(".par2")` kept the whole name as
    // the base, so `parfast c Movie.PAR2 text.txt` wrote
    // `Movie.PAR2.par2` and `Movie.PAR2.vol000+NN.par2` and never
    // created the file the user named. The reference keeps the index
    // name it was given.
    let base = match par2.file_name().and_then(|s| s.to_str()) {
        Some(n) => strip_par2_suffix(n).to_string(),
        None => {
            sink.err("You must specify a Recovery file.");
            return crate::EXIT_INVALID_ARGS;
        }
    };

    // On create the bare arguments are all MEMBERS once `-a` named the
    // set, so the one that would otherwise have been the set name is a
    // member like any other.
    let members = match collect(opts, &dir, &base, &par2, sink) {
        Ok(m) => m,
        Err(code) => return code,
    };
    if members.is_empty() {
        sink.err("You must specify a list of files when creating.");
        return crate::EXIT_INVALID_ARGS;
    }

    let lengths: Vec<u64> = members
        .iter()
        .map(|m| std::fs::metadata(&m.path).map(|md| md.len()).unwrap_or(0))
        .collect();
    let (block_size, raised_from) = block_size(opts, &lengths);
    // Say so when we moved the user's own choice. Silently writing a set at a
    // size they did not ask for is worse than the refusal it replaces.
    if let Some(was) = raised_from {
        sink.line(
            Level::Normal,
            &format!(
                "Block size raised from {was} to {block_size}: at {was} this payload \
                 needs {} slices and the PAR2 limit is {}.",
                slice_total(&lengths, was),
                par2gen::MAX_INPUT_SLICES,
            ),
        );
    }
    let blocks = slice_total(&lengths, block_size);
    let recovery = recovery_blocks(opts, blocks, block_size);

    // `-n` asking for more volumes than there are recovery blocks is a
    // refusal on the reference, not a clamp: exit 3 with one line on
    // stderr and nothing written. Checked BEFORE the header, because the
    // reference prints no header for it either. Measured 3 Sep 2026
    // (research/CLI-SUBSTITUTION-2026-09-03.md).
    if opts.recovery_files.is_some_and(|n| u64::from(n) > recovery) {
        sink.err("Too many recovery files specified.");
        return crate::EXIT_INVALID_ARGS;
    }

    print_header(opts, sink, block_size, members.len(), blocks, recovery);
    for m in &members {
        // THE CONSOLE LINE IS PLATFORM-SPELLED AND THE STORED NAME IS
        // NOT, and par2cmdline makes the same split: it prints the name
        // it opened the file by and writes `/` into the FileDesc packet.
        // Printing `m.name` straight was right only while the two could
        // not differ, which is every posix box - on windows it gives
        // `Opening: linkdir/nested.txt` against the reference's
        // `linkdir\nested.txt`, which the windows conformance leg's
        // `create-symlink-dir-only` row caught the day it existed. See
        // `spec_member_name` for the other half and for why no row had
        // ever put a subdirectory member in a windows set before.
        sink.line(
            Level::Terse,
            &format!("Opening: {}", display_member_name(&m.name)),
        );
    }

    // The COUNT, never a percentage: par2cmdline's switches select an
    // exact number of recovery blocks and the volume split follows it,
    // so a round trip through a percentage moves every file name.
    match par2gen::create_into_exact_controlled(
        &dir,
        &members,
        &base,
        (block_size > 0).then_some(block_size),
        as_count(recovery),
        create_plan(
            opts,
            recovery,
            lengths.iter().copied().max().unwrap_or(0),
            block_size,
        ),
        // `--comment`. The engine refuses a comment it would not be able
        // to read back, and that refusal arrives here as the ordinary
        // create error below - one line on stderr and exit 3's sibling,
        // rather than a set written with the comment silently dropped.
        opts.comment.as_deref(),
        // Fetched ONCE, here: the engine clones it into its own
        // workers, and a watch that answered differently on a second
        // call would be two controls for one create.
        &watch.control(),
    ) {
        Ok(written) => {
            sink.line(
                Level::Normal,
                &format!("Wrote {} bytes to disk", recovery * block_size),
            );
            sink.line(Level::Normal, "Writing recovery packets");
            sink.line(Level::Normal, "Writing verification packets");
            // PUBLICATION, and checked like one. Every rename that did
            // not happen is named on stderr and the command fails: the
            // set on disk is not the set the header, the preview and
            // `final_volume_names` all said would be written, and a
            // caller told `Done` has no way to find that out - both
            // spellings answer the same "is this one of ours" scan.
            let unpublished = rename_volumes(
                &dir,
                &base,
                &written,
                opts.first_block,
                recovery,
                opts.std_naming,
                opts.no_clobber,
            );
            if !unpublished.is_empty() {
                for (from, to, why) in &unpublished {
                    sink.err(&format!("Could not name {from} as {to}: {why}"));
                }
                sink.err(&format!(
                    "The recovery set is on disk but {} of its files could not be given \
                     their final names; nothing was deleted.",
                    unpublished.len()
                ));
                return crate::EXIT_FILE_IO_ERROR;
            }
            sink.line(Level::Terse, "Done");
            crate::EXIT_SUCCESS
        }
        // A cancel is the user's own decision, not a diagnosis: the
        // engine has already removed every file this run wrote, and
        // `lib.rs` says "Cancelled." once on stderr and exits 130 for
        // every command. A "Failed to create" line here would be a
        // second, wronger account of the same press.
        Err(par2gen::Par2GenError::Cancelled) => crate::EXIT_FILE_IO_ERROR,
        Err(e) => {
            sink.err(&format!("Failed to create the recovery set: {e}"));
            crate::EXIT_FILE_IO_ERROR
        }
    }
}

/// Is `path` one of the files THIS create is about to write - the index
/// itself, or one of its recovery volumes?
///
/// A source that is also an output is a source the create destroys. The
/// index is judged by IDENTITY (`same_file`), because the two spellings
/// need not match - a symlink, a hard link, `./set.par2`, a case variant
/// on APFS - and the volumes by NAME, because they do not exist yet and
/// there is nothing to compare an inode against.
///
/// # What this costs, and why it is a skip rather than a refusal
///
/// `parfast c set.par2 set.par2` measured the 40 KB file it was handed,
/// wrote the index over it with `File::create`, and then folded recovery
/// out of the 480 bytes it had just left there - so the engine's own
/// length check fired ("changed length while the PAR2 set was being
/// built"), the command failed, and the user's file was gone anyway. The
/// far commoner route is a glob: `parfast c set.par2 *` after any earlier
/// run sweeps that run's whole set back in as sources.
///
/// Both want the same answer, and it is the reference's - its recovery
/// files are not members of their own set - so these are SKIPPED with a
/// line, beside the 0-byte and out-of-basepath skips this loop already
/// prints. A refusal would break the glob re-run, which is ordinary use;
/// and a create left with no members at all still fails loudly on the
/// "You must specify a list of files" door, with the file intact.
fn is_own_output(path: &Path, par2: Option<&Path>, base: &str) -> bool {
    if par2.is_some_and(|p| same_file(path, p)) {
        return true;
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    // `<base>.vol...par2`, either spelling of the volume numbers - the
    // engine's fixed widths or the renamed ones. Case-insensitively,
    // because the index name is matched that way too
    // (`strip_par2_suffix`).
    let lower = name.to_ascii_lowercase();
    let prefix = format!("{}.vol", base.to_ascii_lowercase());
    lower.starts_with(&prefix) && lower.ends_with(".par2")
}

/// Do these two paths name the same file on disk? Through a symlink, a
/// hard link, or two spellings of one path. A path that is not there is
/// never equal to anything, which is the right answer for an output that
/// has not been written yet.
fn same_file(a: &Path, b: &Path) -> bool {
    let key = |p: &Path| -> Option<(u64, u64)> {
        // Follows links: a symlink and its target are one file for the
        // purpose of "am I about to overwrite this".
        let md = std::fs::metadata(p).ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Some((md.dev(), md.ino()))
        }
        #[cfg(windows)]
        {
            // No `MetadataExt` here on purpose: this arm never calls a
            // method from it, so importing it is an `unused_imports` error
            // under the windows-clippy job's `-D warnings` (and only
            // there, which is why it reached main).
            let _ = md;
            // No inode on Windows; the canonical path is the identity
            // that is available, and it resolves links and `.` the same
            // way `dev`/`ino` does on unix.
            let c = std::fs::canonicalize(p).ok()?;
            let s = c.to_string_lossy().to_lowercase();
            let mut h = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(&s, &mut h);
            Some((std::hash::Hasher::finish(&h), 0))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = md;
            None
        }
    };
    match (key(a), key(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// The SOURCE-argument half of the wildcard refusal - see the long
/// comment in [`collect`] for the defect it replaces, the reason it is
/// spelled `has_wildcard && !exists`, and where it deliberately
/// over-refuses.
///
/// The message is modelled on the reference's own set-name refusal
/// (`par2 file must not have a wildcard in it.`) rather than on
/// `Ignoring non-existent source file`, one word changed, because it is
/// the same kind of statement - an argument the tool will not act on -
/// and because the reference's non-existent-source handling is a SILENT
/// drop at exit 0, which is the behaviour being refused rather than a
/// model for refusing it. It names the argument, which the reference's
/// line does not, because a create can carry many sources and the user
/// needs to know which one to expand by hand.
///
/// Exit 3 (`EXIT_INVALID_ARGS`), matching the set-name refusal and
/// every other argument refusal in this dialect.
fn refuse_wildcard_source(f: &Path, sink: &mut Sink) -> Option<u8> {
    if !crate::cli::has_wildcard(f) || f.exists() {
        return None;
    }
    sink.err(&format!(
        "Source file must not have a wildcard in it: {}",
        f.display()
    ));
    Some(crate::EXIT_INVALID_ARGS)
}

/// The members, with the reference's skip rules applied and announced.
fn collect(
    opts: &Options,
    dir: &Path,
    base: &str,
    out_par2: &Path,
    sink: &mut Sink,
) -> Result<Vec<Member>, u8> {
    let mut named: Vec<PathBuf> = Vec::new();
    if opts.archive.is_some()
        && let Some(first) = &opts.par2
    {
        // Under `-a` the first bare argument is a MEMBER, not the set
        // name, so it takes the SOURCE refusal below and not
        // `refuse_wildcard_set_name` - which `run` has already applied
        // to the archive name itself. Checked here rather than left to
        // the loop because this push does not go through it.
        if let Some(code) = refuse_wildcard_source(first, sink) {
            return Err(code);
        }
        named.push(first.clone());
    }
    for f in &opts.files {
        // A WILDCARD SOURCE ARGUMENT IS REFUSED BY NAME, because the
        // alternative measured on this code was a SILENT MEMBER DROP at
        // exit 0.
        //
        // par2cmdline expands wildcards itself on every platform
        // (`cli::has_wildcard`); `parfast` expands none. Until this
        // check, an argument we could not expand simply failed the
        // `std::fs::metadata` probe further down and fell out of the
        // member list, so `parfast c -b32 out.par2 *.txt rand.bin`
        // wrote a VALID, VERIFIABLE set protecting `rand.bin` alone -
        // one member where the reference has three - and said `Done`.
        // Confirmed by loading that set with the reference: `Target:
        // "rand.bin" - found. All files are correct.` The refusal only
        // ever fired when the drop emptied the list ENTIRELY, which is
        // why it read as "parfast does not glob" rather than as the
        // silent-drop class it actually was. A user protecting a
        // directory before deleting the originals lost the `.txt` half
        // of their set and was told nothing - and on Windows, where
        // `cmd.exe` expands no glob of its own, that is the ORDINARY
        // path rather than a corner of it.
        //
        // Classified HERE, at the argument, rather than at `run`'s
        // empty-member-list door, because the empty case is the one
        // that was already loud; the defect is every case that is not.
        // The `@listfile` route needs no second check: `cli` pushes
        // each line of a listfile into `opts.files`, so a wildcard LINE
        // arrives here as the same argument by a different road, which
        // is also how `commandline.cpp` routes the two.
        //
        // NOT `has_wildcard` ALONE - the argument must also fail to
        // exist. `*` and `?` are ordinary filename characters on unix,
        // so a real file called `weird?.bin` is still protected, and
        // only an argument that names nothing on disk AND carries a
        // metacharacter is treated as a pattern we cannot expand.
        //
        // WHERE THIS OVER-REFUSES, DELIBERATELY: a pattern that matches
        // NOTHING. `par2 c -b32 out.par2 *.nosuch rand.bin` exits 0 on
        // the reference with `rand.bin` alone, because the reference
        // globs, finds nothing, and drops the argument silently the way
        // it drops a missing literal (`out.par2 text.txt nosuch.txt` is
        // exit 0 with `text.txt` there too - measured, 21 Sep 2026, so
        // the silent drop of a MISSING LITERAL is the reference's own
        // behaviour and is left alone). `parfast` cannot tell "this
        // pattern matched nothing" from "we cannot expand this pattern"
        // without implementing the globber, and guessing the first is
        // exactly the guess that produced the defect above. So the
        // over-refusal is the safe side of a choice that has no free
        // answer, it is pinned by the `create-wildcard-nomatch` row so
        // it cannot become invisible, and implementing globbing removes
        // it - which is an open design question about this dialect's
        // scope and is not this function's to settle.
        if let Some(code) = refuse_wildcard_source(f, sink) {
            return Err(code);
        }
        if opts.recurse && f.is_dir() {
            // The windows guard is on the ARGUMENT too, not only on the
            // directories the walk finds below it: the reference reaches
            // both through the same `FindFirstFileW` result. See `walk`.
            if dot_named(f) {
                continue;
            }
            walk(f, &mut named);
        } else {
            named.push(f.clone());
        }
    }
    named.sort();
    named.dedup();
    let mut out = Vec::new();
    for path in named {
        let Ok(md) = std::fs::metadata(&path) else {
            continue;
        };
        if md.is_dir() {
            continue;
        }
        // The reference refuses a source file outside the basepath, and
        // says so on STDOUT before the create fails on stderr.
        //
        // Only for an EXPLICIT `-B`. par2cmdline defaults the basepath
        // to the recovery file's own directory and refuses anything
        // outside it, which parfast does not do - but that refusal
        // cannot be added by defaulting `base_path` here, because
        // `within` deliberately reproduces the reference's own
        // `-B.` quirk (see its doc): the default directory is usually
        // `.`, which canonicalises to `/cwd/.` on macOS and matches no
        // source file, so every create would be refused. Restoring the
        // default refusal needs `within` to separate "the user named
        // this path" from "we derived it", and that is its own change.
        if let Some(bp) = &opts.basepath
            && !within(bp, &path)
        {
            sink.line(
                Level::Terse,
                &format!(
                    "Ignoring out of basepath source file: {}",
                    canonical_pathname(&path).display()
                ),
            );
            continue;
        }
        if md.len() == 0 {
            sink.line(
                Level::Terse,
                &format!(
                    "Skipping 0 byte file: {}",
                    canonical_pathname(&path).display()
                ),
            );
            continue;
        }
        // A file this create is about to WRITE is not a file it can
        // protect. See [`is_own_output`]: without this, the index was
        // opened as a member, measured, and then truncated by the
        // create's own `File::create` - the source/output collision the
        // 17 Sep sweep found in the legacy tool (L1) and which this
        // tree's CLI shared.
        //
        // `out_par2` and NOT `opts.par2`, and the difference is the
        // whole of the `-a` regression this guard shipped with. Under
        // `-a` the output is the ARCHIVE and the first bare argument is
        // an ordinary MEMBER - the comment above `collect`'s call site
        // says so, and `run` resolves the pair correctly two lines
        // earlier. Passing the raw `opts.par2` here made that member
        // look like the file about to be written, so
        // `parfast c -aout2.par2 text.txt rand.bin` protected rand.bin
        // ALONE and reported Done: the "quietly protects four of five"
        // outcome, from the guard written to prevent it. Caught by
        // `tools/conformance/run.py`, which no CI job runs against this
        // binary - `par2-conformance` checks the reference against
        // ITSELF.
        if is_own_output(&path, Some(out_par2), base) {
            sink.line(
                Level::Terse,
                &format!(
                    "Skipping the recovery set's own file: {}",
                    canonical_pathname(&path).display()
                ),
            );
            continue;
        }
        // The stored FileDesc name is RELATIVE TO THE BASEPATH, which is
        // what `-B` is for. It used to be stripped against `dir`, the
        // recovery-file output directory, so a source under `-B` but not
        // under the par2 directory kept its whole path - usually an
        // ABSOLUTE one. `parfast c -B /media/videos /backup/m.par2
        // /media/videos/movie.mkv` stored `/media/videos/movie.mkv`,
        // which fails the spec's relative-name rule and makes the set
        // unusable on any other machine: copy the `.par2` files
        // somewhere else and every member verifies as missing.
        //
        // The `dir` fallback stays for a path under neither, so a plain
        // `parfast c out.par2 text.txt` still stores `text.txt`.
        //
        // Stripped against the CANONICAL basepath, which is the same
        // path `within` above accepted the file under. A lexical
        // `strip_prefix` answers a narrower question than that test
        // does - `-B` naming a symlink to the real directory, or any
        // spelling that only agrees after `canonical_pathname`, passes
        // `within` and then fails to strip - and the fallthrough stores
        // the raw, usually ABSOLUTE, path in the FileDesc. So the two
        // must resolve the path the same way or the accept and the name
        // disagree.
        let cpath = canonical_pathname(&path);
        let rel = opts
            .basepath
            .as_deref()
            .map(canonical_pathname)
            .and_then(|bp| cpath.strip_prefix(&bp).ok().map(Path::to_path_buf))
            .or_else(|| path.strip_prefix(dir).ok().map(Path::to_path_buf))
            .unwrap_or_else(|| path.clone());
        let name = spec_member_name(&rel);
        out.push(Member { name, path });
    }
    Ok(out)
}

/// `<name>.par2` with the extension off, whatever case it was spelled
/// in. Anything else is returned whole.
fn strip_par2_suffix(name: &str) -> &str {
    match name.len().checked_sub(5) {
        Some(cut) if name[cut..].eq_ignore_ascii_case(".par2") => &name[..cut],
        _ => name,
    }
}

/// `-R`, depth first, skipping nothing but directories themselves.
///
/// # Windows drops a dot-named directory, and that is the reference
///
/// `DiskFile::FindFiles` is written twice in par2cmdline, and the two
/// halves do not agree. The unix half tests the argument with `lstat`
/// first: a literal name that IS a directory is recursed into, so
/// `par2 c -R out.par2 .` walks the tree. The windows half has no such
/// branch - it hands the argument straight to `FindFirstFileW`, which
/// answers with the directory's own entry, and then drops it on
/// `if (fd.cFileName[0] == '.') continue;`, the guard that keeps `.`
/// and `..` from looping the recursion. So the same command line finds
/// EVERY file on macOS and NOTHING on Windows, where the reference then
/// fails the create with "You must specify a list of files when
/// creating." (exit 3). Both captured tables say so, from both
/// references, and a single-platform capture would have reported this
/// as settled.
///
/// The guard is a name test and not a `.`/`..` test, so on Windows it
/// also drops a real dot-named subdirectory during the walk. That is
/// the reference's behaviour and it is reproduced rather than
/// corrected: a drop-in that walked further would build a set out of
/// files par2cmdline never read.
///
/// # A link is never followed and never protected, and neither is a fifo
///
/// That is the reference's rule too, MEASURED on 17 Sep 2026 against
/// par2cmdline 1.2.0 rather than read out of its source: over a folder
/// holding `dirlink -> ../other`, `filelink -> real.bin` and a `mkfifo`d
/// entry beside one real file it answers `Source file count: 1` and
/// opens only the real file. The fifo does not even reach its own
/// "Skipping 0 byte file" line - it is gone before `collect` can say
/// that - so the type filter is in the WALK and not below it. It lstats,
/// and a link is not a source.
///
/// This walk followed them until that day, and the cost was not
/// fidelity alone. `Path::is_dir` follows a link, so a `loop -> .` inside
/// a source folder was re-entered at every level until macOS's 32-link
/// `stat` limit stopped it: ONE ordinary file came out as 95 members,
/// 30 of them a file from a DIFFERENT folder reached through a second
/// link, in a set the user never asked for. `named.dedup()` cannot see
/// it, because the 95 spellings are 95 different paths.
///
/// The ARGUMENT is deliberately left alone - `collect` reaches this
/// function only for a path the user typed, and `/tmp` is a link on
/// macOS. The reference refuses a named link outright ("You must specify
/// a list of files when creating."); refusing a path somebody typed is
/// worse than protecting it, and that departure is the same one `within`
/// and the basepath default already make.
///
/// # BOTH HALVES ARE MEASURED NOW, AND THEY DISAGREE
///
/// Read out of v1.3.0's source 20 Sep 2026 (claim
/// `par2-conformance-macos-leg-link-row-20sep`) and RUN on a fleet
/// Windows box the next day (claim
/// `par2-conformance-windows-link-rows-20sep`), which confirmed the
/// reading on every arm.
/// `FindFiles` is written twice and the two halves already disagree
/// about `.` (see `dot_named`, and README.md's windows section). The
/// windows half hands its argument to `FindFirstFileW` and branches on
/// `FILE_ATTRIBUTE_DIRECTORY` and on nothing else: the string
/// `FILE_ATTRIBUTE_REPARSE_POINT` does not occur anywhere in that tag's
/// source, and neither does any other link test. So a FILE link, having
/// no DIRECTORY bit, is pushed onto the match list and the later open
/// follows the reparse point; a directory symlink or a JUNCTION has the
/// bit and is RECURSED INTO. **The reference follows a link on windows
/// and refuses one on unix, from the same tag, so this rule IS a
/// windows-only divergence** - a stated one, recorded in
/// `tools/conformance/README.md` ("Links, and the one answer that came
/// out of the source"), not a defect to fix toward.
///
/// WHAT RUNNING IT CHANGED, AND IT IS NOT WHAT THE READING PREDICTED
/// FOR US: the divergence is the reference's, not ours, and on windows
/// it CLOSES. `parfast` honours a link the user TYPED on every platform,
/// and on windows so does the reference - so `create-symlink-named` and
/// `create-symlink-dir-only` are clean on both windows legs, field for
/// field, and the six waivers that cover them on the three posix legs
/// are scoped away from windows rather than left to swallow it
/// (allow/par2.txt section 8). The rule this function carries is
/// unchanged and was not fixed toward anything.
///
/// The unix half is now MEASURED on every push rather than by hand: the
/// three `linkset` rows landed the same day, `par2-conformance` runs
/// this binary on linux and `par2-conformance-macos` on macOS. What they
/// found is the paragraph above this heading, not this one - the WALK
/// matches the reference on every field, and the typed ARGUMENT is where
/// we differ. The safety argument still decides that: a 95-member set
/// built out of one file is a worse answer than a link left out and
/// counted.
///
/// THE WINDOWS ROWS ARE THE TWO TYPED ONES ONLY, and that is a fact
/// about windows' command line rather than about links: this WALK's own
/// row needs a spelling for "walk this whole tree", and windows has
/// neither `.` (exit 3 there, on the `dot_named` guard) nor a
/// wildcard the candidate expands. See the row in
/// `tools/conformance/run.py`. So the walk half of the rule below is
/// still measured on the two posix legs alone, and the typed half is
/// measured on all five.
///
/// The capture used the same MSBuild-from-tag reference both committed
/// windows tables already came from, and a directory SYMLINK rather than
/// the junction this was expected to need - a junction cannot survive
/// the harness's per-row copy and its `readlink` is an absolute path.
/// Both windows tables moved 71 -> 73 rows with no pre-existing row
/// moving a byte.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        // `DirEntry::file_type` does NOT follow a link. `Path::is_dir`
        // does, which is what made a loop walkable.
        let Ok(ft) = e.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let p = e.path();
        if ft.is_dir() {
            if dot_named(&p) {
                continue;
            }
            walk(&p, out);
        } else if ft.is_file() {
            out.push(p);
        }
    }
}

/// Does the reference's windows recursion guard drop this directory?
///
/// The guard reads `fd.cFileName`, the trailing component of the path
/// `FindFirstFileW` was handed, so this reads the argument the same
/// way - TEXTUALLY, after the last separator. `Path::file_name` will
/// not do: it answers `None` for `.`, which is the one name the guard
/// exists to drop. Always false off Windows, where the unix half of
/// `FindFiles` has no such guard.
fn dot_named(p: &Path) -> bool {
    cfg!(windows) && last_component(p).starts_with('.')
}

/// The trailing component as written, the way `DiskFile::SplitFilename`
/// takes it: everything after the last `/` or `\`, and the whole
/// string when there is neither.
fn last_component(p: &Path) -> &str {
    let s = p.to_str().unwrap_or_default();
    match s.rfind(['/', '\\']) {
        Some(i) => &s[i + 1..],
        None => s,
    }
}

/// The same name spelled the way the PLATFORM writes a path, for the
/// console only. A no-op on unix, where `MAIN_SEPARATOR` already is `/`
/// and a stored name holds no other slash - `spec_member_name` builds it
/// out of components, so every `/` in it IS a separator.
fn display_member_name(name: &str) -> String {
    name.replace('/', std::path::MAIN_SEPARATOR_STR)
}

/// The FileDesc name the spec asks for, which is FORWARD-SLASHED.
///
/// `Member::name` is documented as "the RELATIVE path, forward-slashed",
/// and until 21 Sep 2026 this built it with `to_string_lossy()`, which is
/// the PLATFORM separator - so every set `parfast` created on Windows
/// holding a member in a SUBDIRECTORY stored `linkdir\nested.txt` where
/// par2cmdline stores `linkdir/nested.txt`. PAR2 2.0 gives the filename
/// field one separator and it is `/`; a backslash there is not a path to
/// any other implementation, it is one filename with a backslash in it,
/// so the directory tree a recursive create exists to preserve does not
/// survive the set. Our own reader was not what hid it -
/// `nzbkit_base::disk::relpath::sanitize_relpath_for` accepts `\` on
/// purpose, because other Windows tools write it too - so the sets
/// round-tripped through our own stack and failed only against everyone
/// else's.
///
/// MEASURED, not reasoned: on a native x86 Windows box, `parfast c -R
/// out.par2 linkdir` wrote `linkdir\nested.txt` against the reference's
/// `linkdir/nested.txt`, same packet counts and a different digest. It
/// had never been seen because it needs a set holding a member below the
/// top level, and `create-symlink-dir-only` is the ONLY row of the
/// windows par2 matrix that builds one - the two rows that do so on
/// posix, `create-recurse` and `create-symlink-recurse`, both refuse on
/// windows at exit 3 on the `.` argument.
///
/// `components()` and NOT `replace('\\', "/")`, which would be wrong on
/// unix: a backslash is an ORDINARY CHARACTER in a unix filename, so
/// `a\b.txt` is one component there and must stay one. Joining
/// components re-spells only what the platform actually treats as a
/// separator, which makes this the same expression on both and lets it
/// be tested on either.
fn spec_member_name(rel: &Path) -> String {
    let joined = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    joined.trim_start_matches("./").to_string()
}

/// `DiskFile::GetCanonicalPathname`, which is TWO functions and they do
/// not agree.
///
/// This is what the reference prints on its two full-path lines and
/// what it compares a basepath against, so a drop-in owes the same
/// string rather than merely the same file. `std::fs::canonicalize` is
/// the wrong tool twice over: on Windows it returns an extended-length
/// `\\?\C:\...` path, which the reference never prints, and on both
/// platforms it resolves symlinks, which the reference never does.
///
/// * WINDOWS: `GetFullPathNameW`, then the drive letter upper-cased and
///   every `/` rewritten to `\`. That call resolves `.` and `..`
///   LEXICALLY and completely, so `.` becomes the current directory
///   with no trailing component left over.
/// * UNIX: an absolute path is returned untouched; otherwise the cwd is
///   joined on and the result is walked collapsing `/./` and `/../`.
///   Both patterns require the TRAILING slash, so a path ENDING in `.`
///   keeps it: `.` canonicalises to `/cwd/.`, not to `/cwd`. That
///   surviving dot is the whole reason `-B.` behaves differently on the
///   two platforms - see `within`.
fn canonical_pathname(p: &Path) -> PathBuf {
    let raw = p.to_str().unwrap_or_default();
    if cfg!(windows) {
        return windows_full_path(raw);
    }
    if raw.starts_with('/') {
        return PathBuf::from(raw);
    }
    let Ok(cwd) = std::env::current_dir() else {
        return p.to_path_buf();
    };
    let mut joined = cwd.to_string_lossy().into_owned();
    if !joined.ends_with('/') {
        joined.push('/');
    }
    joined.push_str(raw);
    PathBuf::from(collapse_unix(&joined))
}

/// The unix loop in `GetCanonicalPathname`, character for character:
/// `/./` is dropped and `/../` backtracks the output to the previous
/// `/`. A trailing `/.` or `/..` matches NEITHER, because the pattern
/// is three or four characters wide and the string has run out.
fn collapse_unix(path: &str) -> String {
    let b = path.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && b[i..].starts_with(b"/./") {
            i += 2;
        } else if b[i] == b'/' && b[i..].starts_with(b"/../") {
            i += 3;
            while !out.is_empty() {
                out.pop();
                if out.last() == Some(&b'/') {
                    break;
                }
            }
            // The C loop steps back ONTO the separator and leaves it for
            // the next iteration to copy; popping to just past it is the
            // same string.
            if out.last() == Some(&b'/') {
                out.pop();
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `GetFullPathNameW` plus the two rewrites the reference applies after
/// it. Lexical only: no disk is touched and no symlink is followed.
fn windows_full_path(raw: &str) -> PathBuf {
    let unified = raw.replace('/', "\\");
    let (prefix, rest) = split_windows_root(&unified);
    let prefix = match prefix {
        Some(p) => p,
        None => {
            let Ok(cwd) = std::env::current_dir() else {
                return PathBuf::from(unified);
            };
            let cwd = cwd.to_string_lossy().replace('/', "\\");
            // A cwd read back through the OS can carry the
            // extended-length prefix; the reference's string never does.
            let cwd = cwd.strip_prefix(r"\\?\UNC\").map_or_else(
                || cwd.strip_prefix(r"\\?\").unwrap_or(&cwd).to_string(),
                |u| format!(r"\\{u}"),
            );
            let joined = if rest.is_empty() {
                cwd
            } else {
                format!("{}\\{}", cwd.trim_end_matches('\\'), rest)
            };
            let (p, r) = split_windows_root(&joined);
            return assemble_windows(p.unwrap_or_default(), &r);
        }
    };
    assemble_windows(prefix, &rest)
}

/// Split off `C:\`, `\\server\share\` or a bare `\`, leaving the rest.
/// `None` means the path is relative and needs the cwd.
fn split_windows_root(s: &str) -> (Option<String>, String) {
    let b = s.as_bytes();
    if let Some(unc) = s.strip_prefix(r"\\") {
        let mut parts = unc.splitn(3, '\\');
        let server = parts.next().unwrap_or_default();
        let share = parts.next().unwrap_or_default();
        if !server.is_empty() && !share.is_empty() {
            let rest = parts.next().unwrap_or_default().to_string();
            return (Some(format!(r"\\{server}\{share}\")), rest);
        }
        return (Some(r"\\".to_string()), unc.to_string());
    }
    if b.len() >= 3 && b[1] == b':' && b[2] == b'\\' {
        return (Some(s[..3].to_string()), s[3..].to_string());
    }
    (None, s.to_string())
}

/// Resolve `.` and `..` in the body and put the root back, with the
/// drive letter upper-cased the way the reference upper-cases the first
/// character of the result.
fn assemble_windows(root: String, rest: &str) -> PathBuf {
    let mut parts: Vec<&str> = Vec::new();
    for seg in rest.split('\\') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let mut root = root;
    if let Some(first) = root.chars().next() {
        let upper: String = first.to_uppercase().collect();
        root.replace_range(..first.len_utf8(), &upper);
    }
    PathBuf::from(format!("{}{}", root, parts.join("\\")))
}

/// Is `path` under `base`?
///
/// The reference's test is a SUBSTRING search, not a path-component
/// one: it canonicalises the basepath, appends the separator if the
/// string does not already end in one, and asks whether the
/// canonicalised source file name CONTAINS it
/// (`filename.find(basepath) == npos` -> "Ignoring out of basepath
/// source file"). Reproducing that spelling is what makes `-B.` come
/// out right, and `-B.` comes out DIFFERENTLY on the two platforms:
///
/// * macOS: `.` canonicalises to `/cwd/.` (the collapse pattern needs a
///   trailing slash, so the dot survives), the separator is appended to
///   give `/cwd/./`, and `/cwd/text.txt` does not contain that. So the
///   reference IGNORES the file and then fails the create outright.
/// * Windows: `GetFullPathNameW(".")` resolves to `C:\cwd` with no dot
///   left, the separator gives `C:\cwd\`, and `C:\cwd\text.txt` does
///   contain it. So the reference ACCEPTS the file and creates the set.
///
/// Chip 13 read the macOS half as the rule and wrote "a relative
/// basepath matches nothing", which is true on macOS and wrong on
/// Windows; the windows conformance leg is what showed the difference.
/// Verify and repair are a third case again and DO honour a relative
/// `-B` - see `verify::Loaded`.
fn within(base: &Path, path: &Path) -> bool {
    let sep = if cfg!(windows) { '\\' } else { '/' };
    let mut b = canonical_pathname(base).to_string_lossy().into_owned();
    if !b.ends_with(sep) {
        b.push(sep);
    }
    canonical_pathname(path).to_string_lossy().contains(&b)
}

/// `-s` wins outright; `-b` picks the smallest slice size that fits the
/// payload into that many slices; neither means the reference's default
/// block COUNT.
///
/// # `-b` is a search, not a division
///
/// `ceil(total / count)` is wrong and the conformance harness proved it
/// on the first two-member set it was given. A PAR2 slice grid is
/// per-FILE - each member is sliced from its own offset zero, so each
/// contributes `ceil(len / bs)` and the remainders do not pool. Over
/// a.bin (40,000 bytes) and b.bin (17,000) at `-b64`, the division gives
/// 892, which slices into 45 + 20 = 65 grids: one MORE than asked for,
/// where the reference answers 896 and gets 45 + 19 = 64. So the size is
/// searched upward in the multiples of 4 the spec allows until the
/// per-file ceilings sum to at most `count`, a search that is bounded
/// because every step of 4 can only lower the sum and `total` itself
/// always satisfies a count of 1.
pub fn block_size(opts: &Options, lengths: &[u64]) -> (u64, Option<u64>) {
    let asked = if let Some(s) = opts.block_size {
        s.next_multiple_of(4).max(4)
    } else {
        let count = opts.block_count.unwrap_or(help::DEFAULT_BLOCK_COUNT).max(1);
        let total: u64 = lengths.iter().sum();
        let bs = total.div_ceil(count).next_multiple_of(4).max(4);
        first_size_within(lengths, bs, total.max(4), count)
    };
    let legal = legal_block_size(lengths, asked);
    (legal, (legal != asked).then_some(asked))
}

/// Raise a slice size until the set is legal, and never past that.
///
/// The PAR2 spec caps a set at [`par2gen::MAX_INPUT_SLICES`] input slices,
/// and the engine REFUSES above it - correctly, because a set over the
/// ceiling is one no reader will accept and par2cmdline will not create
/// either. But a refusal is a poor answer to a poster who asked for a slice
/// size that a big payload cannot carry: the engine's own error already says
/// "raise the block size", so do it, and say so.
///
/// It is a SEARCH and not `total / MAX`, for the same reason `-b` is a search
/// (see [`block_size`]): the slice grid is per FILE, each member is sliced
/// from its own offset zero, and the remainders do not pool. A division
/// undercounts every time there is more than one member.
pub fn legal_block_size(lengths: &[u64], asked: u64) -> u64 {
    let cap = par2gen::MAX_INPUT_SLICES as u64;
    if slice_total(lengths, asked) <= cap {
        return asked;
    }
    // RAISE TO A MULTIPLE OF WHAT WAS ASKED FOR, not to the first size that
    // happens to fit.
    //
    // Usenet loses whole ARTICLES, and a lost article destroys every block it
    // touches. When the block size is an exact multiple of the article size
    // and the two grids share offset zero, no article ever straddles a
    // boundary: one article costs exactly one block of parity. Land between
    // multiples and articles straddle two blocks, which costs an extra 1.2x
    // to 1.8x of recovery data on top of the size increase.
    //
    // Measured over a 768,000-byte article (the modal size): 1,152,000 (1.5
    // articles) and 1,536,000 (2 articles) both waste 2.00x - but the second
    // is 33% LARGER, so it needs a third fewer blocks for the same
    // protection. Creeping up in steps of 4 lands between multiples and is
    // strictly worse than jumping to the next one.
    //
    // The engine cannot know the article size, and does not need to: raising
    // to a multiple of the poster's OWN request preserves whatever grid they
    // intended. Someone who asked for 768,000 gets 1,536,000 or 2,304,000,
    // still article-aligned; someone who asked for an arbitrary size is no
    // worse off than the old search left them.
    let total: u64 = lengths.iter().sum();
    let step = asked.max(4);
    let mut mult = 2u64;
    while let Some(bs) = step.checked_mul(mult) {
        if bs > total.max(4) {
            break;
        }
        if slice_total(lengths, bs) <= cap {
            return bs;
        }
        mult += 1;
    }
    // No multiple fits under the ceiling before the payload itself does, so
    // fall back to the finest legal size. Reachable only for a pathological
    // request; a set of one slice per member always satisfies the cap.
    let bs = (total / cap).next_multiple_of(4).max(step).max(4);
    first_size_within(lengths, bs, total.max(4), cap)
}

/// The smallest slice size at or above `start`, in the multiples of 4 the
/// spec allows, whose per-file slice grids sum to at most `target` - and
/// the first multiple of 4 at or past `stop` when none does.
///
/// A BINARY search, and that is the whole point of the function.
/// `slice_total` is non-increasing in `bs` (`l.div_ceil(bs)` is, for each
/// member, and a sum of non-increasing terms is), so the predicate is
/// monotone and the answer is exactly the one a `bs += 4` scan reaches -
/// in about 35 probes rather than `(stop - start) / 4` of them.
///
/// Which matters because the scan is reachable with `stop - start` at
/// payload scale whenever the request is IMPOSSIBLE, and it always is
/// when `-b<count>` names fewer blocks than the set has members: each
/// member is sliced from its own offset zero, so every non-empty member
/// costs at least one slice and the sum can never fall below their
/// number, however large the size grows. `parfast c -b50 out.par2` over
/// 100 files of 1 GiB ran (100 GiB - 2 GiB) / 4 = 2.6e10 iterations,
/// each summing 100 lengths, before answering `total` - hours of busy
/// loop for a command line the reference refuses at once. Even `-b2`
/// over three 1 GiB files spun 4e8 iterations.
fn first_size_within(lengths: &[u64], start: u64, stop: u64, target: u64) -> u64 {
    debug_assert_eq!(start % 4, 0, "the search walks multiples of 4");
    if start >= stop {
        return start;
    }
    if slice_total(lengths, start) <= target {
        return start;
    }
    // The step index the scan would stop at for want of room: the first
    // `k` with `start + 4k >= stop`.
    let last = stop.saturating_sub(start).div_ceil(4);
    let (mut lo, mut hi) = (1u64, last);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if slice_total(lengths, start.saturating_add(4 * mid)) <= target {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    start.saturating_add(4 * lo)
}

/// A `u64` the user typed, narrowed to `usize` by CLAMPING.
///
/// `as usize` truncates on a 32-bit target (armv7 is one), so a figure
/// out of range came back as a small, plausible and entirely different
/// number - `-c4294967297` as 1. Saturating leaves the clamps and range
/// checks downstream in charge of the answer, which is where the
/// decision belongs; on a 64-bit target this is the identity.
fn as_count(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// Slices this grid costs: per FILE, never over the pooled total.
pub fn slice_total(lengths: &[u64], bs: u64) -> u64 {
    if bs == 0 {
        return u64::MAX;
    }
    lengths.iter().map(|&l| l.div_ceil(bs)).sum()
}

/// `-c` wins outright; `-r` is a percentage of the block count or a
/// target size in bytes; neither means the reference's default
/// percentage.
pub fn recovery_blocks(opts: &Options, blocks: u64, block_size: u64) -> u64 {
    if let Some(c) = opts.recovery_count {
        return c;
    }
    match opts.redundancy {
        Some(Redundancy::Percent(p)) => percent_blocks(blocks, u64::from(p)),
        // `-r<c><n>` asks for a SIZE of recovery data. No captured row
        // exercises it (the sweep's `-r` value is a bare `1`), so this
        // is the reading the manual gives and is listed as such in the
        // chip's sign-off rather than claimed as measured.
        Some(Redundancy::TargetBytes(b)) if block_size > 0 => b.div_ceil(block_size),
        Some(Redundancy::TargetBytes(_)) => 0,
        None => percent_blocks(blocks, u64::from(help::DEFAULT_REDUNDANCY_PCT)),
    }
}

/// The reference's percentage rule, measured rather than assumed:
/// round to NEAREST, halves up, and never fewer than one block when a
/// non-zero percentage was asked for.
///
/// Probed against par2cmdline-turbo 1.5.0 on 3 Sep 2026, over 32 input
/// blocks: `-r49` -> 16, `-r50` -> 16, `-r51` -> 16, `-r52` -> 17. Plain
/// `ceil` gives 17 at 51% and is wrong; plain truncation gives 0 at
/// `-r1` where the reference gives 1 and is wrong the other way. Both
/// spellings were in this file for an afternoon and the captured
/// `sweep/r` row is what caught the second.
pub fn percent_blocks(blocks: u64, pct: u64) -> u64 {
    if pct == 0 || blocks == 0 {
        return 0;
    }
    blocks
        .saturating_mul(pct)
        .saturating_add(50)
        .saturating_div(100)
        .max(1)
}

/// The set summary the reference prints before it opens anything.
fn print_header(
    opts: &Options,
    sink: &mut Sink,
    block_size: u64,
    files: usize,
    blocks: u64,
    recovery: u64,
) {
    if !sink.shows(Level::Normal) {
        return;
    }
    sink.line(Level::Normal, &format!("Block size: {block_size}"));
    sink.line(Level::Normal, &format!("Source file count: {files}"));
    sink.line(Level::Normal, &format!("Source block count: {blocks}"));
    sink.line(Level::Normal, &format!("Recovery block count: {recovery}"));
    sink.line(
        Level::Normal,
        &format!(
            "Recovery file count: {}",
            recovery_file_count(opts, recovery)
        ),
    );
    sink.line(Level::Normal, "");
}

/// The layout parfast creates under: the volume split `-u` and `-n`
/// ask for, always with par2cmdline's interleaved critical block.
///
/// The interleave is the drop-in's, not the engine's. par2cmdline
/// repeats the whole critical block through every volume, which makes a
/// volume several times larger than one carrying a single copy at its
/// head - 39,696 bytes against 39,672 for a one-slice volume and
/// 340,360 against 64,564 for the largest of a ten-file set, measured
/// 3 Sep 2026. Four e2e fixtures turn on that size (they poison, or
/// band, a volume by its byte count), so a `par2` that writes smaller
/// volumes is not a drop-in however right its packets are. nzbfast's
/// own posting path keeps [`par2gen::CriticalLayout::Head`]: the
/// packets reach a downloader either way and the second copy is bytes
/// on the wire (research/CLI-SUBSTITUTION-2026-09-03.md, G2).
///
/// Both switches steer ONLY this. They used to be parsed and then
/// dropped, so `par2 create -n4 ...` printed `Recovery file count: 4`
/// and wrote five volumes on the default exponential split - the
/// binary's own stdout contradicting its own output directory, and the
/// shape six e2e fixtures broke on the day parfast stood in for `par2`
/// (research/CLI-SUBSTITUTION-2026-09-03.md). The conformance table
/// could not see it: the `create-nfiles` and `create-uniform` rows
/// carried a `:files` waiver whose stated reason was the Creator packet
/// and the volume interleave, so the geometry difference sat underneath
/// a waiver written for something else.
pub fn create_plan(
    opts: &Options,
    recovery: u64,
    largest_member: u64,
    block_size: u64,
) -> par2gen::CreatePlan {
    let base = par2gen::CreatePlan::ENGINE
        .with_critical(par2gen::CriticalLayout::Interleaved)
        // `-f`, the First Recovery-Block-Number. It was parsed, used as
        // the volume-name PADDING WIDTH, and never reached the
        // exponents - so the documented supplementary create
        // (`-f16 -c16` beside an existing 0..15 set) rewrote the index
        // under a new set id, wrote over the existing vol000+ files, and
        // produced nothing at or above 16. The user's complementary set
        // did not exist and their volume names collided.
        .with_first_exponent(as_count(opts.first_block))
        // The ceiling on one volume, in slices. TWO switches can set
        // one and both are ceilings - see `volume_ceiling`.
        .with_max_blocks_per_volume(volume_ceiling(opts, largest_member, block_size))
        // `--no-clobber`. OFF unless asked, because the reference
        // overwrites and this is a drop-in - see `cli::Options::
        // no_clobber`. This is the one translation point, so the Create
        // pane's preview reaches it too and cannot describe a create
        // under a different write policy from the one that runs.
        .with_no_clobber(opts.no_clobber);
    // Neither switch given is the exponential default, and it must stay
    // literally that call: `Even` over the same COUNT is a different
    // split (1+2+4+8+5 against 4+4+4+4+4), so routing the default
    // through it would reshape every set nzbfast posts.
    if opts.recovery_files.is_none() && !opts.uniform {
        return base;
    }
    match recovery_file_count(opts, recovery) {
        0 => base,
        n => base.with_volumes(par2gen::VolumePlan::Even(as_count(n))),
    }
}

/// The largest number of recovery slices ONE volume may carry, or
/// `None` when neither switch that can set one was given.
///
/// Two switches can, and they mean different things:
///
/// - `-l`, "limit the size of the recovery files": no recovery file
///   larger than the largest input file. A ceiling in BYTES, and the
///   layout counts in slices, so it converts here where both numbers
///   are in hand.
/// - `--volume-blocks=N`, parfast's own, already in slices. The
///   reference has no spelling for it, which is why it is a long
///   option (spec R.3) and why `pf_capabilities.volume_limit_explicit`
///   was false until it existed.
///
/// Both are CEILINGS, so when both are given the tighter one wins.
/// Neither can make a volume bigger and neither changes a plan that
/// already fits - `par2gen::CreatePlan::max_blocks_per_volume` says so
/// at the other end.
///
/// This is the ONE place either ceiling is resolved, so the Create
/// pane's preview and the create it previews cannot disagree about it:
/// `parfast_session::planner::preview` reaches it through
/// [`create_plan`], and so does [`run`].
pub fn volume_ceiling(opts: &Options, largest_member: u64, block_size: u64) -> Option<usize> {
    let from_limit = opts
        .limit
        .then(|| as_count((largest_member / block_size.max(1)).max(1)))
        .filter(|_| block_size > 0);
    let explicit = opts
        .volume_blocks
        .map(|n| usize::try_from(n.max(1)).unwrap_or(usize::MAX));
    match (from_limit, explicit) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// How many volume files the reference's sizing rule produces.
pub fn recovery_file_count(opts: &Options, recovery: u64) -> u64 {
    if recovery == 0 {
        return 0;
    }
    if let Some(n) = opts.recovery_files {
        return u64::from(n).min(recovery);
    }
    // `-u` does NOT mean "one volume per block", and it does not change
    // the COUNT at all: it keeps however many volumes the variable plan
    // would have written and makes them equal sizes, so 20 blocks stay
    // 5 volumes and become 4+4+4+4+4 rather than 1+2+4+8+5. That is why
    // uniform and the default share this line. Measured against
    // par2cmdline 1.3.0 over ten recovery counts on 3 Sep 2026; the
    // uniform arm used to return `recovery`, so the header said 20
    // where the reference said 5.
    par2gen::variable_volume_count(as_count(recovery)) as u64
}

/// par2gen names its volumes `<base>.vol{first:03}+{count:02}.par2` on a
/// fixed width; par2cmdline sizes the two fields to the EXPONENT SPACE,
/// and a drop-in has to write its names because the next tool along
/// finds volumes by that pattern.
///
/// # The widths, measured against the reference on 3 Sep 2026
///
/// The first field is as wide as `first_block + recovery` - the exponent
/// one past the last one written - and NOT as wide as the largest index
/// that actually appears. Thirteen blocks from zero are written
/// `vol00+1 vol01+2 vol03+4 vol07+6`: the widest index present is 7, one
/// digit, and the field is two. A hundred from zero go three wide with
/// the largest index at 63. Nine from 95 go three wide, ending
/// `vol102+2`.
///
/// The second field is as wide as the largest COUNT, which does track
/// what appears: those same thirteen blocks end `+6`, one digit, while a
/// hundred reach `+37`.
///
/// # The spec's own spelling, `--std-naming`
///
/// par2cmdline writes the first exponent and the COUNT; the PAR2 spec's
/// own form is the first exponent and the LAST - `set.vol12-22.par2`
/// where par2cmdline writes `set.vol12+11.par2`. Some tools read only
/// that form, so `--std-naming` selects it. Both fields are exponents
/// there, so both take the FIRST field's width: twelve and twenty-two
/// are two digits each, and thirteen blocks from zero go
/// `vol00-00 vol01-02 vol03-06 vol07-12`.
///
/// Renaming after the fact is safe and is not a workaround: a PAR2
/// volume's packets carry no filename of their own, so the bytes are
/// untouched and only the directory entry moves.
///
/// # Why this is a function over NAMES and not a loop over files
///
/// The Create pane has to show a poster the file names BEFORE anything
/// is written, and `par2gen::plan_files` answers in the engine's own
/// fixed-width spelling (its `PlannedFile::name` doc says so and points
/// here). [`final_volume_names`] is what both callers read, so a
/// preview cannot name a file the create will not write - which is the
/// same invariant the selection rules above are `pub` for.
pub fn final_volume_names(
    base: &str,
    written: &[String],
    first_block: u64,
    recovery: u64,
    std_naming: bool,
) -> Vec<String> {
    let parsed: Vec<Option<(u64, u64)>> = written
        .iter()
        .map(|name| split_volume_name(base, name))
        .collect();
    let fw = digits(first_block.saturating_add(recovery));
    let cw = parsed
        .iter()
        .flatten()
        .map(|&(_, c)| digits(c))
        .max()
        .unwrap_or(1);
    written
        .iter()
        .zip(&parsed)
        .map(|(name, parsed)| match *parsed {
            // The last exponent, not one past it: a volume carrying
            // `count` slices from `first` ends at `first + count - 1`.
            Some((first, count)) if std_naming => {
                let last = first.saturating_add(count.saturating_sub(1));
                format!("{base}.vol{first:0fw$}-{last:0fw$}.par2")
            }
            Some((first, count)) => format!("{base}.vol{first:0fw$}+{count:0cw$}.par2"),
            // Not a volume - the index - and it keeps its name.
            None => name.clone(),
        })
        .collect()
}

/// [`final_volume_names`] applied to what the writer left on disk.
///
/// Answers the renames that did NOT happen, as
/// `(engine name, final name, why)`. An empty vector is the whole set
/// published under the names the caller asked for, and nothing else is.
///
/// # Why this is not `let _ =`
///
/// It was, and the caller then printed `Done` and returned zero
/// unconditionally. A final name occupied by a DIRECTORY, a
/// cross-device layout, a read-only parent, a Windows share that refuses
/// the rename - each leaves the engine's `vol000+01` spelling on disk,
/// the requested `vol0+1` absent, and the command claiming success. A
/// caller cannot tell the two apart afterwards either, because both
/// spellings match the same "is this one of ours" scan.
///
/// Renaming is part of PUBLICATION, not a cosmetic pass after it: the
/// names are what `final_volume_names` promised the preview, so a create
/// that could not write them has not written the set that was asked for.
///
/// # `no_clobber` and why this arm is a check and not an open
///
/// `std::fs::rename` REPLACES its destination - that is what the POSIX
/// call does and there is no portable no-clobber spelling of it - so
/// under `--no-clobber` the engine's `O_EXCL` opens would refuse every
/// file of the set and this pass would then quietly write over the one
/// name the user actually sees. A destination that exists is therefore
/// checked here and reported as a rename that did not happen, which is
/// the same outcome and the same message as a destination occupied by a
/// directory.
///
/// It is a check-then-act and it is honestly weaker than the engine's
/// door: something that creates the final name between the check and the
/// rename still loses it. That window is much narrower than it looks,
/// because the INDEX is the first member the engine creates and it is
/// never renamed - so two creates over one base have already been
/// separated by `O_EXCL` long before either reaches this line, and what
/// is left is a create racing an unrelated writer over one volume name.
#[must_use = "a rename that failed leaves the set under the engine's own names"]
pub fn rename_volumes(
    dir: &Path,
    base: &str,
    written: &[String],
    first_block: u64,
    recovery: u64,
    std_naming: bool,
    no_clobber: bool,
) -> Vec<(String, String, std::io::Error)> {
    let want = final_volume_names(base, written, first_block, recovery, std_naming);
    let mut failed = Vec::new();
    for (name, want) in written.iter().zip(&want) {
        if want == name {
            continue;
        }
        // `symlink_metadata`, not `exists`: a dangling symlink under the
        // final name is still a file the rename would replace, and
        // `exists` follows the link and answers no.
        if no_clobber && dir.join(want).symlink_metadata().is_ok() {
            failed.push((
                name.clone(),
                want.clone(),
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "a file is already there and --no-clobber was given",
                ),
            ));
            continue;
        }
        if let Err(e) = std::fs::rename(dir.join(name), dir.join(want)) {
            failed.push((name.clone(), want.clone(), e));
        }
    }
    failed
}

/// `<base>.vol<first>+<count>.par2` back into its two numbers.
pub fn split_volume_name(base: &str, name: &str) -> Option<(u64, u64)> {
    let rest = name
        .strip_prefix(base)?
        .strip_prefix(".vol")?
        .strip_suffix(".par2")?;
    let (first, count) = rest.split_once('+')?;
    Some((first.parse().ok()?, count.parse().ok()?))
}

/// Decimal width of `n`, floored at 1.
fn digits(n: u64) -> usize {
    n.checked_ilog10().unwrap_or(0) as usize + 1
}

#[cfg(test)]
mod tests {

    use super::*;

    /// THE FileDesc NAME IS FORWARD-SLASHED ON EVERY PLATFORM, which is
    /// `Member`'s documented contract and was broken on windows only -
    /// see `spec_member_name`. This test runs on any host because the
    /// helper re-spells COMPONENTS rather than replacing a character, so
    /// the unix side of it (a backslash that is part of a filename and
    /// must survive) is checkable from the same box as the windows side.
    #[test]
    fn a_member_name_uses_the_spec_separator() {
        assert_eq!(spec_member_name(Path::new("text.txt")), "text.txt");
        assert_eq!(spec_member_name(Path::new("./text.txt")), "text.txt");
        // The case the windows conformance row found: a member below the
        // top level. On unix this is already one component per level and
        // the answer is unchanged; on windows `to_string_lossy` gave
        // `linkdir\nested.txt` here and this gives the spec's spelling.
        let nested: std::path::PathBuf = ["linkdir", "nested.txt"].iter().collect();
        assert_eq!(spec_member_name(&nested), "linkdir/nested.txt");
        let deep: std::path::PathBuf = ["a", "b", "c.bin"].iter().collect();
        assert_eq!(spec_member_name(&deep), "a/b/c.bin");
        // AND A SEPARATOR THAT IS NOT ONE. On unix a backslash is an
        // ordinary filename character, so this is ONE component and must
        // come back whole - which is why the fix joins components and
        // does not `replace('\\', "/")`. On windows such a name cannot
        // exist, and `components()` splits it, so the assertion is
        // written for the platform that can hold it.
        #[cfg(unix)]
        assert_eq!(
            spec_member_name(Path::new(r"weird\name.txt")),
            r"weird\name.txt"
        );
        // AND THE CONSOLE HALF GOES BACK THE OTHER WAY. par2cmdline
        // prints the path it opened and stores the spec's spelling, so
        // the two differ on windows and agree everywhere else.
        let shown = display_member_name(&spec_member_name(&nested));
        #[cfg(unix)]
        assert_eq!(shown, "linkdir/nested.txt");
        #[cfg(windows)]
        assert_eq!(shown, r"linkdir\nested.txt");
        assert_eq!(display_member_name("text.txt"), "text.txt");
    }

    /// UNDER `-a` THE FIRST BARE ARGUMENT IS A MEMBER, NOT THE OUTPUT -
    /// and the no-self-overwrite guard below shipped reading it as the
    /// output, so `parfast c -aout2.par2 text.txt rand.bin` protected
    /// rand.bin alone and said Done.
    ///
    /// Found 17 Sep 2026 by `tools/conformance/run.py par2`, which no
    /// CI job runs against this binary: `par2-conformance` builds the
    /// pinned par2cmdline and checks it against its OWN committed
    /// table, so it is a table-freshness guard and never a drop-in one.
    /// The reference protects both files.
    #[test]
    fn an_archive_name_does_not_turn_the_first_source_into_the_output() {
        let dir = std::env::temp_dir().join(format!(
            "parfast-archivename-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("text.txt"), b"hello there this is text\n").unwrap();
        std::fs::write(dir.join("rand.bin"), vec![9u8; 4096]).unwrap();
        let opts = Options {
            archive: Some(dir.join("out2.par2")),
            par2: Some(dir.join("text.txt")),
            files: vec![dir.join("rand.bin")],
            block_size: Some(32),
            recovery_count: Some(1),
            ..Default::default()
        };
        assert_eq!(run(&opts, &mut crate::out::Sink::buffered()), 0);
        let set = nzbkit::par2::Par2Set::parse(&[&std::fs::read(dir.join("out2.par2")).unwrap()])
            .expect("our own set parses");
        let mut names: Vec<String> = set.files.iter().map(|f| f.name.clone()).collect();
        names.sort();
        assert_eq!(
            names,
            vec!["rand.bin".to_string(), "text.txt".to_string()],
            "both bare arguments are members once -a named the set"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE WALK IS THE REFERENCE'S WALK: a link is not followed and not
    /// protected, and nothing that is not an ordinary file is a member.
    ///
    /// Measured against par2cmdline 1.2.0 on 17 Sep 2026 rather than
    /// read out of its source. Over a folder holding
    /// `dirlink -> ../other`, `filelink -> real.bin` and a `mkfifo`d
    /// entry beside one real file, the reference answers
    /// `Source file count: 1` and opens only the real file - the fifo
    /// does not even reach its own "Skipping 0 byte file" line - and an
    /// explicitly NAMED link is refused outright with "You must specify
    /// a list of files when creating."
    ///
    /// This walk followed them until that day, which is a fidelity gap
    /// and a defect in its own right: `loop -> .` is re-entered at every
    /// level until the kernel's 32-link `stat` limit stops it, so ONE
    /// file becomes 33 members of a set 33 times the size it should be.
    /// `named.dedup()` cannot see it - the 33 spellings are 33 different
    /// paths. The ARGUMENT is left alone, deliberately: `/tmp` is a link
    /// on macOS and a user who typed a path meant the path.
    #[cfg(unix)]
    #[test]
    fn a_walk_takes_only_ordinary_files_and_never_follows_a_link() {
        unsafe extern "C" {
            #[link_name = "mkfifo"]
            fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
        }
        let dir = std::env::temp_dir().join(format!(
            "parfast-walk-rules-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let inside = dir.join("chosen");
        let outside = dir.join("elsewhere");
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(inside.join("movie.mkv"), vec![4u8; 30_000]).unwrap();
        std::fs::write(outside.join("theirs.bin"), vec![5u8; 30_000]).unwrap();
        std::os::unix::fs::symlink(&outside, inside.join("out")).unwrap();
        std::os::unix::fs::symlink("movie.mkv", inside.join("alias.mkv")).unwrap();
        std::os::unix::fs::symlink(".", inside.join("loop")).unwrap();
        let pipe = inside.join("pipe");
        let c = std::ffi::CString::new(pipe.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: `c` is a NUL-terminated C string that outlives the
        // call, which is all `mkfifo(2)` asks of its argument.
        assert_eq!(unsafe { mkfifo(c.as_ptr(), 0o644) }, 0, "mkfifo");

        let index = dir.join("set.par2");
        let opts = Options {
            par2: Some(index.clone()),
            files: vec![inside.clone()],
            recurse: true,
            block_size: Some(8192),
            recovery_count: Some(1),
            ..Default::default()
        };
        assert_eq!(run(&opts, &mut crate::out::Sink::buffered()), 0);
        let set = nzbkit::par2::Par2Set::parse(&[&std::fs::read(&index).unwrap()])
            .expect("our own set parses");
        let mut names: Vec<String> = set.files.iter().map(|f| f.name.clone()).collect();
        names.sort();
        assert_eq!(
            names,
            vec!["chosen/movie.mkv".to_string()],
            "one ordinary file in the chosen folder, protected once"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A WILDCARD SOURCE BESIDE A LITERAL REFUSES, AND WRITES NOTHING.
    ///
    /// The regression this pins is not "parfast does not glob" - that
    /// was always true and always loud. It is the SILENT half: the
    /// unexpandable argument used to be dropped from the member list,
    /// so the surviving literal carried the create to exit 0 and a
    /// valid set protecting one file of two was written with no
    /// diagnostic at all. The assertion that matters is the third one:
    /// no set on disk. An exit code alone would still pass if the
    /// create refused AFTER writing an index.
    #[test]
    fn a_wildcard_source_beside_a_literal_refuses_and_writes_nothing() {
        let dir = std::env::temp_dir().join(format!(
            "parfast-wildcard-drop-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("text.txt"), b"a text member\n").unwrap();
        std::fs::write(dir.join("rand.bin"), vec![7u8; 40_000]).unwrap();

        let opts = Options {
            par2: Some(dir.join("out.par2")),
            files: vec![dir.join("*.txt"), dir.join("rand.bin")],
            block_size: Some(8192),
            recovery_count: Some(1),
            ..Default::default()
        };
        assert_eq!(
            run(&opts, &mut crate::out::Sink::buffered()),
            crate::EXIT_INVALID_ARGS,
            "a wildcard source argument must fail the create, not be dropped from it"
        );
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".par2"))
            .collect();
        assert!(
            left.is_empty(),
            "the refused create still wrote a set: {left:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// AND THE REFUSAL DOES NOT REACH A REAL FILE WHOSE NAME CONTAINS A
    /// METACHARACTER. `*` and `?` are ordinary filename characters on
    /// unix, so the test is `has_wildcard AND does not exist` rather
    /// than `has_wildcard` alone - a blanket refusal would stop
    /// protecting a file the reference opens without comment, which is
    /// a regression in the opposite direction from the one above.
    ///
    /// Unix only: `?` cannot appear in a Win32 filename, so there is no
    /// such file to create on windows and the case does not exist there.
    #[cfg(unix)]
    #[test]
    fn a_real_file_whose_name_holds_a_metacharacter_is_still_protected() {
        let dir = std::env::temp_dir().join(format!(
            "parfast-wildcard-literal-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let odd = dir.join("weird?.bin");
        std::fs::write(&odd, vec![3u8; 40_000]).unwrap();

        let opts = Options {
            par2: Some(dir.join("out.par2")),
            files: vec![odd],
            block_size: Some(8192),
            recovery_count: Some(1),
            ..Default::default()
        };
        assert_eq!(
            run(&opts, &mut crate::out::Sink::buffered()),
            crate::EXIT_SUCCESS,
            "a file that really exists must be protected whatever its name spells"
        );
        assert!(dir.join("out.par2").exists(), "no index was written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A WILDCARD IN THE SET NAME NEVER BECOMES A FILENAME. Before this,
    /// `parfast c -b32 *.par2 text.txt` exited 0 on posix having written
    /// files literally called `*.par2` and `*.vol0+1.par2`. The
    /// reference refuses it outright.
    ///
    /// Posix only, matching `cli::refuse_wildcard_set_name`'s own gate:
    /// on windows the reference never reaches its check either and both
    /// binaries fail at the OS instead, with a different exit code.
    #[cfg(not(windows))]
    #[test]
    fn a_wildcard_set_name_is_refused_rather_than_created() {
        let dir = std::env::temp_dir().join(format!(
            "parfast-wildcard-setname-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("text.txt"), vec![5u8; 40_000]).unwrap();

        let opts = Options {
            par2: Some(dir.join("*.par2")),
            files: vec![dir.join("text.txt")],
            block_size: Some(8192),
            recovery_count: Some(1),
            ..Default::default()
        };
        assert_eq!(
            run(&opts, &mut crate::out::Sink::buffered()),
            crate::EXIT_INVALID_ARGS
        );
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains('*'))
            .collect();
        assert!(
            left.is_empty(),
            "a file was created under a name holding a wildcard: {left:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// L1 (reports/code-audit-2026-09-17), in THIS tree rather than the
    /// legacy one: a create never destroys a file it was asked to
    /// protect.
    ///
    /// The sweep found the collision in the old standalone checkout and
    /// asked for the current CLI to be checked independently. It was
    /// checked, and it had it: `parfast c set.par2 set.par2` opened the
    /// index as a member, measured 40,000 bytes, wrote the index over it
    /// with `File::create`, and folded recovery out of the 480 bytes it
    /// had just left there. The engine's own length check then fired
    /// ("changed length while the PAR2 set was being built") and the
    /// command failed - with the user's file already gone, which is the
    /// only part that matters.
    ///
    /// Three arms, because each reaches the same destruction by a
    /// different route: the index named as a source, one of the set's
    /// own recovery VOLUMES swept back in by a glob on a re-run (by far
    /// the commonest route in the field), and the index reached through
    /// a SYMLINK, where a path comparison sees two different names.
    #[test]
    fn a_create_never_protects_a_file_it_is_about_to_write() {
        let dir = std::env::temp_dir().join(format!(
            "parfast-self-overwrite-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let index = dir.join("set.par2");
        let sentinel: Vec<u8> = (0..40_000u32).map(|i| (i * 13 + 7) as u8).collect();

        // 1. The index named as its own only source. Nothing is left to
        //    protect, so the create refuses - and the file is intact.
        std::fs::write(&index, &sentinel).unwrap();
        let opts = Options {
            par2: Some(index.clone()),
            files: vec![index.clone()],
            block_size: Some(8192),
            recovery_count: Some(1),
            ..Default::default()
        };
        assert_eq!(
            run(&opts, &mut crate::out::Sink::buffered()),
            crate::EXIT_INVALID_ARGS
        );
        assert_eq!(
            std::fs::read(&index).unwrap(),
            sentinel,
            "the create wrote its index over the file it was protecting"
        );

        // 2. A RECOVERY VOLUME of this same set, which is what
        //    `parfast c set.par2 *` sweeps back in on every re-run. The
        //    real member is protected and the volume is not a member.
        let member = dir.join("movie.mkv");
        std::fs::write(&member, vec![4u8; 30_000]).unwrap();
        let volume = dir.join("set.vol0+1.par2");
        std::fs::write(&volume, &sentinel).unwrap();
        let opts = Options {
            par2: Some(index.clone()),
            files: vec![member.clone(), index.clone(), volume.clone()],
            block_size: Some(8192),
            recovery_count: Some(1),
            ..Default::default()
        };
        assert_eq!(run(&opts, &mut crate::out::Sink::buffered()), 0);
        let set = nzbkit::par2::Par2Set::parse(&[&std::fs::read(&index).unwrap()])
            .expect("our own set parses");
        let names: Vec<String> = set.files.iter().map(|f| f.name.clone()).collect();
        assert_eq!(
            names,
            vec!["movie.mkv".to_string()],
            "the set protects its own files"
        );

        // 3. Through a SYMLINK, where the two spellings do not compare
        //    equal and only the file's identity says they are one file.
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&index);
            std::fs::write(&index, &sentinel).unwrap();
            let link = dir.join("alias.par2");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&index, &link).unwrap();
            let opts = Options {
                par2: Some(index.clone()),
                files: vec![link],
                block_size: Some(8192),
                recovery_count: Some(1),
                ..Default::default()
            };
            assert_eq!(
                run(&opts, &mut crate::out::Sink::buffered()),
                crate::EXIT_INVALID_ARGS
            );
            assert_eq!(
                std::fs::read(&index).unwrap(),
                sentinel,
                "a symlink to the index is still the index"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P9 (reports/code-audit-2026-09-17): a create whose final names
    /// could not be written must not report success.
    ///
    /// `rename_volumes` discarded every `fs::rename` error and returned
    /// nothing, and the caller printed `Done` and returned zero
    /// whatever happened. The set was then on disk under the ENGINE's
    /// fixed-width spelling (`set.vol000+01.par2`) with the requested
    /// `set.vol0+1.par2` absent, and nobody downstream could tell:
    /// "is this one of ours" matches both spellings, so the GUI listed
    /// the wrong names as this job's output and the exit code agreed
    /// with it.
    ///
    /// A DIRECTORY sitting on the final name is the portable way to
    /// make one rename fail without root or a second filesystem - it is
    /// `ENOTDIR`/`EISDIR` on unix and the same refusal on Windows - and
    /// it is also a shape a user reaches by accident.
    #[test]
    fn a_create_that_cannot_publish_its_final_names_does_not_report_done() {
        let dir = std::env::temp_dir().join(format!(
            "parfast-rename-fail-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let member = dir.join("a.bin");
        std::fs::write(&member, vec![5u8; 40_000]).unwrap();
        // ONE recovery block, so the engine writes `set.vol000+01.par2`
        // and the rename wants `set.vol0+1.par2`.
        let opts = Options {
            par2: Some(dir.join("set.par2")),
            files: vec![member],
            block_size: Some(8192),
            recovery_count: Some(1),
            ..Default::default()
        };
        // The blocker. Asserted to be the name the rename actually
        // wants, so the test cannot pass by aiming at the wrong file.
        let blocked = dir.join("set.vol0+1.par2");
        assert_eq!(
            final_volume_names("set", &["set.vol000+01.par2".to_string()], 0, 1, false),
            vec!["set.vol0+1.par2".to_string()],
            "the final name this test blocks is not the one the create asks for"
        );
        std::fs::create_dir(&blocked).unwrap();

        let code = run(&opts, &mut crate::out::Sink::buffered());
        assert_ne!(
            code,
            crate::EXIT_SUCCESS,
            "a create that could not publish its final names claimed success"
        );
        assert!(
            blocked.is_dir(),
            "the create must not have removed what was in its way"
        );
        // And the bytes are still there under the engine's spelling, so
        // the failure is a naming one and nothing was thrown away.
        assert!(
            dir.join("set.vol000+01.par2").is_file(),
            "the recovery volume itself went missing"
        );

        // The control arm: the same create with nothing in the way both
        // succeeds AND publishes the final name, so the refusal above is
        // the rename and not the create.
        let _ = std::fs::remove_dir(&blocked);
        let code = run(&opts, &mut crate::out::Sink::buffered());
        assert_eq!(code, crate::EXIT_SUCCESS);
        assert!(blocked.is_file(), "the final name was never published");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE PLUMB for `--comment`, which is the half this repo has
    /// shipped broken twice (`-m` and `-t` both parsed onto `Options`
    /// and were read by nobody). A parse assertion alone would have
    /// passed on both of those days, so this drives a whole create and
    /// reads the comment back out of the bytes on disk.
    ///
    /// The set is built by the ENGINE and never by an external `par2`,
    /// which is why there is no `have_par2()` guard here - the engine
    /// implements the comment packet and par2cmdline implements neither.
    #[test]
    fn the_comment_switch_reaches_the_set_on_disk() {
        let dir = std::env::temp_dir().join(format!(
            "parfast-comment-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let member = dir.join("a.bin");
        std::fs::write(&member, vec![7u8; 60_000]).unwrap();

        let create_with = |comment: Option<&str>| {
            let opts = Options {
                par2: Some(dir.join("set.par2")),
                files: vec![member.clone()],
                block_size: Some(4096),
                recovery_count: Some(4),
                comment: comment.map(str::to_string),
                ..Default::default()
            };
            let code = run(&opts, &mut crate::out::Sink::buffered());
            (
                code,
                std::fs::read(dir.join("set.par2")).unwrap_or_default(),
            )
        };

        let (code, index) = create_with(Some("posted from the create switch"));
        assert_eq!(code, crate::EXIT_SUCCESS);
        let set = nzbkit::par2::Par2Set::parse(&[&index]).expect("our own set parses");
        assert_eq!(
            set.comment.as_deref(),
            Some("posted from the create switch")
        );

        // And a comment the engine refuses fails the create out loud
        // rather than writing a set with the comment quietly dropped.
        let (code, _) = create_with(Some("wipe \u{1b}[2J"));
        assert_ne!(code, crate::EXIT_SUCCESS, "a refused comment fails loudly");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reference's widths, and the spec's own spelling beside
    /// them, over the thirteen-blocks-from-zero set the width rule
    /// above was measured on. Both read the SAME parsed (first, count)
    /// pairs, so a set can be renamed either way and nothing else moves.
    #[test]
    fn the_spec_form_names_the_last_exponent_where_par2cmdline_names_the_count() {
        // What `par2gen` leaves on disk, in its own fixed widths.
        let written: Vec<String> = ["000+01", "001+02", "003+04", "007+06"]
            .iter()
            .map(|v| format!("set.vol{v}.par2"))
            .collect();

        let reference = final_volume_names("set", &written, 0, 13, false);
        assert_eq!(
            reference,
            [
                "set.vol00+1.par2",
                "set.vol01+2.par2",
                "set.vol03+4.par2",
                "set.vol07+6.par2"
            ],
            "the first field is as wide as first + recovery, the second as the largest count"
        );

        let spec = final_volume_names("set", &written, 0, 13, true);
        assert_eq!(
            spec,
            [
                "set.vol00-00.par2",
                "set.vol01-02.par2",
                "set.vol03-06.par2",
                "set.vol07-12.par2"
            ],
            "the spec form is first and LAST exponent, both in the first field's width"
        );
        // The example the contract quotes: twelve blocks from twelve is
        // `vol12+11` to par2cmdline and `vol12-22` to the spec.
        assert_eq!(
            final_volume_names("set", &["set.vol012+11.par2".to_string()], 12, 11, true),
            ["set.vol12-22.par2"]
        );
    }

    /// The index is not a volume and keeps its name under either
    /// spelling - the property that lets a preview map its whole file
    /// list through one call.
    #[test]
    fn a_name_that_is_not_a_volume_maps_to_itself() {
        let written = vec!["set.par2".to_string(), "set.vol000+01.par2".to_string()];
        for std_naming in [false, true] {
            let out = final_volume_names("set", &written, 0, 1, std_naming);
            assert_eq!(out[0], "set.par2", "std_naming={std_naming}");
        }
    }

    /// TWO switches can cap a volume and both are ceilings, so the
    /// tighter one wins whichever way round they are given. `-l` is a
    /// bound on the largest SOURCE file; `--volume-blocks` says the
    /// number outright, which is the one the reference cannot spell.
    #[test]
    fn the_tighter_of_the_two_volume_ceilings_wins() {
        // One 200,000-byte member at 2,048 is 97 blocks of `-l`.
        let with = |limit: bool, explicit: Option<u64>| {
            let o = Options {
                limit,
                volume_blocks: explicit,
                ..Default::default()
            };
            volume_ceiling(&o, 200_000, 2_048)
        };
        assert_eq!(with(false, None), None, "neither switch caps anything");
        assert_eq!(with(true, None), Some(97), "-l alone");
        assert_eq!(with(false, Some(5)), Some(5), "--volume-blocks alone");
        assert_eq!(with(true, Some(5)), Some(5), "the explicit one is tighter");
        assert_eq!(with(true, Some(500)), Some(97), "-l is tighter");
        // A zero ceiling would ask for volumes that carry nothing; it is
        // raised to one rather than refused, and the CLI refuses it at
        // the parse anyway.
        assert_eq!(with(false, Some(0)), Some(1));
    }

    /// A slice a big payload cannot carry is RAISED, never refused, and only
    /// as far as it has to be: to the smallest MULTIPLE of the request that
    /// fits under the 32,768-slice ceiling.
    ///
    /// It was "the smallest legal slice, stepping by 4" until the multiple
    /// rule replaced it. Stepping by 4 lands between article multiples and
    /// gives away the alignment that keeps a lost article inside one block -
    /// see `legal_block_size`. The old assertion is not loosened here, it is
    /// SUPERSEDED: a multiple is a stricter contract about which size gets
    /// chosen, not a weaker one.
    #[test]
    fn an_illegal_slice_is_raised_to_the_smallest_legal_multiple() {
        let cap = par2gen::MAX_INPUT_SLICES as u64;
        let one = vec![200u64 << 20]; // 200 MiB
        let asked = 4000;
        let raised = legal_block_size(&one, asked);
        assert!(
            raised > asked,
            "4000 was legal for 200 MiB and should not be"
        );
        assert!(
            slice_total(&one, raised) <= cap,
            "raised past the cap: {raised}"
        );
        assert_eq!(raised % asked, 0, "{raised} is not a multiple of {asked}");
        assert!(
            slice_total(&one, raised - asked) > cap,
            "{raised} overshot: {} was already legal",
            raised - asked
        );
    }

    /// The raise lands on a MULTIPLE of what was asked for, so a poster who
    /// aligned their slices to the article size stays aligned after it. An
    /// article straddles a boundary whenever the block is not a whole number
    /// of articles, and a straddling article destroys two blocks instead of
    /// one - so creeping up in steps of 4 gives away the alignment that makes
    /// the recovery data efficient.
    #[test]
    fn the_raise_preserves_the_grid_the_poster_asked_for() {
        let cap = par2gen::MAX_INPUT_SLICES as u64;
        let payload = vec![300u64 << 20]; // 300 MiB
        for asked in [7_680u64, 768_000, 4_000] {
            let got = legal_block_size(&payload, asked);
            if got == asked {
                continue; // already legal, nothing to preserve
            }
            assert_eq!(
                got % asked,
                0,
                "{asked} was raised to {got}, which is not a multiple of it"
            );
            assert!(slice_total(&payload, got) <= cap);
            // and it is the SMALLEST such multiple
            let prev = got - asked;
            assert!(
                prev < asked || slice_total(&payload, prev) > cap,
                "{prev} was already legal, so {got} overshot"
            );
        }
    }

    /// A legal slice is returned untouched, so the ordinary case prints
    /// nothing and the set is exactly what the poster asked for.
    #[test]
    fn a_legal_slice_is_left_alone() {
        let one = vec![200u64 << 20];
        assert_eq!(legal_block_size(&one, 65536), 65536);
        assert_eq!(legal_block_size(&[1u64 << 30], 1 << 20), 1 << 20);
    }

    /// The raise is a SEARCH and not `total / MAX`, because the slice grid
    /// is per FILE: every member is sliced from its own offset zero and the
    /// remainders do not pool, so a division undercounts on a multi-member
    /// set and would hand back a size that is still illegal.
    #[test]
    fn the_raise_counts_the_per_file_grid_not_the_pooled_total() {
        let cap = par2gen::MAX_INPUT_SLICES as u64;
        // Many members whose lengths are not multiples of the slice, so each
        // contributes a partial slice the pooled division would lose.
        let many: Vec<u64> = (0..500).map(|i| (4u64 << 20) + i * 7).collect();
        let raised = legal_block_size(&many, 64);
        assert!(
            slice_total(&many, raised) <= cap,
            "{raised} still needs {} slices",
            slice_total(&many, raised)
        );
        let pooled: u64 = many.iter().sum::<u64>() / cap;
        assert!(
            raised >= pooled,
            "a pooled division ({pooled}) undercounts the per-file grid ({raised})"
        );
    }

    /// The unix collapse only fires on a pattern with a TRAILING slash,
    /// which is why `.` survives at the end of a path and `-B.` refuses
    /// on macOS. Pin the shape rather than the cwd.
    #[test]
    fn a_trailing_dot_survives_the_unix_collapse() {
        assert_eq!(collapse_unix("/a/b/."), "/a/b/.");
        assert_eq!(collapse_unix("/a/b/.."), "/a/b/..");
    }

    #[test]
    fn an_interior_dot_and_dotdot_are_collapsed_the_way_the_c_loop_does() {
        assert_eq!(collapse_unix("/a/./b/c.txt"), "/a/b/c.txt");
        assert_eq!(collapse_unix("/a/b/../c.txt"), "/a/c.txt");
        assert_eq!(collapse_unix("/a/b/../../c.txt"), "/c.txt");
        // Backtracking past the root cannot walk off the front.
        assert_eq!(collapse_unix("/../c.txt"), "/c.txt");
    }

    /// `GetFullPathNameW` resolves the dot completely, which is the half
    /// that makes `-B.` ACCEPT on Windows where macOS refuses.
    #[test]
    fn the_windows_form_resolves_a_dot_and_upper_cases_the_drive() {
        assert_eq!(windows_full_path(r"c:\work\."), PathBuf::from(r"C:\work"));
        assert_eq!(
            windows_full_path(r"c:\work\sub\..\text.txt"),
            PathBuf::from(r"C:\work\text.txt")
        );
        assert_eq!(
            windows_full_path("c:/work/text.txt"),
            PathBuf::from(r"C:\work\text.txt")
        );
    }

    /// The reference never prints an extended-length path, so neither
    /// may we: `\\?\` is what `std::fs::canonicalize` returns and what
    /// took the windows leg red on `Skipping 0 byte file:`.
    #[test]
    fn no_windows_form_carries_the_extended_length_prefix() {
        for raw in [r"c:\work\zero.bin", r"\\server\share\zero.bin", "rel.bin"] {
            let got = windows_full_path(raw);
            assert!(
                !got.to_string_lossy().starts_with(r"\\?\"),
                "{raw} canonicalised to {got:?}"
            );
        }
    }

    #[test]
    fn a_unc_root_is_kept_whole() {
        assert_eq!(
            windows_full_path(r"\\server\share\dir\.\f.bin"),
            PathBuf::from(r"\\server\share\dir\f.bin")
        );
    }

    /// The guard the windows recursion applies, read the way the
    /// reference reads it - off the trailing component as written, so
    /// `.` is seen at all.
    #[test]
    fn the_recursion_guard_reads_the_trailing_component_as_written() {
        assert_eq!(last_component(Path::new(".")), ".");
        assert_eq!(last_component(Path::new("sub")), "sub");
        assert_eq!(last_component(Path::new("./sub")), "sub");
        assert_eq!(last_component(Path::new(r"a\b\.hidden")), ".hidden");
        assert_eq!(dot_named(Path::new(".")), cfg!(windows));
        assert_eq!(dot_named(Path::new(r"a\.hidden")), cfg!(windows));
        assert!(!dot_named(Path::new("sub")));
    }

    /// The set name keeps the case the user spelled it in, and the
    /// extension comes off however it was spelled.
    ///
    /// `strip_suffix(".par2")` matched only lowercase, so
    /// `parfast c Movie.PAR2 text.txt` wrote `Movie.PAR2.par2` and
    /// never created the file that was named. `-a` and verify's
    /// `set_stem` were both already case-insensitive.
    #[test]
    fn the_par2_extension_comes_off_in_any_case() {
        assert_eq!(strip_par2_suffix("Movie.par2"), "Movie");
        assert_eq!(strip_par2_suffix("Movie.PAR2"), "Movie");
        assert_eq!(strip_par2_suffix("Movie.Par2"), "Movie");
        // Not a suffix, and a name that IS the extension keeps its dot.
        assert_eq!(strip_par2_suffix("Movie.par2.bak"), "Movie.par2.bak");
        assert_eq!(strip_par2_suffix("movie"), "movie");
        assert_eq!(strip_par2_suffix(".par2"), "");
        assert_eq!(strip_par2_suffix("par2"), "par2");
    }

    /// A temp directory with one 30 KB source in it, for the
    /// no-clobber arms below, plus the `Options` a plain
    /// `parfast c -s2048 -c1 set.par2 a.bin` parses to.
    fn one_member_create(tag: &str) -> (PathBuf, Options) {
        let dir = std::env::temp_dir().join(format!(
            "parfast-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("a.bin");
        std::fs::write(&src, (0..30_000u32).map(|i| i as u8).collect::<Vec<u8>>()).unwrap();
        let opts = Options {
            par2: Some(dir.join("set.par2")),
            files: vec![src],
            block_size: Some(2048),
            recovery_count: Some(1),
            ..Default::default()
        };
        (dir, opts)
    }

    /// `--no-clobber` over an existing INDEX: the engine's own
    /// `O_EXCL` door answers, the command fails, and the file is
    /// untouched.
    #[test]
    fn no_clobber_refuses_an_existing_index() {
        let (dir, mut opts) = one_member_create("noclobber-index");
        opts.no_clobber = true;
        let theirs = b"the set whose volumes are still beside it".to_vec();
        std::fs::write(dir.join("set.par2"), &theirs).unwrap();

        assert_eq!(
            run(&opts, &mut crate::out::Sink::buffered()),
            crate::EXIT_FILE_IO_ERROR
        );
        assert_eq!(std::fs::read(dir.join("set.par2")).unwrap(), theirs);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--no-clobber` over an existing FINAL volume name, which the
    /// engine's door alone does NOT cover.
    ///
    /// The engine writes `set.vol000+01.par2` and this crate renames it
    /// to par2cmdline's field widths afterwards, so a `set.vol0+1.par2`
    /// already on disk is a name the engine never opens and
    /// `std::fs::rename` would replace without a word. `rename_volumes`
    /// is where that is refused; the create then reports the same
    /// "could not be given their final names" failure as any other
    /// blocked rename, and deletes nothing.
    #[test]
    fn no_clobber_refuses_an_existing_final_volume_name() {
        let (dir, mut opts) = one_member_create("noclobber-final");
        opts.no_clobber = true;
        let theirs = b"an earlier run's only recovery volume".to_vec();
        let final_name = dir.join("set.vol0+1.par2");
        std::fs::write(&final_name, &theirs).unwrap();

        assert_eq!(
            run(&opts, &mut crate::out::Sink::buffered()),
            crate::EXIT_FILE_IO_ERROR
        );
        assert_eq!(
            std::fs::read(&final_name).unwrap(),
            theirs,
            "the rename replaced the file --no-clobber was protecting"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE CONTROL ARM. par2cmdline overwrites and parfast is a
    /// drop-in, so a bare `parfast c` over an existing set still
    /// replaces it - index, engine name and final name alike. A change
    /// to the default would be a divergence the conformance table
    /// cannot see, because no captured row re-runs a create over its
    /// own output.
    #[test]
    fn the_default_create_still_overwrites_an_existing_set() {
        let (dir, opts) = one_member_create("clobber-default");
        std::fs::write(dir.join("set.par2"), b"old index").unwrap();
        std::fs::write(dir.join("set.vol0+1.par2"), b"old volume").unwrap();

        assert_eq!(
            run(&opts, &mut crate::out::Sink::buffered()),
            crate::EXIT_SUCCESS
        );
        assert!(std::fs::metadata(dir.join("set.par2")).unwrap().len() > 64);
        assert!(
            std::fs::metadata(dir.join("set.vol0+1.par2"))
                .unwrap()
                .len()
                > 64
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// And a `--no-clobber` create with nothing in its way writes the
    /// ordinary set: the switch refuses a collision, it does not change
    /// what is written.
    #[test]
    fn no_clobber_over_an_empty_directory_writes_the_ordinary_set() {
        let (clean_dir, clean) = one_member_create("noclobber-clean");
        let (plain_dir, plain) = one_member_create("noclobber-plain");
        let mut clean_opts = clean;
        clean_opts.no_clobber = true;

        assert_eq!(
            run(&clean_opts, &mut crate::out::Sink::buffered()),
            crate::EXIT_SUCCESS
        );
        assert_eq!(
            run(&plain, &mut crate::out::Sink::buffered()),
            crate::EXIT_SUCCESS
        );
        for name in ["set.par2", "set.vol0+1.par2"] {
            assert_eq!(
                std::fs::read(clean_dir.join(name)).unwrap(),
                std::fs::read(plain_dir.join(name)).unwrap(),
                "--no-clobber changed the bytes of {name}"
            );
        }
        let _ = std::fs::remove_dir_all(&clean_dir);
        let _ = std::fs::remove_dir_all(&plain_dir);
    }
}

#[cfg(test)]
mod block_size_search_tests {
    use super::{first_size_within, slice_total};

    /// The linear `bs += 4` scan this replaced, verbatim, as the oracle.
    fn linear(lengths: &[u64], start: u64, stop: u64, target: u64) -> u64 {
        let mut bs = start;
        while bs < stop && slice_total(lengths, bs) > target {
            bs += 4;
        }
        bs
    }

    /// Same answer as the scan, over shapes small enough to run both:
    /// one member and many, empty members among them, targets that are
    /// reachable and targets that are not, and a start already past the
    /// stop.
    #[test]
    fn the_binary_search_answers_exactly_what_the_scan_did() {
        let sets: &[&[u64]] = &[
            &[40_000, 17_000],
            &[1],
            &[0, 0, 5_000],
            &[997, 997, 997, 997],
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            &[65_536, 4, 4, 4],
        ];
        for lengths in sets {
            let total: u64 = lengths.iter().sum();
            let stop = total.max(4);
            for target in 1..=40u64 {
                for start_div in [1u64, 2, 3, 7, 64] {
                    let start = (total / start_div).next_multiple_of(4).max(4);
                    assert_eq!(
                        first_size_within(lengths, start, stop, target),
                        linear(lengths, start, stop, target),
                        "lengths={lengths:?} start={start} stop={stop} target={target}"
                    );
                }
            }
        }
    }

    /// The shape the scan could not finish: `-b<count>` naming fewer
    /// blocks than the set has members. Each member is sliced from its
    /// own offset zero, so the slice sum can never fall below the member
    /// count and NO size satisfies the request - the scan walked the
    /// whole payload in steps of 4 to find that out.
    ///
    /// NEGATIVE CONTROL, run: call `linear` here instead and the test
    /// does not fail, it never returns - 2.6e10 iterations, each summing
    /// 100 lengths. That is why this asserts a wall clock.
    #[test]
    fn an_impossible_block_count_answers_at_once_instead_of_spinning() {
        let lengths: Vec<u64> = vec![1 << 30; 100];
        let total: u64 = lengths.iter().sum();
        let start = total.div_ceil(50).next_multiple_of(4).max(4);

        let t0 = std::time::Instant::now();
        let bs = first_size_within(&lengths, start, total.max(4), 50);
        let took = t0.elapsed();

        assert!(
            took < std::time::Duration::from_secs(2),
            "the search must not walk the payload: took {took:?}"
        );
        assert!(
            bs >= total,
            "no size can meet 50 blocks over 100 members, so the answer is the \
             payload itself, not {bs}"
        );
        assert!(
            slice_total(&lengths, bs) >= lengths.len() as u64,
            "the floor is one slice per member, whatever the size"
        );
    }
}
