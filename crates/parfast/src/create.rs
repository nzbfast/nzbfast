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
//! [`recovery_file_count`], [`volume_ceiling`] and [`final_volume_names`]
//! (and `rename_volumes`, gone since 9 Nov 2026) were private until
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

    /// The engine has returned, and nothing it drives will draw again.
    /// Called ONCE, before the first line the create prints after it,
    /// so a caller whose meter leaves a `\r` fragment on the terminal
    /// can end it there - GH #88's `Doneress: 100.0%` was `Done`
    /// written over the `--progress` bar's `Progress:`.
    fn settled(&self) {}
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
    //
    // The own-output guard is handed the index the ENGINE will write,
    // `<dir>/<base>.par2`, and not the name the user typed: the two
    // differ whenever the suffix is not spelled `.par2` (`Movie.PAR2`, or
    // no suffix at all), and the guard compared the typed one - so on a
    // case-sensitive volume `parfast c Movie.PAR2 Movie.par2` truncated
    // its own source, while `parfast c Movie Movie` skipped a source the
    // create never touches (sweep, Create CLI B1).
    let index = dir.join(format!("{base}.par2"));
    let members = match collect(opts, &dir, &base, &index, sink) {
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
    let created = par2gen::create_into_exact_controlled(
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
    );
    watch.settled();
    match created {
        // PUBLISHED BY THE ENGINE. The volumes are written under the
        // reference's names (`create_plan` selects them) and committed into
        // place by the engine itself, the index last, so an `Ok` here IS
        // the set on disk under the names the header and the preview
        // promised. Until 9 Nov 2026 this arm renamed the engine's own
        // names to those afterwards (`rename_volumes`), a second
        // publication step that a failed or cancelled re-create used to
        // destroy the previous set through - see `final_volume_names`.
        Ok(_) => {
            sink.line(
                Level::Normal,
                &format!("Wrote {} bytes to disk", recovery * block_size),
            );
            sink.line(Level::Normal, "Writing recovery packets");
            sink.line(Level::Normal, "Writing verification packets");
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
    let lower = name.to_ascii_lowercase();
    // A STAGING LEFTOVER of this set - `.<base>.par2.<pid>-<n>.tmp` or the
    // same around a volume name - is what an overwriting create killed
    // with `kill -9` leaves (`par2gen::control::CreateTrail`). The `-R`
    // walk does not skip dot-files (par2cmdline's unix half takes them
    // too), so without this `parfast c -R set.par2 .` after such a kill
    // would describe the dead run's half-written file as a member of the
    // new set. It is judged by the name it was staging for.
    let staged_for = lower
        .strip_prefix('.')
        .and_then(|r| r.strip_suffix(".tmp"))
        .and_then(|r| r.rsplit_once('.'))
        .filter(|(_, run)| {
            run.split_once('-').is_some_and(|(pid, n)| {
                [pid, n]
                    .iter()
                    .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            })
        })
        .map(|(staged, _)| staged);
    let lower = staged_for.unwrap_or(lower.as_str());
    // `<base>.vol...par2`, either spelling of the volume numbers - the
    // engine's fixed widths or the reference's. Case-insensitively,
    // because the index name is matched that way too
    // (`strip_par2_suffix`). A staging leftover of the INDEX counts too.
    let prefix = format!("{}.vol", base.to_ascii_lowercase());
    let index_name = format!("{}.par2", base.to_ascii_lowercase());
    let is_volume = lower.starts_with(&prefix) && lower.ends_with(".par2");
    if !(is_volume || (staged_for.is_some() && lower == index_name)) {
        return false;
    }
    // ...and IN THE DIRECTORY the set is written to. A volume name is
    // only this create's output beside its index: `/src/backup.vol0+1.par2`
    // handed in as a source for `/out/backup.par2` is somebody's file to
    // protect, and was skipped as "the recovery set's own file" on the
    // name alone (Gemini sweep H9). By identity, as the index is, so
    // `./x` and its absolute spelling agree.
    let dir_of = |p: &Path| -> PathBuf {
        match p.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => PathBuf::from("."),
        }
    };
    par2.is_none_or(|p| same_file(&dir_of(path), &dir_of(p)))
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
    // Under `-a` the first bare argument is a MEMBER, not the set name,
    // so it takes the SOURCE refusal below and not
    // `refuse_wildcard_set_name` - which `run` has already applied to
    // the archive name itself.
    //
    // It goes THROUGH the loop, like every other source. It used to be
    // pushed straight into `named` ahead of it, which skipped the `-R`
    // walk as well as the refusal: `parfast c -R -a out.par2 dirA dirB`
    // protected dirB's files alone, dropped dirA without a line at the
    // `is_dir` skip further down, and said `Done` (sweep A5).
    let first = opts.par2.as_ref().filter(|_| opts.archive.is_some());
    for f in first.into_iter().chain(&opts.files) {
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
        // source file, so every create would be refused. The DEFAULT
        // refusal is therefore made where the stored name is derived,
        // below, by a component-wise strip against the recovery file's
        // directory rather than through `within` (sweep A6, 9 Nov 2026).
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
        // Under `-B` the `dir` fallback stays for a path under neither.
        // With no `-B` there is no fallback at all since sweep A6: a
        // plain `parfast c out.par2 text.txt` stores `text.txt` because
        // it strips against the default basepath, and anything that does
        // not strip is ignored - see the `None` arm.
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
        let rel = match opts.basepath.as_deref() {
            Some(bp) => cpath
                .strip_prefix(canonical_pathname(bp))
                .ok()
                .map(Path::to_path_buf)
                .or_else(|| path.strip_prefix(dir).ok().map(Path::to_path_buf))
                .unwrap_or_else(|| path.clone()),
            // NO `-B`: THE DEFAULT BASEPATH IS THE RECOVERY FILE'S OWN
            // DIRECTORY, and a source outside it is IGNORED with the same
            // line the explicit arm prints - par2cmdline's rule, measured
            // against 1.2.0 on 9 Nov 2026: `par2 c out.par2 ../a.bin
            // local.bin` prints `Ignoring out of basepath source file:
            // /abs/a.bin` and protects local.bin alone, and a create left
            // with nothing exits 3 on "You must specify a list of files".
            //
            // Until then this fell through to the RAW path, so
            // `/abs/a.bin` was stored as `//abs/a.bin` and `../a.bin` as
            // `../a.bin` (sweep A6) - a FileDesc name no reader can place,
            // at exit 0. The GUI planner reaches this whenever its output
            // folder is not the source folder and it passes no `-B`.
            //
            // Where the file sits is decided by `default_basepath_rel`,
            // which accepts every shape the old fallthrough stored
            // correctly and refuses only a file that is genuinely outside -
            // see it for the order and why each step is there.
            None => match default_basepath_rel(&path, dir) {
                Some(r) => r,
                None => {
                    sink.line(
                        Level::Terse,
                        &format!("Ignoring out of basepath source file: {}", cpath.display()),
                    );
                    continue;
                }
            },
        };
        let name = spec_member_name(&rel);
        out.push(Member { name, path });
    }
    Ok(out)
}

/// The stored name of `path` relative to the DEFAULT basepath - the
/// recovery file's directory `dir` - or `None` when the file is outside it
/// and the create ignores it (sweep A6). Tried in this order, the first
/// answer winning:
///
/// 1. The LEXICAL strip the no-`-B` arm always did. Whatever it accepted
///    was stored correctly before A6, so it stays an accept.
/// 2. A NAME THAT IS NOT UTF-8 keeps the pre-A6 answer whole: the strip
///    above, else the raw path. `canonical_pathname` reads such a path as
///    an empty string, which resolves to the cwd and stored the member
///    under an EMPTY name - several of them colliding - where the old
///    fallthrough stored a lossy one. Whether such a file should be
///    skipped or refused is an open decision; this does not make it worse.
/// 3. The REAL directories: the file's parent and `dir`, both through
///    `fs::canonicalize`, so a symlink on either side cannot make an inside
///    file look outside. macOS's `/var` and `/tmp` are links, and
///    `parfast c $TMPDIR/x/p.par2 a.bin` from inside `x` compares a typed
///    `/var/...` against a cwd the OS reports as `/private/var/...`; the
///    lexical canonicalisation alone refused that file at exit 3. The
///    PARENT and not the file, because canonicalising a named link to a
///    file elsewhere would follow it out of the directory.
/// 4. The reference's own lexical canonicalisation, for when the disk
///    cannot answer step 3. `dir` takes a trailing separator first, which
///    is what lets `collapse_unix` resolve a final `.` or `..` (its
///    patterns need the slash after them): `../out.par2` from `sub/` names
///    `/x/`, so `s.bin` is stored as `sub/s.bin`, the reference's answer.
///
/// All of them are component-wise strips and none is `within`'s substring
/// test, so `-B.`'s quirk (see `within`) cannot reach the default case.
/// An EMPTY result is never an answer: it would be a nameless member.
fn default_basepath_rel(path: &Path, dir: &Path) -> Option<PathBuf> {
    let keep = |r: &Path| (!r.as_os_str().is_empty()).then(|| r.to_path_buf());
    if let Some(r) = path.strip_prefix(dir).ok().and_then(keep) {
        return Some(r);
    }
    if path.to_str().is_none() {
        return Some(path.to_path_buf());
    }
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    match (
        path.file_name(),
        std::fs::canonicalize(parent),
        std::fs::canonicalize(dir),
    ) {
        // The disk answered for both directories, so its answer stands -
        // including "outside".
        (Some(name), Ok(parent), Ok(root)) => parent
            .strip_prefix(&root)
            .ok()
            .map(|r| r.join(name))
            .and_then(|r| keep(&r)),
        _ => canonical_pathname(path)
            .strip_prefix(canonical_pathname(&dir.join("")))
            .ok()
            .and_then(keep),
    }
}

/// `<name>.par2` with the extension off, whatever case it was spelled
/// in. Anything else is returned whole.
fn strip_par2_suffix(name: &str) -> &str {
    // `get`, not an index: five BYTES back from the end can land inside
    // a multi-byte character (`é€€` is 8 bytes and byte 3 is mid-`€`),
    // and slicing there panicked the whole create.
    match name.len().checked_sub(5) {
        Some(cut)
            if name
                .get(cut..)
                .is_some_and(|tail| tail.eq_ignore_ascii_case(".par2")) =>
        {
            &name[..cut]
        }
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
        // CHECKED. `next_multiple_of` overflows within 3 of `u64::MAX`,
        // which panics a debug build and WRAPS a release one to 0 - so
        // `-s18446744073709551615` became a request for 4 bytes, which
        // the slice ceiling then raised to whatever fit, and a set was
        // written at a block size nobody asked for (sweep A15). The
        // largest multiple of 4 instead, which the engine then refuses
        // loudly as over its block-size ceiling. (par2cmdline 1.2.0
        // refuses the switch itself: `Invalid block size option`.)
        s.checked_next_multiple_of(4).unwrap_or(u64::MAX - 3).max(4)
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
    //
    // The multiple is found by BISECTION, for `first_size_within`'s reason:
    // `slice_total` is non-increasing in the size, so the first multiple
    // that fits is exactly the one a `mult += 1` scan reaches. The scan was
    // linear in `total / asked` with a pass over every member per step, and
    // never exits early when no multiple can fit - above `MAX_INPUT_SLICES`
    // non-empty members every member still costs a slice - so 40,000 small
    // files at a 4-byte request walked `total / 4` steps of 40,000 sums
    // each, on the GUI preview's thread (sweep A29).
    let total: u64 = lengths.iter().sum();
    let step = asked.max(4);
    // The largest multiple whose size does not pass the payload, which is
    // where the scan stopped; `step * hi` cannot overflow under that bound.
    let hi = total.max(4) / step;
    if hi >= 2 && slice_total(lengths, step * hi) <= cap {
        let (mut lo, mut hi) = (2u64, hi);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if slice_total(lengths, step * mid) <= cap {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        return step * lo;
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
        .with_no_clobber(opts.no_clobber)
        // The reference's volume NAMES, written by the engine directly
        // since 9 Nov 2026 rather than renamed to afterwards: the rename
        // was a second publication step after the engine's commit, and it
        // is what let a failed or cancelled re-create destroy the set it
        // was replacing (see `par2gen::VolumeNaming`). Through the plan,
        // so the Create pane's preview names the same files.
        .with_naming(par2gen::VolumeNaming::Reference {
            std_naming: opts.std_naming,
        });
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

/// par2cmdline's volume NAMES for a list of names in the engine's own
/// fixed-width spelling (`<base>.vol{first:03}+{count:02}.par2`), which
/// is what [`par2gen::plan_files`] answers under `CreatePlan::ENGINE`; a
/// name that is not such a volume (the index) keeps its name.
///
/// par2cmdline sizes the two fields to the EXPONENT SPACE, and a drop-in
/// has to write its names because the next tool along finds volumes by
/// that pattern.
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
/// # The rule lives in the engine now, and this answers through it
///
/// Until 9 Nov 2026 this function WAS the rule, and `rename_volumes`
/// applied it to the files once the engine had written them under its
/// own names. That rename was a second publication step after the
/// engine's commit, and it made a failed or cancelled re-create destroy
/// the previous set: the engine's own names are routinely the previous
/// set's final ones, so its opens landed on them (finding E4 of the
/// 9 Nov 2026 parfast sweep). The engine now names the files itself
/// ([`par2gen::VolumeNaming::Reference`], which [`create_plan`] selects)
/// through [`par2gen::volume_names`], and this function asks that same
/// function, so there is still one copy of the widths above and their
/// measured tests below still pin it.
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
    let pairs: Vec<(u64, u64)> = parsed.iter().flatten().copied().collect();
    let mut named = par2gen::volume_names(
        base,
        &pairs,
        first_block,
        recovery,
        par2gen::VolumeNaming::Reference { std_naming },
    )
    .into_iter();
    written
        .iter()
        .zip(&parsed)
        .map(|(name, parsed)| match parsed {
            Some(_) => named.next().expect("one name per parsed volume"),
            // Not a volume - the index - and it keeps its name.
            None => name.clone(),
        })
        .collect()
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
        // And it is refused BEFORE ANYTHING IS WRITTEN. Until 9 Nov 2026
        // the engine wrote `set.vol000+01.par2` and this crate's rename to
        // the final name then failed, so the bytes were left under the
        // engine's spelling and this asserted they were. The engine now
        // writes the final name itself and probes every name it would
        // replace before its first write (`par2gen::control::CreateTrail`),
        // so a final name it cannot take fails the create with the
        // directory exactly as it was: no index, no volume under either
        // spelling, no staging file.
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            ["a.bin", "set.vol0+1.par2"],
            "the refused create wrote something"
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
        // Five bytes back from the end is mid-character here.
        assert_eq!(
            strip_par2_suffix("\u{e9}\u{20ac}\u{20ac}"),
            "\u{e9}\u{20ac}\u{20ac}"
        );
    }

    /// A volume NAME is this create's output only in the directory the
    /// set is written to. Another set's volume handed in from elsewhere
    /// is a source to protect, not a file to skip (Gemini sweep H9).
    #[test]
    fn a_volume_named_like_the_set_elsewhere_is_not_its_own_output() {
        let root = std::env::temp_dir().join(format!(
            "parfast-own-output-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("src");
        std::fs::create_dir_all(root.join("out")).expect("out");
        let par2 = root.join("out").join("backup.par2");
        let elsewhere = root.join("src").join("backup.vol00+01.par2");
        std::fs::write(&elsewhere, b"someone else's volume").expect("fixture");
        assert!(!is_own_output(&elsewhere, Some(&par2), "backup"));
        // Beside the index it still is, existing or not.
        assert!(is_own_output(
            &root.join("out").join("backup.vol00+01.par2"),
            Some(&par2),
            "backup"
        ));
        assert!(is_own_output(
            &root.join("out").join("BACKUP.VOL0+1.PAR2"),
            Some(&par2),
            "backup"
        ));
        let _ = std::fs::remove_dir_all(&root);
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

    /// `--no-clobber` over an existing FINAL volume name.
    ///
    /// Until 9 Nov 2026 the engine wrote `set.vol000+01.par2` and this
    /// crate renamed it to par2cmdline's field widths afterwards, so a
    /// `set.vol0+1.par2` already on disk was a name the engine never
    /// opened, and the rename pass had to refuse it by a check-then-act.
    /// The engine now writes the final name itself, so this is its own
    /// `O_EXCL` door answering - atomically - and the create fails having
    /// removed only its own files.
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

/// The 9 Nov 2026 sweep's create-side findings, one test each. Every one
/// of these had a NEGATIVE CONTROL run when it landed: the fixed line put
/// back, the test seen to fail, the line restored.
#[cfg(test)]
mod sweep_nov_tests {
    use super::*;

    /// A scratch directory for one test, named by process and thread so
    /// two runs of this binary cannot remove each other's.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "parfast-sweep-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn member_names(index: &Path) -> Vec<String> {
        let set = nzbkit::par2::Par2Set::parse(&[&std::fs::read(index).unwrap()])
            .expect("our own set parses");
        let mut names: Vec<String> = set.files.iter().map(|f| f.name.clone()).collect();
        names.sort();
        names
    }

    /// A STAGING LEFTOVER of this set - what an overwriting create killed
    /// with `kill -9` leaves (`par2gen::control::CreateTrail`) - is the
    /// set's own file to the `-R` walk, never a member of the next set.
    /// The walk takes dot-files (the reference's unix half does too), so
    /// without `is_own_output`'s staging arm this run described the dead
    /// run's half-written volume as a source.
    #[test]
    fn a_staging_leftover_of_the_set_is_never_taken_as_a_source() {
        let dir = scratch("staging-leftover");
        std::fs::write(dir.join("a.bin"), vec![7u8; 4096]).unwrap();
        let leftovers = [".set.vol0+1.par2.99999-0.tmp", ".set.par2.99999-1.tmp"];
        for n in leftovers {
            std::fs::write(dir.join(n), vec![9u8; 1000]).unwrap();
        }
        let index = dir.join("set.par2");
        for n in leftovers {
            assert!(is_own_output(&dir.join(n), Some(&index), "set"), "{n}");
        }
        // Only that exact shape: not another set's, not a bare `.tmp`, not
        // a dot-file that merely starts with the base.
        for n in [
            ".other.par2.1-2.tmp",
            ".set.par2.tmp",
            ".set.par2.x-1.tmp",
            ".set.notes.1-2.tmp",
            ".set.vol0+1.par2",
        ] {
            assert!(!is_own_output(&dir.join(n), Some(&index), "set"), "{n}");
        }
        let opts = Options {
            par2: Some(index.clone()),
            files: vec![dir.clone()],
            recurse: true,
            block_size: Some(512),
            recovery_count: Some(1),
            ..Default::default()
        };
        assert_eq!(run(&opts, &mut Sink::buffered()), crate::EXIT_SUCCESS);
        assert_eq!(member_names(&index), vec!["a.bin".to_string()]);
        for n in leftovers {
            assert_eq!(std::fs::read(dir.join(n)).unwrap(), vec![9u8; 1000], "{n}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A5: under `-R -a` the first bare argument is a DIRECTORY to walk
    /// like any other, not a file pushed past the walk and then dropped
    /// at the `is_dir` skip without a line.
    #[test]
    fn recurse_with_an_archive_name_walks_the_first_directory_too() {
        let dir = scratch("a5");
        for (sub, name) in [("dirA", "a.bin"), ("dirB", "b.bin")] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
            std::fs::write(dir.join(sub).join(name), vec![7u8; 4096]).unwrap();
        }
        let opts = Options {
            archive: Some(dir.join("out.par2")),
            par2: Some(dir.join("dirA")),
            files: vec![dir.join("dirB")],
            recurse: true,
            block_size: Some(512),
            recovery_count: Some(1),
            ..Default::default()
        };
        assert_eq!(run(&opts, &mut Sink::buffered()), crate::EXIT_SUCCESS);
        assert_eq!(
            member_names(&dir.join("out.par2")),
            vec!["dirA/a.bin".to_string(), "dirB/b.bin".to_string()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A6: with no `-B`, a source outside the recovery file's directory is
    /// IGNORED with the reference's line, not stored under its raw path
    /// (`/abs/a.bin` became `//abs/a.bin`). A create left with nothing
    /// fails on the reference's door.
    #[test]
    fn a_source_outside_the_set_directory_is_ignored_without_a_basepath() {
        let dir = scratch("a6");
        std::fs::create_dir_all(dir.join("out")).unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let outside = dir.join("src").join("a.bin");
        std::fs::write(&outside, vec![1u8; 4096]).unwrap();
        std::fs::write(dir.join("out").join("b.bin"), vec![2u8; 4096]).unwrap();

        let mut sink = Sink::buffered();
        let opts = Options {
            par2: Some(dir.join("out").join("set.par2")),
            files: vec![outside.clone(), dir.join("out").join("b.bin")],
            block_size: Some(512),
            recovery_count: Some(1),
            ..Default::default()
        };
        assert_eq!(run(&opts, &mut sink), crate::EXIT_SUCCESS);
        let (out, _) = sink.take();
        assert!(
            out.contains(&format!(
                "Ignoring out of basepath source file: {}",
                outside.display()
            )),
            "{out}"
        );
        assert_eq!(
            member_names(&dir.join("out").join("set.par2")),
            vec!["b.bin".to_string()]
        );

        let mut sink = Sink::buffered();
        let opts = Options {
            par2: Some(dir.join("out").join("only.par2")),
            files: vec![outside],
            block_size: Some(512),
            recovery_count: Some(1),
            ..Default::default()
        };
        assert_eq!(run(&opts, &mut sink), crate::EXIT_INVALID_ARGS);
        assert!(!dir.join("out").join("only.par2").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Create CLI B1: the own-output guard judges the index the ENGINE
    /// writes, `<base>.par2`, not the name typed. Typed `Movie`, the
    /// create writes `Movie.par2`: a source of that name is the set's own
    /// file and must be skipped, not opened and then truncated.
    #[test]
    fn the_own_output_guard_reads_the_index_actually_written() {
        let dir = scratch("b1");
        std::fs::write(dir.join("Movie.par2"), vec![3u8; 4096]).unwrap();
        std::fs::write(dir.join("a.bin"), vec![4u8; 4096]).unwrap();
        let mut sink = Sink::buffered();
        let opts = Options {
            par2: Some(dir.join("Movie")),
            files: vec![dir.join("Movie.par2"), dir.join("a.bin")],
            block_size: Some(512),
            recovery_count: Some(1),
            ..Default::default()
        };
        assert_eq!(run(&opts, &mut sink), crate::EXIT_SUCCESS);
        let (out, _) = sink.take();
        assert!(
            out.contains("Skipping the recovery set's own file"),
            "{out}"
        );
        assert_eq!(
            member_names(&dir.join("Movie.par2")),
            vec!["a.bin".to_string()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A6 review: a SYMLINK on either side of the comparison does not make
    /// an inside file look outside. The set is named through a link to the
    /// real directory and the member by its real path, which no lexical
    /// comparison can match up - and the old fallthrough stored that member
    /// under its whole absolute path, so this is a case A6 must not turn
    /// into a skip. (`a_relative_member_beside_a_set_named_through_a_link`
    /// in the integration target is the reviewer's exact command line.)
    #[cfg(unix)]
    #[test]
    fn a_set_named_through_a_symlink_still_owns_its_directory() {
        let root = scratch("a6-link");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let member = root.join("real").join("a.bin");
        std::fs::write(&member, vec![6u8; 4096]).unwrap();
        assert_eq!(
            default_basepath_rel(&member, &root.join("link")),
            Some(PathBuf::from("a.bin"))
        );
        assert_eq!(
            default_basepath_rel(&root.join("link").join("a.bin"), &root.join("real")),
            Some(PathBuf::from("a.bin"))
        );
        // And outside is still outside, through the link or not.
        std::fs::write(root.join("b.bin"), vec![6u8; 4096]).unwrap();
        assert_eq!(
            default_basepath_rel(&root.join("b.bin"), &root.join("link")),
            None
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A6 review: a name that is not UTF-8 keeps the pre-A6 answer and is
    /// never stored EMPTY. `canonical_pathname` reads such a path as "",
    /// which is the cwd, so with the set in the cwd the member came out
    /// nameless. The parent here does not exist, so the disk cannot answer
    /// and only the name rule stands between it and that empty name.
    #[cfg(unix)]
    #[test]
    fn a_name_that_is_not_utf8_is_never_stored_empty() {
        use std::os::unix::ffi::OsStrExt;
        let raw = Path::new(std::ffi::OsStr::from_bytes(b"no-such-dir/caf\xe9.bin"));
        assert_eq!(
            default_basepath_rel(raw, Path::new(".")),
            Some(raw.to_path_buf())
        );
        assert!(!spec_member_name(raw).is_empty());
    }

    /// A15: `-s` within 3 of `u64::MAX` must not wrap to a 4-byte request.
    #[test]
    fn a_block_size_near_the_top_of_u64_does_not_wrap() {
        let opts = Options {
            block_size: Some(u64::MAX),
            ..Default::default()
        };
        let (bs, raised) = block_size(&opts, &[4096]);
        assert_eq!(bs, u64::MAX - 3);
        assert_eq!(raised, None);
    }

    /// The pre-A29 multiplier scan, kept as the oracle the bisection must
    /// agree with.
    fn linear_raise(lengths: &[u64], asked: u64) -> Option<u64> {
        let cap = par2gen::MAX_INPUT_SLICES as u64;
        let total: u64 = lengths.iter().sum();
        let step = asked.max(4);
        let mut mult = 2u64;
        while let Some(bs) = step.checked_mul(mult) {
            if bs > total.max(4) {
                return None;
            }
            if slice_total(lengths, bs) <= cap {
                return Some(bs);
            }
            mult += 1;
        }
        None
    }

    /// A29: the raise finds exactly the multiple the old scan found, on
    /// every shape small enough for the scan to finish.
    #[test]
    fn the_bisected_raise_answers_exactly_what_the_scan_did() {
        let cap = par2gen::MAX_INPUT_SLICES as u64;
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            x >> 11
        };
        let check = |lengths: &[u64], asked: u64, what: &str| -> u64 {
            assert!(slice_total(lengths, asked) > cap, "{what}: legal as asked");
            let got = legal_block_size(lengths, asked);
            match linear_raise(lengths, asked) {
                Some(want) => assert_eq!(got, want, "{what}: at {asked}"),
                None => assert!(got.is_multiple_of(4), "{what}: fell back to {got}"),
            }
            got
        };
        let mut compared = 0;
        for round in 0..300 {
            // A third of the rounds are MANY-member sets - hundreds - where
            // the per-file grid differs most from a pooled division.
            let n = if round % 3 == 0 {
                200 + (next() % 400) as usize
            } else {
                1 + (next() % 16) as usize
            };
            let lengths: Vec<u64> = (0..n).map(|_| (next() % (cap * 64)) + 1).collect();
            let asked = 4 * (1 + next() % 16);
            if slice_total(&lengths, asked) <= cap {
                continue;
            }
            if linear_raise(&lengths, asked).is_some() {
                compared += 1;
            }
            check(&lengths, asked, &format!("round {round} ({n} members)"));
        }
        assert!(
            compared > 100,
            "only {compared} rounds reached the scan's answer"
        );

        // The EXACT-CAP boundary: `cap * 8` bytes at 8 is `cap` slices on
        // the nose, which is legal, so the first multiple is the answer; one
        // byte more is `cap + 1` at 8, and the answer moves to 12.
        assert_eq!(check(&[cap * 8], 4, "exactly cap"), 8);
        assert_eq!(check(&[cap * 8 + 1], 4, "cap plus one"), 12);
        let half = vec![16u64; (cap / 2) as usize];
        assert_eq!(check(&half, 4, "many members, exactly cap"), 8);

        // `hi < 2`: no multiple of the request fits under the payload, so the
        // raise falls back to the finest legal size without bisecting at all.
        let ones = vec![1u64; 40_000];
        let total: u64 = ones.iter().sum();
        let asked = (total / 2 + 4).next_multiple_of(4);
        assert_eq!(total.max(4) / asked, 1, "the fixture is the hi < 2 shape");
        assert_eq!(linear_raise(&ones, asked), None);
        let got = check(&ones, asked, "hi below 2");
        assert!(got >= asked, "fell below the request: {got}");
        assert!(
            got <= total,
            "the fallback never goes past the payload, and a multiple of {asked} would: {got}"
        );
    }

    /// A29: past `MAX_INPUT_SLICES` non-empty members no size can fit, and
    /// the raise must say so at once rather than walk `total / asked`
    /// multiples of 40,000 sums each.
    ///
    /// NEGATIVE CONTROL, run: with the linear scan back this never
    /// returns (it was stopped after 60 s), which is why it asserts a
    /// wall clock.
    #[test]
    fn more_members_than_the_slice_ceiling_answers_at_once() {
        let lengths = vec![1_000_000u64; 40_000];
        let t0 = std::time::Instant::now();
        let bs = legal_block_size(&lengths, 4);
        let took = t0.elapsed();
        assert!(
            took < std::time::Duration::from_secs(10),
            "the raise walked the payload: {took:?}"
        );
        assert!(
            bs >= 1_000_000,
            "no size below a member's length can help: {bs}"
        );
    }

    /// A14: an exponent sum that OVERFLOWS is past 65535, not in range.
    #[test]
    fn an_overflowing_exponent_end_is_refused_not_passed() {
        assert_eq!(par2gen::spec_exponent_end(65_534, Some(1)), None);
        assert_eq!(
            par2gen::spec_exponent_end(65_535, Some(1)),
            Some((65_535, 65_536))
        );
        assert_eq!(
            par2gen::spec_exponent_end(usize::MAX, Some(1)),
            Some((usize::MAX, usize::MAX))
        );
        assert_eq!(
            par2gen::spec_exponent_end(usize::MAX - 1, Some(5)),
            Some((usize::MAX - 1, usize::MAX))
        );
    }

    /// A14 through the command: `-f` at the top of `u64` is refused by
    /// the engine's exponent check and writes no set.
    #[test]
    fn a_first_block_at_the_top_of_u64_writes_nothing() {
        let dir = scratch("a14");
        std::fs::write(dir.join("a.bin"), vec![5u8; 4096]).unwrap();
        let mut sink = Sink::buffered();
        let opts = Options {
            par2: Some(dir.join("set.par2")),
            files: vec![dir.join("a.bin")],
            block_size: Some(512),
            recovery_count: Some(1),
            first_block: u64::MAX,
            ..Default::default()
        };
        assert_ne!(run(&opts, &mut sink), crate::EXIT_SUCCESS);
        let (_, err) = sink.take();
        assert!(err.contains("run past the PAR2 limit"), "{err}");
        let vols: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".vol"))
            .collect();
        assert!(vols.is_empty(), "volumes were written: {vols:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
