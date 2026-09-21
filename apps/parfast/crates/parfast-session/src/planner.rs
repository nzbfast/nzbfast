//! What a create WOULD do, before it does any of it.
//!
//! # Every number here comes from somebody else
//!
//! The Create pane shows a block size, a block count, the padding, the
//! efficiency, a recovery block count and a table of the files that
//! will be written. Not one of those is computed in this file. The
//! selection rules are `parfast::create`'s, measured against
//! par2cmdline and pinned by `tools/conformance/run.py`; the file names
//! and byte sizes are `nzbkit::par2gen::plan_files`', which builds the
//! critical block the creator would build and adds up the packets the
//! writer would write. This module's whole job is to turn one
//! [`crate::job::CreateSpec`] into the `parfast::cli::Options` those
//! two speak, and to turn the answers back into JSON.
//!
//! That is the point. The maintainer notes record what it costs when
//! two callers of one engine each
//! carry their own arithmetic: the numbers diverge, both look
//! plausible, and nothing in either tree says which is right. A preview
//! that disagreed with the create it previews would be that defect with
//! a progress bar on it.
//!
//! # The command line is generated, not described
//!
//! "Copy command" hands a human a `parfast c ...` line. It is built
//! from the same `Options` this module built the preview from and is
//! asserted to parse BACK into an equal `Options` through
//! `parfast::cli::parse` - so a line that would not do what the pane
//! shows cannot be shown.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::job::{BlockSpec, CreateSpec, PathMode, Pow2Limit, RecoverySpec, Source, VolumeSpec};

/// One file a create would write, as the preview table lists them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedFile {
    pub name: String,
    pub size: u64,
    /// Recovery slices in this file; 0 for the index.
    pub blocks: u64,
    /// Recovery payload as a percentage of the file's own size - how
    /// much of what a downloader fetches is parity rather than packet
    /// overhead.
    pub efficiency_pct: f64,
}

/// What `pf_plan_preview` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanPreview {
    pub block_size: u64,
    pub block_count: u64,
    /// Bytes of zero padding in the last block of each member: the
    /// slice grid is per FILE, so this is the sum of every member's own
    /// remainder and never one pooled figure.
    pub padding_bytes: u64,
    pub padding_pct: f64,
    /// Payload as a percentage of the padded grid.
    pub efficiency_pct: f64,
    pub recovery_blocks: u64,
    pub recovery_percent: f64,
    pub recovery_bytes: u64,
    /// Every byte the create writes, index and volumes together.
    pub total_bytes: u64,
    pub files: Vec<PlannedFile>,
    /// The `parfast c` line equivalent to this plan.
    pub command: String,
    /// Things worth saying before a human presses Create. Never a
    /// refusal - a preview that refuses is a pane that cannot be
    /// filled in from left to right.
    pub warnings: Vec<String>,
    /// The source bytes the grid is over. An ADDITION to section 4.5:
    /// the padding percentage is unreadable without it.
    pub source_bytes: u64,
    /// How many member files the set protects. An ADDITION, for the
    /// same reason.
    pub source_files: u64,
}

/// Why a plan could not be built at all. Only four things can do it,
/// and each is a state a pane can be in halfway through being filled -
/// so the host shows the message and keeps the pane open.
///
/// `missing_source`, `no_sources`, `unsupported_source` and the block
/// refusal. What a walk merely could not READ is NOT in here: that is
/// [`LeftOut`], and it is reported rather than refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanError {
    pub code: &'static str,
    pub message: String,
}

impl PlanError {
    fn new(code: &'static str, message: impl Into<String>) -> PlanError {
        PlanError {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// One member of the set: where it is, and what it is called inside the
/// packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedMember {
    pub path: PathBuf,
    /// The FileDesc name - a basename, or a path relative to the base.
    pub name: String,
    pub length: u64,
}

/// Which files a source expansion leaves out. It is a PAR2 question and
/// not a general one, which is the whole reason this is a parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceRules {
    /// par2cmdline's own: no dot-files, and never a `.par2` - the
    /// reference does not protect the recovery files of any set,
    /// including the one it is writing.
    Par2,
    /// Everything the user pointed at. A CHECKSUM file is not a PAR2
    /// set and has no such rule: `md5sum` and `sha256sum` hash what they
    /// are given, dot-file or not, and a `.par2` is an ordinary file to
    /// take a digest of - protecting a folder of recovery volumes with a
    /// SHA-256 manifest is a thing people do.
    ///
    /// Sharing `Par2`'s rule was silently wrong in both directions: a
    /// checksum job over a folder holding a PAR2 set wrote a manifest
    /// with every `.par2` missing from it, and a dot-file named
    /// EXPLICITLY as a source was dropped with nothing said. The
    /// manifest still verified clean, because what is not in it is not
    /// checked - which is the worst shape a "verified" answer can have.
    All,
}

/// What an expansion could not take in, so the caller can SAY so.
///
/// The doc on [`expand_sources`] is the whole reason this type exists:
/// a named source that is not there is an error, because a job that
/// quietly protects four of five named files is the worst outcome
/// available - and until 17 Sep 2026 a whole SUBTREE that could not be
/// enumerated took the opposite route and vanished, with the plan
/// reporting success over what was left. One unreadable `.Trashes` on
/// a volume must not refuse a 400 GB create, so this is not a refusal;
/// it is the count that turns a silent omission into a stated one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeftOut {
    /// Folders `read_dir` could not enumerate, with the reason the OS
    /// gave. A folder whose listing failed part-way is in here too: the
    /// entries before the failure are still members, so this is "not
    /// complete" rather than "not read".
    pub dirs: Vec<(PathBuf, String)>,
    /// Links found during a walk. Never followed - see [`walk`].
    pub links: u64,
    /// Entries that are neither a folder nor an ordinary file: fifos,
    /// sockets, devices.
    pub special: u64,
}

impl LeftOut {
    pub fn is_empty(&self) -> bool {
        self.dirs.is_empty() && self.links == 0 && self.special == 0
    }

    /// One line per kind, for a preview's `warnings` and a job's result.
    ///
    /// The unreadable folders are NAMED, up to three of them, because
    /// "1 folder could not be read" is not actionable and the path is
    /// the whole of the fix. The other two are counted: a folder of
    /// links is an ordinary shape and thirty paths would bury the
    /// sentence that matters.
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.dirs.is_empty() {
            let named: Vec<String> = self
                .dirs
                .iter()
                .take(3)
                .map(|(p, e)| format!("{} ({e})", p.display()))
                .collect();
            let more = self.dirs.len().saturating_sub(named.len());
            let tail = if more > 0 {
                format!(", and {more} more")
            } else {
                String::new()
            };
            out.push(format!(
                "{} folder(s) could not be read and are NOT protected: {}{tail}",
                self.dirs.len(),
                named.join(", ")
            ));
        }
        if self.links > 0 {
            out.push(format!(
                "{} link(s) were found and are not protected: a walk never leaves \
                 the folder you chose. Add what a link points at as its own source.",
                self.links
            ));
        }
        if self.special > 0 {
            out.push(format!(
                "{} item(s) are not ordinary files (a pipe, a socket, a device) \
                 and are not protected",
                self.special
            ));
        }
        out
    }
}

/// The members a create would protect, and what the expansion could not
/// take in on the way to them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expansion {
    pub members: Vec<PlannedMember>,
    pub left_out: LeftOut,
}

/// Expand the spec's sources into the members a create would protect,
/// in the order the create would see them.
///
/// A directory contributes the files directly in it, or the whole tree
/// under it when `recursive`. What is left out is [`SourceRules`]'s to
/// say; a path that does not exist is an error rather than a silent
/// omission either way, because a pane that quietly protects four of
/// five named files is the worst outcome available.
///
/// # A NAMED source is the user's spelling; a WALK is not
///
/// The two halves deliberately answer differently, and the rule is
/// whose choice the path was:
///
/// * A source the user NAMED is followed as spelled, link or not. `/tmp`
///   is a symlink on macOS and NAS mounts are full of them; refusing one
///   because of what it is made of would be refusing the thing the user
///   pointed at. Only a named path that is neither a folder nor an
///   ordinary file is refused (`unsupported_source`), because there is
///   nothing there a create could hash.
/// * A path the WALK found is taken only when it is an ordinary file or
///   a real directory. See [`walk`] for what that buys and what it
///   costs.
///
/// Everything the walk declined is in [`Expansion::left_out`], and every
/// caller is expected to put it in front of the user. It is not an error
/// and must not become one: an unreadable `.Trashes` or `.Spotlight-V100`
/// is the ordinary state of a mac volume's root.
pub fn expand_sources(
    sources: &[Source],
    mode: PathMode,
    base: Option<&Path>,
    rules: SourceRules,
) -> Result<Expansion, PlanError> {
    let mut out: Vec<PlannedMember> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut left_out = LeftOut::default();
    for src in sources {
        let meta = std::fs::metadata(&src.path).map_err(|e| {
            PlanError::new("missing_source", format!("{}: {e}", src.path.display()))
        })?;
        if meta.is_dir() {
            let mut found = Vec::new();
            walk(&src.path, src.recursive, &mut found, &mut left_out);
            found.sort();
            for p in found {
                add(&mut out, &mut seen, p, mode, base, rules)?;
            }
        } else if meta.is_file() {
            add(&mut out, &mut seen, src.path.clone(), mode, base, rules)?;
        } else {
            // A fifo named as a source is the case that makes this a
            // refusal rather than a skip: `checksum::write_text_watched`
            // OPENS every member, and opening a fifo for reading blocks
            // until a writer appears - forever, inside the one call the
            // cancel gate cannot interrupt. Silently dropping it would
            // be the four-of-five outcome the doc above refuses.
            return Err(PlanError::new(
                "unsupported_source",
                format!(
                    "{}: not an ordinary file or folder, so there is nothing here to protect",
                    src.path.display()
                ),
            ));
        }
    }
    if out.is_empty() {
        return Err(PlanError::new(
            "no_sources",
            "no files to protect: add at least one file or a folder that holds one",
        ));
    }
    Ok(Expansion {
        members: out,
        left_out,
    })
}

/// Every ordinary file directly under `dir`, or in its whole tree when
/// `recursive`, with what could not be taken in RECORDED rather than
/// dropped.
///
/// # A walk never leaves the folder it was pointed at
///
/// A link found during a walk is not followed and not protected. That
/// is the reference's own rule, measured rather than read: par2cmdline
/// 1.2.0 over a folder holding `dirlink -> ../other` and
/// `filelink -> real.bin` reports `Source file count: 1` and opens only
/// the real file, and it refuses an explicitly named link outright with
/// "You must specify a list of files when creating." It lstats, and a
/// link is never a source.
///
/// This walk used to follow them, with three consequences, all of them
/// found on 17 Sep 2026 by pointing a fixture's `loop` at its own
/// parent:
///
/// * **The walk left the tree.** The link's target is walked as if the
///   user had chosen it, so a link to `$HOME` in a folder being
///   protected puts `$HOME` in the recovery set.
/// * **A loop multiplied the set.** `a/loop -> ../a` is entered again at
///   each level until the kernel's symlink limit (32 on macOS) makes the
///   `stat` fail, so one file became 33 members - 33 FileDesc packets
///   with ONE name, over one file's bytes, in a set 33 times the size it
///   should be. `add`'s dedupe did not catch it because the 33 spellings
///   are 33 different paths.
/// * **A stranger's file could refuse the create.** The escaped walk
///   reached `$TMPDIR`, found a PowerShell named pipe, and `add` failed
///   the whole expansion on it - a create refused because of a file in a
///   folder the user never chose.
///
/// A visited-inode set would have fixed the second of those and neither
/// of the others, which is why the answer is the reference's and not a
/// cycle guard.
///
/// The measurement is the reference's UNIX half, and the windows half
/// DOES follow where this refuses - read out of v1.3.0's source
/// 20 Sep 2026 and RUN on a fleet Windows box on 21 Sep, which confirmed
/// the reading on every arm (claim
/// `par2-conformance-windows-link-rows-20sep`). It branches on
/// `FILE_ATTRIBUTE_DIRECTORY` and on nothing else, and
/// `FILE_ATTRIBUTE_REPARSE_POINT` occurs nowhere in that tag, so a file
/// link is taken as a source and a directory link is recursed into. That
/// makes this rule a STATED windows-only divergence rather than a defect
/// to fix toward; see `parfast::create::walk`, which carries the whole
/// note, and `tools/conformance/README.md`'s "Links, and the one answer
/// that came out of the source".
///
/// WHAT THE WINDOWS RUN ADDED: the two TYPED rows are on the windows
/// tables too and are CLEAN there, because we honour a typed link and so
/// does the reference on that platform - the divergence closes. This
/// WALK's own row is posix-only, and not because links are hard there:
/// windows can spell "walk this whole tree" only as `.`, which the
/// reference refuses on its own dot guard, or as a wildcard, which is a
/// separate axis. So the rule this function carries is pinned on the two
/// posix legs and on no windows one, which is worth knowing before
/// reading a green windows leg as cover for it.
///
/// # And nothing that is not an ordinary file
///
/// A fifo stats as zero length and OPENS by blocking until a writer
/// appears; a socket and a device are not hashable either. The
/// reference drops all three during a walk (measured: a `mkfifo`d entry
/// does not appear in its source count, and not as a "Skipping 0 byte
/// file" line either - it is gone before that). The PAR2 create's own
/// `parfast::create::collect` happened to drop a fifo as a zero-byte
/// file; the CHECKSUM create has no such rule and hashed it, which is
/// the hang this closes.
///
/// # An unreadable folder is reported and never fatal
///
/// `read_dir` refusing is the ordinary state of `.Trashes`,
/// `.Spotlight-V100` and `.fseventsd` on a mac volume, so refusing the
/// create would make "protect this drive" impossible. It goes in
/// `left` and every caller states it.
fn walk(dir: &Path, recursive: bool, out: &mut Vec<PathBuf>, left: &mut LeftOut) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            left.dirs.push((dir.to_path_buf(), e.to_string()));
            return;
        }
    };
    for e in rd {
        // An entry the directory could not describe is the same kind of
        // hole as a directory that could not be opened, and it used to
        // go the same silent way (`rd.flatten()`).
        let e = match e {
            Ok(e) => e,
            Err(err) => {
                left.dirs.push((dir.to_path_buf(), err.to_string()));
                continue;
            }
        };
        // `DirEntry::file_type` does NOT follow a link, which is the
        // whole point - `Path::is_dir` does, and that was the bug.
        let ft = match e.file_type() {
            Ok(ft) => ft,
            Err(err) => {
                left.dirs.push((dir.to_path_buf(), err.to_string()));
                continue;
            }
        };
        if ft.is_symlink() {
            left.links += 1;
        } else if ft.is_dir() {
            if recursive {
                walk(&e.path(), recursive, out, left);
            }
        } else if ft.is_file() {
            out.push(e.path());
        } else {
            left.special += 1;
        }
    }
}

/// The reference skips dot-files and never protects a `.par2`. See
/// [`SourceRules`] for why this asks which rule is in force rather than
/// applying that one to everything.
fn skipped(path: &Path, rules: SourceRules) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        // A name this process cannot even spell is left out under either
        // rule: nothing downstream could record it.
        return true;
    };
    if rules == SourceRules::All {
        return false;
    }
    name.starts_with('.')
        || path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("par2"))
}

/// The key two spellings of ONE file share, so the set cannot carry the
/// same bytes twice under two names.
///
/// The CANONICAL PATH and deliberately not dev+ino, which is the other
/// obvious answer and is wrong here: two HARD LINKS are one inode and
/// two real names, and a create asked to protect both is being asked
/// for both - PAR2 protects names. `realpath` collapses exactly the
/// aliasing a symlink creates and leaves a hard link alone, which is
/// also what par2cmdline dedupes on (its own `GetCanonicalPathname`,
/// lexically).
///
/// Falls back to the path as given when it cannot be resolved, so a
/// path that vanished between the walk and here is still deduped
/// against itself rather than silently against everything.
fn identity(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn add(
    out: &mut Vec<PlannedMember>,
    seen: &mut std::collections::HashSet<PathBuf>,
    path: PathBuf,
    mode: PathMode,
    base: Option<&Path>,
    rules: SourceRules,
) -> Result<(), PlanError> {
    if skipped(&path, rules) || !seen.insert(identity(&path)) {
        return Ok(());
    }
    let length = std::fs::metadata(&path)
        .map_err(|e| PlanError::new("missing_source", format!("{}: {e}", path.display())))?
        .len();
    let name = match (mode, base) {
        (PathMode::Relative, Some(b)) => path
            .strip_prefix(b)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/"),
        _ => path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
    };
    out.push(PlannedMember { path, name, length });
    Ok(())
}

/// The `parfast::cli::Options` this spec means, and the warnings the
/// translation produced.
///
/// Split out of [`preview`] because the RUNNER needs the identical
/// `Options`: a create that ran off a second translation could write a
/// set the preview never described.
///
/// # It has to be the WHOLE translation, and for a while it was not
///
/// The volume scheme was resolved in [`preview`] and nowhere else, so
/// the `Options` this returned carried no `-n`, no `-u` and no ceiling
/// - and `runner::run_create`, which builds the create's argv from
/// exactly this, wrote the exponential default over every scheme a user
/// picked. A pane showing four equal volumes, four equal volumes in the
/// copied command line, and 1+2+4+8+5 on disk. Found 12 Sep 2026 by
/// `queue::tests::a_create_writes_exactly_the_files_its_preview_drew`,
/// which compares a real create's files against its own preview rather
/// than comparing two previews.
///
/// So the grid is resolved HERE, where the scheme needs it, and
/// `preview` adds nothing to what comes back: everything the create
/// gets, this function put there.
pub fn options_for(
    spec: &CreateSpec,
    members: &[PlannedMember],
) -> Result<(parfast::cli::Options, Vec<String>), PlanError> {
    let mut warnings = Vec::new();
    let mut o = parfast::cli::Options {
        par2: Some(spec.output.clone()),
        files: members.iter().map(|m| m.path.clone()).collect(),
        first_block: spec.first_recovery_block,
        threads: spec.perf.threads,
        mem_mb: spec.perf.memory_mb,
        std_naming: spec.std_naming,
        // The pane's Overwrite tick, inverted: unticked means the
        // engine must refuse a file already under one of the set's
        // names rather than truncate it. Resolved HERE, with every
        // other switch, because this is the one translation the runner
        // and the copied command line both read - see `command_args`,
        // which spells it.
        no_clobber: !spec.overwrite,
        ..Default::default()
    };
    if spec.path_mode == PathMode::Relative {
        o.basepath = spec.base_path.clone();
    }
    // An untouched Comment field is the absence of a comment and not an
    // empty one, so the run and the copied command line both omit it.
    if !spec.comment.is_empty() {
        o.comment = Some(spec.comment.clone());
    }
    match spec.block {
        Some(BlockSpec::Size { size }) => o.block_size = Some(size),
        Some(BlockSpec::Count { count }) => o.block_count = Some(count),
        None => {}
    }
    match spec.recovery {
        Some(RecoverySpec::Percent { percent }) => {
            // `-r` is an INTEGER percentage in the reference's dialect,
            // so a fractional ask is rounded and said out loud rather
            // than silently taken as something else. A poster who wants
            // 7.5% of 1,000 blocks wants `-c75`, and the pane's Count
            // spelling is how they say it.
            let rounded = percent.max(0.0).round();
            if (rounded - percent).abs() > f64::EPSILON {
                warnings.push(format!(
                    "the reference's -r takes whole percents, so {percent}% was taken as \
                     {rounded}%; use a recovery block count for finer control"
                ));
            }
            o.redundancy = Some(parfast::cli::Redundancy::Percent(rounded as u32));
        }
        Some(RecoverySpec::Count { count }) => o.recovery_count = Some(count),
        Some(RecoverySpec::Size { size }) => {
            o.redundancy = Some(parfast::cli::Redundancy::TargetBytes(size))
        }
        None => {}
    }
    // The scheme resolves `blocks_per_file` and `file_size` into a
    // volume COUNT, so it needs the block size and the recovery count -
    // both pure functions of the options so far, so this is the same
    // grid `preview` goes on to show.
    let lengths: Vec<u64> = members.iter().map(|m| m.length).collect();
    let (block_size, block_count, raised_from) = grid(&o, &lengths);
    if let Some(asked) = raised_from {
        warnings.push(format!(
            "a block size of {asked} would put the set over the spec's \
             {} input slices, so {block_size} is used",
            nzbkit::par2gen::MAX_INPUT_SLICES
        ));
    }
    // A block COUNT below the member count is unreachable at any block size,
    // because a slice never spans a file boundary and every member needs one.
    // `create::block_size`'s search runs out and lands on the payload itself -
    // one slice per member - and said NOTHING about it until 12 Sep 2026, so a
    // poster who typed 2 over three files got a block size of the whole set
    // with no explanation of where it came from. The engine still does not
    // refuse it, correctly: one slice per member is a legal set. It is the
    // silence that was wrong.
    if let Some(BlockSpec::Count { count }) = spec.block {
        let files = members.len() as u64;
        if count < files {
            warnings.push(format!(
                "a block count of {count} is fewer than the {files} files in the set, \
                 and a block never spans a file boundary, so the set has {block_count} \
                 blocks of {block_size} bytes"
            ));
        }
    }
    let recovery = parfast::create::recovery_blocks(&o, block_count, block_size);
    apply_scheme(&mut o, spec, block_size, recovery, &mut warnings);
    Ok((o, warnings))
}

/// The block size and block count this spec resolves to - the two
/// numbers every other number below depends on.
fn grid(o: &parfast::cli::Options, lengths: &[u64]) -> (u64, u64, Option<u64>) {
    let (bs, raised_from) = parfast::create::block_size(o, lengths);
    (bs, parfast::create::slice_total(lengths, bs), raised_from)
}

/// Finish the `Options` with the volume scheme, which needs the block
/// size and the recovery count to resolve `blocks_per_file` and
/// `file_size` into a volume COUNT.
fn apply_scheme(
    o: &mut parfast::cli::Options,
    spec: &CreateSpec,
    block_size: u64,
    recovery: u64,
    warnings: &mut Vec<String>,
) {
    // One recovery slice costs its 4-byte exponent and a 64-byte packet
    // head on top of the slice itself - the writer's own 68, read out
    // of `par2gen` rather than restated as a literal.
    let per_block = block_size.saturating_add(68);
    match &spec.volumes {
        VolumeSpec::None => o.recovery_files = Some(1),
        VolumeSpec::Uniform {
            files,
            blocks_per_file,
            file_size,
        } => {
            let named = [
                files.map(u64::from),
                blocks_per_file.map(|b| recovery.div_ceil(b.max(1))),
                file_size.map(|s| recovery.div_ceil((s / per_block.max(1)).max(1))),
            ];
            if named.iter().filter(|n| n.is_some()).count() > 1 {
                warnings.push(
                    "the uniform scheme takes one of files, blocks_per_file or file_size; \
                     the first one given was used"
                        .to_string(),
                );
            }
            let n = named.into_iter().flatten().next().unwrap_or(0);
            // `-u` with no count is the variable plan's OWN count made
            // equal-sized, which is what `recovery_file_count` answers
            // when `recovery_files` is None.
            if n == 0 {
                o.uniform = true;
            } else {
                o.recovery_files =
                    Some(n.clamp(1, u64::from(parfast::help::MAX_RECOVERY_FILES)) as u32);
            }
        }
        VolumeSpec::Pow2 => {}
        // All three ceilings are CARRIED since 12 Sep 2026, and
        // `pf_capabilities.volume_limit_explicit` says so. `-l` is the
        // only one the reference's dialect can spell - no volume larger
        // than the largest source file - and the other two reach
        // `par2gen::CreatePlan::max_blocks_per_volume` through
        // `parfast`'s `--volume-blocks=N` long option. The preview and
        // the run both resolve through `parfast::create::create_plan`,
        // so neither can describe a layout the other would not write.
        VolumeSpec::Pow2Limit { limit } => match limit {
            Pow2Limit::Named(_) => o.limit = true,
            Pow2Limit::Blocks { blocks } => o.volume_blocks = Some((*blocks).max(1)),
            // A ceiling in BYTES becomes one in slices at this block
            // size, by the same arithmetic the uniform scheme's
            // `file_size` already uses - one slice costs its own bytes
            // plus the writer's 68. It is a floor division, so the
            // resolved ceiling never exceeds what was asked; a volume
            // still carries copies of the critical block on top, which
            // is what the note says out loud rather than leaving the
            // file a little larger than the number the user typed.
            Pow2Limit::Size { size } => {
                let blocks = (size / per_block.max(1)).max(1);
                warnings.push(format!(
                    "a ceiling of {size} bytes per volume is {blocks} recovery block(s) at \
                     this block size; each volume also carries a copy of the set's critical \
                     packets, so a file is a little larger than that"
                ));
                o.volume_blocks = Some(blocks);
            }
        },
    }
}

/// Everything the Create pane shows, for one spec.
pub fn preview(spec: &CreateSpec) -> Result<PlanPreview, PlanError> {
    let Expansion { members, left_out } = expand_sources(
        &spec.sources,
        spec.path_mode,
        spec.base_path.as_deref(),
        SourceRules::Par2,
    )?;
    // EVERYTHING the create is told is in here, and nothing is added to
    // it below: `runner::run_create` builds its argv from this same
    // call, so a switch this pane resolved on its own would be a switch
    // the create never gets. That is not hypothetical - see
    // [`options_for`].
    let (o, translation_warnings) = options_for(spec, &members)?;
    // WHAT IS NOT COVERED GOES FIRST, ahead of the translation's own
    // rounding notes. It is the only line here that changes whether a
    // user should press Create at all, and a pane that shows it fourth
    // under three notes about `-r` has published it without saying it.
    let mut warnings = left_out.lines();
    warnings.extend(translation_warnings);
    let lengths: Vec<u64> = members.iter().map(|m| m.length).collect();
    let (block_size, block_count, _raised) = grid(&o, &lengths);
    let recovery = parfast::create::recovery_blocks(&o, block_count, block_size);
    let largest = lengths.iter().copied().max().unwrap_or(0);

    let base = base_name(&spec.output);
    // The plan is `parfast::create::create_plan`'s and nothing is added
    // to it here, which is the whole invariant: a preview must show what
    // the create will actually write.
    //
    // It once took an explicit `pow2_limit` ceiling on top, which made
    // the PREVIEW right and the RUN wrong - the job goes through
    // `parfast::create::run`, which knows only what the command line can
    // spell. The answer was never to add the ceiling here; it was to
    // give the CLI a spelling for it (`--volume-blocks=N`, 12 Sep 2026),
    // so ONE function resolves it for both sides. Nothing is added here
    // still, and nothing should be: a number this pane can reach and
    // `run` cannot is the same defect in a new place.
    let plan = parfast::create::create_plan(&o, recovery, largest, block_size);
    // The COMMENT-aware door, because a comment packet is bytes in the
    // critical block and the critical block is in every file this pane
    // shows a size for. A preview built on the plain `plan_files` would
    // under-report the index and every volume by exactly the packet -
    // the same preview/run disagreement `volume_limit_explicit` records
    // and that this whole crate exists to remove.
    let planned = nzbkit::par2gen::plan_files_with_comment(
        &members
            .iter()
            .map(|m| (m.name.clone(), m.length))
            .collect::<Vec<_>>(),
        &base,
        block_size,
        recovery as usize,
        plan,
        Some(spec.comment.as_str()),
    );

    let source_bytes: u64 = lengths.iter().sum();
    let padded = block_count.saturating_mul(block_size);
    let padding_bytes = padded.saturating_sub(source_bytes);
    let recovery_bytes = recovery.saturating_mul(block_size);
    let total_bytes: u64 = planned.iter().map(|f| f.bytes).sum();

    // `plan_files` answers in the ENGINE's fixed-width spelling, and the
    // create renames afterwards - to par2cmdline's measured widths, or
    // to the spec's `vol<first>-<last>` under `--std-naming`. So the
    // names go through the create's own rule, or this pane would list
    // files the user never sees. (It did, for every set whose widths
    // the rename narrowed: the pane said `set.vol000+01.par2` and the
    // disk said `set.vol00+1.par2`.)
    let final_names = parfast::create::final_volume_names(
        &base,
        &planned.iter().map(|f| f.name.clone()).collect::<Vec<_>>(),
        o.first_block,
        recovery,
        o.std_naming,
    );
    let files = planned
        .iter()
        .zip(final_names)
        .map(|(f, name)| PlannedFile {
            name,
            size: f.bytes,
            blocks: f.blocks as u64,
            efficiency_pct: pct(f.blocks as u64 * block_size, f.bytes),
        })
        .collect();

    if block_count > nzbkit::par2gen::MAX_INPUT_SLICES as u64 {
        warnings.push(format!(
            "block count {block_count} exceeds the spec's {}; increase the block size",
            nzbkit::par2gen::MAX_INPUT_SLICES
        ));
    }
    if recovery == 0 {
        warnings.push("no recovery blocks: this set can verify but never repair".to_string());
    }
    // A SET THE CREATE WOULD REFUSE, said in the pane rather than discovered
    // when the job fails. PAR2's exponents stop at 65535 and
    // `par2gen::check_create_inputs` refuses a create that would run past it,
    // but nothing here looked - so a `-f` near the ceiling drew a complete,
    // confident preview of a set that cannot exist. The predicate is the
    // engine's own (`pub` since 12 Sep 2026) rather than a second reading of
    // the rule, which is the same discipline the comment check below follows.
    if let Some((first, last)) = nzbkit::par2gen::spec_exponent_end(
        spec.first_recovery_block as usize,
        Some(recovery as usize),
    ) {
        warnings.push(format!(
            "recovery exponents {first}..{last} run past the PAR2 limit of 65535, so the \
             create will refuse this set: lower the recovery block count or the first \
             recovery block"
        ));
    }
    if spec.comment.is_empty() {
        // Nothing to say; the field is simply unused.
    } else if !capabilities_comment() {
        warnings.push(
            "this build writes no PAR2 comment packet, so the comment will not be stored"
                .to_string(),
        );
    } else if let Err(e) = nzbkit::par2gen::check_comment(&spec.comment) {
        // The create would REFUSE this comment, so say so in the pane
        // that is showing the user what the create will do rather than
        // letting them find out when it fails. The predicate is the
        // engine's own, not a second reading of the rule.
        warnings.push(format!("the comment will be refused: {e}"));
    }

    Ok(PlanPreview {
        block_size,
        block_count,
        padding_bytes,
        padding_pct: pct(padding_bytes, padded),
        efficiency_pct: pct(source_bytes, padded),
        recovery_blocks: recovery,
        recovery_percent: pct(recovery, block_count),
        recovery_bytes,
        total_bytes,
        files,
        command: command_line(&o, &members, spec, recovery),
        warnings,
        source_bytes,
        source_files: members.len() as u64,
    })
}

/// Whether this build writes the PAR2 comment packet. One predicate,
/// read by the planner and by `pf_capabilities`, so a pane that shows
/// the field and a capability that hides it cannot disagree.
///
/// TRUE since 12 Sep 2026: `par2gen::create_into_exact_with_comment`
/// writes the spec's optional `CommASCI` / `CommUni` packet and
/// `par2::Par2Set::comment` reads one back. What may be IN a comment is
/// not free-form - one carrying a control character other than newline,
/// carriage return or tab is REFUSED at the create
/// (`par2gen::check_comment`), and so is one past
/// `par2gen::MAX_COMMENT_BYTES` - so a host that lets a user paste
/// arbitrary bytes into the field must be ready for the create to fail
/// with that message rather than assume every field value is writable.
pub fn capabilities_comment() -> bool {
    true
}

/// `x / y` as a percentage, with the only division-by-zero this file
/// can reach answered once.
fn pct(x: u64, y: u64) -> f64 {
    if y == 0 {
        return 0.0;
    }
    (x as f64) * 100.0 / (y as f64)
}

/// The set's base name: the output path without its `.par2` suffix,
/// which is what every volume's name is built on.
pub fn base_name(output: &Path) -> String {
    let name = output
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.strip_suffix(".par2")
        .or_else(|| name.strip_suffix(".PAR2"))
        .unwrap_or(&name)
        .to_string()
}

/// The `parfast c` line that would do this. See [`round_trips`] in the
/// tests: it is asserted to parse back into the same `Options`.
pub fn command_line(
    o: &parfast::cli::Options,
    members: &[PlannedMember],
    spec: &CreateSpec,
    recovery: u64,
) -> String {
    let mut parts = vec!["parfast".to_string(), "c".to_string()];
    for arg in command_args(o, members, spec, recovery) {
        parts.push(quote(&arg));
    }
    parts.join(" ")
}

/// The argv the line spells, unquoted - what the round-trip test feeds
/// back to `parfast::cli::parse`.
pub fn command_args(
    o: &parfast::cli::Options,
    members: &[PlannedMember],
    spec: &CreateSpec,
    recovery: u64,
) -> Vec<String> {
    let mut a = Vec::new();
    if let Some(s) = o.block_size {
        a.push(format!("-s{s}"));
    }
    if let Some(b) = o.block_count {
        a.push(format!("-b{b}"));
    }
    match o.redundancy {
        Some(parfast::cli::Redundancy::Percent(p)) => a.push(format!("-r{p}")),
        // `-r<c><n>` is a SCALED integer - k, m or g - and nothing
        // else, so a byte target that is not a clean multiple of one
        // of them has no `-r` spelling at all. It has an exact `-c`
        // one, because that is what the size resolves to anyway
        // (`parfast::create::recovery_blocks`: `bytes.div_ceil(block)`),
        // so the line says the same thing in the dialect that can hold
        // it rather than saying something close.
        Some(parfast::cli::Redundancy::TargetBytes(b)) => match scaled(b) {
            Some(spelling) => a.push(format!("-r{spelling}")),
            None => a.push(format!("-c{recovery}")),
        },
        None => {}
    }
    if let Some(c) = o.recovery_count {
        a.push(format!("-c{c}"));
    }
    if let Some(n) = o.recovery_files {
        a.push(format!("-n{n}"));
    }
    if o.uniform {
        a.push("-u".to_string());
    }
    if o.limit {
        a.push("-l".to_string());
    }
    // The two non-reference long options, spelled here for the same
    // reason every switch above is: `runner::run_create` re-parses this
    // argv and runs off the result, so a switch the line does not carry
    // is a switch the create does not get - however carefully the
    // `Options` it was resolved into were built.
    if let Some(n) = o.volume_blocks {
        a.push(format!("--volume-blocks={n}"));
    }
    if o.std_naming {
        a.push("--std-naming".to_string());
    }
    // And the third, which is the pane's Overwrite tick turned off.
    // It has to be ON THE LINE and not set on the far side of the
    // re-parse: the line is what the pane SHOWS, and a create the pane
    // says is protected whose copied command silently overwrites is the
    // pane lying about the one thing that tick is for.
    if o.no_clobber {
        a.push("--no-clobber".to_string());
    }
    if o.first_block != 0 {
        a.push(format!("-f{}", o.first_block));
    }
    if let Some(t) = o.threads {
        a.push(format!("-t{t}"));
    }
    if let Some(m) = o.mem_mb {
        a.push(format!("-m{m}"));
    }
    if let Some(b) = &o.basepath {
        a.push(format!("-B{}", b.display()));
    }
    if let Some(c) = &o.comment {
        a.push(format!("--comment={c}"));
    }
    a.push(spec.output.to_string_lossy().into_owned());
    for m in members {
        a.push(m.path.to_string_lossy().into_owned());
    }
    a
}

/// `-r`'s scaled spelling for a byte count, largest unit first, or
/// `None` for a count no unit divides.
fn scaled(bytes: u64) -> Option<String> {
    for (letter, unit) in [('g', 1u64 << 30), ('m', 1 << 20), ('k', 1 << 10)] {
        if bytes >= unit && bytes.is_multiple_of(unit) {
            return Some(format!("{letter}{}", bytes / unit));
        }
    }
    None
}

/// Shell quoting for the copied line, and nothing more: a path with a
/// space in it must survive a paste into a terminal.
fn quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./=+,:@%".contains(&b))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::Perf;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "parfast-session-plan-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("temp dir");
        p
    }

    fn spec_over(dir: &Path, files: &[(&str, usize)]) -> CreateSpec {
        for (name, len) in files {
            std::fs::write(dir.join(name), vec![7u8; *len]).expect("fixture");
        }
        CreateSpec {
            sources: files
                .iter()
                .map(|(n, _)| Source {
                    path: dir.join(n),
                    recursive: false,
                })
                .collect(),
            path_mode: PathMode::Basename,
            base_path: None,
            block: None,
            recovery: None,
            output: dir.join("set.par2"),
            volumes: VolumeSpec::Pow2,
            first_recovery_block: 0,
            comment: String::new(),
            overwrite: false,
            std_naming: false,
            unicode: crate::job::UnicodePolicy::Auto,
            perf: Perf::default(),
        }
    }

    /// THE PROPERTY THAT MAKES THE PLANNER SAFE: the numbers are
    /// `parfast::create`'s own, so a preview and the create it previews
    /// cannot disagree. `-b` is a SEARCH and not a division (the
    /// per-file grid does not pool remainders), and this is the shape
    /// that proved it.
    #[test]
    fn the_grid_is_parfasts_own_search_and_not_a_division() {
        let d = tmp("grid");
        let mut spec = spec_over(&d, &[("a.bin", 40_000), ("b.bin", 17_000)]);
        spec.block = Some(BlockSpec::Count { count: 64 });
        let p = preview(&spec).expect("preview");
        assert_eq!(p.block_size, 896, "the reference's answer, not 40000/64");
        assert_eq!(p.block_count, 64);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The padding is per FILE and never one pooled remainder.
    #[test]
    fn padding_is_the_sum_of_every_members_own_remainder() {
        let d = tmp("pad");
        let mut spec = spec_over(&d, &[("a.bin", 5_000), ("b.bin", 5_000)]);
        spec.block = Some(BlockSpec::Size { size: 4_096 });
        let p = preview(&spec).expect("preview");
        // Two members, two blocks each, 8,192 - 5,000 = 3,192 wasted in
        // each. A pooled division would have said 6,192.
        assert_eq!(p.block_count, 4);
        assert_eq!(p.padding_bytes, 2 * (8_192 - 5_000));
        assert_eq!(p.source_bytes, 10_000);
        assert!((p.efficiency_pct - 61.03515625).abs() < 1e-9, "{p:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The reference's percentage rule is round-to-nearest with a floor
    /// of one block, and the planner reads it rather than restating it.
    #[test]
    fn the_recovery_percentage_is_the_references_rounding() {
        let d = tmp("pct");
        let mut spec = spec_over(&d, &[("a.bin", 32_768)]);
        spec.block = Some(BlockSpec::Size { size: 1_024 });
        for (ask, want) in [(49u32, 16u64), (50, 16), (51, 16), (52, 17), (1, 1)] {
            spec.recovery = Some(RecoverySpec::Percent {
                percent: f64::from(ask),
            });
            let p = preview(&spec).expect("preview");
            assert_eq!(p.block_count, 32);
            assert_eq!(p.recovery_blocks, want, "-r{ask}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The comment reaches the run AND is priced in the preview, and
    /// the capability that lets a host show the field at all is on.
    ///
    /// The preview half is the one that has gone wrong before
    /// (`volume_limit_explicit`): a pane whose sizes are built on a
    /// different call from the create's writes a size the create then
    /// contradicts.
    #[test]
    fn the_comment_is_carried_and_priced() {
        assert!(capabilities_comment(), "the engine writes the packet now");
        let d = tmp("comment");
        let mut spec = spec_over(&d, &[("a.bin", 40_000)]);
        spec.block = Some(BlockSpec::Size { size: 2_048 });
        spec.recovery = Some(RecoverySpec::Count { count: 6 });

        let plain = preview(&spec).expect("preview");
        spec.comment = "a comment worth some bytes".to_string();
        let with = preview(&spec).expect("preview");
        assert!(
            with.warnings.iter().all(|w| !w.contains("comment")),
            "{:?}",
            with.warnings
        );
        assert!(
            with.total_bytes > plain.total_bytes,
            "the comment packet is priced: {} vs {}",
            with.total_bytes,
            plain.total_bytes
        );
        assert!(with.command.contains("--comment="));

        let members = expand_sources(&spec.sources, spec.path_mode, None, SourceRules::Par2)
            .expect("members")
            .members;
        let (o, _) = options_for(&spec, &members).expect("options");
        assert_eq!(o.comment.as_deref(), Some("a comment worth some bytes"));

        // A comment the ENGINE would refuse is said in the pane rather
        // than discovered when the create fails.
        spec.comment = "wipe \u{1b}[2J screen".to_string();
        let bad = preview(&spec).expect("preview");
        assert!(
            bad.warnings.iter().any(|w| w.contains("refused")),
            "{:?}",
            bad.warnings
        );

        // An untouched field is the absence of a comment: no switch on
        // the line and no bytes in the plan.
        spec.comment = String::new();
        let none = preview(&spec).expect("preview");
        assert!(!none.command.contains("--comment"));
        assert_eq!(none.total_bytes, plain.total_bytes);
        let (o, _) = options_for(&spec, &members).expect("options");
        assert_eq!(o.comment, None);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// THE ROUND TRIP. Every line the pane can copy must parse back
    /// into the same `Options` it was built from, or the command shown
    /// is not the command described.
    #[test]
    fn round_trips() {
        let d = tmp("cmd");
        let schemes = [
            VolumeSpec::Pow2,
            VolumeSpec::None,
            VolumeSpec::Uniform {
                files: Some(7),
                blocks_per_file: None,
                file_size: None,
            },
            VolumeSpec::Uniform {
                files: None,
                blocks_per_file: Some(4),
                file_size: None,
            },
            VolumeSpec::Pow2Limit {
                limit: Pow2Limit::Named("largest_source".to_string()),
            },
            // The two ceilings only parfast can spell, which makes
            // `--volume-blocks=N` part of the round trip rather than a
            // switch nothing reads back.
            VolumeSpec::Pow2Limit {
                limit: Pow2Limit::Blocks { blocks: 3 },
            },
            VolumeSpec::Pow2Limit {
                limit: Pow2Limit::Size { size: 100_000 },
            },
        ];
        let recoveries = [
            None,
            Some(RecoverySpec::Percent { percent: 10.0 }),
            Some(RecoverySpec::Count { count: 12 }),
            Some(RecoverySpec::Size { size: 1_000_000 }),
        ];
        for scheme in schemes {
            for recovery in recoveries {
                let mut spec = spec_over(&d, &[("a.bin", 40_000), ("b b.bin", 17_000)]);
                spec.volumes = scheme.clone();
                spec.recovery = recovery;
                spec.block = Some(BlockSpec::Size { size: 2_048 });
                spec.perf.threads = Some(3);
                // A comment with a space and an `=` in it, so the line
                // the pane copies survives both the shell quoting and
                // the parser's own `--opt=value` split.
                spec.comment = "ripped 2026-09-12 = retail".to_string();
                // Flipped across the sweep rather than doubling it: the
                // naming switch is independent of every other field on
                // the line, so one arm of each is the whole property.
                spec.std_naming = recovery.is_none();
                // The Overwrite tick, flipped across the sweep for the
                // same reason and with the OTHER parity, so both arms
                // of both switches are reached and the two are not
                // accidentally tested only together.
                spec.overwrite = recovery.is_some();
                let members =
                    expand_sources(&spec.sources, spec.path_mode, None, SourceRules::Par2)
                        .expect("members")
                        .members;
                // The WHOLE translation, scheme included - `options_for`
                // is what the runner gets, so it is what this must spell.
                let (o, _) = options_for(&spec, &members).expect("options");
                let lengths: Vec<u64> = members.iter().map(|m| m.length).collect();
                let (bs, bc, _) = grid(&o, &lengths);
                let rec = parfast::create::recovery_blocks(&o, bc, bs);
                let args = command_args(&o, &members, &spec, rec);
                let back = parfast::cli::parse("parfast", &{
                    let mut v = vec!["c".to_string()];
                    v.extend(args.iter().cloned());
                    v
                })
                .unwrap_or_else(|e| panic!("{args:?}: {}", e.message));
                assert_eq!(back.command, parfast::cli::Command::Create);
                let b = &back.opts;
                // Compared by what the options MEAN and not field for
                // field: a byte target that no `-r` unit divides is
                // spelled `-c`, which is the same set and a different
                // field. The assertion that matters is that the line
                // would build the set the pane just described.
                let (bs2, bc2, _) = grid(b, &lengths);
                assert_eq!((bs2, bc2), (bs, bc), "{args:?}: grid");
                let rec2 = parfast::create::recovery_blocks(b, bc2, bs2);
                assert_eq!(rec2, rec, "{args:?}: recovery blocks");
                let mut warn2 = Vec::new();
                let mut b2 = b.clone();
                apply_scheme_is_not_reapplied(&mut b2, &mut warn2);
                assert_eq!(
                    parfast::create::recovery_file_count(b, rec2),
                    parfast::create::recovery_file_count(&o, rec),
                    "{args:?}: volume count"
                );
                assert_eq!(
                    parfast::create::create_plan(b, rec2, 40_000, bs2),
                    parfast::create::create_plan(&o, rec, 40_000, bs),
                    "{args:?}: volume plan"
                );
                assert_eq!(b.std_naming, o.std_naming, "{args:?}: volume naming");
                // The one switch on this line that decides whether a
                // file survives, so the round trip is the whole of its
                // guarantee: a pane that says the set is protected and
                // hands over a line that overwrites has told the user
                // the opposite of the truth.
                assert_eq!(b.no_clobber, o.no_clobber, "{args:?}: no-clobber");
                assert_eq!(
                    o.no_clobber, !spec.overwrite,
                    "{args:?}: the Overwrite tick is what sets it"
                );
                assert_eq!(b.volume_blocks, o.volume_blocks, "{args:?}: volume ceiling");
                assert_eq!(b.threads, o.threads, "{args:?}");
                assert_eq!(b.comment, o.comment, "{args:?}: comment");
                assert_eq!(b.files.len(), o.files.len(), "{args:?}");
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The scheme is already IN the parsed line's switches, so
    /// re-applying it would be applying it twice. Named rather than
    /// left as a bare comment so the round trip cannot quietly grow a
    /// second application later.
    fn apply_scheme_is_not_reapplied(_o: &mut parfast::cli::Options, _w: &mut Vec<String>) {}

    /// The pane SHOWS a command line, and with Overwrite unticked that
    /// line must carry `--no-clobber`.
    ///
    /// `round_trips` above proves the argv parses back; this proves the
    /// switch reaches the string a user can actually select and paste,
    /// which is a different claim and the one a user is hurt by. It was
    /// wrong for the first hour of `--no-clobber`'s life: the runner set
    /// the field on the far side of the re-parse, so the create WAS
    /// protected and the line the pane displayed beside it would have
    /// overwritten the set if anyone ran it.
    #[test]
    fn the_copied_line_carries_the_overwrite_decision() {
        let d = tmp("cmdclobber");
        let mut spec = spec_over(&d, &[("a.bin", 40_000)]);
        spec.block = Some(BlockSpec::Size { size: 2_048 });
        spec.recovery = Some(RecoverySpec::Count { count: 2 });

        spec.overwrite = false;
        let guarded = preview(&spec).expect("preview");
        assert!(
            guarded.command.contains("--no-clobber"),
            "the pane protects the set and its own line does not: {}",
            guarded.command
        );

        // And the control arm: ticking Overwrite takes it back off,
        // rather than the switch being unconditional.
        spec.overwrite = true;
        let plain = preview(&spec).expect("preview");
        assert!(
            !plain.command.contains("--no-clobber"),
            "Overwrite is ticked and the line still refuses: {}",
            plain.command
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A path with a space survives the paste, and a plain one is not
    /// dressed up in quotes nobody needs.
    #[test]
    fn the_copied_line_quotes_only_what_has_to_be_quoted() {
        assert_eq!(quote("/abs/a.bin"), "/abs/a.bin");
        assert_eq!(quote("-s1024"), "-s1024");
        assert_eq!(quote("/abs/b b.bin"), "'/abs/b b.bin'");
        assert_eq!(quote("it's"), r"'it'\''s'");
    }

    /// The five schemes each reach a DIFFERENT layout, which is the one
    /// thing a scheme picker has to be true for.
    #[test]
    fn each_scheme_reaches_its_own_layout() {
        let d = tmp("scheme");
        let mut spec = spec_over(&d, &[("a.bin", 200_000)]);
        spec.block = Some(BlockSpec::Size { size: 2_048 });
        spec.recovery = Some(RecoverySpec::Count { count: 20 });

        spec.volumes = VolumeSpec::Pow2;
        let pow2 = preview(&spec).expect("pow2");
        // 1 + 2 + 4 + 8 + 5, so five volumes plus the index.
        assert_eq!(pow2.files.len(), 6, "{:?}", pow2.files);
        assert_eq!(pow2.files[1].blocks, 1);
        assert_eq!(pow2.files[2].blocks, 2);

        spec.volumes = VolumeSpec::None;
        let one = preview(&spec).expect("none");
        assert_eq!(one.files.len(), 2);
        assert_eq!(one.files[1].blocks, 20);

        spec.volumes = VolumeSpec::Uniform {
            files: Some(4),
            blocks_per_file: None,
            file_size: None,
        };
        let even = preview(&spec).expect("uniform");
        assert_eq!(even.files.len(), 5);
        assert!(
            even.files[1..].iter().all(|f| f.blocks == 5),
            "{:?}",
            even.files
        );

        spec.volumes = VolumeSpec::Uniform {
            files: None,
            blocks_per_file: Some(5),
            file_size: None,
        };
        let per = preview(&spec).expect("blocks_per_file");
        assert_eq!(per.files.len(), 5);
        assert!(per.files[1..].iter().all(|f| f.blocks == 5));

        // `-l` caps a volume at the largest SOURCE file, which over a
        // single 200,000-byte member at 2,048 is 97 blocks - well above
        // the 20 this set has - so the ceiling changes nothing here.
        // That is the point: the preview shows what the create will
        // actually write.
        spec.volumes = VolumeSpec::Pow2Limit {
            limit: Pow2Limit::Named("largest_source".to_string()),
        };
        let limited = preview(&spec).expect("pow2_limit");
        assert_eq!(
            limited.files.iter().map(|f| f.blocks).collect::<Vec<_>>(),
            pow2.files.iter().map(|f| f.blocks).collect::<Vec<_>>()
        );

        // An EXPLICIT ceiling IS carried since 12 Sep 2026, through
        // parfast's own `--volume-blocks=N`. Three is under the
        // eight-block volume the exponential plan above has, so the
        // layout must actually move - a ceiling that changed nothing
        // would pass an "is it honoured?" assertion by doing nothing.
        spec.volumes = VolumeSpec::Pow2Limit {
            limit: Pow2Limit::Blocks { blocks: 3 },
        };
        let capped = preview(&spec).expect("pow2_limit blocks");
        assert!(
            capped.warnings.is_empty(),
            "an exact ceiling has nothing to apologise for: {:?}",
            capped.warnings
        );
        assert!(
            capped.files[1..].iter().all(|f| f.blocks <= 3),
            "the ceiling must bind: {:?}",
            capped.files
        );
        assert!(
            capped.files.len() > pow2.files.len(),
            "a binding ceiling splits further than the plan it caps"
        );
        // The copied command line carries it too, which is the whole
        // reason the run honours it: `runner::run_create` re-parses
        // exactly this.
        assert!(
            capped.command.contains("--volume-blocks=3"),
            "{}",
            capped.command
        );

        // A ceiling in BYTES becomes one in blocks at this block size,
        // and the preview says which number it became rather than
        // leaving the user to work it out from the file sizes.
        spec.volumes = VolumeSpec::Pow2Limit {
            limit: Pow2Limit::Size {
                size: 3 * (2_048 + 68),
            },
        };
        let sized = preview(&spec).expect("pow2_limit size");
        assert!(
            sized.files[1..].iter().all(|f| f.blocks <= 3),
            "{:?}",
            sized.files
        );
        assert!(
            sized
                .warnings
                .iter()
                .any(|w| w.contains("3 recovery block(s)")),
            "the resolved block count must be said out loud: {:?}",
            sized.warnings
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Every planned file's size is `par2gen`'s, and their sum is what
    /// the pane calls "total".
    #[test]
    fn the_total_is_the_sum_of_the_planned_files() {
        let d = tmp("total");
        let mut spec = spec_over(&d, &[("a.bin", 100_000)]);
        spec.block = Some(BlockSpec::Size { size: 4_096 });
        spec.recovery = Some(RecoverySpec::Count { count: 8 });
        let p = preview(&spec).expect("preview");
        assert_eq!(p.total_bytes, p.files.iter().map(|f| f.size).sum::<u64>());
        assert_eq!(p.recovery_bytes, 8 * 4_096);
        assert!(p.files[0].blocks == 0, "the index carries no parity");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A SET THE CREATE WOULD REFUSE is said in the pane, because a
    /// preview of an impossible set is worse than no preview.
    ///
    /// PAR2's exponents stop at 65535 and `par2gen::check_create_inputs`
    /// refuses a create that would run past it. `preview` did not look
    /// until 12 Sep 2026, so `-f` near the ceiling drew a complete,
    /// confident pane for a set that cannot exist - and the predicate
    /// here is the engine's own rather than a second reading of `>
    /// 65535`, so the two cannot drift.
    #[test]
    fn a_set_whose_exponents_run_past_the_spec_is_said_out_loud() {
        let d = tmp("exponents");
        let mut spec = spec_over(&d, &[("a.bin", 200_000)]);
        spec.block = Some(BlockSpec::Size { size: 2_048 });
        spec.recovery = Some(RecoverySpec::Count { count: 40 });

        // Far from the ceiling: nothing to say.
        spec.first_recovery_block = 0;
        let fine = preview(&spec).expect("preview");
        assert!(
            fine.warnings.iter().all(|w| !w.contains("65535")),
            "{:?}",
            fine.warnings
        );

        // 65_500 + 40 runs past it, so the create would refuse.
        spec.first_recovery_block = 65_500;
        let over = preview(&spec).expect("preview");
        assert!(
            over.warnings
                .iter()
                .any(|w| w.contains("65535") && w.contains("refuse")),
            "{:?}",
            over.warnings
        );

        // The boundary is the engine's, not a restatement: the last legal
        // set ends exactly at 65535 and says nothing.
        spec.first_recovery_block = 65_535 - 40;
        let exact = preview(&spec).expect("preview");
        assert!(
            exact.warnings.iter().all(|w| !w.contains("65535")),
            "{:?}",
            exact.warnings
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A block COUNT below the file count is unreachable at any block
    /// size, and the pane now says where the number it shows came from.
    ///
    /// A slice never spans a file boundary, so every member needs one and
    /// the search runs out at the payload itself. The engine does not
    /// REFUSE it - one slice per member is a legal set - so this is a
    /// warning and not an error; what was wrong until 12 Sep 2026 was the
    /// silence, which left a poster who typed 2 over three files looking
    /// at a block size of the whole set with no explanation.
    #[test]
    fn a_block_count_no_block_size_can_reach_says_what_it_became() {
        let d = tmp("unreachable");
        let mut spec = spec_over(
            &d,
            &[("a.bin", 10_000), ("b.bin", 10_000), ("c.bin", 10_000)],
        );
        spec.block = Some(BlockSpec::Count { count: 2 });
        let p = preview(&spec).expect("preview");
        assert_eq!(p.block_count, 3, "one slice per member is where it lands");
        assert_eq!(p.block_size, 30_000);
        assert!(
            p.warnings
                .iter()
                .any(|w| w.contains("fewer than the 3 files")),
            "{:?}",
            p.warnings
        );

        // A reachable count says nothing.
        spec.block = Some(BlockSpec::Count { count: 6 });
        let ok = preview(&spec).expect("preview");
        assert!(
            ok.warnings.iter().all(|w| !w.contains("fewer than")),
            "{:?}",
            ok.warnings
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A directory source contributes its files; `recursive` reaches
    /// the tree; a `.par2` and a dot-file are never members.
    #[test]
    fn a_directory_source_expands_the_way_the_reference_walks_it() {
        let d = tmp("walk");
        std::fs::create_dir_all(d.join("sub")).expect("sub");
        for (p, n) in [
            ("a.bin", 10usize),
            (".hidden", 10),
            ("old.par2", 10),
            ("sub/b.bin", 10),
        ] {
            std::fs::write(d.join(p), vec![1u8; n]).expect("fixture");
        }
        let flat = expand_sources(
            &[Source {
                path: d.clone(),
                recursive: false,
            }],
            PathMode::Basename,
            None,
            SourceRules::Par2,
        )
        .expect("flat");
        assert_eq!(
            flat.members
                .iter()
                .map(|m| m.name.as_str())
                .collect::<Vec<_>>(),
            vec!["a.bin"]
        );
        let deep = expand_sources(
            &[Source {
                path: d.clone(),
                recursive: true,
            }],
            PathMode::Relative,
            Some(&d),
            SourceRules::Par2,
        )
        .expect("deep");
        let mut names: Vec<&str> = deep.members.iter().map(|m| m.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["a.bin", "sub/b.bin"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_source_that_is_not_there_is_an_error_and_not_a_quiet_omission() {
        let e = expand_sources(
            &[Source {
                path: PathBuf::from("/nonexistent/parfast-session/x.bin"),
                recursive: false,
            }],
            PathMode::Basename,
            None,
            SourceRules::Par2,
        )
        .expect_err("a missing source refuses");
        assert_eq!(e.code, "missing_source");
    }

    #[cfg(unix)]
    fn mkfifo_at(p: &Path) {
        unsafe extern "C" {
            #[link_name = "mkfifo"]
            fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
        }
        let c = std::ffi::CString::new(p.to_string_lossy().as_bytes()).expect("cstr");
        // SAFETY: `c` is a NUL-terminated C string that outlives the
        // call, which is all `mkfifo(2)` asks of its argument.
        assert_eq!(unsafe { mkfifo(c.as_ptr(), 0o644) }, 0, "mkfifo {p:?}");
    }

    /// The sentences a user actually reads, spelled out - the three are
    /// built with `\` line continuations, and the classic slip there is
    /// a word joined to the next with no space. A `contains` assertion
    /// cannot see it.
    #[test]
    fn the_coverage_lines_read_as_sentences() {
        let l = LeftOut {
            dirs: vec![
                (PathBuf::from("/vol/.Trashes"), "Permission denied".into()),
                (PathBuf::from("/vol/a"), "Permission denied".into()),
                (PathBuf::from("/vol/b"), "Permission denied".into()),
                (PathBuf::from("/vol/c"), "Permission denied".into()),
            ],
            links: 2,
            special: 1,
        };
        assert_eq!(
            l.lines(),
            vec![
                "4 folder(s) could not be read and are NOT protected: \
                 /vol/.Trashes (Permission denied), /vol/a (Permission denied), \
                 /vol/b (Permission denied), and 1 more"
                    .to_string(),
                "2 link(s) were found and are not protected: a walk never leaves \
                 the folder you chose. Add what a link points at as its own source."
                    .to_string(),
                "1 item(s) are not ordinary files (a pipe, a socket, a device) \
                 and are not protected"
                    .to_string(),
            ]
        );
        assert!(LeftOut::default().is_empty());
        assert!(LeftOut::default().lines().is_empty());
    }

    /// A WALK NEVER LEAVES THE FOLDER IT WAS POINTED AT, and `loop -> .`
    /// is the shape that proved it did.
    ///
    /// Before 17 Sep 2026 this walked the link, and then walked it
    /// again from inside itself, until macOS's 32-link `stat` limit
    /// stopped it: one file, 33 members, 33 FileDesc packets carrying
    /// ONE name. `add`'s path dedupe cannot see it - the 33 spellings
    /// are 33 different paths.
    #[cfg(unix)]
    #[test]
    fn a_link_that_points_back_up_the_tree_does_not_multiply_the_set() {
        let d = tmp("loop");
        std::fs::write(d.join("f.bin"), vec![3u8; 10]).expect("fixture");
        std::os::unix::fs::symlink(".", d.join("loop")).expect("symlink");
        let got = expand_sources(
            &[Source {
                path: d.clone(),
                recursive: true,
            }],
            PathMode::Basename,
            None,
            SourceRules::Par2,
        )
        .expect("expand");
        let names: Vec<&str> = got.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["f.bin"], "one file, protected once");
        assert_eq!(got.left_out.links, 1, "and the link is STATED: {got:?}");
        assert!(
            got.left_out.lines().iter().any(|w| w.contains("link")),
            "{:?}",
            got.left_out.lines()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The same defect's other half, and the worse one: a link in a
    /// source folder used to put its TARGET in the recovery set. The
    /// first fixture written for the test above pointed at the system
    /// temp directory by accident and the walk protected it.
    #[cfg(unix)]
    #[test]
    fn a_walk_never_protects_what_is_outside_the_folder_it_was_given() {
        let d = tmp("escape");
        let inside = d.join("chosen");
        let outside = d.join("elsewhere");
        std::fs::create_dir_all(&inside).expect("inside");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(inside.join("mine.bin"), vec![3u8; 10]).expect("fixture");
        std::fs::write(outside.join("theirs.bin"), vec![4u8; 10]).expect("fixture");
        std::os::unix::fs::symlink(&outside, inside.join("out")).expect("symlink");
        let got = expand_sources(
            &[Source {
                path: inside.clone(),
                recursive: true,
            }],
            PathMode::Basename,
            None,
            SourceRules::Par2,
        )
        .expect("expand");
        let names: Vec<&str> = got.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["mine.bin"], "the link's target is not ours");
        assert_eq!(got.left_out.links, 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A fifo stats as a zero-length file and OPENS by blocking until a
    /// writer appears. `checksum::write_text_watched` opens every
    /// member, inside the one call the cancel gate cannot interrupt, so
    /// a fifo reaching a member list is a hang and not an oddity. It
    /// reached one until 17 Sep 2026, under `SourceRules::All` - the
    /// checksum rule, which is exactly the caller that opens.
    #[cfg(unix)]
    #[test]
    fn a_fifo_in_the_folder_is_never_a_member() {
        let d = tmp("fifo");
        std::fs::write(d.join("f.bin"), vec![3u8; 10]).expect("fixture");
        mkfifo_at(&d.join("pipe"));
        let got = expand_sources(
            &[Source {
                path: d.clone(),
                recursive: true,
            }],
            PathMode::Basename,
            None,
            SourceRules::All,
        )
        .expect("expand");
        let names: Vec<&str> = got.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["f.bin"], "the fifo is not an ordinary file");
        assert_eq!(got.left_out.special, 1, "and it is STATED: {got:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A fifo NAMED as a source is refused rather than dropped, for the
    /// reason the missing-source test below gives: what the user
    /// pointed at is not something the manifest can quietly leave out.
    #[cfg(unix)]
    #[test]
    fn a_named_source_that_is_not_an_ordinary_file_is_refused() {
        let d = tmp("named-fifo");
        let pipe = d.join("pipe");
        mkfifo_at(&pipe);
        let e = expand_sources(
            &[Source {
                path: pipe,
                recursive: false,
            }],
            PathMode::Basename,
            None,
            SourceRules::All,
        )
        .expect_err("a fifo is not protectable");
        assert_eq!(e.code, "unsupported_source");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A SUBTREE THAT CANNOT BE ENUMERATED IS REPORTED, NOT DROPPED -
    /// and not refused either. One unreadable `.Trashes` must not stop
    /// a create over the volume that holds it, so the walk keeps going
    /// and the folder's name reaches `warnings`.
    #[cfg(unix)]
    #[test]
    fn a_folder_that_cannot_be_read_is_named_and_the_plan_still_builds() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("unreadable");
        let shut = d.join("shut");
        std::fs::create_dir_all(&shut).expect("shut");
        std::fs::write(shut.join("hidden.bin"), vec![5u8; 10]).expect("fixture");
        std::fs::write(d.join("seen.bin"), vec![3u8; 10]).expect("fixture");
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        // root reads a 0o000 directory anyway, and then there is nothing
        // to observe. Say so rather than asserting something false.
        if std::fs::read_dir(&shut).is_ok() {
            let _ = std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::remove_dir_all(&d);
            eprintln!("skipped: this user can read a 0o000 directory");
            return;
        }
        let got = expand_sources(
            &[Source {
                path: d.clone(),
                recursive: true,
            }],
            PathMode::Basename,
            None,
            SourceRules::Par2,
        )
        .expect("an unreadable subtree is not a refusal");
        let names: Vec<&str> = got.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["seen.bin"]);
        assert_eq!(got.left_out.dirs.len(), 1, "{got:?}");
        assert_eq!(got.left_out.dirs[0].0, shut);
        let said = got.left_out.lines();
        assert!(
            said.iter().any(|w| w.contains("shut") && w.contains("NOT")),
            "the folder is NAMED, because the path is the whole of the fix: {said:?}"
        );

        // And the pane says it, ahead of the arithmetic's own notes.
        let spec = CreateSpec {
            sources: vec![Source {
                path: d.clone(),
                recursive: true,
            }],
            ..spec_over(&d, &[])
        };
        let p = preview(&spec).expect("preview");
        assert!(
            p.warnings.first().is_some_and(|w| w.contains("shut")),
            "coverage comes first: {:?}",
            p.warnings
        );
        assert_eq!(p.source_files, 1);

        let _ = std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Two spellings of ONE file are one member, or the set carries two
    /// FileDesc packets with the same name over the same bytes.
    #[cfg(unix)]
    #[test]
    fn two_spellings_of_one_file_are_one_member() {
        let d = tmp("alias");
        std::fs::create_dir_all(d.join("real")).expect("real");
        std::fs::write(d.join("real/f.bin"), vec![3u8; 10]).expect("fixture");
        std::os::unix::fs::symlink("real", d.join("link")).expect("symlink");
        let got = expand_sources(
            &[
                Source {
                    path: d.join("real/f.bin"),
                    recursive: false,
                },
                Source {
                    path: d.join("link/f.bin"),
                    recursive: false,
                },
            ],
            PathMode::Basename,
            None,
            SourceRules::Par2,
        )
        .expect("expand");
        assert_eq!(got.members.len(), 1, "one file, one member: {got:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The other half of that rule, and why the key is the canonical
    /// PATH and not the inode: two HARD LINKS are one inode and two real
    /// names, and a create asked for both is being asked for both.
    #[cfg(unix)]
    #[test]
    fn two_hard_links_are_two_members_because_par2_protects_names() {
        let d = tmp("hardlink");
        std::fs::write(d.join("a.bin"), vec![3u8; 10]).expect("fixture");
        std::fs::hard_link(d.join("a.bin"), d.join("b.bin")).expect("hard link");
        let got = expand_sources(
            &[Source {
                path: d.clone(),
                recursive: false,
            }],
            PathMode::Basename,
            None,
            SourceRules::Par2,
        )
        .expect("expand");
        let mut names: Vec<&str> = got.members.iter().map(|m| m.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["a.bin", "b.bin"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_base_name_drops_one_par2_suffix_and_no_more() {
        assert_eq!(base_name(Path::new("/abs/set.par2")), "set");
        assert_eq!(base_name(Path::new("/abs/set.part1.par2")), "set.part1");
        assert_eq!(base_name(Path::new("/abs/set")), "set");
    }
}
