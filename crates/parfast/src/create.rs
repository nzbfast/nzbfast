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
    let members = match collect(opts, &dir, sink) {
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
        sink.line(Level::Terse, &format!("Opening: {}", m.name));
    }

    // The COUNT, never a percentage: par2cmdline's switches select an
    // exact number of recovery blocks and the volume split follows it,
    // so a round trip through a percentage moves every file name.
    match par2gen::create_into_exact_controlled(
        &dir,
        &members,
        &base,
        (block_size > 0).then_some(block_size),
        recovery as usize,
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
            rename_volumes(
                &dir,
                &base,
                &written,
                opts.first_block,
                recovery,
                opts.std_naming,
            );
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

/// The members, with the reference's skip rules applied and announced.
fn collect(opts: &Options, dir: &Path, sink: &mut Sink) -> Result<Vec<Member>, u8> {
    let mut named: Vec<PathBuf> = Vec::new();
    if opts.archive.is_some()
        && let Some(first) = &opts.par2
    {
        named.push(first.clone());
    }
    for f in &opts.files {
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
        let name = opts
            .basepath
            .as_deref()
            .map(canonical_pathname)
            .and_then(|bp| cpath.strip_prefix(&bp).ok().map(Path::to_path_buf))
            .or_else(|| path.strip_prefix(dir).ok().map(Path::to_path_buf))
            .unwrap_or_else(|| path.clone())
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
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
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if dot_named(&p) {
                continue;
            }
            walk(&p, out);
        } else {
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
        let mut bs = total.div_ceil(count).next_multiple_of(4).max(4);
        while bs < total.max(4) && slice_total(lengths, bs) > count {
            bs += 4;
        }
        bs
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
    let mut bs = (total / cap).next_multiple_of(4).max(step).max(4);
    while bs < total.max(4) && slice_total(lengths, bs) > cap {
        bs += 4;
    }
    bs
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
        .with_first_exponent(opts.first_block as usize)
        // The ceiling on one volume, in slices. TWO switches can set
        // one and both are ceilings - see `volume_ceiling`.
        .with_max_blocks_per_volume(volume_ceiling(opts, largest_member, block_size));
    // Neither switch given is the exponential default, and it must stay
    // literally that call: `Even` over the same COUNT is a different
    // split (1+2+4+8+5 against 4+4+4+4+4), so routing the default
    // through it would reshape every set nzbfast posts.
    if opts.recovery_files.is_none() && !opts.uniform {
        return base;
    }
    match recovery_file_count(opts, recovery) {
        0 => base,
        n => base.with_volumes(par2gen::VolumePlan::Even(n as usize)),
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
        .then(|| (largest_member / block_size.max(1)).max(1) as usize)
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
    par2gen::variable_volume_count(recovery as usize) as u64
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
pub fn rename_volumes(
    dir: &Path,
    base: &str,
    written: &[String],
    first_block: u64,
    recovery: u64,
    std_naming: bool,
) {
    let want = final_volume_names(base, written, first_block, recovery, std_naming);
    for (name, want) in written.iter().zip(&want) {
        if want != name {
            let _ = std::fs::rename(dir.join(name), dir.join(want));
        }
    }
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
}
