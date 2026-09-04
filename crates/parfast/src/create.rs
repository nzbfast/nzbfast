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

use std::path::{Path, PathBuf};

use nzbkit::par2gen::{self, Member};

use crate::cli::{Options, Redundancy};
use crate::help;
use crate::out::{Level, Sink};

/// `c` / `create`.
pub fn run(opts: &Options, sink: &mut Sink) -> u8 {
    sink.set_level(opts.level);
    let Some(par2) = opts.archive.clone().or_else(|| opts.par2.clone()) else {
        sink.err("You must specify a Recovery file.");
        return crate::EXIT_INVALID_ARGS;
    };
    let dir = par2
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let base = match par2.file_name().and_then(|s| s.to_str()) {
        Some(n) => n.strip_suffix(".par2").unwrap_or(n).to_string(),
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
    let block_size = block_size(opts, &lengths);
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
    match par2gen::create_into_exact(
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
    ) {
        Ok(written) => {
            sink.line(
                Level::Normal,
                &format!("Wrote {} bytes to disk", recovery * block_size),
            );
            sink.line(Level::Normal, "Writing recovery packets");
            sink.line(Level::Normal, "Writing verification packets");
            rename_volumes(&dir, &base, &written, opts.first_block, recovery);
            sink.line(Level::Terse, "Done");
            crate::EXIT_SUCCESS
        }
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
        let name = opts
            .basepath
            .as_deref()
            .and_then(|bp| path.strip_prefix(bp).ok())
            .or_else(|| path.strip_prefix(dir).ok())
            .unwrap_or(&path)
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
        out.push(Member { name, path });
    }
    Ok(out)
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
fn block_size(opts: &Options, lengths: &[u64]) -> u64 {
    if let Some(s) = opts.block_size {
        return s.next_multiple_of(4).max(4);
    }
    let count = opts.block_count.unwrap_or(help::DEFAULT_BLOCK_COUNT).max(1);
    let total: u64 = lengths.iter().sum();
    let mut bs = total.div_ceil(count).next_multiple_of(4).max(4);
    while bs < total.max(4) && slice_total(lengths, bs) > count {
        bs += 4;
    }
    bs
}

/// Slices this grid costs: per FILE, never over the pooled total.
fn slice_total(lengths: &[u64], bs: u64) -> u64 {
    if bs == 0 {
        return u64::MAX;
    }
    lengths.iter().map(|&l| l.div_ceil(bs)).sum()
}

/// `-c` wins outright; `-r` is a percentage of the block count or a
/// target size in bytes; neither means the reference's default
/// percentage.
fn recovery_blocks(opts: &Options, blocks: u64, block_size: u64) -> u64 {
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
fn percent_blocks(blocks: u64, pct: u64) -> u64 {
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
fn create_plan(
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
        // `-l`, "limit the size of the recovery files": no recovery file
        // larger than the largest input file. A ceiling in bytes, and
        // the layout counts in slices, so it converts here where both
        // numbers are in hand.
        .with_max_blocks_per_volume(
            opts.limit
                .then(|| (largest_member / block_size.max(1)).max(1) as usize)
                .filter(|_| block_size > 0),
        );
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

/// How many volume files the reference's sizing rule produces.
fn recovery_file_count(opts: &Options, recovery: u64) -> u64 {
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
/// Renaming after the fact is safe and is not a workaround: a PAR2
/// volume's packets carry no filename of their own, so the bytes are
/// untouched and only the directory entry moves.
fn rename_volumes(dir: &Path, base: &str, written: &[String], first_block: u64, recovery: u64) {
    let mut parsed: Vec<(String, u64, u64)> = Vec::new();
    for name in written {
        let Some((first, count)) = split_volume_name(base, name) else {
            continue;
        };
        parsed.push((name.clone(), first, count));
    }
    let fw = digits(first_block.saturating_add(recovery));
    let cw = parsed.iter().map(|&(_, _, c)| digits(c)).max().unwrap_or(1);
    for (name, first, count) in parsed {
        let want = format!("{base}.vol{first:0fw$}+{count:0cw$}.par2");
        if want != name {
            let _ = std::fs::rename(dir.join(&name), dir.join(&want));
        }
    }
}

/// `<base>.vol<first>+<count>.par2` back into its two numbers.
fn split_volume_name(base: &str, name: &str) -> Option<(u64, u64)> {
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
}
