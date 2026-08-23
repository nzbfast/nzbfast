//! Plain split files: HJSplit-style `.001/.002/…` and `.1/.2/…` runs that
//! carry NO archive header at all, where the whole "extraction" is a
//! concatenation in numeric order.
//!
//! A poster who byte-splits a raw `Movie.mkv` into `Movie.mkv.001`,
//! `Movie.mkv.002`, … posts something no archive arm on the ladder can
//! open, because there is no archive: every part is payload bytes. SABnzbd
//! joins these in its post-processing joiner; we used to land the parts
//! loose and leave the user to `cat` them by hand. This module is the
//! missing arm, and it is deliberately the LAST one - see
//! [`collect_split_sets`] for why the detector refuses far more than it
//! accepts.
//!
//! This is emphatically NOT the numeric-volume handling in `rarfix.rs`
//! (`numeric_vol_base`, `stem_volume_set`). Those group `.001` parts that
//! DO carry the `Rar!` magic, and requiring the magic is what stops a
//! `.7z.001` or `.zip.001` part owned by another arm forming a bogus RAR
//! group. Here the magic is the disqualifier rather than the entry ticket:
//! a part carrying any archive head belongs to whichever arm owns that
//! head, never to this one.
//!
//! ...with ONE exception, [`SplitScan::Container`], and it earns its place
//! by a measured failure (TODO 211): an HJSplit of a single store
//! `stage.rar` into `stage.rar.001`..`.062` is a byte split like any other,
//! but part 1 carries the archive's own head, so the rule above refused it
//! while the RAR arm - handed a `.001` that is 1/62nd of an archive - failed
//! with `input is too short`, and the job ended with all 62 parts on disk
//! and nothing delivered. That set belongs to nobody: the arm that owns the
//! head cannot open it. So the head is forgiven on part 1 ALONE, and only
//! once that arm has already failed on this directory - see
//! [`rescue_split_of_container`].

use crate::*;
use tracing::{info, warn};

/// One accepted split-file set: the joined output's name, and its parts in
/// numeric order (part 1 first). Only ever produced by
/// [`collect_split_sets`], so every invariant it checks holds here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SplitSet {
    /// The joined file's name - the part names with the numeric tail
    /// stripped, in part 1's original case.
    pub(crate) base: String,
    /// Parts 1..=n in numeric order.
    pub(crate) parts: Vec<PathBuf>,
    /// The parts' total size as MEASURED during detection. The join
    /// compares the bytes it copied against this, so a part that changed
    /// under us between detection and join refuses instead of publishing
    /// a file that is not the payload.
    pub(crate) total: u64,
}

/// What a scan of the directory is looking for - the two readings of
/// rule 5, and the ONLY thing that differs between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SplitScan {
    /// Rule 5 in full: no part carries an archive head and the base names
    /// no other arm's format. The ordinary arm, and the only one that runs
    /// on a healthy pass.
    Plain,
    /// A byte split OF A CONTAINER: part 1 may carry an archive head and
    /// the base may end in a container extension, because that is exactly
    /// what a split `stage.rar` looks like from the outside. Parts 2..=n
    /// must still be headless, and that is the whole discriminator - a
    /// GENUINE numbered volume set (`film.001`, `film.002`, each a RAR in
    /// its own right) carries the signature on every member, and
    /// concatenating those would produce garbage and delete the volumes.
    /// Only [`rescue_split_of_container`] scans this way.
    Container,
}

/// The numeric tail of a split part: `Movie.mkv.001` -> (`Movie.mkv`, 1, 3).
/// The third field is the tail's WIDTH, which the set-level check uses to
/// refuse a directory mixing `.1` and `.01` for one base.
///
/// Width 1-4 covers every splitter in the wild (`.1`…`.9`, `.001`…`.9999`).
/// Wider than that is not a split tail, it is a name that happens to end in
/// digits (`Movie.2019.12345`).
fn numeric_tail(name: &str) -> Option<(&str, u32, usize)> {
    let p = name.rfind('.')?;
    let tail = &name[p + 1..];
    if !(1..=4).contains(&tail.len()) || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((&name[..p], tail.parse().ok()?, tail.len()))
}

/// Does this name's base belong to some OTHER arm of the ladder, or to no
/// arm at all? The magic check is the real gate - this is the name-level
/// twin of it, so the last-resort routing is visible in the names too and
/// does not rest on a head read alone.
///
/// Refused:
/// * a base another extractor owns (`.rar`, `.7z`, `.zip`/`.zipx`, a
///   `.rNN`/`.zNN` volume tail). A genuine one of those carries its magic
///   and is refused anyway; refusing by name as well means a HEADERLESS
///   `payload.zip.001` (a truncated or decoy first part) is still left for
///   the zip arm to report as the gap it is, rather than silently joined
///   into a file nothing can open.
/// * PAR2 recovery data in every spelling - `.par2`/`.par` and the
///   `.volNNN+NNN` slice marker anywhere in the base. Recovery volumes are
///   an INPUT to repair, and this function's caller deletes what it joins.
/// * `.rev` recovery volumes, for the same reason.
/// * a base that is itself a numeric tail (`Movie.001.001`), a hidden name,
///   a name with no alphanumeric character in it, or anything carrying a
///   path separator. No splitter writes those, and the base becomes an
///   output filename.
///
/// Under [`SplitScan::Container`] the FOUR container extensions are
/// allowed - the joined `stage.rar` is the thing the ordinary path then
/// extracts, so refusing its name is refusing the fix. Nothing else moves:
/// `.par2`/`.par`/`.rev`/`.sfv` are recovery INPUTS and this function's
/// caller deletes what it joins, so those refuse in either reading, as do
/// the `.rNN`/`.zNN` volume tails (a member of a set, never a whole one).
fn plausible_base(base: &str, scan: SplitScan) -> bool {
    if base.is_empty() || base.starts_with('.') || base.contains(std::path::is_separator) {
        return false;
    }
    if !base.chars().any(char::is_alphanumeric) {
        return false;
    }
    if numeric_tail(base).is_some() {
        return false;
    }
    let lower = base.to_ascii_lowercase();
    // Extensions other arms own, plus the recovery/verification sidecars.
    let containers = [".rar", ".7z", ".zip", ".zipx"];
    for owned in containers
        .iter()
        .filter(|_| scan == SplitScan::Plain)
        .chain([".par2", ".par", ".rev", ".sfv"].iter())
    {
        if lower.ends_with(owned) {
            return false;
        }
    }
    // `.rNN` / `.sNN`.. rollover / `.zNN` spanned-zip volume tails, in the
    // letter-plus-TWO-digits spelling every one of those actually uses.
    // `looks_like_named_rar` accepts wider tails (`.r100`); widening it here
    // would eat a release name ending `.x264`, and refusing THAT costs a
    // legitimate join while the magic check - the real gate - already covers
    // any of these that is genuinely an archive.
    if let Some((_, tail)) = lower.rsplit_once('.')
        && tail.len() == 3
        && matches!(tail.as_bytes()[0], b'r'..=b'z')
        && tail[1..].bytes().all(|c| c.is_ascii_digit())
    {
        return false;
    }
    // `name.vol000+01` - a PAR2 slice whose `.par2` was stripped or
    // renamed. Segment-scoped so an innocent `Vol.3` release name survives
    // (the marker is `vol` immediately followed by digits).
    !lower.split('.').any(|seg| {
        seg.strip_prefix("vol")
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
    })
}

/// Does this file open with a head that names it as some other arm's work?
/// RAR, 7-Zip, PAR2 and zip, plus `nzbkit::zip`'s own per-path verdict so
/// the zip arm's grammar (spanned `.zNN`, byte-split `.zip.NNN`) is asked
/// in its own words rather than reimplemented here.
///
/// Checked on EVERY part, not just the first. Only part 1 can carry the
/// joined file's real head, so a later part matching is either a coincidence
/// (~1 in 4 billion, and it costs us a refusal, never a bad join) or a sign
/// the run is not what it looks like. Refusing is free: the parts stay.
///
/// `zip_is_the_payload` is set when the SET'S BASE names a ZIP-backed
/// final payload (`comic.cbz`, `book.epub`, an office document - see
/// `nzbkit::zip::is_final_file`). A `.cbz` IS a zip container, so its
/// first part carrying zip magic is what the deliverable's own bytes look
/// like, not a sign that some other arm owns the set. Refusing on it left
/// `comic.cbz` unwritten while the zip arm extracted the pages instead
/// (read-only sweep 2 M11). Only the ZIP families are forgiven, and only
/// because the NAME said to expect them: a `Rar!`, 7-Zip or PAR2 head
/// under a `.cbz` base is still somebody else's, and still refuses.
fn carries_archive_magic(path: &std::path::Path, zip_is_the_payload: bool) -> bool {
    use std::io::Read;
    if rar_magic(path) || sevenz_magic(path) || file_starts_with_par2_magic(path) {
        return true;
    }
    if zip_is_the_payload {
        return false;
    }
    if nzbkit::zip::is_container(path) {
        return true;
    }
    let mut head = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|()| matches!(&head, b"PK\x03\x04" | b"PK\x05\x06" | b"PK\x07\x08"))
}

/// Every plain split-file set in `dir` that is safe to join, in name order.
///
/// Conservative by construction: a set that fails ANY check below is not
/// reported, and an unreported set is simply left on disk exactly as it
/// arrived. The checks, per candidate base:
///
/// 1. **Gapless from 1.** The parts present must be exactly 1..=n. A
///    missing MIDDLE part (`.001 .002 .004`) leaves a hole in that run and
///    refuses the whole set - joining it would publish a silently truncated
///    file over a set the user could still fix by hand. (A missing FINAL
///    part is not detectable from names alone; nothing can be, and PAR2 has
///    already spoken for completeness by the time this runs.)
/// 2. **No duplicate index.** On a case-sensitive filesystem `Movie.001`
///    and `movie.001` are two files claiming to be part 1. We cannot know
///    which, and the caller deletes what it joins.
/// 3. **Consistent numbering width.** Either every tail is the same width
///    (`.001 .002`), or every tail is minimal (`.1 … .9 .10`, which is how
///    an unpadded splitter rolls over). A mix is not a set we understand.
/// 4. **Uniform part sizes.** Every part but the last is the same non-zero
///    size, and the last is non-empty and no larger. That is what a byte
///    splitter produces, and it is the cheapest evidence that these files
///    are one payload rather than a coincidence of names.
/// 5. **No archive head on any part** ([`carries_archive_magic`]) and a
///    **plausible base** ([`plausible_base`]) - the two halves of "some
///    other arm owns this". Under [`SplitScan::Container`] this one check
///    reads the other way round on part 1: it must carry a head, and parts
///    2..=n still must not.
/// 6. **The output does not already exist.** Joining is never an overwrite -
///    and it is what keeps the one-digit `.1`/`.2` form honest, because the
///    other thing that spells names that way is a duplicate-download suffix
///    (`notes.txt`, `notes.txt.1`), which by construction leaves the
///    unsuffixed original sitting right there.
pub(crate) fn collect_split_sets(dir: &std::path::Path) -> Result<Vec<SplitSet>> {
    collect_sets(dir, SplitScan::Plain)
}

/// [`collect_split_sets`] reading rule 5 the [`SplitScan::Container`] way:
/// every set here is a byte split whose part 1 carries a container's head.
/// Never joined on its own account - [`rescue_split_of_container`] is the
/// only caller, and it runs only after the arm that owns that head failed.
pub(crate) fn collect_container_split_sets(dir: &std::path::Path) -> Result<Vec<SplitSet>> {
    collect_sets(dir, SplitScan::Container)
}

/// Is this container split set the OBFUSCATED twin of a `<base>.7z.NNN`
/// set - a numbered byte split whose part 1 opens with a 7-Zip start
/// header, posted under a name that says nothing at all (`hash.001`,
/// `hash.002`, ...)?
///
/// Such a set is a job of the 7z arm, which reads the ordered parts
/// where they lie through `rarfix::sevenz::SplitParts` (TODO 212) - the
/// exact bytes a join would publish, for none of what a join costs. TODO
/// 258 priced that join at **+1.000x read and +1.000x write of the
/// container** plus 0.49-0.75 cpu_s per GiB, against 10-25 ns a read for
/// the in-place reader, and the numbers carry over here unchanged
/// because it is the same reader over the same join. So
/// `collect_sevenz_archives` groups these into one job, and
/// [`rescue_split_of_container`] stands aside from them for the same
/// reason it already stands aside from a `.7z` base.
///
/// The sniff is deliberately STRONGER than the six-byte magic
/// `collect_sevenz_archives` accepts on a single obfuscated file, and
/// the asymmetry is the whole safety argument. There, a false positive
/// costs one failed open and the file stays on disk. Here it would cost
/// the JOIN, which is this set's only other route, so a coincidence must
/// not be able to reach it: `nzbkit::nameprobe::sevenz_start` parses the
/// full 32-byte signature header and checks the CRC32 it carries over
/// its own twenty geometry bytes, which is 48 bits of magic and 32 bits
/// of checksum. A raw payload that opens that way is not a case worth
/// designing for - and if one ever did, the parts are still all there
/// and untouched, because this path never writes anything.
///
/// Header encryption does not hide it, which is what makes the whole
/// shape identifiable before anyone has a password: `-mhe` encrypts the
/// END header, and that lies in the LAST part, while the signature
/// header sits in plaintext at offset 0 of part 1.
///
/// Named container extensions are refused ([`plausible_base`]'s ordinary
/// reading). A `<base>.7z.NNN` set is already a 7z job by name and is
/// grouped by `split_7z_part`; a `.rar`/`.zip`/`.zipx` base carrying a 7z
/// head is a set whose name and head disagree, and that one keeps
/// today's behaviour - the arm that owns the NAME fails on it first and
/// the rescue then joins it. A named payload base (`comic.cb7`) is
/// refused for the standing reason: its 7z bytes ARE the deliverable.
pub(crate) fn obfuscated_sevenz_split(set: &SplitSet) -> bool {
    use std::io::Read as _;
    if !plausible_base(&set.base, SplitScan::Plain)
        || nzbkit::extract::is_final_name(&set.base.to_ascii_lowercase())
    {
        return false;
    }
    let Some(first) = set.parts.first() else {
        return false;
    };
    let mut head = [0u8; 32];
    std::fs::File::open(first)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|()| nzbkit::nameprobe::sevenz_start(&head).is_some())
}

/// Every obfuscated 7z split set in `dir`, as the ordered part lists the
/// 7z arm takes as jobs - the shape `collect_sevenz_archives` appends to
/// its own scan. See [`obfuscated_sevenz_split`] for what qualifies.
pub(crate) fn collect_obfuscated_sevenz_splits(dir: &std::path::Path) -> Result<Vec<Vec<PathBuf>>> {
    Ok(collect_container_split_sets(dir)?
        .into_iter()
        .filter(obfuscated_sevenz_split)
        .map(|s| s.parts)
        .collect())
}

fn collect_sets(dir: &std::path::Path, scan: SplitScan) -> Result<Vec<SplitSet>> {
    use std::collections::BTreeMap;
    // base (lowercased, for grouping) -> index -> (path, base as written, size, tail width)
    type Part = (PathBuf, String, u64, usize);
    let mut groups: BTreeMap<String, BTreeMap<u32, Vec<Part>>> = BTreeMap::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let path = e.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let Some((base, idx, width)) = numeric_tail(&name) else {
            continue;
        };
        let Ok(md) = e.metadata() else {
            continue;
        };
        groups
            .entry(base.to_ascii_lowercase())
            .or_default()
            .entry(idx)
            .or_default()
            .push((path, base.to_string(), md.len(), width));
    }
    let mut out = Vec::new();
    for (_key, indexed) in groups {
        // (2) one file per index, or we cannot say what part 1 is.
        if indexed.values().any(|v| v.len() != 1) {
            continue;
        }
        let parts: Vec<&Part> = indexed.values().filter_map(|v| v.first()).collect();
        // (1) exactly 1..=n, in order - a hole anywhere refuses the set.
        let n = parts.len();
        if n < 2 || !indexed.keys().copied().eq(1..=(n as u32)) {
            continue;
        }
        // (3) all one width, or all minimal.
        let uniform = parts.iter().all(|p| p.3 == parts[0].3);
        let minimal = parts
            .iter()
            .enumerate()
            .all(|(i, p)| p.3 == (i + 1).to_string().len());
        if !uniform && !minimal {
            continue;
        }
        // (4) every part but the last the same non-zero size; the last
        //     non-empty and no bigger (an evenly divided payload makes the
        //     last part full-size, so this is `<=`, not `<`).
        let chunk = parts[0].2;
        if chunk == 0
            || parts[..n - 1].iter().any(|p| p.2 != chunk)
            || parts[n - 1].2 == 0
            || parts[n - 1].2 > chunk
        {
            continue;
        }
        // (5) name and head both have to say "nobody else owns this" -
        //     with the base's own extension deciding which heads that
        //     rules out, so a split `.cbz`/`.epub`/office payload is
        //     rebuilt rather than opened. The name is RECOVERED from
        //     under the numeric suffix, never sniffed: `nzbkit::zip`'s
        //     standing rules (never magic-sniff a named file, never touch
        //     a final payload) are what this is applying, not widening.
        let base = parts[0].1.clone();
        let zip_is_the_payload = nzbkit::zip::is_final_file(std::path::Path::new(&base));
        // Part 1 alone is read differently by the two scans; parts 2..=n
        // are checked identically by both, and a head on one of THOSE is
        // what says "this is a volume set, not a byte split".
        let head_1 = carries_archive_magic(&parts[0].0, zip_is_the_payload);
        let heads_ok = match scan {
            SplitScan::Plain => !head_1,
            // A headless `payload.zip.001` is a decoy or a truncated grab,
            // never a split container, so it stays refused here too - the
            // arm that owns the name reports it as the gap it is.
            SplitScan::Container => head_1,
        };
        if !plausible_base(&base, scan)
            || !heads_ok
            || parts[1..]
                .iter()
                .any(|p| carries_archive_magic(&p.0, zip_is_the_payload))
        {
            continue;
        }
        // (6) never an overwrite.
        if dir.join(&base).exists() {
            continue;
        }
        out.push(SplitSet {
            base,
            parts: parts.iter().map(|p| p.0.clone()).collect(),
            total: parts.iter().map(|p| p.2).sum(),
        });
    }
    Ok(out)
}

/// Join every set in `sets`, consuming the parts of each one that
/// succeeds. Returns true only when every set produced its file.
///
/// The join lands in an [`ExtractStaging`] dir and is published by rename,
/// the same dance the zip and 7z arms use and for the same reason: a
/// half-written join must never be visible in the output directory, and on
/// any failure the staging dir's `Drop` takes the partial file with it
/// while every part stays exactly where it was. Parts are removed only
/// AFTER the publish, through [`remove_spent_volumes`] - so a failure
/// anywhere leaves the user with precisely what they had before.
pub(crate) fn join_split_sets(dir: &std::path::Path, sets: &[SplitSet]) -> bool {
    let mut all_ok = true;
    for set in sets {
        info!(
            target: "extract",
            "joining {} split part(s) into {}…",
            set.parts.len(),
            set.base
        );
        match join_one(dir, set) {
            Ok(bytes) => {
                info!(
                    target: "extract",
                    "split join complete ✔ ({:.1} MiB)",
                    bytes as f64 / (1u64 << 20) as f64
                );
                remove_spent_volumes(&set.parts);
            }
            Err(e) => {
                warn!(target: "extract", "could not join {} - {e}", set.base);
                all_ok = false;
            }
        }
    }
    all_ok
}

/// TODO 211: rejoin a byte-split CONTAINER the arm that owns its head has
/// just failed on, then extract what the join produced.
///
/// The shape, measured (`research/DISKSHAPE-ROUND-2026-08-21.md` §2.2): a
/// single store `stage.rar` cut into `stage.rar.001`..`.062`. Part 1 is a
/// RAR head over 1/62nd of an archive, so the in-stream mapper refuses it
/// (`data area exceeds volume`) and the set lands whole on disk; the RAR
/// arm then unpacks that `.001` alone and fails at offset 0x1d with `input
/// is too short`; the joiner refused it on the head. Nobody owned it and
/// the job ended rc=1 with all 62 parts on disk.
///
/// `arrived` is the container-scan taken BEFORE any arm ran, and the sets
/// joined here are the intersection of it with a scan taken now - the same
/// invariant step 7 keeps, for the same reason: an arm's OUTPUT must never
/// become this collector's INPUT, and a set that changed size under us is
/// not the set we measured.
///
/// The join's output is extracted in a scratch dir rather than in place.
/// The directory this rescue runs in is by definition one where an arm has
/// already FAILED, and quite possibly one where another arm SUCCEEDED (the
/// ladder records and carries on); re-running the whole ladder over it
/// would extract that arm's archive a second time, beside its own output.
/// The scratch dance is what the top-level nested pass already does with an
/// inner archive for exactly that reason.
///
/// `Ok(None)` = there was nothing to rescue and the caller's own verdict
/// stands. Otherwise the verdict of the directory AFTER the join, which is
/// the honest one: the parts are gone, and what is left is what the join
/// and the extraction made of them.
pub(crate) fn rescue_split_of_container(
    dir: &std::path::Path,
    arrived: &[SplitSet],
    password: Option<&str>,
    depth: usize,
) -> Result<Option<NestOutcome>> {
    let sets: Vec<SplitSet> = collect_container_split_sets(dir)?
        .into_iter()
        .filter(|s| arrived.contains(s))
        // A `.7z` base is never rescued here. Every `<base>.7z.NNN` set
        // this scan accepts is already a job of the 7z arm (step 4 takes
        // any `.7z.<digits>` name, no head check), and since TODO 212
        // that arm reads the parts as ONE byte-space - the exact bytes a
        // join would publish. So if it failed, a join fails the same way,
        // having first written the whole payload a second time and
        // deleted the parts; on the field's header-encrypted shape with
        // no password that is the 1.000x this rescue was measured adding
        // back (`research/SEVENZ-MHE-ROUND-2026-08-22.md` §4.4 priced the
        // 7z arm's own join; this was the second one, found when the
        // first was removed). The parts stay, and the verdict stands.
        .filter(|s| !s.base.to_ascii_lowercase().ends_with(".7z"))
        // And neither is its obfuscated twin - a numbered set posted as
        // `hash.001` whose part 1 carries a CRC-valid 7z start header.
        // The 7z arm groups and reads those in place too, so a join here
        // would re-add the 1.000x that arm just declined to pay; and on
        // the SUCCEEDING ending - where the arm landed the payload but
        // some other archive in this directory failed, which is what
        // brings the rescue here at all - it would join a spent set and
        // then DELETE its parts. See `obfuscated_sevenz_split`.
        .filter(|s| !obfuscated_sevenz_split(s))
        .collect();
    if sets.is_empty() {
        return Ok(None);
    }
    info!(
        target: "extract",
        "no arm could open the split archive - joining the parts and retrying…"
    );
    let joined_all = join_split_sets(dir, &sets);
    let joined: Vec<PathBuf> = sets
        .iter()
        .map(|s| dir.join(&s.base))
        .filter(|p| p.is_file())
        .collect();
    if joined.is_empty() {
        return Ok(None); // nothing published; every part is still there
    }
    let sub = nest_scratch_dir(dir)?;
    let (joined, moved_all) = stage_joined_into(joined, &sub);
    // `false`: no second rescue. The parts are spent, so a nested one could
    // only ever fire on something an extraction just produced.
    // No reason channel: the caller this rescue answers to (step 8 of
    // `extract_one_level_at`) has already taken its own, and the join
    // publishes one container from parts that are already on disk.
    let inner = extract_one_level_at(&sub, password, depth, false, &mut Vec::new(), &mut None)?;
    if inner == Some(NestOutcome::Produced) {
        // The container we built is spent - its bytes now sit beside it as
        // the extracted payload, and we made the file seconds ago, so there
        // is nothing here a user could want back. `None` (nothing claimed
        // it) is the case where the joined file IS the payload: keep it.
        //
        // Except that `inner` is ONE verdict for the whole scratch dir and
        // carries no ownership: with two sets joined here, a sibling's
        // success makes it `Produced` even for an input no arm ever
        // touched (Codex F-01, 23 Aug 2026). A final-payload name is
        // exactly that input by construction - `collect_sevenz_archives`
        // and the stray-archive door both refuse `.cb7`/`.cbr`, so its
        // bytes ARE the deliverable and nothing can ever have consumed
        // them. Deleting one loses it outright: the parts went with the
        // join. Any other joined container that no arm claimed makes the
        // aggregate `Failed`, so this branch does not run for it.
        for p in &joined {
            if nzbkit::extract::is_final_file(p) || nzbkit::zip::is_final_file(p) {
                continue;
            }
            if let Some(name) = p.file_name() {
                let _ = std::fs::remove_file(sub.join(name));
            }
        }
    }
    let lifted = lift_nest_outputs(&sub, dir);
    if lifted {
        let _ = std::fs::remove_dir_all(&sub);
    } else {
        warn!(
            target: "extract",
            "split-join lift-back incomplete - keeping {} in place",
            sub.display()
        );
    }
    Ok(Some(rescue_verdict(joined_all, moved_all, inner, lifted)))
}

/// Move each joined container into `sub`, the scratch dir the retry
/// extraction will run in. Returns the ones that got there, and whether
/// EVERY one did.
///
/// The parts are already spent, so a joined file is the only copy of
/// itself: one that fails to move stays in `dir` unopened, and an empty
/// scratch must not then read as "the join IS the payload" (Codex F-12,
/// 22 Aug 2026). Split out of [`rescue_split_of_container`] so that arm
/// is reachable without a rename seam - a scratch directory this process
/// may not write to is a real `EACCES`, where reaching the same line
/// through the caller needs a live pool and an unpack ladder that has
/// already failed.
fn stage_joined_into(joined: Vec<PathBuf>, sub: &std::path::Path) -> (Vec<PathBuf>, bool) {
    let mut moved_all = true;
    let staged: Vec<PathBuf> = joined
        .into_iter()
        .filter(|p| {
            let Some(name) = p.file_name() else {
                return false;
            };
            match std::fs::rename(p, sub.join(name)) {
                Ok(()) => true,
                Err(e) => {
                    warn!(target: "extract", "could not stage {} for extraction: {e}", p.display());
                    moved_all = false;
                    false
                }
            }
        })
        .collect();
    (staged, moved_all)
}

/// The rescue's verdict, from the four things that can go wrong inside
/// it. Stated as a function rather than folded inline because the F-12
/// input is the one the others hide.
///
/// `inner` is what the retry extraction made of the scratch dir, and
/// `None` there means nobody claimed the joined container - the honest
/// "the join IS the payload" ending, and the only reason a rescue that
/// extracted nothing still reports `Produced`. **An empty scratch dir
/// answers `None` too**, so a joined file that never got staged reaches
/// this with exactly the reading of a payload delivered whole; only
/// `moved_all` separates them. `joined_all` is the same story one step
/// earlier (a set that would not join at all) and `lifted` one step
/// later (output the lift-back left stranded in the scratch dir).
fn rescue_verdict(
    joined_all: bool,
    moved_all: bool,
    inner: Option<NestOutcome>,
    lifted: bool,
) -> NestOutcome {
    let mut out = inner.unwrap_or(NestOutcome::Produced);
    if !joined_all || !moved_all || !lifted {
        out = out.and(NestOutcome::Failed);
    }
    out
}

/// [`rescue_split_of_container`] for the callers that have just watched
/// their own disk unpack fail on the DOWNLOADED files - the get tail's
/// demoted-volume ladder, which unpacks through `try_unrar_spent` rather
/// than through the extraction ladder and so never reaches step 8.
///
/// Nothing in this directory has been produced by an extraction yet (the
/// unpack that would have produced it is the thing that just failed), so
/// the scan taken now IS the arrival scan step 8 compares against. Returns
/// true only when the join happened AND what it produced was extracted.
pub(crate) fn rescue_split_after_failed_unpack(
    dir: &std::path::Path,
    password: Option<&str>,
) -> bool {
    let arrived = match collect_container_split_sets(dir) {
        Ok(a) if !a.is_empty() => a,
        _ => return false,
    };
    matches!(
        rescue_split_of_container(dir, &arrived, password, 0),
        Ok(Some(o)) if o.produced()
    )
}

/// Concatenate one set into `dir`, returning the joined size.
///
/// `concat_files` was the 7z arm's join until TODO 212 (22 Aug 2026)
/// taught that arm to read its parts in place; this is now its one
/// caller, and it lives on with the 7z code so the two stay in reach of
/// each other.
fn join_one(dir: &std::path::Path, set: &SplitSet) -> Result<u64> {
    let staging = ExtractStaging::new(dir)?;
    let target = staging.path().join(&set.base);
    concat_files(&set.parts, &target).with_context(|| format!("writing {}", target.display()))?;
    let written = std::fs::metadata(&target)
        .with_context(|| format!("sizing {}", target.display()))?
        .len();
    // Measured at detection, compared after the copy: a part that grew,
    // shrank or vanished under us means something else is writing to this
    // directory and the joined file is not the payload. Refuse rather than
    // publish it - and refusing is what keeps the parts.
    if written != set.total {
        anyhow::bail!(
            "the parts changed size while joining ({written} of {} bytes)",
            set.total
        );
    }
    staging.publish_into(dir)?;
    Ok(written)
}

#[cfg(test)]
#[path = "splitjoin_tests.rs"]
mod splitjoin_tests;
