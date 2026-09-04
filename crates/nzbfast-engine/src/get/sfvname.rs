//! Checksum-sidecar naming - the no-RAR matrix's case 22 (finding F6),
//! widened to content sniffing and `.md5` on 30 Aug 2026 (matrix-read
//! rows M4-20 and M4-27), and to the SFV DIALECTS the same day (M4-35:
//! the CRC on the left, md5sum's `*` marker, a quoted name - each one a
//! whole sidecar that used to parse to nothing). Two more the same day
//! (M4-49, M4-50) are the two ways this tier threw a WHOLE honest name
//! map away: a sidecar that repeats itself, and one that is large.
//!
//! A checksum sidecar maps real names to whole-file checksums, and for
//! small sets it is the LIGHTEST name source a poster can ship - a few
//! hundred bytes of text against even a manifest-only PAR2's kilobytes.
//! Field posts use exactly that: payload under random names, one honest
//! sidecar. We classified them as usenet furniture and never read them
//! for naming, so everything kept its posted hash (measured 29 Aug 2026,
//! matrix row 22).
//!
//! Two shapes are read, and they are the two the field actually ships.
//! An `.sfv` maps names to CRC32s; an md5sum / RapidCRC `.md5` maps MD5s
//! to names. Past the parse the tier treats them identically - a unique
//! checksum on one side matching a unique checksum on the other is a
//! name. Do NOT grow a third format here (BSD `MD5 (name) = hash`,
//! `.sha1`) without a measurement saying the field ships one: M4-27's
//! ruling was explicit that SFV plus md5sum is enough.
//!
//! This is the settle-time tier that closes it, and it is deliberately
//! the WEAKEST tier: it runs LAST on both settle paths, after every
//! repair fallback, and only for slots nothing else named. The proof
//! standard is the poster's own: a checksum computed over the full
//! settled file matching the sidecar's entry. Two rules keep it sound,
//! both the house ambiguity discipline:
//!
//! * A checksum claimed by two DIFFERENT names, or two files hashing to
//!   one checksum, is ambiguity - those entries and files are declined,
//!   not guessed at (the same rule the name and md5-16k tiers follow).
//!   An MD5 shared by two payloads of one job declines exactly as a
//!   shared CRC32 does; a stronger checksum is not a licence to guess
//!   where a weaker one would have declined. DIFFERENT is load-bearing
//!   and was measured (M4-49): a checksum claimed twice by the SAME name
//!   is a sidecar repeating itself, and declining it declined a mapping
//!   that was never in doubt. What counts as the same name, and why it
//!   is not what `sanitize_out_name` would say, is at
//!   [`unambiguous_names`].
//! * GH #63's hint rule applies unchanged: a slot whose posted name
//!   beats the sidecar's keeps it (`filedesc_name_is_better`).
//!
//! A sidecar name is a MEMBER name and gets the member-name policy: the
//! publish claims `nzbkit::disk::sanitize_out_name`, so a Windows-authored
//! `VIDEO_TS\VTS_01_1.VOB` lands as the tree it spells and a traversal
//! shape flattens, exactly as a PAR2 FileDesc path does (M4-36, measured
//! GREEN and pinned rather than fixed - see
//! `an_sfv_name_with_a_windows_tree_lands_as_a_tree`). That is a property
//! of a function two modules away, and spelling this publish with
//! `sanitize_filename` instead would flatten a disc tree with nothing
//! else in the tree reporting it.
//!
//! A 32-bit checksum is a weaker claim than PAR2's MD5 pair, and even
//! the MD5 read here is the poster's unverified word rather than a
//! recovery set's, which is why this tier never touches a set-covered
//! file and never overwrites anything: it renames a settled unclaimed
//! file, exactly as the poster asked.
//!
//! # Why the sidecar is found by CONTENT and not by extension (M4-20)
//!
//! Field obfuscation that hashes EVERYTHING hashes the sidecar too, so
//! the one file carrying every real name in the post arrives under a
//! hash with no extension at all. An extension test then declines to
//! open exactly the posts that need this tier most - measured M4-20,
//! CONFIRMED red on the 30 Aug 2026 baseline: the CRC mapping never ran,
//! every name stayed a hash, and rc was still 0. So every settled
//! candidate small enough to BE a sidecar is opened and parsed.
//!
//! **Strictness is the false-positive guard, and it is the whole of it.**
//! A file whose extension DECLARES its format is parsed leniently - the
//! poster told us what it is, and a stray junk line in a real `.sfv`
//! must not cost the whole post its names. A file with no declaring
//! extension has to EARN the reading: it must decode as text, carry no
//! NUL, and EVERY non-comment non-blank line must be well-formed for
//! that format. One bad line and the file is not a sidecar. That is what
//! keeps an `.nfo`, a release log or a small text payload from being
//! parsed into renames - prose does not end every line in 8 hex digits,
//! and `a_hash_named_nfo_is_not_parsed_as_a_sidecar` pins it with an
//! `.nfo` whose last line ends in the payload's own CRC32.
//!
//! # What "small enough to BE a sidecar" means, and what it cost (M4-50)
//!
//! It used to mean a megabyte, refused on `metadata` before the open -
//! cheap, and wrong in one direction nobody had measured: a disc rip's
//! full checksum list with long paths crosses that without being
//! anything unusual, and the WHOLE map went, so a post whose only name
//! source was large got none of it. Measured 30 Aug 2026, rc=0 with
//! every payload under its posted hash.
//!
//! Size is now two ceilings and a question about CONTENT.
//! [`SIDECAR_CAP`] is what a candidate is read on no evidence at all and
//! is unchanged, so every post the tier was built for pays exactly what
//! it paid before. Past it, [`head_reads_as_a_list`] reads 8 KiB and
//! asks whether the file reads as a checksum list; only that earns the
//! rest, and it is bounded again at [`SIDECAR_MAX`], above which nothing
//! is opened whatever it is called. [`SIDECAR_MAX_LINES`] is the third
//! and is the one that describes a sidecar rather than its size.
//!
//! The cost argument survives intact, which is the point of doing it
//! this way rather than by raising the number: a 50 GB payload is asked
//! the question too, and answers it in 8 KiB on its first NUL. What a
//! bigger constant would have bought instead is a full read of every
//! payload under it.
//!
//! # Why it runs on the with-set path too (W4-03/W4-05, 30 Aug 2026)
//!
//! It used to run only where no set activated, which sounds like the
//! same sentence as "it is the weakest tier" and is a different one.
//! Evidence tiers RANK; they do not exclude. A post whose PAR2 covers
//! and names A while B sits outside that set under a hash is exactly
//! the shape the weakest tier exists for, and gating the whole pass on
//! "some usable set exists anywhere in this job" suppressed it for B -
//! measured W4-05: B keeps its hash at rc=0, with an honest SFV sitting
//! right beside it naming it. So the gate is now PER FILE and not per
//! job: a slot some recovery set CLAIMED is off limits (its FileDesc
//! name is the stronger claim and has already been applied), a healthy
//! unclaimed one is fair game whatever the rest of the post carries.
//!
//! Two rules keep composition from becoming precedence-weakening, and
//! both are enforced here rather than trusted to the caller:
//!
//! * a claimed slot is never a rename candidate, and is never
//!   CHECKSUMMED either - see the cost note below;
//! * the publish goes through `publish_weak_name`, which declines
//!   rather than replacing anything already at the target - W4-03,
//!   where an SFV entry named an already-landed same-job file and
//!   `fs::rename` silently ate it at rc=0.
//!
//! # What the census costs, and the limit that buys it back
//!
//! Matching an entry means reading a whole file, and a set-covered
//! release with an `.sfv` beside its PAR2 is the ORDINARY shape - so a
//! census over every settled file would have made this pass a second
//! full read of the payload on a large fraction of real jobs. Measured
//! against the alternative it is not close: 50 GB of extra reads to
//! name a `.nfo`.
//!
//! So the census is the CANDIDATES - the unclaimed files - and nothing
//! else. On a fully covered release that is zero bytes read; on the
//! W4-05 shape it is exactly the file the tier exists to name. The
//! stated limit, rather than one to be found later: an entry whose CRC
//! matches BOTH a claimed file and an unclaimed one is no longer seen as
//! ambiguous, and the unclaimed one takes the name. What that costs is
//! bounded and small - the claimed file keeps the FileDesc name an MD5
//! pair proved, so the worst case is a byte-identical twin landing under
//! the sidecar's name as well, and `publish_weak_name` is what stops it
//! being anything more destructive than that. Two files sharing a CRC32
//! and NOT their content is a 1-in-4-billion draw; two files sharing a
//! CRC32 and their content is a duplicate posting, which is a shape this
//! codebase already treats as ordinary.
use crate::*;
use nzbkit::md5fast::Digest as _;
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

/// Ceiling on a sidecar read on NO evidence at all. Everything the tier
/// was built for is under it - a real sidecar for an ordinary post is a
/// few lines per payload file - so every such post pays exactly what it
/// paid before this row: one `metadata`, then one read.
const SIDECAR_CAP: u64 = 1 << 20;

/// Ceiling on a sidecar that has EARNED a longer read by reading as a
/// checksum list in its first [`SIDECAR_PROBE`] bytes (M4-50). Nothing
/// above this is opened at all, whatever it is called.
///
/// That last clause is what keeps M4-33's shape out: a payload wearing a
/// `.sfv`, 200 MB of it, is refused on its `metadata` and never read.
/// The row that asked for this cap to be lifted said in the same breath
/// that it must not be DELETED, and this is the line that honours it.
///
/// 16 MiB is ~130k lines of long-path SFV, which is far past any post
/// that has ever existed and is a read a settled job absorbs without
/// noticing. It is a bound on I/O and it is not a bound on memory - see
/// [`SIDECAR_MAX_LINES`], which is the one that describes a sidecar
/// rather than its size.
const SIDECAR_MAX: u64 = 16 << 20;

/// How much of an over-[`SIDECAR_CAP`] candidate is read to decide
/// whether it has earned the rest. Enough for many complete lines of
/// every dialect this module parses.
const SIDECAR_PROBE: usize = 8 << 10;

/// The STRUCTURAL bound, and the one the M4-50 row actually asked for: a
/// sidecar is a bounded LIST, and how many bytes it happens to occupy is
/// not what makes it one.
///
/// It is not redundant with [`SIDECAR_MAX`], because the two bound
/// different resources. 16 MiB of `a DEADBEEF\n` is 1.4 million entries,
/// and this pass clones the entry list for the zero-byte tier, so a byte
/// ceiling alone leaves memory a function of the smallest legal line.
/// Counted in LINES rather than parsed entries because it is checked
/// BEFORE the parse, which is the only place it can stop the allocation
/// it exists to bound.
const SIDECAR_MAX_LINES: usize = 200_000;

/// Whether a candidate is too large to be a sidecar at all.
///
/// The size comes from `metadata`, NEVER from what a read returned, and
/// this signature is the guard on that: it takes a PATH and no body, so
/// it cannot be implemented by reading the file. That ordering is the
/// whole cost argument for sniffing by content - the sniff opens every
/// small settled candidate rather than only the `.sfv`-named ones, and
/// it is bounded per file only while every payload above the ceiling is
/// refused BEFORE it is opened. A refactor that reads first and measures
/// after turns that into a full second read of every payload in the job,
/// and nothing would report it.
fn too_big_to_sniff(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.len() > SIDECAR_MAX)
}

/// Whether a candidate is over the no-evidence ceiling, and so has to
/// show the head evidence below before the rest of it is read. Same
/// path-and-no-body discipline as [`too_big_to_sniff`], and for the same
/// reason: this is the question asked of every settled candidate in the
/// job, including the 50 GB one.
fn needs_head_evidence(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.len() > SIDECAR_CAP)
}

/// Whether a candidate's FIRST bytes read as a checksum list, which is
/// what earns it a read past [`SIDECAR_CAP`] (M4-50).
///
/// This is a COST question and never a correctness one, and keeping the
/// two apart is the whole of why it is safe to be permissive here.
/// [`sidecar_entries`] is still the entirety of what decides whether a
/// body is a sidecar, strict for a sniffed file and lenient for a
/// declared one exactly as before - so this asks only the cheap version,
/// one complete well-formed line and no NUL, and a file that passes it
/// and then parses to nothing has cost one bounded read and named
/// nothing. Asking the STRICT question here instead would quietly move
/// the lenient path's ceiling below the strict one's, so a real `.sfv`
/// with a stray junk line in its first 8 KiB would be refused for its
/// SIZE - which is the defect this row is about, reintroduced one layer
/// down.
///
/// A DECLARING extension does NOT earn the longer read, deliberately.
/// M4-33's shape is a payload wearing a furniture extension, and the
/// module doc's whole M4-20 argument is that content decides and the
/// poster's name for the file does not.
///
/// Reads exactly [`SIDECAR_PROBE`] bytes and no more. The trailing
/// partial line is dropped by construction - the probe ends at a fixed
/// byte offset, so its last line is almost certainly cut in half, and
/// half a line is evidence for neither answer. A probe with no newline
/// in it at all therefore judges nothing and says no, which is correct:
/// the file is over a megabyte, so a first line longer than 8 KiB is not
/// a checksum line.
fn head_reads_as_a_list(path: &Path) -> bool {
    use std::io::Read as _;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = vec![0u8; SIDECAR_PROBE];
    let mut n = 0usize;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => return false,
        }
    }
    buf.truncate(n);
    // A UTF-16 byte order mark is two bytes of unambiguous evidence that
    // a tool wrote TEXT here, which is all this question needs. Decoding
    // a UTF-16 prefix cut at a fixed byte offset is not worth doing:
    // `read_sidecar` decodes the whole body properly or refuses it, and
    // that refusal is where a UTF-16 body that is not a sidecar stops.
    //
    // BEFORE the NUL refusal below, and that order is the whole of what
    // keeps W4-13's UTF-16 sidecars reachable at this size: UTF-16LE of
    // ASCII is a NUL every other byte, so a NUL-first probe refuses every
    // one of them for looking binary. Found by the test rather than by
    // reading, which is why the case is pinned.
    if matches!(buf.get(..2), Some([0xFF, 0xFE]) | Some([0xFE, 0xFF])) {
        return true;
    }
    // The same refusal `sidecar_entries` makes, made earlier and more
    // cheaply: no tool that writes one of these files emits a NUL, and
    // it is what a payload's first bytes fail on.
    if buf.contains(&0) {
        return false;
    }
    // A prefix cut mid-character is not a decode failure - `valid_up_to`
    // is by definition a character boundary, so the valid part is taken
    // and judged rather than the whole probe thrown away.
    let text = match std::str::from_utf8(&buf) {
        Ok(s) => s,
        Err(e) => match std::str::from_utf8(&buf[..e.valid_up_to()]) {
            Ok(s) => s,
            Err(_) => return false,
        },
    };
    let Some(cut) = text.rfind('\n') else {
        return false;
    };
    let judged = &text[..=cut];
    !parse_sfv(judged).0.is_empty() || !parse_md5(judged).0.is_empty()
}

/// The checksum a sidecar entry carries. Both kinds flow through one
/// mapping, so a post that ships BOTH an `.sfv` and a `.md5` for the
/// same files simply agrees with itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Sum {
    Crc32(u32),
    Md5([u8; 16]),
}

/// One sidecar line's claim: the name the poster declares, and the
/// checksum they claim for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    pub(super) name: String,
    pub(super) sum: Sum,
}

/// True for a line a sidecar parser must ignore rather than judge:
/// blank, or one of the two comment leaders both formats use (`;` is
/// SFV's and RapidCRC's, `#` is the GNU convention).
fn is_skippable(line: &str) -> bool {
    line.is_empty() || line.starts_with(';') || line.starts_with('#')
}

/// Split a sidecar body into lines the way any text reader must: `\n`,
/// `\r\n`, OR a bare `\r` alone (X6-06). `str::lines()` handles only the
/// first two - it tolerates a trailing `\r` before a `\n` but never
/// splits on one without it - so a sidecar written with classic Mac
/// CR-only endings reads as ONE line, and every structural bound that
/// counts lines the same way (`SIDECAR_MAX_LINES`) agrees with it. A
/// `\r\n` pair yields one empty entry between its two delimiters, which
/// [`is_skippable`] already treats as blank - so this costs nothing on
/// the ordinary `\n` and `\r\n` bodies every other test here builds.
fn text_lines(body: &str) -> impl Iterator<Item = &str> {
    body.split(['\r', '\n'])
}

/// Decode one sidecar's bytes.
///
/// W4-13 (30 Aug 2026): this was `read_to_string`, so a UTF-16 sidecar -
/// what a Windows editor writes when you pick "Unicode" - was skipped by
/// a `let Ok(..) else { continue }` that said nothing, and a UTF-8 BOM
/// rode straight into the first filename. Encodings are DECODED where the
/// bytes say unambiguously what they are (a BOM), and a body that decodes
/// as nothing is reported rather than dropped in silence: an invisible
/// wrong name is the one outcome neither answer may produce.
///
/// Nothing is guessed. There is no charset sniffing here and no lossy
/// decode: `from_utf8_lossy` would turn a CP1252 name into one carrying
/// U+FFFD, which is a wrong name that LOOKS landed - exactly the class
/// this function exists to refuse. A non-BOM sidecar is read as UTF-8,
/// which subsumes the ASCII that real sidecars are written in.
fn read_sidecar(path: &Path) -> Option<String> {
    use std::io::Read as _;
    // Bounded by the same ceiling the `metadata` gate applied, rather
    // than trusting that the two agree: `std::fs::read` here would size
    // its buffer from a stat and then read to EOF regardless, so a file
    // that grew between the gate and the open is read whole. Settled
    // files do not grow, which is why this is a belt and not a fix, but
    // the belt is two lines and the thing it holds back is a 200 MB read
    // in the one function whose ceiling is the M4-33 refusal.
    let mut raw = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(SIDECAR_MAX + 1)
        .read_to_end(&mut raw)
        .ok()?;
    if raw.len() as u64 > SIDECAR_MAX {
        return None;
    }
    // UTF-16 with a BOM: two bytes of unambiguous evidence, so decoding
    // it is reading the file rather than guessing at it. An unpaired
    // surrogate makes the whole body undecodable - reported, not
    // half-taken.
    let utf16 = |le: bool| -> Option<String> {
        // An odd trailing byte is half a code unit. `chunks_exact` would
        // drop it in silence, which is the half-take this whole function
        // refuses to do - so a body that is not a whole number of code
        // units is not decodable at all.
        if raw.len() % 2 != 0 {
            return None;
        }
        let units: Vec<u16> = raw[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                if le {
                    u16::from_le_bytes(*c)
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16(&units).ok()
    };
    let decoded = match raw.get(..2) {
        Some([0xFF, 0xFE]) => utf16(true),
        Some([0xFE, 0xFF]) => utf16(false),
        _ => String::from_utf8(raw.clone()).ok(),
    };
    if decoded.is_none() {
        warn!(
            target: "verify",
            "{} is not text this build can read (not UTF-8, and no UTF-16 byte \
             order mark) - not read for names",
            path.display()
        );
    }
    decoded
}
/// One layer of the quotes a tool wraps a name in, off - and nothing
/// else. `QuickSFV` and several Windows front-ends quote a name that
/// carries spaces, and the quotes are the TOOL's punctuation rather than
/// characters of the file's name, so leaving them on produces a
/// directory entry spelled `"Real Quoted Name.mkv"` that matches nothing
/// (measured on the M4-35 baseline, and that is exactly what landed).
///
/// One layer, and only when BOTH ends carry it: a name that really does
/// begin or end with a quote is legal on every filesystem this ships to,
/// and stripping a lone one would rename the poster's file to something
/// they did not ask for.
fn unquote(name: &str) -> &str {
    let n = name.trim();
    // A lone `"` strips its prefix and then fails the suffix, so the
    // both-ends rule is the `and_then` itself rather than a length test.
    n.strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(n)
}

/// Parse an SFV body in ONE dialect: `;`/`#` comments, and either
/// `name crc8` (the CRC is the LAST whitespace-separated token, so names
/// with spaces survive) or `crc8 name` when `crc_first`.
///
/// The CRC-first spelling is M4-35: QuickCRC and several Windows tools
/// put the checksum on the left, and tools that borrow that layout from
/// md5sum borrow its binary-mode `*` marker with it - so the marker is
/// stripped there, in the position md5sum writes it, and NOT in the
/// name-first spelling where a leading `*` is a character of the name.
///
/// [`parse_sfv`] is what chooses between the two, over the whole body.
fn parse_sfv_side(body: &str, crc_first: bool) -> (Vec<Entry>, bool) {
    let mut out = Vec::new();
    let mut clean = true;
    for line in text_lines(body) {
        let line = line.trim();
        if is_skippable(line) {
            continue;
        }
        let split = if crc_first {
            line.split_once(char::is_whitespace)
        } else {
            line.rsplit_once(char::is_whitespace)
        };
        let Some((first, last)) = split else {
            clean = false;
            continue;
        };
        let (name, crc) = if crc_first {
            (last, first)
        } else {
            (first, last)
        };
        let crc = crc.trim();
        let name = name.trim();
        let name = if crc_first {
            name.strip_prefix('*').unwrap_or(name)
        } else {
            name
        };
        let name = unquote(name);
        // Every digit checked rather than left to `from_str_radix`,
        // which accepts a leading `+` and would take `+1234567` as an
        // eight-character CRC. That is a tightening of the name-first
        // arm as well as a rule for the new one: a sign is not a hex
        // digit, and the strict sniff leans on this test.
        if name.is_empty() || crc.len() != 8 || !crc.bytes().all(|b| b.is_ascii_hexdigit()) {
            clean = false;
            continue;
        }
        let Ok(v) = u32::from_str_radix(crc, 16) else {
            clean = false;
            continue;
        };
        out.push(Entry {
            name: name.to_string(),
            sum: Sum::Crc32(v),
        });
    }
    (out, clean)
}

/// Parse an SFV body, deciding the dialect over the WHOLE file (M4-35).
///
/// Returns the entries and whether EVERY judged line parsed. That second
/// value is what the content sniff turns on (M4-20); the
/// declared-extension path ignores it and stays lenient, so a stray junk
/// line in a real `.sfv` costs that line and not the post's names. See
/// the module doc on strictness.
///
/// # Why the dialect is a property of the FILE and never of the line
///
/// A line whose name happens to be eight hex characters reads both ways
/// and there is nothing IN it to settle which, but a real sidecar is
/// written by one tool in one layout - so the rest of the file settles
/// it. `DEADBEEF AABBCCDD` beside `Real.Name.mkv 12345678` is
/// unambiguous, because only the name-first reading parses the second
/// line at all. Deciding per line instead would let one tool's file be
/// read as two, which is how a strict parse stops being strict.
///
/// A body where BOTH readings are well-formed over every line and they
/// DISAGREE is ambiguity, and this tier declines ambiguity rather than
/// guessing at it - the same rule a checksum claimed by two entries
/// gets. It yields nothing and is not sniffable. (Agreement is not
/// ambiguity: `AABBCCDD AABBCCDD` reads identically either way.)
///
/// Neither reading clean is the LENIENT case, which only a declaring
/// extension ever reaches: the one that recovered more entries wins, and
/// a tie keeps the name-first answer - so every `.sfv` that parsed
/// before this row parses byte-for-byte the same way now.
///
/// # The stated cost of the CRC-first arm
///
/// Widening the grammar widens what the CONTENT sniff can mistake for a
/// sidecar, and this is the shape it opens: a text file whose every line
/// STARTS with eight hex characters - a hex dump's offset column is the
/// realistic one. Bounded rather than argued away: such a file would be
/// counted a sidecar and left out of the rename census, and its
/// "entries" could only rename something by matching a payload's real
/// CRC32, which a column of file offsets does not do. Prose is refused
/// as it always was: it neither starts nor ends a line in eight hex
/// digits.
///
/// The leading U+FEFF is NOT handled here - [`sidecar_entries`] strips it
/// off the body once, so both parsers inherit one strip and neither can
/// do it per line. W4-13's own caveat is why that matters: U+FEFF is a
/// legal character inside a real filename, so a per-line strip would
/// silently corrupt a name on line 40.
fn parse_sfv(body: &str) -> (Vec<Entry>, bool) {
    let name_first = parse_sfv_side(body, false);
    let crc_first = parse_sfv_side(body, true);
    let nf_ok = name_first.1 && !name_first.0.is_empty();
    let cf_ok = crc_first.1 && !crc_first.0.is_empty();
    match (nf_ok, cf_ok) {
        (true, true) if name_first.0 != crc_first.0 => (Vec::new(), false),
        (true, _) => name_first,
        (false, true) => crc_first,
        (false, false) if crc_first.0.len() > name_first.0.len() => crc_first,
        (false, false) => name_first,
    }
}

/// Parse an md5sum / RapidCRC `.md5` body: `32-hex<ws>[*]name` per line
/// (M4-27). The hash comes FIRST here, the mirror image of SFV: md5sum's
/// text mode writes two spaces and its binary mode writes one space plus
/// a `*` marker, and everything after the separator is the name - so
/// names with spaces survive the same way SFV's do.
///
/// BSD's `MD5 (name) = hash` is deliberately NOT read; see the module
/// doc's rule against a third format.
///
/// Same return contract as [`parse_sfv`].
fn parse_md5(body: &str) -> (Vec<Entry>, bool) {
    let mut out = Vec::new();
    let mut clean = true;
    for line in text_lines(body) {
        let line = line.trim();
        if is_skippable(line) {
            continue;
        }
        let Some((hash, rest)) = line.split_once(char::is_whitespace) else {
            clean = false;
            continue;
        };
        // The binary-mode marker belongs to the SEPARATOR, not the name:
        // md5sum writes exactly one space then `*`, and a file really
        // called `*foo` is spelled that way in text mode too, so
        // stripping ONE leading `*` is the reading every md5sum reader
        // uses. Taking it as part of the name renames the payload to
        // `*Real.Md5.Two.mkv`, which the e2e row asserts against.
        let rest = rest.trim_start();
        let name = rest.strip_prefix('*').unwrap_or(rest).trim_end();
        // Every digit checked rather than left to `from_str_radix`, the
        // same test and the same reasoning `parse_sfv_side` carries: a
        // sign is not a hex digit, and the strict sniff leans on this
        // test. It is load-bearing HERE for a second reason, so do not
        // read it as redundant with the error arm below and tidy it
        // away - `hash.len()` is a BYTE length, and the fixed-offset
        // slice under it is str indexing. Without this test a 32-BYTE
        // token holding a multi-byte character (a CJK subtitle line, an
        // accented credit line) cut inside that character and PANICKED,
        // unwinding the settle tail and filing a completed,
        // PAR2-verified job as "post-processing crashed" on every
        // retry. All-ASCII-hex makes every pair provably a char
        // boundary.
        if hash.len() != 32 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) || name.is_empty() {
            clean = false;
            continue;
        }
        let mut sum = [0u8; 16];
        let mut ok = true;
        for (i, b) in sum.iter_mut().enumerate() {
            match u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16) {
                Ok(v) => *b = v,
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            clean = false;
            continue;
        }
        out.push(Entry {
            name: name.to_string(),
            sum: Sum::Md5(sum),
        });
    }
    (out, clean)
}

/// The entries one candidate file offers, or none if it is not a
/// sidecar. See the module doc for why the two paths differ: an
/// extension DECLARES the format and is read leniently, anything else
/// must parse STRICTLY to count at all.
///
/// The byte-order mark comes off HERE, once, off the BODY - so both
/// parsers inherit it and neither can strip it per line. W4-13 measured
/// what leaving it costs (`"\u{FEFF}Real.Bom.mkv"` became a real
/// directory entry, a name that renders identically to the right one and
/// matches nothing) and the parser docs carry why `trim` cannot do it:
/// U+FEFF is not White_Space under Unicode.
fn sidecar_entries(path: &Path, body: &str) -> Vec<Entry> {
    let body = body.strip_prefix('\u{FEFF}').unwrap_or(body);
    // The structural bound (M4-50), and it is checked HERE - before
    // either parser and before the declared/sniffed split - because this
    // is the only place it can stop the allocation it exists to bound.
    // One pass over a string already in memory, no allocation of its
    // own. Refused WHOLE rather than truncated: a half-read name map is
    // the half-take this module refuses everywhere else, and it would
    // publish a subset of the poster's answer while reporting success.
    let judged = text_lines(body).filter(|l| !is_skippable(l.trim())).count();
    if judged > SIDECAR_MAX_LINES {
        warn!(
            target: "verify",
            "{} carries {judged} checksum lines, past the {SIDECAR_MAX_LINES} a \
             sidecar is bounded at - not read for names",
            path.display()
        );
        return Vec::new();
    }
    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .map(|x| x.to_ascii_lowercase());
    // A declaring extension is read leniently (see the module doc), but
    // "lenient" must not mean "silent": the strict `clean` gate below is
    // what would otherwise have caught a malformed sidecar, and a file
    // that DECLARES itself one skips it entirely. X6-06: a CR-only
    // `.sfv` used to parse to nothing here with nothing in the log
    // saying so - every file kept its hash and the post looked
    // untouched. This is a WARN, not a refusal: the lenient contract
    // (a stray junk line costs only that line, never the whole file)
    // is unchanged, and an entry that did parse still returns normally.
    if let Some(kind @ ("sfv" | "md5")) = ext.as_deref() {
        let entries = if kind == "sfv" {
            parse_sfv(body).0
        } else {
            parse_md5(body).0
        };
        if entries.is_empty() {
            warn!(
                target: "verify",
                "{} declares itself a .{kind} sidecar but no name/checksum \
                 line parsed from it - not read for names",
                path.display()
            );
        }
        return entries;
    }
    // A NUL says "not a text sidecar" more cheaply and more honestly
    // than any parse can. `read_sidecar` has already refused bytes that
    // decode as nothing; this refuses bytes that DO decode and still are
    // not text, which no tool that writes these files ever emits.
    if body.contains('\0') {
        return Vec::new();
    }
    let parsers: [fn(&str) -> (Vec<Entry>, bool); 2] = [parse_sfv, parse_md5];
    for parse in parsers {
        let (entries, clean) = parse(body);
        if clean && !entries.is_empty() {
            return entries;
        }
    }
    Vec::new()
}

/// Streaming checksums of a settled file - only the kinds the sidecars
/// actually asked for, in ONE pass over the bytes. A post that ships an
/// `.sfv` alone never pays for an MD5, and vice versa.
fn sums_of(path: &Path, want_crc: bool, want_md5: bool) -> std::io::Result<Vec<Sum>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut crc = crc32fast::Hasher::new();
    let mut md5 = nzbkit::md5fast::Md5::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if want_crc {
            crc.update(&buf[..n]);
        }
        if want_md5 {
            md5.update(&buf[..n]);
        }
    }
    let mut out = Vec::new();
    if want_crc {
        out.push(Sum::Crc32(crc.finalize()));
    }
    if want_md5 {
        out.push(Sum::Md5(md5.finalize().into()));
    }
    Ok(out)
}

/// How a checksum reads in a naming line: the SFV's own 8 hex digits, or
/// an MD5 abbreviated to its first four bytes - enough to find the entry
/// in the sidecar without putting 32 characters in every log line.
fn describe(sum: &Sum) -> String {
    match sum {
        Sum::Crc32(v) => format!("CRC32 {v:08X}"),
        Sum::Md5(v) => {
            let head: String = v[..4].iter().map(|b| format!("{b:02x}")).collect();
            format!("MD5 {head}...")
        }
    }
}

/// The NO-SET path's name registry, seeded from the live slot paths -
/// what makes "never rename over a file this job already landed" true
/// rather than hoped for. Before W4-03 that path handed the SFV tier a
/// FRESH registry, which knows no name, so every target looked free and
/// `fs::rename` replaced whatever was at it.
///
/// The out_dir-RELATIVE name, matching what a publish claims: a
/// tree-preserved slot owns its whole relative path.
///
/// # Why the WITH-SET path does not call this
///
/// It has something better. `super::publishplan::plan_publish_names`
/// decides where every slot will land before a single file moves, and
/// its own header makes the argument against a blanket seed: a slot only
/// OWNS the name it sits under if it is going to STAY there, so seeding
/// a name its own slot is about to vacate pushes that name's rightful
/// owner onto a `{slot:03}-` prefix for a collision that never happens.
/// That pass needs the FileDesc targets to reason about, which is
/// exactly what the no-set path does not have - there are no targets
/// there beyond the ones this tier is about to propose.
///
/// So the blanket seed is kept where it is still the best available
/// answer, and its cost is the one that pass names: an SFV that renames
/// A away from a name it also gives to B leaves B disambiguated for a
/// collision that resolved itself. That is the conservative direction
/// for the weakest tier - B lands under `{slot:03}-` rather than
/// destroying A - and `publish_weak_name` would decline it anyway, since
/// A's file is still at that name when B is published. Extending the
/// plan pass to this path would improve it and is that pass's call to
/// make, not this one's.
pub(super) fn seeded_names(
    slots: &[Arc<FileSlot>],
    extractor: &nzbkit::extract::Extractor,
    out_dir: &Path,
) -> crate::unpack::PublishedNames {
    let mut names = crate::unpack::PublishedNames::for_dir(out_dir);
    for sidx in 0..slots.len() {
        if let Some(p) = extractor.slot_path(sidx) {
            names.seed(sidx, &nzbkit::disk::out_name_of(out_dir, &p));
        }
    }
    names
}
/// The one name each checksum unambiguously claims - the entries side of
/// the module doc's ambiguity rule, in one place so the pass and the
/// test that pins it cannot spell it two ways.
///
/// # A post that says one thing twice has still said one thing (M4-49)
///
/// Two entries on one checksum carrying the SAME name are the sidecar
/// repeating itself, and there are three ordinary ways to get there: a
/// generator that lists a line twice, the same `.sfv` posted twice in
/// one job (both are opened, because M4-20 finds sidecars by content),
/// and a verify-only PAR2 FileDesc agreeing with the `.md5` beside it -
/// that last one being the shape this tier itself creates, since
/// `nonrecovery_entries` and a `.md5` sidecar land under the same
/// [`Sum::Md5`] key. Declining those declined a UNIQUE mapping: measured
/// 30 Aug 2026 on the M4-49 baseline, a two-line sidecar naming one file
/// twice left the payload under its posted hash at rc=0, with the answer
/// sitting in the file beside it.
///
/// Two entries that say DIFFERENT names are the ambiguity this tier
/// declines rather than guesses at. That rule is unchanged, and it is
/// the one the collapse must not weaken.
///
/// # EQUAL IS BYTE-IDENTICAL, and that is a decision rather than the
/// easy reading
///
/// Not equal-after-`sanitize_out_name`, which is the tempting widening
/// because that is the function the publish actually claims. Refused for
/// two reasons, either of which is enough. It is LOSSY: it maps
/// genuinely different declarations onto one string (`..\evil.bin`
/// flattens onto a plain `evil.bin`), so collapsing on it merges two
/// claims that are not the same claim, which is the guess this rule
/// exists to refuse. And it is `cfg!(windows)`-dependent, so the merge -
/// and therefore whether a post gets named at all - would differ between
/// the platforms this ships to, which is not a property any naming
/// decision may have.
///
/// The stated cost, rather than one to be found later: two spellings
/// that differ and would land at one target - a Windows `a\b.mkv` beside
/// a unix `a/b.mkv` for one checksum - stay declined. That is the
/// conservative direction for the weakest tier, and no measured field
/// shape produces it: a sidecar's two copies of a line, and a FileDesc
/// beside the poster's own `.md5`, are written by one tool in one
/// spelling.
///
/// The name list never grows past TWO, which is not an optimisation
/// detail: two distinct names is already the whole answer, and without
/// the cap the duplicate test is quadratic in a sidecar that repeats one
/// checksum a hundred thousand times - a shape [`SIDECAR_MAX_LINES`]
/// bounds but does not forbid.
fn unambiguous_names(entries: Vec<Entry>) -> HashMap<Sum, String> {
    let mut by_sum: HashMap<Sum, Vec<String>> = HashMap::new();
    for e in entries {
        let names = by_sum.entry(e.sum).or_default();
        if names.len() < 2 && !names.contains(&e.name) {
            names.push(e.name);
        }
    }
    let mut out = HashMap::new();
    for (sum, mut names) in by_sum {
        if names.len() == 1 {
            out.insert(sum, names.remove(0));
        }
    }
    out
}

/// The Main packet's VERIFY-ONLY members as checksum entries (M4-21).
///
/// PAR2 lets a Main packet list file ids the set describes but carries no
/// parity for - QuickPar's "verify but do not repair", the shape a poster
/// uses for an `.nfo` or a sample they want checked and not healed. Those
/// descriptors never enter the recovery set (`Par2Set::nonrecovery` says
/// at length why they must not), so no tier above this one has ever seen
/// them: the file kept its posted hash, unnamed and unverified, and
/// nothing said so.
///
/// A FileDesc is a name plus a whole-file MD5, which is precisely this
/// tier's `Entry`. So they are read HERE rather than given a pass of
/// their own, and every rule in this module then applies to them
/// unchanged - the ambiguity decline, the claimed-slot exclusion, the
/// `filedesc_name_is_better` hint rule, and `publish_weak_name`. The
/// evidence bar is the tier's own and is the right one: the name
/// nominates, and the MD5 over the FULL settled file finalizes it, so a
/// verify-only member is named only when its content proves it is that
/// file. Verify-and-name without repair is exactly the product answer
/// PAR2 asks for here.
///
/// Zero-length members are dropped: the empty MD5 is shared by every
/// empty file in the job, and the census below already refuses a
/// zero-byte candidate, so an entry for one could only ever go unmatched
/// or - if two sets both listed one - manufacture a false ambiguity that
/// declines a real name elsewhere.
fn nonrecovery_entries(sets: &[Arc<nzbkit::par2::Par2Set>]) -> Vec<Entry> {
    sets.iter()
        .flat_map(|s| s.nonrecovery.iter())
        .filter(|f| f.length > 0 && !f.name.is_empty())
        .map(|f| Entry {
            name: f.name.clone(),
            sum: Sum::Md5(f.md5),
        })
        .collect()
}

/// Every name a PAR2 descriptor in this post declares with BYTES IN IT,
/// sanitized and lowercased - the veto list for the zero-byte tier
/// ([`super::sfvempty`]), and the whole of what stands in for the no-set
/// gate that tier shipped with (M4-05, 30 Aug 2026).
///
/// The test is "a descriptor declares it at a NONZERO length" and NOT "a
/// descriptor declares it", which is the distinction the widening turns
/// on. M4-05's shape is a MIXED post - a set over some files, a checksum
/// sidecar over the rest, and the sidecar-only ones legitimately empty -
/// so the coarser test refuses exactly the case being served. A
/// descriptor declaring the name at length ZERO is not a veto either:
/// the two sources then AGREE the file is empty, and there is nothing to
/// protect against.
///
/// The pairs come off the descriptor lists rather than from
/// `settle::union_set_names`, which is `pub(super)` and convenient and
/// flattens to names alone - the length is the one field this needs.
///
/// `nonrecovery` is read beside `files` on purpose. A verify-only member
/// (M4-21) is a FileDesc like any other: it declares a name and a
/// length, so a sidecar claiming that name is empty contradicts it just
/// as loudly - and MORE consequentially, because no parity in the post
/// covers a nonrecovery member, so a 0-byte file invented over one can
/// never be corrected by a repair. Reading it here can only ever DECLINE
/// more, never create more, and every entry it declines is one where two
/// of the post's own records disagree about whether the file has bytes.
fn names_declared_with_bytes(
    sets: &[Arc<nzbkit::par2::Par2Set>],
) -> std::collections::HashSet<String> {
    sets.iter()
        .flat_map(|s| s.files.iter().chain(s.nonrecovery.iter()))
        .filter(|f| f.length > 0)
        .map(|f| nzbkit::disk::sanitize_out_name(&f.name).to_lowercase())
        .collect()
}

/// Rename settled unclaimed slot files onto the names the post's
/// checksum sidecars declare for them. Runs last on both settle paths.
///
/// `set_reports` is the settle pass's per-slot report list, which exists
/// exactly for the slots some recovery set CLAIMED - that is what makes a
/// report exist - so it is the per-file gate the module doc describes.
/// Empty on the no-set path, where nothing is claimed by anything.
pub(super) fn land_sfv_names(
    slots: &[Arc<FileSlot>],
    extractor: &nzbkit::extract::Extractor,
    out_dir: &Path,
    published_names: &mut crate::unpack::PublishedNames,
    set_reports: &[(usize, nzbkit::live::SlotReport)],
    sets: &[Arc<nzbkit::par2::Par2Set>],
) {
    let claimed: std::collections::HashSet<usize> = set_reports.iter().map(|(i, _)| *i).collect();
    // Settled, healthy, unmapped slots and their on-disk files - the
    // same eligibility bar the zero-length pairing tier uses: a slot
    // that lost articles or fed an extraction has no finished file for
    // a checksum to speak about.
    //
    // `errors == 0` STAYS, and X6-01 is why it is worth saying so here
    // rather than at each of the four bands that copy this one
    // (`emptydesc.rs` and `yencname.rs` both name this tier as the bar
    // they follow; `tail.rs`'s quarantine spells it out a fourth time).
    // `FileSlot::errors` is `fetch_add`-only - nothing stores, swaps or
    // decrements it anywhere - so the adversarial read was that it
    // counts wire history rather than final bytes, and permanently
    // disqualifies a file some transient already healed. Measured
    // 31 Aug 2026 and REFUTED: TODO 114's consumer steer takes the
    // reject BEFORE the increment (`workers.rs`, the `Err(e)` decode
    // arm - `note_decoded` answers `Steered` and the arm `continue`s
    // past the counter), so a body refetched clean elsewhere leaves
    // this at zero and the file is admitted. When the steer CANNOT
    // heal, the increment happens and those bytes are genuinely lost,
    // which is what makes the clause the completeness witness HERE: a
    // decode error moves no other counter - `missing`, `remaining` and
    // `abandoned` all stay zero - so deleting it admits a holed file to
    // a naming tier. The quarantine is the one band that has a second
    // witness (`slot_uncovered`), so there it is redundant rather than
    // load-bearing. Both readings say do not delete it; the pins are
    // `tests/e2e_norar/healed.rs`, verified to bite by mutation.
    let settled: Vec<(usize, std::path::PathBuf)> = slots
        .iter()
        .enumerate()
        .filter(|(i, s)| {
            !s.is_par2()
                && !s.sample_skipped
                && s.missing.load(Ordering::Relaxed) == 0
                && s.remaining.load(Ordering::Relaxed) == 0
                && s.errors.load(Ordering::Relaxed) == 0
                && s.abandoned.load(Ordering::Relaxed) == 0
                && !extractor.is_mapped(*i)
                && !extractor.is_chased(*i)
        })
        .filter_map(|(i, _)| extractor.slot_path(i).map(|p| (i, p)))
        .collect();

    // Sidecars by CONTENT (M4-20). Every candidate under the ceiling is
    // opened, because an obfuscated post's sidecar has no extension to
    // test; the strict parse in `sidecar_entries` is what refuses
    // everything that is not one. A claimed slot is opened too - the set
    // named it, which says nothing about whether its BYTES are a sidecar
    // that can name the files the set left out.
    let mut entries: Vec<Entry> = nonrecovery_entries(sets);
    let mut is_sidecar: Vec<bool> = vec![false; slots.len()];
    // Counted as a source the moment it contributes an entry, so the
    // closing line's arithmetic stays true when a post ships both.
    let mut sources = usize::from(!entries.is_empty());
    for (i, path) in &settled {
        let declared = path
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("sfv") || x.eq_ignore_ascii_case("md5"));
        if too_big_to_sniff(path) {
            // Only worth a line when the poster SAID it was a sidecar.
            // Every large payload in the job is over this ceiling, and a
            // warning per payload file is noise, not a diagnosis.
            if declared {
                warn!(
                    target: "verify",
                    "{} is over the {} MiB hard sidecar ceiling - not read for names",
                    path.display(),
                    SIDECAR_MAX >> 20
                );
            }
            continue;
        }
        // Over the no-evidence ceiling, so it has to look like a
        // checksum list before the rest of it is read (M4-50). This is
        // the ordinary path for a large real sidecar and it costs one
        // 8 KiB read; for every large PAYLOAD in the job it is the same
        // 8 KiB, refused on the first NUL.
        if needs_head_evidence(path) && !head_reads_as_a_list(path) {
            if declared {
                warn!(
                    target: "verify",
                    "{} is over the {} MiB sidecar ceiling and its first bytes do not \
                     read as a checksum list - not read for names",
                    path.display(),
                    SIDECAR_CAP >> 20
                );
            }
            continue;
        }
        let Some(body) = read_sidecar(path) else {
            continue;
        };
        let parsed = sidecar_entries(path, &body);
        if !parsed.is_empty() {
            sources += 1;
            is_sidecar[*i] = true;
            entries.extend(parsed);
        }
    }
    if entries.is_empty() {
        return;
    }
    // Matrix row M4-07: the zero-byte tier reads the entries RAW, before
    // the ambiguity decline below - a tree declaring the empty checksum
    // twice is two placeholders and not a coincidence. It runs at the
    // END of this function, after the renames, so nothing can publish
    // over what it creates; see `super::sfvempty` for the argument.
    let raw_entries = entries.clone();
    // Decline duplicate checksums among the entries (ambiguity, not a
    // choice). A post shipping an `.sfv` AND a `.md5` for the same files
    // lands two entries per file under DIFFERENT keys, so agreement
    // between the two costs nothing here; disagreement is caught below.
    let want_crc = entries.iter().any(|e| matches!(e.sum, Sum::Crc32(_)));
    let want_md5 = entries.iter().any(|e| matches!(e.sum, Sum::Md5(_)));
    let by_sum = unambiguous_names(entries);

    // Checksum the candidate files - settled, not itself a sidecar, and
    // not claimed by any recovery set - declining two-files-one-checksum
    // the same way.
    //
    // `claimed` is ONE filter doing two jobs, and it is written once
    // rather than twice on purpose. It is the precedence rule (W4-05: a
    // slot a recovery set spoke for keeps the name an MD5 pair proved -
    // this tier composes on disjoint files and never overrules), and it
    // is also what keeps the pass off the payload of an ordinary covered
    // release, which the module doc measures. Restating it as a second
    // guard at the rename below was tried and taken back out: with the
    // census excluding them, a mutation of either copy leaves the other
    // holding, so neither is falsifiable and the pair reads as belt and
    // braces while testing nothing. One gate, and `par2_and_an_sfv_
    // compose_on_disjoint_files` kills it.
    //
    // The sidecar exclusion beside it is by SLOT INDEX and no longer by
    // extension, which is M4-20's other half: an obfuscated sidecar has
    // no `.sfv` to be excluded by, and letting it into the census would
    // have it compete for its own entries' names.
    let mut files_by_sum: HashMap<Sum, Vec<usize>> = HashMap::new();
    for (i, path) in &settled {
        if claimed.contains(i) || is_sidecar[*i] {
            continue;
        }
        if !std::fs::metadata(path).is_ok_and(|m| m.len() > 0) {
            continue;
        }
        match sums_of(path, want_crc, want_md5) {
            Ok(sums) => {
                for s in sums {
                    files_by_sum.entry(s).or_default().push(*i);
                }
            }
            Err(e) => warn!(
                target: "verify",
                "could not checksum {} for the sidecar match: {e}",
                path.display()
            ),
        }
    }
    files_by_sum.retain(|_, v| v.len() == 1);

    // Resolve every entry to its slot FIRST, then decline the
    // contradictions, then rename. Two sidecars - or an `.sfv` and a
    // `.md5` that disagree - can put two names on one slot or one name
    // on two slots, and discovering that mid-rename would leave the job
    // half-published under a contradiction with the first entry's answer
    // already on disk. One slot, one name, or nobody moves.
    let mut resolved: Vec<(usize, String, Sum)> = Vec::new();
    for (sum, name) in by_sum {
        let Some(&sidx) = files_by_sum.get(&sum).map(|v| &v[0]) else {
            continue;
        };
        resolved.push((sidx, name, sum));
    }
    let mut names_per_slot: HashMap<usize, Vec<&str>> = HashMap::new();
    let mut slots_per_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for (sidx, name, _) in &resolved {
        let n = names_per_slot.entry(*sidx).or_default();
        if !n.contains(&name.as_str()) {
            n.push(name);
        }
        let s = slots_per_name.entry(name.as_str()).or_default();
        if !s.contains(sidx) {
            s.push(*sidx);
        }
    }
    let contested: std::collections::HashSet<usize> = resolved
        .iter()
        .filter(|(sidx, name, _)| {
            names_per_slot.get(sidx).is_some_and(|v| v.len() > 1)
                || slots_per_name
                    .get(name.as_str())
                    .is_some_and(|v| v.len() > 1)
        })
        .map(|(sidx, _, _)| *sidx)
        .collect();

    let mut renamed = 0usize;
    let mut done: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for (sidx, name, sum) in &resolved {
        if contested.contains(sidx) {
            warn!(
                target: "verify",
                "the post's checksum sidecars disagree about {} - it keeps its \
                 posted name rather than being renamed onto a guess",
                slots[*sidx].hint
            );
            continue;
        }
        // An `.sfv` and a `.md5` that AGREE resolve one slot twice.
        if !done.insert(*sidx) {
            continue;
        }
        let Some(path) = extractor.slot_path(*sidx) else {
            continue;
        };
        // Already under the declared name (or something better).
        if !super::settle::filedesc_name_is_better(&slots[*sidx], name) {
            continue;
        }
        if let Some(new) = publish_weak_name(&path, name, out_dir, *sidx, published_names) {
            // What LANDED, which is not always what was asked for: the
            // registry pushes a claim off a name another slot of this job
            // already holds, and the user reading the directory needs to
            // be told that happened rather than left to spot a `{slot:03}-`
            // prefix and wonder (W4-03).
            let landed = nzbkit::disk::out_name_of(out_dir, &new);
            if landed == nzbkit::disk::sanitize_out_name(name) {
                info!(
                    target: "verify",
                    "✔ {name} - named by a checksum sidecar ({} over the full file, \
                     posted as {})",
                    describe(sum),
                    slots[*sidx].hint
                );
            } else {
                warn!(
                    target: "verify",
                    "a checksum sidecar names two different files {name} - this post \
                     contradicts itself. {} is the one that matches {}, so it landed \
                     as {landed} rather than replacing the file already at that name",
                    slots[*sidx].hint,
                    describe(sum)
                );
            }
            extractor.note_slot_renamed(*sidx, new);
            renamed += 1;
        }
    }
    // M4-07's zero-byte tier, and M4-05's widening of it. It runs on
    // BOTH paths, with the hazard the old no-set gate stood in for
    // refused per ENTRY instead: `declared_with_bytes` vetoes any name a
    // descriptor in this post declares at a nonzero length. See
    // `super::sfvempty` for why that is the honest form of the bound.
    let made = super::sfvempty::materialize_empty_sfv_entries(
        &raw_entries,
        out_dir,
        &names_declared_with_bytes(sets),
    );
    if renamed > 0 || made > 0 {
        info!(
            target: "verify",
            "{renamed} file(s) named and {made} empty placeholder(s) materialized by \
             {sources} checksum source(s) - the post's own checksums"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CRC32 entries of a parse, in order - the shape the SFV tests
    /// were written against before `.md5` joined the enum.
    fn crcs(v: &[Entry]) -> Vec<(String, u32)> {
        v.iter()
            .filter_map(|e| match e.sum {
                Sum::Crc32(c) => Some((e.name.clone(), c)),
                Sum::Md5(_) => None,
            })
            .collect()
    }

    #[test]
    fn sidecar_lines_parse_and_junk_is_skipped() {
        let body = "; comment\r\n# also comment\r\nA Name With Spaces.mkv DEADBEEF\r\n\
                    plain.bin 0012ABCD\r\nnot-a-crc.bin XYZ\r\nshort.bin ABC\r\n\r\n";
        let (got, clean) = parse_sfv(body);
        assert_eq!(
            crcs(&got),
            vec![
                ("A Name With Spaces.mkv".to_string(), 0xDEADBEEF),
                ("plain.bin".to_string(), 0x0012ABCD),
            ]
        );
        // Two lines did not parse, so this body could never be SNIFFED as
        // a sidecar - only a declaring `.sfv` extension reads it (M4-20).
        assert!(!clean);
    }

    /// X6-06: classic Mac CR-only line endings (`\r` with no `\n`) must
    /// split the same as `\n` and `\r\n` do. `str::lines()` tolerates a
    /// trailing `\r` before a `\n` but never splits on one alone, so a
    /// CR-only `.sfv` used to read as ONE line and parse to nothing -
    /// silently, on a file whose extension declares it a sidecar.
    #[test]
    fn cr_only_line_endings_split_like_any_other() {
        let body = "first.mkv DEADBEEF\rsecond.mkv 0012ABCD\r";
        let got = sidecar_entries(Path::new("r.sfv"), body);
        assert_eq!(
            crcs(&got),
            vec![
                ("first.mkv".to_string(), 0xDEADBEEF),
                ("second.mkv".to_string(), 0x0012ABCD),
            ],
            "a CR-only sidecar must parse the same as an LF one"
        );
        // Mixed CRLF/CR in one body - a real editor rarely does this, but
        // the splitter must not double-count or lose a line either way.
        let mixed = "first.mkv DEADBEEF\r\nsecond.mkv 0012ABCD\rthird.mkv AABBCCDD\n";
        assert_eq!(
            crcs(&sidecar_entries(Path::new("r.sfv"), mixed)).len(),
            3,
            "CRLF and bare CR must both split in a mixed body"
        );
    }

    /// X6-06's other half: a file whose EXTENSION declares it a sidecar
    /// is read leniently and skips the strict `clean` gate entirely - so
    /// a CR-only (or otherwise unparseable) declared sidecar must not
    /// fail SILENTLY. This does not assert on the log line itself (no
    /// subscriber is installed in this suite); it pins the outcome the
    /// warn guards - nothing parses, and the safe empty return still
    /// stands - so a regression that makes it panic or misparse is caught
    /// even though the warn text is not.
    #[test]
    fn a_declared_sidecar_that_parses_to_nothing_still_returns_empty() {
        assert!(sidecar_entries(Path::new("r.sfv"), "not a checksum line at all").is_empty());
        assert!(sidecar_entries(Path::new("r.md5"), "").is_empty());
    }

    /// A sidecar that is neither UTF-8 nor BOM-marked UTF-16 is REFUSED,
    /// never taken lossily. `from_utf8_lossy` on a CP1252 name yields one
    /// carrying U+FFFD - a wrong name that looks landed, which is the one
    /// outcome W4-13 says neither answer may produce. Pinned because the
    /// lossy call is the tempting one-token "fix" for a sidecar that will
    /// not decode, and nothing else in the tree would report it.
    #[test]
    fn an_undecodable_sidecar_is_refused_rather_than_taken_lossily() {
        let dir = std::env::temp_dir().join(format!("nzbfast-sfvdec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 0x93/0x94 are CP1252 curly quotes and are not valid UTF-8; no
        // BOM, so there is no evidence to decode them with.
        let p = dir.join("release.sfv");
        std::fs::write(&p, b"\x93name\x94.mkv DEADBEEF\r\n").unwrap();
        assert!(
            read_sidecar(&p).is_none(),
            "an undecodable sidecar must be refused, not lossily decoded"
        );
        // ...while the ordinary ASCII one it sits beside still reads.
        let ok = dir.join("plain.sfv");
        std::fs::write(&ok, b"name.mkv DEADBEEF\r\n").unwrap();
        assert_eq!(
            read_sidecar(&ok).as_deref(),
            Some("name.mkv DEADBEEF\r\n"),
            "a plain sidecar must still read"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// W4-13: U+FEFF is not White_Space, so `trim` leaves it on the first
    /// name and the output directory gains an entry that renders right and
    /// matches nothing. Pinned at [`sidecar_entries`], which is where the
    /// strip moved when `.md5` arrived (M4-27) - one strip off the BODY,
    /// inherited by both parsers, so neither can do it per line. Only the
    /// FIRST line can carry a BOM; a U+FEFF anywhere else is a character
    /// of a real name, and the second entry here pins that.
    #[test]
    fn a_leading_bom_is_not_part_of_the_first_name() {
        let got = sidecar_entries(
            Path::new("r.sfv"),
            "\u{FEFF}first.mkv DEADBEEF\r\n\u{FEFF}second.mkv 0012ABCD\r\n",
        );
        assert_eq!(
            crcs(&got),
            vec![
                ("first.mkv".to_string(), 0xDEADBEEF),
                ("\u{FEFF}second.mkv".to_string(), 0x0012ABCD),
            ]
        );
        // ...and `trim` alone really does leave it there, which is the
        // measurement this strip exists for rather than a guess about
        // Unicode.
        assert!("\u{FEFF}first.mkv".trim().starts_with('\u{FEFF}'));
        // The `.md5` half, which had no strip of its own before this.
        let got = sidecar_entries(
            Path::new("Zj3uMc77LqB"),
            "\u{FEFF}d41d8cd98f00b204e9800998ecf8427e *First.mkv\r\n",
        );
        assert_eq!(got.len(), 1, "a BOM kept the md5 sidecar from sniffing");
        assert_eq!(got[0].name, "First.mkv");
    }

    fn entries(v: &[(&str, Sum)]) -> Vec<Entry> {
        v.iter()
            .map(|(n, s)| Entry {
                name: (*n).to_string(),
                sum: *s,
            })
            .collect()
    }

    /// The rename pass drops a checksum two entries claim with DIFFERENT
    /// names. Pinned against [`unambiguous_names`] itself and no longer
    /// against a hand-copy of the retain it used to inline: the rule and
    /// its test spelling each other differently is how a rule stops being
    /// the one the product runs.
    #[test]
    fn duplicate_sums_are_ambiguity_not_a_choice() {
        let by_sum = unambiguous_names(entries(&[
            ("one.bin", Sum::Crc32(7)),
            ("two.bin", Sum::Crc32(7)),
            ("three.bin", Sum::Crc32(9)),
        ]));
        assert_eq!(by_sum.len(), 1);
        assert_eq!(by_sum[&Sum::Crc32(9)], "three.bin");
    }

    /// M4-49: a sidecar that says the SAME thing twice has still said one
    /// thing, and the ambiguity decline must not eat it. Measured red on
    /// the 30 Aug 2026 baseline - two identical lines left the payload
    /// under its posted hash at rc=0.
    ///
    /// Four shapes in one, and the third and fourth are the ones a reader
    /// would not think to write: an `.sfv` posted twice in a job (M4-20
    /// opens both), and a verify-only PAR2 FileDesc agreeing with the
    /// poster's own `.md5`, which land under the same [`Sum::Md5`] key
    /// and so were declining each other.
    #[test]
    fn a_repeated_identical_entry_is_not_ambiguity() {
        let md5 = Sum::Md5(md5::Md5::digest(b"x").into());
        for (label, v) in [
            ("a line listed twice", vec![("dup.bin", Sum::Crc32(7)); 2]),
            (
                "the same sfv posted twice",
                vec![("dup.bin", Sum::Crc32(7)); 2],
            ),
            ("a FileDesc agreeing with a .md5", vec![("dup.bin", md5); 2]),
            (
                "one repeated a hundred times",
                vec![("dup.bin", Sum::Crc32(7)); 100],
            ),
        ] {
            let by_sum = unambiguous_names(entries(&v));
            assert_eq!(by_sum.len(), 1, "{label}: declined a unique mapping");
            assert_eq!(by_sum.values().next().unwrap(), "dup.bin", "{label}");
        }
        // ...and the decline still bites the moment a SECOND name shows
        // up, however many times the first one was repeated. This is the
        // half a collapse could quietly take away.
        let mut v = vec![("dup.bin", Sum::Crc32(7)); 50];
        v.push(("other.bin", Sum::Crc32(7)));
        assert!(
            unambiguous_names(entries(&v)).is_empty(),
            "a second distinct name must still be ambiguity"
        );
        // EQUAL IS BYTE-IDENTICAL: two spellings that `sanitize_out_name`
        // would collapse onto one target stay declined, which is the
        // stated cost of not collapsing on that lossy, platform-dependent
        // function. Pinned so the widening is a decision and not a drift.
        let cross = entries(&[("a\\b.mkv", Sum::Crc32(7)), ("a/b.mkv", Sum::Crc32(7))]);
        assert!(
            unambiguous_names(cross).is_empty(),
            "two spellings of one target are still two claims"
        );
    }

    /// M4-27: md5sum writes its binary mode with one space and a `*`, its
    /// text mode with two spaces, and RapidCRC writes a `;` header. All
    /// three are one format and all three must parse CLEAN, or the sniff
    /// refuses the file that carries them.
    #[test]
    fn md5sum_bodies_parse_in_both_modes() {
        let body = "; RapidCRC\r\n\
            d41d8cd98f00b204e9800998ecf8427e *Binary Mode.mkv\r\n\
            0123456789abcdef0123456789ABCDEF  two spaces.bin\r\n\
            fedcba98765432100123456789abcdef single.bin\r\n";
        let (got, clean) = parse_md5(body);
        assert!(clean, "every line is well-formed md5sum");
        let names: Vec<&str> = got.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["Binary Mode.mkv", "two spaces.bin", "single.bin"]
        );
        assert_eq!(got[0].sum, Sum::Md5(md5::Md5::digest(b"").into()));
    }

    /// A 32-BYTE first token is not a 32-character hash, and the
    /// difference used to be a panic: the hash was sliced at fixed byte
    /// offsets after a length test alone, so a token holding a
    /// multi-byte character cut inside it and unwound the settle tail -
    /// which files a completed, PAR2-verified job as
    /// "post-processing crashed", permanently, since every retry reads
    /// the same bytes again. Any UTF-8 text file under the sidecar
    /// bound reaches this parser through the M4-20 content sniff, so a
    /// subtitle or an `.nfo` with a CJK or accented line was enough.
    /// The fix is the hexdigit test `parse_sfv_side` already carried;
    /// these bodies must come back empty and NOT clean.
    #[test]
    fn a_multibyte_first_token_is_refused_and_never_sliced() {
        // A leading three-byte character: the very first pair, at byte
        // offset 0, cuts inside it.
        let cjk = format!("{}{} subtitle.srt\n", '\u{4e2d}', "a".repeat(29));
        assert_eq!(cjk.split(' ').next().unwrap().len(), 32);
        let (got, clean) = parse_md5(&cjk);
        assert!(got.is_empty(), "a multi-byte token yields no entry");
        assert!(!clean, "and the body is not clean, so the sniff refuses it");

        // And the arm the `from_str_radix` error path does NOT save: the
        // first pair is valid hex ("Ca"), so the loop reaches i = 1,
        // where the slice cuts the accented character in half.
        let hexish = format!("Caf\u{e9}{} credits.txt\n", "x".repeat(27));
        assert_eq!(hexish.split(' ').next().unwrap().len(), 32);
        let (got, clean) = parse_md5(&hexish);
        assert!(got.is_empty());
        assert!(!clean);

        // The path the census actually walks: an extensionless UTF-8
        // text file, sniffed by content.
        assert!(sidecar_entries(Path::new("Zj3uMc77LqB"), &cjk).is_empty());
        assert!(sidecar_entries(Path::new("Qw7pLm31Rt"), &hexish).is_empty());
        // And the lenient path, which ignores `clean` entirely and so
        // reaches the same slice with nothing between it and the body.
        assert!(sidecar_entries(Path::new("release.md5"), &cjk).is_empty());
        assert!(sidecar_entries(Path::new("release.md5"), &hexish).is_empty());
    }

    /// M4-20's false-positive guard, which is the whole cost of sniffing
    /// by content: an `.nfo` is text, decodes fine, and must still yield
    /// nothing when nothing DECLARED it a sidecar.
    #[test]
    fn prose_is_not_a_sidecar_however_it_is_sniffed() {
        let nfo = "Release notes for something\n\
                   Encoded by nobody in particular\n\
                   Greets to everyone DEADBEEF\n";
        assert!(sidecar_entries(Path::new("Zj3uMc77LqB"), nfo).is_empty());
        // One bad line is enough, even when every other line is perfect.
        let nearly = "good.bin DEADBEEF\nthis line is prose\nalso.bin 0012ABCD\n";
        assert!(sidecar_entries(Path::new("Kd8wRn42PfX"), nearly).is_empty());
        // The same body under a DECLARING extension is read leniently -
        // a stray junk line must not cost a real `.sfv` its names.
        assert_eq!(sidecar_entries(Path::new("r.sfv"), nearly).len(), 2);
        // And the `.md5` arm of that same lenient path. M4-27's literal
        // shape is one honestly named `release.md5`, which never reaches
        // the sniff at all.
        let mixed = "d41d8cd98f00b204e9800998ecf8427e *ok.bin\nthis line is prose\n";
        assert_eq!(sidecar_entries(Path::new("release.md5"), mixed).len(), 1);
        assert!(sidecar_entries(Path::new("Ax9zEr20Wm"), mixed).is_empty());
    }

    /// M4-20 and M4-27 in one: a sidecar under a hash with no extension
    /// is read by content, in both formats.
    #[test]
    fn an_extensionless_sidecar_is_read_by_content() {
        let sfv = "; generated\r\nReal.Hidden.mkv DEADBEEF\r\n";
        let got = sidecar_entries(Path::new("Zj3uMc77LqB"), sfv);
        assert_eq!(
            crcs(&got),
            vec![("Real.Hidden.mkv".to_string(), 0xDEADBEEF)]
        );
        let md5 = "d41d8cd98f00b204e9800998ecf8427e *Real.Hidden.mkv\r\n";
        let got = sidecar_entries(Path::new("Ep2vBn94XhT"), md5);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "Real.Hidden.mkv");
        assert!(matches!(got[0].sum, Sum::Md5(_)));
    }

    /// `read_sidecar` refuses bytes that decode as nothing; this refuses
    /// bytes that DO decode and still are not a text sidecar. Valid UTF-8
    /// carrying a NUL is the shape neither a strict line parse nor a
    /// decode can speak for.
    #[test]
    fn a_binary_body_that_decodes_is_still_refused() {
        let body = "good.bin DEADBEEF\n\0\n";
        assert!(sidecar_entries(Path::new("Ox8bFs51QdG"), body).is_empty());
    }

    /// M4-35: the CRC-first dialects. QuickCRC and several Windows tools
    /// write the CRC on the LEFT, md5sum's binary marker rides in the same
    /// position when a tool borrows it, and a name carrying spaces gets
    /// quoted on either side. Every one of these is one line of a real
    /// `.sfv`; a name-first-only reader takes the whole sidecar as junk.
    #[test]
    fn crc_first_and_quoted_sfv_dialects_parse() {
        for (body, want) in [
            ("AABBCCDD filename.mkv\r\n", "filename.mkv"),
            ("AABBCCDD *filename.mkv\r\n", "filename.mkv"),
            ("AABBCCDD \"file name.mkv\"\r\n", "file name.mkv"),
            ("\"file name.mkv\" AABBCCDD\r\n", "file name.mkv"),
            ("filename.mkv AABBCCDD\r\n", "filename.mkv"),
        ] {
            let (got, clean) = parse_sfv(body);
            assert!(clean, "not clean: {body:?}");
            assert_eq!(
                crcs(&got),
                vec![(want.to_string(), 0xAABB_CCDD)],
                "{body:?}"
            );
        }
    }

    /// The dialect is decided over the WHOLE body and never per line, so a
    /// line that reads either way takes the answer the rest of the file
    /// gives it. Here line 2 can only be name-first, which settles line 1.
    #[test]
    fn the_sfv_dialect_is_a_property_of_the_file() {
        let (got, clean) = parse_sfv("DEADBEEF AABBCCDD\r\nReal.Name.mkv 12345678\r\n");
        assert!(clean);
        assert_eq!(
            crcs(&got),
            vec![
                ("DEADBEEF".to_string(), 0xAABB_CCDD),
                ("Real.Name.mkv".to_string(), 0x1234_5678),
            ]
        );
        // Mirror image: line 2 can only be CRC-first, so line 1 takes the
        // opposite reading of the very same bytes.
        let (got, clean) = parse_sfv("DEADBEEF AABBCCDD\r\n12345678 Real.Name.mkv\r\n");
        assert!(clean);
        assert_eq!(
            crcs(&got),
            vec![
                ("AABBCCDD".to_string(), 0xDEAD_BEEF),
                ("Real.Name.mkv".to_string(), 0x1234_5678),
            ]
        );
    }

    /// ...and a body where NOTHING settles it is ambiguity, which this
    /// tier declines rather than guesses at - the same rule a duplicate
    /// checksum gets. Both readings are well-formed and they disagree
    /// about which token is the name, so there is no answer to publish.
    #[test]
    fn a_wholly_ambiguous_sfv_is_declined_rather_than_guessed_at() {
        let body = "DEADBEEF AABBCCDD\r\n0012ABCD 12345678\r\n";
        let (got, clean) = parse_sfv(body);
        assert!(got.is_empty(), "an ambiguous body must yield no entries");
        assert!(!clean, "and must never be sniffable as a sidecar");
        assert!(sidecar_entries(Path::new("r.sfv"), body).is_empty());
        assert!(sidecar_entries(Path::new("Zj3uMc77LqB"), body).is_empty());
    }

    /// M4-36: an SFV written on Windows spells its tree with `\`, and the
    /// name a sidecar declares must go through the SAME relpath rules a
    /// PAR2 FileDesc name does - a disc tree that lands flat does not
    /// play. The parser keeps the poster's spelling; `sanitize_out_name`
    /// is the one policy function every member name goes through, and the
    /// publish this tier calls uses it (`publish_weak_name`).
    #[test]
    fn a_windows_tree_in_an_sfv_name_survives_as_a_tree() {
        let (got, clean) = parse_sfv("VIDEO_TS\\VTS_01_1.VOB AABBCCDD\r\n");
        assert!(clean);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "VIDEO_TS\\VTS_01_1.VOB");
        assert_eq!(
            nzbkit::disk::sanitize_out_name(&got[0].name),
            "VIDEO_TS/VTS_01_1.VOB",
            "the SFV name must reach the tree-preserving policy, not a flat join"
        );
        // The CRC-first spelling of the same tree, and the traversal
        // shape that must still flatten.
        let (got, _) = parse_sfv("AABBCCDD VIDEO_TS\\VTS_01_1.VOB\r\n");
        assert_eq!(
            nzbkit::disk::sanitize_out_name(&got[0].name),
            "VIDEO_TS/VTS_01_1.VOB"
        );
        let (got, _) = parse_sfv("..\\evil.bin AABBCCDD\r\n");
        let flat = nzbkit::disk::sanitize_out_name(&got[0].name);
        assert!(
            !flat.contains('/') && flat.ends_with("evil.bin"),
            "a traversal-shaped SFV name must flatten, got {flat:?}"
        );
    }

    /// The sniff opens every small settled candidate rather than only the
    /// `.sfv`-named ones, and what bounds that is the ceiling being read
    /// from `metadata` BEFORE the open. Pinned against real files,
    /// because a comment saying "measure before you open" is exactly the
    /// kind of thing that decays.
    #[test]
    fn the_size_ceilings_are_measured_and_not_read() {
        let dir = std::env::temp_dir().join(format!("nzbfast-sidecarcap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let small = dir.join("small.sfv");
        std::fs::write(&small, b"one.bin DEADBEEF\n").unwrap();
        assert!(!too_big_to_sniff(&small));
        assert!(!needs_head_evidence(&small), "a small sidecar owes nothing");
        // Over the no-evidence ceiling but under the hard one: readable,
        // and only on the head evidence below.
        let mid = dir.join("mid.sfv");
        std::fs::write(&mid, vec![b'x'; (SIDECAR_CAP + 1) as usize]).unwrap();
        assert!(
            !too_big_to_sniff(&mid),
            "M4-50: a 1 MiB sidecar is not refused outright"
        );
        assert!(needs_head_evidence(&mid));
        // ...and M4-33's shape, which the row that lifted the cap said in
        // the same breath must still be refused: over the hard ceiling,
        // never opened, whatever it is called.
        let big = dir.join("big.sfv");
        std::fs::write(&big, vec![b'x'; (SIDECAR_MAX + 1) as usize]).unwrap();
        assert!(
            too_big_to_sniff(&big),
            "a payload wearing .sfv must stay refused"
        );
        // A path that is not there is not a sidecar and not a refusal -
        // the collection loop's own read declines it a moment later.
        assert!(!too_big_to_sniff(&dir.join("gone.sfv")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A descriptor whose length is what decides the veto, driven
    /// directly. The e2e pins cover the road to it; this covers the one
    /// field, because the alternative reading of it - veto every name a
    /// descriptor declares, at any length - is behaviourally MASKED
    /// end-to-end and so cannot be caught out there.
    ///
    /// Why masked, stated rather than left to be rediscovered: the only
    /// case the two readings disagree on is a descriptor declaring the
    /// name at length ZERO, and there [`super::emptydesc`] materializes
    /// the file from the descriptor's own empty MD5 whatever this tier
    /// does. So an e2e written for it would pass under both readings and
    /// read as a pin while testing nothing - which is this file's own
    /// standing lesson about guards that cannot be falsified. The pin
    /// belongs here, on the function, where the disagreement is visible.
    ///
    /// `nonrecovery` is in the same assertion for the same reason: it is
    /// a separate list on [`nzbkit::par2::Par2Set`] that a reader
    /// tidying this function would not think to keep.
    #[test]
    fn only_a_descriptor_with_bytes_in_it_vetoes_a_placeholder() {
        fn f(name: &str, length: u64) -> nzbkit::par2::Par2File {
            nzbkit::par2::Par2File {
                file_id: [1u8; 16],
                name: name.to_string(),
                length,
                md5: [0u8; 16],
                md5_16k: [0u8; 16],
                blocks: Vec::new(),
            }
        }
        let sets = vec![Arc::new(nzbkit::par2::Par2Set {
            recovery_set_id: [7u8; 16],
            block_size: 1000,
            files: vec![f("Real.Feature.MKV", 60_000), f("Placeholder.bin", 0)],
            nonrecovery: vec![f("Sample.nfo", 900), f("Empty.nfo", 0)],
            recovery_blocks_seen: 0,
        })];
        let mut got: Vec<String> = names_declared_with_bytes(&sets).into_iter().collect();
        got.sort();
        assert_eq!(
            got,
            vec!["real.feature.mkv".to_string(), "sample.nfo".to_string()],
            "the veto list is not exactly the descriptors with bytes in them, folded \
             for the key the tier looks itself up by"
        );
    }

    /// M4-51 - a `.sha256` / `.sha` sidecar as the post's ONLY name map.
    ///
    /// This is a MEASUREMENT of today's answer, not an endorsement of
    /// it. Measured 30 Aug 2026: a well-formed sha256sum body yields
    /// ZERO entries under all three routes - declared by `.sha256`,
    /// declared by `.sha`, and arriving obfuscated under a hash with no
    /// extension - so every name in such a post stays a hash at rc=0.
    /// `smart::is_junk_ext` already lists both extensions, so nothing
    /// downstream treats the file as payload either.
    ///
    /// The module header's rule is what stands: do not grow a third
    /// format here without a measurement saying the field ships one.
    /// That is a PRODUCT decision and it is queued as one - the
    /// sidecar-format policy in `research/CHIP-QUEUE-2026-08-30.md`,
    /// which now has FIVE rows behind it (M4-47 `.srr`, this one, M4-72
    /// uuencode/gzip, M4-73 `.m3u`/`.pls`, M4-100 PAR1) and is
    /// deliberately decided once rather than five times. The
    /// measurement and the price are written up in
    /// `research/M4-51-SHA-SIDECAR-COST-2026-08-30.md`.
    ///
    /// So this test exists to make the current answer a DECISION rather
    /// than an accident. If the policy comes back the other way, DELETE
    /// it - do not weaken it into something a half-built parser also
    /// passes.
    #[test]
    fn a_sha256_sidecar_is_not_read_pending_the_format_ruling() {
        let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  \
Real.One.mkv\n5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03 \
*Real.Two.mkv\n";
        for name in ["release.sha256", "release.sha", "Zj3uMc77LqB"] {
            assert!(
                sidecar_entries(Path::new(name), sha).is_empty(),
                "{name}: the sha256 dialect is not a format this tier reads"
            );
        }
        // The CONTROL: the same two lines in the md5sum dialect this
        // tier DOES read, so a red above is the digest width and not the
        // grammar - the two bodies differ only in that.
        let md5 = "d41d8cd98f00b204e9800998ecf8427e  Real.One.mkv\n\
5891b5b522d5df086d0ff0b110fbd9d2 *Real.Two.mkv\n";
        assert_eq!(sidecar_entries(Path::new("release.md5"), md5).len(), 2);
    }

    /// M4-50's gate: what earns a candidate a read past [`SIDECAR_CAP`]
    /// is its CONTENT, and the probe is bounded whatever the file is.
    ///
    /// The payload arm is the cost argument made executable. A 50 GB
    /// video is asked this question too, and what must happen is that it
    /// costs one 8 KiB read and says no - not that it is skipped for
    /// being large, which is the rule this row replaced.
    #[test]
    fn the_head_probe_decides_who_earns_a_longer_read() {
        let dir = std::env::temp_dir().join(format!("nzbfast-sidecarhead-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let write = |n: &str, b: &[u8]| {
            let p = dir.join(n);
            std::fs::write(&p, b).unwrap();
            p
        };
        // A real long sidecar in each dialect, and a name-first one whose
        // first line is a comment.
        for (n, head) in [
            ("sfv", "one.bin DEADBEEF\r\n".to_string()),
            ("crcfirst", "DEADBEEF one.bin\r\n".to_string()),
            (
                "md5",
                "d41d8cd98f00b204e9800998ecf8427e *one.bin\r\n".to_string(),
            ),
            (
                "commented",
                "; QuickSFV\r\none.bin DEADBEEF\r\n".to_string(),
            ),
        ] {
            let p = write(n, head.repeat(400).as_bytes());
            assert!(head_reads_as_a_list(&p), "{n} must earn its read");
        }
        // A payload: binary, and refused on the NUL long before the
        // probe is exhausted.
        let p = write("movie.mkv", &vec![0u8; SIDECAR_PROBE * 2]);
        assert!(!head_reads_as_a_list(&p));
        // Prose is text and is still not a checksum list.
        let p = write(
            "notes.nfo",
            "Release notes for something\n".repeat(400).as_bytes(),
        );
        assert!(!head_reads_as_a_list(&p));
        // A first line longer than the whole probe judges nothing, and
        // says no rather than guessing from half of it.
        let p = write("oneline.sfv", &vec![b'x'; SIDECAR_PROBE * 2]);
        assert!(!head_reads_as_a_list(&p));
        // A UTF-16 byte order mark is evidence of TEXT, which is all this
        // question asks; `read_sidecar` is what decodes or refuses it.
        let mut u16body = vec![0xFFu8, 0xFE];
        for c in "one.bin DEADBEEF\r\n".repeat(200).encode_utf16() {
            u16body.extend_from_slice(&c.to_le_bytes());
        }
        let p = write("utf16.sfv", &u16body);
        assert!(head_reads_as_a_list(&p));
        assert!(!head_reads_as_a_list(&dir.join("gone.sfv")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The structural bound (M4-50). A sidecar is a bounded LIST, and the
    /// refusal past that bound is WHOLE rather than truncated - a half
    /// name map published as a success is the half-take this module
    /// refuses everywhere else.
    #[test]
    fn a_list_past_the_line_bound_is_refused_whole() {
        let ok = "one.bin DEADBEEF\n".repeat(SIDECAR_MAX_LINES);
        assert_eq!(
            sidecar_entries(Path::new("r.sfv"), &ok).len(),
            SIDECAR_MAX_LINES,
            "the bound itself must still read"
        );
        let over = "one.bin DEADBEEF\n".repeat(SIDECAR_MAX_LINES + 1);
        assert!(
            sidecar_entries(Path::new("r.sfv"), &over).is_empty(),
            "past the bound is refused whole, not truncated"
        );
        // Comments and blanks are not list lines, so a heavily commented
        // sidecar at the bound is still read - the bound describes the
        // LIST and not the file.
        let commented = format!("{}{}", "; header\n".repeat(50_000), ok);
        assert_eq!(
            sidecar_entries(Path::new("r.sfv"), &commented).len(),
            SIDECAR_MAX_LINES
        );
    }
}
