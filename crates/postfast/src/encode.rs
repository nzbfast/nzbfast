//! `[encoding]`, plane 7.D: the payload becomes articles.
//!
//! **Why this crate frames its own yEnc rather than calling
//! `nzbkit::yenc::encode`.** That function is the posting engine's
//! encoder and is right to be: it frames at a compiled-in `LINE_LEN`,
//! its trailer always carries the true CRC, its `=ybegin size` is
//! always the true total, and nothing follows the trailer. Every one of
//! those is a plane here - E1, E3, E4, E5 are exactly the cases where
//! the emitted article is NOT what an honest encoder writes - so a
//! flag on that function would be four ways for a production encoder to
//! emit a post no production caller wants. Same argument, and the same
//! shape, as the second NZB emitter in [`crate::nzb`].
//!
//! What keeps a second encoder from drifting into a second DIALECT is
//! [`tests::the_neutral_frame_is_byte_identical_to_the_engines_own`]:
//! at the neutral selection this file's output is compared
//! byte-for-byte against `nzbkit::yenc::encode` over a payload covering
//! all 256 byte values, single-part and multi-part. So the knobs are
//! deviations from the engine's own bytes, provably, rather than from
//! a second reading of the yEnc spec.
//!
//! **`article_bytes` is not a shape variant, and never was.** It is
//! the chunk size the encoder is built around rather than a variation
//! on the emitted shape: there is no "default only" version of
//! chunking, the code reads the field either way, and a multi-part
//! layout is unreachable without it (a 64 KiB test payload at the
//! default 768,000-byte article is one part, so N6's reordered indices
//! would have nothing to reorder). Keeping the payload small is the
//! catalog's own rule 4, and this is the field that lets a profile obey
//! it and still be multi-part.
//!
//! **Message-ids are `<tag-part@mock>`, and that is load-bearing.**
//! `nzbkit::mock::MockServer` is keyed on the id with its angle
//! brackets, and `nzbkit::mock::make_file_articles` (the shape every
//! existing fixture in this repo is built with) mints exactly
//! `{idtag}-{part}@mock`. Matching it mint for mint is what lets the
//! oracle hand a generated layout to the same mock the hand-written
//! fixtures use, with no translation layer to be wrong in.
//!
//! Nothing here draws from the clock or from OS entropy: the tag comes
//! from the seeded generator and the Date header is a fixed instant
//! ([`FRESH_DATE_UNIX`]), because "byte-identical from the same seed"
//! is not a property a `SystemTime::now()` anywhere in the crate can
//! have.

use std::collections::HashMap;

use crate::assemble::SourceFile;
use crate::naming::{FileNaming, GROUP, Plan};
use crate::profile::{DeclaredSize, Encoding, PartCrc, Profile, Trailing, Ypart};
use crate::rng::Rng;

/// The Date header every generated article carries, and the instant
/// `[nzb] date = "fresh"` means.
///
/// A constant rather than the clock because the determinism contract
/// (spec section 9.3) is byte-identical output from one seed, and a
/// clock read anywhere in the crate ends that. It only has to be recent
/// enough that a client reads the post as inside retention; moving it
/// is a deliberate catalog-wide change that shifts every generated
/// article, so it is worth a commit of its own. 2026-09-03T00:00:00Z,
/// the day the toolkit spec was written.
pub const FRESH_DATE_UNIX: i64 = 1_788_393_600;

/// Largest `article_bytes` a profile may ask for. The same cap the
/// posting engine applies (`nzbkit::post::ARTICLE_SIZE_CAP`): a
/// generator that admits what the poster refuses can build a layout
/// nothing in the fleet could ever post.
pub const ARTICLE_SIZE_CAP: u32 = 16 << 20;

/// One article's identity in the NZB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The part number this chunk was given. Equal to its position
    /// under N1; a shuffled index under N6.
    pub number: u32,
    /// Message-id WITHOUT angle brackets, which is what an NZB carries.
    /// The article and header maps are keyed WITH them, as the mock
    /// wants.
    pub message_id: String,
    /// Encoded (yEnc body) size in bytes, which is what the NZB's
    /// `bytes` attribute states.
    pub bytes: u64,
}

/// One encoded file: what the NZB needs, plus the poster that wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFile {
    /// The Subject the NZB carries for this file: the subject of part
    /// 1, which is what a real NZB records whatever order the segments
    /// are listed in.
    pub subject: String,
    pub poster: String,
    /// Decoded size.
    pub size: u64,
    pub parts_total: u32,
    /// Segments in EMISSION order, which is the order they appear in
    /// the NZB. Under N6 that is byte order carrying shuffled `number`
    /// attributes, so a client sorting by `number` reads the file in
    /// the wrong order and only `=ypart begin=` saves it.
    pub segments: Vec<Segment>,
}

/// Widest `line_width` a profile may ask for.
///
/// E1's vocabulary is "128 / 256 / non-standard", so the range has to
/// admit an unusual width without admitting a nonsensical one. The
/// ceiling is the 998-octet line limit of RFC 5322 section 2.1.1, which
/// NNTP inherits: past it the article is not a line-oriented message
/// any more, and a generator that emitted one would be testing the
/// client's tolerance for a shape no server would carry. The floor is
/// 1, which is legal and produces one byte per line - deliberately
/// admitted, because "the framing is wrong in a direction nobody
/// expected" is what E1 is for.
pub const LINE_WIDTH_MAX: u32 = 998;

/// Why a payload could not be encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// `article_bytes` outside `1..=ARTICLE_SIZE_CAP`.
    ArticleSize(u32),
    /// `line_width` outside `1..=LINE_WIDTH_MAX`.
    LineWidth(u32),
    /// E2's absent-`=ypart` arm asked for over a file that is more than
    /// one part. The single-part yEnc form has no `part=`, no `total=`
    /// and no `=ypart`, so there is nowhere to say which part this is:
    /// emitting it over a multi-part file would post a set of articles
    /// that each claim to be the whole file.
    YpartAbsentOnMultipart { file: String, parts: u32 },
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArticleSize(n) => write!(
                f,
                "[encoding] article_bytes = {n} is outside 1..={ARTICLE_SIZE_CAP}, which is \
                 the range the posting engine itself accepts"
            ),
            Self::LineWidth(n) => write!(
                f,
                "[encoding] line_width = {n} is outside 1..={LINE_WIDTH_MAX}: past the \
                 RFC 5322 line limit the article stops being a line-oriented message, and \
                 no server would carry it"
            ),
            Self::YpartAbsentOnMultipart { file, parts } => write!(
                f,
                "[encoding] ypart = \"absent\" over {file}, which is {parts} parts: the \
                 single-part yEnc form carries no part number at all, so every article \
                 would claim to be the whole file. Raise article_bytes until the file is \
                 one part, or select ypart = \"present\""
            ),
        }
    }
}

/// The article maps a layout hands the mock server.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Articles {
    /// `<message-id>` to yEnc body, exactly the map
    /// `nzbkit::mock::MockServer::start` takes.
    pub bodies: HashMap<String, Vec<u8>>,
    /// `<message-id>` to the article's header block, for the mock's
    /// HEAD plane. Faithful to the bodies by construction: both are
    /// written in the same loop from the same subject and poster.
    pub headers: HashMap<String, Vec<u8>>,
}

/// Encode every source file into articles under a naming plan.
///
/// Draw order, continuing the determinism contract: the poisoned part
/// (E3's `wrong` arm) FIRST, drawn once and only when that arm is
/// selected, then for each file in source order the message-id tag and
/// (only under N6) the part permutation. A draw that happens only for
/// the profiles that ask for it is what keeps every layout written
/// before this plane existed byte-identical to what it was.
///
/// `payload_files` is how many of `sources` are payload rather than
/// recovery. **A generation-time lie is told about the payload and
/// never about the set that has to describe it.** E4's misstated total
/// applied to a `.par2` makes the index arrive as its real bytes
/// followed by a hole - a damaged recovery set, which is the fault
/// plane's F4 - so the row that meant to ask "is the declared total
/// trusted?" would instead have been asking whether a broken set still
/// verifies. Same rule, same sentence, as Z4's in [`crate::nzb`].
pub fn encode(
    profile: &Profile,
    sources: &[SourceFile],
    plan: &Plan,
    payload_files: usize,
    rng: &mut Rng,
) -> Result<(Vec<EncodedFile>, Articles), EncodeError> {
    let e = &profile.encoding;
    let art = e.article_bytes;
    if art == 0 || art > ARTICLE_SIZE_CAP {
        return Err(EncodeError::ArticleSize(art));
    }
    if e.line_width == 0 || e.line_width > LINE_WIDTH_MAX {
        return Err(EncodeError::LineWidth(e.line_width));
    }
    // E3 `wrong`: which ONE article carries a CRC that does not match
    // its bytes.
    //
    // ONE, and always in the first file, and that is a decision rather
    // than a convenience. A post whose every part carried a bad CRC is
    // a post no client could ever complete, so the only end state the
    // oracle could grade for it is "nothing arrived" - which is not
    // what E3 asks. E3 asks whether the client TRUSTS a CRC, and the
    // sharp form of that question is one poisoned article inside an
    // otherwise healthy post: a client that checks refuses that
    // article and needs the recovery set, and a client that does not
    // check writes corrupt bytes and completes green. The first file is
    // always payload - `crate::layout::generate` appends the recovery
    // files last - so the poison can never land on the set that has to
    // heal it. `payload_files >= 1` is guaranteed one stage earlier -
    // the recovery plane refuses a post whose every member is a 0-byte
    // placeholder, because it would carry no articles at all - so there
    // is always a payload file for the poison and for E4's lie to land
    // on. Pinned by `a_post_with_no_payload_file_at_all_is_refused_
    // upstream` below, so relaxing that refusal reddens here.
    let poisoned = match e.part_crc {
        PartCrc::Wrong => {
            let parts = sources
                .first()
                .map_or(1, |s| s.bytes.len().div_ceil(art as usize).max(1));
            Some(rng.below(parts as u64) as usize)
        }
        _ => None,
    };
    let files_total = sources.len() as u32;
    let mut out = Vec::with_capacity(sources.len());
    let mut articles = Articles::default();
    for (i, (src, nm)) in sources.iter().zip(&plan.files).enumerate() {
        let tag = rng.token();
        let numbers = part_numbers(src.bytes.len(), art as usize, plan.reorder_parts, rng);
        if e.ypart == Ypart::Absent && numbers.len() > 1 {
            return Err(EncodeError::YpartAbsentOnMultipart {
                file: src.rel.clone(),
                parts: numbers.len() as u32,
            });
        }
        out.push(encode_file(
            src,
            nm,
            plan.title.as_deref(),
            i as u32 + 1,
            files_total,
            e,
            &tag,
            &numbers,
            if i == 0 { poisoned } else { None },
            i < payload_files,
            &mut articles,
        ));
    }
    Ok((out, articles))
}

/// What `=ybegin size=` states, against the real total (E4).
///
/// `Fixture::add_file_declaring` in `crates/nzbfast/tests/e2e.rs` is
/// the shape both arms follow: the PART is self-consistent - its
/// `=ypart begin=`/`end=` range is true, its trailer's `size=` is the
/// real chunk length and its CRC is the real CRC - and only the
/// file-level total lies. That separates the question ("is the declared
/// total trusted?") from a corrupt article, which is a different plane.
///
/// `long` is the arm with teeth: the writer is sized from this untrusted
/// total, so a post declaring more than it ships used to retire every
/// counter and complete GREEN with a hole in the file (Codex sweep
/// 3 Aug M7). `short` is the opposite lie and is the control: the bytes
/// that arrive exceed the declaration, and a client sized from it must
/// not truncate them.
fn declared_total(real: u64, sel: DeclaredSize) -> u64 {
    match sel {
        DeclaredSize::True => real,
        // Halved rather than a fixed number, so the lie scales with the
        // profile's payload and stays a lie for every size.
        DeclaredSize::Short => (real / 2).max(1),
        DeclaredSize::Long => real.saturating_mul(2).max(1),
    }
}

/// The part number each chunk is given, in chunk (byte) order.
///
/// N1 is the identity. N6 is a seeded Fisher-Yates shuffle of it, which
/// is a LEGAL post and not a corrupt one: `=ypart begin=`/`end=` stay
/// truthful, and that is the field a decoder must place bytes from -
/// `nzbkit::yenc` says so at its own `Decoded::offset`. So a shuffled
/// `part=` is exactly the segment-map robustness the row asks for, and
/// a decoder that reconstructs offsets from the part index instead
/// writes the file in the wrong order. Lying about `begin=` would be a
/// different thing entirely: a broken post, not a layout.
fn part_numbers(len: usize, art: usize, reorder: bool, rng: &mut Rng) -> Vec<u32> {
    let total = len.div_ceil(art).max(1) as u32;
    let mut n: Vec<u32> = (1..=total).collect();
    if reorder {
        // Fisher-Yates from the seeded stream, so the permutation is
        // part of the reproducible layout like every other choice.
        for i in (1..n.len()).rev() {
            let j = rng.below(i as u64 + 1) as usize;
            n.swap(i, j);
        }
    }
    n
}

/// Encode one file's articles and record them in `articles`.
///
/// `poisoned` is the CHUNK index whose trailer carries a CRC that does
/// not match its bytes (E3 `wrong`), or `None`. Chunk index rather than
/// part number, because under N6 the part numbers are shuffled and the
/// fault has to land on a definite article either way.
#[allow(clippy::too_many_arguments)]
fn encode_file(
    src: &SourceFile,
    nm: &FileNaming,
    title: Option<&str>,
    file_index: u32,
    files_total: u32,
    enc: &Encoding,
    tag: &str,
    numbers: &[u32],
    poisoned: Option<usize>,
    is_payload: bool,
    articles: &mut Articles,
) -> EncodedFile {
    let art = enc.article_bytes as usize;
    let size = src.bytes.len() as u64;
    let declared = if is_payload {
        declared_total(size, enc.declared_size)
    } else {
        size
    };
    let total = numbers.len() as u32;
    let mut segments = Vec::with_capacity(numbers.len());
    let mut part_one_subject = String::new();
    // A 0-byte file is still ONE article on the wire: a lone
    // `=ybegin size=0` part, the placeholder shape posters who ship
    // empties produce. `chunks` over an empty slice yields nothing, so
    // the empty case is spelled out rather than falling out of the
    // loop, exactly as `nzbkit::mock::make_file_articles` spells it.
    let chunks: Vec<&[u8]> = if src.bytes.is_empty() {
        vec![&[]]
    } else {
        src.bytes.chunks(art).collect()
    };
    for (i, chunk) in chunks.iter().enumerate() {
        let number = numbers[i];
        let begin = (i * art) as u64 + 1;
        let body = frame(
            &Frame {
                name: &nm.yenc,
                declared,
                part: match enc.ypart {
                    Ypart::Present => Some((number, total)),
                    Ypart::Absent => None,
                },
                begin,
                width: enc.line_width as usize,
                crc: enc.part_crc,
                trailing: enc.trailing,
                bad_crc: poisoned == Some(i),
            },
            chunk,
        );
        let id = format!("{tag}-{number}@mock");
        let subject = subject(nm, title, file_index, files_total, number, total);
        if number == 1 {
            part_one_subject = subject.clone();
        }
        articles.headers.insert(
            format!("<{id}>"),
            header_block(&nm.poster, &subject, &id, FRESH_DATE_UNIX),
        );
        segments.push(Segment {
            number,
            message_id: id.clone(),
            bytes: body.len() as u64,
        });
        articles.bodies.insert(format!("<{id}>"), body);
    }
    EncodedFile {
        subject: part_one_subject,
        poster: nm.poster.clone(),
        size,
        parts_total: total,
        segments,
    }
}

/// One article's framing, as the encoding plane asks for it.
struct Frame<'a> {
    /// The `name=` on the `=ybegin` line.
    name: &'a str,
    /// What `size=` states. The real total under E4's neutral arm.
    declared: u64,
    /// `Some((part, total))` writes the multi-part form; `None` writes
    /// the single-part form, which has no part number and no `=ypart`.
    part: Option<(u32, u32)>,
    /// 1-based inclusive offset of this chunk in the file.
    begin: u64,
    /// E1: bytes per encoded line, and the `line=` field's value.
    width: usize,
    /// E3.
    crc: PartCrc,
    /// E5.
    trailing: Trailing,
    /// True on the one article E3's `wrong` arm poisons.
    bad_crc: bool,
}

/// Write one yEnc article.
///
/// At the neutral selection this is `nzbkit::yenc::encode` byte for
/// byte, and a test asserts exactly that - see the module header for
/// why the two exist rather than one taking four flags.
fn frame(f: &Frame<'_>, data: &[u8]) -> Vec<u8> {
    let real_crc = crc32fast::hash(data);
    // A CRC that is present and does not describe these bytes. XOR with
    // all-ones rather than a random draw: it can never accidentally
    // equal the real CRC, which a draw could, and a row whose fault
    // silently was not a fault is the failure this crate refuses
    // everywhere else.
    let crc = if f.bad_crc { !real_crc } else { real_crc };
    let width = f.width.max(1);
    let mut out = Vec::with_capacity(data.len() + data.len() / 32 + 256);
    let name = f.name;
    let size = f.declared;
    match f.part {
        Some((p, total)) => {
            out.extend_from_slice(
                format!("=ybegin part={p} total={total} line={width} size={size} name={name}\r\n")
                    .as_bytes(),
            );
            let end = f.begin + data.len() as u64 - 1;
            out.extend_from_slice(format!("=ypart begin={} end={end}\r\n", f.begin).as_bytes());
        }
        None => {
            out.extend_from_slice(
                format!("=ybegin line={width} size={size} name={name}\r\n").as_bytes(),
            );
        }
    }
    encode_body(&mut out, data, width);
    // The trailer's `size=` is this CHUNK's length and stays true under
    // every selection: E4 is a lie about the FILE's total, and a lie
    // about the part as well would be a truncated article, which is the
    // fault plane rather than this one.
    let mut trailer = format!("=yend size={}", data.len());
    if let Some((p, _)) = f.part {
        trailer.push_str(&format!(" part={p}"));
    }
    match (f.crc, f.part.is_some()) {
        // E3 `absent`: no CRC field at all, which leaves the article
        // decodable and UNVERIFIED - `decode_checked` reports
        // `crc_checked = false` and the bytes are treated as untrusted
        // downstream. That is a real posting shape, not a corrupt one.
        (PartCrc::Absent, _) => {}
        // The field is named for the form: `pcrc32` describes a part,
        // `crc32` describes a whole file. Writing `pcrc32` on a
        // single-part article would be the one shape `trailer_gates`
        // cannot read as fatal, so the two forms keep their own field.
        (_, true) => trailer.push_str(&format!(" pcrc32={crc:08x}")),
        (_, false) => trailer.push_str(&format!(" crc32={crc:08x}")),
    }
    trailer.push_str("\r\n");
    out.extend_from_slice(trailer.as_bytes());
    match f.trailing {
        Trailing::None => {}
        // Plain text after the trailer. Two lines, because one could be
        // read as a stray CRLF rather than as content.
        Trailing::Signature => {
            out.extend_from_slice(b"posted with a tool that signs its work\r\n");
            out.extend_from_slice(b"alt.binaries.test\r\n");
        }
        // A second complete copy of the block, appended with no
        // separator: M4-84's own shape. A decoder that does not stop at
        // the first `=yend` writes the payload twice.
        Trailing::Article => {
            let again = out.clone();
            out.extend_from_slice(&again);
        }
    }
    out
}

/// The yEnc body: every byte offset by 42, the five critical values
/// escaped, wrapped at `width`.
///
/// Lifted from `nzbkit::yenc::encode` with `LINE_LEN` made a parameter
/// and nothing else changed, which is what makes the byte-identity test
/// in this file provable rather than approximate.
fn encode_body(out: &mut Vec<u8>, data: &[u8], width: usize) {
    let mut col = 0usize;
    for &b in data {
        let enc = b.wrapping_add(42);
        let critical = matches!(enc, 0x00 | 0x0A | 0x0D | b'=') || (col == 0 && enc == b'.');
        if critical {
            out.push(b'=');
            out.push(enc.wrapping_add(64));
            col += 2;
        } else {
            out.push(enc);
            col += 1;
        }
        if col >= width {
            out.extend_from_slice(b"\r\n");
            col = 0;
        }
    }
    if col > 0 {
        out.extend_from_slice(b"\r\n");
    }
}

/// The Subject for one article.
///
/// Descriptive is `nzbkit::post::subject_for`, verbatim, because the
/// quoted-filename convention is the one every downloader in the world
/// parses and a second spelling of it here would be a second thing to
/// keep right. Neutral (N5) is furniture: a per-file token and the part
/// counter, with no name and nothing that ties this file to the next.
/// The counter stays because a subject with no part number is a
/// different plane (a header shape no poster emits), not a more neutral
/// one.
fn subject(
    nm: &FileNaming,
    title: Option<&str>,
    file_index: u32,
    files_total: u32,
    part: u32,
    parts_total: u32,
) -> String {
    match &nm.subject_token {
        Some(t) => format!("{t} ({part}/{parts_total})"),
        None => nzbkit::post::subject_for(
            title,
            &nm.posted,
            file_index,
            files_total,
            part,
            parts_total,
        ),
    }
}

/// The header block the mock's HEAD plane serves: the same five headers
/// `nzbkit::post::build_wire_article` writes in front of a body, in the
/// same order, CRLF-framed and with control bytes neutralised so no
/// value can split or smuggle a header line.
fn header_block(poster: &str, subject: &str, message_id: &str, date_unix: i64) -> Vec<u8> {
    let date = nzbkit::post::rfc5322_date(date_unix);
    let mut out = Vec::with_capacity(subject.len() + 256);
    for (k, v) in [
        ("From", poster),
        ("Newsgroups", GROUP),
        ("Subject", subject),
        ("Message-ID", &format!("<{message_id}>") as &str),
        ("Date", &date),
    ] {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        let safe: String = v
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        out.extend_from_slice(safe.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assemble::sources as assemble;
    use crate::naming::plan as naming_plan;

    fn run(extra: &str, files: &str) -> Result<(Vec<EncodedFile>, Articles), EncodeError> {
        let text =
            format!("[layout]\nname = \"t\"\nseed = 1\n\n[source]\nfiles = [{files}]\n\n{extra}");
        let p = Profile::parse(&text).expect("test profile parses");
        let mut rng = Rng::for_profile(&p);
        let s = assemble(&p, &mut rng).expect("sources assemble");
        let plan = naming_plan(&p, &s, &mut rng).expect("naming plans");
        let n = s.len();
        encode(&p, &s, &plan, n, &mut rng)
    }

    const SMALL: &str = "[encoding]\narticle_bytes = 1024\n";
    const ONE: &str = "{ name = \"a.bin\", bytes = 4096 }";

    /// The headline property: every article decodes back to the bytes
    /// it was made from, at the offset it claims.
    #[test]
    fn every_article_decodes_back_to_its_source_bytes() {
        let p = Profile::parse(&format!(
            "[layout]\nname = \"t\"\nseed = 1\n\n[source]\nfiles = [{ONE}]\n\n{SMALL}"
        ))
        .unwrap();
        let mut rng = Rng::for_profile(&p);
        let s = assemble(&p, &mut rng).unwrap();
        let plan = naming_plan(&p, &s, &mut rng).unwrap();
        let (files, arts) = encode(&p, &s, &plan, s.len(), &mut rng).unwrap();
        assert_eq!(files[0].parts_total, 4);
        let mut rebuilt = vec![0u8; s[0].bytes.len()];
        for seg in &files[0].segments {
            let body = &arts.bodies[&format!("<{}>", seg.message_id)];
            let d = nzbkit::yenc::decode(body).expect("article decodes");
            let at = d.offset() as usize;
            rebuilt[at..at + d.data.len()].copy_from_slice(&d.data);
        }
        assert_eq!(rebuilt, s[0].bytes);
    }

    /// Message-ids are minted exactly as `make_file_articles` mints
    /// them, which is what makes a generated layout servable by the
    /// same mock the hand-written fixtures use.
    #[test]
    fn message_ids_match_the_mocks_own_shape() {
        let (files, arts) = run(SMALL, ONE).unwrap();
        for seg in &files[0].segments {
            let (tag, part) = seg.message_id.split_once('-').expect("tag-part@mock");
            assert_eq!(tag.len(), 24);
            assert_eq!(part, format!("{}@mock", seg.number));
            assert!(arts.bodies.contains_key(&format!("<{}>", seg.message_id)));
            assert!(arts.headers.contains_key(&format!("<{}>", seg.message_id)));
        }
    }

    /// N6: the part numbers are a permutation, the byte ranges stay
    /// truthful, and the file still reassembles. A shuffle that broke
    /// `begin=` would be a corrupt post rather than a layout.
    #[test]
    fn n6_shuffles_part_numbers_and_keeps_the_byte_ranges_truthful() {
        let p = Profile::parse(&format!(
            "[layout]\nname = \"t\"\nseed = 4\n\n[source]\nfiles = [{ONE}]\n\n\
             [naming]\npart_order = \"reordered\"\n\n{SMALL}"
        ))
        .unwrap();
        let mut rng = Rng::for_profile(&p);
        let s = assemble(&p, &mut rng).unwrap();
        let plan = naming_plan(&p, &s, &mut rng).unwrap();
        let (files, arts) = encode(&p, &s, &plan, s.len(), &mut rng).unwrap();
        let numbers: Vec<u32> = files[0].segments.iter().map(|s| s.number).collect();
        let mut sorted = numbers.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![1, 2, 3, 4], "still a permutation");
        assert_ne!(numbers, sorted, "seed 4 actually shuffles");
        // Segments are listed in BYTE order, so the numbers a client
        // reads out of the NZB are out of order, and only `=ypart` says
        // where the bytes go.
        let mut rebuilt = vec![0u8; s[0].bytes.len()];
        for (i, seg) in files[0].segments.iter().enumerate() {
            let d = nzbkit::yenc::decode(&arts.bodies[&format!("<{}>", seg.message_id)]).unwrap();
            assert_eq!(d.offset() as usize, i * 1024);
            let at = d.offset() as usize;
            rebuilt[at..at + d.data.len()].copy_from_slice(&d.data);
        }
        assert_eq!(rebuilt, s[0].bytes);
    }

    /// A 0-byte file posts as one empty part rather than as no
    /// segments, which would make the NZB lie about a file it lists.
    #[test]
    fn a_zero_byte_file_posts_as_one_empty_part() {
        let (files, arts) = run(SMALL, "{ name = \"e.bin\", bytes = 0 }").unwrap();
        assert_eq!(files[0].segments.len(), 1);
        assert_eq!(files[0].parts_total, 1);
        let body = &arts.bodies[&format!("<{}>", files[0].segments[0].message_id)];
        assert!(nzbkit::yenc::decode(body).unwrap().data.is_empty());
    }

    /// The NZB's subject is part 1's, whatever order the segments are
    /// listed in.
    #[test]
    fn the_nzb_subject_is_part_ones() {
        let (files, _) = run(SMALL, ONE).unwrap();
        assert_eq!(files[0].subject, "\"a.bin\" yEnc (1/4)");
    }

    /// N5 subjects carry no name and no cross-file linkage, and still
    /// carry the part counter.
    #[test]
    fn a_neutral_subject_carries_furniture_only() {
        let (files, _) = run(
            "[naming]\nsubject = \"neutral\"\n\n[encoding]\narticle_bytes = 1024\n",
            ONE,
        )
        .unwrap();
        assert!(!files[0].subject.contains("a.bin"));
        assert!(files[0].subject.ends_with(" (1/4)"));
    }

    /// The header plane is faithful to the bodies: the same subject,
    /// the same poster, the same id, CRLF-framed.
    #[test]
    fn headers_agree_with_the_articles_they_describe() {
        let (files, arts) = run(SMALL, ONE).unwrap();
        let seg = &files[0].segments[0];
        let h = String::from_utf8(arts.headers[&format!("<{}>", seg.message_id)].clone()).unwrap();
        assert!(h.contains(&format!("Message-ID: <{}>\r\n", seg.message_id)));
        assert!(h.contains(&format!("Subject: {}\r\n", files[0].subject)));
        assert!(h.contains(&format!("From: {}\r\n", files[0].poster)));
        assert!(h.contains(&format!("Newsgroups: {GROUP}\r\n")));
        assert!(h.contains("Date: Thu, 03 Sep 2026 00:00:00 +0000\r\n"));
    }

    /// The pairing that makes a second encoder safe: at the neutral
    /// selection this file writes exactly what the engine's own encoder
    /// writes, over a payload covering all 256 byte values (so every
    /// escape rule is reached) in both the single-part and multi-part
    /// forms. Any divergence - a field, an order, a line ending, a
    /// `size=` - fails here rather than in a client months later.
    #[test]
    fn the_neutral_frame_is_byte_identical_to_the_engines_own() {
        let data: Vec<u8> = (0..4096).map(|i| (i * 7 + i / 251) as u8).collect();
        let neutral = |part, begin, chunk: &[u8], declared| {
            frame(
                &Frame {
                    name: "movie.mkv",
                    declared,
                    part,
                    begin,
                    width: 128,
                    crc: PartCrc::Present,
                    trailing: Trailing::None,
                    bad_crc: false,
                },
                chunk,
            )
        };
        // Single-part form, and the empty article a 0-byte file posts.
        for d in [&data[..], &[]] {
            assert_eq!(
                neutral(None, 1, d, d.len() as u64),
                nzbkit::yenc::encode("movie.mkv", d.len() as u64, None, 1, d),
                "the single-part frame must be the engine's own bytes"
            );
        }
        // Multi-part form, every chunk, at a size that leaves a short
        // final part and crosses a line boundary mid-escape.
        let art = 1000;
        let chunks: Vec<&[u8]> = data.chunks(art).collect();
        for (i, c) in chunks.iter().enumerate() {
            let begin = (i * art) as u64 + 1;
            let part = Some((i as u32 + 1, chunks.len() as u32));
            assert_eq!(
                neutral(part, begin, c, data.len() as u64),
                nzbkit::yenc::encode("movie.mkv", data.len() as u64, part, begin, c),
                "part {} must be the engine's own bytes",
                i + 1
            );
        }
    }

    /// E1: a non-default width frames at that width, states it in
    /// `line=`, and still decodes to the same bytes. 256 is the other
    /// standard width and 91 is a width no tool uses, which is the
    /// point of the third arm.
    #[test]
    fn e1_a_non_default_line_width_frames_and_decodes() {
        for width in [64u32, 91, 256, 998] {
            let (files, arts) = run(
                &format!("[encoding]\narticle_bytes = 1024\nline_width = {width}\n"),
                ONE,
            )
            .expect("a legal width encodes");
            let body = &arts.bodies[&format!("<{}>", files[0].segments[0].message_id)];
            let text = String::from_utf8_lossy(body);
            assert!(
                text.starts_with(&format!("=ybegin part=1 total=4 line={width} ")),
                "the header must state the width it framed at: {}",
                &text[..40.min(text.len())]
            );
            // Every payload line is at most `width` bytes. The escape
            // can push a line one over, exactly as the engine's own
            // encoder does, so the bound is width + 1. Measured on the
            // RAW bytes: a yEnc body is not UTF-8, and a lossy string's
            // `len()` counts three bytes for every high byte it could
            // not decode, which would make this assertion measure the
            // wrong thing at every width.
            for line in body.split(|&b| b == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if line.starts_with(b"=y") || line.is_empty() {
                    continue;
                }
                assert!(
                    line.len() <= width as usize + 1,
                    "a payload line of {} exceeds width {width}",
                    line.len()
                );
            }
            let d = nzbkit::yenc::decode(body).expect("the client decodes it");
            assert_eq!(d.data.len(), 1024);
        }
    }

    /// E1: a width outside the RFC 5322 line limit is refused with its
    /// own number, rather than emitting an article no server carries.
    #[test]
    fn e1_an_impossible_line_width_is_refused() {
        assert_eq!(
            run("[encoding]\nline_width = 0\n", ONE),
            Err(EncodeError::LineWidth(0))
        );
        let big = LINE_WIDTH_MAX + 1;
        assert_eq!(
            run(&format!("[encoding]\nline_width = {big}\n"), ONE),
            Err(EncodeError::LineWidth(big))
        );
    }

    /// E2: the single-part form carries no part number anywhere and a
    /// `crc32=` rather than a `pcrc32=`, and the client reads the same
    /// file out of it.
    #[test]
    fn e2_a_single_part_file_can_be_posted_without_ypart() {
        let (files, arts) = run(
            "[encoding]\narticle_bytes = 8192\nypart = \"absent\"\n",
            ONE,
        )
        .expect("one part encodes without =ypart");
        assert_eq!(files[0].parts_total, 1);
        let body = &arts.bodies[&format!("<{}>", files[0].segments[0].message_id)];
        let text = String::from_utf8_lossy(body);
        assert!(!text.contains("=ypart"), "the single-part form has none");
        assert!(!text.contains("part="), "and no part number anywhere");
        assert!(text.contains(" crc32="), "a whole-file CRC, not a part one");
        let d = nzbkit::yenc::decode(body).expect("the client decodes it");
        assert_eq!(d.offset(), 0);
        assert_eq!(d.data.len(), 4096);
    }

    /// E2: and the same selection over a file that is more than one
    /// part is refused by name, because every article would claim to be
    /// the whole file.
    #[test]
    fn e2_ypart_absent_over_a_multipart_file_is_refused() {
        assert_eq!(
            run(
                "[encoding]\narticle_bytes = 1024\nypart = \"absent\"\n",
                ONE
            ),
            Err(EncodeError::YpartAbsentOnMultipart {
                file: "a.bin".into(),
                parts: 4,
            })
        );
    }

    /// E3 `absent`: no CRC field at all. The article still decodes, and
    /// `decode_checked` reports it as UNVERIFIED rather than verified -
    /// which is the honest answer and the whole content of the row.
    #[test]
    fn e3_an_absent_part_crc_decodes_unverified() {
        let (files, arts) = run(
            "[encoding]\narticle_bytes = 1024\npart_crc = \"absent\"\n",
            ONE,
        )
        .expect("an absent CRC encodes");
        for seg in &files[0].segments {
            let body = &arts.bodies[&format!("<{}>", seg.message_id)];
            assert!(!String::from_utf8_lossy(body).contains("crc32="));
            let (d, checked) = nzbkit::yenc::decode_checked(body).expect("it decodes");
            assert!(!checked, "an article with no CRC cannot be verified");
            assert_eq!(d.data.len(), 1024);
        }
    }

    /// E3 `wrong`: exactly ONE article of the FIRST file carries a CRC
    /// that does not match its bytes, the client refuses that article
    /// by name, and every other article is untouched. Both halves
    /// matter: a poisoned post is only a row about CRC trust if the
    /// rest of it is healthy.
    #[test]
    fn e3_a_wrong_part_crc_poisons_exactly_one_article() {
        let (files, arts) = run(
            "[encoding]\narticle_bytes = 1024\npart_crc = \"wrong\"\n",
            "{ name = \"a.bin\", bytes = 4096 }, { name = \"b.bin\", bytes = 2048 }",
        )
        .expect("a wrong CRC encodes");
        let mut refused = 0;
        for (i, f) in files.iter().enumerate() {
            for seg in &f.segments {
                let body = &arts.bodies[&format!("<{}>", seg.message_id)];
                match nzbkit::yenc::decode(body) {
                    Ok(_) => {}
                    Err(nzbkit::yenc::YencError::CrcMismatch { .. }) => {
                        assert_eq!(i, 0, "the poison may only land on the first file");
                        refused += 1;
                    }
                    Err(e) => panic!("unexpected refusal: {e}"),
                }
            }
        }
        assert_eq!(refused, 1, "exactly one article, never zero and never all");
    }

    /// E4: the declared TOTAL lies while every part stays
    /// self-consistent, which is `Fixture::add_file_declaring`'s shape.
    /// Both arms keep the part's own range, length and CRC true, so a
    /// client that refuses the article has refused it for the total and
    /// not for a corruption.
    #[test]
    fn e4_a_lying_total_leaves_every_part_self_consistent() {
        for (sel, want) in [("short", 2048u64), ("long", 8192)] {
            let (files, arts) = run(
                &format!("[encoding]\narticle_bytes = 1024\ndeclared_size = \"{sel}\"\n"),
                ONE,
            )
            .expect("a lying total encodes");
            assert_eq!(files[0].size, 4096, "the real size is unchanged");
            for (i, seg) in files[0].segments.iter().enumerate() {
                let body = &arts.bodies[&format!("<{}>", seg.message_id)];
                let text = String::from_utf8_lossy(body);
                assert!(
                    text.contains(&format!(" size={want} name=")),
                    "=ybegin must state the lie"
                );
                assert!(
                    text.contains("=yend size=1024 "),
                    "the trailer states the real PART length"
                );
                let (d, checked) =
                    nzbkit::yenc::decode_checked(body).expect("a self-consistent part decodes");
                assert!(checked, "its own CRC still verifies");
                assert_eq!(d.offset() as usize, i * 1024);
                assert_eq!(d.file_size, want, "the client reads the declared total");
            }
        }
    }

    /// E5: whatever follows the `=yend` trailer, the article decodes to
    /// the bytes it was made from and to nothing more. M4-84 by name:
    /// before that rule a second concatenated block silently doubled
    /// the slot, and the `article` arm is that exact shape.
    #[test]
    fn e5_nothing_after_the_trailer_reaches_the_payload() {
        let clean = run(SMALL, ONE).unwrap();
        for sel in ["signature", "article"] {
            let (files, arts) = run(
                &format!("[encoding]\narticle_bytes = 1024\ntrailing = \"{sel}\"\n"),
                ONE,
            )
            .expect("a trailing tail encodes");
            for (seg, base) in files[0].segments.iter().zip(&clean.0[0].segments) {
                let body = &arts.bodies[&format!("<{}>", seg.message_id)];
                let plain = &clean.1.bodies[&format!("<{}>", base.message_id)];
                assert!(body.len() > plain.len(), "{sel} really appended something");
                let (d, checked) = nzbkit::yenc::decode_checked(body).expect("it decodes");
                assert!(
                    checked,
                    "the trailer's own CRC is still the one that counts"
                );
                assert_eq!(
                    d.data,
                    nzbkit::yenc::decode(plain).unwrap().data,
                    "{sel} must not change one byte of the payload"
                );
            }
        }
    }

    /// The invariant the payload-scoped selections rest on, asserted
    /// where it can be seen rather than assumed: a post whose every
    /// source is a described-but-unposted member is refused UPSTREAM,
    /// by the recovery plane, so `payload_files` is never 0 by the time
    /// the encoder reads it and "the lie is told about the payload"
    /// never degenerates into "the lie is told about the set". If that
    /// refusal is ever relaxed, this test goes red and the two
    /// payload-scoped arms need a guard of their own.
    #[test]
    fn a_post_with_no_payload_file_at_all_is_refused_upstream() {
        let p = Profile::parse(
            "[layout]\nname = \"t\"\nseed = 1\n\n[source]\n\
             files = [{ name = \"Empty.One.bup\", bytes = 0 }]\n\n\
             [recovery]\nkind = \"par2\"\nredundancy_pct = 20\n\
             zero_byte_member = true\n",
        )
        .expect("profile parses");
        assert!(matches!(
            crate::layout::generate(&p),
            Err(crate::layout::GenError::Recovery(_))
        ));
    }

    /// E6: the article size is the parameter, and it is what decides
    /// how many articles a payload becomes.
    #[test]
    fn e6_the_article_size_decides_the_part_count() {
        for (art, parts) in [(512u32, 8u32), (1024, 4), (4096, 1), (65536, 1)] {
            let (files, _) = run(&format!("[encoding]\narticle_bytes = {art}\n"), ONE).unwrap();
            assert_eq!(files[0].parts_total, parts, "at article_bytes = {art}");
        }
    }

    /// A zero or absurd article size is refused with its own number in
    /// the message.
    #[test]
    fn an_impossible_article_size_is_refused() {
        assert_eq!(
            run("[encoding]\narticle_bytes = 0\n", ONE),
            Err(EncodeError::ArticleSize(0))
        );
        let big = ARTICLE_SIZE_CAP + 1;
        assert_eq!(
            run(&format!("[encoding]\narticle_bytes = {big}\n"), ONE),
            Err(EncodeError::ArticleSize(big))
        );
    }
}
