//! Reference yEnc codec (scalar).
//!
//! This is the *correctness oracle*: simple, obviously-right code used for
//! tests and as the differential baseline when the rapidyenc SIMD path lands.
//! It is fast enough for prototyping (~hundreds of MB/s) but the production
//! decode path will be rapidyenc via FFI.
//!
//! yEnc in one paragraph: every payload byte is `(b + 42) mod 256`; the
//! critical output bytes NUL, LF, CR and `=` are escaped as `=` followed by
//! `(b + 64) mod 256`. Articles carry `=ybegin` / `=ypart` / `=yend` header
//! lines with sizes, part byte-ranges (1-based inclusive) and CRC32s. On the
//! wire, NNTP dot-stuffs lines starting with `.` (doubles the dot); we undo
//! that by stripping exactly one leading dot from any line that starts with
//! one, which is what the production SIMD path does too.

use std::collections::HashMap;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum YencError {
    #[error("no =ybegin header found")]
    MissingBegin,
    #[error("=yend size {actual} does not match decoded length {expected}")]
    LengthMismatch { expected: u64, actual: u64 },
    #[error("CRC32 mismatch: decoded {computed:08x}, header says {header:08x}")]
    CrcMismatch { computed: u32, header: u32 },
    #[error("article ended without a =yend trailer (truncated)")]
    Truncated,
    #[error("=ypart begin={begin} end={end} cannot hold {len} decoded bytes")]
    PartGeometry { begin: u64, end: u64, len: u64 },
    /// `=ybegin part=` and `=yend part=` disagree about which part this is.
    /// Found by the round-4 torture set advZA (TODO 159): the article decoded
    /// and placed correctly, because placement comes from `=ypart` alone, so
    /// nothing detected that the two part numbers contradicted each other. A
    /// post where BOTH were wrong would then be indistinguishable from a
    /// healthy one. Cheap to check, and an inconsistent trailer is evidence
    /// the article is not what it claims to be.
    #[error("=ybegin part={begin} but =yend part={end} - inconsistent trailer")]
    PartNumberMismatch { begin: u32, end: u32 },
    /// A second `=ybegin` line in one article body. Found by the wave-4
    /// matrix read (M4-63, 30 Aug 2026): every `=ybegin ` line was taken
    /// as a header, so the LAST one won and silently overwrote `name`,
    /// `size`, `part` and the single-part `end` the first had declared. A
    /// truthful first header followed by a lying second (`size=4
    /// name=x.bin`) made the article declare a 4-byte file under a decoy
    /// name, which is W4-11's under-declare produced inside ONE article.
    ///
    /// Refused rather than resolved first-wins, for the reason
    /// [`Self::PartNumberMismatch`] above is refused: a body carrying two
    /// headers is not what it claims to be, and the bytes on either side
    /// of the second header belong to two different declarations, so
    /// ignoring the second would concatenate two payloads under the
    /// first name and place them at the first offset. Per the wave-4
    /// family rule (`2b7f5495e`), a weaker or later clue may nominate but
    /// never overwrite: neither header here outranks the other, so the
    /// article carries no usable identity and PAR2 repairs it - which is
    /// the honest price, and the same one a dropped article already pays.
    #[error("a second =ybegin header in one article - contradictory declaration")]
    DuplicateBegin,
    /// A recognised `=yencryption ` control line (spike flag ON) whose
    /// fields will not parse: unknown cipher, or a salt/tag that is not
    /// 32 hex chars. Refused rather than skipped, because skipping the
    /// line hands ciphertext to the verifier as if it were plaintext.
    /// Only reachable under `NZBFAST_YENC_CRYPT=1` - with the flag off
    /// the line decodes as payload bytes, exactly as before the spike.
    #[error("malformed =yencryption control line")]
    BadEncryption,
    /// The article declares body encryption and parsed cleanly, but this
    /// job cannot decrypt it: no password, or the NZB cannot carry the
    /// draft's continuous segmentIndex (multi-file with no `[n/m]`
    /// subject prefixes). Constructed by the decode consumer, not the
    /// decoder - the decoder cannot know what the job holds.
    #[error(
        "encrypted article (=yencryption) but decryption is unavailable - \
         no NZB password, or no [n/m] subject file numbering"
    )]
    EncryptedUnsupported,
    /// Poly1305 authentication failed on an encrypted article: wrong
    /// password, wrong segmentIndex derivation, or a corrupt body whose
    /// damage the yEnc CRC did not catch. Constructed by the decode
    /// consumer after [`Self::BadEncryption`]'s parse succeeded.
    #[error("encrypted article failed authentication (wrong password or corrupt body)")]
    DecryptAuth,
}

/// A decoded yEnc article (one part of a file, or a whole small file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// Filename from `=ybegin name=`.
    pub name: String,
    /// Total file size from `=ybegin size=`.
    pub file_size: u64,
    /// Part number from `=ybegin part=` (None for single-part posts).
    pub(crate) part: Option<u32>,
    /// 1-based inclusive byte range from `=ypart begin=`/`end=`.
    /// For single-part posts this covers the whole file.
    pub begin: u64,
    pub end: u64,
    pub data: Vec<u8>,
    /// The `=yencryption` control line, captured only under
    /// `NZBFAST_YENC_CRYPT=1` (with the flag off the line decodes as
    /// payload, preserving pre-spike behavior byte for byte). When set,
    /// `data` is XChaCha20-Poly1305 ciphertext the consumer still owes a
    /// decrypt+authenticate pass - see `crate::yencrypt`.
    pub encryption: Option<crate::yencrypt::EncHeader>,
}

impl Decoded {
    /// Zero-based file offset where `data` belongs - feed straight to pwrite.
    /// Saturating: `begin` is normalized to >=1 at parse time, but guard the
    /// subtraction anyway so no code path can produce a u64::MAX offset.
    pub fn offset(&self) -> u64 {
        self.begin.saturating_sub(1)
    }
}

/// Everything a decoded article carries EXCEPT the payload bytes, which
/// [`crate::yenc_simd::decode_into`] writes into a caller-owned (pooled)
/// buffer instead of a fresh per-article `Vec` - the hot download path
/// recycles that buffer, killing the per-article ~800 KB alloc/free the
/// [`crate::pool::BufPool`] already removed on the network side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub name: String,
    pub file_size: u64,
    pub part: Option<u32>,
    pub begin: u64,
    pub end: u64,
    /// Length of the decoded payload now in the caller's buffer.
    pub len: usize,
    /// See [`Decoded::encryption`] - same capture, same flag gating.
    pub encryption: Option<crate::yencrypt::EncHeader>,
}

impl Meta {
    /// Zero-based file offset where the payload belongs - feed to pwrite.
    /// Saturating for the same reason as [`Decoded::offset`].
    pub fn offset(&self) -> u64 {
        self.begin.saturating_sub(1)
    }
}

/// Decode a full article body (the lines between the NNTP BODY response and
/// the terminating `.`), verifying part length and CRC32 when present.
pub fn decode(body: &[u8]) -> Result<Decoded, YencError> {
    decode_checked(body).map(|(d, _)| d)
}

/// Like [`decode`], but also reports whether a CRC field was present AND
/// compared (returned `true` only then). The SIMD bare-LF fallback needs
/// this to avoid vouching `crc_checked` for an article that carried no
/// `pcrc32`/`crc32` at all - decoding success alone is not CRC verification.
pub fn decode_checked(body: &[u8]) -> Result<(Decoded, bool), YencError> {
    decode_checked_opts(body, crate::yencrypt::wire_enabled())
}

/// [`decode_checked`] with the body-encryption capture arm explicit
/// instead of read off the process env - the in-process seam the unit
/// tests use (the env OnceLock cannot be toggled per test; see the
/// test-global rules). Production callers go through [`decode_checked`].
pub(crate) fn decode_checked_opts(body: &[u8], enc_ok: bool) -> Result<(Decoded, bool), YencError> {
    match decode_framed(body, enc_ok) {
        // M4-76: a CR-FRAMED article. Both decoders split on `\n` and strip a
        // trailing `\r`, so CRLF and bare LF both work and bare CR does not -
        // the whole body reads as ONE line, so either there is no `=ybegin `
        // at its head (MissingBegin) or there is and no separate `=yend` line
        // can ever follow it (Truncated). Classic-Mac and some very old
        // posting tools still emit `\r`-only bodies, and the article was
        // simply dropped.
        //
        // Retried rather than parsed in the first pass, on both the evidence
        // and the cost: "no LF anywhere in the body" is a strong, whole-body
        // statement about the FRAMING and a weak one about any single line,
        // and testing it up front would put a scan of every article on the
        // hot path to serve a shape almost nothing posts. These two errors
        // are the only ones CR framing can produce, so nothing else pays for
        // the retry either.
        Err(e @ (YencError::MissingBegin | YencError::Truncated)) => {
            match cr_framed_to_crlf(body) {
                Some(reframed) => decode_framed(&reframed, enc_ok),
                None => Err(e),
            }
        }
        other => other,
    }
}

/// [`decode_checked`] over a body whose line framing is already LF or CRLF.
fn decode_framed(body: &[u8], enc_ok: bool) -> Result<(Decoded, bool), YencError> {
    // M4-78: some Windows-saved and indexer-rewritten first articles carry a
    // UTF-8 BOM glued to the header, and `=ybegin ` then does not start the
    // line. Stripped at the START OF THE BODY only: that is where an editor
    // or an indexer writes one, and a BOM anywhere else is payload bytes.
    let body = strip_bom(body);

    let mut name = String::new();
    let mut file_size: u64 = 0;
    let mut part: Option<u32> = None;
    let mut begin: u64 = 1;
    let mut end: u64 = 0;
    let mut trailer = Trailer::default();
    let mut seen_begin = false;
    let mut seen_yend = false;
    let mut seen_ypart = false;
    let mut encryption = None;
    let mut data = Vec::with_capacity(body.len());

    for raw_line in body.split(|&b| b == b'\n') {
        let mut line = raw_line;
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            continue;
        }
        // NNTP dot-unstuffing: the wire ALWAYS doubles a line-leading '.',
        // so exactly one leading dot is removed - `..` -> `.` (a payload
        // byte 0x04, or a stuffed `.=yend`), `.` -> ``. Stripping only the
        // doubled form left this oracle one byte richer than the production
        // SIMD path (rapidyenc unstuffs any line-leading dot), which the
        // differential fuzzer flags as a divergence on every mutated body.
        if line.first() == Some(&b'.') {
            line = &line[1..];
            if line.is_empty() {
                continue;
            }
        }

        if let Some(fields) = header_fields(line, b"begin", false) {
            // M4-63: the second header is a contradiction, not an update.
            // See YencError::DuplicateBegin.
            if seen_begin {
                return Err(YencError::DuplicateBegin);
            }
            seen_begin = true;
            let kv = parse_header(&fields);
            if let Some(v) = kv.get("name") {
                name = v.clone();
            }
            file_size = num(&kv, "size").unwrap_or(0);
            part = num(&kv, "part")
                .filter(|n| *n <= u64::from(u32::MAX))
                .map(|n| n as u32);
            // Until/unless =ypart overrides, a single-part post spans the file.
            //
            // M4-77: `=ypart` may arrive FIRST. The spec order is ybegin then
            // ypart, but a poster that swaps them used to have this line
            // overwrite the real part range with the whole-file size, so a
            // part-2 article declaring `begin=800001 end=900000` became
            // `end=<file size>` and either failed the geometry check or was
            // written at the right offset with the wrong length. `=ypart` is
            // the only declaration of an actual RANGE and this is a default
            // for the case where there is none, so it may not overwrite one
            // that has already been read - a weaker clue never overrides the
            // strongest available evidence (the wave-4 family rule).
            if !seen_ypart {
                end = file_size;
            }
        } else if let Some(fields) = header_fields(line, b"part", false) {
            seen_ypart = true;
            let kv = parse_header(&fields);
            // yEnc `begin` is 1-based; a hostile/broken `begin=0` would
            // underflow offset() to u64::MAX. Clamp to the valid floor.
            begin = num(&kv, "begin").filter(|&b| b >= 1).unwrap_or(1);
            end = num(&kv, "end").unwrap_or(0);
        } else if let Some(fields) = header_fields(line, b"end", true) {
            seen_yend = true;
            // A bare `=yend` (no trailing space/fields) carries no size or
            // CRC but still marks a complete article.
            let kv = parse_header(&fields);
            trailer = Trailer {
                size: num(&kv, "size"),
                pcrc32: hex(&kv, "pcrc32"),
                crc32: hex(&kv, "crc32"),
                // The trailer's part number, kept only to check it against
                // =ybegin's below. Nothing places bytes with it.
                part: num(&kv, "part")
                    .filter(|n| *n <= u64::from(u32::MAX))
                    .map(|n| n as u32),
            };
            // M4-84: the FIRST `=yend` ends the article, full stop. Lines
            // after it used to keep flowing into `decode_line` because
            // `seen_begin` was still true, so a poster's signature, a second
            // concatenated article with no header of its own, or a trailer
            // that simply omitted `size=` and `pcrc32=` silently GREW the
            // slot - measured at double length, with nothing to notice it
            // when no length or CRC gate was declared. Per the spec the
            // article ends here; trailing bytes describe nothing and may not
            // decide what lands on disk.
            break;
        } else if enc_ok && let Some(fields) = header_fields(line, b"encryption", false) {
            // Body-encryption spike: capture the line instead of decoding
            // it as payload. Malformed fields REFUSE the article - see
            // YencError::BadEncryption. Accepted anywhere in the block
            // (the draft says "after =ybegin" and is silent about
            // =ypart), last one wins, same as the SIMD path.
            encryption = Some(
                crate::yencrypt::EncHeader::parse_fields(fields.as_ref())
                    .ok_or(YencError::BadEncryption)?,
            );
        } else if seen_begin {
            decode_line(line, &mut data);
        }
    }

    if !seen_begin {
        return Err(YencError::MissingBegin);
    }
    // No =yend trailer means the article was cut short (the NNTP dot arrived
    // mid-body). Without this the decoder returns Ok on a partial payload;
    // the destination was preallocated to the declared size, so the missing
    // tail stays as sparse zero bytes and a no-PAR job completes with
    // silently corrupt output.
    if !seen_yend {
        return Err(YencError::Truncated);
    }
    // Both part numbers present and disagreeing means the trailer does not
    // belong to this header. Checked before the length and CRC because it is
    // the cheapest and most specific of the three, and a mismatch here makes
    // the other two meaningless.
    if let (Some(b), Some(e)) = (part, trailer.part)
        && b != e
    {
        return Err(YencError::PartNumberMismatch { begin: b, end: e });
    }
    let gates = trailer_gates(
        &trailer,
        &Declared {
            part,
            seen_ypart,
            begin,
            end,
            file_size,
            len: data.len() as u64,
        },
    );
    if let Some(len) = gates.len
        && len != data.len() as u64
    {
        return Err(YencError::LengthMismatch {
            expected: data.len() as u64,
            actual: len,
        });
    }
    check_part_geometry(seen_ypart, begin, end, data.len() as u64)?;
    let mut crc_verified = false;
    if let Some(header) = gates.crc {
        let computed = crc32fast::hash(&data);
        if computed != header {
            return Err(YencError::CrcMismatch { computed, header });
        }
        crc_verified = true;
    } else if let Some(advisory) = gates.crc_advisory
        && crc32fast::hash(&data) == advisory
    {
        // M4-87: a `crc32` on a PART trailer cannot gate that part (see
        // [`trailer_gates`]), but if it happens to match the part's own
        // bytes it has verified them, so say so rather than throwing the
        // one check the article offered away.
        crc_verified = true;
    }

    Ok((
        Decoded {
            name,
            file_size,
            part: declared_part(part),
            begin,
            end,
            data,
            encryption,
        },
        crc_verified,
    ))
}

/// The `=yend` trailer as it was literally written.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Trailer {
    pub size: Option<u64>,
    pub pcrc32: Option<u32>,
    pub crc32: Option<u32>,
    pub part: Option<u32>,
}

/// What the article declared about ITSELF - the header fields plus how many
/// bytes actually decoded. Input to [`trailer_gates`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Declared {
    pub part: Option<u32>,
    pub seen_ypart: bool,
    pub(crate) begin: u64,
    pub end: u64,
    pub file_size: u64,
    pub len: u64,
}

/// Which trailer fields may DECIDE this article: `len` and `crc` are fatal
/// on mismatch, `crc_advisory` only ever upgrades an article from unverified
/// to verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gates {
    pub len: Option<u64>,
    pub crc: Option<u32>,
    pub crc_advisory: Option<u32>,
}

/// Decide which `=yend` fields are talking about THIS ARTICLE.
///
/// ONE function, called by BOTH decoders, for the reason [`name_len`] is:
/// two copies of a rule is how the oracle and the production path start to
/// drift, and the differential fuzzer compares acceptance.
///
/// On a multipart post the trailer's `size` is the PART length and `pcrc32`
/// the part CRC, while `crc32` is the WHOLE FILE's. Old single-part tools
/// pointed at a split post get both wrong in the same direction - they copy
/// the file's size and the file's CRC onto every part - and both mistakes
/// used to be fatal, so EVERY article of such a post was refused and the
/// slot came out empty (M4-87 and M4-93, measured 31 Aug 2026). Neither
/// field is dropped blindly:
///
/// * `size` is ignored ONLY when `=ypart` declared a real range, which the
///   geometry check then enforces exactly (`end - begin + 1 == len`), AND
///   the trailer's figure is the `=ybegin size` rather than a third number.
///   A part that is genuinely short still fails, on the stronger evidence.
/// * `crc32` on a part becomes ADVISORY rather than fatal: nothing here can
///   compare a whole-file CRC against one part, so it may not refuse the
///   article - but if it does match the part's bytes it has verified them.
///   An article left unverified reports `crc_checked = false` and is treated
///   downstream as untrusted, which is the honest answer and the same one a
///   trailer carrying no CRC at all already gets.
pub(crate) fn trailer_gates(t: &Trailer, d: &Declared) -> Gates {
    // `part=0` is not a declaration that this body is a part - see
    // [`declared_part`] (M4-59), landed the day before this. Both relaxations
    // below are scoped to articles that ARE parts, so an out-of-spec 0 must
    // not buy either of them: such an article still has its `crc32` and its
    // trailer `size` read as a single-part post's, which is the arm that
    // keeps both gates fatal. That is the same direction the contradiction
    // check above goes for the opposite reason - it reads the RAW fields
    // because a `part=0` header against a `=yend part=1` trailer is still a
    // trailer that does not belong.
    let is_part = declared_part(d.part).is_some() || d.seen_ypart;
    // The geometry check can stand in for the trailer's length only where
    // `=ypart` gave it a range to enforce. `end == 0` (no `end=` at all) and
    // a reversed range are both waved through by `check_part_geometry`, so
    // neither may be read as a length check that has already been done.
    let ranged = d.seen_ypart && d.end >= d.begin && d.end > 0;
    let len = match t.size {
        Some(s) if is_part && ranged && s != d.len && d.file_size != 0 && s == d.file_size => None,
        other => other,
    };
    let (crc, crc_advisory) = match (t.pcrc32, t.crc32) {
        (Some(p), _) => (Some(p), None),
        (None, Some(c)) if is_part => (None, Some(c)),
        (None, c) => (c, None),
    };
    Gates {
        len,
        crc,
        crc_advisory,
    }
}

/// A UTF-8 BOM at the very start of an article body, removed. See M4-78 at
/// [`decode_framed`] for why only at the start.
pub(crate) fn strip_bom(body: &[u8]) -> &[u8] {
    body.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(body)
}

/// A CR-framed body rewritten with CRLF endings, or None if the body is not
/// CR-framed. See M4-76 at [`decode_checked`].
///
/// `pub` for the differential fuzz target alone, which lives in its own
/// workspace and has to ask the same question this decoder asks - "is this
/// body about to be retried on a rewrite of itself" - before it can judge
/// the two documented oracle/SIMD deviations over the right bytes. One
/// rule, one place: a second copy of the predicate in the fuzz crate is
/// how a guard and the code it guards start to drift.
///
/// CRLF and not bare LF because the production decoder's block mode asks
/// rapidyenc to stop at `\r\n=y`: reframing to LF alone would hand it a body
/// whose trailer it cannot see, which is the bare-LF fallback path, so the
/// article would decode on the scalar oracle at scalar speed.
///
/// "No LF anywhere" is the whole test. A raw CR is never payload - valid
/// yEnc escapes it as `=M` and both decoders drop a stray one - so a body
/// carrying CRs and no LF at all is framed with CR, and one carrying any LF
/// is framed with LF or CRLF and is not this shape.
pub fn cr_framed_to_crlf(body: &[u8]) -> Option<Vec<u8>> {
    if !body.contains(&b'\r') || body.contains(&b'\n') {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() + body.len() / 64 + 16);
    for &b in body {
        out.push(b);
        if b == b'\r' {
            out.push(b'\n');
        }
    }
    Some(out)
}

/// The field text of the header `=y<kw>` (`begin` / `part` / `end`), with
/// TAB separators normalised to spaces, or None if `line` is not that
/// header. `bare_ok` allows the keyword with no fields after it at all,
/// which only `=yend` may be.
///
/// M4-85: both decoders required a literal SPACE after the keyword, so
/// `=ybegin\tline=128 size=4 name=a` was not a header at all - the article
/// was dropped with MissingBegin. Some indexers and copy-paste paths emit
/// tabs. The tab is a separator here and nowhere else: the field scanners
/// on both sides still see spaces only, so they cannot drift apart over a
/// second separator (a form feed glued to a key once made them read
/// different `crc32` fields - see [`parse_header`]).
///
/// The normalisation covers the WHOLE header including a `name=` value, so
/// a filename containing a literal tab is spelled with a space. That costs
/// an exact-name nomination and nothing else - a name nominates and only
/// content finalizes (W4-02) - where leaving tabs alone past `name=` would
/// hand the trailing `\tsize=`/`\tpcrc32=` tokens to the FILENAME, which is
/// M4-42 in tab form.
pub(crate) fn header_fields<'a>(
    line: &'a [u8],
    kw: &[u8],
    bare_ok: bool,
) -> Option<std::borrow::Cow<'a, [u8]>> {
    header_tail(line.strip_prefix(b"=y")?.strip_prefix(kw)?, bare_ok)
}

/// [`header_fields`] over the text already past the `=y<kw>` keyword - the
/// production decoder's block mode reconstructs a control line in that
/// shape, so both spellings share one rule.
pub(crate) fn header_tail(after_kw: &[u8], bare_ok: bool) -> Option<std::borrow::Cow<'_, [u8]>> {
    match after_kw.first() {
        None => bare_ok.then_some(std::borrow::Cow::Borrowed(after_kw)),
        Some(&b) if b == b' ' || b == b'\t' => {
            let fields = &after_kw[1..];
            if fields.contains(&b'\t') {
                Some(std::borrow::Cow::Owned(
                    fields
                        .iter()
                        .map(|&c| if c == b'\t' { b' ' } else { c })
                        .collect(),
                ))
            } else {
                Some(std::borrow::Cow::Borrowed(fields))
            }
        }
        Some(_) => None,
    }
}

/// The part number a decoded article may be said to DECLARE, with the
/// out-of-spec `part=0` reported as no declaration at all.
///
/// M4-59 (wave-4 matrix read, 30 Aug 2026). yEnc part numbers are
/// 1-based by the spec, so `=ybegin part=0` states an impossible part.
/// Both decoders parsed it into `Some(0)` and handed that on as though
/// it were a claim about which part this body is, which it cannot be.
///
/// The exported field has exactly ONE consumer: the pool's split-brain
/// identity gate, which compares it against the NZB's own segment number
/// (`ArticleReq::part`, where 0 already means "unknown"). Placement has
/// never read it - `Decoded::offset` comes from `=ypart begin=` - so
/// nothing about where the bytes land moves here.
///
/// MEASURED on the 30 Aug 2026 baseline, two servers with `crc_steer`
/// on: an article declaring `part=0` against a 1-based NZB segment was
/// steered as "valid body for the wrong article (part mismatch)" and
/// refetched from the other server - a doubled fetch of a post that was
/// never damaged. Nothing was lost (every article delivered, none bad),
/// which falsifies the row's predicted "silent drop or a sparse hole";
/// the cost is wire. Pinned at
/// [`crate::pool::rig_tests::a_part_zero_header_does_not_steer_the_article`],
/// whose header also records what this does NOT fix: a fully 0-BASED
/// poster, whose later articles declare real numbers that are off by
/// one and are the F-09 latch's business, not this function's.
///
/// The house rule is what settles it: a weaker or earlier clue may
/// NOMINATE, only the strongest available evidence may finalize
/// identity. A field carrying a value the grammar forbids is not
/// evidence of anything, so it nominates nothing.
///
/// Deliberately NOT applied to the `=ybegin`/`=yend` contradiction check
/// above, which reads the RAW parsed fields: `part=0` against `=yend
/// part=1` is still a trailer that does not belong to its header, and
/// both decoders still refuse it by name. Normalizing before that test
/// would have traded a live check away for this.
///
/// Refusing the article outright - the row's other suggestion - was
/// considered and rejected: the body decodes and passes its own pcrc32,
/// and every server posting the file spells it the same way, so a
/// refusal turns a doubled fetch into a job that can never complete.
pub(crate) fn declared_part(part: Option<u32>) -> Option<u32> {
    part.filter(|&p| p != 0)
}

/// Reject a multipart article whose declared range cannot hold what it
/// decoded to. Shared by both decoders - a divergence here is a divergence
/// the differential fuzzer would (rightly) call a bug.
///
/// `begin`/`end` are 1-based inclusive, so the range holds `end - begin + 1`
/// bytes and the payload must be exactly that. Without this, a CRC-valid
/// article could declare `=ypart begin=<1 TiB> end=<1 TiB>` and have its few
/// bytes written a terabyte into the output: positioned writes extend a file,
/// so a PAR2-less job finished "complete" with a huge sparse hole and an
/// output nothing in the post ever described.
///
/// Deliberately NOT checked: `end` against `=ybegin size`. Real posters do get
/// the total size field wrong on otherwise perfectly good articles, and the
/// authoritative length (`=yend size`) is already compared above. This test
/// only rejects geometry that contradicts ITSELF.
pub(crate) fn check_part_geometry(
    seen_ypart: bool,
    begin: u64,
    end: u64,
    len: u64,
) -> Result<(), YencError> {
    // No `=ypart`: `end` came from the (untrusted, unchecked) `=ybegin size`
    // field rather than a range declaration, so there is nothing to
    // contradict.
    if !seen_ypart {
        return Ok(());
    }
    // `=ypart` carrying no `end=` at all: both decoders default it to 0.
    // "Nothing to check the range against" must not collapse into
    // "anything goes" - `begin` ALONE still positions the write
    // (`Meta::offset()` is `begin - 1`), so returning Ok here handed back
    // exactly the write-anywhere primitive described above, with the
    // article no longer even having to make its range self-consistent to
    // get it. A zero-length part legitimately produces `end == 0`, and a
    // part beginning at the top of the file has nowhere to go: both stay
    // accepted. A non-empty part claiming a nonzero offset while
    // declining to declare its range does not - the spec requires `end=`
    // on `=ypart`, so that shape is malformed by construction rather
    // than a poster quirk we have to tolerate.
    if end == 0 {
        if len > 0 && begin > 1 {
            return Err(YencError::PartGeometry { begin, end, len });
        }
        return Ok(());
    }
    if begin > end || end - begin + 1 != len {
        return Err(YencError::PartGeometry { begin, end, len });
    }
    Ok(())
}

/// Decode one payload line (yEnc unescaping) onto `out`. `pub(crate)` because
/// the SIMD path must decode an unrecognised `=y…` control line as payload
/// through this exact routine to stay byte-identical with this oracle.
pub(crate) fn decode_line(line: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < line.len() {
        let b = line[i];
        if b == b'=' {
            if i + 1 < line.len() {
                out.push(line[i + 1].wrapping_sub(64).wrapping_sub(42));
                i += 2;
            } else {
                // Trailing lone '=' - malformed; ignore.
                i += 1;
            }
        } else if b == b'\r' || b == b'\n' {
            // A raw CR/LF is a line separator, never data - valid yEnc escapes
            // them (`=M`/`=J`). rapidyenc drops them, so a stray mid-line CR
            // used to leave this oracle one 0xE3 byte richer (fuzz find).
            i += 1;
        } else {
            out.push(b.wrapping_sub(42));
            i += 1;
        }
    }
}

/// The yEnc header vocabulary OTHER than `name`, across all three header
/// lines (`=ybegin` / `=ypart` / `=yend`). Closed on purpose: it is the
/// only thing that may cut a filename short, so it must be a list of
/// keys and never a guess about what a key looks like.
const HEADER_KEYS: [&[u8]; 8] = [
    b"part", b"total", b"line", b"size", b"begin", b"end", b"pcrc32", b"crc32",
];

/// How many bytes of `after` (everything past a `name=` token) belong to
/// the FILENAME.
///
/// `name=` runs to end of line, because filenames contain spaces - but
/// only until the next ` <key>=` token from the closed vocabulary above.
/// An encoder that writes `... name=foo.bin size=1000 pcrc32=DEADBEEF`
/// (keys AFTER name, seen in the wild; ours puts `name=` last, so every
/// in-tree fixture was blind to it) otherwise stores the whole tail as
/// the filename: the PAR2 exact-name tier can never hit it, and on a
/// post with no recovery set at all the file is PUBLISHED under it
/// (matrix M4-42, measured 30 Aug 2026 - `Trail.Keys.bin size=1000
/// pcrc32=DEADBEEF` on disk).
///
/// The cut is deliberately NOT allowed to un-hide those keys: whatever
/// follows a `name=` is still invisible to [`field_value`] and to
/// [`parse_header`]'s loop, so a filename can never inject an article's
/// size or CRC gate. The only thing that changes is where the NAME ends.
/// A filename that genuinely contains ` size=` or ` part=` is truncated,
/// which costs an exact-name nomination and nothing else - a name
/// nominates and only content finalizes (W4-02) - where the old spelling
/// cost the name outright.
///
/// ONE function, called by BOTH decoders. The HashMap oracle and the
/// allocation-free SIMD extractors are held to identical answers by the
/// differential fuzzer, and two copies of this rule is how they start to
/// drift.
fn name_len(after: &[u8]) -> usize {
    let mut i = 0usize;
    while i < after.len() {
        if after[i] != b' ' {
            i += 1;
            continue;
        }
        let tok = &after[i + 1..];
        if HEADER_KEYS
            .iter()
            .any(|k| tok.len() > k.len() && tok.starts_with(k) && tok[k.len()] == b'=')
        {
            return i;
        }
        i += 1;
    }
    after.len()
}

/// Parse `key=value` pairs from a yEnc header line. `name=` consumes the
/// rest of the line (filenames contain spaces) up to the next ` key=`
/// token - see [`name_len`].
pub(crate) fn parse_header(rest: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let text = String::from_utf8_lossy(rest);
    // ASCII SPACE is the only field separator, and the only thing trimmed:
    // `str::trim` also eats \t, \x0b, \x0c and Unicode spaces, which the SIMD
    // extractors (space-delimited byte scan) do not - a form feed glued to a
    // key made the two paths read different `crc32` fields (fuzz find).
    let mut remaining = text.trim_matches(' ');
    while !remaining.is_empty() {
        let Some(eq) = remaining.find('=') else { break };
        // The key is the token immediately before the `=`: everything back to
        // the previous space, exactly what the SIMD path's `find_key` matches
        // (line start or a space, then the key, then `=`). Taking the whole
        // span before the `=` instead made `=ybegin l<junk>128 size=4 …` parse
        // as one key `l<junk>128 size` on this side and as `size` on the SIMD
        // side - a differential-fuzz find, and the shape a poster gets by
        // corrupting one header byte.
        let key = remaining[..eq].rsplit(' ').next().unwrap_or("").to_string();
        let after = &remaining[eq + 1..];
        if key == "name" {
            map.entry(key).or_insert_with(|| {
                after[..name_len(after.as_bytes())]
                    .trim_matches(|c: char| c.is_ascii_whitespace())
                    .to_string()
            });
            break;
        }
        let (value, rest2) = match after.find(' ') {
            Some(sp) => (&after[..sp], after[sp + 1..].trim_start_matches(' ')),
            None => (after, ""),
        };
        // FIRST occurrence wins on a duplicated key. The SIMD path's
        // `find_key` scan stops at the first match, so last-wins here made
        // the two decoders disagree on `begin` (the write offset!) for a
        // header like `begin=5part begin=50000` - found by the differential
        // fuzzer. Well-formed headers never repeat a key.
        map.entry(key).or_insert_with(|| value.to_string());
        remaining = rest2;
    }
    map
}

pub(crate) fn num(kv: &HashMap<String, String>, key: &str) -> Option<u64> {
    kv.get(key)?.parse().ok()
}

pub(crate) fn hex(kv: &HashMap<String, String>, key: &str) -> Option<u32> {
    u32::from_str_radix(kv.get(key)?, 16).ok()
}

// ---------------------------------------------------------------------------
// Allocation-free field extractors for the hot SIMD decode path. The
// `parse_header` HashMap parser above stays the correctness oracle (and
// keeps the two decoders independent for the differential tests); the
// SIMD path uses these to avoid a HashMap + Strings per article. yEnc
// headers are ` key=value` tokens; only `name` may contain spaces (it
// runs to the end of the line, or to the next ` key=` token - the one
// rule both decoders take from `name_len`).
// ---------------------------------------------------------------------------

/// Index of `key` in `rest`, matched as a whole token (preceded by the
/// line start or a space, followed by `=`).
fn find_key(rest: &[u8], key: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + key.len() < rest.len() {
        if (i == 0 || rest[i - 1] == b' ')
            && rest[i..].starts_with(key)
            && rest[i + key.len()] == b'='
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Value of `key=` up to the next space (empty if absent). The search
/// STOPS at a `name=` token, matching `parse_header` (which breaks out of
/// its loop on `name`). Without that a filename could carry its own
/// `size=`/`pcrc32=` text and be read as the article's gates on this path
/// but not on the oracle's - a differential-fuzz find.
///
/// That guard is unchanged by [`name_len`], and deliberately: a name is
/// now CUT at the first following ` key=` token, but the keys past it
/// stay unreadable to both decoders, so no filename can ever supply an
/// article's size or CRC gate.
fn field_value<'a>(rest: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let rest = if key == b"name" {
        rest
    } else {
        match find_key(rest, b"name") {
            Some(n) => &rest[..n],
            None => rest,
        }
    };
    let i = find_key(rest, key)?;
    let vs = i + key.len() + 1;
    let ve = rest[vs..]
        .iter()
        .position(|&b| b == b' ')
        .map_or(rest.len(), |p| vs + p);
    Some(&rest[vs..ve])
}

pub(crate) fn field_u64(rest: &[u8], key: &[u8]) -> Option<u64> {
    std::str::from_utf8(field_value(rest, key)?)
        .ok()?
        .parse()
        .ok()
}

pub(crate) fn field_hex(rest: &[u8], key: &[u8]) -> Option<u32> {
    u32::from_str_radix(std::str::from_utf8(field_value(rest, key)?).ok()?, 16).ok()
}

/// `name=` value - the remainder of the line up to the next ` key=`
/// token ([`name_len`]), trimmed. Returns None if there is no `name=`
/// token.
pub(crate) fn field_name(rest: &[u8]) -> Option<&[u8]> {
    let i = find_key(rest, b"name")?;
    let after = &rest[i + 5..]; // 5 = "name=".len()
    Some(after[..name_len(after)].trim_ascii())
}

// ---------------------------------------------------------------------------
// Encoder - used by tests as the round-trip oracle, and eventually by the
// posting feature.
// ---------------------------------------------------------------------------

const LINE_LEN: usize = 128;

/// Encode one part of a file as a complete yEnc article body (no NNTP
/// dot-stuffing - that belongs to the wire layer).
pub fn encode(
    name: &str,
    file_size: u64,
    part: Option<(u32, u32)>, // (part number, total parts)
    begin: u64,               // 1-based inclusive
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 32 + 256);
    let crc = crc32fast::hash(data);

    match part {
        Some((p, total)) => {
            out.extend_from_slice(
                format!(
                    "=ybegin part={p} total={total} line={LINE_LEN} size={file_size} name={name}\r\n"
                )
                .as_bytes(),
            );
            let end = begin + data.len() as u64 - 1;
            out.extend_from_slice(format!("=ypart begin={begin} end={end}\r\n").as_bytes());
        }
        None => {
            out.extend_from_slice(
                format!("=ybegin line={LINE_LEN} size={file_size} name={name}\r\n").as_bytes(),
            );
        }
    }

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
        if col >= LINE_LEN {
            out.extend_from_slice(b"\r\n");
            col = 0;
        }
    }
    if col > 0 {
        out.extend_from_slice(b"\r\n");
    }

    match part {
        Some((p, _)) => out.extend_from_slice(
            format!("=yend size={} part={p} pcrc32={crc:08x}\r\n", data.len()).as_bytes(),
        ),
        None => out
            .extend_from_slice(format!("=yend size={} crc32={crc:08x}\r\n", data.len()).as_bytes()),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic byte soup covering all 256 values many times over.
    fn test_data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    /// M4-59 - the out-of-spec `part=0`.
    ///
    /// Both decoders parse it, place the bytes off `=ypart` as they
    /// always did, and report NO declared part: 0 is not a part number,
    /// so it makes no claim the pool's split-brain gate could test. The
    /// pair check above still reads the RAW fields, so a header saying 0
    /// and a trailer saying 1 is still a named refusal.
    ///
    /// Driven through BOTH decoders on every case, because
    /// `declared_part` is the one function and a divergence here is a
    /// divergence the differential fuzzer would have to find at random.
    #[test]
    fn an_out_of_spec_part_zero_declares_no_part() {
        let data = test_data(64);
        let art = encode("p.bin", 128, Some((0, 2)), 1, &data);
        let o = decode(&art).expect("part=0 must still decode");
        let s = crate::yenc_simd::decode(&art).expect("part=0 must still decode (simd)");
        assert_eq!(o.part, None, "part=0 is not a part number");
        assert_eq!(s.part, None, "the two decoders must agree");
        assert_eq!(o, s, "the two decoders must agree on the whole article");
        // Placement is unmoved: `=ypart begin=1` puts these bytes at 0.
        assert_eq!((o.offset(), o.data.len()), (0, 64));

        // A real part number is untouched.
        let art1 = encode("p.bin", 128, Some((1, 2)), 1, &data);
        assert_eq!(decode(&art1).unwrap().part, Some(1));
        assert_eq!(crate::yenc_simd::decode(&art1).unwrap().part, Some(1));

        // The =ybegin/=yend contradiction check reads the RAW fields, so
        // it still fires on a 0/1 pair rather than being normalized away.
        // Byte-level surgery: a yEnc body is arbitrary bytes, not UTF-8.
        let mut mixed = art.clone();
        let at = mixed
            .windows(6)
            .rposition(|w| w == b"part=0")
            .expect("the trailer's part field");
        mixed[at + 5] = b'1';
        assert!(
            matches!(
                decode(&mixed),
                Err(YencError::PartNumberMismatch { begin: 0, end: 1 })
            ),
            "a 0/1 header-trailer pair must still be refused by name"
        );
        assert!(matches!(
            crate::yenc_simd::decode(&mixed),
            Err(YencError::PartNumberMismatch { begin: 0, end: 1 })
        ));
    }

    #[test]
    fn round_trip_single_part() {
        let data = test_data(10_000);
        let article = encode("test file.bin", data.len() as u64, None, 1, &data);
        let dec = decode(&article).unwrap();
        assert_eq!(dec.name, "test file.bin");
        assert_eq!(dec.file_size, 10_000);
        assert_eq!(dec.part, None);
        assert_eq!(dec.offset(), 0);
        assert_eq!(dec.data, data);
    }

    #[test]
    fn round_trip_multi_part_offsets() {
        let file = test_data(300_000);
        let (a, b) = file.split_at(150_000);
        let art2 = encode("f.bin", 300_000, Some((2, 2)), 150_001, b);
        let dec = decode(&art2).unwrap();
        assert_eq!(dec.part, Some(2));
        assert_eq!(dec.begin, 150_001);
        assert_eq!(dec.end, 300_000);
        assert_eq!(dec.offset(), 150_000);
        assert_eq!(dec.data, b);

        let dec1 = decode(&encode("f.bin", 300_000, Some((1, 2)), 1, a)).unwrap();
        assert_eq!(dec1.offset(), 0);
        assert_eq!(dec1.data, a);
    }

    /// A part whose declared range cannot hold what it decoded to is
    /// rejected, on BOTH decoders. The attack it closes: a CRC-valid article
    /// declaring `begin` a terabyte in and a handful of bytes of payload,
    /// which the positioned write happily placed there - leaving a job that
    /// "completed" with a sparse output nothing in the post described.
    #[test]
    fn impossible_part_geometry_is_rejected_on_both_paths() {
        let payload = test_data(4096);
        // A multipart article with an arbitrary declared range, carrying the
        // reference encoder's own payload lines and (valid) `=yend` trailer.
        let article = |begin: u64, end: u64| -> Vec<u8> {
            let mut body = format!(
                "=ybegin part=1 total=2 line=128 size=1099511631872 name=g.bin\r\n\
                 =ypart begin={begin} end={end}\r\n"
            )
            .into_bytes();
            let single = encode("g.bin", payload.len() as u64, None, 1, &payload);
            let payload_starts = single.windows(2).position(|w| w == b"\r\n").unwrap() + 2;
            body.extend_from_slice(&single[payload_starts..]);
            body
        };

        // A huge offset alone is not the defect: this range holds exactly the
        // 4096 bytes that arrived, so it stays valid.
        let ok = article(1_099_511_627_777, 1_099_511_631_872);
        assert!(decode(&ok).is_ok());
        assert!(crate::yenc_simd::decode(&ok).is_ok());

        // One declared byte, 4 KiB of payload - the shape that let a CRC-valid
        // article place bytes anywhere it liked.
        let short = article(1_099_511_627_777, 1_099_511_627_777);
        assert!(matches!(
            decode(&short),
            Err(YencError::PartGeometry { len: 4096, .. })
        ));
        assert!(matches!(
            crate::yenc_simd::decode(&short),
            Err(YencError::PartGeometry { len: 4096, .. })
        ));

        // begin > end is impossible whatever the payload.
        let inverted = article(1_099_511_631_873, 1_099_511_627_777);
        assert!(decode(&inverted).is_err());
        assert!(crate::yenc_simd::decode(&inverted).is_err());

        // Ordinary multipart posts are untouched.
        let good = encode("f.bin", 8192, Some((2, 2)), 4097, &payload);
        assert_eq!(decode(&good).unwrap().data, payload);
        assert_eq!(crate::yenc_simd::decode(&good).unwrap().data, payload);
    }

    /// The same write-anywhere primitive, reached by simply OMITTING
    /// `end=` instead of lying about it.
    ///
    /// Both decoders default a missing `end` to 0, and the geometry
    /// check used to return Ok on `end == 0` - so an article that
    /// declined to declare its range got the arbitrary offset without
    /// even having to make the range self-consistent, which is a strictly
    /// easier bypass than the one the test above pins.
    #[test]
    fn a_part_that_declares_no_end_may_not_claim_an_offset() {
        let payload = test_data(4096);
        let article = |ypart: &str| -> Vec<u8> {
            let mut body = format!(
                "=ybegin part=1 total=2 line=128 size=1099511631872 name=g.bin\r\n\
                 {ypart}\r\n"
            )
            .into_bytes();
            let single = encode("g.bin", payload.len() as u64, None, 1, &payload);
            let starts = single.windows(2).position(|w| w == b"\r\n").unwrap() + 2;
            body.extend_from_slice(&single[starts..]);
            body
        };

        let no_end = article("=ypart begin=1099511627777");
        assert!(matches!(
            decode(&no_end),
            Err(YencError::PartGeometry { len: 4096, .. })
        ));
        assert!(matches!(
            crate::yenc_simd::decode(&no_end),
            Err(YencError::PartGeometry { len: 4096, .. })
        ));

        // `end=0` spelled out reaches the same default and is the same
        // article.
        let zero_end = article("=ypart begin=1099511627777 end=0");
        assert!(decode(&zero_end).is_err());
        assert!(crate::yenc_simd::decode(&zero_end).is_err());

        // A part at the top of the file has nowhere to place itself, so
        // an absent `end` costs nothing and stays accepted - this is the
        // shape real single-part posts take.
        let at_one = article("=ypart begin=1");
        assert_eq!(decode(&at_one).unwrap().data, payload);
        assert_eq!(crate::yenc_simd::decode(&at_one).unwrap().data, payload);

        // And the empty part that legitimately produces `end == 0` is
        // still legal wherever it sits.
        assert!(check_part_geometry(true, 4097, 0, 0).is_ok());
    }

    #[test]
    fn survives_nntp_dot_stuffing() {
        let data = test_data(50_000);
        let article = encode("dots.bin", data.len() as u64, None, 1, &data);
        // Simulate the NNTP wire: any line starting with '.' gets doubled.
        let mut stuffed = Vec::new();
        for line in article.split_inclusive(|&b| b == b'\n') {
            if line.first() == Some(&b'.') {
                stuffed.push(b'.');
            }
            stuffed.extend_from_slice(line);
        }
        let dec = decode(&stuffed).unwrap();
        assert_eq!(dec.data, data);
    }

    #[test]
    fn detects_corruption() {
        let data = test_data(5_000);
        let mut article = encode("c.bin", data.len() as u64, None, 1, &data);
        // Flip a payload byte (past the =ybegin line) to a harmless
        // non-critical value.
        let payload_start = article.windows(2).position(|w| w == b"\r\n").unwrap() + 2;
        article[payload_start] = if article[payload_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        match decode(&article) {
            Err(YencError::CrcMismatch { .. }) => {}
            other => panic!("expected CRC mismatch, got {other:?}"),
        }
    }

    #[test]
    fn missing_begin_rejected() {
        assert_eq!(decode(b"just some text\r\n"), Err(YencError::MissingBegin));
    }

    /// A hostile `=ypart begin=0` must not underflow offset() to u64::MAX
    /// (which panicked the par2-capture consumer). begin is clamped to its
    /// 1-based floor, so offset() is 0.
    #[test]
    fn ypart_begin_zero_does_not_underflow() {
        // No =yend size / crc → no length or CRC gate; payload bytes are
        // irrelevant, only begin/offset matter. (`=yend` with no fields.)
        let body = b"=ybegin part=1 total=1 line=128 size=4 name=x.bin\r\n\
                     =ypart begin=0 end=4\r\n\
                     test\r\n=yend\r\n";
        let dec = decode(body).unwrap();
        assert_eq!(dec.begin, 1, "begin=0 must clamp to the 1-based floor");
        assert_eq!(dec.offset(), 0, "begin=0 must clamp, not wrap to u64::MAX");
    }

    /// Hostile-header torture matrix (shapes catalogued from other
    /// downloaders' yEnc regression suites, synthesized fresh here): every
    /// case must return a clean value or error - never panic, never
    /// allocate from a declared size, never wrap an offset.
    #[test]
    fn hostile_headers_never_panic_or_overallocate() {
        // Declared 1 TiB size with a 4-byte payload: allocation follows the
        // BODY length, not the header, and the size just rides in metadata.
        let huge = b"=ybegin part=1 line=128 size=1099511627776 name=big.bin\r\n\
                     =ypart begin=1 end=4\r\ntest\r\n=yend\r\n";
        let dec = decode(huge).unwrap();
        assert_eq!(dec.file_size, 1_099_511_627_776);
        assert!(dec.data.len() < 16);

        // Negative size: not a u64, parses as absent (0) - no panic.
        let neg = b"=ybegin line=128 size=-5 name=n.bin\r\ntest\r\n=yend\r\n";
        let _ = decode(neg);

        // Garbage / overlong / empty CRC fields: ignored or clean error,
        // never a parse panic.
        for crc in [
            "pcrc32=XYZNOTHEX",
            "pcrc32=deadbeefdeadbeefdeadbeef",
            "pcrc32=",
        ] {
            let body = format!(
                "=ybegin part=1 line=128 size=4 name=c.bin\r\n=ypart begin=1 end=4\r\ntest\r\n=yend size=4 {crc}\r\n"
            );
            let _ = decode(body.as_bytes());
        }

        // Double =ybegin: refused outright, and pinned by name rather
        // than by `let _ =` - see the M4-63 test below for why.
        let dbl = b"=ybegin line=128 size=4 name=a.bin\r\n\
                    =ybegin line=128 size=4 name=b.bin\r\ntest\r\n=yend\r\n";
        assert_eq!(decode(dbl), Err(YencError::DuplicateBegin));

        // =ypart with begin > end, and =ypart without =ybegin.
        let inv = b"=ybegin part=1 line=128 size=4 name=i.bin\r\n\
                    =ypart begin=9 end=2\r\ntest\r\n=yend\r\n";
        let _ = decode(inv);
        let orphan = b"=ypart begin=1 end=4\r\ntest\r\n";
        assert!(decode(orphan).is_err());

        // Truncations: header cut mid-fields, missing =yend entirely.
        let _ = decode(b"=ybegin part=1 li");
        let _ = decode(b"=ybegin line=128 size=4 name=t.bin\r\ntest\r\n");

        // Dot-stuffing-only body and newline-only body.
        let _ = decode(b"=ybegin line=128 size=2 name=d.bin\r\n..\r\n=yend\r\n");
        let _ = decode(b"=ybegin line=128 size=0 name=e.bin\r\n\r\n\r\n=yend\r\n");

        // NUL bytes and non-ASCII everywhere in the filename.
        let nul = b"=ybegin line=128 size=4 name=a\x00b\xff\xfe.bin\r\ntest\r\n=yend\r\n";
        let _ = decode(nul);

        // Escape byte at end of line (dangling '=').
        let dangling = b"=ybegin line=128 size=3 name=g.bin\r\nte=\r\n=yend\r\n";
        let _ = decode(dangling);
    }

    /// The allocation-free field extractors must agree with the HashMap
    /// oracle on real header shapes, including a spaced filename (runs to
    /// end), whole-token matching, and absent fields.
    #[test]
    fn field_extractors_match_oracle() {
        let h = b"size=123456 part=2 pcrc32=deadBEEF name=My Movie (2026).mkv";
        let kv = parse_header(h);
        assert_eq!(field_u64(h, b"size"), num(&kv, "size"));
        assert_eq!(field_u64(h, b"part"), num(&kv, "part"));
        assert_eq!(field_hex(h, b"pcrc32"), hex(&kv, "pcrc32"));
        assert_eq!(field_u64(h, b"size"), Some(123456));
        assert_eq!(field_hex(h, b"pcrc32"), Some(0xDEAD_BEEF));
        // name runs to end of line, spaces and all.
        assert_eq!(field_name(h).unwrap(), b"My Movie (2026).mkv");
        // Absent / non-token-boundary keys.
        assert_eq!(field_u64(h, b"begin"), None);
        assert_eq!(field_u64(h, b"art"), None); // must not match inside "part"
        assert_eq!(field_name(b"size=1"), None);
        // Field at end with empty value.
        assert_eq!(field_value(b"size=10 crc32=", b"crc32"), Some(&b""[..]));
    }

    /// M4-42: `=ybegin` keys written AFTER `name=`.
    ///
    /// The greedy `name=` used to store `foo.bin size=1000
    /// pcrc32=DEADBEEF` as the FILENAME. That is invisible to every
    /// other fixture in this tree because our own encoder puts `name=`
    /// last; the shape comes off the wire from posters whose tooling
    /// does not. Both decoders must cut at the first ` key=` token from
    /// the closed vocabulary and must cut at the SAME place, or the
    /// differential fuzz oracle stops meaning anything.
    #[test]
    fn keys_written_after_name_are_not_part_of_the_filename() {
        let h = b"part=1 total=3 line=128 size=4 name=foo.bin size=1000 pcrc32=DEADBEEF";
        let kv = parse_header(h);
        assert_eq!(kv.get("name").map(String::as_str), Some("foo.bin"));
        assert_eq!(field_name(h).unwrap(), b"foo.bin");
        // The real `size=` before the name still wins, and the one the
        // filename dragged along stays unreadable to BOTH decoders - a
        // name may never supply an article's gates.
        assert_eq!(num(&kv, "size"), Some(4));
        assert_eq!(field_u64(h, b"size"), Some(4));
        assert_eq!(hex(&kv, "pcrc32"), None);
        assert_eq!(field_hex(h, b"pcrc32"), None);

        // A trailing key run with nothing but keys, and one at the very
        // end of the line.
        for (line, want) in [
            (&b"line=128 name=a.bin part=2"[..], &b"a.bin"[..]),
            (&b"line=128 name=a.bin crc32=DEADBEEF"[..], &b"a.bin"[..]),
            (&b"line=128 name=a.bin end=9 begin=1"[..], &b"a.bin"[..]),
        ] {
            assert_eq!(field_name(line).unwrap(), want, "{line:?}");
            assert_eq!(
                parse_header(line).get("name").map(String::as_str),
                Some(std::str::from_utf8(want).unwrap()),
                "{line:?}"
            );
        }

        // What must NOT be cut: a filename with ordinary spaces, one
        // carrying a bare `=`, one carrying a word that merely CONTAINS
        // a key ("part" inside "partial", "end" inside "ending"), and a
        // key-shaped word with no space in front of it.
        for line in [
            &b"size=4 name=My Movie (2026).mkv"[..],
            &b"size=4 name=track 01 = intro.flac"[..],
            &b"size=4 name=partial ending.mkv"[..],
            &b"size=4 name=S01E02 xsize=7.mkv"[..],
        ] {
            let kv = parse_header(line);
            let want = &line[line.iter().position(|&b| b == b'=').unwrap() + 1..];
            let want = &want[want.iter().position(|&b| b == b'=').unwrap() + 1..];
            assert_eq!(field_name(line).unwrap(), want, "{line:?}");
            assert_eq!(
                kv.get("name").map(String::as_str),
                Some(std::str::from_utf8(want).unwrap()),
                "{line:?}"
            );
        }
    }

    /// Round-4 torture set advZA: `=yend part=` contradicting `=ybegin part=`.
    ///
    /// The article decodes and places CORRECTLY - placement comes from
    /// `=ypart` alone - so nothing used to notice the two part numbers
    /// disagreed, and a post where BOTH were wrong would have been
    /// indistinguishable from a healthy one. Both decoders must reject it, and
    /// must reject it the SAME way, or the differential fuzz oracle is
    /// meaningless.
    #[test]
    fn a_yend_part_that_contradicts_ybegin_is_rejected_by_both_decoders() {
        let data = test_data(3_000);
        let article = encode("z.bin", 9_000, Some((2, 3)), 3_001, &data);
        // Sanity: untouched, it decodes.
        assert!(
            decode(&article).is_ok(),
            "the unmutated article must decode"
        );

        // Rewrite ONLY the trailer's part number, exactly as pynntp_evil's
        // `yend_partnum` fault does. Byte-level, not via String: a yEnc
        // payload is arbitrary binary and is NOT valid UTF-8.
        let tail = article
            .windows(6)
            .position(|w| w == b"=yend ")
            .expect("encoded article must carry a =yend trailer");
        let mut mutated = article.clone();
        let at = mutated[tail..]
            .windows(6)
            .position(|w| w == b"part=2")
            .map(|i| tail + i)
            .expect("=yend must carry part=2");
        mutated[at + 5] = b'9'; // same length, so nothing downstream shifts
        assert_ne!(mutated, article, "the mutation must change the bytes");

        let scalar = decode(&mutated);
        assert!(
            matches!(
                scalar,
                Err(YencError::PartNumberMismatch { begin: 2, end: 9 })
            ),
            "scalar decoder accepted a contradictory trailer: {scalar:?}"
        );

        let mut buf = vec![0u8; mutated.len()];
        let simd = crate::yenc_simd::decode_into(&mutated, &mut buf);
        assert!(
            matches!(
                simd,
                Err(YencError::PartNumberMismatch { begin: 2, end: 9 })
            ),
            "SIMD decoder disagreed with the oracle: {simd:?}"
        );
    }

    /// M4-63: a TRUTHFUL first `=ybegin` followed by a LYING second one.
    ///
    /// Measured on origin/main 30 Aug 2026, both decoders: the article
    /// decoded `Ok` and reported the SECOND header's identity - name
    /// `b.bin`, `file_size` 99, `end` 99 - carrying the FIRST header's
    /// payload bytes. Last-wins, on the poster's word alone. Combined
    /// with the extractor latching the first non-zero size, that is
    /// W4-11's under-declare produced inside one article rather than by
    /// arrival order across articles.
    ///
    /// Neither header outranks the other, so per the wave-4 family rule
    /// (`2b7f5495e` - a name NOMINATES, only content FINALIZES) there is
    /// nothing here strong enough to overwrite an identity, and nothing
    /// strong enough to keep one either. Both decoders refuse, and refuse
    /// IDENTICALLY, or the differential fuzz oracle is meaningless.
    ///
    /// The second header is in the BODY on purpose: the first payload
    /// line has already put the SIMD path into rapidyenc block mode, so
    /// the second header comes back through the `END_CONTROL` arm and not
    /// through the line-mode one the header-only fixture exercises. Both
    /// arms are covered here.
    #[test]
    fn a_second_ybegin_in_one_article_is_refused_by_both_decoders() {
        let data = test_data(3_000);
        let honest = encode("real.mkv", 3_000, None, 1, &data);
        assert!(decode(&honest).is_ok(), "the unmutated article must decode");

        // Splice the lying header in just before the trailer, so it lands
        // after real payload - the shape a hostile appender produces.
        let at = honest
            .windows(6)
            .position(|w| w == b"=yend ")
            .expect("encoded article must carry a =yend trailer");
        let mut body = honest[..at].to_vec();
        body.extend_from_slice(b"=ybegin line=128 size=4 name=x.bin\r\n");
        body.extend_from_slice(&honest[at..]);

        assert_eq!(
            decode(&body),
            Err(YencError::DuplicateBegin),
            "scalar decoder took a second =ybegin as an update"
        );
        let mut buf = Vec::new();
        assert_eq!(
            crate::yenc_simd::decode_into(&body, &mut buf),
            Err(YencError::DuplicateBegin),
            "SIMD decoder disagreed with the oracle"
        );

        // And the line-mode arm: a second header before any payload line.
        let mut early = b"=ybegin line=128 size=3000 name=real.mkv\r\n\
                          =ybegin line=128 size=4 name=x.bin\r\n"
            .to_vec();
        early.extend_from_slice(
            &honest[honest
                .windows(2)
                .position(|w| w == b"\r\n")
                .expect("header line must end")
                + 2..],
        );
        assert_eq!(decode(&early), Err(YencError::DuplicateBegin));
        let mut buf2 = Vec::new();
        assert_eq!(
            crate::yenc_simd::decode_into(&early, &mut buf2),
            Err(YencError::DuplicateBegin)
        );

        // Control: the SAME splice removed decodes clean, so the refusal
        // above is the second header and not the surgery around it.
        assert!(
            decode(&honest).is_ok(),
            "control: the un-spliced article must still decode"
        );
    }

    // -----------------------------------------------------------------
    // The yEnc LINE GRAMMAR rows of the wave-4 matrix (M4-76, M4-77,
    // M4-78, M4-84, M4-85, M4-87, M4-93), measured on origin/main 31 Aug
    // 2026 and all seven confirmed refusing or corrupting an article a
    // real poster produces. Every one is driven against BOTH decoders,
    // because a fix on one alone is a divergence the differential fuzz
    // target would (rightly) call a bug - and each carries the control
    // the family rule asks for: the same fixture with the trigger
    // removed, which must behave as it always did.
    // -----------------------------------------------------------------

    /// Both decoders over one body, as `(len, name, crc_verified)`.
    fn both(
        article: &[u8],
    ) -> (
        Result<(usize, String, bool), YencError>,
        Result<(usize, String, bool), YencError>,
    ) {
        let oracle = decode_checked(article).map(|(d, v)| (d.data.len(), d.name.clone(), v));
        let mut buf = Vec::new();
        let simd = crate::yenc_simd::decode_into_delegable(article, &mut buf, true)
            .map(|(m, v)| (m.len, m.name.clone(), v));
        (oracle, simd)
    }

    /// Both decoders agree, and the payload is exactly `want`.
    fn assert_both_decode(article: &[u8], want: &[u8], what: &str) {
        let dec = decode(article).unwrap_or_else(|e| panic!("{what}: oracle refused: {e}"));
        assert_eq!(dec.data, want, "{what}: oracle payload");
        let mut buf = Vec::new();
        let meta = crate::yenc_simd::decode_into(article, &mut buf)
            .unwrap_or_else(|e| panic!("{what}: SIMD refused: {e}"));
        assert_eq!(buf, want, "{what}: SIMD payload");
        assert_eq!(meta.name, dec.name, "{what}: name diverged");
        assert_eq!(meta.begin, dec.begin, "{what}: begin diverged");
        assert_eq!(meta.end, dec.end, "{what}: end diverged");
    }

    fn at(hay: &[u8], needle: &[u8]) -> usize {
        hay.windows(needle.len())
            .position(|w| w == needle)
            .unwrap_or_else(|| panic!("fixture must contain {:?}", String::from_utf8_lossy(needle)))
    }

    /// End of the line starting at `from` (past its CRLF).
    fn line_end(a: &[u8], from: usize) -> usize {
        from + at(&a[from..], b"\r\n") + 2
    }

    /// Every CRLF rewritten as a bare CR - a classic-Mac / old-tool body.
    fn cr_framed(a: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(a.len());
        let mut i = 0;
        while i < a.len() {
            if a[i] == b'\r' && a.get(i + 1) == Some(&b'\n') {
                out.push(b'\r');
                i += 2;
            } else {
                out.push(a[i]);
                i += 1;
            }
        }
        out
    }

    /// M4-76. A CR-framed article is one enormous line to a decoder that
    /// splits on `\n`: the `=yend` can never be a line of its own, so the
    /// article was refused Truncated and every byte of it lost.
    #[test]
    fn a_cr_framed_article_decodes_on_both_paths() {
        let data = test_data(4_000);
        let single = encode("cr only.bin", data.len() as u64, None, 1, &data);
        assert_both_decode(&cr_framed(&single), &data, "CR-framed single-part");

        // Multipart too - the reframing has to carry =ypart, not just the
        // header and trailer.
        let file = test_data(9_000);
        let part2 = &file[4_000..];
        let multi = encode("cr part.bin", 9_000, Some((2, 2)), 4_001, part2);
        let reframed = cr_framed(&multi);
        assert_both_decode(&reframed, part2, "CR-framed multipart");
        assert_eq!(decode(&reframed).unwrap().offset(), 4_000);

        // Control 1: the SAME article left CRLF-framed decodes identically,
        // so the reframing is what the retry rescued and not the surgery.
        assert_both_decode(&multi, part2, "control CRLF multipart");

        // Control 2: the retry must not rescue a GENUINELY truncated
        // article. Cut the trailer off, in both framings.
        let cut = &single[..at(&single, b"=yend")];
        assert_eq!(decode(cut), Err(YencError::Truncated), "CRLF, no trailer");
        assert_eq!(
            decode(&cr_framed(cut)),
            Err(YencError::Truncated),
            "CR-framed, no trailer"
        );
        let mut buf = Vec::new();
        assert_eq!(
            crate::yenc_simd::decode_into(&cr_framed(cut), &mut buf),
            Err(YencError::Truncated)
        );
    }

    /// M4-77. `=ypart` is the only declaration of a real byte range;
    /// `=ybegin` sets `end` from the file size as a single-part default.
    /// Posted in the other order, that default used to overwrite the range.
    #[test]
    fn ypart_before_ybegin_keeps_the_part_range() {
        // Part ONE of two, so the part range (1..500) and the whole-file
        // size (1000) are different numbers - a last-part fixture cannot
        // show this at all, since there end == file_size either way.
        let file = test_data(1_000);
        let part1 = &file[..500];
        let honest = encode("swap.bin", 1_000, Some((1, 2)), 1, part1);
        let h1 = line_end(&honest, 0);
        let h2 = line_end(&honest, h1);

        let mut swapped = Vec::new();
        swapped.extend_from_slice(&honest[h1..h2]); // =ypart first
        swapped.extend_from_slice(&honest[..h1]); // then =ybegin
        swapped.extend_from_slice(&honest[h2..]);

        assert_both_decode(&swapped, part1, "=ypart before =ybegin");
        let d = decode(&swapped).unwrap();
        assert_eq!((d.begin, d.end), (1, 500), "the =ypart range must survive");
        assert_eq!(d.file_size, 1_000, "and =ybegin size is still the file's");
        // Everything the honest order produces, from the swapped one.
        assert_eq!(d, decode(&honest).unwrap());

        // Control: the un-swapped fixture, which was always green.
        assert_both_decode(&honest, part1, "control spec order");
    }

    /// M4-78. A UTF-8 BOM glued to the first header by a Windows-saved or
    /// indexer-rewritten article made `=ybegin` not start the line.
    #[test]
    fn a_leading_utf8_bom_does_not_hide_the_header() {
        let data = test_data(2_048);
        let article = encode("bom.bin", data.len() as u64, None, 1, &data);
        let mut bommed = vec![0xef, 0xbb, 0xbf];
        bommed.extend_from_slice(&article);
        assert_both_decode(&bommed, &data, "BOM-prefixed article");
        assert_eq!(decode(&bommed).unwrap().name, "bom.bin");

        // Control 1: without the BOM, unchanged.
        assert_both_decode(&article, &data, "control unprefixed");

        // Control 2: only a leading BOM is skipped. A body that carries one
        // and no header at all is still MissingBegin - the strip does not
        // go looking for a header further in.
        let mut junk = vec![0xef, 0xbb, 0xbf];
        junk.extend_from_slice(b"not a header at all\r\n");
        assert_eq!(decode(&junk), Err(YencError::MissingBegin));
        let mut buf = Vec::new();
        assert_eq!(
            crate::yenc_simd::decode_into(&junk, &mut buf),
            Err(YencError::MissingBegin)
        );
    }

    /// M4-84. Payload lines after the trailer kept flowing into the decode
    /// because `seen_begin` was still true, so a body whose trailer omitted
    /// `size=`/`pcrc32=` silently grew - measured at exactly double length.
    #[test]
    fn the_first_yend_ends_the_article() {
        let data = test_data(1_200);
        let article = encode("tail.bin", data.len() as u64, None, 1, &data);
        let body = line_end(&article, 0);
        let yend = at(&article, b"=yend");

        // A gate-free trailer followed by the payload all over again, and
        // then a SECOND trailer describing the doubled length. The second
        // trailer is what makes this bite the production decoder: without
        // it rapidyenc runs off the end of the body without another
        // `\r\n=y`, which is the bare-LF END_NONE path, and that hands the
        // whole article to the oracle - so a SIMD arm that kept reading
        // past the first trailer would be masked by the oracle's own
        // answer. Measured while mutation-testing this fix, 31 Aug 2026.
        let twice = crc32fast::hash(&[&data[..], &data[..]].concat());
        let mut doubled = Vec::new();
        doubled.extend_from_slice(&article[..yend]);
        doubled.extend_from_slice(b"=yend\r\n");
        doubled.extend_from_slice(&article[body..yend]);
        doubled.extend_from_slice(
            format!("=yend size={} crc32={twice:08x}\r\n", data.len() * 2).as_bytes(),
        );
        assert_both_decode(&doubled, &data, "bare =yend then a second payload");

        // The same defect with the trailer FIRST, which is the shape that
        // reaches the production decoder's LINE-mode trailer arm rather
        // than its block-mode one - an empty article, then bytes nothing
        // declared, then a trailer that would vouch for them.
        let mut empty_then_junk = article[..body].to_vec();
        empty_then_junk.extend_from_slice(b"=yend size=0 crc32=00000000\r\n");
        empty_then_junk.extend_from_slice(&article[body..]);
        assert_both_decode(&empty_then_junk, b"", "=yend before any payload");

        // And the commoner shape: a full trailer, then a poster's signature
        // line, which is yEnc-decodable bytes to anything still reading.
        let mut signed = article.clone();
        signed.extend_from_slice(b"powered by some poster\r\n");
        assert_both_decode(&signed, &data, "trailer then a signature line");

        // Control: the same article with nothing appended.
        assert_both_decode(&article, &data, "control untouched");
    }

    /// M4-85. Both decoders required a literal SPACE after the keyword, so
    /// a tab-separated header was not a header at all and the article was
    /// dropped with MissingBegin.
    #[test]
    fn tab_separated_headers_parse_on_both_paths() {
        let file = test_data(2_000);
        let part2 = &file[1_000..];
        let crc = crc32fast::hash(part2);
        let payload = {
            let honest = encode("tabs.bin", 2_000, Some((2, 2)), 1_001, part2);
            let body = line_end(&honest, line_end(&honest, 0));
            honest[body..at(&honest, b"=yend")].to_vec()
        };
        let tabbed = |head: &str, ypart: &str, tail: &str| {
            let mut v = Vec::new();
            v.extend_from_slice(head.as_bytes());
            v.extend_from_slice(ypart.as_bytes());
            v.extend_from_slice(&payload);
            v.extend_from_slice(tail.as_bytes());
            v
        };

        let article = tabbed(
            "=ybegin\tpart=2\ttotal=2\tline=128\tsize=2000\tname=tabs.bin\r\n",
            "=ypart\tbegin=1001\tend=2000\r\n",
            &format!("=yend\tsize=1000\tpart=2\tpcrc32={crc:08x}\r\n"),
        );
        assert_both_decode(&article, part2, "tab-separated headers");
        let d = decode(&article).unwrap();
        assert_eq!(
            (d.name.as_str(), d.part, d.begin, d.end),
            ("tabs.bin", Some(2), 1_001, 2_000)
        );

        // The FIELDS really parsed, not merely the keyword: corrupt one
        // payload byte and the tab-separated pcrc32 must still refuse it.
        // Without this a decoder that skipped every tabbed field would pass
        // the test above by having no gates left to fail.
        let mut corrupt = article.clone();
        let p = line_end(&corrupt, line_end(&corrupt, 0));
        corrupt[p] = if corrupt[p] == b'A' { b'B' } else { b'A' };
        assert!(
            matches!(decode(&corrupt), Err(YencError::CrcMismatch { .. })),
            "the tabbed pcrc32 must still gate the article"
        );
        let mut buf = Vec::new();
        assert!(matches!(
            crate::yenc_simd::decode_into(&corrupt, &mut buf),
            Err(YencError::CrcMismatch { .. })
        ));

        // Control: a payload line that merely STARTS with the keyword is
        // not a header - the separator is required, not optional.
        let single = encode("plain.bin", 4, None, 1, b"abcd");
        assert_both_decode(&single, b"abcd", "control space-separated");
        assert_eq!(header_fields(b"=ybeginner line=1", b"begin", false), None);
        assert_eq!(header_fields(b"=ybegin", b"begin", false), None);
    }

    /// M4-87. On a split post `crc32` is the WHOLE FILE's CRC; the part's
    /// is `pcrc32`. Old single-part tools write only the former, and every
    /// article of such a post was refused CrcMismatch - the slot came out
    /// empty with the payload perfectly intact on the wire.
    #[test]
    fn whole_file_crc32_on_a_part_is_advisory_not_a_gate() {
        let file = test_data(2_000);
        let part2 = &file[1_000..];
        let honest = encode("wholecrc.bin", 2_000, Some((2, 2)), 1_001, part2);
        let ye = at(&honest, b"=yend");
        let trailer = |t: String| {
            let mut v = honest[..ye].to_vec();
            v.extend_from_slice(t.as_bytes());
            v
        };

        // The whole file's CRC on the part's trailer, no pcrc32.
        let whole = crc32fast::hash(&file);
        let art = trailer(format!("=yend size=1000 part=2 crc32={whole:08x}\r\n"));
        assert_both_decode(&art, part2, "whole-file crc32 on a part");
        let (oracle, simd) = both(&art);
        assert!(!oracle.unwrap().2, "and it must NOT vouch for the bytes");
        assert!(!simd.unwrap().2);

        // A `crc32` that DOES match this part still verifies it - the one
        // check the article offered is not thrown away.
        let own = crc32fast::hash(part2);
        let art = trailer(format!("=yend size=1000 part=2 crc32={own:08x}\r\n"));
        assert_both_decode(&art, part2, "part-matching crc32");
        let (oracle, simd) = both(&art);
        assert!(oracle.unwrap().2, "a matching crc32 verifies");
        assert!(simd.unwrap().2);

        // Control 1: `pcrc32` IS the part's gate and still refuses a lie.
        let art = trailer("=yend size=1000 part=2 pcrc32=deadbeef\r\n".to_string());
        assert!(matches!(decode(&art), Err(YencError::CrcMismatch { .. })));
        let mut buf = Vec::new();
        assert!(matches!(
            crate::yenc_simd::decode_into(&art, &mut buf),
            Err(YencError::CrcMismatch { .. })
        ));

        // Control 2: on a SINGLE-part post `crc32` is the article's own CRC
        // and stays fatal - the relaxation is scoped to parts.
        let single = encode("one.bin", 4, None, 1, b"abcd");
        let lying = {
            let mut v = single[..at(&single, b"=yend")].to_vec();
            v.extend_from_slice(b"=yend size=4 crc32=deadbeef\r\n");
            v
        };
        assert!(matches!(decode(&lying), Err(YencError::CrcMismatch { .. })));
        assert!(matches!(
            crate::yenc_simd::decode_into(&lying, &mut buf),
            Err(YencError::CrcMismatch { .. })
        ));
    }

    /// M4-93. The same poster bug in the size field: `=yend size=` on a
    /// split post is the PART length, and a tool that copies the file's
    /// size onto every trailer used to fail every article LengthMismatch.
    #[test]
    fn whole_file_size_on_a_part_trailer_defers_to_the_ypart_range() {
        let file = test_data(2_000);
        let part2 = &file[1_000..];
        let crc = crc32fast::hash(part2);
        let honest = encode("wholesize.bin", 2_000, Some((2, 2)), 1_001, part2);
        let ye = at(&honest, b"=yend");
        let trailer = |t: String| {
            let mut v = honest[..ye].to_vec();
            v.extend_from_slice(t.as_bytes());
            v
        };

        let art = trailer(format!("=yend size=2000 part=2 pcrc32={crc:08x}\r\n"));
        assert_both_decode(&art, part2, "whole-file size on a part trailer");

        // Control 1: a third number - neither the part's length nor the
        // file's - is still a LengthMismatch. Only the documented poster
        // bug is tolerated, not any size at all.
        let art = trailer(format!("=yend size=999 part=2 pcrc32={crc:08x}\r\n"));
        assert_eq!(
            decode(&art),
            Err(YencError::LengthMismatch {
                expected: 1_000,
                actual: 999
            })
        );
        let mut buf = Vec::new();
        assert!(matches!(
            crate::yenc_simd::decode_into(&art, &mut buf),
            Err(YencError::LengthMismatch { .. })
        ));

        // Control 2: the =ypart range is what decides instead, so a body
        // that does not fill the range it declared is still refused - the
        // trailer is ignored on the STRENGTH of that check, not instead of
        // any check.
        let short = {
            let h1 = line_end(&honest, 0);
            let mut v = honest[..h1].to_vec();
            v.extend_from_slice(b"=ypart begin=1001 end=1500\r\n");
            v.extend_from_slice(&honest[line_end(&honest, h1)..ye]);
            v.extend_from_slice(format!("=yend size=2000 part=2 pcrc32={crc:08x}\r\n").as_bytes());
            v
        };
        assert!(
            matches!(decode(&short), Err(YencError::PartGeometry { .. })),
            "a range that cannot hold the payload must still refuse"
        );
        assert!(matches!(
            crate::yenc_simd::decode_into(&short, &mut buf),
            Err(YencError::PartGeometry { .. })
        ));

        // Control 3: a part with NO `=ypart` at all has no range either,
        // so its trailer size stays fatal too. Without this the ignore
        // would fire on an article whose length NOTHING then checks - the
        // trailer is only set aside because something stronger is standing
        // in for it, and here there is nothing.
        let no_range = {
            let mut v = b"=ybegin part=2 total=2 line=128 size=2000 name=norange.bin\r\n".to_vec();
            let b = line_end(&honest, line_end(&honest, 0));
            v.extend_from_slice(&honest[b..ye]);
            v.extend_from_slice(format!("=yend size=2000 part=2 pcrc32={crc:08x}\r\n").as_bytes());
            v
        };
        assert_eq!(
            decode(&no_range),
            Err(YencError::LengthMismatch {
                expected: 1_000,
                actual: 2_000
            })
        );
        assert!(matches!(
            crate::yenc_simd::decode_into(&no_range, &mut buf),
            Err(YencError::LengthMismatch { .. })
        ));

        // Control 4: an unstated `=ybegin size` is not a figure the trailer
        // can be "quoting", so a `size=0` trailer on a 1,000-byte part is
        // still a mismatch rather than a match on two zeroes.
        let sizeless = {
            let h1 = line_end(&honest, 0);
            let mut v = b"=ybegin part=2 total=2 line=128 name=sizeless.bin\r\n".to_vec();
            v.extend_from_slice(&honest[h1..ye]);
            v.extend_from_slice(b"=yend size=0 part=2\r\n");
            v
        };
        assert!(matches!(
            decode(&sizeless),
            Err(YencError::LengthMismatch { .. })
        ));
        assert!(matches!(
            crate::yenc_simd::decode_into(&sizeless, &mut buf),
            Err(YencError::LengthMismatch { .. })
        ));

        // Control 5: a SINGLE-part post has no range to fall back on, so
        // its trailer size stays fatal.
        let single = encode("one.bin", 4, None, 1, b"abcd");
        let lying = {
            let mut v = single[..at(&single, b"=yend")].to_vec();
            v.extend_from_slice(b"=yend size=4000 crc32=00000000\r\n");
            v
        };
        assert!(matches!(
            decode(&lying),
            Err(YencError::LengthMismatch { .. })
        ));
        assert!(matches!(
            crate::yenc_simd::decode_into(&lying, &mut buf),
            Err(YencError::LengthMismatch { .. })
        ));
    }
}
