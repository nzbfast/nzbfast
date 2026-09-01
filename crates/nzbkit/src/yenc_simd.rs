//! SIMD yEnc decoder - rapidyenc (vendor/rapidyenc) via FFI.
//!
//! Drop-in replacement for [`crate::yenc::decode`]: same `Decoded` result,
//! same error cases, differentially tested against that oracle. The shape
//! is dictated by the yEnc article layout: header lines (`=ybegin` / `=ypart`) are
//! parsed in ordinary code, the payload region is fed to
//! `rapidyenc_decode_incremental` - which does the yEnc unescaping AND the
//! NNTP dot-unstuffing in one SIMD pass and stops at the `\r\n=y` end
//! sequence - then the `=yend` trailer is parsed in ordinary code again.
//! CRC32 comes from rapidyenc's PMULL/CRC-instruction kernels.
//!
//! Known (unreachable-in-practice) deviations from the oracle, both only for
//! malformed input that our NNTP layer never produces:
//! - a terminating `\r\n.\r\n` inside the body ends decoding here, whereas the
//!   oracle would decode the lone `.` as payload (per its contract the
//!   terminator is stripped before `decode` is called);
//! - a lone `=` at the very end of a payload line is ignored by the oracle
//!   but consumes the following CR in rapidyenc. Valid yEnc never ends a
//!   line with a bare `=`;
//! - MIXED line endings inside one body (some CRLF, some bare LF): rapidyenc
//!   only treats `\r\n` as a line break, so after a bare LF it neither stops
//!   at a `=y…` control line nor unstuffs a leading dot, while the oracle
//!   (which splits on `\n`) does both. A wholly bare-LF body IS handled - it
//!   takes the END_NONE scalar fallback below - and closing the mixed case
//!   would cost a full extra scan of every article on the hot path to catch
//!   a shape no poster produces. The length/CRC gates still fire, so it is a
//!   rejected article, not silent corruption.
//!
//! The first two of those are reachable from a CR-FRAMED body too, since
//! 31 Aug 2026: both decoders retry such a body on the CRLF rewrite of
//! itself (M4-76, `yenc::cr_framed_to_crlf`), and a `\r.\r` or a `\r`-ended
//! payload line only BECOMES a line once that rewrite has happened. Same
//! two deviations, same reason they are unreachable from the wire - the
//! NNTP layer strips the terminator and dot-stuffs every payload line - so
//! the differential fuzz target judges its guard over the reframed bytes as
//! well as the raw ones. Measured while landing the retry, not predicted.

use std::ffi::{c_int, c_void};
use std::sync::Once;

use crate::yenc::{Decoded, Meta, YencError, field_hex, field_name, field_u64};

// SAFETY: these declarations must match the C definitions exported by the
// vendored rapidyenc library (vendor/rapidyenc, see module doc). Pointer
// contracts are documented and upheld at each call site below.
unsafe extern "C" {
    fn rapidyenc_decode_init();
    fn rapidyenc_crc_init();
    /// Returns RapidYencDecoderEnd (0 = none, 1 = `\r\n=y` found, 2 =
    /// `\r\n.\r\n` found). `src`/`dest` are advanced past what was
    /// consumed/written; `state` is the RapidYencDecoderState scan state.
    fn rapidyenc_decode_incremental(
        src: *mut *const c_void,
        dest: *mut *mut c_void,
        src_length: usize,
        state: *mut c_int,
    ) -> c_int;
    fn rapidyenc_crc(src: *const c_void, src_length: usize, init_crc: u32) -> u32;
    fn rapidyenc_crc_combine(crc1: u32, crc2: u32, length2: u64) -> u32;
    fn rapidyenc_crc_zeros(init_crc: u32, length: u64) -> u32;
    fn rapidyenc_decode_kernel() -> c_int;
    fn rapidyenc_crc_kernel() -> c_int;
}

/// RYDEC_STATE_CRLF - "previous bytes were a line break", the correct state
/// at any line start (and rapidyenc's own default).
const STATE_CRLF: c_int = 0;
const END_CONTROL: c_int = 1; // \r\n=y seen
const END_ARTICLE: c_int = 2; // \r\n.\r\n seen

static INIT: Once = Once::new();

fn init() {
    // SAFETY: argumentless FFI initialisers, nothing to dereference; the Once
    // serialises the pair so rapidyenc is initialised exactly once before any
    // other entry point (every public fn in this module calls init() first).
    INIT.call_once(|| unsafe {
        rapidyenc_decode_init();
        rapidyenc_crc_init();
    });
}

/// (decode_kernel, crc_kernel) as RYKERN_* values - for diagnostics/bench.
pub fn kernels() -> (i32, i32) {
    init();
    // SAFETY: argumentless FFI queries; init() has run on the line above.
    unsafe { (rapidyenc_decode_kernel(), rapidyenc_crc_kernel()) }
}

/// CRC32 of `data1 ++ data2` given the two parts' CRCs - CRC32 composes
/// over concatenation, which is what lets live verify hold boundary-block
/// fragments as 4-byte CRCs instead of block-sized buffers (B1).
pub fn crc32_combine(crc1: u32, crc2: u32, len2: u64) -> u32 {
    init();
    // SAFETY: by-value arguments only, nothing dereferenced; init() has run
    // on the line above.
    unsafe { rapidyenc_crc_combine(crc1, crc2, len2) }
}

/// CRC32 of `data ++ [0u8; len]` given CRC32(data) - extends a CRC over
/// zero padding in O(log len) (PAR2 IFSC checksums cover the block
/// zero-padded to block_size).
pub fn crc32_zeros(crc: u32, len: u64) -> u32 {
    init();
    // SAFETY: by-value arguments only, nothing dereferenced; init() has run
    // on the line above.
    unsafe { rapidyenc_crc_zeros(crc, len) }
}

/// Decode a full article body, SIMD path. Semantics identical to
/// [`crate::yenc::decode`]. Allocates a fresh payload buffer - hot
/// callers should use [`decode_into`] with a pooled buffer instead.
pub fn decode(body: &[u8]) -> Result<Decoded, YencError> {
    let mut data = Vec::with_capacity(body.len());
    let m = decode_into(body, &mut data)?;
    Ok(Decoded {
        name: m.name,
        file_size: m.file_size,
        part: m.part,
        begin: m.begin,
        end: m.end,
        data,
        encryption: m.encryption,
    })
}

/// Decode a full article body into `out` (cleared first), returning
/// everything but the payload. `out` is meant to be a recycled buffer
/// (see [`crate::pool::BufPool`]); its existing capacity absorbs the
/// decoded bytes, so the hot path does no per-article payload allocation.
pub fn decode_into(body: &[u8], out: &mut Vec<u8>) -> Result<Meta, YencError> {
    decode_into_delegable(body, out, true).map(|(m, _)| m)
}

/// What an article's decode established about its own integrity.
///
/// The CRC is carried as a VALUE rather than a bool so a caller can reuse
/// it instead of hashing the same bytes again: for a RAR5 STORE span that
/// is byte-for-byte one article, the verified pcrc32 already IS the CRC
/// the stored-file composition needs (measured on a real corpus: 98.75%
/// of STORE payload bytes qualify). `Option<u32>` also makes an
/// unverified CRC unrepresentable, where a separate `(bool, u32)` pair
/// could be misread.
#[derive(Debug, Clone, Copy, Default)]
pub struct DecodeIntegrity {
    /// The article carried a pcrc32, it was calculated, and it matched.
    pub crc_checked: bool,
    /// That verified CRC32, when the decoder has it to hand. The SIMD
    /// path always does. The bare-LF scalar fallback enforces the CRC
    /// internally without surfacing the value, so it reports
    /// `crc_checked` with None here and callers hash for themselves -
    /// correct, just not free.
    pub verified_article_crc: Option<u32>,
}

/// [`decode_into`] with the whole-article CRC made optional (M32 perf:
/// it is 14% of single-core CPU). Pass `verify_crc = false` ONLY when
/// integrity is delegated - the caller has arranged for every byte to
/// be full-MD5-verified downstream (live verify, fast mode OFF, slot
/// matched to a PAR2 file). Returns `(meta, crc_checked)`;
/// `crc_checked` is false when the check was skipped OR the article
/// carried no pcrc32 - feed such spans to the verifier as UNtrusted.
pub fn decode_into_delegable(
    body: &[u8],
    out: &mut Vec<u8>,
    verify_crc: bool,
) -> Result<(Meta, bool), YencError> {
    decode_into_integrity(body, out, verify_crc).map(|(m, i)| (m, i.crc_checked))
}

/// [`decode_into_delegable`], keeping the verified CRC value.
pub fn decode_into_integrity(
    body: &[u8],
    out: &mut Vec<u8>,
    verify_crc: bool,
) -> Result<(Meta, DecodeIntegrity), YencError> {
    decode_into_integrity_opts(body, out, verify_crc, crate::yencrypt::wire_enabled())
}

/// [`decode_into_integrity`] with the body-encryption capture arm
/// explicit - the in-process seam the unit tests use, same reasoning as
/// `yenc::decode_checked_opts`.
pub(crate) fn decode_into_integrity_opts(
    body: &[u8],
    out: &mut Vec<u8>,
    verify_crc: bool,
    enc_ok: bool,
) -> Result<(Meta, DecodeIntegrity), YencError> {
    match decode_framed(body, out, verify_crc, enc_ok) {
        // M4-76: the same CR-framed retry the oracle does, on the same two
        // errors and for the same reasons - see yenc::decode_checked. Both
        // decoders must answer identically or the differential fuzz oracle
        // is meaningless.
        Err(e @ (YencError::MissingBegin | YencError::Truncated)) => {
            match crate::yenc::cr_framed_to_crlf(body) {
                Some(reframed) => decode_framed(&reframed, out, verify_crc, enc_ok),
                None => Err(e),
            }
        }
        other => other,
    }
}

/// [`decode_into_integrity`] over a body already framed with LF or CRLF.
fn decode_framed(
    body: &[u8],
    out: &mut Vec<u8>,
    verify_crc: bool,
    enc_ok: bool,
) -> Result<(Meta, DecodeIntegrity), YencError> {
    init();
    out.clear();
    // M4-78: a UTF-8 BOM glued to the first header, stripped at the start of
    // the body only. Same rule, same one function, as the oracle.
    let body = crate::yenc::strip_bom(body);

    let mut name = String::new();
    let mut file_size: u64 = 0;
    let mut part: Option<u32> = None;
    let mut begin: u64 = 1;
    let mut end: u64 = 0;
    let mut trailer = crate::yenc::Trailer::default();
    let mut seen_begin = false;
    let mut seen_yend = false;
    let mut seen_ypart = false;
    let mut encryption = None;
    let data = out;

    let mut pos = 0usize;
    let mut in_body = false;

    while pos < body.len() {
        if !in_body {
            // ---- line mode: header parsing, oracle-identical ----
            let (line_start, next) = match memchr_nl(&body[pos..]) {
                Some(i) => (pos, pos + i + 1),
                None => (pos, body.len()),
            };
            let raw_end = if next > line_start && body[next - 1] == b'\n' {
                next - 1
            } else {
                next
            };
            let mut line = &body[line_start..raw_end];
            if line.last() == Some(&b'\r') {
                line = &line[..line.len() - 1];
            }
            // NNTP unstuffing for header MATCHING only (payload lines re-enter
            // block mode at the raw line start and let rapidyenc unstuff):
            // exactly one leading dot comes off, as the oracle and rapidyenc
            // both do, so a stuffed `.=ybegin`/`.=yend` is still recognised.
            if line.first() == Some(&b'.') {
                line = &line[1..];
            }
            if line.is_empty() {
                pos = next;
                continue;
            }
            if let Some(h) = crate::yenc::header_fields(line, b"begin", false) {
                // M4-63: a second header contradicts the first rather than
                // updating it - refuse, exactly as the oracle does. See
                // YencError::DuplicateBegin in yenc.rs.
                if seen_begin {
                    return Err(YencError::DuplicateBegin);
                }
                seen_begin = true;
                let h = h.as_ref();
                if let Some(v) = field_name(h) {
                    name = String::from_utf8_lossy(v).into_owned();
                }
                file_size = field_u64(h, b"size").unwrap_or(0);
                part = field_u64(h, b"part")
                    .filter(|n| *n <= u64::from(u32::MAX))
                    .map(|n| n as u32);
                // M4-77: never overwrite a range `=ypart` has already
                // declared - see the oracle's twin for the whole argument.
                if !seen_ypart {
                    end = file_size;
                }
                pos = next;
            } else if let Some(h) = crate::yenc::header_fields(line, b"part", false) {
                seen_ypart = true;
                let h = h.as_ref();
                // Clamp `begin` to its 1-based floor: a hostile `begin=0`
                // would underflow Meta::offset() to u64::MAX (see yenc.rs).
                begin = field_u64(h, b"begin").filter(|&b| b >= 1).unwrap_or(1);
                end = field_u64(h, b"end").unwrap_or(0);
                pos = next;
            } else if let Some(h) = crate::yenc::header_fields(line, b"end", true) {
                seen_yend = true;
                // A bare `=yend` carries no size/crc - nothing to gate on, but
                // it still proves the article was not cut short.
                let h = h.as_ref();
                trailer = crate::yenc::Trailer {
                    size: field_u64(h, b"size"),
                    pcrc32: field_hex(h, b"pcrc32"),
                    crc32: field_hex(h, b"crc32"),
                    part: field_u64(h, b"part")
                        .filter(|n| *n <= u64::from(u32::MAX))
                        .map(|n| n as u32),
                };
                // M4-84: the first trailer ends the article on this path too.
                // See the oracle's twin. This also retires the older rule
                // that a SECOND, bare `=yend` cleared the gates a fielded
                // one had set: there is no second trailer to reach now, on
                // either decoder, so the two still agree on a multi-trailer
                // body - they simply agree on the first one.
                break;
            } else if enc_ok && let Some(h) = crate::yenc::header_fields(line, b"encryption", false)
            {
                // Body-encryption spike: capture, never decode as payload.
                // ONE parser with the scalar oracle (yencrypt.rs), and the
                // same refusal on malformed fields - the differential
                // fuzzer compares acceptance, so the arms must agree.
                encryption = Some(
                    crate::yencrypt::EncHeader::parse_fields(h.as_ref())
                        .ok_or(YencError::BadEncryption)?,
                );
                pos = next;
            } else if seen_begin {
                // First payload line: switch to SIMD block mode from the raw
                // line start (dot-unstuffing needs the untouched bytes).
                in_body = true;
            } else {
                pos = next;
            }
        } else {
            // ---- payload mode: one rapidyenc pass over the rest ----
            let chunk = &body[pos..];
            data.reserve(chunk.len());
            // SAFETY: data.len() <= capacity always holds for a Vec, so the
            // offset lands at the start of the spare capacity, within (or one
            // past the end of) the same allocation.
            let dest_base = unsafe { data.as_mut_ptr().add(data.len()) };
            let mut src: *const c_void = chunk.as_ptr().cast();
            let mut dst: *mut c_void = dest_base.cast();
            let mut state: c_int = STATE_CRLF;
            // SAFETY: src covers exactly chunk.len() readable bytes of `body`;
            // the reserve() above guarantees chunk.len() writable bytes at
            // dest_base, enough because decode is non-expanding (written <=
            // input, re-asserted below); src/dst/state are live locals.
            let endseq = unsafe {
                rapidyenc_decode_incremental(&mut src, &mut dst, chunk.len(), &mut state)
            };
            let written = dst as usize - dest_base as usize;
            // Hard assert (not debug_assert, which is compiled out of release):
            // set_len past capacity is heap corruption. The invariant (decode is
            // non-expanding, so written <= input) holds, but this is the last
            // line of defence over the FFI boundary, so keep it in release too.
            assert!(
                written <= chunk.len(),
                "rapidyenc decoded {written} bytes from {} input (would overflow the output buffer)",
                chunk.len()
            );
            // SAFETY: written <= chunk.len() <= the spare capacity reserved
            // above (enforced by the assert), and rapidyenc has initialised
            // those `written` bytes.
            unsafe { data.set_len(data.len() + written) };
            let consumed = src as usize - chunk.as_ptr() as usize;
            pos += consumed;

            match endseq {
                END_CONTROL => {
                    // src points just past the 'y' of "\r\n=y". Reconstruct
                    // the control line ("=y" + remainder) and parse it in
                    // line mode.
                    let rest_end = memchr_nl(&body[pos..])
                        .map(|i| pos + i)
                        .unwrap_or(body.len());
                    let mut rest = &body[pos..rest_end];
                    if rest.last() == Some(&b'\r') {
                        rest = &rest[..rest.len() - 1];
                    }
                    if let Some(h) = rest
                        .strip_prefix(b"end")
                        .and_then(|t| crate::yenc::header_tail(t, true))
                    {
                        seen_yend = true;
                        let h = h.as_ref();
                        trailer = crate::yenc::Trailer {
                            size: field_u64(h, b"size"),
                            pcrc32: field_hex(h, b"pcrc32"),
                            crc32: field_hex(h, b"crc32"),
                            part: field_u64(h, b"part")
                                .filter(|n| *n <= u64::from(u32::MAX))
                                .map(|n| n as u32),
                        };
                        // M4-84: the first trailer ends the article. Reached
                        // through block mode rather than line mode, and the
                        // same rule either way - the oracle's twin carries
                        // the argument.
                        break;
                    } else if let Some(h) = rest
                        .strip_prefix(b"begin")
                        .and_then(|t| crate::yenc::header_tail(t, false))
                    {
                        // The same M4-63 refusal as the line-mode arm above.
                        // This is the arm a real second header reaches: the
                        // first payload line has already put us in block
                        // mode, so rapidyenc stops at the `\r\n=y` and hands
                        // the control line back here.
                        if seen_begin {
                            return Err(YencError::DuplicateBegin);
                        }
                        seen_begin = true;
                        let h = h.as_ref();
                        if let Some(v) = field_name(h) {
                            name = String::from_utf8_lossy(v).into_owned();
                        }
                        file_size = field_u64(h, b"size").unwrap_or(0);
                        part = field_u64(h, b"part")
                            .filter(|n| *n <= u64::from(u32::MAX))
                            .map(|n| n as u32);
                        // M4-77: `=ypart` may have already declared the real
                        // range - see the oracle's twin.
                        if !seen_ypart {
                            end = file_size;
                        }
                    } else if let Some(h) = rest
                        .strip_prefix(b"part")
                        .and_then(|t| crate::yenc::header_tail(t, false))
                    {
                        // Set it here too, exactly as the line-mode twin
                        // does. `seen_ypart` is read at one site - the
                        // `check_part_geometry` short-circuit - so leaving
                        // it false silently DISABLED the geometry check on
                        // the production decoder whenever `=ypart` arrived
                        // after the first payload line, making the SIMD
                        // path strictly more permissive than its own
                        // scalar oracle (and a latent panic for the
                        // differential fuzz target, which compares
                        // acceptance).
                        seen_ypart = true;
                        let h = h.as_ref();
                        // Same 1-based clamp as the line-mode arm above and the
                        // oracle (yenc.rs): `begin=0` must not underflow offset().
                        begin = field_u64(h, b"begin").filter(|&b| b >= 1).unwrap_or(1);
                        end = field_u64(h, b"end").unwrap_or(0);
                    } else if enc_ok
                        && let Some(h) = rest
                            .strip_prefix(b"encryption")
                            .and_then(|t| crate::yenc::header_tail(t, false))
                    {
                        // The mid-payload spelling of the spike arm above -
                        // rapidyenc stops at any `\r\n=y`, so a nonconforming
                        // poster's late `=yencryption` lands here. Same
                        // parser, same refusal, same last-one-wins as the
                        // oracle, which handles every position in one arm.
                        encryption = Some(
                            crate::yencrypt::EncHeader::parse_fields(h.as_ref())
                                .ok_or(YencError::BadEncryption)?,
                        );
                    } else {
                        // Not a yEnc control line, just a payload line that
                        // happens to start with the `=y` escape (`=y` decodes
                        // to 0x0F). rapidyenc stops at ANY `\r\n=y`, so without
                        // this arm the whole line's bytes were dropped on the
                        // floor - silent truncation the oracle does not do, and
                        // one a hostile poster could hide behind a size=/crc32=
                        // computed over the truncated output. The oracle's
                        // `else if seen_begin { decode_line(..) }` fall-through
                        // decodes it as payload, so do exactly that, over the
                        // reconstructed `=y` ++ rest (the `=y` is itself one
                        // escape pair and cannot be decoded separately).
                        // Cold path: reached only after rapidyenc has stopped.
                        let mut line = Vec::with_capacity(rest.len() + 2);
                        line.extend_from_slice(b"=y");
                        line.extend_from_slice(rest);
                        crate::yenc::decode_line(&line, data);
                    }
                    pos = if rest_end < body.len() {
                        rest_end + 1 // skip the '\n'
                    } else {
                        body.len()
                    };
                    in_body = false;
                }
                END_ARTICLE => {
                    // NNTP terminator inside the body - treat as end of input.
                    pos = body.len();
                }
                _ => {
                    // END_NONE: rapidyenc consumed the whole buffer without
                    // hitting `\r\n=y`. That means the `=yend` trailer wasn't
                    // CRLF-preceded - a bare-LF trailer, which our NNTP layer
                    // can deliver (`read_multiline_into` appends body lines
                    // raw, preserving wire endings, and even accepts a bare
                    // `.\n` terminator). rapidyenc has just decoded `=yend …`
                    // AS payload, so `expected_len`/`expected_crc` were never
                    // parsed and the length + CRC guards below would be
                    // silently skipped - a corrupt segment would return Ok.
                    // Re-decode on the scalar oracle, which splits on `\n`,
                    // stops at `=yend` regardless of line ending, and enforces
                    // both guards. A well-formed CRLF article never reaches
                    // here, so the hot path keeps the SIMD speed.
                    debug_assert_eq!(pos, body.len());
                    let (d, crc_verified) = crate::yenc::decode_checked_opts(body, enc_ok)?;
                    data.clear();
                    data.extend_from_slice(&d.data);
                    // The scalar oracle enforced length + CRC itself. Report
                    // the REAL crc_checked: a bare-LF article that carried no
                    // pcrc32/crc32 was NOT verified, so it must fall through to
                    // the stronger MD5 settle read-back downstream rather than
                    // being marked decoder-vouched (a same-CRC/different-MD5
                    // swap would otherwise slip through). Honour verify_crc too
                    // for parity with the normal SIMD path.
                    return Ok((
                        Meta {
                            name: d.name,
                            file_size: d.file_size,
                            part: d.part,
                            begin: d.begin,
                            end: d.end,
                            len: data.len(),
                            encryption: d.encryption,
                        },
                        DecodeIntegrity {
                            crc_checked: crc_verified && verify_crc,
                            // The oracle checked it without handing back
                            // the value; no reuse from this rare path.
                            verified_article_crc: None,
                        },
                    ));
                }
            }
        }
    }

    if !seen_begin {
        return Err(YencError::MissingBegin);
    }
    // Same invariant the scalar decoder enforces (yenc.rs): no `=yend` means
    // the article was cut short. This path can exit the loop WITHOUT ever
    // entering payload mode - a body truncated right after the header lines
    // sets `pos = next` past the end, so rapidyenc is never invoked, END_NONE
    // never fires, and the scalar fallback that carries this check is never
    // consulted. It then returned Ok with 0 bytes: the segment counted as
    // delivered, the preallocated file kept the range as sparse zeros, and a
    // PAR2-less job completed silently corrupt. Both decoders must agree here,
    // or the differential fuzz oracle is meaningless.
    if !seen_yend {
        return Err(YencError::Truncated);
    }
    // Same trailer-consistency check as the scalar oracle, in the same
    // position: both decoders must agree or the differential fuzz oracle is
    // meaningless. Placement never uses either part number, so this only ever
    // turns a silently-inconsistent article into a named error.
    if let (Some(b), Some(e)) = (part, trailer.part)
        && b != e
    {
        return Err(YencError::PartNumberMismatch { begin: b, end: e });
    }
    // M4-87 / M4-93: which trailer fields may decide this article. ONE
    // function, shared with the oracle, for the reason `check_part_geometry`
    // is - see yenc::trailer_gates.
    let gates = crate::yenc::trailer_gates(
        &trailer,
        &crate::yenc::Declared {
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
    // Same test, same shared implementation as the scalar oracle.
    crate::yenc::check_part_geometry(seen_ypart, begin, end, data.len() as u64)?;
    let mut crc_checked = false;
    let mut verified_article_crc = None;
    // NZBFAST_SKIP_PCRC=1 is the loopback-rig MEASUREMENT switch -
    // it force-skips regardless of delegation (bench only; the CRC
    // is the sole guard on PAR2-less sets - bare-LF trailer bug).
    static SKIP_PCRC: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let force_skip =
        *SKIP_PCRC.get_or_init(|| std::env::var("NZBFAST_SKIP_PCRC").is_ok_and(|v| v == "1"));
    if let Some(header) = gates.crc {
        if verify_crc && !force_skip {
            // SAFETY: reads exactly data.len() bytes from the live `data`
            // buffer; init() ran at function entry.
            let computed = unsafe { rapidyenc_crc(data.as_ptr().cast(), data.len(), 0) };
            if computed != header {
                return Err(YencError::CrcMismatch { computed, header });
            }
            crc_checked = true;
            // Equal to `header` by the check just above, over exactly the
            // decoded bytes in `data`.
            verified_article_crc = Some(computed);
        }
    } else if let Some(advisory) = gates.crc_advisory
        && verify_crc
        && !force_skip
    {
        // M4-87: a whole-file `crc32` on a part trailer may not refuse the
        // article, but a match still verifies these bytes. Same answer as
        // the oracle's twin, which is what the differential fuzzer compares.
        // SAFETY: as above.
        let computed = unsafe { rapidyenc_crc(data.as_ptr().cast(), data.len(), 0) };
        if computed == advisory {
            crc_checked = true;
            verified_article_crc = Some(computed);
        }
    }

    Ok((
        Meta {
            name,
            file_size,
            // M4-59: the same normalization as the scalar oracle, in the
            // same position and through the same function - an
            // out-of-spec `part=0` declares no part. The two decoders
            // are held equal by the differential fuzzer, so this cannot
            // be spelled twice or moved on one side alone.
            part: crate::yenc::declared_part(part),
            begin,
            end,
            len: data.len(),
            encryption,
        },
        DecodeIntegrity {
            crc_checked,
            verified_article_crc,
        },
    ))
}

#[inline]
fn memchr_nl(haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yenc;

    /// Deterministic byte soup covering all 256 values (same pattern as the
    /// oracle's tests).
    fn test_data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    fn assert_matches_oracle(article: &[u8]) {
        let oracle = yenc::decode(article);
        let simd = decode(article);
        assert_eq!(oracle, simd, "SIMD result diverged from oracle");
    }

    #[test]
    fn round_trip_differential_sizes() {
        for &len in &[1usize, 5, 128, 4096, 700_000] {
            let data = test_data(len);

            // Single-part.
            let art = yenc::encode("diff test.bin", len as u64, None, 1, &data);
            let dec = decode(&art).expect("simd decode single");
            assert_eq!(dec, yenc::decode(&art).unwrap(), "single-part len={len}");
            assert_eq!(dec.data, data);
            assert_eq!(dec.part, None);

            // Multi-part with =ypart: pretend this is part 2 of a bigger file.
            let begin = 1_000_001u64;
            let art2 = yenc::encode(
                "diff part.bin",
                begin - 1 + len as u64,
                Some((2, 3)),
                begin,
                &data,
            );
            let dec2 = decode(&art2).expect("simd decode part");
            assert_eq!(dec2, yenc::decode(&art2).unwrap(), "multi-part len={len}");
            assert_eq!(dec2.data, data);
            assert_eq!(dec2.part, Some(2));
            assert_eq!(dec2.begin, begin);
            assert_eq!(dec2.offset(), begin - 1);
        }
    }

    #[test]
    fn survives_nntp_dot_stuffing() {
        for &len in &[5_000usize, 50_000] {
            let data = test_data(len);
            let article = yenc::encode("dots.bin", len as u64, None, 1, &data);
            // Simulate the NNTP wire: any line starting with '.' is doubled
            // (same transform as the oracle's test).
            let mut stuffed = Vec::new();
            for line in article.split_inclusive(|&b| b == b'\n') {
                if line.first() == Some(&b'.') {
                    stuffed.push(b'.');
                }
                stuffed.extend_from_slice(line);
            }
            let dec = decode(&stuffed).unwrap();
            assert_eq!(dec.data, data);
            assert_matches_oracle(&stuffed);
        }
    }

    #[test]
    fn detects_corruption_same_as_oracle() {
        let data = test_data(5_000);
        let mut article = yenc::encode("c.bin", data.len() as u64, None, 1, &data);
        let payload_start = article.windows(2).position(|w| w == b"\r\n").unwrap() + 2;
        article[payload_start] = if article[payload_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        match decode(&article) {
            Err(YencError::CrcMismatch { computed, header }) => {
                // Oracle must agree byte-for-byte on the error too.
                assert_eq!(
                    yenc::decode(&article),
                    Err(YencError::CrcMismatch { computed, header })
                );
            }
            other => panic!("expected CRC mismatch, got {other:?}"),
        }
    }

    #[test]
    fn delegable_decode_skips_crc_only_when_told() {
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let mut art = crate::yenc::encode("f.bin", 40_000, Some((1, 1)), 1, &payload);
        // Corrupt one payload byte mid-article (past the header lines).
        let mid = art.len() / 2;
        art[mid] ^= 0x01;
        let mut out = Vec::new();
        // Default path: the corruption is caught by the article CRC.
        assert!(matches!(
            decode_into(&art, &mut out),
            Err(YencError::CrcMismatch { .. })
        ));
        // Delegated path: decode succeeds, but the span is flagged as
        // NOT crc-checked so the caller feeds it untrusted (full MD5
        // downstream catches the corruption instead).
        let (meta, checked) = decode_into_delegable(&art, &mut out, false).unwrap();
        assert!(!checked);
        assert_eq!(meta.len, 40_000);
        // And verify_crc=true through the delegable API still enforces.
        assert!(decode_into_delegable(&art, &mut out, true).is_err());
    }

    /// The whole reuse story rests on rapidyenc's article CRC and
    /// `crc32fast::hash` being the SAME function over the same bytes. They
    /// are both CRC-32/ISO-HDLC, but nothing in the type system says so,
    /// and if they ever diverge the extractor would compose verified
    /// nonsense and demote clean jobs (or, worse, agree by accident on the
    /// short buffers a smaller test would use). Checked across sizes,
    /// including the empty and single-byte edges and a payload spanning
    /// many SIMD blocks.
    #[test]
    fn the_verified_article_crc_is_the_crc32_the_extractor_composes() {
        for len in [0usize, 1, 2, 15, 16, 17, 1024, 65_535, 65_536, 300_000] {
            let payload = test_data(len);
            let art = yenc::encode("c.bin", len as u64, Some((1, 1)), 1, &payload);
            let mut out = Vec::new();
            let (meta, integrity) = decode_into_integrity(&art, &mut out, true).unwrap();
            assert_eq!(meta.len, len);
            assert_eq!(out, payload, "len {len}: decoded bytes differ");
            assert_eq!(
                integrity.verified_article_crc,
                Some(crc32fast::hash(&out)),
                "len {len}: the article CRC is not the CRC the composition uses"
            );
        }
    }

    /// Delegation and the scalar fallback must both report NO reusable
    /// value, or the extractor would compose from a CRC nobody checked.
    #[test]
    fn an_unverified_article_offers_no_crc_to_reuse() {
        let payload = test_data(9_000);
        let art = yenc::encode("d.bin", 9_000, Some((1, 1)), 1, &payload);
        let mut out = Vec::new();

        // Delegated: the check was skipped, so there is nothing to vouch.
        let (_, integrity) = decode_into_integrity(&art, &mut out, false).unwrap();
        assert!(!integrity.crc_checked);
        assert_eq!(integrity.verified_article_crc, None);

        // Bare-LF: the scalar oracle enforces the CRC internally but does
        // not surface the value. Checked, yet nothing to reuse.
        let lf: Vec<u8> = art.iter().copied().filter(|&b| b != b'\r').collect();
        let (_, integrity) = decode_into_integrity(&lf, &mut out, true).unwrap();
        assert!(integrity.crc_checked, "bare-LF must still enforce the CRC");
        assert_eq!(integrity.verified_article_crc, None);
    }

    #[test]
    fn bare_lf_trailer_enforces_crc() {
        // Some servers/posters deliver bodies with bare-LF line endings, and
        // the NNTP layer passes them through raw. rapidyenc only stops at a
        // literal `\r\n=y`, so a bare-LF `=yend` used to be decoded as payload
        // - skipping the length + CRC guards and returning Ok with garbage
        // appended. The decoder must instead agree with the scalar oracle:
        // correct bytes on a good article, rejection on a corrupt one.
        let data = test_data(5_000);
        let crlf = yenc::encode("bare-lf.bin", data.len() as u64, None, 1, &data);
        // Encoded yEnc never contains a raw 0x0D (it is escaped as `=M`), so
        // dropping every '\r' yields a valid, purely LF-terminated article -
        // one with no `\r\n=y` anywhere, which forces the END_NONE path.
        let lf: Vec<u8> = crlf.iter().copied().filter(|&b| b != b'\r').collect();

        // Well-formed bare-LF article: correct payload, identical to oracle.
        let dec = decode(&lf).expect("bare-LF decode");
        assert_eq!(dec.data, data, "bare-LF payload wrong (garbage appended?)");
        assert_matches_oracle(&lf);

        // Corrupt one payload byte: the guard must now fire. Before the fix
        // this returned Ok (CRC never checked); now it matches the oracle's
        // rejection byte-for-byte.
        let mut bad = lf.clone();
        let first_payload = bad.iter().position(|&b| b == b'\n').unwrap() + 1;
        bad[first_payload] = if bad[first_payload] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert!(
            matches!(
                decode(&bad),
                Err(YencError::CrcMismatch { .. }) | Err(YencError::LengthMismatch { .. })
            ),
            "corrupt bare-LF article must be rejected, got {:?}",
            decode(&bad)
        );
        assert_matches_oracle(&bad);
    }

    #[test]
    fn unknown_control_line_decodes_as_payload() {
        // rapidyenc stops at ANY `\r\n=y`, not just `\r\n=yend`. A payload line
        // that happens to begin with the `=y` escape pair (0x0F) used to fall
        // through every header branch and be DISCARDED - the article decoded
        // short, silently. The oracle decodes it as payload; so must we.
        let body =
            b"=ybegin line=128 size=8 name=a.bin\r\nAAAA\r\n=yzzzz\r\nBBBB\r\n=yend\r\n".as_slice();
        let simd = decode(body).expect("simd decode");
        let oracle = yenc::decode(body).expect("oracle decode");
        assert_eq!(
            simd, oracle,
            "SIMD diverged from oracle on a `=y` payload line"
        );
        // 4 + 5 + 4: the middle line contributes 0x0F ('=y') then four 'z'.
        assert_eq!(
            simd.data,
            vec![23, 23, 23, 23, 15, 80, 80, 80, 80, 24, 24, 24, 24],
            "the `=y…` line's bytes were dropped"
        );
    }

    #[test]
    fn crafted_checksum_over_truncated_output_is_rejected() {
        // The dangerous shape: a hostile poster sets size=/crc32= to match the
        // TRUNCATED decode, so every gate passed and the decoder returned Ok
        // with crc_checked=true - vouching for bytes that were missing the
        // whole `=y…` line. With the line decoded as payload the length gate
        // now fires, and the oracle agrees.
        let truncated: [u8; 8] = [23, 23, 23, 23, 24, 24, 24, 24];
        let crc = crc32fast::hash(&truncated);
        let body = format!(
            "=ybegin line=128 size=8 name=a.bin\r\nAAAA\r\n=yzzzz\r\nBBBB\r\n=yend size=8 crc32={crc:08x}\r\n"
        );
        let body = body.as_bytes();
        let mut out = Vec::new();
        let simd = decode_into_delegable(body, &mut out, true);
        assert!(
            matches!(simd, Err(YencError::LengthMismatch { .. })),
            "crafted-checksum truncation must be rejected, got {simd:?}"
        );
        // No `Ok(_, true)` can be produced for this article on either flag.
        assert!(decode_into_delegable(body, &mut out, false).is_err());
        assert_matches_oracle(body);
    }

    #[test]
    fn probe_single_dot_line() {
        for body in [
            b"=ybegin line=4 size=4 name=d.bin\r\nAAAA\r\n..=yend size=4\r\n".as_slice(),
            b"=ybegin line=4 size=4 name=d.bin\r\nAAAA\r\n.=yend size=4\r\n".as_slice(),
            b"=ybegin line=4 size=4 name=d.bin\r\nAAAA\r\n..=ypart begin=1 end=4\r\n=yend size=4\r\n".as_slice(),
            b"=ybegin line=4 size=4 name=d.bin\r\n..\r\nAAAA\r\n=yend size=4\r\n".as_slice(),
        ] {
            eprintln!("BODY {:?}\n  ORACLE {:?}\n  SIMD   {:?}",
                String::from_utf8_lossy(body),
                yenc::decode(body),
                decode(body));
        }
    }

    #[test]
    fn line_leading_dot_unstuffs_like_the_wire() {
        // Found by the differential fuzzer once the corpus could reach the
        // payload loop: rapidyenc unstuffs ANY line-leading dot (the NNTP
        // wire rule), the oracle used to strip only the doubled form, so an
        // unstuffed `.`-leading line left the two decoders one byte apart.
        for body in [
            // `.` payload line: one dot removed by both.
            b"=ybegin line=4 size=6 name=d.bin\r\nAAAA\r\n.AB\r\n=yend size=6\r\n".as_slice(),
            // Stuffed form of a payload line whose first byte is 0x04.
            b"=ybegin line=4 size=7 name=d.bin\r\nAAAA\r\n..AB\r\n=yend size=7\r\n".as_slice(),
            // Dot on the FIRST payload line (buffer start, not mid-scan).
            b"=ybegin line=4 size=2 name=d.bin\r\n.AB\r\n=yend size=2\r\n".as_slice(),
            // A stuffed trailer: the dot comes off and `=yend` is a trailer.
            b"=ybegin line=4 size=4 name=d.bin\r\nAAAA\r\n.=yend size=4\r\n".as_slice(),
        ] {
            assert_matches_oracle(body);
            assert!(decode(body).is_ok(), "{:?}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn duplicate_header_key_first_wins_on_both_paths() {
        // Differential-fuzz find: `begin=5part begin=50000` - the oracle's
        // HashMap used to keep the LAST `begin`, the SIMD scan the first, so
        // the two paths placed the payload at different file offsets.
        let body = b"=ybegin part=2 total=5 line=4 size=99 name=p.bin\r\n=ypart begin=5part begin=50000\r\nAAAA\r\n=yend size=4\r\n".as_slice();
        assert_matches_oracle(body);
        assert_eq!(decode(body).unwrap().begin, 1);
    }

    #[test]
    fn malformed_headers_parse_identically_on_both_paths() {
        // Each of these is a differential-fuzz find: the two header parsers
        // (HashMap oracle vs allocation-free scan) read a different field.
        for body in [
            // Junk glued to the key: `size` is a token, `l<junk>128 size` is not.
            b"=ybegin l\x99\x91\x9a\xc2128 size=4 name=b.bin\r\nAAAA\r\n=yend\r\n".as_slice(),
            // `name=` runs to end of line: text after it is a FILENAME, never
            // another field, so this `size=1` must not become the gate.
            b"=ybegin line=128 name=p size=1 x.bin\r\nAAAA\r\n=yend\r\n".as_slice(),
            // A form feed is not a field separator (only ASCII space is).
            b"=ybegin line=128 size=4 name=b.bin\r\nAAAA\r\n=yend size=4 crc32\x0c=76db3168\r\n"
                .as_slice(),
            // Second, bare `=yend` clears the gates the first one set.
            b"=ybegin line=128 size=4 name=b.bin\r\nAAAA\r\n=yend size=99\r\n=yend\r\n".as_slice(),
            // Dot-stuffed header lines are still headers.
            b".=ybegin line=128 size=4 name=b.bin\r\nAAAA\r\n.=yend size=4\r\n".as_slice(),
        ] {
            assert_matches_oracle(body);
        }
    }

    #[test]
    fn missing_begin_rejected() {
        assert_eq!(decode(b"just some text\r\n"), Err(YencError::MissingBegin));
        assert_matches_oracle(b"just some text\r\n");
        assert_eq!(decode(b""), Err(YencError::MissingBegin));
    }

    /// Splitmix64 - tiny deterministic PRNG, no dependencies.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    #[test]
    fn fuzz_lite_200_articles() {
        let mut rng = Rng(0x5EED_CAFE_F00D_0001);
        for i in 0..200u32 {
            let len = (100 + rng.below(900_000 - 100)) as usize;
            let mut data = vec![0u8; len];
            // Fill with PRNG bytes, 8 at a time.
            for chunk in data.chunks_mut(8) {
                let v = rng.next().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            let name = format!("fuzz-{i}.bin");
            let article = if rng.below(2) == 0 {
                yenc::encode(&name, len as u64, None, 1, &data)
            } else {
                let part_no = 1 + rng.below(50) as u32;
                let begin = 1 + rng.below(1 << 30);
                yenc::encode(
                    &name,
                    begin - 1 + len as u64 + rng.below(1 << 20),
                    Some((part_no, part_no + rng.below(10) as u32)),
                    begin,
                    &data,
                )
            };
            // Half the articles additionally go through NNTP dot-stuffing.
            let wire = if rng.below(2) == 0 {
                let mut stuffed = Vec::with_capacity(article.len() + 16);
                for line in article.split_inclusive(|&b| b == b'\n') {
                    if line.first() == Some(&b'.') {
                        stuffed.push(b'.');
                    }
                    stuffed.extend_from_slice(line);
                }
                stuffed
            } else {
                article
            };
            let oracle = yenc::decode(&wire);
            let simd = decode(&wire);
            assert_eq!(oracle, simd, "fuzz article {i} (len={len}) diverged");
            let dec = simd.unwrap();
            assert_eq!(dec.data, data, "fuzz article {i} payload wrong");
        }
    }

    #[test]
    fn crc32_combine_and_zeros_match_direct() {
        // The B1 composition identities the live verifier leans on:
        // combine(crc(a), crc(b), |b|) == crc(a ++ b), and
        // zeros(crc(a), n) == crc(a ++ [0; n]).
        let a = test_data(70_001);
        let b = test_data(4096);
        let whole = crc32fast::hash(&[&a[..], &b[..]].concat());
        assert_eq!(
            crc32_combine(crc32fast::hash(&a), crc32fast::hash(&b), b.len() as u64),
            whole
        );
        let padded = crc32fast::hash(&[&a[..], &[0u8; 733][..]].concat());
        assert_eq!(crc32_zeros(crc32fast::hash(&a), 733), padded);
        // Degenerate lengths.
        assert_eq!(
            crc32_combine(crc32fast::hash(&a), 0, 0),
            crc32fast::hash(&a)
        );
        assert_eq!(crc32_zeros(crc32fast::hash(&a), 0), crc32fast::hash(&a));
    }

    /// F12's "no `=yend` means truncated" invariant has to hold on the decoder
    /// the DOWNLOADER actually calls. The SIMD scan can leave its loop without
    /// ever entering payload mode - a body cut right after the header lines
    /// advances `pos` past the end - so rapidyenc is never invoked, `END_NONE`
    /// never fires, and the scalar fallback that carried the only `Truncated`
    /// check was never consulted. It returned `Ok` with 0 bytes: the segment
    /// counted as delivered and the preallocated file kept that range as
    /// sparse zeros, so a PAR2-less job completed silently corrupt.
    #[test]
    fn truncated_article_is_rejected_by_both_decoders() {
        let data = test_data(5000);
        let art = yenc::encode("cut.bin", 5000, Some((1, 2)), 1, &data);

        // The exact shape that escaped: header lines only, no payload, no
        // trailer - what a provider returns for a stored-short article.
        let hdr_end = art
            .windows(9)
            .position(|w| w == b"\r\n=ypart ")
            .map(|i| i + 2)
            .expect("=ypart header");
        let ypart_end = hdr_end
            + art[hdr_end..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .unwrap()
            + 2;
        for cut in [hdr_end, ypart_end] {
            assert!(
                matches!(decode(&art[..cut]), Err(YencError::Truncated)),
                "header-only truncation at {cut} must not decode as Ok"
            );
        }

        // Both decoders must agree at EVERY cut point, or the differential
        // fuzz oracle over these two functions is meaningless.
        for cut in 1..art.len() {
            assert_matches_oracle(&art[..cut]);
        }

        // ...and the intact article still decodes, so the guard cannot be
        // failing healthy traffic.
        assert_eq!(decode(&art).unwrap().data, data);
    }

    #[test]
    fn simd_kernel_selected() {
        let (dec, crc) = kernels();
        // On any modern target we expect a non-generic kernel; on Apple
        // Silicon specifically: NEON decode (0x1000) + ARM CRC/PMULL.
        if cfg!(target_arch = "aarch64") {
            assert_eq!(dec, 0x1000, "expected NEON decode kernel");
            assert!(crc != 0, "expected accelerated CRC kernel");
        }
    }
}
