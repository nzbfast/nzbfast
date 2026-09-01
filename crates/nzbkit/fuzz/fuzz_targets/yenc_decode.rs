#![no_main]
//! Fuzz the SIMD yEnc decoder on RAW untrusted article bodies. The
//! existing lite fuzzer only round-trips well-formed encodings; this
//! feeds arbitrary bytes straight to the decoder (its OOB/panic surface).
//!
//! It is also the DIFFERENTIAL oracle: the SIMD path is what the
//! downloader calls, the scalar path is the reference, and a shape one
//! accepts while the other rejects is a bug in whichever is wrong. Both
//! results used to be discarded, so a divergence could not be observed -
//! which is how a truncated article the scalar decoder rejected went on
//! decoding as `Ok` with 0 bytes on the production path.
use libfuzzer_sys::fuzz_target;

/// The two deviations documented in `yenc_simd`'s module header, both only
/// reachable with input the NNTP layer cannot deliver. Comparing on them
/// would wedge this target on a known-benign difference and hide the real
/// divergences behind it.
/// - a lone `.` line is the NNTP article terminator, stripped before decode
///   is ever called; mid-body it ends the SIMD decode but not the oracle's.
/// - a payload line ending in a bare `=` is malformed yEnc; the oracle
///   ignores it, rapidyenc consumes the following CR.
/// - MIXED line endings (some CRLF, some bare LF) in one body: rapidyenc's
///   state machine only recognises `\r\n` as a line break, so after a bare
///   LF it neither stops at a `=y…` control line nor unstuffs a leading
///   dot, while the oracle (which splits on `\n`) does both. A body that is
///   wholly bare-LF is fine - it takes the END_NONE scalar fallback - and a
///   wholly-CRLF body is the real wire. Only the mix deviates.
fn hits_documented_deviation(data: &[u8]) -> bool {
    let has_crlf = data.windows(2).any(|w| w == b"\r\n");
    let has_bare_lf = data
        .iter()
        .enumerate()
        .any(|(i, &b)| b == b'\n' && (i == 0 || data[i - 1] != b'\r'));
    if has_crlf && has_bare_lf {
        return true;
    }
    data.split(|&b| b == b'\n').any(|l| {
        let l = l.strip_suffix(b"\r").unwrap_or(l);
        l == b"." || l.last() == Some(&b'=')
    })
}

fuzz_target!(|data: &[u8]| {
    if hits_documented_deviation(data) {
        return;
    }
    // M4-76: a CR-FRAMED body (CRs, no LF anywhere) is retried by BOTH
    // decoders on the CRLF rewrite of itself, so the deviations above have
    // to be judged over that rewrite too - a lone `.` line and a payload
    // line ending in a bare `=` only become LINES once the reframing has
    // happened, and the raw body has no line for the guard to look at.
    // Measured: `=ybegin …\rABCD\r.\r=yend size=4\r` decodes on the oracle
    // and is Truncated on the SIMD path, which is deviation one, reached a
    // new way rather than a new divergence.
    if let Some(reframed) = nzbkit::yenc::cr_framed_to_crlf(data) {
        if hits_documented_deviation(&reframed) {
            return;
        }
    }
    let simd = nzbkit::yenc_simd::decode(data);
    let scalar = nzbkit::yenc::decode(data);
    match (&simd, &scalar) {
        // Both accepted: payload and framing must be identical.
        (Ok(a), Ok(b)) => assert_eq!(a, b, "decoders disagree on an ACCEPTED article"),
        // Both rejected: the variants may differ (each reports the first
        // problem it reaches), but the verdict must match.
        (Err(_), Err(_)) => {}
        _ => panic!("decoders disagree on acceptance: simd={simd:?} scalar={scalar:?}"),
    }
});
