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
//!
//! WHICH SIMD KERNEL. rapidyenc compiles five decode kernels into an x86
//! binary plus a scalar one, and picks ONE by runtime CPU detection - so
//! an unpinned run of this target covers a sixth of the only
//! memory-unsafe parse code nzbfast ships
//! (`research/SANDBOX-SCOPING-2026-08.md` section 2.5, gap ii). Set
//! `NZBFAST_FUZZ_YENC_KERNEL` to a kernel name (`generic`, `sse2`,
//! `ssse3`, `avx`, `avx2`, `vbmi2`, `neon`) to pin this run to that one
//! instead. Either way the kernel actually in force is PRINTED at
//! startup, so a log says which kernel a run covered rather than leaving
//! it to be inferred from the runner. fuzz-smoke.yml drives the pinned
//! runs; the unpinned run stays as it was, so the existing gate is
//! unchanged and the pinned ones are additive.
//!
//! `NZBFAST_FUZZ_CRC_KERNEL` does the same for rapidyenc's SEPARATE CRC
//! dispatch (`generic`, `armcrc`, `armpmull`, `pclmul`, `vpclmul`), which
//! this target drives on every article carrying a `crc32=`/`pcrc32=`
//! trailer. The two pins are independent and can be set together.
//!
//! A name this build cannot provide - `avx2` on a runner without it -
//! exits 0 straight away rather than re-fuzzing the detected kernel
//! under a misleading label. A name that is not a kernel at all is a
//! TYPO and aborts, because a silently skipped run is exactly how a
//! kernel stops being covered without anyone noticing.
use libfuzzer_sys::fuzz_target;
use nzbkit::yenc_simd::{crc_kernel, kernel};

/// Pin the decoder if asked to, and say what is in force either way.
/// Runs once, before any input, via libFuzzer's initialiser.
fn select_kernel() {
    let want = std::env::var("NZBFAST_FUZZ_YENC_KERNEL").unwrap_or_default();
    if !want.is_empty() {
        let Some(level) = kernel::by_name(&want) else {
            panic!(
                "NZBFAST_FUZZ_YENC_KERNEL={want:?} is not a kernel name; \
                 expected one of {:?}",
                kernel::ALL.map(kernel::name)
            );
        };
        match nzbkit::yenc_simd::pin_decode_kernel(level) {
            Some(got) if got == level => {}
            _ => {
                println!(
                    "yEnc kernel {want} is not available in this build on this \
                     CPU (detected: {}) - nothing to fuzz, skipping",
                    kernel::name(nzbkit::yenc_simd::detected_decode_kernel())
                );
                std::process::exit(0);
            }
        }
    }
    // The CRC kernel is a SECOND dispatch, pinned by a second variable.
    // rapidyenc selects it from its own CPU probe into its own three
    // function pointers (`crc.cc`), and this target already drives it on
    // every article whose trailer carries `crc32=`/`pcrc32=` - so pinning
    // it here reaches the OTHER CRC kernels under AddressSanitizer at the
    // cost of one env var, no new target and no second corpus.
    //
    // That ASan reach is the whole reason this exists. The exhaustive
    // sweep in `yenc_simd::tests::every_reachable_crc_kernel_matches_the_oracle`
    // already covers every (alignment, length-residue) class each CRC
    // kernel can take - a CRC branches on no byte VALUE, so there is
    // nothing left for a mutator to find in the ANSWERS. What that test
    // cannot do is watch for an out-of-bounds READ, which is a sanitizer's
    // job and this build has one.
    let want_crc = std::env::var("NZBFAST_FUZZ_CRC_KERNEL").unwrap_or_default();
    if !want_crc.is_empty() {
        let Some(level) = crc_kernel::by_name(&want_crc) else {
            panic!(
                "NZBFAST_FUZZ_CRC_KERNEL={want_crc:?} is not a CRC kernel name; \
                 expected one of {:?}",
                crc_kernel::ALL.map(crc_kernel::name)
            );
        };
        match nzbkit::yenc_simd::pin_crc_kernel(level) {
            Some(got) if got == level => {}
            _ => {
                println!(
                    "CRC kernel {want_crc} is not available in this build on \
                     this CPU (detected: {}) - nothing to fuzz, skipping",
                    crc_kernel::name(nzbkit::yenc_simd::detected_crc_kernel())
                );
                std::process::exit(0);
            }
        }
    }
    let (dec, crc) = nzbkit::yenc_simd::kernels();
    println!(
        "yEnc decode kernel in force: {} / CRC kernel in force: {}",
        kernel::name(dec),
        crc_kernel::name(crc)
    );
    // And whether the kernel above is actually being WATCHED. rapidyenc is
    // `cc`-built C++, so it is sanitized only because build.rs puts
    // `-fsanitize=address` on it; before that landed, ASan saw none of it
    // (section 2.5 gap iv). On Apple clang the flag going missing is a link
    // error, but on gcc it is silent - a green run on a Linux runner is
    // equally consistent with full coverage and with none - so the run says
    // which it was instead of leaving it to be inferred from the platform.
    println!(
        "rapidyenc C++ AddressSanitizer instrumentation: {}",
        if nzbkit::yenc_simd::cxx_asan_instrumented() {
            "yes"
        } else {
            "NO - the C++ half of this build is unwatched"
        }
    );
}

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

fuzz_target!(init: select_kernel(), |data: &[u8]| {
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
