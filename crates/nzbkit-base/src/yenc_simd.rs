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
    fn rapidyenc_crc_unzero(init_crc: u32, length: u64) -> u32;
    fn rapidyenc_decode_kernel() -> c_int;
    fn rapidyenc_crc_kernel() -> c_int;
    /// Ours, not rapidyenc's: `crates/nzbkit/csrc/yenc_kernel_pin.cc`.
    /// Latches the kernel rapidyenc's own CPU detection chose. Must be
    /// called before any pin, or it latches the pinned level instead.
    fn nzbfast_rapidyenc_latch_detected_kernel() -> c_int;
    /// Ours. Pins the decode kernel; returns the level actually in force
    /// afterwards, or -1 if the request was refused.
    fn nzbfast_rapidyenc_pin_decode_kernel(want: c_int) -> c_int;
    /// Ours. The CRC twins of the two above - same contract, over
    /// rapidyenc's `_crc32_isa` and its three CRC function pointers.
    fn nzbfast_rapidyenc_latch_detected_crc_kernel() -> c_int;
    fn nzbfast_rapidyenc_pin_crc_kernel(want: c_int) -> c_int;
    /// Ours, test support. The address installed in one of the three CRC
    /// function pointers (0/1/2 = incremental/shift/multiply).
    fn nzbfast_rapidyenc_crc_impl_addr(which: c_int) -> usize;
    /// Ours. 1 when the `cc`-built C++ half of this build carries
    /// `-fsanitize=address`, 0 when it does not. A compile-time constant.
    fn nzbfast_rapidyenc_asan_instrumented() -> c_int;
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
        // Latch the DETECTED kernel here, while it is still the detected
        // one. `pin_decode_kernel` overwrites rapidyenc's `_decode_isa`,
        // so a latch taken after a pin would record the pin and the
        // "never pin above what this CPU supports" ceiling would be a
        // ceiling on nothing.
        nzbfast_rapidyenc_latch_detected_kernel();
        // Same for the CRC dispatcher, which has a ceiling of its own:
        // `_crc32_isa` is a separate variable set by `crc32_init()`, and a
        // box can perfectly well have (say) NEON decode and no PMULL.
        nzbfast_rapidyenc_latch_detected_crc_kernel();
    });
}

/// rapidyenc's decode-kernel identifiers (its public `RYKERN_*` values).
///
/// Six of them are compiled into an x86 build and one is selected by
/// runtime CPU detection, so an unpinned run exercises exactly one - see
/// [`pin_decode_kernel`].
pub mod kernel {
    /// The scalar C++ fallback. Compiled into every build, selected by no
    /// x86 or arm64 CPU, and therefore the one kernel that only a pin
    /// reaches.
    pub const GENERIC: i32 = 0;
    pub const SSE2: i32 = 0x100;
    pub const SSSE3: i32 = 0x200;
    pub const AVX: i32 = 0x381;
    pub const AVX2: i32 = 0x403;
    pub const VBMI2: i32 = 0x603;
    pub const NEON: i32 = 0x1000;

    /// Every kernel a pin can ask for, lowest first. Not every one is
    /// reachable on a given CPU - [`super::pinnable_decode_kernels`]
    /// answers that.
    pub const ALL: [i32; 7] = [GENERIC, SSE2, SSSE3, AVX, AVX2, VBMI2, NEON];

    /// Lower-case name, as `NZBFAST_FUZZ_YENC_KERNEL` and the CI logs
    /// spell it.
    pub fn name(k: i32) -> &'static str {
        match k {
            GENERIC => "generic",
            SSE2 => "sse2",
            SSSE3 => "ssse3",
            AVX => "avx",
            AVX2 => "avx2",
            VBMI2 => "vbmi2",
            NEON => "neon",
            _ => "unknown",
        }
    }

    /// The inverse of [`name`]. `None` is a TYPO, not an unsupported CPU:
    /// a caller that cannot tell those apart turns a misspelled kernel
    /// into a silently skipped run.
    pub fn by_name(s: &str) -> Option<i32> {
        ALL.iter().copied().find(|&k| name(k) == s)
    }
}

/// The decode kernel rapidyenc's own CPU detection chose - the one every
/// unpinned run of this process uses.
pub fn detected_decode_kernel() -> i32 {
    init();
    // SAFETY: argumentless FFI query into our own shim; init() latched the
    // value on the line above, so this cannot observe a pinned level.
    unsafe { nzbfast_rapidyenc_latch_detected_kernel() }
}

/// Force the SIMD decoder onto a specific kernel, returning the kernel
/// actually in force afterwards - or `None` if this CPU or this build
/// cannot provide the one asked for.
///
/// **This is a fuzzing and testing lever, and it is PROCESS-GLOBAL.** It
/// rewrites the three function pointers rapidyenc dispatches through, for
/// every thread and every later call, until something pins it back. The
/// production path never calls it.
///
/// The point of it is coverage: rapidyenc is the only memory-unsafe parse
/// code nzbfast ships, an x86 build carries five decode kernels plus the
/// scalar one, and CPU detection means a differential run reaches exactly
/// one of them. See `research/SANDBOX-SCOPING-2026-08.md` section 2.5
/// gap (ii).
///
/// A pin only ever goes DOWN - `want` above [`detected_decode_kernel`] is
/// refused, because the kernel would execute instructions this CPU does
/// not have. The return value is the level rapidyenc reports after the
/// call, which can be LOWER than `want` when a kernel was compiled out
/// (upstream's setters fall back among themselves). Check it; do not
/// assume the request was honoured exactly.
pub fn pin_decode_kernel(want: i32) -> Option<i32> {
    init();
    // SAFETY: by-value `int` argument into our own shim, nothing
    // dereferenced. init() has run, so rapidyenc's lookup tables are
    // built and the detected ceiling is latched.
    let got = unsafe { nzbfast_rapidyenc_pin_decode_kernel(want) };
    if got < 0 { None } else { Some(got) }
}

/// Every kernel [`pin_decode_kernel`] can actually reach on this CPU and
/// in this build, lowest first, with the currently detected kernel
/// restored before returning.
///
/// It answers by TRYING each one rather than by reasoning about the CPU:
/// a kernel that was compiled out falls back to a lower one, and only the
/// level rapidyenc reports back distinguishes those two cases.
pub fn pinnable_decode_kernels() -> Vec<i32> {
    let detected = detected_decode_kernel();
    let mut out = Vec::new();
    for want in kernel::ALL {
        // A pin that lands SOMEWHERE ELSE (upstream's setters fall back
        // among themselves) is not this kernel being reachable, so only
        // an exact landing counts.
        if pin_decode_kernel(want) == Some(want) && !out.contains(&want) {
            out.push(want);
        }
    }
    pin_decode_kernel(detected);
    out
}

/// Whether the C++ half of this build - rapidyenc, the whole
/// memory-unsafe parse surface nzbfast ships - is compiled with
/// AddressSanitizer.
///
/// `false` in an ordinary build, which is correct: `crates/nzbkit-base/build.rs`
/// adds `-fsanitize=address` only when the RUST half is sanitized, so
/// `cargo build` and every CI job but the fuzz ones are untouched. It is
/// the `true` that matters, and it is the only DIRECT evidence a fuzz run
/// has that its C++ is being watched.
///
/// That evidence is not decorative. On Apple clang the flag going missing
/// is loud - the fuzz binary fails to link on a version-check symbol - but
/// on gcc it is silent: the build succeeds and coverage is simply gone,
/// which is the shipped state `research/SANDBOX-SCOPING-2026-08.md`
/// section 2.5 gap (iv) measured as blind. `yenc_decode` prints this, so
/// the log says which it was rather than leaving it to be inferred from
/// the platform.
pub fn cxx_asan_instrumented() -> bool {
    // SAFETY: argumentless FFI query into our own shim, returning a
    // compile-time constant. Nothing is dereferenced and rapidyenc's
    // tables are not consulted, so this needs no init().
    unsafe { nzbfast_rapidyenc_asan_instrumented() != 0 }
}

/// rapidyenc's CRC-kernel identifiers (its public `RYKERN_*` values).
///
/// A SEPARATE ladder from [`kernel`], because rapidyenc dispatches CRC
/// through its own `_crc32_isa` and its own three function pointers: an
/// x86 build carries two accelerated CRC kernels plus the scalar one and
/// an arm64 build carries two, and `crc32_init()` picks one of each by
/// runtime CPU detection exactly as the decoder does.
///
/// The values are NOT one ordered ladder across platforms. `PCLMUL` and
/// `VPCLMUL` are ISA LEVELS and compare numerically; `ARMCRC` and
/// `ARMPMULL` are FEATURE BITS, and `ARMPMULL` is `ARMCRC` plus the PMULL
/// bit, because upstream only compiles the PMULL matrix helpers when the
/// CRC kernel is compiled too. The shim's two platform arms each use the
/// test that is true for them; nothing here should be read as a single
/// ordering.
pub mod crc_kernel {
    /// The scalar slice-by-4 fallback in `crc.cc`. Compiled into every
    /// build, selected by no x86 or arm64 CPU that has CLMUL or ARMv8
    /// CRC, and therefore the one CRC kernel only a pin reaches.
    pub const GENERIC: i32 = 0;
    /// ARMv8 CRC32 instructions (`crc_arm.cc`).
    pub const ARMCRC: i32 = 8;
    /// ARMv8 CRC32 plus PMULL for the shift/multiply matrix math
    /// (`crc_arm_pmull.cc`). Implies [`ARMCRC`].
    pub const ARMPMULL: i32 = 0x48;
    /// SSE4.1 + PCLMULQDQ folding (`crc_folding.cc`).
    pub const PCLMUL: i32 = 0x340;
    /// AVX2 + VPCLMULQDQ folding (`crc_folding_256.cc`).
    pub const VPCLMUL: i32 = 0x440;

    /// Every CRC kernel a pin can ask for. Not every one is reachable on
    /// a given CPU - [`super::pinnable_crc_kernels`] answers that.
    pub const ALL: [i32; 5] = [GENERIC, ARMCRC, ARMPMULL, PCLMUL, VPCLMUL];

    /// Lower-case name, as the CI logs spell it.
    pub fn name(k: i32) -> &'static str {
        match k {
            GENERIC => "generic",
            ARMCRC => "armcrc",
            ARMPMULL => "armpmull",
            PCLMUL => "pclmul",
            VPCLMUL => "vpclmul",
            _ => "unknown",
        }
    }

    /// The inverse of [`name`]. `None` is a TYPO, not an unsupported CPU -
    /// same reasoning as [`super::kernel::by_name`].
    pub fn by_name(s: &str) -> Option<i32> {
        ALL.iter().copied().find(|&k| name(k) == s)
    }
}

/// The CRC kernel rapidyenc's own CPU detection chose - the one every
/// unpinned run of this process uses.
pub fn detected_crc_kernel() -> i32 {
    init();
    // SAFETY: argumentless FFI query into our own shim; init() latched the
    // value on the line above, so this cannot observe a pinned kernel.
    unsafe { nzbfast_rapidyenc_latch_detected_crc_kernel() }
}

/// Force the CRC path onto a specific kernel, returning the kernel
/// actually in force afterwards - or `None` if this CPU or this build
/// cannot provide the one asked for.
///
/// **A fuzzing and testing lever, and PROCESS-GLOBAL**, exactly like
/// [`pin_decode_kernel`]: it rewrites the three function pointers that
/// `crc.cc` dispatches through, for every thread and every later call. The
/// production path never calls it.
///
/// It moves MORE than "hash these bytes": `_crc32_shift` and
/// `_crc32_multiply` are swapped too, so [`crc32_combine`],
/// [`crc32_zeros`], [`crc32_unzero`] and [`crc32_of_middle`] all change
/// implementation under a pin. That is the point - those three run the
/// carry-less matrix math a plain checksum test never reaches.
///
/// A pin only ever goes DOWN, and what "down" means differs by platform
/// (see [`crc_kernel`]). The return value is what rapidyenc reports after
/// the call and can be lower than `want` when a kernel was compiled out.
/// Check it; do not assume the request was honoured exactly.
pub fn pin_crc_kernel(want: i32) -> Option<i32> {
    init();
    // SAFETY: by-value `int` argument into our own shim, nothing
    // dereferenced. init() has run, so rapidyenc's CRC tables are built
    // and the detected ceiling is latched.
    let got = unsafe { nzbfast_rapidyenc_pin_crc_kernel(want) };
    if got < 0 { None } else { Some(got) }
}

/// Every kernel [`pin_crc_kernel`] can actually reach on this CPU and in
/// this build, with the currently detected kernel restored before
/// returning.
///
/// It answers by TRYING each one, for the same reason its decode twin
/// does: a kernel compiled out falls back to a lower one, and only the
/// value rapidyenc reports back tells those two cases apart.
pub fn pinnable_crc_kernels() -> Vec<i32> {
    let detected = detected_crc_kernel();
    let mut out = Vec::new();
    for want in crc_kernel::ALL {
        if pin_crc_kernel(want) == Some(want) && !out.contains(&want) {
            out.push(want);
        }
    }
    pin_crc_kernel(detected);
    out
}

/// The addresses currently installed in rapidyenc's three CRC function
/// pointers: `[incremental, shift, multiply]`.
///
/// TEST SUPPORT, not a diagnostic. It is what makes a kernel sweep's
/// result non-vacuous: every other assertion in such a sweep is about
/// ANSWERS, and a CRC is correct whichever kernel computed it, so a pin
/// that moved the kernel id and nothing else would leave the sweep green
/// while covering one kernel repeatedly. Two distinct kernels must install
/// distinct triples.
pub fn crc_impl_addrs() -> [usize; 3] {
    init();
    // SAFETY: by-value `int` selector into our own shim; it dereferences
    // nothing and returns the pointer VALUE as an integer, so nothing here
    // is ever called through.
    unsafe {
        [
            nzbfast_rapidyenc_crc_impl_addr(0),
            nzbfast_rapidyenc_crc_impl_addr(1),
            nzbfast_rapidyenc_crc_impl_addr(2),
        ]
    }
}

/// CRC32 of `data`, seeded with `init_crc`, through whichever CRC kernel
/// is in force - rapidyenc's detected one, or the one [`pin_crc_kernel`]
/// last installed.
pub fn crc32(data: &[u8], init_crc: u32) -> u32 {
    init();
    crc32_raw(data, init_crc)
}

/// [`crc32`] without the `init()` call, for the decode path, which has
/// already run it. One `unsafe` block for all three call sites.
#[inline]
fn crc32_raw(data: &[u8], init_crc: u32) -> u32 {
    // SAFETY: reads exactly data.len() bytes from the live `data` slice;
    // every caller has run init(), so rapidyenc's CRC tables are built.
    unsafe { rapidyenc_crc(data.as_ptr().cast(), data.len(), init_crc) }
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

/// The inverse of [`crc32_zeros`]: given CRC32(`data ++ [0u8; len]`),
/// CRC32(`data`). O(log len), like its forward half.
pub fn crc32_unzero(crc: u32, len: u64) -> u32 {
    init();
    // SAFETY: by-value arguments only, nothing dereferenced; init() has run
    // on the line above.
    unsafe { rapidyenc_crc_unzero(crc, len) }
}

/// CRC32 of the MIDDLE piece of `head ++ mid ++ tail`, given the CRC32
/// of the whole and of the two pieces around it - the one CRC a verified
/// article can hand its blocks for free.
///
/// The live verifier spends a yEnc article's decoder-verified CRC32 on
/// the PAR2 blocks the article covers: every piece but one is hashed,
/// and this derives the one that was not (the largest, by choice of the
/// caller). Both outer pieces may be empty - pass `(0, 0)` for an empty
/// tail and `0` for an empty head, CRC32 of the empty string being 0.
///
/// The arithmetic: CRC32 concatenation is affine in the LEFT operand,
/// `combine(a, b, |b|) == T_{|b|}(a) ^ b` for a linear `T` (zlib's
/// `crc32_combine` is literally that matrix product followed by the
/// xor), so
///
/// ```text
/// whole = combine(head, combine(mid, tail, |tail|), |mid| + |tail|)
///       = T_{|mid|+|tail|}(head) ^ T_{|tail|}(mid) ^ tail
/// ```
///
/// and `T_{|tail|}(mid)` is `whole ^ combine(head, 0, |mid|+|tail|) ^
/// tail`. Undoing `T_n` is the one step no combine can do, and
/// `crc32_zeros` is `T_n` plus a constant (`zeros(c, n) == T_n(c) ^
/// zeros(0, n)`), so `crc32_unzero` undoes it: `T_n^{-1}(y) ==
/// unzero(y ^ zeros(0, n), n)`. `yenc_simd::tests::
/// crc32_of_middle_matches_direct` pins every identity above against
/// `crc32fast` over the bytes.
pub fn crc32_of_middle(whole: u32, head: u32, mid_len: u64, tail: u32, tail_len: u64) -> u32 {
    let shifted = whole ^ crc32_combine(head, 0, mid_len + tail_len) ^ tail;
    if tail_len == 0 {
        shifted
    } else {
        crc32_unzero(shifted ^ crc32_zeros(0, tail_len), tail_len)
    }
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
            let computed = crc32_raw(data, 0);
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
        let computed = crc32_raw(data, 0);
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

    /// The derivation the live verifier's CRC reuse rests on: the CRC of
    /// a middle piece recovered from the whole's and its neighbours',
    /// with every shape of empty neighbour.
    #[test]
    fn crc32_of_middle_matches_direct() {
        let bytes = test_data(300_007);
        let h = crc32fast::hash;
        // unzero really is zeros' inverse.
        assert_eq!(crc32_unzero(crc32_zeros(h(&bytes), 4097), 4097), h(&bytes));
        assert_eq!(crc32_unzero(h(&bytes), 0), h(&bytes));
        for &(hl, ml) in &[
            (0usize, 300_007usize), // the whole article is the piece
            (0, 700),               // head empty
            (100_000, 200_007),     // tail empty
            (1, 1),                 // one-byte pieces
            (123_456, 65_536),      // all three present
            (300_006, 1),           // a one-byte tail-less middle
            (0, 1),                 // one byte, both neighbours empty
        ] {
            let (head, rest) = bytes.split_at(hl);
            let (mid, tail) = rest.split_at(ml);
            assert_eq!(
                crc32_of_middle(h(&bytes), h(head), ml as u64, h(tail), tail.len() as u64),
                h(mid),
                "head {hl} mid {ml} tail {}",
                tail.len()
            );
        }
        // And a middle whose head and tail are themselves compositions,
        // as the verifier builds them.
        let (a, rest) = bytes.split_at(1000);
        let (b, rest) = rest.split_at(2000);
        let (mid, rest) = rest.split_at(250_000);
        let (c, d) = rest.split_at(10_000);
        let head = crc32_combine(h(a), h(b), b.len() as u64);
        let tail = crc32_combine(h(c), h(d), d.len() as u64);
        assert_eq!(
            crc32_of_middle(
                h(&bytes),
                head,
                mid.len() as u64,
                tail,
                (c.len() + d.len()) as u64
            ),
            h(mid)
        );
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
        // The DETECTED kernels, not `kernels()`. This test asks what CPU
        // detection chose, and that is latched once and never moves; what
        // `kernels()` reports is the LIVE dispatch, which the two pinning
        // sweeps in this module rewrite process-globally while they run.
        // Reading the live value made this an assertion about whichever
        // sibling test happened to be mid-sweep: observed failing here as
        // `expected NEON decode kernel / left: 0 right: 4096` - generic,
        // because a sweep had pinned down to it - and it passed on the
        // next five runs, which is the shape that gets a flake blamed on
        // load. `cargo test` puts the whole target in ONE process, so a
        // pin reaches this test; nextest gives each test its own process
        // and cannot see it at all, which is why CI's unit-one-process
        // job is the one that would have caught it.
        let dec = detected_decode_kernel();
        let crc = detected_crc_kernel();
        // On any modern target we expect a non-generic kernel; on Apple
        // Silicon specifically: NEON decode (0x1000) + ARM CRC/PMULL.
        if cfg!(target_arch = "aarch64") {
            assert_eq!(dec, 0x1000, "expected NEON decode kernel");
            assert!(crc != 0, "expected accelerated CRC kernel");
        }
    }

    /// The control arm for `build.rs`'s ASan flag: an ORDINARY build must
    /// not carry it.
    ///
    /// `build.rs::asan_requested()` adds `-fsanitize=address` to the
    /// `cc`-built rapidyenc objects exactly when the Rust half asked for
    /// the sanitizer, and its header claims "an ordinary `cargo build` and
    /// every CI job except the fuzz ones are untouched". Nothing tested
    /// that claim, and a condition that answered yes unconditionally would
    /// put ASan into every shipped binary while every fuzz run still
    /// printed the reassuring `yes` - so the false direction needs a pin
    /// of its own, not just the true one the fuzz log carries.
    ///
    /// This also LINKS the shim function, which `cargo check` does not: an
    /// FFI name that no longer resolves fails here rather than in a fuzz
    /// build nobody runs on this box.
    ///
    /// A sanitized `cargo test` would legitimately flip this, and that is
    /// not a configuration this repo runs anywhere; if you are the one
    /// running it, this failure is the expected report, not a defect.
    #[test]
    fn an_ordinary_build_does_not_sanitize_the_cxx() {
        assert!(
            !cxx_asan_instrumented(),
            "the cc-built rapidyenc objects carry -fsanitize=address in a \
             plain test build - build.rs's asan_requested() is answering yes \
             outside a sanitized build, which would ship ASan to users"
        );
    }

    /// Every kernel this CPU can run, differentialled against the scalar
    /// oracle - not just the one CPU detection picked.
    ///
    /// rapidyenc is the only memory-unsafe parse code nzbfast ships, and
    /// an x86 build carries five decode kernels plus the scalar fallback
    /// while running exactly one of them. So on an x86 CI runner this
    /// test covers four to six kernels where every other test in the tree
    /// covers one; on this arm64 box it covers NEON and generic. It is
    /// the cheap half of the study's gap (ii) - the fuzz target's
    /// `NZBFAST_FUZZ_YENC_KERNEL` is the other half, and this one runs on
    /// every push.
    ///
    /// The pin is PROCESS-GLOBAL, so a sibling test decoding at the same
    /// moment gets whichever kernel is pinned right now. That is
    /// deliberately tolerable: every kernel is supposed to decode
    /// identically, so a sibling that fails under a pinned kernel has
    /// found the bug this test is looking for. The detected kernel is put
    /// back before returning either way.
    #[test]
    fn every_reachable_kernel_matches_the_oracle() {
        let detected = detected_decode_kernel();
        let available = pinnable_decode_kernels();
        assert!(
            available.contains(&detected),
            "the detected kernel {} is not in the pinnable set {:?} - the pin \
             shim and rapidyenc's dispatch disagree about what this CPU has",
            kernel::name(detected),
            available
                .iter()
                .map(|&k| kernel::name(k))
                .collect::<Vec<_>>()
        );
        assert!(
            available.contains(&kernel::GENERIC),
            "the scalar kernel must always be pinnable - it is the one no \
             CPU selects, so a pin is the only thing that ever reaches it"
        );

        // Articles chosen to straddle the SIMD width boundaries: every
        // kernel falls back to scalar for the head, the tail and any body
        // shorter than two vector widths, so a length sweep is what
        // actually reaches the vector loop.
        let mut articles: Vec<Vec<u8>> = Vec::new();
        for &len in &[1usize, 31, 32, 63, 64, 127, 128, 129, 4096, 70_000] {
            let data = test_data(len);
            articles.push(yenc::encode("k.bin", len as u64, None, 1, &data));
            // Multi-part, framed the way the round-trip test above frames
            // it: part 2 of 3 starting a million bytes in, so the =ypart
            // header carries real numbers rather than degenerate ones.
            let begin = 1_000_001u64;
            articles.push(yenc::encode(
                "kp.bin",
                begin - 1 + len as u64,
                Some((2, 3)),
                begin,
                &data,
            ));
        }
        // Escapes and dot-stuffing are the branchy part of every kernel.
        let esc = test_data(9_000);
        let art = yenc::encode("esc.bin", 9_000, None, 1, &esc);
        let mut stuffed = Vec::new();
        for line in art.split_inclusive(|&b| b == b'\n') {
            if line.first() == Some(&b'.') {
                stuffed.push(b'.');
            }
            stuffed.extend_from_slice(line);
        }
        articles.push(stuffed);
        // ...and truncations, the shape that once decoded as Ok with zero
        // bytes on the production path.
        for cut in [7usize, 64, 200, art.len() - 1] {
            articles.push(art[..cut.min(art.len())].to_vec());
        }
        articles.push(art);

        let mut covered = Vec::new();
        for &k in &available {
            let got = pin_decode_kernel(k).unwrap_or_else(|| {
                panic!(
                    "pinning {} failed after it was \
                     reported pinnable",
                    kernel::name(k)
                )
            });
            assert_eq!(got, k, "pin landed on the wrong kernel");
            assert_eq!(
                kernels().0,
                k,
                "rapidyenc reports a different kernel than the pin installed"
            );
            for a in &articles {
                assert_eq!(
                    yenc::decode(a),
                    decode(a),
                    "kernel {} diverged from the scalar oracle",
                    kernel::name(k)
                );
            }
            covered.push(kernel::name(k));
        }
        pin_decode_kernel(detected);
        assert_eq!(
            kernels().0,
            detected,
            "the detected kernel was not restored"
        );
        // Printed rather than merely counted: a run that silently covered
        // one kernel is exactly the state this test exists to end, and a
        // count alone does not say WHICH.
        println!("yEnc kernels differentialled: {}", covered.join(", "));
        assert!(
            covered.len() >= 2,
            "only one kernel was reachable ({covered:?}) - on x86 that means \
             the pin shim is not working, not that the CPU is limited"
        );
    }

    /// The CRC half of the same gap: every CRC kernel this CPU can run,
    /// differentialled against `crc32fast`.
    ///
    /// `crc32fast` is the oracle rather than rapidyenc's own generic
    /// kernel, and that is a deliberate choice. The generic kernel is the
    /// closer analogue in shape, but it is rapidyenc code: the accelerated
    /// shift/multiply functions share the `crc_power` table with the
    /// generic ones, so a wrong entry in that table - or a wrong
    /// polynomial - would agree with itself and the differential would see
    /// nothing. `crc32fast` is an independent implementation, and it is
    /// already the CRC the SCALAR yEnc decoder checks articles against
    /// (`yenc.rs`), so this is the same shape as the decode differential
    /// above: the SIMD path against the answer the scalar path gives.
    ///
    /// `crc32_combine` / `crc32_zeros` / `crc32_unzero` are exercised on
    /// purpose. They dispatch through `_crc32_shift` and `_crc32_multiply`,
    /// which a pin swaps and which hashing bytes never reaches - and their
    /// oracle is stronger still: hash the concatenated or zero-padded bytes
    /// directly, which ties the O(log n) carry-less matrix math back to
    /// real data rather than to another closed-form implementation.
    ///
    /// The pin is process-global, so under `cargo test` (one process for
    /// the whole target) this runs concurrently with tests that compute
    /// CRCs. That is safe because a pinned kernel still computes the
    /// CORRECT CRC - only which code path computes it changes - and this
    /// test restores the detected kernel before returning.
    #[test]
    fn every_reachable_crc_kernel_matches_the_oracle() {
        let detected = detected_crc_kernel();
        let available = pinnable_crc_kernels();
        assert!(
            available.contains(&detected),
            "the detected CRC kernel {} is not in the pinnable set {:?} - the \
             pin shim and rapidyenc's dispatch disagree about what this CPU has",
            crc_kernel::name(detected),
            available
                .iter()
                .map(|&k| crc_kernel::name(k))
                .collect::<Vec<_>>()
        );
        assert!(
            available.contains(&crc_kernel::GENERIC),
            "the scalar CRC kernel must always be pinnable - it is the one no \
             CPU with CLMUL or ARMv8 CRC selects, so a pin is the only thing \
             that ever reaches it"
        );

        // One buffer, sliced four ways for the four alignments, over EVERY
        // length up to 160.
        //
        // Contiguous rather than a hand-picked list of interesting sizes,
        // and that is the whole argument for why this test is enough on its
        // own (see the CI-lever note in section 2.5 of the scoping study).
        // None of these kernels branches on byte VALUES - a CRC has no
        // parsing and no state machine - so the reachable paths through one
        // are a function of exactly two things: the start alignment and the
        // length's residue against the fold width. The widest of those is
        // 128 bytes (VPCLMUL folds four 32-byte lanes), so 0..=160 at all
        // four alignments covers every residue class of every kernel here,
        // with a lap to spare. A mutation fuzzer re-rolling byte values
        // would explore nothing this does not already reach.
        //
        // Each case gets its OWN allocation, sized `off + len`, and is
        // taken as `&v[off..]`. That is not incidental: it puts the end of
        // every case at the end of a heap block, so a kernel that reads one
        // byte past its input is reading past an allocation rather than
        // into the middle of a shared buffer, where nothing - not a
        // sanitizer, not a hardened allocator - could see it. The `off`
        // prefix is what still varies the start alignment.
        let big = test_data(70_016);
        let mut owned: Vec<(Vec<u8>, usize)> = Vec::new();
        let mut lens: Vec<usize> = (0..=160).collect();
        // ...plus sizes past the point where a folding kernel runs its main
        // loop many times over, and one past 64 KiB.
        lens.extend_from_slice(&[255, 256, 511, 512, 1023, 1024, 4095, 4096, 65_535, 70_000]);
        for len in lens {
            for off in 0..4usize {
                owned.push((test_data(off + len), off));
            }
        }
        let cases: Vec<&[u8]> = owned.iter().map(|(v, off)| &v[*off..]).collect();

        let mut covered = Vec::new();
        let mut impls: Vec<(&str, [usize; 3])> = Vec::new();
        for &k in &available {
            let got = pin_crc_kernel(k).unwrap_or_else(|| {
                panic!(
                    "pinning CRC kernel {} failed after it was reported pinnable",
                    crc_kernel::name(k)
                )
            });
            assert_eq!(got, k, "CRC pin landed on the wrong kernel");
            assert_eq!(
                kernels().1,
                k,
                "rapidyenc reports a different CRC kernel than the pin installed"
            );
            // Before any answer is compared: the pin must have moved CODE,
            // not just the kernel id. See `crc_impl_addrs`.
            let addrs = crc_impl_addrs();
            for (prev_name, prev) in &impls {
                assert_ne!(
                    *prev,
                    addrs,
                    "CRC kernels {} and {} dispatch through the SAME three \
                     functions - the pin moved the kernel id and nothing else, \
                     so every comparison below would be that one kernel \
                     against itself",
                    prev_name,
                    crc_kernel::name(k)
                );
            }
            impls.push((crc_kernel::name(k), addrs));

            for c in &cases {
                assert_eq!(
                    crc32(c, 0),
                    crc32fast::hash(c),
                    "CRC kernel {} diverged from the oracle at len {} off {}",
                    crc_kernel::name(k),
                    c.len(),
                    c.as_ptr() as usize % 4
                );
                // Non-zero seed: a resumed CRC over the same bytes in two
                // calls must equal the one-shot. This is the `init_crc`
                // argument's own path (`~init` seeding and the final
                // complement), which a zero seed leaves half-tested.
                let (head, tail) = c.split_at(c.len() / 2);
                assert_eq!(
                    crc32(tail, crc32(head, 0)),
                    crc32fast::hash(c),
                    "CRC kernel {} diverged on a seeded continuation at len {}",
                    crc_kernel::name(k),
                    c.len()
                );
            }

            // The shift/multiply half. A pin swaps these two pointers as
            // well, and nothing above reaches them.
            // `crc32_shift` loops once per SET BIT of the byte-power of
            // its length, so the lengths here are chosen for their bit
            // patterns as much as their size: 65_535 and 43_690 (0xAAAA)
            // drive it around that loop 16 and 8 times where a power of two
            // drives it once.
            for &(alen, blen) in &[
                (0usize, 0usize),
                (0, 17),
                (1, 1),
                (3, 5),
                (16, 16),
                (31, 33),
                (1024, 7),
                (4096, 70_000),
                (43_690, 43_690),
                (65_535, 65_535),
                (70_000, 1),
            ] {
                let a = &big[..alen];
                let b = &big[7..7 + blen];
                let mut cat = a.to_vec();
                cat.extend_from_slice(b);
                assert_eq!(
                    crc32_combine(crc32fast::hash(a), crc32fast::hash(b), blen as u64),
                    crc32fast::hash(&cat),
                    "CRC kernel {} combine diverged at {alen}+{blen}",
                    crc_kernel::name(k)
                );

                let mut padded = a.to_vec();
                padded.resize(alen + blen, 0);
                assert_eq!(
                    crc32_zeros(crc32fast::hash(a), blen as u64),
                    crc32fast::hash(&padded),
                    "CRC kernel {} zeros diverged at {alen}+{blen}",
                    crc_kernel::name(k)
                );
                assert_eq!(
                    crc32_unzero(crc32fast::hash(&padded), blen as u64),
                    crc32fast::hash(a),
                    "CRC kernel {} unzero diverged at {alen}+{blen}",
                    crc_kernel::name(k)
                );

                // ...and the composite the live PAR2 verifier actually
                // calls, which is combine and zeros together.
                let mid = &big[3..3 + blen];
                let mut whole = a.to_vec();
                whole.extend_from_slice(mid);
                whole.extend_from_slice(b);
                assert_eq!(
                    crc32_of_middle(
                        crc32fast::hash(&whole),
                        crc32fast::hash(a),
                        blen as u64,
                        crc32fast::hash(b),
                        blen as u64,
                    ),
                    crc32fast::hash(mid),
                    "CRC kernel {} of_middle diverged at {alen}+{blen}",
                    crc_kernel::name(k)
                );
            }
            covered.push(crc_kernel::name(k));
        }
        pin_crc_kernel(detected);
        assert_eq!(
            kernels().1,
            detected,
            "the detected CRC kernel was not restored"
        );
        // Printed, not merely counted, for the same reason its decode twin
        // prints: a run that silently covered one kernel is the state this
        // test exists to end, and a count does not say WHICH.
        println!("yEnc CRC kernels differentialled: {}", covered.join(", "));
        // The floor is TWO wherever this build compiles an accelerated CRC
        // kernel at all, and that is the only place the guard means
        // anything: the generic kernel is the one no such CPU selects, so a
        // sweep that covered it alone says the pin shim stopped moving code.
        //
        // Which targets those are is `build.rs`'s decision, not a guess:
        // `is_x86 || is_arm64` is the split it compiles the CRC groups by
        // (`crc_folding.cc` / `crc_folding_256.cc` behind x86 CLMUL,
        // `crc_arm.cc` / `crc_arm_pmull.cc` behind ARMv8 CRC32). Off that
        // split - 32-bit ARM, which the nightly armv7-cross job runs under
        // qemu - the ARM sources self-guard themselves empty, so `generic`
        // alone is the correct AND complete answer rather than a broken
        // shim, and a flat floor of 2 was asserting the desktop answer on a
        // target that cannot produce it (run 33737735769).
        //
        // The `else` arm is an exact set, not a relaxed floor: it still
        // fails if such a build ever grows a second kernel, which is the
        // moment this predicate needs updating rather than quietly widening.
        let accelerated = cfg!(any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "aarch64"
        ));
        if accelerated {
            assert!(
                covered.len() >= 2,
                "only one CRC kernel was reachable ({covered:?}) - every x86 CPU \
                 since ~2010 has PCLMUL and every arm64 one here has ARMv8 CRC, \
                 so this means the pin shim is not working, not that the CPU is \
                 limited"
            );
        } else {
            assert_eq!(
                covered,
                [crc_kernel::name(crc_kernel::GENERIC)],
                "this target compiles no accelerated CRC kernel (build.rs gates \
                 them on x86 or arm64), so the scalar one is the whole reachable \
                 set - a different answer here means the floor above needs to \
                 know about a kernel that did not exist when it was written"
            );
        }
    }
}
