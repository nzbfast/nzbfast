// Pin rapidyenc's decode kernel AND its CRC kernel, so a fuzz campaign (or
// an ordinary test) can reach more than the one of each this CPU happens
// to select.
//
// WHY THIS FILE EXISTS. rapidyenc is the whole memory-unsafe parse surface
// nzbfast ships - about 4,000 lines of hand-written SIMD C++ on x86 and
// 2,700 on arm64, on the path of every article
// (research/SANDBOX-SCOPING-2026-08.md section 2.2, gap ii). But
// `decoder_init()` picks ONE of six kernels by runtime CPU detection, so a
// differential run exercises whichever kernel the runner supports and
// leaves the rest - all compiled into the shipped x86 binary, all reached
// on users' machines - untested. Upstream's public API exposes no
// kernel-forcing knob, but its per-kernel setters (`decoder_set_*_funcs`)
// are ordinary external symbols, so a shim of our own can call them
// directly. That is far cheaper than the two levers the study named
// (runners of differing CPU capability, or an ISA-limiting emulator), and
// it is the only one that also works from a plain `cargo test`.
//
// This file is OURS, not vendor: the same code inside vendor/rapidyenc
// would be drift the next re-sync has to reconcile.
//
// A kernel may only be pinned DOWNWARD - to a level this CPU actually
// supports - or the pinned code executes instructions the CPU does not
// have. The ceiling is read out of rapidyenc itself: after
// `decoder_init()`, `_decode_isa` holds the level its own CPU detection
// chose, which is by construction the highest supported. The decoder's
// ISA_LEVEL_* constants are ordered, so on the DECODE side "want <=
// detected" is the whole test. It is NOT the whole test on the CRC side -
// see below.
//
// The setters fall back among themselves when a kernel was compiled out
// (decoder_vbmi2.cc's `#else` arm calls the avx2 setter, and so on), and
// each writes `_decode_isa` to what it ACTUALLY installed. So the pin
// reports the level in force AFTER the call, never the one it was asked
// for: a caller must check, not assume.
//
// A setter is called AT MOST ONCE per kernel here, and the three function
// pointers it installed are cached; a later pin to the same kernel
// reinstalls them from the cache. That is not a speed optimisation - it is
// what keeps this leak-free. Every SSE-family setter runs
// `ALIGN_ALLOC(lookups, sizeof(SSELookups), 16)` into a translation-unit
// static and never frees the old one, and `SSELookups::compact` alone is
// 512 KB, so a sweep that pinned by calling setters would strand half a
// megabyte per repeat - which LeakSanitizer reports, and libFuzzer runs
// LeakSanitizer after every input.
//
// THE CRC HALF, added 2 Sep 2026, is the same technique one module across
// and is NOT symmetric with the decode half in three ways. Getting each
// wrong is a different bug, so each is worked out against the vendor
// source rather than copied:
//
//  1. THREE pointers, and not every setter touches all three.
//     `crc.cc` dispatches through `_do_crc32_incremental` (hash bytes),
//     `_crc32_shift` and `_crc32_multiply` (the O(log n) matrix math
//     behind crc32_combine / crc32_zeros / crc32_unzero). ARM's
//     `crc_pmull_set_funcs()` sets ONLY shift and multiply and leaves
//     `_do_crc32_incremental` alone, because PMULL is a speed-up for the
//     matrix math layered on top of the ARMv8 CRC instruction, not a
//     replacement kernel. So ARMPMULL is pinned by calling the ARMCRC
//     setter FIRST and the PMULL setter second, exactly as `crc32_init()`
//     does. x86 is the other way round: `crc_clmul256_set_funcs()` calls
//     `crc_clmul_set_funcs()` itself before overriding the incremental
//     function, so one call is enough there.
//
//  2. "Downward" means different things on the two platforms, because
//     RYKERN_ARMCRC (8) and RYKERN_ARMPMULL (0x48) are FEATURE BITS while
//     RYKERN_PCLMUL (0x340) and RYKERN_VPCLMUL (0x440) are ordered
//     LEVELS. A subset test is right on ARM and wrong on x86 (0x340 &
//     0x440 == 0x40, so a legitimate VPCLMUL-CPU pin down to PCLMUL would
//     be refused); a numeric test is right on x86 and only accidentally
//     right on ARM. Each arm below uses the form that is actually true
//     for it. `cpu_supports_crc_isa()` returns a coarse 0/1/2 rather than
//     an ISA level, but `crc32_init()` turns that into _crc32_isa, so the
//     latched ceiling is still a kernel identifier and not a probe result.
//
//  3. NO CACHING, deliberately. The decode setters cache because they
//     leak 512 KB a call; every CRC setter (crc_folding.cc,
//     crc_folding_256.cc, crc_arm.cc, crc_arm_pmull.cc, crc_riscv.cc) is
//     nothing but pointer assignments - checked 2 Sep 2026, zero malloc /
//     ALIGN_ALLOC / new in any of the five - so calling one twice costs
//     nothing and strands nothing. `crc32_init()`'s one-time
//     `generate_crc32_slice_table()` malloc is not on this path: no setter
//     calls it. Caching here would be machinery guarding against a hazard
//     this side does not have.

// Included through the vendor ROOT, not through vendor/src: rapidyenc
// ships its own src/stdint.h, so putting src/ on the include path makes
// every later `#include <stdint.h>` resolve to it and the SDK headers stop
// compiling. A quoted include searches the includer's own directory first,
// so common.h still finds its neighbours from here.
#include "src/common.h"
#include "src/decoder_common.h"
#include "src/crc_common.h"

namespace {

typedef RapidYenc::YencDecoderEnd (*DecodeFn)(const unsigned char**, unsigned char**, size_t,
                                              RapidYenc::YencDecoderState*);

DecodeFn g_scalar_decode;
DecodeFn g_scalar_decode_raw;
DecodeFn g_scalar_decode_end_raw;

RapidYenc::crc_func g_scalar_crc;
RapidYenc::crc_mul_func g_scalar_crc_shift;
RapidYenc::crc_mul_func g_scalar_crc_multiply;

// Captures the scalar (ISA_GENERIC) function pointers so a pin can restore
// them. They are constant-initialised in decoder.cc - the address of a
// function is a constant expression - so those three pointers hold the
// scalar defaults before ANY dynamic initialiser runs, this one included.
// That is what makes capturing them here well defined rather than a race
// with `decoder_init()`.
//
// The same argument covers the three CRC pointers captured alongside them:
// `crc.cc` constant-initialises `_do_crc32_incremental`, `_crc32_shift` and
// `_crc32_multiply` to its generic implementations, and `crc32_init()` -
// the only thing that ever moves them - runs from Rust long after static
// initialisation. Two of the three generic functions (crc32_shift_generic,
// crc32_multiply_generic) are also declared in crc_common.h and could be
// named directly, but `do_crc32_incremental_generic` is file-static and
// cannot, so all three go through the capture: one mechanism to reason
// about rather than two, and it follows whatever a vendor re-sync installs.
struct ScalarCapture {
	ScalarCapture() {
		g_scalar_decode = RapidYenc::_do_decode;
		g_scalar_decode_raw = RapidYenc::_do_decode_raw;
		g_scalar_decode_end_raw = RapidYenc::_do_decode_end_raw;
		g_scalar_crc = RapidYenc::_do_crc32_incremental;
		g_scalar_crc_shift = RapidYenc::_crc32_shift;
		g_scalar_crc_multiply = RapidYenc::_crc32_multiply;
	}
};
ScalarCapture g_scalar_capture;

int g_detected = -1;
int g_crc_detected = -1;

// One slot per kernel: the three pointers its setter installed, captured
// the first time it ran. `level` is 0 while the slot is empty - ISA_GENERIC
// is 0 too, but generic never uses a slot (it restores from
// g_scalar_* instead), so the sentinel is unambiguous.
struct KernelSlot {
	int level;
	DecodeFn decode;
	DecodeFn decode_raw;
	DecodeFn decode_end_raw;
};
KernelSlot g_slots[8];

// Reinstall a cached kernel. Returns false when nothing is cached for it.
bool install_cached(int level) {
	for(const KernelSlot& s : g_slots) {
		if(s.level == level) {
			RapidYenc::_do_decode = s.decode;
			RapidYenc::_do_decode_raw = s.decode_raw;
			RapidYenc::_do_decode_end_raw = s.decode_end_raw;
			RapidYenc::_decode_isa = level;
			return true;
		}
	}
	return false;
}

// Cache whatever a setter just installed, under the level it reported.
void remember_installed(void) {
	const int level = RapidYenc::_decode_isa;
	if(level == ISA_GENERIC) return;
	for(KernelSlot& s : g_slots) {
		if(s.level == level) return; // already held
		if(s.level == 0) {
			s.level = level;
			s.decode = RapidYenc::_do_decode;
			s.decode_raw = RapidYenc::_do_decode_raw;
			s.decode_end_raw = RapidYenc::_do_decode_end_raw;
			return;
		}
	}
}

} // namespace

extern "C" {

// Latch the level rapidyenc's own CPU detection chose. Call this ONCE,
// immediately after `rapidyenc_decode_init()` and before any pin - after a
// pin, `_decode_isa` is the pinned level, not the detected one. The Rust
// side does exactly that, inside the same `Once` that runs the init.
int nzbfast_rapidyenc_latch_detected_kernel(void) {
	if(g_detected < 0) {
		g_detected = RapidYenc::_decode_isa;
		// `decoder_init()` has already run its setter for this kernel, so
		// cache what it installed rather than making the first pin back to
		// it run that setter a second time.
		remember_installed();
	}
	return g_detected;
}

// Pin the decode kernel to `want` (an RYKERN_* / ISA_LEVEL_* value).
// Returns the level actually in force afterwards, or -1 if `want` is not a
// kernel this build has, or is above what this CPU supports.
int nzbfast_rapidyenc_pin_decode_kernel(int want) {
	const int detected = nzbfast_rapidyenc_latch_detected_kernel();
	if(want == ISA_GENERIC) {
		RapidYenc::_do_decode = g_scalar_decode;
		RapidYenc::_do_decode_raw = g_scalar_decode_raw;
		RapidYenc::_do_decode_end_raw = g_scalar_decode_end_raw;
		RapidYenc::_decode_isa = ISA_GENERIC;
		return ISA_GENERIC;
	}
	if(want > detected) return -1;
	if(install_cached(want)) return want;
#ifdef PLATFORM_X86
	switch(want) {
		case ISA_LEVEL_SSE2:  RapidYenc::decoder_set_sse2_funcs();  break;
		case ISA_LEVEL_SSSE3: RapidYenc::decoder_set_ssse3_funcs(); break;
		case ISA_LEVEL_AVX:   RapidYenc::decoder_set_avx_funcs();   break;
		case ISA_LEVEL_AVX2:  RapidYenc::decoder_set_avx2_funcs();  break;
		case ISA_LEVEL_VBMI2: RapidYenc::decoder_set_vbmi2_funcs(); break;
		default: return -1;
	}
	remember_installed();
	return RapidYenc::_decode_isa;
#elif defined(PLATFORM_ARM)
	if(want == ISA_LEVEL_NEON) {
		RapidYenc::decoder_set_neon_funcs();
		remember_installed();
		return RapidYenc::_decode_isa;
	}
	return -1;
#else
	(void)want;
	return -1;
#endif
}

// Latch the CRC kernel rapidyenc's own CPU detection chose. Same contract
// as its decode twin: call it ONCE, right after `rapidyenc_crc_init()` and
// before any CRC pin, or it latches the pin instead of the ceiling.
int nzbfast_rapidyenc_latch_detected_crc_kernel(void) {
	if(g_crc_detected < 0) g_crc_detected = RapidYenc::_crc32_isa;
	return g_crc_detected;
}

// Pin the CRC kernel to `want` (an RYKERN_* value: GENERIC, PCLMUL,
// VPCLMUL on x86; GENERIC, ARMCRC, ARMPMULL on arm64). Returns the kernel
// actually in force afterwards, or -1 if `want` is not a CRC kernel this
// build has, or is above what this CPU supports.
//
// The setters fall back among themselves the way the decode ones do
// (crc_folding_256.cc's `#else` arm calls the PCLMUL setter and leaves
// `_crc32_isa` at PCLMUL), so the return value is read back out of
// rapidyenc rather than assumed to be `want`.
int nzbfast_rapidyenc_pin_crc_kernel(int want) {
	const int detected = nzbfast_rapidyenc_latch_detected_crc_kernel();
	if(want == ISA_GENERIC) {
		RapidYenc::_do_crc32_incremental = g_scalar_crc;
		RapidYenc::_crc32_shift = g_scalar_crc_shift;
		RapidYenc::_crc32_multiply = g_scalar_crc_multiply;
		RapidYenc::_crc32_isa = ISA_GENERIC;
		return ISA_GENERIC;
	}
#ifdef PLATFORM_X86
	// LEVELS, so the ordering test is numeric. The reachable ceilings are
	// GENERIC < PCLMUL < VPCLMUL and `cpu_supports_crc_isa()` gates
	// VPCLMUL behind everything PCLMUL needs, so "want <= detected" admits
	// exactly the kernels this CPU can run.
	if(want > detected) return -1;
	switch(want) {
		// Sets all three pointers.
		case ISA_LEVEL_PCLMUL:   RapidYenc::crc_clmul_set_funcs();    break;
		// Calls crc_clmul_set_funcs() itself for shift/multiply, then
		// overrides the incremental function - so one call, not two.
		case ISA_LEVEL_VPCLMUL:  RapidYenc::crc_clmul256_set_funcs(); break;
		default: return -1;
	}
	return RapidYenc::_crc32_isa;
#elif defined(PLATFORM_ARM)
	// FEATURE BITS, so the ordering test is a subset test. ISA_FEATURE_CRC
	// is 8 and ISA_FEATURE_PMULL is 0x40; RYKERN_ARMPMULL is both together,
	// because crc_arm_pmull.cc only compiles when the CRC kernel does.
	if((want & detected) != want) return -1;
	if(want == ISA_FEATURE_CRC || want == (ISA_FEATURE_CRC | ISA_FEATURE_PMULL)) {
		// ARMCRC first, always. Its setter ASSIGNS `_crc32_isa`, which is
		// what clears a previously pinned PMULL bit; the PMULL setter ORs
		// its bit in and swaps only shift/multiply, so calling it without
		// the CRC setter first would leave the generic byte hasher in
		// place under a kernel id claiming otherwise.
		RapidYenc::crc_arm_set_funcs();
		if(want & ISA_FEATURE_PMULL) RapidYenc::crc_pmull_set_funcs();
		return RapidYenc::_crc32_isa;
	}
	return -1;
#else
	// RISC-V's ZBC kernel is reachable through crc_riscv_set_funcs() and is
	// deliberately not wired up: no box on this fleet is riscv64, so a pin
	// here would be an arm nothing can run and nothing can test. The decode
	// side leaves RVV out for the same reason. Add both together if a
	// riscv64 target ever ships.
	(void)want;
	(void)detected;
	return -1;
#endif
}

// TEST SUPPORT: the address currently installed in one of the three CRC
// function pointers (0 = `_do_crc32_incremental`, 1 = `_crc32_shift`,
// 2 = `_crc32_multiply`), or 0 for any other selector.
//
// This exists to falsify the one way a kernel sweep can pass vacuously.
// Every assertion a differential makes is about ANSWERS, and a CRC is
// correct whichever kernel computed it - so a pin that moved `_crc32_isa`
// and nothing else would leave the sweep green while covering one kernel
// N times. In particular it is the check on the scalar capture above: if
// `ScalarCapture` ever ran after `crc32_init()` instead of before, pinning
// GENERIC would reinstall the ACCELERATED functions under the generic
// label and no answer-based test could tell.
uintptr_t nzbfast_rapidyenc_crc_impl_addr(int which) {
	switch(which) {
		case 0: return (uintptr_t)RapidYenc::_do_crc32_incremental;
		case 1: return (uintptr_t)RapidYenc::_crc32_shift;
		case 2: return (uintptr_t)RapidYenc::_crc32_multiply;
		default: return 0;
	}
}

// Is the C++ half of this build compiled with AddressSanitizer?
//
// `crates/nzbkit/build.rs` adds `-fsanitize=address` to every rapidyenc
// object when the RUST half is sanitized, and this file goes through the
// same `base_build()`, so the answer here is the answer for all of them.
//
// WHY THIS IS WORTH AN EXPORTED FUNCTION RATHER THAN A COMMENT. rapidyenc
// is the only memory-unsafe parse code nzbfast ships, so that flag going
// missing costs it its entire sanitizer coverage - and on gcc it would go
// missing SILENTLY. The loud failure build.rs documents (an undefined
// `___asan_version_mismatch_check_apple_clang_*`) is an APPLE CLANG
// symptom; a gcc build with the flag absent links perfectly and reports
// nothing, which is exactly the shipped state that
// `research/SANDBOX-SCOPING-2026-08.md` section 2.5 gap (iv) measured as
// blind. `yenc_decode` prints this beside the kernel it pinned, so a fuzz
// run SAYS whether its C++ was watched instead of leaving it to be
// inferred from the platform - the same reason that target prints the
// kernel in force at all.
//
// False in an ordinary build, and that is correct: build.rs adds the flag
// only for sanitized builds, so `cargo build` and every CI job but the
// fuzz ones are untouched.
int nzbfast_rapidyenc_asan_instrumented(void) {
#if defined(__SANITIZE_ADDRESS__)
	// gcc's spelling, and clang's too since clang 18.
	return 1;
#elif defined(__has_feature)
#  if __has_feature(address_sanitizer)
	// Older clang, including the Apple clang this is developed against.
	return 1;
#  else
	return 0;
#  endif
#else
	return 0;
#endif
}

} // extern "C"
