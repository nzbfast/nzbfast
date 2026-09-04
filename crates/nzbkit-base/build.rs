//! Build rapidyenc (vendor/rapidyenc) as a static library - decode + CRC only.
//!
//! We drive the `cc` crate rather than cmake (cmake is not installed on the
//! dev machine). This replicates upstream CMakeLists.txt: every kernel source
//! is compiled with the arch flags it needs; the sources self-guard with
//! `#ifdef PLATFORM_X86` / `__aarch64__` etc., so files for a foreign ISA
//! compile to empty objects. Runtime CPU detection in decoder.cc / crc.cc
//! picks the best kernel (NEON + ARMv8 CRC/PMULL on Apple Silicon).
//!
//! Encoder is excluded (RAPIDYENC_DISABLE_ENCODE) - nzbfast only decodes.
//! crcutil is excluded (YENC_DISABLE_CRCUTIL) - rapidyenc's own slice-by-4
//! generic CRC covers the no-SIMD case, and this keeps the Apache-2.0
//! crcutil code out of our binaries entirely.
//!
//! FUZZ BUILDS ADDITIONALLY GET `-fsanitize=address` (see
//! `asan_requested()`). Without it the one memory-unsafe component
//! nzbfast ships was the one component ASan was not watching: cargo-fuzz
//! drives the sanitizer through RUSTFLAGS, the `cc` crate reads CFLAGS /
//! CXXFLAGS, and cargo-fuzz sets neither. Measured on 2 Sep 2026 rather
//! than assumed - `research/SANDBOX-SCOPING-2026-08.md` section 2.5 gap
//! (iv) called it unverified, and the experiment that settled it is
//! recorded there.

use std::path::Path;

const VENDOR: &str = "../../vendor/rapidyenc";

/// True when the RUST half of this build is being compiled with
/// AddressSanitizer - which in practice means cargo-fuzz.
///
/// This is the condition, rather than "is this a fuzz build", on purpose:
/// `cargo fuzz build -s none` and `-s memory` are both fuzz builds that
/// must NOT get `-fsanitize=address`, and the flag has to match whatever
/// runtime the final link pulls in.
///
/// Read out of `CARGO_ENCODED_RUSTFLAGS` (unit-separated, the form cargo
/// gives a build script) with plain `RUSTFLAGS` as a fallback. Measured
/// under `cargo fuzz build` on 2 Sep 2026: `CARGO_ENCODED_RUSTFLAGS`
/// carries `-Zsanitizer=address`, and `CXXFLAGS` / `CXXFLAGS_<target>`
/// are all unset - so nothing else in this build was ever going to reach
/// the C++.
fn asan_requested() -> bool {
    let encoded = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let plain = std::env::var("RUSTFLAGS").unwrap_or_default();
    let all = format!("{} {}", encoded.replace('\u{1f}', " "), plain);
    all.split_whitespace().any(|f| {
        f.strip_prefix("-Zsanitizer=")
            .is_some_and(|list| list.split(',').any(|s| s == "address"))
    })
}

fn base_build() -> cc::Build {
    let mut b = cc::Build::new();
    b.cpp(true)
        .include(VENDOR)
        .define("RAPIDYENC_DISABLE_ENCODE", "1")
        .define("YENC_DISABLE_CRCUTIL", "1")
        .opt_level(3)
        .flag_if_supported("-fno-exceptions")
        .flag_if_supported("-fno-rtti")
        .flag_if_supported("-fwrapv")
        .flag_if_supported("-fvisibility=hidden")
        .warnings(false);
    if asan_requested() {
        // A frame pointer is what makes the report name the kernel the
        // fault was in, so the omit-frame-pointer above is dropped for
        // exactly these builds and nothing else.
        b.flag("-fsanitize=address").flag("-fno-omit-frame-pointer");
        // Apple clang emits a call to a version-check symbol of its own
        // (`___asan_version_mismatch_check_apple_clang_2100` on clang 21)
        // that rustc's bundled compiler-rt runtime does not export, so
        // the fuzz binary fails to LINK - which is how this arrives if
        // the flag is dropped: not as silent loss of coverage but as a
        // loud undefined symbol. This LLVM knob suppresses the check, and
        // it must be two separate arguments (`-mllvm` folded into the
        // -fsanitize= argument is rejected by the driver). Guarded on
        // clang because gcc has no `-mllvm`, and gcc emits the portable
        // `__asan_version_mismatch_check_v8`, which that runtime does
        // export.
        if b.get_compiler().is_like_clang() {
            b.flag("-mllvm")
                .flag("-asan-guard-against-version-mismatch=0");
        }
    } else {
        b.flag_if_supported("-fomit-frame-pointer");
    }
    b
}

fn compile_group(lib: &str, files: &[&str], flags: &[&str]) {
    let mut b = base_build();
    for f in files {
        b.file(Path::new(VENDOR).join(f));
    }
    for fl in flags {
        b.flag_if_supported(fl);
    }
    b.compile(lib);
}

fn main() {
    println!("cargo:rerun-if-changed=csrc");
    println!("cargo:rerun-if-changed={VENDOR}/rapidyenc.cc");
    println!("cargo:rerun-if-changed={VENDOR}/rapidyenc.h");
    println!("cargo:rerun-if-changed={VENDOR}/src");

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let is_x86 = arch == "x86_64" || arch == "x86";
    let is_arm64 = arch == "aarch64";

    // Core: dispatchers, generic kernels, the C API wrapper. No arch flags -
    // these must run on any CPU of the target family.
    let mut core: Vec<&str> = vec![
        "src/platform.cc",
        "src/decoder.cc",
        "src/crc.cc",
        "rapidyenc.cc",
    ];
    // NEON is baseline on aarch64: no extra flags needed, so it can live in
    // the core group (upstream compiles decoder_neon64.cc with no flags too).
    if is_arm64 {
        core.push("src/decoder_neon64.cc");
    } else if !is_x86 {
        core.push("src/decoder_neon.cc"); // self-guards; empty off-ARM
    }
    // Self-guarding no-ops off their ISA; harmless to include everywhere.
    core.push("src/decoder_rvv.cc");
    core.push("src/crc_riscv.cc");
    compile_group("rapidyenc_core", &core, &[]);

    if is_x86 {
        compile_group("ry_dec_sse2", &["src/decoder_sse2.cc"], &["-msse2"]);
        compile_group("ry_dec_ssse3", &["src/decoder_ssse3.cc"], &["-mssse3"]);
        compile_group(
            "ry_dec_avx",
            &["src/decoder_avx.cc"],
            &["-mavx", "-mpopcnt"],
        );
        compile_group(
            "ry_dec_avx2",
            &["src/decoder_avx2.cc"],
            &["-mavx2", "-mpopcnt", "-mbmi", "-mbmi2", "-mlzcnt"],
        );
        compile_group(
            "ry_dec_vbmi2",
            &["src/decoder_vbmi2.cc"],
            &[
                "-mavx512vbmi2",
                "-mavx512vl",
                "-mavx512bw",
                "-mpopcnt",
                "-mbmi",
                "-mbmi2",
                "-mlzcnt",
            ],
        );
        compile_group(
            "ry_crc_fold",
            &["src/crc_folding.cc"],
            &["-mssse3", "-msse4.1", "-mpclmul"],
        );
        compile_group(
            "ry_crc_fold256",
            &["src/crc_folding_256.cc"],
            &["-mavx2", "-mvpclmulqdq", "-mpclmul"],
        );
    } else {
        // Off-x86 these compile empty, but decoder.cc's x86 dispatch table is
        // fully #ifdef'd out, so we can simply skip them. ARM CRC kernels do
        // need their feature flags:
        compile_group("ry_crc_arm", &["src/crc_arm.cc"], &["-march=armv8-a+crc"]);
        compile_group(
            "ry_crc_pmull",
            &["src/crc_arm_pmull.cc"],
            &["-march=armv8-a+crypto+crc"],
        );
    }

    // Our own shim, NOT vendor code: it reaches rapidyenc's per-kernel
    // setters so a fuzz run or a test can exercise more than the one
    // kernel this CPU selects. No arch flags - it only calls the setters,
    // it contains no SIMD of its own - and the vendor ROOT is the only
    // include path it gets (see the note at the top of the shim: src/ on
    // the include path shadows the SDK's stdint.h).
    {
        let mut b = base_build();
        b.file("csrc/yenc_kernel_pin.cc");
        b.compile("nzbfast_yenc_kernel_pin");
    }
}
