//! Rig pre-flight: which `gf16` multi-fold kernel does THIS part select?
//!
//! A row-gate or fold round's whole premise is the kernel class of the box it
//! ran on, and the model name is not that answer - a part can carry AVX-512
//! and still not select the fan-in-12 leaf. So the reading is TAKEN, on the
//! metal, from a release build of the tree the round will use:
//!
//!     cargo run --release -p nzbkit-base --example kernelclass
//!
//! This existed as an untracked file on two rig boxes from 16 Sep 2026, which
//! meant the premise check for `avx512-bare-metal-row-gate` could not be
//! reproduced from the repository by anyone who did not already have those
//! boxes. Tracked 17 Sep 2026 for that reason.
//!
//! It is PORTABLE on purpose. The original was x86-only
//! (`is_x86_feature_detected!` does not exist on other arches), and the clippy
//! gate builds `--all-targets`, so an x86-only example in this crate reddens
//! every aarch64 box in the fleet - which is every dev Mac here.

fn main() {
    let w = nzbkit_base::gf16::multi_fold_width();
    // Keep these names identical to `par2seams::KernelClass`'s, so a round's
    // log line and the class a lane quotes in a note are the same words.
    let class = match w {
        12 => "AVX-512 GFNI (fan-in 12)",
        8 => "aarch64 NEON (fan-in 8)",
        6 => "GFNI-256 (fan-in 6)",
        4 => "nibble AVX2/SSSE3 (fan-in 4)",
        0 => "no multi kernel",
        _ => "unknown",
    };
    println!("multi_fold_width = {w}  -> {class}");
    println!("arch = {}", std::env::consts::ARCH);

    #[cfg(target_arch = "x86_64")]
    {
        println!(
            "cpu_features: avx2={} avx512f={} gfni={} vpclmulqdq={}",
            is_x86_feature_detected!("avx2"),
            is_x86_feature_detected!("avx512f"),
            is_x86_feature_detected!("gfni"),
            is_x86_feature_detected!("vpclmulqdq")
        );
        println!(
            "             avx512bw={} avx512vl={}",
            is_x86_feature_detected!("avx512bw"),
            is_x86_feature_detected!("avx512vl")
        );
    }
    #[cfg(target_arch = "aarch64")]
    {
        println!(
            "cpu_features: neon={} pmull={} sha3={}",
            std::arch::is_aarch64_feature_detected!("neon"),
            std::arch::is_aarch64_feature_detected!("pmull"),
            std::arch::is_aarch64_feature_detected!("sha3")
        );
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        println!("cpu_features: not reported on this architecture");
    }
}
