//! A/B the crate's MD5 (`nzbkit::md5fast::Md5`) against the `md-5` crate,
//! in one process, interleaved.
//!
//! This exists because the choice between the two is a compile-time
//! `cfg` (see `md5fast`'s header), so "before and after" would otherwise
//! mean two binaries and two build clocks - and on the Windows rigs that
//! is 3 to 20 minutes an arm, with the box's state moving underneath.
//! One binary that runs both arms back to back, several times, removes
//! every question about which build produced which number.
//!
//! On Windows x86-64 arm A is this crate's inline-assembly block
//! function and arm B is `md-5`'s portable Rust one - the comparison the
//! 2 Sep 2026 PAR2 audit's section 6 item 0c asks for. On ARM64 macOS
//! and Linux arm A is AWS-LC's assembly block function and arm B is the
//! same portable `md-5`. On x86-64 macOS and Linux arm A is `md-5` WITH
//! its `asm` feature (the `md5-asm` crate, Nayuki's routine) and arm B
//! is that same crate, so the A/B pair is a noise floor - which is
//! itself worth printing: it says how much of any delta is method rather
//! than implementation.
//!
//! Wherever `md5fast::awslc` compiles (every x86-64 and ARM64 desktop
//! target since 13 Sep 2026) a THIRD arm, `awslc`, runs AWS-LC's
//! assembly block function beside the two. On ARM64 that is arm A
//! again; on x86-64 it is the comparison the single-file create chip
//! asked for (research/PARFAST-SINGLE-FILE-CREATE-VS-PARPAR-2026-09-13.md):
//! `md5-x86_64.pl` keeps its LEA off the 64-step chain and `md5-asm`
//! has it on, and only a number says what that is worth.
//!
//! Shape copied from `sysbench::compute` deliberately, so the per-core
//! figure here is comparable with `nzbfast bench-cpu`'s md5 line: 1 MiB
//! chunks, one-shot digests, single thread then one thread per core.
//!
//!   cargo run --release -p nzbkit --example md5_ab_bench [-- <MiB> <reps>]

use std::hint::black_box;
use std::time::Instant;

fn payload(bytes: usize) -> Vec<u8> {
    // xorshift64*, so the corpus is the same on every box and every run.
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut v = vec![0u8; bytes];
    for b in v.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = (s >> 33) as u8;
    }
    v
}

fn timed(p: &[u8], cores: usize, f: &(dyn Fn(&[u8]) + Sync)) -> (f64, f64) {
    let t0 = Instant::now();
    f(p);
    let one = p.len() as f64 / t0.elapsed().as_secs_f64() / 1e9;
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..cores {
            s.spawn(|| f(p));
        }
    });
    let all = (p.len() * cores) as f64 / t0.elapsed().as_secs_f64() / 1e9;
    (one, all)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mib: usize = args.first().and_then(|a| a.parse().ok()).unwrap_or(256);
    let reps: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(3);
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    let p = payload(mib << 20);

    let ours = |p: &[u8]| {
        use nzbkit::md5fast::{Digest, Md5};
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5::digest(c).into();
            black_box(d);
        }
    };
    let refr = |p: &[u8]| {
        use md5::{Digest, Md5};
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5::digest(c).into();
            black_box(d);
        }
    };
    #[cfg(any(
        all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
        all(
            target_arch = "x86_64",
            any(target_os = "macos", target_os = "linux", target_os = "windows")
        )
    ))]
    let awslc = Some(|p: &[u8]| {
        use nzbkit::md5fast::Digest;
        use nzbkit::md5fast::awslc::Md5;
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5::digest(c).into();
            black_box(d);
        }
    });
    #[cfg(not(any(
        all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
        all(
            target_arch = "x86_64",
            any(target_os = "macos", target_os = "linux", target_os = "windows")
        )
    )))]
    let awslc: Option<fn(&[u8])> = None;
    // The fourth arm, Windows x86-64 only: the inline-assembly port that
    // was the Windows `Md5` until 13 Sep 2026.
    #[cfg(all(windows, target_arch = "x86_64"))]
    let winasm = Some(|p: &[u8]| {
        use nzbkit::md5fast::{Digest, Md5WinAsm};
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5WinAsm::digest(c).into();
            black_box(d);
        }
    });
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    let winasm: Option<fn(&[u8])> = None;

    // Correctness before speed: a fast wrong hash is worth nothing, and
    // this prints on the same box that produced the timings.
    {
        use md5::Digest as _;
        for n in [
            0usize,
            1,
            55,
            56,
            63,
            64,
            65,
            119,
            120,
            1000,
            1 << 20,
            p.len(),
        ] {
            let a: [u8; 16] =
                <nzbkit::md5fast::Md5 as nzbkit::md5fast::Digest>::digest(&p[..n]).into();
            let b: [u8; 16] = md5::Md5::digest(&p[..n]).into();
            assert_eq!(a, b, "md5 mismatch at len {n}");
            #[cfg(any(
                all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")),
                all(
                    target_arch = "x86_64",
                    any(target_os = "macos", target_os = "linux", target_os = "windows")
                )
            ))]
            {
                let c: [u8; 16] =
                    <nzbkit::md5fast::awslc::Md5 as nzbkit::md5fast::Digest>::digest(&p[..n])
                        .into();
                assert_eq!(c, b, "awslc md5 mismatch at len {n}");
            }
            #[cfg(all(windows, target_arch = "x86_64"))]
            {
                let w: [u8; 16] =
                    <nzbkit::md5fast::Md5WinAsm as nzbkit::md5fast::Digest>::digest(&p[..n]).into();
                assert_eq!(w, b, "winasm md5 mismatch at len {n}");
            }
        }
        println!(
            "AGREE ours == md-5{}{} over 12 lengths up to {} MiB",
            if awslc.is_some() { " == awslc" } else { "" },
            if winasm.is_some() { " == winasm" } else { "" },
            mib
        );
    }

    println!("cpu cores={cores} payload={mib} MiB reps={reps}  (GB/s, higher is better)");
    // One untimed pass of each arm first: the page cache, the thread
    // pool and the clock are all cold on rep 1 otherwise, and on a
    // 32-core box that alone moved an all-core figure 19% between two
    // reps of the SAME code.
    timed(&p, cores, &ours);
    timed(&p, cores, &refr);
    if let Some(f) = awslc.as_ref() {
        timed(&p, cores, f);
    }
    if let Some(f) = winasm.as_ref() {
        timed(&p, cores, f);
    }

    let mut best = (0.0f64, 0.0f64, 0.0f64, 0.0f64, 0.0f64, 0.0f64);
    for r in 1..=reps {
        let (o1, oa) = timed(&p, cores, &ours);
        let (r1, ra) = timed(&p, cores, &refr);
        let (l1, la) = awslc.as_ref().map_or((0.0, 0.0), |f| timed(&p, cores, f));
        let (w1, wa) = winasm.as_ref().map_or((0.0, 0.0), |f| timed(&p, cores, f));
        print!(
            "REP {r} ours 1c={o1:.3} all={oa:.3} | md-5 1c={r1:.3} all={ra:.3} | \
             delta 1c={:+.1}% all={:+.1}%",
            (o1 / r1 - 1.0) * 100.0,
            (oa / ra - 1.0) * 100.0
        );
        if awslc.is_some() {
            print!(
                " | awslc 1c={l1:.3} all={la:.3} | awslc/md-5 1c={:+.1}% all={:+.1}%",
                (l1 / r1 - 1.0) * 100.0,
                (la / ra - 1.0) * 100.0
            );
        }
        if winasm.is_some() {
            print!(
                " | winasm 1c={w1:.3} all={wa:.3} | winasm/md-5 1c={:+.1}% all={:+.1}%",
                (w1 / r1 - 1.0) * 100.0,
                (wa / ra - 1.0) * 100.0
            );
        }
        println!();
        best = (
            best.0.max(o1),
            best.1.max(oa),
            best.2.max(r1),
            best.3.max(ra),
            best.4.max(l1),
            best.5.max(la),
        );
    }
    print!(
        "BEST ours 1c={:.3} all={:.3} | md-5 1c={:.3} all={:.3} | delta 1c={:+.1}% all={:+.1}%",
        best.0,
        best.1,
        best.2,
        best.3,
        (best.0 / best.2 - 1.0) * 100.0,
        (best.1 / best.3 - 1.0) * 100.0
    );
    if awslc.is_some() {
        print!(
            " | awslc 1c={:.3} all={:.3} | awslc/md-5 1c={:+.1}% all={:+.1}%",
            best.4,
            best.5,
            (best.4 / best.2 - 1.0) * 100.0,
            (best.5 / best.3 - 1.0) * 100.0
        );
    }
    println!();
}
