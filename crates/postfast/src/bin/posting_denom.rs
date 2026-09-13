//! Research-only measurement driver for RAR5 creation's share of
//! end-to-end posting wall time.
//!
//! Times each phase of a real posting job over REAL files on disk,
//! using exactly the production entry points a real post goes through
//! (`postfast::container::wrap_with` with `Packing::LAZY`,
//! `postfast::recovery::build`, `postfast::naming::plan`,
//! `postfast::encode::encode`) rather than a second implementation of
//! any of them; the source read is a plain per-file `std::fs::read`
//! rather than `postfast::post::read_inputs` (see the comment at its
//! call site for why). This binary changes no production default: it
//! is a caller, like `postfast gen`/`postfast post`, that happens to
//! print `Instant`/`getrusage` deltas around each call instead of
//! writing a layout to disk.
//!
//! Usage: `posting_denom <redundancy_pct> <file>...`
//!
//! Prints one line of tab-separated phase timings (wall_ms and cpu_ms,
//! both process-wide via `getrusage(RUSAGE_SELF)`, which is the whole
//! process's user+sys time across every thread a phase used - rars and
//! the recovery builder both pool threads internally):
//!
//!   read_wall_ms read_cpu_ms rar_wall_ms rar_cpu_ms par2_wall_ms
//!   par2_cpu_ms yenc_wall_ms yenc_cpu_ms total_bytes rar_bytes par2_bytes

use std::path::PathBuf;
use std::time::Instant;

use postfast::assemble::SourceFile;
use postfast::container::{self, Packing};
use postfast::encode;
use postfast::naming;
use postfast::post::{self, Input};
use postfast::profile::Profile;
use postfast::recovery;
use postfast::rng::Rng;

// getrusage(RUSAGE_SELF): process-wide user+sys CPU seconds across
// every thread, without pulling in a crate for two fields. The trailing
// buffer is sized well past the real `struct rusage` (16 longs plus two
// timevals on Darwin) so the kernel never writes past what we own; we
// never read past the two timevals we declared.
#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i32,
    _pad: i32,
}
#[repr(C)]
struct RUsageHead {
    ru_utime: Timeval,
    ru_stime: Timeval,
    _rest: [u8; 256],
}
unsafe extern "C" {
    fn getrusage(who: i32, usage: *mut RUsageHead) -> i32;
}
const RUSAGE_SELF: i32 = 0;

fn cpu_seconds() -> f64 {
    // SAFETY: an all-zero `RUsageHead` (two all-zero `Timeval`s plus a
    // zeroed trailing buffer) is a valid bit pattern for this repr(C)
    // struct - every field is a plain integer, nothing here is a
    // reference or has an invariant zero would violate.
    let mut ru: RUsageHead = unsafe { std::mem::zeroed() };
    // SAFETY: `ru` is a valid, uniquely-owned `RUsageHead` for the
    // duration of this call and the buffer is sized well past the real
    // Darwin `struct rusage`, so the kernel writes only within it.
    let rc = unsafe { getrusage(RUSAGE_SELF, &mut ru as *mut _) };
    assert_eq!(rc, 0, "getrusage failed");
    let u = ru.ru_utime.tv_sec as f64 + ru.ru_utime.tv_usec as f64 / 1e6;
    let s = ru.ru_stime.tv_sec as f64 + ru.ru_stime.tv_usec as f64 / 1e6;
    u + s
}

struct Phase {
    wall: f64,
    cpu: f64,
}

fn time_phase<F: FnOnce() -> R, R>(f: F) -> (Phase, R) {
    let w0 = Instant::now();
    let c0 = cpu_seconds();
    let r = f();
    let phase = Phase {
        wall: w0.elapsed().as_secs_f64(),
        cpu: cpu_seconds() - c0,
    };
    (phase, r)
}

const PROFILE_TOML: &str = r#"
[layout]
name = "posting-denom"
seed = 1

[source]
files = [{ name = "placeholder.bin", bytes = 1 }]

[container]
kind = "rar-compressed"

[recovery]
kind = "par2"
"#;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: posting_denom <redundancy_pct> <file>...");
        std::process::exit(2);
    }
    let redundancy_pct: u32 = args[0].parse().expect("redundancy_pct must be an integer");
    let paths: Vec<PathBuf> = args[1..].iter().map(PathBuf::from).collect();

    // --- source read -----------------------------------------------
    //
    // `post::read_inputs` is the CLI verb's own convenience wrapper and
    // enforces `assemble::MAX_TOTAL_PAYLOAD` (256 MiB) - a limit on
    // that gated verb's own catalog/oracle use, not on the functions
    // this driver is timing (`container::wrap_with`, `recovery::build`,
    // `encode::encode` take arbitrary byte slices and enforce no such
    // cap). A representative movie or season-pack corpus is well over
    // 256 MiB, so this does the same walk-and-read `read_inputs` does,
    // without its cap, to reach the sizes those functions actually see
    // in production.
    let (read_phase, inputs) = time_phase(|| {
        paths
            .iter()
            .map(|p| {
                let rel = p
                    .file_name()
                    .expect("path has a file name")
                    .to_string_lossy()
                    .into_owned();
                let bytes = std::fs::read(p).expect("read source file failed");
                Input { rel, bytes }
            })
            .collect::<Vec<Input>>()
    });

    let mut profile = Profile::parse(PROFILE_TOML).expect("bad embedded profile");
    profile.recovery.redundancy_pct = redundancy_pct;
    let profile = post::override_source(&profile, &inputs);
    profile
        .validate()
        .expect("profile invalid after override_source");

    let sources: Vec<SourceFile> = inputs
        .iter()
        .map(|i| SourceFile {
            rel: i.rel.clone(),
            base: i.rel.clone(),
            bytes: i.bytes.clone(),
        })
        .collect();
    let total_bytes: u64 = sources.iter().map(|s| s.bytes.len() as u64).sum();

    let mut rng = Rng::for_profile(&profile);

    // --- RAR5 creation ---------------------------------------------------
    let (rar_phase, contained) = time_phase(|| {
        container::wrap_with(&profile, &sources, &mut rng, Packing::LAZY)
            .expect("container::wrap_with failed")
    });
    let carried: &[SourceFile] = match &contained {
        Some(c) => &c.volumes,
        None => &sources,
    };
    let rar_bytes: u64 = carried.iter().map(|s| s.bytes.len() as u64).sum();

    // --- PAR2 creation ---------------------------------------------------
    let (par2_phase, recovered) =
        time_phase(|| recovery::build(&profile, carried).expect("recovery::build failed"));
    let par2_bytes: u64 = recovered.files.iter().map(|f| f.bytes.len() as u64).sum();

    let posted: Vec<SourceFile> = carried
        .iter()
        .enumerate()
        .filter(|(i, _)| !recovered.is_unposted(*i))
        .map(|(_, s)| s.clone())
        .collect();
    let payload_files = posted.len();
    let mut plan = naming::plan(&profile, &posted, &mut rng).expect("naming::plan failed");
    plan.files
        .extend(naming::plan_recovery(&profile, &recovered.files, &mut rng));
    let mut all = posted;
    for f in &recovered.files {
        all.push(SourceFile {
            rel: f.name.clone(),
            base: f.name.clone(),
            bytes: f.bytes.clone(),
        });
    }

    // --- yEnc encode ---------------------------------------------------
    let (yenc_phase, _articles) = time_phase(|| {
        encode::encode(&profile, &all, &plan, payload_files, &mut rng).expect("encode failed")
    });

    println!(
        "{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{}\t{}\t{}",
        read_phase.wall * 1000.0,
        read_phase.cpu * 1000.0,
        rar_phase.wall * 1000.0,
        rar_phase.cpu * 1000.0,
        par2_phase.wall * 1000.0,
        par2_phase.cpu * 1000.0,
        yenc_phase.wall * 1000.0,
        yenc_phase.cpu * 1000.0,
        total_bytes,
        rar_bytes,
        par2_bytes,
    );
}
