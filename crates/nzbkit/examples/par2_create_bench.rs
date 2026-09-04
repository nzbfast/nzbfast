//! Time the native PAR2 creator (`par2gen::create_into`) over a directory
//! of files, for the create leg of the component rig - the one leg where
//! ParPar is the reference, since ParPar only creates.
//!
//! cargo run --release -p nzbkit --example par2_create_bench -- <dir> <out-dir> [redundancy_pct] [block_size]
//!
//! Every regular file in <dir> is a member (names = leaf names); the set
//! is written into <out-dir> as `bench.par2` + volumes.

use std::time::Instant;

fn main() {
    // Timing lines are tracing events; without a sink NZBFAST_REPAIR_TIMING prints nothing.
    tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_target(true)
        .with_writer(std::io::stderr)
        .init();
    let mut args = std::env::args().skip(1);
    let dir = std::path::PathBuf::from(
        args.next()
            .expect("usage: par2_create_bench <dir> <out-dir> [pct] [bs]"),
    );
    let out = std::path::PathBuf::from(
        args.next()
            .expect("usage: par2_create_bench <dir> <out-dir> [pct] [bs]"),
    );
    let pct: u32 = args.next().and_then(|v| v.parse().ok()).unwrap_or(10);
    let bs: Option<u64> = args.next().and_then(|v| v.parse().ok());
    nzbkit::mem::opt_out_of_power_throttling();
    let mut members: Vec<nzbkit::par2gen::Member> = std::fs::read_dir(&dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        // A rig directory carries the set's own PAR2 files beside the
        // payload; the rivals are handed the payload only.
        .filter(|e| !e.file_name().to_string_lossy().ends_with(".par2"))
        .map(|e| nzbkit::par2gen::Member {
            name: e.file_name().to_string_lossy().into_owned(),
            path: e.path(),
        })
        .collect();
    members.sort_by(|a, b| a.name.cmp(&b.name));
    std::fs::create_dir_all(&out).expect("out dir");
    let spec = nzbkit::par2gen::Par2Spec {
        redundancy_pct: pct,
        block_size: bs,
    };
    let t0 = Instant::now();
    let files = nzbkit::par2gen::create_into(&out, &members, "bench", &spec).expect("create");
    let dt = t0.elapsed();
    let bytes: u64 = files
        .iter()
        .map(|f| std::fs::metadata(out.join(f)).map(|m| m.len()).unwrap_or(0))
        .sum();
    println!(
        "create {} members, {pct}% redundancy, bs {:?}: {:.3?} ({} files, {:.1} MB written)",
        members.len(),
        bs,
        dt,
        files.len(),
        bytes as f64 / 1e6
    );
}
