//! Run N `par2gen::create_into` calls CONCURRENTLY in one process, so the
//! footprint of simultaneous creates can be measured against one.
//!
//! Codex's ranked remaining item 3 ("process-wide create admission") says the
//! creator's scan ceiling is INVOCATION-wide rather than process-wide, and
//! that the recovery accumulators and the transform's window are accounted by
//! their own separate budgets on top of it. Nothing in the tree measured what
//! two simultaneous creates actually cost, so this is the instrument for it.
//!
//! ```text
//! cargo run --release -p nzbkit --example par2_create_concurrent_bench -- \
//!     <root> <lanes> <members-per-lane> <member-bytes> <pct> <block-bytes>
//! ```
//!
//! `<root>/lane<i>/src` is generated once and REUSED on a later run with the
//! same geometry, so an A/B over lane counts reads the same bytes every time;
//! delete the root to regenerate. Each lane writes into its own `out` dir, so
//! no two lanes share an output file, and every lane's produced file names and
//! their SHA-256 are printed - a lane count must not change the output.
//!
//! Peak RSS is the point, and it belongs to the PROCESS: take it from
//! `/usr/bin/time -l` (macOS) or `-v` (Linux) around the whole command.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn arg<T: std::str::FromStr>(args: &mut impl Iterator<Item = String>, what: &str) -> T {
    args.next()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("expected {what}"))
}

/// Deterministic filler, so a regenerated fixture is the same fixture.
fn fill(buf: &mut [u8], mut seed: u64) {
    for chunk in buf.chunks_mut(8) {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let b = seed.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}

fn ensure_member(path: &Path, bytes: u64, seed: u64) {
    if std::fs::metadata(path).map(|m| m.len()).ok() == Some(bytes) {
        return;
    }
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).expect("create member"));
    let mut buf = vec![0u8; (4 << 20).min(bytes) as usize];
    let mut left = bytes;
    let mut s = seed;
    while left > 0 {
        let n = (buf.len() as u64).min(left) as usize;
        s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
        fill(&mut buf[..n], s);
        f.write_all(&buf[..n]).expect("write member");
        left -= n as u64;
    }
    f.flush().expect("flush member");
}

fn main() {
    let mut args = std::env::args().skip(1);
    let root = PathBuf::from(
        args.next()
            .expect("usage: <root> <lanes> <members> <bytes> <pct> <bs>"),
    );
    let lanes: usize = arg(&mut args, "lanes");
    let members: usize = arg(&mut args, "members-per-lane");
    let member_bytes: u64 = arg(&mut args, "member-bytes");
    let pct: u32 = arg(&mut args, "pct");
    let block_bytes: u64 = arg(&mut args, "block-bytes");
    nzbkit::mem::opt_out_of_power_throttling();
    // A daemon publishes its budget at startup; a bench that does not is
    // measuring `MemBudget::auto`, which on a 512 GB box bounds nothing.
    if let Some(total) = std::env::var("NZBFAST_BENCH_MEM_LIMIT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
    {
        nzbkit::mem::set_process_budget(nzbkit::mem::MemBudget { total });
    }
    println!(
        "process budget {} B, scan pool {} B, accumulators {} B",
        nzbkit::mem::process_budget().total,
        nzbkit::par2gen::scan_pool_budget_bytes(),
        nzbkit::par2gen::accum_budget_bytes(),
    );

    let mut lane_members: Vec<Vec<nzbkit::par2gen::Member>> = Vec::new();
    let mut outs: Vec<PathBuf> = Vec::new();
    for l in 0..lanes {
        let src = root.join(format!("lane{l}/src"));
        let out = root.join(format!("lane{l}/out"));
        std::fs::create_dir_all(&src).expect("src dir");
        // A stale out dir would let a lane read back another round's set.
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out).expect("out dir");
        let mut ms = Vec::with_capacity(members);
        for m in 0..members {
            let name = format!("m{m:04}.bin");
            let p = src.join(&name);
            // Every lane gets the SAME payload bytes, so a lane's output is
            // comparable across lane counts, but its own COPY of them, so two
            // lanes never share a page-cache page and the footprint is honest.
            ensure_member(&p, member_bytes, m as u64 + 1);
            ms.push(nzbkit::par2gen::Member { name, path: p });
        }
        lane_members.push(ms);
        outs.push(out);
    }

    let spec = nzbkit::par2gen::Par2Spec {
        redundancy_pct: pct,
        block_size: (block_bytes != 0).then_some(block_bytes),
    };
    let t0 = Instant::now();
    let mut results: Vec<(std::time::Duration, Vec<(String, String)>)> = Vec::new();
    std::thread::scope(|s| {
        let handles: Vec<_> = lane_members
            .iter()
            .zip(outs.iter())
            .map(|(ms, out)| {
                let spec = &spec;
                s.spawn(move || {
                    let t = Instant::now();
                    let names =
                        nzbkit::par2gen::create_into(out, ms, "bench", spec).expect("create_into");
                    let dt = t.elapsed();
                    let digests = names
                        .iter()
                        .map(|n| {
                            let b = std::fs::read(out.join(n)).expect("read produced file");
                            let d = <sha2::Sha256 as sha2::Digest>::digest(&b);
                            let hex: String = d.iter().map(|x| format!("{x:02x}")).collect();
                            (n.clone(), hex)
                        })
                        .collect::<Vec<_>>();
                    (dt, digests)
                })
            })
            .collect();
        results = handles
            .into_iter()
            .map(|h| h.join().expect("lane panicked"))
            .collect();
    });
    let wall = t0.elapsed();

    println!(
        "lanes {lanes} x {members} members x {member_bytes} B, {pct}%, bs {block_bytes}: wall {:.3?}",
        wall
    );
    for (i, (dt, digests)) in results.iter().enumerate() {
        println!("  lane {i}: {:.3?}, {} files", dt, digests.len());
        for (n, d) in digests {
            println!("    {n} {d}");
        }
    }
    // Every lane built the same set from the same bytes, so their manifests
    // must agree; a mismatch means the lanes interfered and no footprint
    // number from this round is worth reading.
    if let Some((_, first)) = results.first() {
        for (i, (_, d)) in results.iter().enumerate().skip(1) {
            assert_eq!(first, d, "lane {i} produced a different set than lane 0");
        }
    }
    println!("MANIFESTS AGREE across {lanes} lane(s)");
}
