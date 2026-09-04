//! Time the PAR2 VERIFY path alone over a directory, N passes in one
//! process, for the two-point instruction-count method that
//! `bench/component/par2-icount.sh` documents.
//!
//!   cargo run --release -p nzbkit --example par2_verify_bench -- <dir> <passes>
//!
//! It mirrors `nzbfast_unpack::unpack`'s production verify driver - every
//! set in the directory, biggest member first, one global lane budget - and
//! then does NOTHING ELSE: no repair, no volume scan, no filing. So the
//! per-pass figure is the verify path's own cost on the shape it was
//! pointed at.
//!
//! It prints a FNV digest of every member's bitmap plus its md5/md5-16k
//! flags. That digest is the verdict-identity gate between two arms: two
//! binaries that print the same digest agreed about every block of every
//! file, which is the thing a hashing-order change has to keep.

use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .expect("usage: par2_verify_bench <dir> [passes]");
    let passes: usize = args
        .next()
        .map(|s| s.parse().expect("passes must be a number"))
        .unwrap_or(1);
    nzbkit::mem::opt_out_of_power_throttling();

    let dir = Path::new(&dir);
    let mut par2_bytes = Vec::new();
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .expect("read_dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("par2"))
        })
        .collect();
    names.sort();
    for p in &names {
        par2_bytes.push(std::fs::read(p).expect("read par2"));
    }
    let refs: Vec<&[u8]> = par2_bytes.iter().map(|v| v.as_slice()).collect();
    let sets = nzbkit::live::pick_sets(&refs).expect("pick_sets");

    // Same job list and same lane arithmetic as the production driver.
    let jobs: Vec<_> = sets
        .iter()
        .flat_map(|s| s.files.iter().map(move |f| (s, f)))
        .map(|(set, file)| {
            let path =
                nzbkit::disk::join_out_name(dir, &nzbkit::disk::sanitize_out_name(&file.name));
            (set, file, path)
        })
        .collect();
    let mut order: Vec<usize> = (0..jobs.len()).collect();
    order.sort_unstable_by_key(|&i| std::cmp::Reverse(jobs[i].1.length));
    let machine = nzbkit::mem::cpu_workers().clamp(1, nzbkit::par2::VERIFY_MAX_WORKERS);
    let workers = machine.min(jobs.len()).max(1);
    let inner = (machine / workers).max(1);

    let mut digest = 0u64;
    let mut wall = std::time::Duration::ZERO;
    for pass in 0..passes {
        let next = std::sync::atomic::AtomicUsize::new(0);
        let t0 = std::time::Instant::now();
        let mut results: Vec<(usize, u64)> = Vec::new();
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|_| {
                    scope.spawn(|| {
                        let mut out = Vec::new();
                        loop {
                            let oi = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let Some(&ji) = order.get(oi) else {
                                break;
                            };
                            let (set, file, path) = &jobs[ji];
                            let v =
                                nzbkit::par2::verify_file_path(path, file, set.block_size, inner)
                                    .expect("verify_file_path");
                            // Order-independent per-member fold, so the
                            // digest does not depend on which lane got there
                            // first - only on the verdicts.
                            let mut h = 0xcbf2_9ce4_8422_2325u64;
                            for b in &v.blocks {
                                h = (h ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3);
                            }
                            h = (h ^ u64::from(v.md5_ok)).wrapping_mul(0x100_0000_01b3);
                            h = (h ^ u64::from(v.md5_16k_ok)).wrapping_mul(0x100_0000_01b3);
                            out.push((ji, h));
                        }
                        out
                    })
                })
                .collect();
            for handle in handles {
                results.extend(handle.join().expect("worker panicked"));
            }
        });
        let elapsed = t0.elapsed();
        results.sort_unstable();
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for (ji, member) in &results {
            h = (h ^ *ji as u64).wrapping_mul(0x100_0000_01b3);
            h = (h ^ *member).wrapping_mul(0x100_0000_01b3);
        }
        if pass == 0 {
            digest = h;
        } else {
            assert_eq!(digest, h, "verdicts changed between passes");
        }
        wall += elapsed;
        eprintln!("pass {pass} {:.4}s", elapsed.as_secs_f64());
    }
    println!(
        "passes {passes}  members {}  verdict {digest:016x}  wall_total {:.4}s  wall_mean {:.4}s",
        jobs.len(),
        wall.as_secs_f64(),
        wall.as_secs_f64() / passes as f64
    );
}
