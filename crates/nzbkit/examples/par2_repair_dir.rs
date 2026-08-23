//! Drive `par2repair::repair_dir` on a directory, for profiling the
//! offline/CLI disk-repair path against a real corpus.
//!
//! cargo run --release -p nzbkit --example par2_repair_dir -- <dir>
//!
//! Set NZBFAST_REPAIR_TIMING=1 for the per-phase breakdown.

use std::time::Instant;

fn main() {
    // nzbkit emits its timing lines as tracing events; an example binary
    // has to install a sink or NZBFAST_REPAIR_TIMING prints nothing.
    tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        // Keep the target: it is the `repair-timing` / `fold-trace`
        // key these lines have always been grepped by.
        .with_target(true)
        .with_writer(std::io::stderr)
        .init();
    let dir = std::env::args()
        .nth(1)
        .expect("usage: par2_repair_dir <dir>");
    // The daemon does this at startup (crates/nzbfast/src/main.rs), and a
    // bench driver that skips it measures the Windows scheduler instead of the
    // repair path: execution-speed throttling demotes sustained "background"
    // work onto E-cores a few seconds in, which took a heavy repair leg from
    // 16.6 s to 58 s on the laptop rig. No effect anywhere else.
    nzbkit::mem::opt_out_of_power_throttling();
    // Mirror the daemon's "fast par mode" setting, which serve/startup.rs
    // turns ON at startup (FAST_PAR_DEFAULT). The library flag defaults to OFF
    // because it is the daemon's setting to own, so a driver that skips this
    // call runs the streaming fold and reports a configuration nobody ships
    // any more - the same class of mistake as benchmarking `ourrars` instead
    // of `prodrar`. It cost a heavy-damage repair leg 3x in the 31 Jul round.
    //
    // MUST TRACK `nzbfast::serve::FAST_PAR_DEFAULT`; nzbkit cannot depend on
    // the daemon crate to read it directly.
    //
    // `NZBFAST_NTT=0` still forces the fold (the env overrides the setting in
    // both directions), which is how the fold comparison column is measured.
    nzbkit::par2repair::set_fast_par_enabled(true);
    let t0 = Instant::now();
    let status = nzbkit::par2repair::repair_dir(std::path::Path::new(&dir));
    println!(
        "total {:.3?}  status: {:?}",
        t0.elapsed(),
        status.map(|s| match s {
            nzbkit::par2repair::RepairStatus::NoDamage => "NoDamage".to_string(),
            nzbkit::par2repair::RepairStatus::Repaired(r) => {
                format!(
                    "Repaired rebuilt={} adopted={}",
                    r.blocks_rebuilt, r.blocks_adopted
                )
            }
            nzbkit::par2repair::RepairStatus::Unrepairable { needed, have } => {
                format!("Unrepairable needed={needed} have={have}")
            }
        })
    );
}
