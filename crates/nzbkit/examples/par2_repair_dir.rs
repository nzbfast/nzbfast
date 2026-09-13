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
    // Mirror the daemon's "fast par mode" setting. The 3x this call was
    // written for is real and still measurable - forcing the fold with
    // NZBFAST_NTT=0 costs 2.8x on a 3,000-block repair, measured 9 Sep -
    // but the call is now REDUNDANT: `fastpar::FAST_PAR_DEFAULT` is
    // `true` and the process-wide flag is initialised from it, so an
    // embedder that never calls this already gets fast par mode. That
    // has been so since the nzbkit split (ad425b5980, 3 Sep); this
    // comment said "defaults to OFF" until 9 Sep and was wrong, which
    // is worth a line because it made the parfast CLI look like it
    // shipped the slow path when it does not.
    //
    // Kept rather than deleted: it pins the driver to the daemon's
    // setting explicitly, so a future change to the default cannot
    // silently move what this bench measures.
    //
    // MUST TRACK `nzbfast::serve::FAST_PAR_DEFAULT`; nzbkit cannot depend on
    // the daemon crate to read it directly.
    //
    // `NZBFAST_NTT=0` still forces the fold (the env overrides the setting in
    // both directions), which is how the fold comparison column is measured.
    nzbkit::par2repair::set_fast_par_enabled(true);
    let t0 = Instant::now();
    let status = nzbkit::par2repair::repair_dir(std::path::Path::new(&dir));
    let elapsed = t0.elapsed();
    // Close the retention admission census's observation window, when
    // one was armed (`NZBFAST_RETENTION_CENSUS`). A file with no
    // `run_close` line is an UNBOUNDED window and its tail has to be
    // read as unknown - this driver owns its process, so it can say.
    //
    // AFTER the clock is read, and that is not fussiness: this driver
    // is what the census's own A/A is timed with, and a close inside
    // the window would put the census's last write in the number the
    // census-off arm is compared against.
    nzbkit::par2repair::close_retention_census();
    println!(
        "total {elapsed:.3?}  status: {:?}",
        status.map(|s| match s {
            nzbkit::par2repair::RepairStatus::NoDamage => "NoDamage".to_string(),
            nzbkit::par2repair::RepairStatus::Repaired(r) => {
                format!(
                    "Repaired rebuilt={} adopted={}",
                    r.blocks_rebuilt, r.blocks_adopted
                )
            }
            nzbkit::par2repair::RepairStatus::Unrepairable {
                needed,
                have,
                adopted,
                partial,
            } => {
                format!(
                    "Unrepairable needed={needed} have={have} adopted={adopted} published={}",
                    partial.files_patched.len()
                )
            }
        })
    );
}
