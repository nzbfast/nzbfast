//! TODO 353's acceptance: what a SLABBED repair pays to rebuild its
//! back-substitution plan once per sweep, and what hoisting it costs in
//! memory.
//!
//! Separate from `repair_row_acceptance` rather than an arm of it, for
//! two reasons. That rig answers TODO 333's question - does the queue
//! ROW move, and does Cancel stop it - and it samples the published bar
//! to do so; this one answers a cost question and needs two numbers that
//! rig does not take: the `memgauge::Sub::RepairWork` PEAK, which is the
//! half of 353's trade a wall-clock reading cannot state, and the sweep
//! count the repair actually ran at. It also leaves that file untouched
//! while TODO 352's lane holds it.
//!
//! # Running it
//!
//! ```text
//! NZBFAST_REPAIR_SOLVE_BUDGET=<bytes> repair_backsub_hoist <dir>
//! ```
//!
//! `<dir>` is a COPY of a damaged PAR2 set - the repair patches its
//! members in place. The budget is what cuts the solve window into
//! sweeps (`reconstruct::plan_slabs`); without it a fixture that fits
//! runs at one slab and there is nothing for a hoist to save.
//!
//! Set `NZBFAST_REPAIR_TIMING=1` alongside it to get the engine's own
//! `back-substitution setup (...)` line per PLAN COMPUTED, which is the
//! direct reading: `slabs` of them before the hoist and one after.

use std::sync::Arc;
use std::time::Instant;

fn main() {
    let Some(dir) = std::env::args().nth(1).map(std::path::PathBuf::from) else {
        eprintln!("usage: repair_backsub_hoist <dir>");
        std::process::exit(2);
    };
    // THE ENGINE'S OWN TIMING LINE NEEDS A SUBSCRIBER, and without one
    // `NZBFAST_REPAIR_TIMING=1` sets an env var that changes nothing a
    // reader can see: `reconstruct` emits `back-substitution setup
    // (...)` through `tracing`, and an example that installs no sink
    // drops it on the floor. `parfast::install_timing_sink` is the same
    // three lines for the same reason; this is a copy because an
    // example cannot reach that crate's private function.
    if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(true)
            .with_writer(std::io::stderr)
            .try_init();
    }

    let ids = nzbkit::par2repair::disk_set_ids(&dir).expect("the directory holds a readable set");
    let id = *ids.first().expect("at least one PAR2 set in the directory");
    println!("dir      {}", dir.display());
    println!(
        "budget   {:?}",
        std::env::var("NZBFAST_REPAIR_SOLVE_BUDGET").ok()
    );

    let sc = Arc::new(nzbfast_core::streamhub::SideCancel::new());
    let t0 = Instant::now();
    let status = {
        let _run = sc.repair_progress().enter();
        nzbkit::par2repair::repair_dir_set_with_donors_controlled_as(
            &dir,
            &id,
            &[],
            nzbkit::par2repair::RetentionCaller::default(),
            sc.repair_control(),
        )
    };
    let wall = t0.elapsed();

    println!("---");
    println!("wall     {:.2}s", wall.as_secs_f64());
    match &status {
        Ok(st) => println!("verdict  {st:?}"),
        Err(e) => println!("verdict  Err({e:?})"),
    }
    // THE OTHER HALF OF 353's TRADE. The plan is `~4*m^2` bytes on the
    // dense arm, and the objection to hoisting it is that holding it
    // across every sweep is the live allocation `plan_slabs` exists to
    // avoid. Read AFTER the repair: the gauge keeps a high-water mark,
    // so this is the peak of the whole run and not what is live now.
    let peak = nzbkit::memgauge::snapshot().peak_of(nzbkit::memgauge::Sub::RepairWork);
    println!("peak     {peak} B ({:.1} MB) RepairWork", peak as f64 / 1e6);
}
