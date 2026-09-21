//! TODO 333's stated acceptance, as a rig rather than a paragraph.
//!
//! The item asked for two things and got both on 12 and 16 Sep 2026
//! (`daemon-infold-progress-cancel`, `nested-repair-infold-control`,
//! `repair-control-two-censused-sites-16sep`): a heartbeat the PAR2
//! fold emits often enough for the queue row to move, and a stop flag
//! polled finely enough that a Cancel means something. What it never
//! got was the acceptance the item NAMED - the m = 10,000 gapped
//! fixture, which takes about a minute on a 20-core arm64 box, with a
//! row that moves through it and a cancel that stops it inside a few
//! seconds - because the landing lanes proved the mechanism on a
//! four-block set in a unit rig, which is a different claim: a bar
//! that moves through a repair
//! measured in MICROSECONDS says nothing about one measured in a
//! minute, and the complaint the item exists to answer was specifically
//! about a long one.
//!
//! So this is that test, over a real fixture, at the surface the queue
//! row actually reads. It is deliberately NOT a new mechanism: every
//! line below is the production path -
//! [`SideCancel`](nzbfast_core::streamhub::SideCancel) is the handle
//! the daemon registers per nzo_id, `repair_control()` is what
//! `repair::nativepass` hands the engine, and the poller reads
//! `RepairProgress::bar()` through the same ONE load
//! `sabcompat`'s `"repair"` object does. What it does not cover is the
//! HTTP hop and the page's JavaScript, both of which are pinned by
//! tests of their own (`nzbfast_api`'s payload rows, and the
//! dashboard's `s.repair` branch).
//!
//! # Running it
//!
//! ```text
//! repair_row_acceptance <dir> [--cancel-after-secs N]
//! ```
//!
//! `<dir>` is a directory holding a damaged PAR2 set. The one this was
//! written for is the m = 10,000 gapped set the PAR2 ladder rig builds
//! (`par2rig-ceiling.sh`, about two minutes from scratch). THE
//! REPAIR IS DESTRUCTIVE: it patches the members in place, which is the
//! point, so hand it a COPY of the fixture and not the fixture. With
//! `--cancel-after-secs` the rig presses Cancel from a watcher thread
//! at that offset and reports how long the fold took to honour it;
//! without it the repair runs to its verdict.
//!
//! Every reading it prints is a `(phase, per-mille)` pair the queue row
//! would have drawn at that instant, so the transcript IS the row's
//! history and a stalled row is visible as a repeated line.

use nzbkit::sync::MutexExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(dir) = args.next().map(std::path::PathBuf::from) else {
        eprintln!("usage: repair_row_acceptance <dir> [--cancel-after-secs N]");
        std::process::exit(2);
    };
    let mut cancel_after: Option<u64> = None;
    while let Some(a) = args.next() {
        if a == "--cancel-after-secs" {
            cancel_after = args.next().and_then(|v| v.parse().ok());
        }
    }

    let ids = nzbkit::par2repair::disk_set_ids(&dir).expect("the directory holds a readable set");
    let id = *ids.first().expect("at least one PAR2 set in the directory");
    println!("dir      {}", dir.display());
    println!("set      {}", hex16(&id));
    match cancel_after {
        Some(n) => println!("mode     cancel after {n}s"),
        None => println!("mode     run to verdict"),
    }

    let sc = Arc::new(nzbfast_core::streamhub::SideCancel::new());
    let t0 = Instant::now();

    // THE ROW, sampled the way the payload samples it: one `bar()` load
    // per poll, 250 ms apart, printed only when the reading changes.
    // 250 ms rather than the dashboard's ~1 s so a cancel's tail is
    // measurable at a finer grain than the thing being measured.
    let stop = Arc::new(AtomicBool::new(false));
    let poller = {
        let (prog, stop) = (sc.repair_progress().clone(), stop.clone());
        std::thread::spawn(move || {
            // The WHOLE published object, not just the bar: `done` and
            // `total` are the phase's own units and the payload sends
            // them beside the per-mille, and a phase that has BEGUN but
            // never stepped is visible in them and in nothing else -
            // which is exactly the shape the 18 Sep acceptance found in
            // the Write phase.
            let mut last: Option<(String, u64, u64, u64)> = None;
            while !stop.load(Ordering::Relaxed) {
                let now = prog
                    .bar()
                    .map(|(ph, pm)| (ph.to_string(), pm, prog.done(), prog.total()));
                if now != last {
                    match &now {
                        Some((ph, pm, done, total)) => println!(
                            "{:>8.2}s  {ph:<7} {:>5.1}%   done {done} / {total}",
                            t0.elapsed().as_secs_f64(),
                            *pm as f64 / 10.0
                        ),
                        None => println!(
                            "{:>8.2}s  -       (no engine repair)",
                            t0.elapsed().as_secs_f64()
                        ),
                    }
                    last = now;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        })
    };

    // The Cancel, pressed from outside exactly as the delete path
    // presses it: `SideCancel::cancel()`, the whole button.
    let pressed = Arc::new(std::sync::Mutex::new(None::<Instant>));
    let canceller = cancel_after.map(|n| {
        let (sc, pressed) = (sc.clone(), pressed.clone());
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(n));
            *pressed.lock_ok() = Some(Instant::now());
            println!("{:>8.2}s  CANCEL pressed", n as f64);
            sc.cancel();
        })
    });

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
    let returned = Instant::now();
    let wall = t0.elapsed();
    stop.store(true, Ordering::Relaxed);
    poller.join().expect("poller");
    if let Some(h) = canceller {
        h.join().expect("canceller");
    }

    println!("---");
    println!("wall     {:.2}s", wall.as_secs_f64());
    match &status {
        Ok(st) => println!("verdict  {st:?}"),
        Err(e) => println!("verdict  Err({e:?})"),
    }
    if let Some(p) = *pressed.lock_ok() {
        // Measured to the instant the ENGINE CALL RETURNED, not to
        // now: the poller join after it is the rig's own cost and
        // charging it to the fold would overstate the very number this
        // rig exists to report.
        println!(
            "honoured {:.2}s after the press",
            returned.saturating_duration_since(p).as_secs_f64()
        );
        println!(
            "cancelled-flag {} (the handle's own mirror)",
            sc.repair_cancelled()
        );
    }
}

fn hex16(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}
