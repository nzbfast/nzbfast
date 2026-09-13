//! The nested ladder's PAR2 pass reports, and a cancel ends it.
//!
//! Until 12 Sep 2026 `unpack::nested_par2_repair` was the last daemon
//! repair path with no channel at all: no progress out of it, nothing
//! its loops polled, and `serve/mod.rs`'s unattended unstructured
//! ceiling named this function by name as the reason it was still set.
//! It now carries the owner's own `SideCancel`, threaded down the
//! nested ladder (`extract_nested_why` -> `extract_nested_capped`), and
//! that handle is BOTH halves - the progress the queue payload
//! publishes and the cancel the fold polls - so the repair arrives at
//! the engine ATTENDED and is exempt from that ceiling by itself. (The
//! CEILING CALL STILL STANDS, for two other paths: the census is at
//! that call and on `linalg::set_unattended_unstructured_ceiling`.)
//!
//! Three things are pinned here and they are the three that can break
//! separately:
//!
//! 1. the handle the ladder builds is the ATTENDED shape (both halves,
//!    which is what the exemption turns on - `RepairControl::
//!    is_attended`), and an absent handle is the inert control the CLI
//!    has always passed;
//! 2. a live repair's four phases reach the queue row's
//!    `RepairProgress`, which is the value `mode=queue` reads;
//! 3. a cancel ENDS it, is not reported as an unreadable set, and does
//!    not let the level's extraction attempt run as though the layer
//!    had been repaired.
//!
//! The set is a real one: `par2gen::create_into` writes it and the
//! member is then holed, so this is the repair engine rather than a
//! stub of it - the same choice `get::latesets`' `cancel_tests` made.
use super::*;
use crate::streamhub::SideCancel;

fn scratch(tag: &str) -> crate::testscratch::ScratchDir {
    crate::testscratch::ScratchDir::attach(&std::env::temp_dir().join(format!(
        "nzbfast-nestrepair-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )))
}

/// A directory holding one damaged member, its real recovery set, and a
/// nested archive - so `dir_has_nested_extractable` opens the pass.
///
/// 8 MiB rather than a few blocks, and that is about the WATCHER in
/// `a_nested_layer_repair_reports_its_phases_to_the_queue_row` and not
/// about the repair: the row is sampled from another thread the way the
/// queue payload samples it, so the repair has to be long enough that a
/// spinning sampler cannot miss the whole of it. The verify pass alone
/// reads and hashes 8 MiB off disk. Still tens of milliseconds, which is
/// what keeps this a unit test.
fn damaged_layer(tag: &str) -> (crate::testscratch::ScratchDir, Vec<u8>) {
    let dir = scratch(tag);
    let mut data = vec![0u8; 8_192 * 1_024];
    let mut x = 0x9E37_79B9u32;
    for b in &mut data {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }
    std::fs::write(dir.join("inner.bin"), &data).unwrap();
    nzbkit::par2gen::create_into(
        &dir,
        &[nzbkit::par2gen::Member {
            name: "inner.bin".to_string(),
            path: dir.join("inner.bin"),
        }],
        "inner",
        &nzbkit::par2gen::Par2Spec {
            redundancy_pct: 25,
            block_size: Some(8_192),
        },
    )
    .expect("par2 set written");
    let mut holed = data.clone();
    for b in &mut holed[8_192 * 3..8_192 * 4] {
        *b ^= 0xFF;
    }
    std::fs::write(dir.join("inner.bin"), &holed).unwrap();
    // The archive gate: without an extractable file beside the set the
    // pass never opens (`dir_has_nested_extractable`), which is the
    // guard that keeps a bare-file payload from being re-hashed.
    std::fs::write(
        dir.join("payload.rar"),
        nzbkit::rar::fixtures::rar5_volume(&[("note.txt", 6, b"nested".as_slice(), false, false)]),
    )
    .unwrap();
    (dir, data)
}

/// THE ATTENDED SHAPE, which is the half the unattended ceiling turns
/// on: the handle the ladder is given builds a control with BOTH a sink
/// and a gate, and no handle builds the inert one the CLI has always
/// passed. Half a control is not a watcher, and neither half alone
/// lifts the ceiling - `RepairControl::is_attended` carries why.
#[test]
fn the_ladders_handle_builds_an_attended_control() {
    let c = SideCancel::new();
    assert!(
        c.repair_control().is_attended(),
        "the nested ladder's repair must arrive attended, or it is capped by the ceiling \
         `serve/mod.rs` sets and nothing says so"
    );
    assert!(
        !nzbkit::par2repair::RepairControl::default().is_attended(),
        "the CLI's no-handle call must stay inert - the ceiling is what protects it"
    );
}

/// A NESTED LAYER'S REPAIR NOW MOVES THE QUEUE ROW. The phases land on
/// the very `RepairProgress` `mode=queue` reads off the job's
/// `SideCancel`, so the payload needs no change. (The PAGE does not
/// draw them under this stage's activity word - see
/// `unpack::nested_par2_repair`, which states that limit.)
///
/// WHY A SAMPLER RATHER THAN A SECOND SINK, and why it is not flaky.
/// The control carries ONE sink and it is the job's, so the only way to
/// see the phases from outside is the way the payload sees them: poll
/// the published value while the pass runs. `damaged_layer` is 8 MiB
/// for that reason alone - the verify pass reads and hashes all of it
/// off disk before the fold starts, so a spinning sampler cannot miss
/// the whole repair. WHICH phases it catches is still a property of the
/// sampler, so only "it saw one" is asserted here; that each of the
/// four reports, and that each lands at the top of its band, is pinned
/// without a sampler at the engine door
/// (`par2repair::unit_tests::the_present_sets_door_asks_for_a_control_once_per_set`)
/// and in `nzbfast_core::repairprog`.
#[test]
fn a_nested_layer_repair_reports_its_phases_to_the_queue_row() {
    let (dir, whole) = damaged_layer("reports");
    let cancel = SideCancel::new();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    // The engine's sink is called on the repair's own threads, so the
    // row is sampled from another one while the pass runs - which is
    // exactly how the payload reads it.
    let watching = {
        let seen = seen.clone();
        let prog = cancel.repair_progress().clone();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = stop.clone();
        let h = std::thread::spawn(move || {
            while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
                if let Some(p) = prog.phase() {
                    let mut s = seen.lock().unwrap_or_else(|p| p.into_inner());
                    if s.last().map(String::as_str) != Some(p) {
                        s.push(p.to_string());
                    }
                }
                std::thread::yield_now();
            }
        });
        (h, stop)
    };
    let verdict = crate::unpack::nested_par2_repair(&dir, 1, Some(&cancel));
    watching.1.store(true, std::sync::atomic::Ordering::Relaxed);
    watching.0.join().unwrap();

    assert_eq!(
        verdict,
        crate::unpack::NestedRepair::Ran,
        "an uncancelled pass runs to its end"
    );
    assert_eq!(
        std::fs::read(dir.join("inner.bin")).unwrap(),
        whole,
        "the damaged member is healed - this is a real repair, not a stub"
    );
    let phases = seen.lock().unwrap_or_else(|p| p.into_inner()).clone();
    assert!(
        !phases.is_empty(),
        "the queue row saw no phase at all: this path reported nothing before 12 Sep 2026 \
         and the whole point of the control is that it now does"
    );
    assert!(
        cancel.repair_progress().phase().is_none(),
        "and the window CLOSES when the pass returns - the row must not go on naming a \
         phase through the extraction attempt that follows"
    );
}

/// A CANCEL ENDS THE PASS, IS NOT A BROKEN SET, AND STOPS THE LEVEL.
///
/// All three in one test because they are one contract: the ladder runs
/// the PAR2 pass first precisely because the cure is packed beside the
/// disease, so a level whose repair was cut halfway must not go on to
/// extract from bytes nobody proved - and it must not blame the archive
/// for it either.
#[test]
fn a_cancelled_nested_repair_stops_the_level_and_is_not_a_broken_set() {
    let (dir, _) = damaged_layer("cancelled");
    let cancel = SideCancel::new();
    // The press the delete arms make, through `postproc::
    // cancel_tail_fetches`: the network latch and the repair gate at
    // once.
    cancel.cancel();

    assert_eq!(
        crate::unpack::nested_par2_repair(&dir, 1, Some(&cancel)),
        crate::unpack::NestedRepair::Cancelled,
        "a cancelled repair must be reported as a cancel, not as a set that could not be read"
    );

    // ...and the level stops. `Failed` is the honest outcome for a job
    // being deleted; what must never happen is `Produced`, which would
    // say this layer was denested over an unproven one.
    let mut why = None;
    let out = extract_nested_capped(
        &dir,
        None,
        1,
        nzbkit::extract::nested_depth_cap(),
        &mut why,
        Some(&cancel),
    )
    .expect("the pass returns rather than erroring");
    assert_eq!(
        out,
        NestOutcome::Failed,
        "a cancelled level must not report the extraction it never attempted as produced"
    );
    assert_eq!(
        why.as_deref(),
        Some("the job was cancelled"),
        "the reason travels with the failure, so nothing downstream blames the archive"
    );
}
