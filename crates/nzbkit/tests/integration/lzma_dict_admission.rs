//! F-03: the LZMA dictionary budget is process-global, so the sequential
//! disk read shares it with whatever else is decoding right now - the
//! entry pool `rarfix` runs an archive's entries on, and the older job's
//! post-processing that the queue hand-over overlaps with the newer job's
//! chase. The disk read has no lower rung to demote to, so a refusal there
//! filed a structurally valid method-14 zip as a `ZipGap`. It now waits
//! for the window instead.
//!
//! Its own test binary because both tests move the process-global gauge.

use std::sync::mpsc;
use std::time::Duration;

use nzbkit::mem::{self, MemBudget};
use nzbkit::zip::fixtures::Spec;
use nzbkit::zip::{Archive, fixtures};

/// Both tests drive one process-global gauge, so they never overlap.
/// (Under nextest each test is its own process anyway; this is for a
/// plain `cargo test`, which threads them.)
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Payload that does not compress to nothing, so the decode is real.
fn payload() -> Vec<u8> {
    (0..90_000u32).map(|i| (i / 613 % 241) as u8).collect()
}

fn write_zip(tag: &str, data: &[u8]) -> (std::path::PathBuf, std::path::PathBuf) {
    let d = std::env::temp_dir().join(format!("nzbkit-dictadmit-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("c.zip");
    std::fs::write(&p, fixtures::zip_of(&[Spec::lzma("a.bin", data)])).unwrap();
    (d, p)
}

/// The concrete sequence from the report, with the budget pinned so one
/// held window fills it: a chase holds the whole dictionary budget while
/// an on-disk method-14 entry is read on another thread. Before the fix
/// the read failed immediately with `OutOfMemory` and the job was filed
/// as a gap; now it waits for the charge to be released and produces the
/// byte-exact entry.
#[test]
fn a_disk_read_waits_for_the_dictionary_window_rather_than_failing() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    mem::set_process_budget(MemBudget { total: 256 << 20 });
    let data = payload();
    let (dir, path) = write_zip("wait", &data);

    // The chase's window: the first charge always admits, and at this
    // budget it leaves room for nothing else.
    let held = mem::charge_lzma_dict(256 << 20).expect("the first window always admits");
    assert!(mem::charge_lzma_dict(4096).is_none(), "budget is full");

    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let ar = Archive::open(&[path]).unwrap();
        let mut out = Vec::new();
        let r = ar.read_entry_to(&ar.entries()[0], &mut out);
        tx.send(()).unwrap();
        r.map(|()| out)
    });

    // It must be waiting, not failing: nothing arrives while the charge
    // is held.
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "the disk read finished while the whole budget was held - it \
         either refused the archive or ignored the gauge"
    );
    drop(held);
    let got = reader.join().unwrap().expect("valid method-14 entry");
    assert_eq!(got, data, "the decoded entry must be byte-exact");
    assert_eq!(mem::lzma_dict_outstanding(), 0, "every charge released");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The chase side is unchanged: an ADDITIONAL window over budget is still
/// refused, which is what demotes that container to the disk pass. Pinned
/// at the admission rule, the one thing both modes share.
#[test]
fn an_extra_nested_window_over_budget_is_still_refused() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    mem::set_process_budget(MemBudget { total: 256 << 20 });
    let first = mem::charge_lzma_dict(256 << 20).expect("the first window always admits");
    assert!(
        mem::charge_lzma_dict(256 << 20).is_none(),
        "a second full window must not stack past the budget"
    );
    drop(first);
    assert!(
        mem::charge_lzma_dict(256 << 20).is_some(),
        "released charges free the budget again"
    );
}
