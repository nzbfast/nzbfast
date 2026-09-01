//! G1 (wave-4 follow-up, 31 Aug 2026) - where the donor-vanish pin
//! STOPS.
//!
//! [`super::super::adopt::pin_donor_sources`] closes the patch-time
//! donor-vanish window by holding a handle open across the solve and
//! the patch, and its own doc states two limits on that: truncation is
//! not survived, and candidates past [`PIN_DONOR_FDS`] "stay on the
//! lazy-open path, with the pre-pin vanish window that implies". BOTH
//! are reachable - and G1's own headline, a donor DELETED between the
//! scan and the patch, is NOT: that window closed on 25 Aug 2026
//! (2199ddb75) and is pinned twice over in the parent module, five days
//! before G1 was written.
//!
//! The TRUNCATION limit is the live one and is deliberately NOT pinned
//! here, because a test asserting today's answer would future-lock a
//! defect. Its route: a donor is a FAILED predecessor's `out_dir`
//! (`crates/nzbfast/src/serve/tasks/worker.rs`), a Failed history row
//! reads as `DirClaim::Free`
//! (`crates/nzbfast/src/serve/daemon_cats.rs`), and a retry of that
//! predecessor therefore "finds its own folder unclaimed and reuses it
//! in place" (`crates/nzbfast/src/serve/daemon_retry.rs`) - putting a
//! truncating writer inside the directory this repair is reading
//! through pinned handles. That is a daemon-layer reservation
//! question, tracked separately.
//!
//! The fd CEILING is what this module measures, because it is a
//! decision rather than a defect and was stated rather than measured.
//!
//! WHAT IS BEING PINNED IS THE STATED LIMIT ITSELF, which is the point:
//! the cap's overflow arm is the one place a donor read is still fatal,
//! so the behaviour there must be a decision somebody made and not a
//! side effect nobody has looked at. The obvious "fix" - dropping the
//! adoptions the cap could not pin, the way an UNOPENABLE candidate is
//! dropped - is what this pin refuses, and refuses for a measured
//! reason: it would trade a rare fatal error for a certain lost
//! donation on every set with more than `PIN_DONOR_FDS` donor files,
//! turning repairs that succeed today into `Unrepairable`.
//!
//! A child of `unit_tests` rather than a sibling, for its fixture
//! helpers and because `unit_tests.rs` was at 2,960 of the 3,000-line
//! ceiling when this landed.

use super::*;
use adopt::PIN_DONOR_FDS;

/// The pin's fd ceiling is where its protection ends, and the two sides
/// of that boundary answer a vanished donor differently.
///
/// One repair, `PIN_DONOR_FDS + 1` donor files each donating one slice.
/// Every one is present and openable at pin time, so NOTHING degrades -
/// the overflow arm is not the unopenable arm and must not behave like
/// it. What differs is the handle: the first `PIN_DONOR_FDS` are held,
/// and the one past the cap is not, so when the racing cleanup lands
/// between the pin and the read, the held candidate still serves its
/// bytes and the unheld one is the `?`-fatal `NotFound` that fails the
/// whole repair.
///
/// Asserted through the const rather than through a literal 64, so
/// moving the cap moves the test with it - what this pins is the SHAPE
/// of the overflow arm, never today's number.
#[test]
fn the_pin_fd_ceiling_is_the_boundary_a_vanishing_donor_is_answered_at() {
    let donor = tmpdir("pincap-src");
    let n = PIN_DONOR_FDS + 1;
    let mut cands: Vec<(PathBuf, u64)> = Vec::new();
    for i in 0..n {
        let p = donor.join(format!("d{i:04}.dat"));
        std::fs::write(&p, payload(BS, i as u64)).unwrap();
        cands.push((p, BS as u64));
    }
    let mut adopted: HashMap<usize, AdoptSrc> = HashMap::new();
    for i in 0..n {
        adopted.insert(i, AdoptSrc { cand: i, offset: 0 });
    }
    let mut missing: Vec<usize> = Vec::new();
    let open = adopt::pin_donor_sources(&cands, &(0..n), &mut adopted, &mut missing);

    assert_eq!(open.len(), PIN_DONOR_FDS, "the ceiling is what it holds");
    assert_eq!(
        adopted.len(),
        n,
        "the overflow arm drops NOTHING - a candidate the cap could not \
         reach is still adopted, on the lazy open"
    );
    assert!(
        missing.is_empty(),
        "and nothing rejoined missing: this is not the unopenable arm"
    );
    let unpinned: Vec<usize> = (0..n).filter(|ci| !open.contains_key(ci)).collect();
    assert_eq!(unpinned.len(), 1, "exactly one candidate is past the cap");
    let over = unpinned[0];
    let under = (0..n).find(|ci| open.contains_key(ci)).unwrap();

    // The racing cleanup, landing after the decision on BOTH.
    std::fs::remove_file(&cands[over].0).unwrap();
    std::fs::remove_file(&cands[under].0).unwrap();
    let mut reader = super::super::adopt::CandReader {
        cands: &cands,
        open,
    };
    let held = reader.read(
        AdoptSrc {
            cand: under,
            offset: 0,
        },
        BS,
    );
    assert!(
        held.is_ok(),
        "a PINNED donor still serves its bytes once unlinked"
    );
    let lost = reader.read(
        AdoptSrc {
            cand: over,
            offset: 0,
        },
        BS,
    );
    let err = lost.expect_err("past the cap the lazy open is still fatal");
    assert!(
        matches!(&err, RepairError::Io(e) if e.kind() == std::io::ErrorKind::NotFound),
        "and it is the raw NotFound that fails the whole repair, not a \
         degraded verdict: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&donor);
}
