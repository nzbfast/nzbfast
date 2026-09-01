//! X6-01 - a HEALED wire error must not disqualify a byte-exact file.
//!
//! `FileSlot::errors` is `fetch_add`-only: nothing anywhere stores,
//! swaps or decrements it, so it counts articles that ever went wrong
//! on the wire for the life of the job. Four eligibility bands read
//! `errors == 0` - `get/sfvname.rs`'s `settled` filter,
//! `get/emptydesc.rs`'s `empty_slots` filter,
//! `get/yencname.rs`'s contested-name bar, and
//! `get/tail.rs`'s `held_downloaded_files`, the TODO 159 quarantine that
//! decides which payload a FAILED job still hands the user. The wave-4
//! adversarial read (row X6-01) predicted that a monotone counter
//! therefore withholds a whole file over a transient somebody already
//! healed, and called the quarantine arm the only row in that wave
//! whose worst outcome is a payload kept from the user.
//!
//! MEASURED 31 Aug 2026 AND REFUTED, which is why these are PASS pins
//! and not fixes. The counter never sees a healed article: TODO 114's
//! consumer steer takes the reject BEFORE the increment
//! (`get/workers.rs`, the `Err(e)` decode arm - `note_decoded` answers
//! `Steered`, the arm `continue`s, and the increment is on the far side
//! of it), which is exactly what that arm's own comment claims and what
//! nothing had ever executed as an assertion. So a corrupt body that is
//! refetched clean elsewhere leaves `errors` at zero and every band
//! admits the file.
//!
//! The complement was measured too, because "the clause never fires"
//! and "the clause is harmless" are different statements. When the
//! steer CANNOT heal - no peer, `NZBFAST_CRC_STEER=0`, a second bad
//! copy - the increment does happen, and the article's bytes are then
//! lost: the span is never written, so `Extractor::slot_uncovered`
//! reports the same damage independently. `errors > 0` therefore
//! implies a hole, and at the quarantine the clause is REDUNDANT with
//! the `uncovered == Some(0)` test beside it rather than wrong. At the
//! three naming tiers there is no coverage test, so it is the only
//! witness a decode error leaves and is load-bearing. Both readings say
//! the same thing: do not delete it.
//!
//! What these pin is the ADMISSION - that a healed wire error does not
//! change the output directory - so the next lane that reaches for a
//! wire counter as a health test has something to fail against. Both
//! were verified to bite by mutation against the real tree: moving the
//! `slot.errors.fetch_add` above the steer's `continue`, so a healed
//! article does count an error, reddens both.
//!
//! A child of `e2e_norar` for `sfvmixed`'s reason word for word: a
//! sibling directory would have to be declared in `tests/e2e.rs`, which
//! is sitting on its own size-gate baseline.

use super::*;

/// One corrupting server beside a clean twin, both same-host - which is
/// why `NZBFAST_CRC_STEER=1` is explicit here, exactly as
/// `crc_steer_corrupt_storm_finishes_clean_without_repair` explains: the
/// default's different-host elsewhere rule correctly refuses mock twins.
/// `NZBFAST_POOL_DEBUG=1` is what makes the fixture self-verifying - it
/// prints the `[crc-steer] <id>: steered` line each test asserts on, so
/// a run in which nothing was ever corrupted fails instead of passing.
async fn run_steered(fx: &Fixture, chaos_a: Chaos) -> (String, bool, PathBuf) {
    let a = MockServer::start(fx.articles.clone(), chaos_a).await;
    let b = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&a, &b]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || {
            run_get(
                &cfg,
                &nzb,
                &out,
                &[("NZBFAST_CRC_STEER", "1"), ("NZBFAST_POOL_DEBUG", "1")],
            )
        }
    })
    .await
    .unwrap();
    (log, ok, out)
}

/// How many of `file`'s articles the pool took off the corrupting server
/// and refetched elsewhere. Zero means the fixture never asked the
/// question, which every caller treats as a failure rather than a pass -
/// the split between the two servers is the pool's to make, so this is
/// the only thing standing between an inert fixture and a green line.
fn steered_articles(log: &str, file: &str) -> usize {
    log.lines()
        .filter(|l| l.contains("[crc-steer]") && l.contains(": steered") && l.contains(file))
        .count()
}

/// Arm 1 of X6-01 - the checksum-sidecar tier. An obfuscated payload, an
/// honest `.sfv` that names it, no recovery set anywhere, and one server
/// corrupting every body it serves. The file must land under the name
/// the sidecar gives it, byte-exact.
///
/// The predicted failure was silent: the payload keeps its posted hash
/// at rc 0, with nothing in the log connecting the missed rename to a
/// wire error healed minutes earlier. So the assertion is on the NAME
/// and on the BYTES - a `.exists()` on either alone would pass a run
/// that renamed a holed file, or that failed for some unrelated reason
/// before the tier ran at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_healed_wire_error_does_not_cost_a_file_its_sidecar_name() {
    let mut fx = Fixture::new("x601sfv");
    let data = payload(600_000, 41);
    fx.add_file_obfuscated("Pm4hSx62WbJ", "Pm4hSx62WbJ", &data, 40_000);
    let sfv = format!("Movie.One.mkv {:08X}\r\n", crc32fast::hash(&data));
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    let (log, ok, out) = run_steered(
        &fx,
        Chaos {
            corrupt_every: 1,
            ..Default::default()
        },
    )
    .await;
    assert!(ok, "healed-sidecar post failed outright:\n{log}");
    let healed = steered_articles(&log, "Pm4hSx62WbJ");
    assert!(
        healed > 0,
        "the fixture never healed a payload article, so it never asked \
         X6-01's question - a green line here would mean nothing:\n{log}"
    );
    let got = std::fs::read(out.join("Movie.One.mkv")).unwrap_or_else(|e| {
        panic!(
            "the payload kept its posted hash after {healed} healed wire \
             error(s): {e}; tree {:?}\n{log}",
            tree_names(&out)
        )
    });
    assert!(
        got == data,
        "renamed but not byte-exact - the tier admitted a holed file\n{log}"
    );
    drop(fx);
}

/// Arm 3 of X6-01, and the row's whole reason for being P0 - the TODO
/// 159 quarantine. A two-file job that FAILS: `A.bin` loses an article
/// on every server and can never be rebuilt (no recovery data in the
/// post), while `B.bin` is complete after healed wire errors.
///
/// Both halves are the oracle. B delivered ALONE would pass on a build
/// that quarantines nothing at all; A withheld ALONE would pass on one
/// that withholds everything, which is precisely the behaviour TODO 159
/// item 1 exists to end ("the difference between a user getting two of
/// three files and none"). The job must also actually fail - a run that
/// completed would reach no quarantine and assert nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_healed_wire_error_does_not_withhold_a_complete_file_from_a_failed_job() {
    let mut fx = Fixture::new("x601quar");
    let a = payload(200_000, 7);
    let b = payload(600_000, 9);
    fx.add_file("A.bin", &a, 40_000);
    fx.add_file("B.bin", &b, 40_000);
    // Absent from BOTH servers, so it is terminal rather than healable -
    // that is what makes the job fail and reach the quarantine at all.
    let gone = fx
        .articles
        .keys()
        .find(|k| k.contains("A_bin") && k.ends_with("-2@mock>"))
        .unwrap()
        .clone();
    let srv_a = MockServer::start(
        fx.articles.clone(),
        Chaos {
            missing: [gone.clone()].into(),
            corrupt_every: 1,
            ..Default::default()
        },
    )
    .await;
    let srv_b = MockServer::start(
        fx.articles.clone(),
        Chaos {
            missing: [gone].into(),
            ..Default::default()
        },
    )
    .await;
    let cfg = fx.write_config(&[&srv_a, &srv_b]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || {
            run_get(
                &cfg,
                &nzb,
                &out,
                &[("NZBFAST_CRC_STEER", "1"), ("NZBFAST_POOL_DEBUG", "1")],
            )
        }
    })
    .await
    .unwrap();
    assert!(
        !ok,
        "the post was supposed to fail on A.bin - nothing reached the \
         quarantine, so this asserted nothing:\n{log}"
    );
    let healed = steered_articles(&log, "B_bin");
    assert!(
        healed > 0,
        "the fixture never healed a B.bin article, so it never asked \
         X6-01's question - a green line here would mean nothing:\n{log}"
    );
    let got = std::fs::read(out.join("B.bin")).unwrap_or_else(|e| {
        panic!(
            "a COMPLETE file was withheld from the user over {healed} wire \
             error(s) that were healed: {e}; tree {:?}\n{log}",
            tree_names(&out)
        )
    });
    assert!(got == b, "B.bin delivered but not byte-exact\n{log}");
    assert!(
        !out.join("A.bin").exists(),
        "A.bin is short an article no server has and must NOT be \
         delivered; tree {:?}\n{log}",
        tree_names(&out)
    );
    drop(fx);
}
