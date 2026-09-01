//! §282 section D: what the queue row offers when a job cannot finish,
//! and what the switch leaves behind for the user to read.
//!
//! A child of daemon_tests, same shape as dupe_tests beside it - the
//! module is named for its file so size-gate.py's CFG_TEST_MOD resolver
//! reads it as test code, and `use super::*` brings the harness
//! (`with_daemon`, `jv`, `DUPE_PRIORITY`).

use super::*;

use crate::serve::altcand;

/// A `PostHealth` verdict at exactly §138's bar - every configured
/// server answered, every sampled article was missing, past the
/// propagation age gate, not waived.
///
/// Written as the WIRE form and parsed back, rather than built as a
/// struct: that is the shape a restored queue.json carries, so a test
/// that built the struct directly would pass over a record the daemon
/// could not actually restore.
fn gone_health() -> serde_json::Value {
    serde_json::json!({
        "bucket": "red", "reason": "no server has it",
        "per_server": [{"host": "news.example", "have": 0, "missing": 8}],
        "sampled": 8, "present": 0, "absent": 8,
        "answered": 1, "servers": 1, "age_days": 644,
        "checked_at": 1, "probes": 1, "waived": false,
    })
}

#[test]
fn the_offer_appears_only_on_a_terminal_verdict_and_names_the_spares_it_can_promote() {
    with_daemon("altcand-offer", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "doomed",
                "Show.S01E01.2160p-A",
                serde_json::json!({"health": gone_health(), "dupe_key": "show/s1e1"}),
            ));
            q.push_back(jv(
                "healthy",
                "Show.S01E02.2160p-A",
                serde_json::json!({"dupe_key": "show/s1e2"}),
            ));
            q.push_back(jv(
                "spare",
                "Show.S01E01.2160p-B",
                serde_json::json!({
                    "paused": true, "priority": DUPE_PRIORITY,
                    "held_for": "doomed", "dupe_key": "show/s1e1",
                }),
            ));
            // Held, but for something else: it must not be offered here,
            // and promoting it would start a different title.
            q.push_back(jv(
                "elsewhere",
                "Other.S01E01-C",
                serde_json::json!({
                    "paused": true, "priority": DUPE_PRIORITY,
                    "held_for": "healthy", "dupe_key": "show/s1e2",
                }),
            ));
        }
        let held = d.alt_held_spares();
        let find = |id: &str| {
            let q = d.queue.lock_ok();
            let j = q
                .iter()
                .find(|j| j.lock_ok().nzo_id == id)
                .cloned()
                .unwrap();
            let g = j.lock_ok();
            altcand::offer_json(&g, &held, false)
        };
        // No verdict, no offer - which is every row of every ordinary
        // queue, including the one holding a spare of its own.
        assert!(find("healthy").is_none());
        assert!(find("spare").is_none());
        let offer = find("doomed").expect("the doomed row offers");
        assert_eq!(offer["reason"], "gone", "{offer}");
        let detail = offer["detail"].as_str().unwrap_or_default();
        assert!(
            !detail.is_empty(),
            "the sentence rides along for a token the page cannot translate yet: {offer}"
        );
        // The sentence the user is SHOWN must not borrow
        // `health::giveup_reason`'s closing clause, which names
        // `post_health_fail` and says the job was already failed by it.
        // Both halves are false here: that setting is off (issue #29
        // says it stays off) and nothing has failed - this row is being
        // offered a button, not a verdict. It shipped that way for one
        // afternoon and was caught on a live daemon, so it is pinned.
        assert!(
            !detail.contains("setting is on") && !detail.contains("failed without downloading"),
            "the offer must not claim a setting that is off: {detail}"
        );
        let spares = offer["spares"].as_array().expect("spares array");
        assert_eq!(spares.len(), 1, "only the row held for THIS job: {offer}");
        assert_eq!(spares[0]["nzo_id"], "spare", "{offer}");
    });
}

#[test]
fn a_switch_promotes_the_spare_files_the_original_and_stamps_both_halves() {
    with_daemon("altcand-switch", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "doomed",
                "Show.S01E01.2160p-A",
                serde_json::json!({"health": gone_health(), "dupe_key": "show/s1e1"}),
            ));
            q.push_back(jv(
                "spare",
                "Show.S01E01.2160p-B",
                serde_json::json!({
                    "paused": true, "priority": DUPE_PRIORITY,
                    "held_for": "doomed", "dupe_key": "show/s1e1",
                }),
            ));
        }
        assert_eq!(d.alt_switch("doomed", "spare"), None, "the switch is taken");

        // The spare runs, and carries what it replaced and why. The
        // `why` is the verdict's own sentence, not the build-stamped
        // fail_message: item 14's clause is prose, not a bug report.
        let q = d.queue.lock_ok();
        assert_eq!(q.len(), 1, "the original left the queue");
        let g = q[0].lock_ok();
        assert_eq!(g.nzo_id, "spare");
        assert!(!g.paused && g.priority == 0, "promoted, not still held");
        assert!(g.held_for.is_empty(), "the hold is spent");
        assert_eq!(g.alt_from, "doomed");
        assert_eq!(g.alt_from_name, "Show.S01E01.2160p-A");
        assert!(
            !g.alt_why.is_empty() && !g.alt_why.contains("[nzbfast "),
            "{}",
            g.alt_why
        );
        drop(g);
        drop(q);

        // ...and the original is in history saying what replaced it,
        // which is the half the user reading a strange release name in
        // their download folder actually needs.
        let h = d.history.lock_ok();
        assert_eq!(h.len(), 1, "the original was filed, not dropped");
        let g = h[0].lock_ok();
        assert_eq!(g.nzo_id, "doomed");
        assert_eq!(g.state, JobState::Failed);
        assert_eq!(g.alt_to_name, "Show.S01E01.2160p-B");
        assert!(
            g.fail_message.contains("[nzbfast "),
            "the failure the *arrs and the report read keeps its build stamp: {}",
            g.fail_message
        );
    });
}

#[test]
fn a_switch_is_refused_on_every_row_it_would_be_wrong_for() {
    with_daemon("altcand-refuse", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "doomed",
                "Show.S01E01-A",
                serde_json::json!({"health": gone_health(), "dupe_key": "show/s1e1"}),
            ));
            q.push_back(jv("fine", "Show.S02E01-A", serde_json::json!({})));
            q.push_back(jv(
                "spare",
                "Show.S01E01-B",
                serde_json::json!({
                    "paused": true, "priority": DUPE_PRIORITY,
                    "held_for": "doomed", "dupe_key": "show/s1e1",
                }),
            ));
            q.push_back(jv(
                "running",
                "Show.S03E01-A",
                serde_json::json!({"state": "Downloading", "health": gone_health()}),
            ));
        }
        // Neither half may be a row that is not there.
        assert!(d.alt_switch("absent", "spare").is_some());
        assert!(d.alt_switch("doomed", "absent").is_some());
        // A healthy row has no verdict to switch on: the button never
        // appears for it, so reaching here means the queue moved.
        assert!(d.alt_switch("fine", "spare").is_some());
        // The runner owns a downloading record and files it itself.
        assert!(d.alt_switch("running", "spare").is_some());
        // And a row that is not a held spare of THIS job is not one the
        // promotion path would take either.
        assert!(d.alt_switch("doomed", "fine").is_some());
        assert_eq!(d.queue.lock_ok().len(), 4, "nothing moved on a refusal");
        assert!(d.history.lock_ok().is_empty(), "and nothing was filed");
    });
}

#[test]
fn the_report_clause_says_both_halves_and_stays_quiet_on_an_ordinary_job() {
    let plain = jv("a", "Show.S01E01-A", serde_json::json!({}));
    assert!(altcand::switch_lines(&plain.lock_ok()).is_empty());

    let switched = jv(
        "b",
        "Show.S01E01-B",
        serde_json::json!({
            "alt_from": "a", "alt_from_name": "Show.S01E01-A",
            "alt_why": "the recovery data for this post cannot be fetched",
            "alt_to_name": "Show.S01E01-C",
        }),
    );
    let lines = altcand::switch_lines(&switched.lock_ok());
    let keys: Vec<&str> = lines.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, ["replaced", "replaced because", "replaced by"]);
    assert_eq!(lines[0].1, "Show.S01E01-A");
    assert_eq!(lines[2].1, "Show.S01E01-C");
}

#[test]
fn the_build_stamp_comes_off_the_clause_and_nothing_else_does() {
    assert_eq!(
        altcand::why_from_fail("post is gone: nothing carries it [nzbfast 9.9.9]"),
        "post is gone: nothing carries it"
    );
    // A message that merely mentions the name, or ends without the
    // bracket, is left exactly as it is.
    assert_eq!(
        altcand::why_from_fail("nzbfast could not write"),
        "nzbfast could not write"
    );
    assert_eq!(
        altcand::why_from_fail("boom [nzbfast 1.0] and then more"),
        "boom [nzbfast 1.0] and then more"
    );
}

/// The RECOVERY arm, which is the verdict §282 was written against: a
/// payload that samples clean and a PAR2 set nothing will serve.
///
/// The payload half is deliberately GREEN here, because that is the
/// incident - both live jobs badged green while their recovery set was
/// dead, and a test whose payload was also red could not tell the two
/// arms apart.
fn dead_recovery_health() -> serde_json::Value {
    serde_json::json!({
        "bucket": "green", "reason": "the payload answered",
        "per_server": [{"host": "news.example", "have": 8, "missing": 0}],
        "sampled": 8, "present": 8, "absent": 0,
        "answered": 1, "servers": 1, "age_days": 644,
        "checked_at": 1, "probes": 1, "waived": false,
        "recovery": {
            "bucket": "red", "reason": "pre-flight: the recovery set is not there",
            "per_server": [{"host": "news.example", "have": 0, "missing": 6}],
            "sampled": 6, "present": 0, "absent": 6,
            "answered": 1, "servers": 1, "volumes": 127, "fetched": false,
        },
    })
}

#[test]
fn a_dead_recovery_set_offers_the_switch_even_though_the_payload_is_green() {
    let j = jv(
        "doomed",
        "Show.S01E01-A",
        serde_json::json!({"health": dead_recovery_health()}),
    );
    let g = j.lock_ok();
    // The payload verdict alone would say nothing at all: it is green,
    // and `no_server_can_supply` is false. This is the whole gap §282
    // item 1 closes and item 12 renders.
    let (token, why, lead) = altcand::terminal_reason(&g).expect("the recovery arm fires");
    assert_eq!(token, "recovery");
    assert!(
        why.starts_with("the repair data for this post cannot be fetched from your provider"),
        "the sentence §282 asks for by name, not a segment count: {why}"
    );
    assert!(
        why.contains("127"),
        "and it names the reach of the sample: {why}"
    );
    // The lead is a CLASSIFICATION: `fail_kind` must read it as the
    // class whose remedy is "grab another release" and which arms no
    // retry. `Gone` would be wrong here - the payload is fine.
    assert_eq!(
        crate::failkind::fail_kind_token(crate::failkind::fail_kind(lead)),
        "preflight",
        "{lead}"
    );
}

#[test]
fn a_recovery_verdict_short_of_the_bar_offers_nothing() {
    // Red, but one server of two stayed silent - it had no say, exactly
    // as `no_server_can_supply` argues for the payload. And a red set
    // with only SOME articles missing is what PAR2 is for.
    for (answered, servers, absent, sampled) in [(1u32, 2u32, 6u32, 6u32), (1, 1, 3, 6)] {
        let mut h = dead_recovery_health();
        h["recovery"]["answered"] = serde_json::json!(answered);
        h["recovery"]["servers"] = serde_json::json!(servers);
        h["recovery"]["absent"] = serde_json::json!(absent);
        h["recovery"]["sampled"] = serde_json::json!(sampled);
        let j = jv("q", "Show.S01E01-A", serde_json::json!({"health": h}));
        assert!(
            altcand::terminal_reason(&j.lock_ok()).is_none(),
            "answered {answered}/{servers}, absent {absent}/{sampled} is not a verdict"
        );
    }
}

/// §294 x §295: a HELD row never carries the offer, however doomed its
/// probed health reads. Unreachable before §295 (held rows were never
/// probed, so they had no health for `terminal_reason` to read) and
/// live the day the prober started visiting them: without this guard a
/// held spare of a dead post sprouts "cannot finish" with a search
/// button on a row that is not downloading anything, and hunting a
/// replacement FOR A SPARE is the junk-queue class §282 forbids. The
/// dead-ness still shows where §295 put it - the health badge, and the
/// promotion band that ranks the spare last.
#[test]
fn a_held_row_with_doomed_health_still_offers_nothing() {
    let doomed = serde_json::json!({
        "bucket": "red", "reason": "gone",
        "per_server": [{"host": "news.example", "have": 0, "missing": 8}],
        "sampled": 8, "present": 0, "absent": 8,
        "answered": 1, "servers": 1, "age_days": 400,
        "checked_at": 1, "probes": 1, "waived": false,
    });
    let held_row = jv(
        "heldspare",
        "Show.S09E01.2160p-B",
        serde_json::json!({
            "paused": true, "priority": DUPE_PRIORITY,
            "held_for": "someprimary", "dupe_key": "show/s9e1",
            "health": doomed.clone(),
        }),
    );
    assert!(
        altcand::offer_json(&held_row.lock_ok(), &[], false).is_none(),
        "a held row must never offer, whatever its health says"
    );
    // The same health on an UNHELD row is the ordinary offer - which
    // proves the guard above is the held_for field and not the verdict.
    let live_row = jv(
        "liveprimary",
        "Show.S09E01.1080p-A",
        serde_json::json!({"health": doomed}),
    );
    assert!(
        altcand::offer_json(&live_row.lock_ok(), &[], false).is_some(),
        "the identical verdict on a live row still offers"
    );
}

/// The THIRD arm (§294): partial loss past what the recovery set can
/// fund. Neither older arm can see this shape - the payload is not
/// wholly gone (`no_server_can_supply` is false at 20 of 64) and the
/// recovery set answers fine; what is doomed is the ARITHMETIC, and
/// only the joint verdict carries it. `doubtful` deliberately offers
/// nothing: an offer is a claim the job cannot finish, and the
/// interval saying "cannot tell" is not that claim.
#[test]
fn a_completable_no_verdict_offers_the_switch_on_partial_loss() {
    let health = |completable: &str| {
        serde_json::json!({
            "bucket": "red", "reason": "sampled loss",
            "per_server": [{"host": "news.example", "have": 44, "missing": 20}],
            "sampled": 64, "present": 44, "absent": 20,
            "answered": 1, "servers": 1, "age_days": 400,
            "checked_at": 1, "probes": 1, "waived": false,
            "completable": completable,
        })
    };
    let j = jv(
        "short",
        "Show.S01E01-A",
        serde_json::json!({"health": health("no")}),
    );
    let (token, why, lead) = altcand::terminal_reason(&j.lock_ok()).expect("the short arm fires");
    assert_eq!(token, "short");
    assert!(
        why.contains("20 of 64"),
        "the sentence carries the sample it rests on: {why}"
    );
    assert_eq!(
        crate::failkind::fail_kind_token(crate::failkind::fail_kind(lead)),
        "preflight",
        "{lead}"
    );
    let j = jv(
        "unsure",
        "Show.S01E01-B",
        serde_json::json!({"health": health("doubtful")}),
    );
    assert!(
        altcand::terminal_reason(&j.lock_ok()).is_none(),
        "doubtful is the interval saying it cannot tell - never an offer"
    );
}

/// The third arm's age gate (release-eve sweep S4). Both sibling arms
/// only fire through Red, which requires the post to be past
/// `GONE_MIN_AGE_DAYS` - but `score_completable` never reads the age,
/// so a post sampled minutes after upload can carry `completable: "no"`
/// on evidence the module's own Amber sentence calls "a warning and
/// nothing more". The VERDICT may stand (it is an honest projection of
/// the sample); the OFFER, whose copy says the articles "are gone" and
/// whose class says no retry can help, must wait out propagation
/// exactly as its siblings do.
#[test]
fn a_young_completable_no_verdict_offers_nothing() {
    // Identical loss shape to the test above, aged AT and BELOW the
    // propagation gate. Amber is what `health::score` builds for
    // absent > 0 at this age, so the fixture is the shape the prober
    // actually lands.
    let health = |age_days: u32, bucket: &str| {
        serde_json::json!({
            "bucket": bucket, "reason": "sampled loss",
            "per_server": [{"host": "news.example", "have": 44, "missing": 20}],
            "sampled": 64, "present": 44, "absent": 20,
            "answered": 1, "servers": 1, "age_days": age_days,
            "checked_at": 1, "probes": 1, "waived": false,
            "completable": "no",
        })
    };
    for age in [0u32, crate::diag::GONE_MIN_AGE_DAYS - 1] {
        let j = jv(
            "young",
            "Show.S01E01-A",
            serde_json::json!({"health": health(age, "amber")}),
        );
        assert!(
            altcand::terminal_reason(&j.lock_ok()).is_none(),
            "at {age} day(s) the post may still be propagating - no offer"
        );
    }
    // The boundary itself fires: at GONE_MIN_AGE_DAYS the same evidence
    // is past the propagation window, exactly as Red's own gate reads it.
    let j = jv(
        "aged",
        "Show.S01E01-A",
        serde_json::json!({"health": health(crate::diag::GONE_MIN_AGE_DAYS, "red")}),
    );
    let (token, _, _) =
        altcand::terminal_reason(&j.lock_ok()).expect("past the gate the arm fires");
    assert_eq!(token, "short");
}

// -- §284: the same surface on a row that has ALREADY failed ---------------

/// A real spooled `.nzb` for a parked row.
///
/// `jv`'s default `nzb_path` is `/tmp/x.nzb`, which does not exist -
/// and `altcand::parked_replaceable` requires the spool file, because
/// the hunt's age gate and item 6's same-post admission test both read
/// it and a button that can only ever refuse is worse than no button. So
/// a test that wants the offer has to put a file there.
///
/// The file lives inside a `ScratchDir` and the caller has to hold that
/// guard, or the fixture is one more `$TMPDIR` entry per run forever:
/// this one wrote a bare path and nothing removed it, which is 1,731 of
/// the 66,095 leaked entries measured on the dev Mac on 31 Aug 2026 -
/// the single largest family. See `crates/nzbfast/tests/scratch/mod.rs`.
///
/// PER THREAD as well as per process, and that is what the guard costs.
/// This used to be ONE path shared by every test here and rewritten by
/// each, which is safe while nothing ever DELETES it - the content never
/// mattered, `parked_replaceable` asks only whether it exists. A guard
/// clears its tree on attach and removes it on drop, so under `cargo
/// test` - one process, these tests side by side - a shared path is one
/// test pulling the fixture out from under another. libtest gives each
/// test its own thread, so the thread id is the discriminator; nextest
/// gives each its own process, where the pid already was.
fn spooled() -> (crate::testscratch::ScratchDir, std::path::PathBuf) {
    let d = crate::testscratch::ScratchDir::attach(&std::env::temp_dir().join(format!(
        "nzbfast-284-spool-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )));
    let p = d.join("spool.nzb");
    std::fs::write(&p, b"<nzb></nzb>").expect("write spool fixture");
    (d, p)
}

/// The verdict a parked row carries: the failure LEAD `fail_kind` reads
/// by prefix, then its evidence. `fail_action` maps this to `"search"`,
/// which is the retry surface's own "another release is the only move"
/// answer and the bound §284 draws its offer at.
const GONE_FAIL: &str = "post is gone: all 8 sampled article(s) were reported missing by every \
                         one of your 1 configured server(s), and at 644 day(s) old the post is \
                         past the point where propagation explains it [nzbfast 1.2.2]";

fn parked(
    id: &str,
    name: &str,
    spool: &std::path::Path,
    extra: serde_json::Value,
) -> Arc<Mutex<Job>> {
    let mut v = serde_json::json!({
        "state": "Failed",
        "fail_message": GONE_FAIL,
        "nzb_path": spool.to_string_lossy(),
        "finished_unix": 1,
    });
    if let Some(m) = extra.as_object() {
        for (k, val) in m {
            v[k] = val.clone();
        }
    }
    jv(id, name, v)
}

#[test]
fn a_failed_row_offers_the_spare_still_held_for_it() {
    with_daemon("altcand-parked-offer", |d| {
        let (_spooldir, spool) = spooled();
        let dead = parked(
            "dead",
            "Show.S01E01.2160p-A",
            &spool,
            serde_json::json!({"dupe_key": "show/s1e1"}),
        );
        d.history.lock_ok().push(dead);
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "spare",
                "Show.S01E01.2160p-B",
                serde_json::json!({
                    "paused": true, "priority": DUPE_PRIORITY,
                    "held_for": "dead", "dupe_key": "show/s1e1",
                }),
            ));
        }
        let held = d.alt_held_spares();
        let h = d.history.lock_ok();
        let g = h[0].lock_ok();
        let offer = altcand::parked_offer_json(&g, &held).expect("the parked row offers");
        // TWO KEYS, and the absences are the design: the drawer has
        // already printed this record's own Reason, so no `detail`, and
        // this job HAS failed, so `auto`'s "one will be searched for
        // when it does" is not a promise that can still be kept.
        assert!(offer.get("detail").is_none(), "{offer}");
        assert!(offer.get("auto").is_none(), "{offer}");
        assert_eq!(offer["search"], true, "not an *arr row: {offer}");
        let spares = offer["spares"].as_array().expect("spares array");
        assert_eq!(spares.len(), 1, "the spare held for THIS job: {offer}");
        assert_eq!(spares[0]["nzo_id"], "spare", "{offer}");
    });
}

#[test]
fn the_parked_offer_is_drawn_only_where_another_copy_is_the_move() {
    with_daemon("altcand-parked-gate", |_d| {
        let (_spooldir, spool) = spooled();
        let held: Vec<altcand::HeldSpare> = Vec::new();
        let open = |j: &Arc<Mutex<Job>>| {
            let g = j.lock_ok();
            altcand::parked_offer_json(&g, &held).is_some()
        };
        // The shape the whole section exists for.
        assert!(
            open(&parked(
                "dead",
                "Show.S01E01-A",
                &spool,
                serde_json::json!({})
            )),
            "a Gone failure with its spool still on disk"
        );
        // A repair that could not complete is `Unrepairable`, whose
        // `fail_action` is also "search" - the recovery-set death §282
        // was written against.
        assert!(open(&parked(
            "unrep",
            "Show.S01E02-A",
            &spool,
            serde_json::json!({"fail_message": "repair could not complete: too few recovery blocks"}),
        )));
        // A job that finished has nothing to replace.
        assert!(!open(&parked(
            "done",
            "Show.S02E01-A",
            &spool,
            serde_json::json!({"state": "Completed", "fail_message": ""}),
        )));
        // A LOCAL fault - a full disk, a permission error - fails a
        // second copy the same way, so another one is not the move.
        // `hunt_gates` would refuse it as `LocalFault` one step later;
        // the offer must not be drawn on it in the first place.
        assert!(!open(&parked(
            "local",
            "Show.S02E02-A",
            &spool,
            serde_json::json!({"fail_message": "unpack failed: no space left on device"}),
        )));
        // Pieces missing right now is what RETRY is for, and the row
        // beside this one already says so.
        assert!(!open(&parked(
            "missing",
            "Show.S02E03-A",
            &spool,
            serde_json::json!({"fail_message": "download incomplete: 12 articles missing"}),
        )));
        // THE AUTO-RETRY WINDOW (§284's second judgement). The original
        // is coming back through the queue in minutes - `park_gen`
        // guards both the promotion and the hunt on exactly this - so a
        // button offered inside it spends a copy on a job that has not
        // finished failing.
        assert!(!open(&parked(
            "armed",
            "Show.S03E01-A",
            &spool,
            serde_json::json!({"auto_retry_at": unix_now().unsigned_abs() + 600}),
        )));
        // ...and a stamp in the PAST is a retry that never ran, which is
        // not a reason to withhold the offer for good.
        assert!(open(&parked(
            "lapsed",
            "Show.S03E02-A",
            &spool,
            serde_json::json!({"auto_retry_at": 1}),
        )));
        // Already replaced: item 14's stamp IS the record that this
        // switch happened, and a second offer spends a third copy of one
        // release.
        assert!(!open(&parked(
            "switched",
            "Show.S04E01-A",
            &spool,
            serde_json::json!({"alt_to_name": "Show.S04E01-B"}),
        )));
        // The user's own delete is not a failure. Set on the Job
        // rather than through `jv`: `tombstone` is runtime-only and
        // `job_from_json` never reads it, so a wire fixture cannot
        // carry it.
        let tomb = parked("tomb", "Show.S05E01-A", &spool, serde_json::json!({}));
        tomb.lock_ok().tombstone = true;
        assert!(!open(&tomb));
        // And a record whose spool has gone can only ever refuse the
        // pick, because item 6's admission test has nothing to compare.
        assert!(!open(&parked(
            "nospool",
            "Show.S06E01-A",
            std::path::Path::new("/tmp/nzbfast-284-definitely-absent.nzb"),
            serde_json::json!({}),
        )));
    });
}

#[test]
fn switching_a_parked_row_promotes_the_spare_and_leaves_the_record_alone() {
    with_daemon("altcand-parked-switch", |d| {
        let (_spooldir, spool) = spooled();
        let dead = parked(
            "dead",
            "Show.S01E01.2160p-A",
            &spool,
            serde_json::json!({"dupe_key": "show/s1e1", "finished_unix": 1000}),
        );
        d.history.lock_ok().push(dead);
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "spare",
                "Show.S01E01.2160p-B",
                serde_json::json!({
                    "paused": true, "priority": DUPE_PRIORITY,
                    "held_for": "dead", "dupe_key": "show/s1e1",
                }),
            ));
        }
        assert_eq!(d.alt_switch("dead", "spare"), None, "the switch is taken");

        // The spare runs and carries item 14's clause, exactly as it
        // does on the queue road - `why` off the row's own sentence with
        // the build stamp taken back off.
        let q = d.queue.lock_ok();
        assert_eq!(q.len(), 1);
        let g = q[0].lock_ok();
        assert_eq!(g.nzo_id, "spare");
        assert!(!g.paused && g.priority == 0, "promoted, not still held");
        assert!(g.held_for.is_empty(), "the hold is spent");
        assert_eq!(g.alt_from_name, "Show.S01E01.2160p-A");
        assert!(g.alt_why.starts_with("post is gone"), "{}", g.alt_why);
        assert!(!g.alt_why.contains("[nzbfast "), "{}", g.alt_why);
        drop(g);
        drop(q);

        // THE RECORD IS UNTOUCHED except for item 14's half that could
        // not be known any earlier. It failed hours ago: rewriting its
        // verdict would move it under readers who have already acted on
        // it, and re-stamping `finished_unix` would jump it to the top
        // of a history sorted by when things finished.
        let h = d.history.lock_ok();
        assert_eq!(h.len(), 1, "not filed a second time");
        let g = h[0].lock_ok();
        assert_eq!(g.nzo_id, "dead");
        assert_eq!(g.alt_to_name, "Show.S01E01.2160p-B");
        assert_eq!(g.fail_message, GONE_FAIL, "its own verdict, unrewritten");
        assert_eq!(g.finished_unix, Some(1000), "and its own finished stamp");
        drop(g);
        drop(h);

        // ONE event and not two. `job.failed` announces that a job has
        // just failed; this one failed hours ago and `park_gen` said so
        // then, so re-emitting it would tell every webhook, every *arr
        // and the page's own failure alarm that a record they have
        // already handled failed again.
        let ring = d.life_events.lock_ok();
        let sw: Vec<_> = ring
            .iter()
            .filter(|e| e["kind"] == "job.switched")
            .collect();
        assert_eq!(sw.len(), 1, "{ring:?}");
        assert_eq!(sw[0]["by"], "user", "{ring:?}");
        assert_eq!(sw[0]["replaces"], "dead", "{ring:?}");
        assert_eq!(sw[0]["nzo_id"], "spare", "{ring:?}");
        assert!(
            !ring.iter().any(|e| e["kind"] == "job.failed"),
            "the parked road must not re-announce a failure that already happened: {ring:?}"
        );
    });
}

#[test]
fn a_switched_away_record_does_not_come_back_on_a_stamp_that_never_fired() {
    with_daemon("altcand-switch-disarms", |d| {
        let (_spooldir, spool) = spooled();
        // A stamp in the PAST, which is the state the offer is drawn in:
        // `parked_replaceable` admits a lapsed one deliberately, and a
        // busy or held daemon is exactly what leaves it unconsumed.
        let dead = parked(
            "dead",
            "Show.S01E01-A",
            &spool,
            serde_json::json!({
                "dupe_key": "show/s1e1",
                "auto_retry_at": 1, "auto_retry_why": "transient",
            }),
        );
        d.history.lock_ok().push(dead);
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "spare",
                "Show.S01E01-B",
                serde_json::json!({
                    "paused": true, "priority": DUPE_PRIORITY,
                    "held_for": "dead", "dupe_key": "show/s1e1",
                }),
            ));
        }
        assert_eq!(d.alt_switch("dead", "spare"), None, "the switch is taken");
        {
            let h = d.history.lock_ok();
            let g = h[0].lock_ok();
            assert_eq!(g.auto_retry_at, None, "the switch disarmed the stamp");
            assert_eq!(g.auto_retry_why, None);
        }
        // The scheduler's own pass, which is where the double download
        // came from: it filters on Failed + due and nothing else.
        d.run_due_auto_retries();

        let h = d.history.lock_ok();
        assert_eq!(h.len(), 1, "the record is still filed");
        let g = h[0].lock_ok();
        assert_eq!(g.nzo_id, "dead");
        assert_eq!(g.alt_to_name, "Show.S01E01-B", "item 14's row survives");
        assert_eq!(g.state, JobState::Failed);
        drop(g);
        drop(h);
        let q = d.queue.lock_ok();
        let ids: Vec<String> = q.iter().map(|j| j.lock_ok().nzo_id.clone()).collect();
        assert_eq!(q.len(), 1, "only the replacement runs: {ids:?}");
        assert_eq!(q[0].lock_ok().nzo_id, "spare");
    });
}

#[test]
fn a_parked_switch_is_refused_on_every_record_it_would_be_wrong_for() {
    with_daemon("altcand-parked-refuse", |d| {
        let (_spooldir, spool) = spooled();
        {
            let mut h = d.history.lock_ok();
            h.push(parked(
                "dead",
                "Show.S01E01-A",
                &spool,
                serde_json::json!({"dupe_key": "show/s1e1"}),
            ));
            // A finished download: nothing to replace, and the offer is
            // never drawn on it - so reaching here means the tab is old.
            h.push(parked(
                "done",
                "Show.S02E01-A",
                &spool,
                serde_json::json!({"state": "Completed", "fail_message": ""}),
            ));
        }
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "spare",
                "Show.S01E01-B",
                serde_json::json!({
                    "paused": true, "priority": DUPE_PRIORITY,
                    "held_for": "dead", "dupe_key": "show/s1e1",
                }),
            ));
            q.push_back(jv("other", "Unrelated-A", serde_json::json!({})));
        }
        // In neither store.
        assert!(d.alt_switch("absent", "spare").is_some());
        // In history, but not a record another copy answers.
        assert!(d.alt_switch("done", "spare").is_some());
        // The spare half is still resolved against the QUEUE only: a
        // spare is a queue row by definition.
        assert!(d.alt_switch("dead", "absent").is_some());
        // ...and it must be held for THIS record.
        assert!(d.alt_switch("dead", "other").is_some());
        assert_eq!(d.history.lock_ok().len(), 2, "nothing moved on a refusal");
        assert_eq!(d.queue.lock_ok().len(), 2);
        assert!(
            d.life_events.lock_ok().is_empty(),
            "and a refusal changed nothing, so it announced nothing"
        );
    });
}

/// A grab that held TWO spares and had one picked BY HAND does not
/// strand the other.
///
/// `promote_held_alternative` repoints the runners-up at the winner on
/// the automatic road, and says why: the original has left the queue, so
/// nothing will ever park it again and `held_against` can never match
/// them. The clicked switch reaches the same outcome and did not, on
/// either road - which is a grab that holds two spares only ever trying
/// one, because the user pressed the button instead of waiting.
#[test]
fn a_clicked_switch_repoints_the_spares_it_did_not_pick() {
    with_daemon("altcand-switch-repoint", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "doomed",
                "Show.S01E01.2160p-A",
                serde_json::json!({"health": gone_health(), "dupe_key": "show/s1e1"}),
            ));
            for (id, name, origin) in [
                ("spare-a", "Show.S01E01.2160p-B", "spare"),
                ("spare-b", "Show.S01E01.1080p-C", "spare"),
                // The user's own duplicate keeps naming what it was added
                // against, exactly as it did before §282 existed.
                ("theirs", "Show.S01E01.720p-D", "dashboard"),
            ] {
                q.push_back(jv(
                    id,
                    name,
                    serde_json::json!({
                        "paused": true, "priority": DUPE_PRIORITY,
                        "held_for": "doomed", "dupe_key": "show/s1e1",
                        "origin": origin,
                    }),
                ));
            }
        }
        assert_eq!(
            d.alt_switch("doomed", "spare-a"),
            None,
            "the switch is taken"
        );

        let q = d.queue.lock_ok();
        let held: Vec<(String, String)> = q
            .iter()
            .map(|j| {
                let g = j.lock_ok();
                (g.nzo_id.clone(), g.held_for.clone())
            })
            .collect();
        assert_eq!(
            held,
            vec![
                ("spare-a".to_string(), String::new()),
                ("spare-b".to_string(), "spare-a".to_string()),
                ("theirs".to_string(), "doomed".to_string()),
            ],
            "the runner-up must be held against the row that took the original's place"
        );
    });
}

/// The same, on §284's PARKED road - and the reason it is a second test
/// rather than a second assertion is that the two roads strand the
/// runner-up for different reasons. The queue road takes the original
/// out of the queue; this one never had it there, and what ends the
/// offer is `alt_to_name` being stamped, which is exactly what
/// `parked_replaceable` reads to refuse a second switch on that record.
#[test]
fn a_clicked_switch_on_a_failed_row_repoints_the_spares_it_did_not_pick() {
    with_daemon("altcand-parked-repoint", |d| {
        let (_spooldir, spool) = spooled();
        d.history.lock_ok().push(parked(
            "dead",
            "Show.S01E01.2160p-A",
            &spool,
            serde_json::json!({"dupe_key": "show/s1e1"}),
        ));
        {
            let mut q = d.queue.lock_ok();
            for (id, name) in [
                ("spare-a", "Show.S01E01.2160p-B"),
                ("spare-b", "Show.S01E01.1080p-C"),
            ] {
                q.push_back(jv(
                    id,
                    name,
                    serde_json::json!({
                        "paused": true, "priority": DUPE_PRIORITY,
                        "held_for": "dead", "dupe_key": "show/s1e1",
                        "origin": "spare",
                    }),
                ));
            }
        }
        assert_eq!(d.alt_switch("dead", "spare-a"), None, "the switch is taken");
        let q = d.queue.lock_ok();
        let runner = q[1].lock_ok();
        assert_eq!(runner.nzo_id, "spare-b");
        assert_eq!(
            runner.held_for, "spare-a",
            "the runner-up still names a record that will never be offered again"
        );
    });
}

/// The same switch, on a `history.jsonl` this daemon cannot append to -
/// left 0444, or owned by a uid it no longer runs as after one
/// `sudo nzbfast`. `queue.json` goes through `persist::write_atomic` and
/// needs only the DIRECTORY, so it keeps landing while every history
/// append is refused.
///
/// This is the QUEUE -> history road, so there is no `park_prewrite`
/// behind it and no second write after it: the one upsert here is the
/// only thing that will ever put the original on disk, and its answer
/// was dropped by a semicolon. The switch had already been reported
/// taken, the queue row was already gone, and the record came back at
/// the next start as a QUEUED job beside the alternative that replaced
/// it - the user's release downloaded twice.
#[test]
fn a_switch_files_the_original_through_a_store_that_refuses_the_append() {
    use crate::serve::storecut::{Store, arm_store_cut, disarm};

    with_daemon("altcand-switch-refused", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "doomed",
                "Show.S01E01.2160p-A",
                serde_json::json!({"health": gone_health(), "dupe_key": "show/s1e1"}),
            ));
            q.push_back(jv(
                "spare",
                "Show.S01E01.2160p-B",
                serde_json::json!({
                    "paused": true, "priority": DUPE_PRIORITY,
                    "held_for": "doomed", "dupe_key": "show/s1e1",
                }),
            ));
        }

        arm_store_cut(&[Store::HistoryAppend]);
        assert_eq!(d.alt_switch("doomed", "spare"), None, "the switch is taken");
        disarm();

        let d2 = restart(d);
        assert!(
            d2.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "doomed"),
            "the replaced record was lost from BOTH stores - the append was \
             refused and nothing stood the rewrite in for it"
        );
        assert!(
            d2.queue
                .lock_ok()
                .iter()
                .all(|j| j.lock_ok().nzo_id != "doomed"),
            "and it must not come back as a queued job beside its replacement"
        );
    });
}
