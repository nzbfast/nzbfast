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
            altcand::offer_json(&g, &held)
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
