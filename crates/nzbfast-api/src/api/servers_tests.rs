//! Unit tests for [`super`]'s server doors.
//!
//! A `#[path]` child of `servers.rs` rather than an inline
//! `#[cfg(test)] mod tests`, so the parent stays under the size gate's
//! FILE ceiling - which counts RAW lines, tests included, unlike the
//! per-function one. Nothing about scope changes: this is still a child
//! module of `servers`, so `use super::*` reaches the same private items
//! it always did.

use super::*;
use nzbkit::nntp::{AuthRefusal, NntpError};

fn cfg(host: &str, enabled: bool) -> nzbkit::config::ServerConfig {
    serde_json::from_value(serde_json::json!({ "host": host, "enabled": enabled })).unwrap()
}

/// The 23 Aug 2026 switch discipline, at the one path that was left
/// out of the sweep that established it. Everywhere else `enabled`
/// means "do not touch this account"; a card that read it as "do not
/// download from it, but do dial it" would make the flag mean
/// different things on different code paths, which is the same as it
/// meaning nothing.
#[test]
fn analyze_dials_the_download_pool_and_names_what_it_skipped() {
    let all = [
        cfg("off.example.net", false),
        cfg("on.example.net", true),
        cfg("also-on.example.net", true),
    ];
    let (pool, off) = diversity_pool(&all, false);
    assert_eq!(
        pool.iter().map(|s| s.host.as_str()).collect::<Vec<_>>(),
        ["on.example.net", "also-on.example.net"],
        "a switched-off account must not be dialled by an Analyze click"
    );
    assert_eq!(
        off,
        ["off.example.net"],
        "and the page has to be able to say which ones it skipped, or \
         the report quietly shows fewer providers than the user has"
    );
}

/// The opt-in is the half that keeps "is this account worth turning
/// back on?" answerable. It restores CONFIG ORDER rather than
/// appending the switched-off ones, because the report is read as a
/// list of the user's servers.
#[test]
fn the_opt_in_restores_every_configured_server_in_config_order() {
    let all = [cfg("off.example.net", false), cfg("on.example.net", true)];
    let (pool, off) = diversity_pool(&all, true);
    assert_eq!(
        pool.iter().map(|s| s.host.as_str()).collect::<Vec<_>>(),
        ["off.example.net", "on.example.net"]
    );
    assert_eq!(
        off,
        ["off.example.net"],
        "still reported on an opt-in run - the page marks those rows \
         switched off rather than dropping the note"
    );
}

/// An all-disabled config has an empty pool by default, and that is
/// what puts the page on the opt-in branch instead of an error. The
/// distinction matters: `m_diversity` answers `nothing_enabled` here
/// rather than `error`, because there is a useful next step to offer
/// and red text with no next step is not one.
#[test]
fn every_server_switched_off_leaves_an_empty_pool_not_a_partial_one() {
    let all = [cfg("a.example.net", false), cfg("b.example.net", false)];
    assert!(diversity_pool(&all, false).0.is_empty());
    assert_eq!(diversity_pool(&all, false).1.len(), 2);
    assert_eq!(diversity_pool(&all, true).0.len(), 2);
}

/// The mapping the dashboard's remedy text hangs off. Capacity and
/// permanent are opposite advice - "lower your connections" versus
/// "your password is wrong" - so getting this backwards sends the
/// user to change a credential that works.
#[test]
fn a_refusal_reaches_the_ui_as_the_kind_the_pool_classified() {
    let cap = NntpError::AuthFailed {
        kind: AuthRefusal::Capacity,
        line: "481 max simultaneous IP addresses reached".into(),
    };
    assert_eq!(refusal_kind(&cap), Some("capacity"));
    let perm = NntpError::AuthFailed {
        kind: AuthRefusal::Permanent,
        line: "481 authentication failed".into(),
    };
    assert_eq!(refusal_kind(&perm), Some("permanent"));
    // Not a statement about the account: no remedy, plain error.
    assert_eq!(refusal_kind(&NntpError::Timeout), None);
    assert_eq!(refusal_kind(&NntpError::Closed), None);
    assert_eq!(
        refusal_kind(&NntpError::Unexpected {
            cmd: "<greeting>".into(),
            line: "502 permission denied".into(),
        }),
        None
    );
}

/// The classifier the arm above depends on, exercised through the
/// same door `Connection::connect` uses. A provider at its cap and a
/// wrong password share reply code 481, so the TEXT is the whole
/// signal - and anything unrecognised must fall to Permanent, since
/// retrying a bad credential forever is the worse failure.
#[test]
fn capacity_wording_is_told_apart_from_a_rejected_credential() {
    for line in [
        "481 max simultaneous IP addresses reached",
        "502 Too many connections",
        "481 Connection limit reached",
    ] {
        assert_eq!(
            nzbkit::nntp::classify_auth_refusal(line),
            AuthRefusal::Capacity,
            "{line}"
        );
    }
    for line in ["481 authentication failed", "481 account suspended"] {
        assert_eq!(
            nzbkit::nntp::classify_auth_refusal(line),
            AuthRefusal::Permanent,
            "{line}"
        );
    }
}

fn srv(host: &str, group: Option<&str>) -> nzbkit::config::ServerConfig {
    serde_json::from_value(json!({"host": host, "group": group})).unwrap()
}

/// The editor may only ghost a name it can defend. A hostname the
/// alias table does not list resolves to its own label, and
/// proposing "myisp" as a provider network teaches the user that
/// the field means something it does not.
#[test]
fn an_unlisted_host_is_offered_no_group_at_all() {
    assert!(group_suggestion(&[], "news.myisp.example", -1).is_none());
    assert!(group_suggestion(&[], "localhost", -1).is_none());
    assert!(group_suggestion(&[], "   ", -1).is_none());
    // Nor does an unlisted twin invent one between them: two hosts
    // of one unknown brand with no name yet are still two servers
    // the page has nothing to call.
    let cfg = [srv("news1.myisp.example", None)];
    assert!(group_suggestion(&cfg, "news2.myisp.example", -1).is_none());
}

/// ...but once one of that pair HAS a name, the other is offered it.
/// The evidence there is the user's own config, not the alias table,
/// and two hosts of one brand really are one network.
#[test]
fn an_unlisted_twin_still_lends_the_name_its_owner_chose() {
    let cfg = [srv("news1.myisp.example", Some("my isp"))];
    let g = group_suggestion(&cfg, "news2.myisp.example", -1).expect("same key as the twin");
    assert_eq!(g.suggest, "my isp");
    assert_eq!(g.same_as.as_deref(), Some("news1.myisp.example"));
}

/// With nothing else configured on that backbone, the oracle's own
/// name for it is the proposal.
#[test]
fn a_listed_host_alone_is_offered_the_backbone_name() {
    let g = group_suggestion(&[], "news.eweka.nl", -1).expect("eweka is listed");
    assert_eq!(g.backbone, "eweka");
    assert_eq!(g.suggest, "eweka");
    assert_eq!(g.same_as, None);
}

/// The point of the field is that both servers spell the group
/// IDENTICALLY - a second spelling folds nothing. So an existing
/// name on the same backbone wins over the backbone's own name,
/// whatever the user called it.
#[test]
fn a_sibling_on_the_same_backbone_lends_its_own_spelling() {
    let cfg = [
        srv("news.myisp.example", Some("ignore me")),
        srv("news.newshosting.com", Some("Highwinds")),
    ];
    let g = group_suggestion(&cfg, "news.usenetserver.com", -1).expect("listed");
    assert_eq!(g.backbone, "highwinds");
    assert_eq!(g.suggest, "Highwinds");
    assert_eq!(g.same_as.as_deref(), Some("news.newshosting.com"));
    // A server on a DIFFERENT backbone lends nothing, even though
    // it has a perfectly good name. Eweka qualifies: same OWNER as
    // Newshosting, its own spool, so it is not a sibling here.
    for other in [
        [srv("news.giganews.com", Some("giga"))],
        [srv("news.eweka.nl", Some("eweka"))],
    ] {
        let g = group_suggestion(&other, "news.usenetserver.com", -1).expect("listed");
        assert_eq!(g.suggest, "highwinds");
        assert_eq!(g.same_as, None);
    }
}

/// The server being edited must not have its own name handed back
/// to it: the box is blank because the user cleared or never set it,
/// and echoing the stored value would look like the field had
/// refilled itself.
#[test]
fn the_server_being_edited_is_not_its_own_sibling() {
    let cfg = [srv("news.newshosting.com", Some("mine"))];
    let g = group_suggestion(&cfg, "news.newshosting.com", 0).expect("listed");
    assert_eq!(g.suggest, "highwinds");
    assert_eq!(g.same_as, None);
    // ...but the SAME list, seen while adding a second server, does
    // lend that name.
    let g = group_suggestion(&cfg, "news.usenetserver.com", -1).expect("listed");
    assert_eq!(g.suggest, "mine");
    assert_eq!(g.same_as.as_deref(), Some("news.newshosting.com"));
}

/// A blank or whitespace group on a sibling is not a name.
#[test]
fn a_sibling_with_an_empty_group_lends_nothing() {
    let cfg = [
        srv("news.newshosting.com", Some("  ")),
        srv("news.easynews.com", None),
    ];
    let g = group_suggestion(&cfg, "news.usenetserver.com", -1).expect("listed");
    assert_eq!(g.suggest, "highwinds");
    assert_eq!(g.same_as, None);
}

/// TODO 312 item 2: a provider that granted NO sockets must not
/// divide by zero, and its carry is reported as "none granted"
/// rather than as a rate of nothing.
///
/// This is the 481 case and it is a legitimate outcome of the probe:
/// an account already full from another machine, or a plan whose
/// connection limit is lower than the row claims. The user pressed
/// the button to find out how many sockets they really have, and
/// that IS the finding.
#[test]
fn a_provider_that_granted_nothing_reports_it_instead_of_dividing_by_zero() {
    let refused = CarryRung {
        connections: 5,
        granted: 0,
        bps: 0,
        bytes: 0,
        drained: false,
    };
    assert_eq!(refused.per_socket(), None);
    assert_eq!(carry_scaling(refused.per_socket(), None), "unknown");
    // And nothing is implied from it, at either end of the
    // arithmetic - a fleet sized off a refusal would be the exact
    // false-low direction TODO 312 names as the hazard.
    assert_eq!(
        nzbkit::pool::linecap::fleet_implied_by_carry(
            1_000_000_000,
            refused.per_socket().unwrap_or(0)
        ),
        0
    );
}

/// The two rungs are what tell a per-CONNECTION limit from a full
/// line, and they want opposite advice - so the verdict is read off
/// the ratio and never off either rate alone.
#[test]
fn doubling_the_sockets_is_what_names_the_regime() {
    let carry = 1_000_000u64;
    // GH #62: each connection is limited, so per-socket carry holds
    // and the total doubled. A bigger fleet buys proportionally.
    assert_eq!(
        carry_scaling(Some(carry), Some(carry)),
        "per_connection",
        "carry that holds means the sockets, not the line, are short"
    );
    // The line (or the path) was already full: the total did not
    // move, so the extra sockets bought nothing at all.
    assert_eq!(carry_scaling(Some(carry), Some(carry / 2)), "line");
    assert_eq!(carry_scaling(Some(carry), Some(carry * 3 / 4)), "mixed");
    // No second rung, so no comparison and no claim.
    assert_eq!(carry_scaling(Some(carry), None), "unknown");
    assert_eq!(carry_scaling(None, Some(carry)), "unknown");
}

/// The probe measures where a download really runs - this server's
/// share of the fleet in force - and then twice that, held to what
/// the account allows.
#[test]
fn the_rungs_straddle_the_fleet_share_without_passing_the_account() {
    // GH #62's shape: a fleet of 25 over five servers is 5 each.
    assert_eq!(carry_rungs_for(5, 24), (5, 10));
    // One server takes the whole fleet, and CARRY_MAX_CONNS is what
    // stops a deliberate press putting a whole account on the wire.
    // The share fills the ceiling, so the BASE rung drops to half
    // of it and the pair is still a real doubling: the second rung
    // is what a download here actually dials, the first is the
    // comparison point. A DECISION, not an accident - this is the
    // commonest install shape, and (24, 24) was the defect that
    // left it with no scaling verdict at all.
    assert_eq!(carry_rungs_for(25, CARRY_MAX_CONNS), (12, 24));
    // Same rule off the constant: any share at an even ceiling.
    assert_eq!(carry_rungs_for(16, 16), (8, 16));
    // An ODD ceiling halves down and doubles back UNDER it, never
    // to it: (11, 22) is a genuine 2x where (11, 23) is not, and
    // the verdict thresholds assume the socket count doubled.
    assert_eq!(carry_rungs_for(23, 23), (11, 22));
    // A small account: never a rung above what it allows, which
    // would measure the provider's refusals and not this link.
    // Under a ceiling of 4 the half-rung would collide with the
    // two-socket floor, so the rungs stay equal, one runs, and the
    // panel says no comparison was possible.
    assert_eq!(carry_rungs_for(5, 3), (3, 3));
    assert_eq!(carry_rungs_for(2, 2), (2, 2));
    assert_eq!(carry_rungs_for(2, 4), (2, 4));
    // ...and at exactly 4 the halving still yields a real pair.
    assert_eq!(carry_rungs_for(4, 4), (2, 4));
    // ...and never one socket, whatever the share says: that is the
    // rung most likely to read ramp-biased low, and low over-states
    // the fleet the line is then said to want.
    assert_eq!(carry_rungs_for(1, 8), (2, 4));
    assert_eq!(carry_rungs_for(0, 1), (2, 2));
    // A share OVER half the ceiling halves down too. Clamping the
    // second rung instead - (23, 24), (17, 24), (13, 16) - hands
    // `carry_scaling`'s doubled-socket thresholds a pair that never
    // doubled, and a fully line-bound link then reads 23/24 = 0.958
    // as `per_connection`: the one verdict that tells the user more
    // sockets would go faster, about a link where they would not.
    // These are the auto curve's own shapes (two servers on the
    // 25..=50 rungs share 13 to 23 against the 24 cap).
    assert_eq!(carry_rungs_for(23, 24), (12, 24));
    assert_eq!(carry_rungs_for(17, 24), (12, 24));
    assert_eq!(carry_rungs_for(13, 16), (8, 16));
}

/// The defect: the probe sized its rungs from the RAW editor list,
/// so an install with five rows and two switched off measured a
/// five-way share while the next download opens a three-way one -
/// and the panel printed 5 as the server count beside a carry it
/// had divided the wrong way.
///
/// The default is the half a reader has to get right: `enabled` is
/// only ever WRITTEN when it is false, so an absent key is enabled
/// (`ServerConfig`'s `default_true`), and a hand-written config that
/// names no such key has every row in the pool. Reading absence as
/// "off" would have counted the commonest config in existence as
/// entirely switched off.
#[test]
fn the_share_is_divided_between_the_enabled_rows_only() {
    let rows = vec![
        json!({"host": "a.example"}),
        json!({"host": "b.example", "enabled": false}),
        json!({"host": "c.example", "enabled": true}),
        json!({"host": "d.example", "enabled": false}),
        json!({"host": "e.example"}),
    ];
    // The number the old spelling produced, kept here as the
    // arithmetic this test is about: `servers.len()` is 5, and 5 is
    // what the panel divided by and printed.
    assert_eq!(rows.len(), 5);
    assert_eq!(
        enabled_server_count(&rows),
        3,
        "two rows are switched off, so the next job is a three-way share"
    );
    // An absent key is a server in the pool, not one out of it.
    assert_eq!(enabled_server_count(&[json!({"host": "a.example"})]), 1);
    // ...and a non-boolean `enabled` is not a switch-off either: the
    // config loader would take the serde default, so reading it as
    // false here would put the panel and the pool at odds.
    assert_eq!(
        enabled_server_count(&[json!({"host": "a.example", "enabled": "yes"})]),
        1
    );
    assert_eq!(enabled_server_count(&[]), 0);
    assert_eq!(
        enabled_server_count(&[json!({"host": "a.example", "enabled": false})]),
        0
    );
}

/// The probe must not run beside a download, and must not dial a row
/// the user switched off. Both were reachable: the shared permit
/// excludes only another ladder or probe, and a probe opens a fresh
/// pool of up to `CARRY_MAX_CONNS` sockets, so against an account
/// already at its connection or IP cap it draws refusals and the
/// live job's own reconnects then fail.
#[test]
fn the_probe_refuses_a_running_download_and_a_switched_off_row() {
    // Idle daemon, enabled row: the door is open, which is the state
    // `tests/daemon_carry` runs in and must keep reaching.
    assert!(carry_refusal("a.example", false, false, false).is_none());

    // A download in flight. Refused whether the row is on or off,
    // and NOT escapable by the opt-in: opting in there would be
    // opting in to making the running job slower.
    for off in [false, true] {
        for opt in [false, true] {
            let r = carry_refusal("a.example", true, off, opt)
                .expect("a download is running, so the probe must not");
            assert_eq!(r["status"], json!(false));
            assert_eq!(r["downloading"], json!(true));
            let e = r["error"].as_str().unwrap_or_default();
            assert!(
                e.contains("a download is running"),
                "the refusal must use the tree's own words for it: {e}"
            );
            // The counter is raised by the post-processing ticket as
            // well as by the runner, so the refusal is wider than
            // "on the wire" and has to say so - or a user watching
            // an idle network graph reads it as a bug.
            assert!(
                e.contains("Unpacking and repair"),
                "the refusal does not say it covers the tail: {e}"
            );
        }
    }

    // A switched-off row on an idle daemon: refused, named, and the
    // page is handed the flag it needs to offer the opt-in rather
    // than red text with no next step.
    let r = carry_refusal("b.example", false, true, false).expect("switched off");
    assert_eq!(r["status"], json!(false));
    assert_eq!(r["server_off"], json!(true));
    assert_eq!(r["host"], json!("b.example"));
    assert!(
        r["error"]
            .as_str()
            .unwrap_or_default()
            .contains("b.example is switched off"),
        "the refusal names no server: {r}"
    );

    // ...and the opt-in is the whole point of the flag: "should I
    // turn this account back on?" stays answerable, the same way
    // `m_diversity`'s `value=1` keeps it answerable one card over.
    assert!(carry_refusal("b.example", false, true, true).is_none());
}

/// The LADDER owes a running download the same refusal the carry
/// probe does, and reads the same signal to decide it.
///
/// It was reachable and heavier: the shared `LadderPermit` excludes
/// another LADDER and says nothing about the download, so pressing
/// Test mid-job opened up to 100 fresh sockets and climbed for four
/// minutes against an account the job was already using - drawing
/// refusals once the connection or IP cap was reached, so the live
/// job's own reconnects then failed, and reading every rung flat
/// besides.
///
/// Two halves, and the SECOND is the one that would rot silently.
/// `downloading_now` is the whole choice of signal: `index_jobs_active`
/// and never `active_stream`, which deliberately outlives its job so
/// playback keeps working - a probe gated on that would refuse for
/// ever after the first download. Nothing else in this file would
/// notice it being swapped.
#[test]
fn the_ladder_reads_the_same_running_download_rule_as_the_carry_probe() {
    let dir = std::env::temp_dir().join(format!("nzbfast-ladderidle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let d = crate::testutil::test_daemon(&dir);

    assert!(!downloading_now(&d), "a fresh daemon is not downloading");
    assert!(
        downloading_refusal(downloading_now(&d)).is_none(),
        "an idle daemon must let the ladder through"
    );

    // The counter the runner and the post-processing ticket both
    // raise. Stored rather than driven through `begin_index_job`
    // because what is being pinned is which SLOT the door reads.
    d.index_jobs_active.store(1, Ordering::Release);
    assert!(downloading_now(&d), "the door must read index_jobs_active");
    let r = downloading_refusal(downloading_now(&d)).expect("a download is running");
    assert_eq!(r["status"], json!(false));
    // The flag the panel keys on, so a refusal is told from a
    // failure without pattern-matching the prose.
    assert_eq!(r["downloading"], json!(true));
    let e = r["error"].as_str().unwrap_or_default();
    assert!(
        e.contains("a download is running") && e.contains("Unpacking and repair"),
        "the ladder's refusal must be the tree's own words, tail included: {e}"
    );

    // `active_stream` is NOT the signal: it outlives its job on
    // purpose, so a door gated on it never reopens.
    d.index_jobs_active.store(0, Ordering::Release);
    assert!(
        !downloading_now(&d),
        "the door must reopen the moment the counter drops"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A rung that ran is billed even when the probe never concluded.
///
/// The carry probe keeps its completed rungs in a `Vec` INSIDE the
/// future its 90 s measure timeout cancels, so on the timeout arm that
/// Vec - and the bytes it records - was dropped with the future and
/// `add_usage` was never reached. The arm is reachable with a completed
/// rung: rung one returns in its 6 s, rung two's pool wedges against a
/// black-holed host, which is the case the 90 s guard exists for.
/// Nothing back-fills it afterwards, so a prepaid block read high by up
/// to a rung and its exhaustion latch tripped late.
///
/// [`ProbeBill`] is the fix and this pins the property that makes it
/// one: what it was told survives the collection being dropped, so the
/// number is still there to bill on an exit that has nothing else left.
#[test]
fn a_rungs_bytes_outlive_the_collection_that_held_the_rung() {
    let bill = ProbeBill::default();
    assert_eq!(bill.owed(), 0, "a probe that ran nothing owes nothing");

    // The rung loop's own shape: record, then push. The scope is the
    // cancelled future, and leaving it drops the Vec exactly as the
    // timeout does.
    {
        let mut rungs: Vec<u64> = Vec::new();
        for bytes in [90_000_000_u64, 210_000_000] {
            bill.rung(bytes);
            rungs.push(bytes);
        }
        assert_eq!(rungs.len(), 2);
    }
    assert_eq!(
        bill.owed(),
        300_000_000,
        "the bytes a completed rung moved must not go with the future"
    );

    // The ladder's callback is handed a RUNNING TOTAL of every settled
    // rung rather than the newest one, so its figure replaces. Billing
    // that as an increment would charge a 100-rung climb its own sum
    // a hundred times over.
    let ladder = ProbeBill::default();
    for total in [10_u64, 30, 70] {
        ladder.total(total);
    }
    assert_eq!(ladder.owed(), 70, "a running total replaces, never adds");
}

/// ...and both timeout arms actually bill it.
///
/// The 90 s carry timeout and the 240 s ladder timeout cannot be driven
/// at test price (priced and declined when the carry probe landed: a
/// real wait is the only thing that reaches them), and the handlers want a daemon, a
/// runtime and a provider besides. What CAN be pinned for the price of
/// a string search is the asymmetry itself: every other exit of both
/// handlers bills what the probe moved, and these arms are the ones that
/// silently did not.
///
/// THREE ARMS NOW, not the two the name says: the ladder's 120 s
/// RE-MEASURE timeout is the same defect a layer down (it cancels
/// `sysbench::remeasure`, whose completed rungs live in a Vec inside
/// that future) and was missed on 1 Sep 2026 by a fix that stopped at
/// the two `Err(_) =>` arms. The name is kept because the sweep record
/// and tests/daemon_carry cite it.
#[test]
fn both_probe_timeouts_bill_before_they_refuse() {
    const SRC: &str = include_str!("servers.rs");
    for msg in ["the carry probe timed out", "connection ladder timed out"] {
        let at = SRC.find(msg).unwrap_or_else(|| {
            panic!(
                "cannot find the refusal {msg:?} in servers.rs, so this test is \
                 checking nothing - repoint it at the arm's new wording rather \
                 than deleting it"
            )
        });
        let arm = SRC[..at].rfind("Err(_) => {").unwrap_or_else(|| {
            panic!(
                "cannot find the timeout arm that answers {msg:?} - repoint this \
                 test at its new shape rather than deleting it"
            )
        });
        assert!(
            SRC[arm..at].contains("d.add_usage("),
            "the {msg:?} arm returns without billing what the probe already \
             moved: a rung that ran moved real bytes whatever the probe then \
             concluded, including when it never concluded"
        );
    }

    // AND THE THIRD TIMEOUT, which is not an `Err(_) =>` arm and so was
    // outside the loop above: the ladder's 120 s RE-MEASURE. It cancels
    // `sysbench::remeasure`, whose own `out` vec goes with the dropped
    // future, and its non-merge arm keeps the jagged ladder - so without
    // a counter fed per rung it billed only the CLIMB and silently
    // dropped every re-measure rung that had already run.
    let rm = SRC
        .find("nzbkit::sysbench::remeasure(")
        .expect("the ladder no longer calls sysbench::remeasure - repoint this test");
    let after = &SRC[rm..(rm + 3000).min(SRC.len())];
    assert!(
        after.contains("rbill.rung("),
        "the re-measure is not handed a per-rung billing callback, so a \
         timeout drops the bytes its finished rungs moved"
    );
    assert!(
        after.contains("rbill.owed()"),
        "nothing reads the re-measure's counter, so the arm that keeps the \
         jagged ladder bills the climb only"
    );
}

// -- server_stats bucket classification ---------------------------

/// A day number for a fixed, boring date, so the windows below are
/// arithmetic rather than "whatever today happens to be".
fn day_num(y: i64, m: u32, d: u32) -> i64 {
    days_from_civil(y, m, d)
}

/// The defect: `"block_base"` is a per-host BYTE count - the
/// lifetime figure stamped when the user pressed "Block refilled" -
/// and `"block_base" >= "2026-08-22"` is TRUE as a string
/// comparison, so the whole of it was billed into `week` and stayed
/// there for the life of the install. `month` and `day` never saw it
/// (`starts_with("2026-08")` and `== today` both reject the name),
/// which is exactly why it could sit there unnoticed: only one of
/// the four figures was wrong.
#[test]
fn a_refilled_block_never_moves_the_week_figure() {
    let today = day_num(2026, 8, 28);
    let mut u = serde_json::Map::new();
    u.insert("2026-08-28".into(), json!({"blk.example": 100u64}));
    u.insert("lifetime".into(), json!({"blk.example": 900u64}));
    let before = server_stats_json(&u, today, &[]);

    // The user presses "Block refilled": the store gains a
    // never-pruned bucket holding this host's lifetime spend.
    u.insert("block_base".into(), json!({"blk.example": 900u64}));
    let after = server_stats_json(&u, today, &[]);

    assert_eq!(after, before, "a refill is not a week of downloading");
    assert_eq!(after["week"], json!(100u64));
    assert_eq!(after["servers"]["blk.example"]["week"], json!(100u64));
    assert_eq!(
        after["total"],
        json!(900u64),
        "lifetime still answers total"
    );
}

/// The same question asked of the bucket that was already skipped by
/// name, plus one nobody has added yet - the point of classifying by
/// what a key IS rather than listing what it is not.
#[test]
fn no_non_date_bucket_is_ever_billed_to_a_window() {
    let today = day_num(2026, 8, 28);
    let mut u = serde_json::Map::new();
    u.insert("2026-08-28".into(), json!({"h": 5u64}));
    let base = server_stats_json(&u, today, &[]);
    for k in [
        "reliability",
        "block_base",
        "quota_base",
        "zzz_future_bucket",
    ] {
        let mut u = u.clone();
        u.insert(k.into(), json!({"h": 1_000_000u64}));
        let got = server_stats_json(&u, today, &[]);
        assert_eq!(
            (&got["total"], &got["month"], &got["week"], &got["day"]),
            (&base["total"], &base["month"], &base["week"], &base["day"]),
            "{k} is not a day"
        );
    }
}

/// ...and the windows themselves still work, or the fix above could
/// be "skip everything" and pass.
#[test]
fn the_date_buckets_still_land_in_their_windows() {
    let today = day_num(2026, 8, 28);
    let mut u = serde_json::Map::new();
    u.insert("2026-08-28".into(), json!({"h": 1u64})); // today
    u.insert("2026-08-23".into(), json!({"h": 2u64})); // in the 7-day window
    u.insert("2026-08-21".into(), json!({"h": 4u64})); // this month, not the week
    u.insert("2026-07-30".into(), json!({"h": 8u64})); // neither
    u.insert("lifetime".into(), json!({"h": 15u64}));
    let s = server_stats_json(&u, today, &[]);
    assert_eq!(s["day"], json!(1u64));
    assert_eq!(s["week"], json!(3u64));
    assert_eq!(s["month"], json!(7u64));
    assert_eq!(s["total"], json!(15u64));
    assert_eq!(s["servers"]["h"]["week"], json!(3u64));
}

/// `reliability` holds try counts rather than bytes, and is read a
/// second time on purpose - being skipped as a byte bucket must not
/// stop the host appearing at all. It no longer fills the counters
/// (`article_days` does, below); a provider answering nothing but
/// 430s bills no bytes, so without this read it would be missing
/// from a payload that is partly about how badly it is doing.
#[test]
fn reliability_still_puts_the_host_on_the_list() {
    let mut u = serde_json::Map::new();
    u.insert(
        "reliability".into(),
        json!({"h": {"tried": 100u64, "missing": 3u64}}),
    );
    let s = server_stats_json(&u, day_num(2026, 8, 28), &[]);
    assert!(s["servers"]["h"].is_object(), "the host is listed");
    assert_eq!(s["week"], json!(0u64), "tries are not bytes");
    // ...and its lifetime pair is NOT smuggled in under a day key.
    assert_eq!(s["servers"]["h"]["articles_tried"], json!({}));
    assert_eq!(s["servers"]["h"]["articles_success"], json!({}));
}

// -- GH #69 / TODO 320: the SAB `server_stats` shape ---------------

/// Finding 1. `"daily":{}` was a literal at two sites and nothing
/// anywhere wrote into it, so the per-day chart the client draws was
/// blank on every install. The values were already in hand: this is
/// the same ledger the three windows are summed from.
#[test]
fn daily_carries_a_row_per_date_bucket() {
    let mut u = serde_json::Map::new();
    u.insert("2026-08-28".into(), json!({"h": 1u64}));
    u.insert("2026-08-23".into(), json!({"h": 2u64}));
    u.insert("2026-07-30".into(), json!({"h": 8u64}));
    u.insert("lifetime".into(), json!({"h": 11u64}));
    u.insert("block_base".into(), json!({"h": 5u64}));
    let s = server_stats_json(&u, day_num(2026, 8, 28), &[]);
    let daily = s["servers"]["h"]["daily"].as_object().unwrap().clone();
    assert_eq!(
        daily
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        ["2026-07-30", "2026-08-23", "2026-08-28"]
            .into_iter()
            .map(str::to_string)
            .collect::<std::collections::BTreeSet<_>>(),
        "every date bucket and nothing else: {daily:?}"
    );
    assert_eq!(daily["2026-08-28"], json!(1u64));
    assert_eq!(daily["2026-07-30"], json!(8u64), "older than the window");
    // The windows are unmoved by carrying the same bytes twice.
    assert_eq!(s["servers"]["h"]["week"], json!(3u64));
    assert_eq!(s["servers"]["h"]["total"], json!(11u64));
}

/// Finding 2, the crash. SAB gives `articles_tried` and
/// `articles_success` as `{"YYYY-MM-DD": n}`; we gave a bare
/// integer, and a statically-typed client deserializing
/// `Map<String,Int>` from `0` throws at parse time.
#[test]
fn the_article_counters_are_date_keyed_maps_and_never_scalars() {
    let mut u = serde_json::Map::new();
    u.insert(
        "article_days".into(),
        json!({"h": {
            "2026-08-28": {"tried": 100u64, "missing": 3u64},
            "2026-08-27": {"tried": 10u64, "missing": 10u64},
        }}),
    );
    let s = server_stats_json(&u, day_num(2026, 8, 28), &[]);
    let (t, ok) = (
        &s["servers"]["h"]["articles_tried"],
        &s["servers"]["h"]["articles_success"],
    );
    assert!(
        t.is_object() && ok.is_object(),
        "maps, not scalars: {t} {ok}"
    );
    assert_eq!(t["2026-08-28"], json!(100u64));
    assert_eq!(ok["2026-08-28"], json!(97u64));
    assert_eq!(t["2026-08-27"], json!(10u64));
    assert_eq!(ok["2026-08-27"], json!(0u64), "every article missing");
    // A zero-traffic server's counters are maps too - the empty
    // map is the shape, so a client parses it the same way.
    let s = server_stats_json(
        &serde_json::Map::new(),
        day_num(2026, 8, 28),
        &["idle.example".to_string()],
    );
    assert_eq!(s["servers"]["idle.example"]["articles_tried"], json!({}));
}

/// ...and a row the day dimension cannot read is skipped rather
/// than emitted under a key that is not a date, which is the one
/// thing that would put the client back where it started.
#[test]
fn a_non_date_row_never_reaches_the_article_maps() {
    let mut u = serde_json::Map::new();
    u.insert(
        "article_days".into(),
        json!({"h": {
            "lifetime": {"tried": 9u64, "missing": 0u64},
            "2026-08-28": {"tried": 1u64, "missing": 0u64},
        }}),
    );
    let s = server_stats_json(&u, day_num(2026, 8, 28), &[]);
    let t = s["servers"]["h"]["articles_tried"].as_object().unwrap();
    assert_eq!(t.len(), 1, "{t:?}");
    assert_eq!(t["2026-08-28"], json!(1u64));
}

/// Finding 3. SAB iterates the CONFIG, so every configured server
/// is listed whether or not it has spent anything; we built the map
/// from the ledger, so a client that walks its own server list and
/// indexes `servers[name]` got a null.
#[test]
fn a_configured_server_with_no_traffic_is_listed_with_zeros() {
    let mut u = serde_json::Map::new();
    u.insert("2026-08-28".into(), json!({"busy.example": 5u64}));
    u.insert("lifetime".into(), json!({"busy.example": 5u64}));
    let s = server_stats_json(
        &u,
        day_num(2026, 8, 28),
        &["busy.example".to_string(), "idle.example".to_string()],
    );
    let idle = &s["servers"]["idle.example"];
    assert!(!idle.is_null(), "the idle server is absent: {s}");
    for k in ["total", "month", "week", "day"] {
        assert_eq!(idle[k], json!(0u64), "{k}");
    }
    assert_eq!(idle["daily"], json!({}));
    // Seeding must not zero a server that HAS traffic, which is the
    // way round this would break silently.
    assert_eq!(s["servers"]["busy.example"]["day"], json!(5u64));
    assert_eq!(s["servers"]["busy.example"]["total"], json!(5u64));
    // A server in the ledger but not in the config still appears -
    // dropping it would lose the history of an account the user has
    // just deleted, and this map is what the totals are read from.
    let s = server_stats_json(&u, day_num(2026, 8, 28), &["only.example".to_string()]);
    assert_eq!(s["servers"]["busy.example"]["day"], json!(5u64));
    assert!(s["servers"]["only.example"].is_object());
}

#[test]
fn is_date_bucket_takes_dates_and_nothing_else() {
    for k in ["2026-08-28", "1999-01-01", "2026-12-31"] {
        assert!(is_date_bucket(k), "{k}");
    }
    for k in [
        "lifetime",
        "reliability",
        "block_base",
        "2026-08",
        "2026-08-28-1",
        "26-08-28",
        "2026-13-01",
        "2026-08-32",
        "2026-aa-28",
        "",
    ] {
        assert!(!is_date_bucket(k), "{k}");
    }
}
