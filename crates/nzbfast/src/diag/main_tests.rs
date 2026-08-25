//! Unit tests for the download-report verdict text and its classifiers.
//!
//! Split out of `diag.rs` verbatim (TODO 106, the `check_tests.rs`
//! pattern) when that file came within a couple of lines of the 3,000
//! line ceiling: this module was 55% of it, so the hoist buys real
//! headroom rather than another three lines. Behaviour unchanged - it is
//! still `diag`'s own child module, so `super::` reaches its private
//! items exactly as it did in place.

use super::LossCauses;

/// The 31 Jul failure this exists for. The pool wedged with 8851
/// segments outstanding, the tail was aborted to recover, and the
/// job was filed as "94 file(s) with missing segments" - which says
/// the release is dead on every server the user has. It was not:
/// almost none of those articles had been ASKED for.
///
/// The counts cannot catch this on their own, which is the trap.
/// Abandoned segments are neither `missing_430` (nobody said 430)
/// nor `transport_failed` (nothing failed in transit), so every
/// cause count is zero and the existing all-transport rule - which
/// needs `transport_failed > 0` - cannot fire. Zero evidence of
/// anything therefore produced the most damning message available.
///
/// Two things have to hold: the text must not blame the post, and
/// the daemon's classifier must read it as Transport, which is what
/// keeps a healthy release from being reported to an indexer as dead
/// and what shortens the retry.
///
/// A run can BOTH stall and collect real 430s, and the first cut of
/// the stall message told the user "not evidence that anything is
/// missing" about a release four providers had just said was short -
/// thousands of times. Denying the inference is right only when
/// nothing was actually confirmed.
#[test]
fn a_stall_with_real_430s_reports_both_not_just_the_stall() {
    let both = super::incomplete_reason(
        94,
        0,
        &LossCauses {
            stalled: true,
            missing_430: 2031,
            takedown_430: 0,
            par2_slots: 4,
            ..no_causes()
        },
    );
    assert!(both.contains("connection pool stalled"), "{both}");
    assert!(
        both.contains("2031 segment(s) WERE confirmed missing"),
        "{both}"
    );
    assert!(
        !both.contains("No server said any article was missing"),
        "the stall must not vouch for a post that servers have called short: {both}"
    );
    // Still Transport: the run was cut off, and with parity present a
    // retry can still finish it.
    assert_eq!(
        crate::failkind::fail_kind(&both),
        crate::failkind::FailKind::Transport
    );
}

/// A post with confirmed-missing segments and NO parity cannot be
/// rebuilt, and the message has to say so - the user is otherwise
/// left retrying a release that arithmetic says will never complete.
///
/// But it stays a CLAUSE, not a verdict. An earlier cut made this
/// final and stopped the automatic retry; the daemon suite caught
/// that it breaks the exact case the retry exists for, because a
/// freshly posted article 430s on every server until it propagates
/// and is indistinguishable from one that is gone for good. So the
/// classification - and the single cheap retry - must not change.
#[test]
fn no_parity_and_confirmed_missing_is_said_plainly_but_still_retries() {
    let dead = super::incomplete_reason(
        94,
        0,
        &LossCauses {
            missing_430: 2031,
            takedown_430: 0,
            par2_slots: 0,
            ..no_causes()
        },
    );
    assert!(dead.contains("no PAR2 recovery data"), "{dead}");
    assert!(dead.contains("another version is the answer"), "{dead}");
    let kind = crate::failkind::fail_kind(&dead);
    assert_eq!(kind, crate::failkind::FailKind::MissingArticles);
    assert!(
        kind.transient(),
        "this must stay retryable: a brand-new post 430s everywhere until it \
         propagates, and refusing to retry would strand it permanently"
    );

    // Parity present: no such clause, nothing to warn about.
    let repairable = super::incomplete_reason(
        2,
        0,
        &LossCauses {
            missing_430: 5,
            takedown_430: 0,
            par2_slots: 4,
            ..no_causes()
        },
    );
    assert!(
        !repairable.contains("no PAR2 recovery data"),
        "{repairable}"
    );
}

#[test]
fn a_stalled_pool_does_not_report_a_healthy_post_as_missing() {
    let stalled = super::incomplete_reason(
        94,
        0,
        &LossCauses {
            stalled: true,
            ..no_causes()
        },
    );
    assert!(
        !stalled.starts_with("download incomplete"),
        "a stall opened with the dead-post verdict: {stalled}"
    );
    assert!(stalled.contains("connection pool stalled"), "{stalled}");
    assert!(
        stalled.contains("rather than evidence about the post"),
        "the message has to deny the inference it used to invite: {stalled}"
    );
    assert_eq!(
        crate::failkind::fail_kind(&stalled),
        crate::failkind::FailKind::Transport,
        "a stall must classify as Transport - MissingArticles reports the release \
         to the indexer as dead and makes the user sit out a propagation wait for \
         a fault on their own machine"
    );

    // A server that never connected is the usual cause, and naming
    // it turns the message into something actionable.
    let dead = ["news.tweaknews.eu".to_string()];
    let with_dead = super::incomplete_reason(
        94,
        0,
        &LossCauses {
            stalled: true,
            dead_servers: &dead,
            ..no_causes()
        },
    );
    assert!(with_dead.contains("news.tweaknews.eu"), "{with_dead}");

    // And the ordinary path is untouched: real 430s still read as a
    // short post, or the fix would hide genuine takedowns.
    let real = super::incomplete_reason(
        3,
        0,
        &LossCauses {
            missing_430: 9,
            takedown_430: 0,
            ..no_causes()
        },
    );
    assert!(real.starts_with("download incomplete"), "{real}");
    assert_eq!(
        crate::failkind::fail_kind(&real),
        crate::failkind::FailKind::MissingArticles
    );
}

/// A3: a server that authenticated, served, and then LEFT before the
/// run ended must reach the user in the message, must never let the
/// `post_gone` verdict fire, and must never let the one automatic
/// retry be suppressed.
///
/// The mechanism: terminal outcomes are decided against `live_mask`,
/// which counts servers that are alive NOW. The moment a server's
/// last worker retires (a permanent refusal, a spent block or quota,
/// the outage budget blown, the connect-attempt cap) the quorum
/// shrinks and nothing says so - `dead_servers` keys on
/// `!ever_connected`, which is FALSE for a server that worked first.
/// So the survivors' 430s on the segments only that server carried
/// read as unanimous, and a healthy post could be reported gone, its
/// retry suppressed, and the release dead-reported to the indexer.
///
/// This pins the PRODUCER/PARSER round trip, exactly as
/// `an_ambiguous_loss_is_never_proven_stale` does for the other four
/// exclusions: the gate reads the clause back off the message, so
/// the wording IS the contract and prose gets rewritten.
#[test]
fn a_server_that_left_mid_run_is_never_proven_stale() {
    let left: Vec<String> = vec!["news.blockprov.example".to_string()];
    fn causes(left: &[String]) -> LossCauses<'_> {
        LossCauses {
            missing_430: 12,
            missing_segments: 1965,
            total_segments: 4506,
            bytes_arrived: 1_879_000_000,
            post_age_days: 9,
            left_servers: left,
            ..no_causes()
        }
    }
    let msg = super::incomplete_reason(1, 0, &causes(&left));
    // The clause the user reads: it says the server WORKED and then
    // stopped, which is a different fact from never connecting, and
    // it says what that cost the verdict.
    assert!(
        msg.contains("news.blockprov.example served for part of the run and then stopped"),
        "{msg}"
    );
    assert!(
        msg.contains("decided without it"),
        "the clause has to say what the departure cost the verdict: {msg}"
    );
    // Distinct from the never-connected clause: the user must not be
    // told a server that served them was unreachable all run.
    assert!(
        !msg.contains("no usable connection"),
        "a server that served must not be described as never connecting: {msg}"
    );
    // The age is still stated - that is honest, and Gary asked for it.
    assert!(msg.contains("well past the minutes-to-hours"), "{msg}");
    assert!(
        !super::missing_articles_proven_stale(&msg),
        "segments decided after a server walked out are not proven absent: {msg}"
    );
    // Appending a clause must not move the OPENING: `fail_kind` and
    // the *arr health mapping key on it.
    assert!(msg.starts_with("download incomplete"), "{msg}");
    assert_eq!(
        crate::failkind::fail_kind(&msg),
        crate::failkind::FailKind::MissingArticles
    );

    // Control: the identical run with every server present all the
    // way through is still proven stale and still loses its retry.
    let whole = super::incomplete_reason(1, 0, &causes(&[]));
    assert!(
        super::missing_articles_proven_stale(&whole),
        "a full quorum on an aged post must still suppress its retry: {whole}"
    );
}

/// The `post_gone` half of A3: "not one article is on any server" is
/// a claim about a quorum that was still whole when the last verdict
/// landed. A server that served and then left makes it unsafe for
/// the same reason a server that never connected does - and it is
/// the more dangerous of the two, because `ever_connected` stays
/// true and nothing else in `LossCauses` would have noticed.
#[test]
fn a_server_leaving_mid_run_disqualifies_the_gone_verdict() {
    let left: Vec<String> = vec!["news.blockprov.example".to_string()];
    fn gone_shape(left: &[String]) -> LossCauses<'_> {
        LossCauses {
            missing_430: 12_018,
            missing_segments: 12_018,
            total_segments: 12_018,
            bytes_arrived: 0,
            post_age_days: 21,
            left_servers: left,
            ..no_causes()
        }
    }
    // Control: the whole fleet answered, so the verdict stands.
    let whole = super::incomplete_reason(94, 0, &gone_shape(&[]));
    assert!(whole.starts_with("post is gone"), "{whole}");
    assert_eq!(
        crate::failkind::fail_kind(&whole),
        crate::failkind::FailKind::Gone
    );

    let short_quorum = super::incomplete_reason(94, 0, &gone_shape(&left));
    assert!(
        !short_quorum.starts_with("post is gone"),
        "a post cannot be called gone by a quorum that shrank mid-run: {short_quorum}"
    );
    assert!(
        short_quorum.starts_with("download incomplete"),
        "{short_quorum}"
    );
    // And it keeps its retry: Gone never retries, MissingArticles does.
    let kind = crate::failkind::fail_kind(&short_quorum);
    assert_eq!(kind, crate::failkind::FailKind::MissingArticles);
    assert!(kind.transient(), "{short_quorum}");
    assert!(
        !super::missing_articles_proven_stale(&short_quorum),
        "{short_quorum}"
    );
}

/// Sweep 8, M7: a recovery article's failure must not decide
/// anything about the payload. Both matrices from the handoff, and
/// both are a wrong verdict on the pre-split counters.
///
/// Trigger A - every lost PAYLOAD article failed in transport while
/// one irrelevant `.par2` article came back 430. On the flat
/// counters that 430 landed in `missing_430`, which suppressed
/// `all_transport`, and a release whose payload a flaky provider
/// simply failed to fetch was reported as missing/gone - to the
/// user, and to the indexer as a dead release.
///
/// Trigger B - the mirror image, and the more expensive one: every
/// PAYLOAD article is confirmed gone while one recovery article had
/// a transport failure. That one failure suppressed the wholly-gone
/// verdict, so a post that really is gone kept its automatic retry
/// and spent the same minutes proving it again.
#[test]
fn a_recovery_articles_failure_never_decides_the_payloads_verdict() {
    // A: payload all transport, one recovery 430.
    let a = super::incomplete_reason(
        5,
        0,
        &LossCauses {
            transport_failed: 40,
            transport_sample: Some("unexpected response to BODY: 999 huh".into()),
            missing_430_recovery: 1,
            ..no_causes()
        },
    );
    assert!(
        a.starts_with("download failed on connection errors"),
        "one 430 on a parity article must not blame the post: {a}"
    );
    // And the recovery loss is still SAID - as repair context, in
    // its own clause, where it cannot move the classification.
    assert!(a.contains("1 recovery (PAR2) segment(s) were lost"), "{a}");
    assert!(
        !a.contains("takedown request"),
        "a plain 430 is not a takedown: {a}"
    );
    assert_eq!(
        crate::failkind::fail_kind(&a),
        crate::failkind::FailKind::Transport,
        "the indexer must not hear about a healthy release: {a}"
    );

    // B: payload wholly gone, one recovery transport failure.
    let backbones = ["highwinds".to_string()];
    let b = super::incomplete_reason(
        94,
        0,
        &LossCauses {
            missing_430: 12_018,
            missing_segments: 12_018,
            total_segments: 12_018,
            bytes_arrived: 0,
            transport_failed_recovery: 1,
            backbones: &backbones,
            post_age_days: 21,
            ..no_causes()
        },
    );
    assert!(
        b.starts_with("post is gone"),
        "one transport failure on a parity article must not un-kill a dead post: {b}"
    );
    let kind = crate::failkind::fail_kind(&b);
    assert_eq!(kind, crate::failkind::FailKind::Gone);
    assert!(
        !kind.transient(),
        "a gone post must not spend the same minutes again: {b}"
    );

    // A takedown on the parity is named in the same sentence -
    // waiting will not bring the recovery volumes back either.
    let a_td = super::incomplete_reason(
        5,
        0,
        &LossCauses {
            transport_failed: 40,
            missing_430_recovery: 2,
            takedown_430_recovery: 2,
            ..no_causes()
        },
    );
    assert!(
        a_td.contains("2 recovery (PAR2) segment(s) were lost as well")
            && a_td.contains("(2 of them reported as removed for a takedown request)"),
        "{a_td}"
    );
    assert!(
        a_td.starts_with("download failed on connection errors"),
        "and it is still not evidence about the payload: {a_td}"
    );

    // The takedown ratio is two of these counters divided, so it is
    // distorted the same way: refusals on parity articles must not
    // dilute "most of the payload was removed".
    let t = super::incomplete_reason(
        5,
        0,
        &LossCauses {
            missing_430: 10,
            takedown_430: 10,
            missing_430_recovery: 90,
            ..no_causes()
        },
    );
    assert!(
        t.contains("10 of the 10 refused segment(s) as removed"),
        "the dominant-takedown wording must count payload refusals only: {t}"
    );

    // And a PAYLOAD loss of the same shape still decides, exactly
    // as before - the split narrows what counts as evidence, it
    // does not switch the evidence off.
    let payload_430 = super::incomplete_reason(
        5,
        0,
        &LossCauses {
            transport_failed: 40,
            missing_430: 1,
            ..no_causes()
        },
    );
    assert!(
        payload_430.starts_with("download incomplete"),
        "{payload_430}"
    );
}

/// TODO 282 item 17, and the sentence the incident turned on.
///
/// The job reported `download incomplete: 83 file(s) with missing
/// segments, 0 decode/write errors; 135 of 17130 segment(s) never
/// arrived (13414 MB did)` - every number true, and an accusation
/// against a payload that was 99.2% intact. What actually died was
/// the recovery set: the repair ladder asked for 1024 MB of parity,
/// was served 68.9 MB of it over 1206 article failures, and spent
/// forty-plus minutes re-asking. The message never mentioned
/// recovery at all, so it sent the user looking at articles, then at
/// par2cmdline, and finally at us.
///
/// Both halves are pinned here, because the value of the clause is
/// entirely in TELLING THEM APART: the recovery-dead shape has to
/// name the recovery set, and the payload-dead shape has to read
/// exactly as it does today.
#[test]
fn the_message_names_which_of_the_two_actually_died() {
    // Recovery dead, payload nearly whole: 900 of the post's 1000
    // parity segments gone, payload short 135 of 17130 (0.79%).
    let backbones = ["giganews".to_string()];
    let rec = super::incomplete_reason(
        83,
        0,
        &LossCauses {
            missing_430: 135,
            missing_430_recovery: 900,
            recovery_segments: 1000,
            missing_segments: 135,
            total_segments: 17130,
            bytes_arrived: 13_414_000_000,
            par2_slots: 127,
            backbones: &backbones,
            post_age_days: 644,
            ..no_causes()
        },
    );
    assert!(
        rec.contains("the recovery data is what failed, not the payload"),
        "the cause has to be the headline: {rec}"
    );
    assert!(
        rec.contains("900 of the post's 1000 PAR2 recovery segment(s) are missing or damaged"),
        "and it has to carry its own evidence: {rec}"
    );
    // The counts are good; they are just not the headline. They still
    // appear, in the census clause, exactly as before.
    assert!(
        rec.contains("135 of 17130 segment(s) never arrived"),
        "the census clause must survive the new opening: {rec}"
    );
    // Said ONCE. The old trailing clause spends the same figures and
    // would read as a second, separate loss.
    assert!(
        !rec.contains("were lost as well"),
        "the recovery loss is stated twice: {rec}"
    );
    // The CLASS is unchanged, and that is deliberate: everything
    // downstream of the opening token - the one automatic retry, the
    // age gate that suppresses it here, the indexer report - was
    // decided for this shape elsewhere. This item changed what the
    // user reads, not what the daemon does.
    assert_eq!(
        crate::failkind::fail_kind(&rec),
        crate::failkind::FailKind::MissingArticles,
        "{rec}"
    );

    // Payload dead, recovery untouched: the same job with the loss on
    // the other side. Reads as it always has.
    let payload = super::incomplete_reason(
        83,
        0,
        &LossCauses {
            missing_430: 9000,
            missing_segments: 9000,
            total_segments: 17130,
            bytes_arrived: 6_000_000_000,
            recovery_segments: 1000,
            par2_slots: 127,
            post_age_days: 644,
            ..no_causes()
        },
    );
    assert!(
        payload.starts_with("download incomplete: 83 file(s) with missing segments"),
        "the payload-dead shape must not have moved: {payload}"
    );
    assert!(
        !payload.contains("recovery data is what failed"),
        "nothing about this run says the parity is the casualty: {payload}"
    );
}

/// The rung's own boundaries, which are where a cause clause goes
/// wrong: it must not vouch for a payload that is also short, and it
/// must not displace an opening that outranks it.
#[test]
fn the_recovery_clause_stands_down_where_it_would_be_a_lie() {
    let both_short = LossCauses {
        missing_430_recovery: 900,
        recovery_segments: 1000,
        // A THIRD of the payload gone as well: whatever killed this
        // job, "not the payload" is not a claim anyone may make.
        missing_430: 5710,
        missing_segments: 5710,
        total_segments: 17130,
        par2_slots: 127,
        ..no_causes()
    };
    let msg = super::incomplete_reason(83, 0, &both_short);
    assert!(
        !msg.contains("not the payload"),
        "both halves were short: {msg}"
    );
    assert!(
        msg.contains("900 recovery (PAR2) segment(s) were lost as well"),
        "and the ordinary recovery clause has to come back: {msg}"
    );

    // A stall outranks it, for the propagation-trap note's reason:
    // the run STOPPED, so none of its counts - the recovery counts
    // included - is evidence about anything.
    let stalled = super::incomplete_reason(
        83,
        0,
        &LossCauses {
            stalled: true,
            missing_430_recovery: 900,
            recovery_segments: 1000,
            missing_segments: 135,
            total_segments: 17130,
            ..no_causes()
        },
    );
    assert!(stalled.contains("connection pool stalled"), "{stalled}");
    assert!(!stalled.contains("not the payload"), "{stalled}");
    assert_eq!(
        crate::failkind::fail_kind(&stalled),
        crate::failkind::FailKind::Transport,
        "{stalled}"
    );

    // And so does an all-transport run: its opening is the one
    // classification that never reports a release to an indexer as
    // dead, and a provider that failed the parity fetch too must not
    // talk its way out of it.
    let transport = super::incomplete_reason(
        83,
        0,
        &LossCauses {
            transport_failed: 135,
            transport_failed_recovery: 900,
            recovery_segments: 1000,
            missing_segments: 135,
            total_segments: 17130,
            ..no_causes()
        },
    );
    assert!(
        transport.starts_with("download failed on connection errors"),
        "{transport}"
    );
    assert_eq!(
        crate::failkind::fail_kind(&transport),
        crate::failkind::FailKind::Transport,
        "{transport}"
    );

    // A post that is wholly gone keeps its own opening too: there is
    // no gap for parity to have closed.
    let backbones = ["giganews".to_string()];
    let gone = super::incomplete_reason(
        83,
        0,
        &LossCauses {
            missing_430: 17130,
            missing_segments: 17130,
            total_segments: 17130,
            missing_430_recovery: 900,
            recovery_segments: 1000,
            par2_slots: 127,
            backbones: &backbones,
            post_age_days: 644,
            ..no_causes()
        },
    );
    assert!(gone.starts_with("post is gone"), "{gone}");
}

/// TODO 282 item 4's seam, driven from this side.
///
/// The incident's own shape reaches this module with EVERY
/// download-time recovery counter at zero - the volumes were
/// deferred, and the fetch that failed ran in the repair ladder,
/// which has no slot to charge. So the rung has a second input that
/// carries a verdict rather than a census, and it words itself
/// without figures it does not have.
#[test]
fn a_repair_side_verdict_reaches_the_message_without_a_census() {
    let msg = super::incomplete_reason(
        83,
        0,
        &LossCauses {
            recovery_unobtainable: true,
            missing_segments: 135,
            total_segments: 17130,
            bytes_arrived: 13_414_000_000,
            par2_slots: 127,
            ..no_causes()
        },
    );
    assert!(
        msg.contains("the recovery data is what failed, not the payload"),
        "{msg}"
    );
    assert!(
        msg.contains("could not be fetched from any server that has the post"),
        "with no census behind it, the clause must not invent one: {msg}"
    );
    assert!(
        !msg.contains("0 of the post's"),
        "and must never quote an empty census: {msg}"
    );
}

/// The same seam, on the shape the PRODUCT actually produces.
///
/// The test above sets `recovery_segments` to zero, and no real run
/// of the incident's shape does. A conventionally named set puts
/// its main `.par2` index in the eager plan - that is how the set
/// goes live at all - so the counter is ONE, and it arrived, so
/// `recovery_unusable()` is zero. Selecting the census wording on
/// `recovery_segments > 0` therefore reached for a census with
/// nothing in it and told the user "0 of the post's 1 PAR2 recovery
/// segment(s) are missing or damaged, so the 1 file(s) that came up
/// short have no parity left to rebuild them from".
///
/// Measured end to end at test scale in
/// `e2e_faults::dead_recovery_set_over_a_healthy_payload_fails_
/// honestly`, which is why the count here is 1 and not a round
/// number: it is what that shape reports.
#[test]
fn a_live_index_over_a_dead_volume_set_does_not_quote_an_empty_census() {
    let msg = super::incomplete_reason(
        1,
        0,
        &LossCauses {
            recovery_unobtainable: true,
            // The main index, downloaded and intact. Nothing else
            // of the recovery set ever got a slot.
            recovery_segments: 1,
            missing_segments: 1,
            total_segments: 40,
            par2_slots: 1,
            ..no_causes()
        },
    );
    assert!(
        msg.contains("the recovery data is what failed, not the payload"),
        "{msg}"
    );
    assert!(
        !msg.contains("0 of the post's 1 PAR2 recovery segment(s)"),
        "an intact index is not evidence that the parity is intact, and \
         quoting it as a census contradicts the clause it is supporting: {msg}"
    );
    assert!(
        msg.contains("could not be fetched from any server that has the post"),
        "the verdict is the only evidence this shape has: {msg}"
    );
}

/// A download-time census and a repair-time verdict, both true.
///
/// NOT two disjoint populations: an obfuscated volume gets a slot,
/// is charged to the census when the sniff flips it, and is then
/// re-fetched by the ladder. Two MEASUREMENTS at different times by
/// different machinery, and two remedies - articles this post has
/// lost, against a source that will not serve what remains - so
/// dropping either sends half the readers to the wrong place.
#[test]
fn an_eager_census_and_a_repair_side_verdict_are_both_stated() {
    let msg = super::incomplete_reason(
        83,
        0,
        &LossCauses {
            recovery_unobtainable: true,
            missing_430_recovery: 40,
            recovery_segments: 1000,
            missing_segments: 135,
            total_segments: 17130,
            par2_slots: 127,
            ..no_causes()
        },
    );
    assert!(
        msg.contains("40 of the post's 1000 PAR2 recovery segment(s) are missing or damaged"),
        "the census it does have must survive: {msg}"
    );
    assert!(
        msg.contains("could not be fetched from any server that has the post"),
        "and so must the verdict: {msg}"
    );
    // SCOPED: unqualified, it reads as walking the 4% census back.
    assert!(
        msg.contains("the PAR2 recovery volumes this repair needed"),
        "the verdict must say which volumes it means beside a census: {msg}"
    );
}

/// A takedown on the parity survives the new opening.
///
/// It rides inside the old trailing clause, which the rung above
/// suppresses to avoid saying the same figures twice - and it is the
/// one fact about a dead recovery set that changes what the user
/// should do next, because waiting cannot bring a removed volume
/// back. So it comes back as its own clause.
#[test]
fn a_parity_takedown_is_still_named_under_the_new_opening() {
    let msg = super::incomplete_reason(
        83,
        0,
        &LossCauses {
            missing_430_recovery: 900,
            takedown_430_recovery: 900,
            recovery_segments: 1000,
            missing_segments: 135,
            total_segments: 17130,
            par2_slots: 127,
            ..no_causes()
        },
    );
    assert!(msg.contains("not the payload"), "{msg}");
    assert!(
        msg.contains("900 of those recovery segment(s) were reported as removed"),
        "{msg}"
    );
    assert!(
        msg.contains("waiting will not bring the parity back"),
        "{msg}"
    );
}

/// A LossCauses with nothing known - each test overrides one field.
fn no_causes() -> LossCauses<'static> {
    LossCauses {
        missing_430: 0,
        takedown_430: 0,
        retention_excluded: 0,
        transport_failed: 0,
        missing_430_recovery: 0,
        takedown_430_recovery: 0,
        retention_excluded_recovery: 0,
        transport_failed_recovery: 0,
        recovery_segments: 0,
        recovery_unobtainable: false,
        transport_sample: None,
        decode_sample: None,
        recovery_errs: 0,
        dead_servers: &[],
        left_servers: &[],
        par2_slots: 1,
        stalled: false,
        missing_segments: 0,
        total_segments: 0,
        bytes_arrived: 0,
        backbones: &[],
        post_age_days: 0,
    }
}

/// BUG (MEDIUM): a full disk, a permission error or a bad sector used
/// to bail with a message that OPENED "download incomplete: 0 file(s)
/// with missing segments" - which the daemon read as a dead post
/// (reporting a healthy release to the indexer) and as transient
/// (arming an automatic retry straight back onto the same full disk).
/// The leading clause now says which of the two it was.
#[test]
fn a_local_write_fault_does_not_claim_missing_segments() {
    let c = LossCauses {
        missing_430: 3,
        takedown_430: 0,
        ..no_causes()
    };
    let missing = super::incomplete_reason(3, 0, &c);
    assert!(missing.starts_with("download incomplete"));
    assert!(missing.contains("3 file(s) with missing segments"));
    // No known extra cause: nothing speculative appended.
    assert!(!missing.contains("retention"), "{missing}");
    assert!(!missing.contains("connection"), "{missing}");

    // Both happened: still the post's problem, and both counts show.
    let both = super::incomplete_reason(2, 5, &c);
    assert!(both.starts_with("download incomplete"));
    assert!(both.contains("5 decode/write errors"));

    // Nothing missing: the articles all arrived, so this is ours.
    let local = super::incomplete_reason(0, 5, &no_causes());
    assert!(!local.starts_with("download incomplete"), "{local}");
    assert!(local.contains("5 decode/write error"));
    assert!(local.contains("no missing segments"));

    // The first decode error rides along - a daemon user has no
    // console, and ENOSPC vs EACCES are different stories.
    let sampled = super::incomplete_reason(
        0,
        5,
        &LossCauses {
            decode_sample: Some("write a.mkv: No space left on device".into()),
            ..no_causes()
        },
    );
    assert!(sampled.contains("No space left on device"), "{sampled}");
}

/// The takedown flavour: when a server put "removed" on the record,
/// the summary says so - dominant misses get the plain-language
/// verdict, a minority gets the bare fact, and zero flagged (the
/// normal case on backbones that never name the reason) leaves the
/// message exactly as before. The clause is APPENDED: the opening,
/// and with it `fail_kind`, must not move for a hint.
#[test]
fn takedown_flavoured_refusals_are_named_but_never_reclassify() {
    // Dominant: most refused segments carried a removal notice.
    let dominant = super::incomplete_reason(
        2,
        0,
        &LossCauses {
            missing_430: 10,
            takedown_430: 9,
            ..no_causes()
        },
    );
    assert!(dominant.starts_with("download incomplete"), "{dominant}");
    assert!(
        dominant.contains("9 of the 10 refused segment(s) as removed for a takedown request"),
        "{dominant}"
    );
    assert!(
        dominant.contains("another release is the likely answer"),
        "{dominant}"
    );

    // Minority: state the fact, claim no verdict.
    let minority = super::incomplete_reason(
        2,
        0,
        &LossCauses {
            missing_430: 10,
            takedown_430: 1,
            ..no_causes()
        },
    );
    assert!(
        minority.contains("a server reported 1 segment(s) as removed for a takedown request"),
        "{minority}"
    );
    assert!(
        !minority.contains("likely answer"),
        "a minority of flagged refusals must not claim the verdict: {minority}"
    );

    // Unflagged: nothing new appears anywhere in the message.
    let plain = super::incomplete_reason(
        2,
        0,
        &LossCauses {
            missing_430: 10,
            takedown_430: 0,
            ..no_causes()
        },
    );
    assert!(!plain.contains("takedown"), "{plain}");
}

/// A run where NO server ever said 430 is a provider problem, not a
/// dead post: it must open with its own clause (FailKind::Transport
/// - auto-retried, never reported to an indexer), and quote the
/// first real error.
#[test]
fn all_transport_losses_do_not_blame_the_post() {
    let all_transport = super::incomplete_reason(
        5,
        0,
        &LossCauses {
            transport_failed: 40,
            transport_sample: Some("unexpected response to BODY: 999 huh".into()),
            ..no_causes()
        },
    );
    assert!(
        all_transport.starts_with("download failed on connection errors"),
        "{all_transport}"
    );
    assert!(
        !all_transport.starts_with("download incomplete"),
        "{all_transport}"
    );
    assert!(all_transport.contains("40 in all"), "{all_transport}");
    assert!(all_transport.contains("999 huh"), "{all_transport}");

    // One real 430 in the mix: the post IS damaged, so the classic
    // opening stands and transport losses append as a clause.
    let mixed = super::incomplete_reason(
        5,
        0,
        &LossCauses {
            missing_430: 2,
            takedown_430: 0,
            transport_failed: 38,
            transport_sample: Some("read timed out".into()),
            ..no_causes()
        },
    );
    assert!(mixed.starts_with("download incomplete"), "{mixed}");
    assert!(
        mixed.contains("38 segment(s) lost to transport/connection errors"),
        "{mixed}"
    );
    assert!(mixed.contains("read timed out"), "{mixed}");
}

/// Hblife (Reddit, v1.0.12): "every file failed - incomplete articles
/// - but SAB got them fine". The two silent ways an article goes
/// Missing WITHOUT every server saying 430 - a retention_days setting
/// excluding it pre-flight, and a server that never held a connection
/// shrinking the unanimity mask - now name themselves in the failure
/// summary. The opening clause must NOT move: the daemon's fail_kind
/// and the *arr health mapping key on it.
#[test]
fn known_missing_causes_are_named_after_the_classifying_clause() {
    let ret = super::incomplete_reason(
        4,
        0,
        &LossCauses {
            retention_excluded: 1200,
            ..no_causes()
        },
    );
    assert!(ret.starts_with("download incomplete: 4 file(s)"), "{ret}");
    assert!(
        ret.contains("1200 segment(s) were never requested"),
        "{ret}"
    );
    assert!(ret.contains("retention_days"), "{ret}");

    let hosts = ["news.eu.example".to_string()];
    let dead = super::incomplete_reason(
        2,
        0,
        &LossCauses {
            missing_430: 9,
            takedown_430: 0,
            dead_servers: &hosts,
            ..no_causes()
        },
    );
    assert!(dead.starts_with("download incomplete: 2 file(s)"), "{dead}");
    assert!(
        dead.contains("no usable connection to news.eu.example for the entire run"),
        "{dead}"
    );

    // Both causes, both named, both after the opening clause.
    let two = ["a.example".to_string(), "b.example".to_string()];
    let both = super::incomplete_reason(
        1,
        0,
        &LossCauses {
            missing_430: 1,
            takedown_430: 0,
            retention_excluded: 7,
            dead_servers: &two,
            ..no_causes()
        },
    );
    assert!(both.starts_with("download incomplete: 1 file(s)"), "{both}");
    assert!(both.contains("7 segment(s)"), "{both}");
    assert!(both.contains("a.example, b.example"), "{both}");

    // A decode/write-only failure never mentions network causes -
    // every article arrived, so retention/server clauses would lie.
    let one = ["a.example".to_string()];
    let local = super::incomplete_reason(
        0,
        3,
        &LossCauses {
            dead_servers: &one,
            ..no_causes()
        },
    );
    assert!(!local.contains("a.example"), "{local}");
}

/// Gary, 16 Aug: the drawer told him "posts often finish
/// propagating within the hour" about a post days old. The age was
/// computed and then thrown away, so the page had no way to know.
/// The clause is what `fail_hint` keys on, so its wording is a
/// contract - and it must stay OFF the openings that own a better
/// hint of their own.
#[test]
fn an_old_post_says_so_and_a_fresh_one_stays_quiet() {
    let missing = |age| {
        super::incomplete_reason(
            1,
            0,
            &LossCauses {
                missing_430: 1965,
                takedown_430: 0,
                missing_segments: 1965,
                total_segments: 4506,
                bytes_arrived: 1_879_000_000,
                post_age_days: age,
                ..no_causes()
            },
        )
    };
    let old = missing(4);
    assert!(
        old.contains("the post is 4 day(s) old, well past the minutes-to-hours"),
        "{old}"
    );
    // Appended, never prepended: `fail_kind` keys on the opening and
    // an automatic retry hangs off that classification.
    assert!(old.starts_with("download incomplete"), "{old}");

    // Same day, and a dateless NZB (which reads as age 0): silent,
    // because propagation really could still be the answer.
    for age in [0, 0] {
        let fresh = missing(age);
        assert!(!fresh.contains("well past the minutes-to-hours"), "{fresh}");
    }

    // A transport failure is OURS - the post's age says nothing
    // about it, and the clause would take `fail_kind`'s Transport
    // classification nowhere useful.
    let transport = super::incomplete_reason(
        1,
        0,
        &LossCauses {
            transport_failed: 40,
            missing_segments: 40,
            total_segments: 4506,
            post_age_days: 9,
            ..no_causes()
        },
    );
    assert!(
        !transport.contains("well past the minutes-to-hours"),
        "{transport}"
    );

    // A short post was never fully posted, so waiting was never the
    // question - and `shortpost` is the hint that must survive.
    let short = super::incomplete_reason(
        1,
        0,
        &LossCauses {
            missing_segments: 0,
            total_segments: 4506,
            post_age_days: 9,
            ..no_causes()
        },
    );
    assert!(short.starts_with("post size header disagrees"), "{short}");
    assert!(!short.contains("well past the minutes-to-hours"), "{short}");
}

/// The age clause is written here and read back by the automatic
/// retry, which suppresses itself on a post older than
/// `GONE_MIN_AGE_DAYS` (a 7-day-old dead post was downloaded twice,
/// 15 Aug). Producer and parser are a round trip across two files,
/// so this test IS the contract - and it covers the two openings
/// that carry no age, where "unknown" has to keep the retry.
#[test]
fn the_age_clause_reads_back() {
    let missing = |age| {
        super::incomplete_reason(
            1,
            0,
            &LossCauses {
                missing_430: 1965,
                takedown_430: 0,
                missing_segments: 1965,
                total_segments: 4506,
                bytes_arrived: 1_879_000_000,
                post_age_days: age,
                ..no_causes()
            },
        )
    };
    for age in [1, 2, super::GONE_MIN_AGE_DAYS, 7, 41, 4000] {
        let msg = missing(age);
        assert_eq!(
            super::post_age_from_message(&msg),
            Some(age),
            "the retry gate has to read its own sentence back: {msg}"
        );
    }
    // No clause, no age - and no age means retry, so every one of
    // these keeps today's behaviour.
    assert_eq!(super::post_age_from_message(&missing(0)), None);
    assert_eq!(super::post_age_from_message(""), None);
    assert_eq!(
        super::post_age_from_message("download incomplete: 3 articles missing"),
        None
    );
    assert_eq!(
        super::post_age_from_message("verification failed and PAR2 repair could not complete"),
        None
    );
}

/// The retry gate reads the age clause, and the age clause is
/// suppressed only when EVERY loss was transport. One confirmed 430
/// alongside a hundred timeouts therefore produced the aged-post
/// sentence, and the gate turned that into "nothing is coming":
/// the single automatic retry was suppressed and the failure went
/// final, so a release that a journal-resume retry would have
/// finished was reported to the indexer as dead (Codex sweep 3, M8).
///
/// The census still SAYS the post is old - that is honest and Gary
/// asked for it. What changed is that the gate now reads the whole
/// message: an age plus an unexplained loss is not proof.
#[test]
fn an_ambiguous_loss_is_never_proven_stale() {
    fn causes(transport: u64, dead: &[String]) -> LossCauses<'_> {
        LossCauses {
            missing_430: 12,
            takedown_430: 0,
            missing_segments: 1965,
            total_segments: 4506,
            bytes_arrived: 1_879_000_000,
            post_age_days: 9,
            transport_failed: transport,
            dead_servers: dead,
            ..no_causes()
        }
    }
    let dead: Vec<String> = vec!["news.example.net".to_string()];
    let mixed = super::incomplete_reason(1, 0, &causes(1900, &[]));
    assert!(
        mixed.contains("well past the minutes-to-hours"),
        "the age is still stated: {mixed}"
    );
    assert!(
        !super::missing_articles_proven_stale(&mixed),
        "a transport-dominant loss is ours to heal, not a dead post: {mixed}"
    );

    let starved = super::incomplete_reason(1, 0, &causes(0, &dead));
    assert!(
        !super::missing_articles_proven_stale(&starved),
        "segments only a never-connected server carries say nothing about the post: {starved}"
    );

    // The case the suppression exists for is untouched: every loss a
    // 430, every server answering, the post long past propagation.
    let stale = super::incomplete_reason(1, 0, &causes(0, &[]));
    assert!(
        super::missing_articles_proven_stale(&stale),
        "a proven-stale post must still suppress its retry: {stale}"
    );
    // ...and a fresh post of the same shape never is.
    let fresh = super::incomplete_reason(
        1,
        0,
        &LossCauses {
            post_age_days: 0,
            ..causes(0, &[])
        },
    );
    assert!(!super::missing_articles_proven_stale(&fresh), "{fresh}");

    // M3: DAMAGE is not absence. Same aged, every-server-answering
    // post as `stale` above, but with decode/write errors in the
    // mix - the bytes were posted and arrived corrupt, and a
    // journal-resume retry re-fetches exactly those. The gate used
    // to read this as a dead post and suppress the one automatic
    // retry, which also made the failure final.
    let damaged = super::incomplete_reason(1, 3, &causes(0, &[]));
    assert!(
        damaged.contains("well past the minutes-to-hours"),
        "the age is still stated, because it is still true: {damaged}"
    );
    assert!(
        !super::missing_articles_proven_stale(&damaged),
        "damaged articles are re-fetchable at any age: {damaged}"
    );

    // Codex sweep 5, M6: corrupt PARITY is damage too. The census
    // subtracts recovery errors from `derrs` - right for payload
    // completeness, wrong for the retry question - so an aged post
    // with one missing payload article and one corrupt parity
    // article read as settled absence and lost its retry, even
    // though fresh parity from another provider repairs the gap.
    let parity = super::incomplete_reason(
        1,
        0,
        &LossCauses {
            recovery_errs: 2,
            ..causes(0, &[])
        },
    );
    assert!(
        !super::missing_articles_proven_stale(&parity),
        "corrupt parity is re-fetchable at any age: {parity}"
    );

    // Retention-excluded segments were never REQUESTED: the
    // configured retention_days pre-seeded the refusal mask, so no
    // server gave an opinion about them. Age proves nothing about a
    // question nobody was asked - and an old post is exactly the one
    // a retention setting excludes, so without this exclusion the
    // user's own settings row suppressed the retry and went final.
    let excluded = super::incomplete_reason(
        1,
        0,
        &LossCauses {
            retention_excluded: 1900,
            ..causes(0, &[])
        },
    );
    assert!(
        excluded.contains("older than every server's configured retention"),
        "{excluded}"
    );
    assert!(
        !super::missing_articles_proven_stale(&excluded),
        "a retention exclusion is a settings problem, not a dead post: {excluded}"
    );
    // The narrower shape the challenger established, and it needs no
    // 430 at all: a decode error makes `incomplete` non-zero on its
    // own, so an aged post whose ONLY fault is corrupt payload took
    // the same opening, the same age clause and the same suppression.
    let corrupt_only = super::incomplete_reason(
        1,
        2,
        &LossCauses {
            missing_430: 0,
            takedown_430: 0,
            missing_segments: 0,
            ..causes(0, &[])
        },
    );
    assert!(
        !super::missing_articles_proven_stale(&corrupt_only),
        "corruption alone must never read as a dead post: {corrupt_only}"
    );
}

/// Field report, 31 Jul: "94 file(s) with missing segments" for a post that
/// was in fact entirely gone. The file count is the same sentence
/// whether one segment or twelve thousand went astray, so the census
/// rides behind the classifying clause - and the clause itself does
/// not move, because `fail_kind` and the *arr health mapping key on
/// it.
#[test]
fn the_segment_census_rides_behind_the_opening() {
    let short = super::incomplete_reason(
        2,
        0,
        &LossCauses {
            missing_430: 3,
            takedown_430: 0,
            missing_segments: 3,
            total_segments: 12_018,
            bytes_arrived: 8_100_000_000,
            ..no_causes()
        },
    );
    assert!(
        short.starts_with("download incomplete: 2 file(s)"),
        "{short}"
    );
    assert!(
        short.contains("3 of 12018 segment(s) never arrived"),
        "{short}"
    );
    assert!(short.contains("8100 MB did"), "{short}");
    // Nearly everything arrived: nothing here may say "gone".
    assert!(!short.starts_with("post is gone"), "{short}");

    // No per-slot accounting (any caller that cannot census): the
    // clause is suppressed rather than printing a bare "0 of 0".
    let censusless = super::incomplete_reason(
        2,
        0,
        &LossCauses {
            missing_430: 3,
            takedown_430: 0,
            ..no_causes()
        },
    );
    assert!(
        !censusless.contains("segment(s) never arrived"),
        "{censusless}"
    );
}

/// A post where NOTHING is retrievable is not a damaged post, and
/// treating it as one spends an automatic retry re-proving it. It
/// earns its own opening (`FailKind::Gone`: still reported to an
/// indexer, never auto-retried) - but ONLY on positive evidence,
/// never on the absence of other causes.
#[test]
fn a_wholly_dead_post_says_so() {
    let backbones = ["highwinds".to_string(), "usenetexpress".to_string()];
    let gone = super::incomplete_reason(
        94,
        0,
        &LossCauses {
            missing_430: 12_018,
            takedown_430: 0,
            missing_segments: 12_018,
            total_segments: 12_018,
            bytes_arrived: 0,
            backbones: &backbones,
            post_age_days: 21,
            ..no_causes()
        },
    );
    assert!(gone.starts_with("post is gone"), "{gone}");
    assert!(gone.contains("not one of the 12018 article(s)"), "{gone}");
    assert!(gone.contains("all 94 file(s)"), "{gone}");
    // Two providers of one backbone are ONE opinion; the count says so.
    assert!(
        gone.contains("asked 2 backbone(s): highwinds, usenetexpress"),
        "{gone}"
    );
    // Already said every article was absent - no census on top.
    assert!(!gone.contains("segment(s) never arrived"), "{gone}");

    // Audit 20 Aug, A2: a takedown that left the `.par2` volumes up
    // is the COMMON gone shape, and `bytes_arrived` counts every
    // slot's wire bytes - so the parity's bytes used to block this
    // verdict and the job spent a full retry re-proving the same
    // payload absent. The census terms are payload-only and already
    // say nothing payload arrived; recovery bytes are tolerated.
    let parity_survived = super::incomplete_reason(
        94,
        0,
        &LossCauses {
            missing_430: 12_018,
            missing_segments: 12_018,
            total_segments: 12_018,
            bytes_arrived: 312_000_000,
            post_age_days: 21,
            ..no_causes()
        },
    );
    assert!(
        parity_survived.starts_with("post is gone"),
        "surviving parity bytes must not veto a wholly-dead payload: {parity_survived}"
    );
    // Without recovery slots those bytes are unexplained, and the
    // old belt stands: unexplained arrivals block the verdict.
    let unexplained = super::incomplete_reason(
        94,
        0,
        &LossCauses {
            missing_430: 12_018,
            missing_segments: 12_018,
            total_segments: 12_018,
            bytes_arrived: 312_000_000,
            post_age_days: 21,
            par2_slots: 0,
            ..no_causes()
        },
    );
    assert!(
        unexplained.starts_with("download incomplete"),
        "{unexplained}"
    );

    // One byte arrived: the post is damaged, not dead.
    let damaged = super::incomplete_reason(
        94,
        0,
        &LossCauses {
            missing_430: 12_017,
            takedown_430: 0,
            missing_segments: 12_017,
            total_segments: 12_018,
            bytes_arrived: 1,
            post_age_days: 21,
            ..no_causes()
        },
    );
    assert!(damaged.starts_with("download incomplete"), "{damaged}");

    // A server that never connected did not vote, so unanimity is
    // unproven and "gone" would be a lie - the dead-server clause
    // still owns this case.
    // A slot the coverage census flagged, with EVERY article
    // accounted for: the size header over-declared, re-downloading
    // cannot change it, and `fail_kind` must NOT read this as
    // missing articles (that arms a retry which replays the same
    // spans to the same gap).
    let lying = super::incomplete_reason(
        1,
        0,
        &LossCauses {
            total_segments: 240,
            ..no_causes()
        },
    );
    assert!(
        lying.starts_with("post size header disagrees with its parts"),
        "{lying}"
    );

    // Audit 20 Aug, A2: a 430 on a `.vol` article used to defeat
    // this verdict and fall through to "1 file(s) with missing
    // segments; 0 of 240 segment(s) never arrived" in one breath,
    // arming a retry that replays the same spans to the same gap.
    // Losses the census attributes to recovery slots must not veto
    // a payload-side verdict - which since sweep 8's M7 is true by
    // construction: the counter they land in is the recovery one.
    let lying_vol_430 = super::incomplete_reason(
        1,
        0,
        &LossCauses {
            total_segments: 240,
            missing_430_recovery: 1,
            ..no_causes()
        },
    );
    assert!(
        lying_vol_430.starts_with("post size header disagrees with its parts"),
        "a recovery-slot 430 must not defeat the size-header verdict: {lying_vol_430}"
    );
    // A loss NOT accounted to a recovery slot is (or may be) payload
    // loss, and the verdict stands down exactly as before.
    let lying_payload_430 = super::incomplete_reason(
        1,
        0,
        &LossCauses {
            total_segments: 240,
            missing_430: 1,
            ..no_causes()
        },
    );
    assert!(
        lying_payload_430.starts_with("download incomplete"),
        "{lying_payload_430}"
    );

    // ...but a DECODE error is not that. The article was posted and
    // arrived, it merely arrived damaged, so `missing_segments`
    // stays at zero while the bytes are a real gap. Claiming "every
    // article arrived and decoded" beside a non-zero decode count is
    // self-contradicting, and routing it away from MissingArticles
    // suppresses exactly the journal-resume retry that can heal it.
    let corrupt = super::incomplete_reason(
        1,
        1,
        &LossCauses {
            total_segments: 240,
            ..no_causes()
        },
    );
    assert!(
        corrupt.starts_with("download incomplete"),
        "a decode error must keep the retryable opening: {corrupt}"
    );

    let hosts = ["news.eu.example".to_string()];
    let unproven = super::incomplete_reason(
        94,
        0,
        &LossCauses {
            missing_430: 12_018,
            takedown_430: 0,
            missing_segments: 12_018,
            total_segments: 12_018,
            bytes_arrived: 0,
            dead_servers: &hosts,
            post_age_days: 21,
            ..no_causes()
        },
    );
    assert!(unproven.starts_with("download incomplete"), "{unproven}");

    // Transport losses in the mix: nobody proved anything about the
    // post, so it must not be declared dead.
    let flaky = super::incomplete_reason(
        94,
        0,
        &LossCauses {
            missing_430: 12_000,
            takedown_430: 0,
            transport_failed: 18,
            missing_segments: 12_018,
            total_segments: 12_018,
            bytes_arrived: 0,
            post_age_days: 21,
            ..no_causes()
        },
    );
    assert!(flaky.starts_with("download incomplete"), "{flaky}");
}

/// A post nobody carries YET is the same picture as a post nobody
/// carries ANY MORE - every article 430, not a byte arrived - and
/// calling the first one dead would skip the automatic retry that
/// exists precisely for it. (This is what the daemon's auto-retry
/// tests caught: a release grabbed off an indexer minutes after its
/// pre 430s everywhere until it propagates.)
#[test]
fn a_post_still_propagating_is_not_a_dead_one() {
    let fresh = |age| {
        super::incomplete_reason(
            8,
            0,
            &LossCauses {
                missing_430: 900,
                takedown_430: 0,
                missing_segments: 900,
                total_segments: 900,
                bytes_arrived: 0,
                post_age_days: age,
                ..no_causes()
            },
        )
    };
    // Hours old, then a day, then the day before the threshold: all
    // still transient, all still eligible for the retry.
    for age in 0..super::GONE_MIN_AGE_DAYS {
        let m = fresh(age);
        assert!(m.starts_with("download incomplete"), "age {age}: {m}");
    }
    // Old enough that propagation cannot be the explanation.
    let old = fresh(super::GONE_MIN_AGE_DAYS);
    assert!(old.starts_with("post is gone"), "{old}");

    // An NZB with no usable date reads as age 0 - unknown is not old,
    // so it keeps the retry rather than being written off.
    assert_eq!(super::nzb_age_days(0), 0);
    assert_eq!(super::nzb_age_days(-1), 0);
}

/// Backbones are named only where a server actually said 430. On a
/// transport-only failure nobody gave an opinion about the post, and
/// listing the backbones there dresses a provider wobble up as a
/// unanimous verdict.
#[test]
fn backbones_are_named_only_when_someone_voted() {
    let backbones = ["highwinds".to_string()];
    let voted = super::incomplete_reason(
        1,
        0,
        &LossCauses {
            missing_430: 5,
            takedown_430: 0,
            backbones: &backbones,
            ..no_causes()
        },
    );
    assert!(voted.contains("asked 1 backbone(s): highwinds"), "{voted}");

    let no_vote = super::incomplete_reason(
        1,
        0,
        &LossCauses {
            transport_failed: 5,
            backbones: &backbones,
            ..no_causes()
        },
    );
    assert!(!no_vote.contains("backbone"), "{no_vote}");

    // A server addressed by IP names no backbone. The collector
    // drops it rather than printing an address as though it were a
    // provider (caught live on a scratch daemon: "asked 1
    // backbone(s): 0", back when a dotted quad reduced to one
    // octet - see sweep 8's L9).
    assert_eq!(nzbkit::oracle::backbone_of("127.0.0.1"), "127.0.0.1");
    let none = super::incomplete_reason(
        1,
        0,
        &LossCauses {
            missing_430: 5,
            takedown_430: 0,
            backbones: &[],
            ..no_causes()
        },
    );
    assert!(!none.contains("backbone"), "{none}");
}

/// The version tag appends and never disturbs the opening clause the
/// daemon classifies on.
#[test]
fn build_tag_appends_without_moving_the_opening() {
    let tagged = super::with_build("download incomplete: 1 file(s)".into());
    assert!(
        tagged.starts_with("download incomplete: 1 file(s)"),
        "{tagged}"
    );
    assert!(tagged.contains("[nzbfast "), "{tagged}");
    assert!(tagged.ends_with(']'), "{tagged}");
}

/// The bomb sentence is one of the Reasons a successful unlock
/// answers.
///
/// It reaches `fail_message` through `unpack_failure` on the refused
/// arm of the manual-unlock tail, so it is not one of the two
/// literals that arm's sibling used to compare against - and a later
/// correct password then left a Completed row reading "extraction
/// exceeded available disk space" for good. Asserted through the
/// composed sentence, not the constant, because the wrapper is what
/// the row actually carries.
#[test]
fn a_successful_unlock_clears_the_bomb_reason_too() {
    assert!(super::unlock_answers(&super::bomb_failure()));
    assert!(super::unlock_answers(&super::unpack_failure(
        Some(super::bomb_failure()),
        "password did not unlock the archive",
    )));
    assert!(super::unlock_answers(&super::unpack_failure(
        None,
        "password did not unlock the archive",
    )));
    assert!(super::unlock_answers("password required to unpack"));
    // And a verdict the unlock did NOT answer keeps its say.
    assert!(!super::unlock_answers(
        "download incomplete: 1 file(s) with missing segments"
    ));
    assert!(!super::unlock_answers(""));
}
