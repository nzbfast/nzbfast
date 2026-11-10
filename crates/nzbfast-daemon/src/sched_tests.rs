use super::{
    MAX_REPLAY_MINUTES, SchedAction, SchedEffect, Tick, WEEK_MINUTES, catch_up_state,
    classify_tick, effective_state, next_resume_in, parse_days, parse_schedule, sched_step,
};
use crate::parse_size;

/// Minute-of-week helper for readable test times (Mon=0).
fn mow(day: u32, h: u32, m: u32) -> u32 {
    day * 1440 + h * 60 + m
}

#[test]
fn sizes_parse() {
    assert_eq!(parse_size("0"), Some(0));
    assert_eq!(parse_size("400000"), Some(400_000));
    assert_eq!(parse_size("500K"), Some(500_000));
    assert_eq!(parse_size("4M"), Some(4_000_000));
    assert_eq!(parse_size("1.5m"), Some(1_500_000));
    assert_eq!(parse_size("2G"), Some(2_000_000_000));
    assert_eq!(parse_size(" 4M "), Some(4_000_000));
    assert_eq!(parse_size("50%"), None);
    assert_eq!(parse_size("-1"), None);
    assert_eq!(parse_size("junk"), None);
}

#[test]
fn days_parse() {
    assert_eq!(parse_days("all"), Some([true; 7]));
    assert_eq!(
        parse_days("mon-fri"),
        Some([true, true, true, true, true, false, false])
    );
    assert_eq!(
        parse_days("sat,sun"),
        Some([false, false, false, false, false, true, true])
    );
    assert_eq!(
        parse_days("Mon,wed-Fri"),
        Some([true, false, true, true, true, false, false])
    );
    // Wrapping range.
    assert_eq!(
        parse_days("sat-mon"),
        Some([true, false, false, false, false, true, true])
    );
    assert_eq!(parse_days("noday"), None);
    assert_eq!(parse_days(""), None);
}

#[test]
fn schedule_parses() {
    let entries = parse_schedule(
        r#"[
          {"days": "mon-fri", "time": "08:00", "action": "speedlimit", "value": "4M"},
          {"days": "mon-fri", "time": "23:30", "action": "speedlimit", "value": 0},
          {"days": "sat,sun", "time": "09:15", "action": "pause"},
          {"days": "all", "time": "17:00", "action": "resume"}
        ]"#,
    )
    .expect("parse");
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].action, SchedAction::SpeedLimit(4_000_000));
    assert_eq!(entries[0].minute, 8 * 60);
    assert!(entries[0].days[4] && !entries[0].days[5]);
    assert_eq!(entries[1].action, SchedAction::SpeedLimit(0));
    assert_eq!(entries[2].action, SchedAction::Pause);
    assert_eq!(entries[2].minute, 9 * 60 + 15);
    assert_eq!(entries[3].action, SchedAction::Resume);

    assert!(parse_schedule(r#"{"not": "an array"}"#).is_err());
    assert!(parse_schedule(r#"[{"time": "25:00", "action": "pause"}]"#).is_err());
    assert!(parse_schedule(r#"[{"time": "08:00", "action": "explode"}]"#).is_err());
    assert!(parse_schedule(r#"[{"time": "08:00", "action": "speedlimit"}]"#).is_err());
}

#[test]
fn effective_state_scenarios() {
    let entries = parse_schedule(
        r#"[
          {"days": "mon-fri", "time": "08:00", "action": "speedlimit", "value": "4M"},
          {"days": "mon-fri", "time": "23:00", "action": "speedlimit", "value": 0},
          {"days": "sat", "time": "10:00", "action": "pause"},
          {"days": "sun", "time": "10:00", "action": "resume"}
        ]"#,
    )
    .unwrap();

    // Wed 12:00 - weekday daytime: limited, and Sunday's resume is the
    // most recent pause-kind action.
    assert_eq!(
        effective_state(&entries, mow(2, 12, 0)),
        (Some(false), Some(4_000_000))
    );
    // Wed 23:30 - after the evening lift.
    assert_eq!(
        effective_state(&entries, mow(2, 23, 30)),
        (Some(false), Some(0))
    );
    // Thu 07:59 - still on Wednesday night's state.
    assert_eq!(
        effective_state(&entries, mow(3, 7, 59)),
        (Some(false), Some(0))
    );
    // Exact boundary counts as fired (restart at Thu 08:00 sharp).
    assert_eq!(
        effective_state(&entries, mow(3, 8, 0)),
        (Some(false), Some(4_000_000))
    );
    // Sat 12:00 - weekend pause in effect; Friday night lifted the cap.
    assert_eq!(
        effective_state(&entries, mow(5, 12, 0)),
        (Some(true), Some(0))
    );
    // Sun 09:00 - still paused from Saturday.
    assert_eq!(
        effective_state(&entries, mow(6, 9, 0)),
        (Some(true), Some(0))
    );
    // Sun 11:00 - resumed.
    assert_eq!(
        effective_state(&entries, mow(6, 11, 0)),
        (Some(false), Some(0))
    );
    // Mon 00:00 wrap-around: Sunday's resume is 14h back, Friday's
    // lift is the newest speedlimit.
    assert_eq!(
        effective_state(&entries, mow(0, 0, 0)),
        (Some(false), Some(0))
    );

    // No entries of a kind → None (nothing overridden at startup).
    let only_limit = parse_schedule(
        r#"[{"days": "all", "time": "12:00", "action": "speedlimit", "value": "1M"}]"#,
    )
    .unwrap();
    assert_eq!(
        effective_state(&only_limit, mow(0, 13, 0)),
        (None, Some(1_000_000))
    );
    assert_eq!(effective_state(&[], 0), (None, None));

    // Tie at the same minute: later entry in the file wins.
    let tie = parse_schedule(
        r#"[
          {"days": "mon", "time": "09:00", "action": "pause"},
          {"days": "mon", "time": "09:00", "action": "resume"}
        ]"#,
    )
    .unwrap();
    assert_eq!(effective_state(&tie, mow(0, 9, 0)).0, Some(false));
}

/// The "paused - by your schedule until 08:00" clause only gets a
/// time when the schedule really has one ahead of it.
#[test]
fn next_resume_is_the_nearest_one_ahead() {
    let entries = parse_schedule(
        r#"[
          {"days": "mon-fri", "time": "23:00", "action": "pause"},
          {"days": "mon-fri", "time": "08:00", "action": "resume"},
          {"days": "sun", "time": "20:00", "action": "resume"}
        ]"#,
    )
    .unwrap();

    // Mon 23:30, inside the weekday quiet hours: Tuesday 08:00.
    assert_eq!(next_resume_in(&entries, mow(0, 23, 30)), Some(8 * 60 + 30));
    // Fri 23:30 - the weekday resumes are all behind us, so the
    // nearest ahead is Sunday 20:00 (44.5 h), not Monday 08:00.
    assert_eq!(next_resume_in(&entries, mow(4, 23, 30)), Some(44 * 60 + 30));
    // Standing exactly ON a resume minute is not a future time, so
    // the answer is that entry a week out - never "in 0 minutes".
    assert_eq!(next_resume_in(&entries, mow(1, 8, 0)), Some(1440));

    // A schedule that only ever pauses promises nothing.
    let one_way =
        parse_schedule(r#"[{"days": "all", "time": "23:00", "action": "pause"}]"#).unwrap();
    assert_eq!(next_resume_in(&one_way, mow(0, 23, 30)), None);
    assert_eq!(next_resume_in(&[], 0), None);
}

#[test]
fn fires_at_boundaries() {
    let e = parse_schedule(r#"[{"days": "tue", "time": "06:30", "action": "pause"}]"#)
        .unwrap()
        .remove(0);
    assert!(e.fires_at(mow(1, 6, 30)));
    assert!(!e.fires_at(mow(1, 6, 29)));
    assert!(!e.fires_at(mow(1, 6, 31)));
    assert!(!e.fires_at(mow(2, 6, 30)));
}

/// §129 2g: the edge actions (server toggles, quota reset) parse, and
/// contribute NOTHING to the standing pause/limit state - replaying a
/// week of config edits at startup would fight the user's own toggles.
#[test]
fn edge_actions_parse_and_carry_no_state() {
    let entries = parse_schedule(
        r#"[
        {"days":"mon","time":"01:00","action":"server_enable","value":"news.example.com"},
        {"days":"mon","time":"02:00","action":"server_disable","value":"backup.example.com"},
        {"days":"mon","time":"03:00","action":"quota_reset"},
        {"days":"mon","time":"04:00","action":"pause"}
    ]"#,
    )
    .unwrap();
    assert_eq!(
        entries[0].action,
        SchedAction::ServerEnable {
            host: "news.example.com".into(),
            on: true
        }
    );
    assert_eq!(
        entries[1].action,
        SchedAction::ServerEnable {
            host: "backup.example.com".into(),
            on: false
        }
    );
    assert_eq!(entries[2].action, SchedAction::QuotaReset);
    // Monday 05:00: the pause entry is the state; the edges said nothing.
    let (paused, limit) = effective_state(&entries, mow(0, 5, 0));
    assert_eq!(paused, Some(true));
    assert_eq!(limit, None);
    // A server action without a host is a config error, said plainly.
    assert!(parse_schedule(r#"[{"days":"mon","time":"01:00","action":"server_enable"}]"#).is_err());
    // ...and an unknown action still names the full menu.
    let err = parse_schedule(r#"[{"days":"mon","time":"01:00","action":"defrag"}]"#)
        .unwrap_err()
        .to_string();
    assert!(err.contains("quota_reset"), "menu missing from: {err}");
}

/// §129 2g: a fired server toggle edits the config exactly as the
/// settings toggle does, keyed by host (case-insensitive); an unknown
/// host does nothing rather than guessing.
#[test]
fn a_scheduled_server_toggle_edits_the_config_by_host() {
    let dir = std::env::temp_dir().join(format!("nzbfast-schedsrv-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = crate::testutil::test_daemon(&dir);
    std::fs::write(
        &d.cfg_path,
        r#"{"servers":[{"host":"news.example.com","port":563,"username":"u","password":"p"}]}"#,
    )
    .unwrap();
    super::apply_action(
        &d,
        SchedAction::ServerEnable {
            host: "NEWS.example.com".into(),
            on: false,
        },
    );
    let cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&d.cfg_path).unwrap()).unwrap();
    assert_eq!(
        cfg["servers"][0]["enabled"],
        serde_json::json!(false),
        "the host match is case-insensitive and writes enabled=false"
    );
    // Re-enabling removes the key (default; keeps the file clean).
    super::apply_action(
        &d,
        SchedAction::ServerEnable {
            host: "news.example.com".into(),
            on: true,
        },
    );
    let cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&d.cfg_path).unwrap()).unwrap();
    assert!(cfg["servers"][0].get("enabled").is_none());
    // An unknown host must not touch the file.
    let before = std::fs::read_to_string(&d.cfg_path).unwrap();
    super::apply_action(
        &d,
        SchedAction::ServerEnable {
            host: "nobody.example.com".into(),
            on: false,
        },
    );
    assert_eq!(std::fs::read_to_string(&d.cfg_path).unwrap(), before);
    // A quota reset only raises the flag; the download runner owns the
    // ledger and applies it on its next pass.
    super::apply_action(&d, SchedAction::QuotaReset);
    assert!(d.quota_reset.load(std::sync::atomic::Ordering::Relaxed));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// F3: a long sleep must not skip reconciliation. Found by the
// 10 September 2026 read-only sweep.
// ---------------------------------------------------------------------------

/// The report's own schedule: pause every evening, resume every morning.
fn nightly() -> Vec<super::SchedEntry> {
    parse_schedule(
        r#"[
          {"days": "all", "time": "20:00", "action": "pause"},
          {"days": "all", "time": "07:00", "action": "resume"},
          {"days": "all", "time": "20:00", "action": "speedlimit", "value": "1M"},
          {"days": "all", "time": "07:00", "action": "speedlimit", "value": 0}
        ]"#,
    )
    .unwrap()
}

/// A tick where both clocks agree and one minute passed is an ordinary
/// advance - the common case, and the one that must keep firing
/// one-shots.
#[test]
fn an_ordinary_minute_tick_advances() {
    let t = 1_789_045_200;
    assert_eq!(
        classify_tick(mow(0, 9, 0), mow(0, 9, 1), t, t + 60),
        Tick::Advance
    );
    // Two half-minute ticks inside the same minute.
    assert_eq!(
        classify_tick(mow(0, 9, 0), mow(0, 9, 0), t, t + 30),
        Tick::Advance
    );
    // A tick the box was too busy to serve on time, still under the
    // replay ceiling.
    assert_eq!(
        classify_tick(mow(0, 9, 0), mow(0, 12, 0), t, t + 3 * 3600),
        Tick::Advance
    );
}

/// The minute cursor may lead the absolute one by a minute, because the
/// two are read from different clocks half a minute apart. That is not a
/// discontinuity, and reading it as one would reconcile on every tick.
#[test]
fn a_one_minute_lead_on_the_absolute_clock_is_not_a_jump() {
    let t = 1_789_045_200;
    // 31 real seconds, but a minute boundary crossed inside them.
    assert_eq!(
        classify_tick(mow(0, 9, 0), mow(0, 9, 1), t, t + 31),
        Tick::Advance
    );
}

/// F3 itself: a twelve-hour suspend is a discontinuity, and the span it
/// reports is the REAL time that passed.
#[test]
fn a_twelve_hour_suspend_reconciles_over_the_hours_it_missed() {
    let t = 1_789_045_200;
    assert_eq!(
        classify_tick(mow(0, 20, 0), mow(1, 8, 0), t, t + 12 * 3600),
        Tick::Reconcile { span: 720 }
    );
}

/// ...and reconciling it produces the resume the old guard threw away.
#[test]
fn the_overnight_sleep_wakes_up_resumed() {
    // Paused at Monday 20:00, machine wakes at Tuesday 08:00. The 07:00
    // resume and the 07:00 lift are both inside the window.
    let (paused, limit) = catch_up_state(&nightly(), mow(1, 8, 0), 720);
    assert_eq!(
        (paused, limit),
        (Some(false), Some(0)),
        "the queue stayed paused all of the next day - this is F3"
    );
}

/// The edge actions in a skipped window must NOT be replayed: waking up
/// to a night of config edits and quota resets is a worse bug than the
/// one being fixed.
#[test]
fn a_reconcile_never_replays_a_one_shot() {
    let entries = parse_schedule(
        r#"[
          {"days": "all", "time": "01:00", "action": "quota_reset"},
          {"days": "all", "time": "02:00", "action": "server_disable", "value": "block.example"},
          {"days": "all", "time": "03:00", "action": "server_enable", "value": "block.example"},
          {"days": "all", "time": "04:00", "action": "resume"}
        ]"#,
    )
    .unwrap();
    // The window holds all four; only the standing one comes back.
    assert_eq!(
        catch_up_state(&entries, mow(1, 8, 0), 720),
        (Some(false), None)
    );
}

/// A window that contains no standing rule at all leaves the daemon's
/// current state alone - the bound is what keeps a wake-up from undoing
/// a manual pause the user made days before the machine slept.
#[test]
fn a_window_with_no_rule_in_it_reconciles_to_nothing() {
    // Woke at 19:00 after a nine-hour sleep from 10:00: the 07:00 rules
    // are behind the window's opening edge, the 20:00 ones ahead of it.
    assert_eq!(
        catch_up_state(&nightly(), mow(1, 19, 0), 9 * 60),
        (None, None)
    );
    // And a zero-length window fires nothing whatever the schedule says.
    assert_eq!(catch_up_state(&nightly(), mow(1, 7, 0), 0), (None, None));
}

/// A whole week of span IS `effective_state` - one rule, one copy.
#[test]
fn a_week_wide_window_is_the_unbounded_state() {
    let e = nightly();
    for now in [mow(0, 0, 0), mow(1, 8, 0), mow(3, 19, 59), mow(6, 23, 59)] {
        assert_eq!(
            catch_up_state(&e, now, WEEK_MINUTES),
            effective_state(&e, now)
        );
    }
    // A machine off for a month is capped at the week, not walked.
    let t = 1_789_045_200;
    assert_eq!(
        classify_tick(mow(0, 9, 0), mow(0, 9, 0), t, t + 30 * 86_400),
        Tick::Reconcile { span: WEEK_MINUTES }
    );
}

/// A window's edges: a rule at `now` itself is inside it, a rule exactly
/// `span` minutes back is not.
#[test]
fn the_window_is_open_at_the_far_edge_and_closed_at_the_near_one() {
    let e = parse_schedule(r#"[{"days": "all", "time": "07:00", "action": "resume"}]"#).unwrap();
    // Fires exactly at `now`.
    assert_eq!(catch_up_state(&e, mow(1, 7, 0), 1).0, Some(false));
    // 60 minutes back, window 60 wide: (06:00, 07:00] excludes 06:00 but
    // the rule is at 07:00 = distance 60 from 08:00.
    assert_eq!(catch_up_state(&e, mow(1, 8, 0), 60).0, None);
    assert_eq!(catch_up_state(&e, mow(1, 8, 0), 61).0, Some(false));
}

/// DST fall back: local time repeats an hour, so the minute cursor runs
/// nearly a whole week "forward" while one real minute passed. That must
/// never read as a week to replay - and since every minute of the
/// repeated hour has already been walked once, the cursor HOLDS rather
/// than walking it again.
#[test]
fn a_dst_fall_back_holds_without_replaying_the_week() {
    let t = 1_793_509_200;
    let tick = classify_tick(mow(6, 1, 59), mow(6, 1, 0), t, t + 30);
    assert_eq!(tick, Tick::Hold);
    // The cursor stays put and nothing fires.
    let (next, _, effects) = sched_step(&nightly(), mow(6, 1, 59), mow(6, 1, 0), t, t + 30);
    assert_eq!((next, effects), (mow(6, 1, 59), vec![]));
}

/// A DST spring forward moves local time an hour ahead of real time. The
/// skipped local hour never existed, so its rules must not fire - but the
/// landing minute did, and it arrives with one real minute boundary in a
/// 30 s tick.
#[test]
fn a_dst_spring_forward_does_not_fire_the_hour_that_never_happened() {
    let t = 1_772_953_200;
    // 01:59:45 -> 03:00:15 local, across the UTC boundary at t.
    let tick = classify_tick(mow(6, 1, 59), mow(6, 3, 0), t - 15, t + 15);
    assert_eq!(tick, Tick::Jump { span: 1 });
}

/// One simulated night at the loop's REAL cadence: a tick every 30 s,
/// local time derived from a UTC clock and an offset that changes at
/// `switch`. Returns every rule fired, with the local minute it fired at.
fn drive_night(
    entries: &[super::SchedEntry],
    phase: u64,
    before: i64,
    after: i64,
) -> Vec<(u32, SchedAction)> {
    // A UTC instant on a minute boundary that reads Sunday 00:30 local;
    // the offset changes when local time first reads 02:00.
    let utc0: u64 = 1_772_953_200;
    let switch = utc0 + 90 * 60;
    let local = |utc: u64| -> u32 {
        let off = if utc >= switch { after } else { before } - before;
        let secs = (utc as i64 - utc0 as i64) + off + i64::from(mow(6, 0, 30)) * 60;
        ((secs / 60) as u32) % WEEK_MINUTES
    };
    let mut fired = Vec::new();
    let (mut last_utc, end) = (utc0 + phase, utc0 + 5 * 3600);
    let mut last = local(last_utc);
    while last_utc < end {
        let now_utc = last_utc + 30;
        let now = local(now_utc);
        let (next, _, effects) = sched_step(entries, last, now, last_utc, now_utc);
        for e in effects {
            match e {
                SchedEffect::Fire(a) => fired.push((now, a)),
                SchedEffect::Reconcile { .. } => panic!("no reconcile on a DST night: {e:?}"),
            }
        }
        last = next;
        last_utc = now_utc;
    }
    fired
}

/// A15: "pause 23:00, resume 03:00" on the night 02:00 becomes 03:00.
/// The loop ticks every 30 s, so seconds-over-sixty saw no real time
/// pass across the jump, reconciled over an empty window, and moved the
/// cursor past 03:00: the resume never fired and the queue stayed paused
/// all day. The one-shot at the landing minute must fire too, and the
/// rule inside the hour that never existed must not.
#[test]
fn a_spring_forward_at_the_real_cadence_fires_the_landing_minute_once() {
    let e = parse_schedule(
        r#"[
          {"days": "all", "time": "03:00", "action": "resume"},
          {"days": "all", "time": "03:00", "action": "quota_reset"},
          {"days": "all", "time": "02:30", "action": "pause"},
          {"days": "all", "time": "04:00", "action": "speedlimit", "value": 0}
        ]"#,
    )
    .unwrap();
    for phase in [0, 1, 14, 15, 29] {
        // Standard time, then an hour ahead from local 02:00.
        let fired = drive_night(&e, phase, 0, 3600);
        assert_eq!(
            fired,
            vec![
                (mow(6, 3, 0), SchedAction::Resume),
                (mow(6, 3, 0), SchedAction::QuotaReset),
                (mow(6, 4, 0), SchedAction::SpeedLimit(0)),
            ],
            "phase {phase}s"
        );
    }
}

/// The fall-back mirror: local 02:00 becomes 01:00 again, and every rule
/// in the repeated hour - one-shots included - fires exactly once.
#[test]
fn a_fall_back_at_the_real_cadence_fires_the_repeated_hour_once() {
    let e = parse_schedule(
        r#"[
          {"days": "all", "time": "01:15", "action": "pause"},
          {"days": "all", "time": "01:30", "action": "quota_reset"},
          {"days": "all", "time": "01:45", "action": "resume"},
          {"days": "all", "time": "02:00", "action": "speedlimit", "value": 0}
        ]"#,
    )
    .unwrap();
    for phase in [0, 1, 14, 15, 29] {
        // An hour ahead, then standard time from local 02:00.
        let fired = drive_night(&e, phase, 3600, 0);
        assert_eq!(
            fired,
            vec![
                (mow(6, 1, 15), SchedAction::Pause),
                (mow(6, 1, 30), SchedAction::QuotaReset),
                (mow(6, 1, 45), SchedAction::Resume),
                (mow(6, 2, 0), SchedAction::SpeedLimit(0)),
            ],
            "phase {phase}s"
        );
    }
}

/// An absolute clock step backwards is not a suspend: nothing elapsed,
/// so nothing is owed.
#[test]
fn an_absolute_step_backwards_reconciles_over_an_empty_window() {
    let t = 1_789_045_200;
    assert_eq!(
        classify_tick(mow(1, 9, 0), mow(1, 8, 0), t, t - 3600),
        Tick::Reconcile { span: 0 }
    );
}

/// The Sunday/Monday boundary: a suspend across the week's own wrap is
/// an ordinary window, not a special case.
#[test]
fn a_suspend_across_the_week_boundary_reconciles_normally() {
    let t = 1_789_045_200;
    // Sunday 20:00 -> Monday 08:00.
    assert_eq!(
        classify_tick(mow(6, 20, 0), mow(0, 8, 0), t, t + 12 * 3600),
        Tick::Reconcile { span: 720 }
    );
    // Monday 07:00's resume is the most recent standing rule in it.
    assert_eq!(
        catch_up_state(&nightly(), mow(0, 8, 0), 720),
        (Some(false), Some(0))
    );
}

/// The replay ceiling is exactly `MAX_REPLAY_MINUTES`: at it the tick
/// still walks, one minute past it it reconciles.
#[test]
fn the_replay_ceiling_is_where_it_says_it_is() {
    let t = 1_789_045_200;
    let at = u64::from(MAX_REPLAY_MINUTES) * 60;
    assert_eq!(
        classify_tick(mow(0, 0, 0), mow(0, 8, 0), t, t + at),
        Tick::Advance
    );
    assert_eq!(
        classify_tick(mow(0, 0, 0), mow(0, 8, 1), t, t + at + 60),
        Tick::Reconcile {
            span: MAX_REPLAY_MINUTES + 1
        }
    );
}
