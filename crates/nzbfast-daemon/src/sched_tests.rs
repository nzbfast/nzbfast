use super::{SchedAction, effective_state, next_resume_in, parse_days, parse_schedule};
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
