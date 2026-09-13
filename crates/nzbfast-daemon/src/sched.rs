//! M14g: the time-of-week scheduler - schedule parsing, the effective
//! pause/speed state for a given minute, and the offline-pause claim.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

// ---------------------------------------------------------------------------
// M14g: time-of-week scheduler (parse_size lives with the other guards
// near ServeOpts)
// ---------------------------------------------------------------------------

pub const WEEK_MINUTES: u32 = 7 * 24 * 60;

#[derive(Debug, Clone, PartialEq)]
pub enum SchedAction {
    Pause,
    Resume,
    SpeedLimit(u64),
    /// §129 2g: enable or disable one server (named by host) at the
    /// scheduled minute - the classic "block account B during peak
    /// hours" setup. An EDGE action: it fires at its minute and edits
    /// the config exactly as the settings toggle does, so
    /// [`effective_state`] deliberately ignores it (replaying a week of
    /// config edits at startup would fight the user's own toggles).
    ServerEnable {
        host: String,
        on: bool,
    },
    /// §129 2g: zero the quota ledger at the scheduled minute, for
    /// providers whose billing window is not a civil day/week/month.
    /// Edge action, same reasoning as above.
    QuotaReset,
}

#[derive(Debug, Clone)]
pub struct SchedEntry {
    /// Mon=0 .. Sun=6.
    pub days: [bool; 7],
    /// Minutes after midnight, in the machine's LOCAL timezone - this
    /// said UTC until 10 Sep 2026 and was never true on a Unix host,
    /// where `local_minute_of_week` has always been what it is compared
    /// against. It WAS true on Windows, by accident, and that accident
    /// is F2.
    pub minute: u32,
    pub action: SchedAction,
}

impl SchedEntry {
    /// Does this entry fire at exactly minute-of-week `mow`?
    pub fn fires_at(&self, mow: u32) -> bool {
        self.days[(mow / 1440) as usize] && self.minute == mow % 1440
    }
}

// `utc_minute_of_week` was here until 10 Sep 2026. It existed only as
// `local_minute_of_week`'s fallback, and the fallback moved down with
// the rest of the platform reading - `nzbfast_core::localtime` is where
// the UTC arm lives now, and where its tests are. `dead_code` is part of
// clippy's `-D warnings` gate, so leaving the wrapper standing was not
// an option; the shape it had is `localtime::utc_civil(secs).minute_of_week()`.

/// Minute-of-week (0 = Monday 00:00) in the machine's LOCAL timezone -
/// people schedule around their own nights, not UTC's. Falls back to UTC
/// where localtime isn't available.
///
/// The platform reading is `nzbfast_core::localtime`, shared with the
/// quota ledger's local midnight. It used to be a `#[cfg(unix)]` block
/// right here with NO Windows arm behind it, so every Windows build ran
/// its weekly schedule on UTC while the dashboard and the manual both
/// promised local time. Do not re-inline it: the two sites are only
/// guaranteed to agree while there is one of them.
pub fn local_minute_of_week() -> u32 {
    localtime::local_or_utc_civil().minute_of_week()
}

/// "mon-fri", "sat,sun", "all", or any comma list of names/ranges
/// ("mon,wed-fri"). Ranges may wrap ("sat-mon").
pub(super) fn parse_days(s: &str) -> Option<[bool; 7]> {
    const NAMES: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    let day = |n: &str| {
        NAMES
            .iter()
            .position(|x| *x == n.trim().to_ascii_lowercase())
    };
    let mut out = [false; 7];
    if s.trim().eq_ignore_ascii_case("all") {
        return Some([true; 7]);
    }
    for part in s.split(',') {
        match part.split_once('-') {
            Some((a, b)) => {
                let (mut i, j) = (day(a)?, day(b)?);
                loop {
                    out[i] = true;
                    if i == j {
                        break;
                    }
                    i = (i + 1) % 7;
                }
            }
            None => out[day(part)?] = true,
        }
    }
    Some(out)
}

/// Parse a schedule file: a JSON array of
/// `{"days": "mon-fri", "time": "23:30", "action": "pause"|"resume"|
///   "speedlimit", "value": "4M"}` (value only for speedlimit; sizes as
/// per `parse_size`, or a bare JSON number of bytes/sec).
pub fn parse_schedule(json: &str) -> Result<Vec<SchedEntry>> {
    let v: Value = serde_json::from_str(json)?;
    let arr = v
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("schedule must be a JSON array"))?;
    arr.iter()
        .enumerate()
        .map(|(i, e)| {
            let bad = |what: &str| anyhow::anyhow!("entry {i}: {what}");
            let days = parse_days(e.get("days").and_then(Value::as_str).unwrap_or("all"))
                .ok_or_else(|| bad("bad days"))?;
            let time = e
                .get("time")
                .and_then(Value::as_str)
                .ok_or_else(|| bad("missing time"))?;
            let (h, m) = time
                .split_once(':')
                .ok_or_else(|| bad("time must be HH:MM"))?;
            let (h, m): (u32, u32) = (
                h.parse().map_err(|_| bad("bad hour"))?,
                m.parse().map_err(|_| bad("bad minute"))?,
            );
            if h >= 24 || m >= 60 {
                return Err(bad("time out of range"));
            }
            let action = match e.get("action").and_then(Value::as_str) {
                Some("pause") => SchedAction::Pause,
                Some("resume") => SchedAction::Resume,
                Some("speedlimit") => {
                    let val = e
                        .get("value")
                        .ok_or_else(|| bad("speedlimit needs value"))?;
                    let bps = match val {
                        Value::Number(n) => n.as_u64(),
                        Value::String(s) => parse_size(s),
                        _ => None,
                    }
                    .ok_or_else(|| bad("bad speedlimit value"))?;
                    SchedAction::SpeedLimit(bps)
                }
                Some(a @ ("server_enable" | "server_disable")) => {
                    let host = e
                        .get("value")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|h| !h.is_empty())
                        .ok_or_else(|| bad("server_enable/disable needs value = the server's host"))?;
                    SchedAction::ServerEnable {
                        host: host.to_string(),
                        on: a == "server_enable",
                    }
                }
                Some("quota_reset") => SchedAction::QuotaReset,
                _ => {
                    return Err(bad(
                        "action must be pause|resume|speedlimit|server_enable|server_disable|quota_reset",
                    ));
                }
            };
            Ok(SchedEntry {
                days,
                minute: h * 60 + m,
                action,
            })
        })
        .collect()
}

/// Which state is currently in effect, given `now` as a minute-of-week:
/// for each kind (paused-ness, speedlimit) the most recent occurrence
/// at-or-before `now` within the past week wins; an exact tie in time goes
/// to the later entry in the file. None = no entry of that kind has fired.
/// Pure - `now` is injected, never read from the clock here.
pub fn effective_state(entries: &[SchedEntry], now: u32) -> (Option<bool>, Option<u64>) {
    // A whole week IS the "everything that ever fires" window, so this
    // is `catch_up_state` and not a second copy of its loop.
    catch_up_state(entries, now, WEEK_MINUTES)
}

/// The standing state implied by the last `span` minutes ending at `now`
/// - i.e. by the window `(now - span, now]` of minutes-of-week.
///
/// The same "most recent wins, a tie goes to the later entry" rule as
/// [`effective_state`], but bounded: `None` for a component means no
/// rule of that kind fired INSIDE the window, and the daemon's current
/// value for it must be left exactly as it is. That bound is the whole
/// point. Reconciling a wake-up against the unbounded state would reach
/// back a week and undo a manual pause the user made days before the
/// machine went to sleep; reconciling against the window replays only
/// what the sleeping daemon actually missed.
///
/// `span == 0` fires nothing: no time passed, so nothing was missed.
/// `span >= WEEK_MINUTES` is [`effective_state`] exactly.
///
/// Edge actions (`ServerEnable`, `QuotaReset`) are ignored here for the
/// same reason [`effective_state`] ignores them: they are one-shots, and
/// replaying a night of config edits at wake-up would be a worse bug
/// than the one this fixes. Pure - `now` is injected.
pub fn catch_up_state(entries: &[SchedEntry], now: u32, span: u32) -> (Option<bool>, Option<u64>) {
    let mut paused: Option<(u32, bool)> = None; // (distance back, state)
    let mut limit: Option<(u32, u64)> = None;
    for e in entries {
        for (d, on) in e.days.iter().enumerate() {
            if !on {
                continue;
            }
            let mow = d as u32 * 1440 + e.minute;
            let dist = (now + WEEK_MINUTES - mow) % WEEK_MINUTES;
            // `dist == 0` is a rule firing at `now` itself, which the
            // window includes; `dist == span` is the minute BEFORE it
            // opened, which it does not.
            if dist >= span {
                continue;
            }
            match e.action {
                SchedAction::Pause | SchedAction::Resume => {
                    if paused.is_none_or(|(best, _)| dist <= best) {
                        paused = Some((dist, e.action == SchedAction::Pause));
                    }
                }
                SchedAction::SpeedLimit(v) => {
                    if limit.is_none_or(|(best, _)| dist <= best) {
                        limit = Some((dist, v));
                    }
                }
                // Edge actions carry no standing state to reconstruct.
                SchedAction::ServerEnable { .. } | SchedAction::QuotaReset => {}
            }
        }
    }
    (paused.map(|(_, p)| p), limit.map(|(_, v)| v))
}

/// The longest gap the scheduler will walk minute by minute, firing
/// every rule in it including the one-shots. Past this the wake-up is
/// reconciled instead - see [`classify_tick`].
pub const MAX_REPLAY_MINUTES: u32 = 8 * 60;

/// `forward` and `elapsed` are integer minutes read from two different
/// clocks half a minute apart, so the local one may legitimately lead by
/// a minute or so. Anything past this is a real discontinuity.
const TICK_SLACK_MINUTES: u64 = 5;

/// What one scheduler tick should do, given where the cursor was and
/// what both clocks now say. Pure; the loop in `tasks::spawn_scheduler`
/// is nothing but this plus the two effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// Ordinary catch-up: walk every minute in `(last, now]` and fire
    /// each entry that matches, one-shots included.
    Advance,
    /// The local clock did not advance the way real time did, or so much
    /// real time passed that walking it would replay a backlog. Move the
    /// cursor to `now` and reconcile the STANDING state implied by the
    /// last `span` minutes - `catch_up_state(entries, now, span)` - so
    /// nothing one-shot is replayed.
    Reconcile { span: u32 },
}

/// Classify a tick from the local minute-of-week cursor AND the absolute
/// clock.
///
/// The absolute clock is the load-bearing half. The guard this replaces
/// looked only at the modular local distance and read any gap over eight
/// hours as a backwards clock step, so an ordinary overnight suspend was
/// discarded whole: a schedule that paused at 20:00 and resumed at 07:00
/// left the queue paused all of the next day, and an old speed limit
/// stayed applied the same way. A minute-of-week difference genuinely
/// cannot tell the two apart - unix seconds can, because a DST step does
/// not move them.
///
/// The three ways a tick is NOT an ordinary advance:
///
/// * the absolute clock went backwards - a real clock step, and nothing
///   elapsed to replay (`span` is 0);
/// * more than [`MAX_REPLAY_MINUTES`] of real time passed - a suspend,
///   or a daemon that lost its scheduler thread to a stall;
/// * local time ran further forward than real time did - a DST spring
///   forward (+1h in a minute) or a fall back, which shows up as a
///   `forward` of nearly a whole week.
pub fn classify_tick(last: u32, now: u32, last_utc: u64, now_utc: u64) -> Tick {
    let elapsed = now_utc.saturating_sub(last_utc) / 60;
    let forward = u64::from((now + WEEK_MINUTES - last) % WEEK_MINUTES);
    if now_utc < last_utc
        || elapsed > u64::from(MAX_REPLAY_MINUTES)
        || forward > elapsed + TICK_SLACK_MINUTES
    {
        // The window is measured in REAL minutes, capped at a week:
        // past that every rule has fired at least once and the bounded
        // window is the unbounded state anyway.
        return Tick::Reconcile {
            span: elapsed.min(u64::from(WEEK_MINUTES)) as u32,
        };
    }
    Tick::Advance
}

/// Minutes from `now` (a minute-of-week) until the schedule's next
/// Resume entry fires, or `None` when the schedule never resumes.
///
/// The header promises a time only when there is one: a schedule that
/// pauses and never resumes leaves the queue held until someone acts,
/// and inventing "until 08:00" out of the nearest entry of any kind
/// would be a promise the daemon cannot keep. Pure - `now` is injected,
/// exactly like [`effective_state`].
pub fn next_resume_in(entries: &[SchedEntry], now: u32) -> Option<u32> {
    entries
        .iter()
        .filter(|e| e.action == SchedAction::Resume)
        .flat_map(|e| {
            e.days
                .iter()
                .enumerate()
                .filter(|(_, on)| **on)
                .map(move |(day, _)| {
                    let mow = day as u32 * 1440 + e.minute;
                    match (mow + WEEK_MINUTES - now) % WEEK_MINUTES {
                        // Fires this very minute - which is not a
                        // future time. The next one is a week out.
                        0 => WEEK_MINUTES,
                        forward => forward,
                    }
                })
        })
        .min()
}

pub fn apply_action(d: &Arc<Daemon>, a: SchedAction) {
    match a {
        SchedAction::Pause | SchedAction::Resume => {
            // A schedule entry is a LATER decision about this hour than
            // any timer armed before it, so it cancels the pending
            // auto-resume exactly as a manual pause or resume does.
            // Without the bump the older sleeper stayed authoritative:
            // "pause for 60 minutes" at 21:30 un-paused the queue at
            // 22:30, inside a 22:00 scheduled off window.
            let pause = a == SchedAction::Pause;
            set_paused_cancel_timer(d, pause);
            // Claim it, so the header can say who decided and until when
            // instead of showing the same word a deliberate pause gets.
            *d.pause_source.lock_ok() = "schedule";
            if pause {
                d.suspend_active(true); // scheduled pause winds down gracefully
            }
        }
        SchedAction::SpeedLimit(v) => d.set_speed_ceiling_from(v, "schedule"),
        SchedAction::ServerEnable { host, on } => {
            // The same edit the settings toggle makes (m_server_enable),
            // keyed by host rather than list index - a schedule outlives
            // reorders and deletions, and a host is what the user can
            // read back in the rule. Applies to the next job/reconnect,
            // exactly like the toggle.
            let _cfg = crate::setup::config_write_lock();
            let mut servers = super::servers::current_servers(&d.cfg_path);
            let Some(s) = servers.iter_mut().find(|s| {
                s.get("host")
                    .and_then(Value::as_str)
                    .is_some_and(|h| h.eq_ignore_ascii_case(&host))
            }) else {
                warn!(
                    target: "schedule",
                    "no server with host {host:?} - the rule did nothing; \
                     check the schedule against your server list"
                );
                return;
            };
            if let Some(o) = s.as_object_mut() {
                if on {
                    o.remove("enabled"); // default; keeps the file clean
                } else {
                    o.insert("enabled".into(), json!(false));
                }
            }
            match crate::setup::write_servers(&d.cfg_path, &servers) {
                Ok(()) => info!(
                    target: "schedule",
                    "{host} {}",
                    if on { "enabled" } else { "disabled" }
                ),
                Err(e) => warn!(target: "schedule", "could not update {host}: {e}"),
            }
        }
        SchedAction::QuotaReset => {
            // The ledger lives in the download runner; hand it the
            // request rather than racing it for the file.
            d.quota_reset.store(true, Ordering::Relaxed);
            info!(target: "schedule", "quota reset requested");
        }
    }
}

/// The queue-pause side of an offline transition, as pure state.
///
/// Returns `(paused, paused_by_offline)`.
///
/// Going offline pauses, because the alternative is spending the outage
/// starting jobs that cannot connect: every one of them would fail
/// against articles that were never missing, and the operator would come
/// back to a queue full of red that says nothing about what happened.
///
/// Coming back online unpauses only what THIS mechanism paused. An
/// operator who had already paused by hand, then went offline, then came
/// back online, must still be paused - resuming their download for them
/// is not something going online was asked to do.
pub fn offline_pause_transition(
    going_offline: bool,
    paused: bool,
    paused_by_offline: bool,
) -> (bool, bool) {
    match going_offline {
        // Claim the pause only if the queue was actually running.
        true => (true, !paused),
        // Release it only if it was ours; either way the claim is spent.
        false => (paused && !paused_by_offline, false),
    }
}

#[cfg(test)]
#[path = "sched_tests.rs"]
mod sched_tests;
