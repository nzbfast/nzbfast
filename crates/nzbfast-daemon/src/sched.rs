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
    /// Minutes after midnight (UTC).
    pub minute: u32,
    pub action: SchedAction,
}

impl SchedEntry {
    /// Does this entry fire at exactly minute-of-week `mow`?
    pub fn fires_at(&self, mow: u32) -> bool {
        self.days[(mow / 1440) as usize] && self.minute == mow % 1440
    }
}

/// Current UTC time as a minute-of-week (Mon 00:00 = 0 .. Sun 23:59 = 10079).
pub(super) fn utc_minute_of_week() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let day = ((secs / 86_400 + 3) % 7) as u32; // epoch day 0 was a Thursday
    day * 1440 + (secs % 86_400 / 60) as u32
}

/// Minute-of-week (0 = Monday 00:00) in the machine's LOCAL timezone -
/// people schedule around their own nights, not UTC's. Falls back to UTC
/// where localtime isn't available.
pub fn local_minute_of_week() -> u32 {
    #[cfg(unix)]
    {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as libc::time_t;
        // SAFETY: `libc::tm` is a plain C struct of integers and a
        // pointer; all-zero is a valid bit pattern, and localtime_r
        // overwrites it before anything is read.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: both pointers are live locals of the expected types,
        // and the exclusive borrow rules out overlap.
        if !unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
            let day = (tm.tm_wday as u32 + 6) % 7; // tm_wday: 0 = Sunday
            return day * 1440 + tm.tm_hour as u32 * 60 + tm.tm_min as u32;
        }
    }
    utc_minute_of_week()
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
    let mut paused: Option<(u32, bool)> = None; // (distance back, state)
    let mut limit: Option<(u32, u64)> = None;
    for e in entries {
        for (d, on) in e.days.iter().enumerate() {
            if !on {
                continue;
            }
            let mow = d as u32 * 1440 + e.minute;
            let dist = (now + WEEK_MINUTES - mow) % WEEK_MINUTES;
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
