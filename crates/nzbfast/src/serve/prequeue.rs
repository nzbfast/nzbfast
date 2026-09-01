//! §129 4a: the pre-queue hook - a script consulted BEFORE an NZB
//! becomes a queued job, able to rename, recategorize, reprioritize,
//! pick a script/pp, or reject outright. The contract mirrors
//! SABnzbd's pre-queue script so switcher scripts port unchanged:
//!
//! Args: 1 job name, 2 pp the add requested (0-3, "" = none named),
//! 3 category, 4 the script the job would run (basename, "" = none),
//! 5 priority, 6 size in bytes, 7 first group.
//! Env: SAB_FILENAME, SAB_PP, SAB_CAT, SAB_SCRIPT, SAB_PRIORITY,
//! SAB_SIZE, SAB_GROUPS (space-joined), SAB_VERSION, plus
//! NZBFAST_NZO_ID and NZBFAST_ORIGIN.
//!
//! Stdout answer, up to 7 lines, a blank line keeping the default:
//! 1 accept (1 = accept, 0 = reject), 2 new name, 3 pp (0-3),
//! 4 new category, 5 script, 6 priority, 7 group (accepted and
//! logged, never stored - a job has no group field).
//!
//! Failure policy is FAIL-OPEN everywhere: no script, unlaunchable,
//! timeout (its own budget - `pre_queue_timeout_secs`, default 30 s,
//! not the post-processing hour), non-zero exit, unusable stdout -
//! the add proceeds untouched with a warning naming the script, the
//! exit status and the stderr tail. A broken hook must never cost a
//! download. A REJECT files the job to history as Failed with the
//! reason (through the same seam as dupe_action=fail: history push +
//! save_queue + history_upsert + the job.failed event); the spool
//! .nzb is kept, so retry-from-history is the escape hatch - and,
//! like SAB, a retry does not re-run the hook.

use super::*;
use script::run_capped_capture;

/// What the script answered, already validated and (for `script`)
/// resolved. `None` fields = keep the daemon's own value.
#[derive(Debug, Default, PartialEq)]
pub(in crate::serve) struct PreVerdict {
    pub accept: bool,
    pub name: Option<String>,
    pub pp: Option<i64>,
    pub category: Option<String>,
    pub script: Option<String>,
    pub priority: Option<i32>,
    pub group: Option<String>,
}

/// Parse the stdout contract. `None` = unusable (fail-open): the first
/// line must be "1", "0" or blank - a script that prints prose instead
/// of the verdict gets its add accepted and its output ignored, loudly.
pub(in crate::serve) fn parse_verdict(stdout: &str) -> Option<PreVerdict> {
    let mut lines = stdout.lines();
    let accept = match lines.next().map(str::trim) {
        None | Some("" | "1") => true,
        Some("0") => false,
        Some(_) => return None,
    };
    let mut next = || {
        lines
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let name = next();
    let pp = next().and_then(|s| s.parse::<i64>().ok().filter(|p| (0..=3).contains(p)));
    let category = next();
    let script = next();
    // SAB's integer priorities: -100 default, -2 paused, -1 low,
    // 0 normal, 1 high, 2 force. Anything else = keep.
    let priority = next().and_then(|s| {
        s.parse::<i32>()
            .ok()
            .filter(|p| matches!(p, -100 | -2 | -1 | 0 | 1 | 2))
    });
    let group = next();
    Some(PreVerdict {
        accept,
        name,
        pp,
        category,
        script,
        priority,
        group,
    })
}

impl Daemon {
    /// Consult the pre-queue script for one add, fail-open. `None` =
    /// no hook configured or the hook was unusable - proceed untouched.
    /// The caller (enqueue) applies the verdict; this runs BEFORE the
    /// add lock, so a slow script never serializes concurrent adds,
    /// and callers reach here from tokio tasks, so the wait is demoted
    /// via `blocking_db` at the call site.
    pub(in crate::serve) fn run_pre_queue(
        &self,
        nzo_id: &str,
        origin: &str,
        stem: &str,
        pp: Option<i64>,
        category: &str,
        priority: i32,
        size: u64,
        groups: &[String],
    ) -> Option<PreVerdict> {
        let script = self.pre_queue_script.lock_ok().clone()?;
        // A bare name is resolved against the configured scripts folder,
        // exactly like the name a verdict hands back on line 5 and like
        // an add's `script=`. Stored raw it went to `Command::new` as
        // written, which searches PATH only - so an installed hook named
        // by its basename simply failed to launch, and the hook then
        // fails OPEN: every add was accepted with no verdict and nothing
        // but a log line to say the gate was not running (L2, 10 Aug
        // sweep). A path-bearing value is the operator's own location
        // and stays exactly as written.
        let script = match script.file_name().map(|n| n.to_os_string()) {
            Some(name) if std::path::Path::new(&name) == script => self
                .known_scripts()
                .into_iter()
                .find(|(n, _)| std::ffi::OsStr::new(n) == name)
                .map(|(_, p)| p)
                .unwrap_or(script),
            _ => script,
        };
        // The script the job WOULD run (category ladder then global),
        // by basename - arg 4 of SAB's contract. No job exists yet, so
        // this is the ladder minus the per-job override.
        let would_run = self
            .cat_meta
            .lock_ok()
            .get(category)
            .map(|m| m.script.clone())
            .filter(|s| !s.is_empty())
            .map(|s| nzbget_script::script_chain(&s))
            .unwrap_or_else(|| self.scripts.lock_ok().clone())
            .iter()
            .filter_map(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
            .collect::<Vec<_>>()
            .join(",");
        // The pp the CALLER asked for, so a policy can branch on the
        // requested post-processing mode (SAB's contract). "" = the add
        // named none. Recording it on the job still happens after the
        // hook, and the hook's own line-3 answer still outranks it.
        let pp = pp.map(|p| p.to_string()).unwrap_or_default();
        let mut cmd = std::process::Command::new(&script);
        cmd.arg(stem) // 1 job name
            .arg(&pp) // 2 pp the add requested
            .arg(category) // 3 category
            .arg(&would_run) // 4 script
            .arg(priority.to_string()) // 5 priority
            .arg(size.to_string()) // 6 size in bytes
            .arg(groups.first().map(String::as_str).unwrap_or("")) // 7 group
            .env("SAB_FILENAME", format!("{stem}.nzb"))
            .env("SAB_PP", &pp)
            .env("SAB_CAT", category)
            .env("SAB_SCRIPT", &would_run)
            .env("SAB_PRIORITY", priority.to_string())
            .env("SAB_SIZE", size.to_string())
            .env("SAB_GROUPS", groups.join(" "))
            .env("SAB_VERSION", SAB_VERSION)
            .env("NZBFAST_NZO_ID", nzo_id)
            .env("NZBFAST_ORIGIN", origin);
        let secs = self.pre_queue_timeout.load(Ordering::Relaxed);
        let (status, stdout, stderr) = match run_capped_capture(cmd, secs) {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    target: "prequeue",
                    "{} failed to launch for {nzo_id}: {e} - accepting the add",
                    script.display()
                );
                return None;
            }
        };
        let Some(st) = status else {
            warn!(
                target: "prequeue",
                "{} still running after {secs}s for {nzo_id} - killed, and the \
                 add is accepted. Raise pre_queue_timeout_secs if it needs longer.",
                script.display()
            );
            return None;
        };
        if !st.success() {
            warn!(
                target: "prequeue",
                "{} exited {st} for {nzo_id}: {} - accepting the add",
                script.display(),
                stderr.trim()
            );
            return None;
        }
        let Some(mut v) = parse_verdict(&stdout) else {
            warn!(
                target: "prequeue",
                "{} answered something that is not the verdict contract for \
                 {nzo_id} (first line must be 1, 0 or blank) - accepting the add",
                script.display()
            );
            return None;
        };
        // Line 5 hands back a script NAME (mode=get_scripts vocabulary):
        // resolve it against the configured list, exactly like a
        // `script=` add param. A path-bearing value stays as written -
        // the operator installed the hook, the hook may name a path.
        // An unknown bare name is a logged compat note, never a broken
        // override. §192: the answer may be a CHAIN, and each link goes
        // through the same rule, so a hook can select an ordered list
        // the same way the setting does.
        if let Some(s) = v.script.take() {
            v.script = if s.eq_ignore_ascii_case("none") {
                Some(s)
            } else {
                let mut out: Vec<String> = Vec::new();
                for link in nzbget_script::script_chain(&s) {
                    let link = link.to_string_lossy().into_owned();
                    if link.contains('/') || link.contains('\\') {
                        out.push(link);
                        continue;
                    }
                    match self.known_scripts().into_iter().find(|(n, _)| *n == link) {
                        Some((_, p)) => out.push(p.to_string_lossy().into_owned()),
                        None => warn!(
                            target: "prequeue",
                            "{nzo_id}: pre-queue script named {link:?}, which is not \
                             configured on this daemon - it is dropped from the \
                             chain this add will run"
                        ),
                    }
                }
                (!out.is_empty()).then(|| out.join(","))
            };
        }
        if let Some(g) = &v.group {
            // Accepted and logged per the contract; a job has no group
            // field to store it in.
            info!(target: "prequeue", "{nzo_id}: group {g:?} noted (not stored)");
        }
        info!(
            target: "prequeue",
            "{} for {nzo_id}: {}{}{}{}{}",
            script.display(),
            if v.accept { "accept" } else { "REJECT" },
            v.name.as_deref().map(|n| format!(", rename to {n:?}")).unwrap_or_default(),
            v.category.as_deref().map(|c| format!(", category {c:?}")).unwrap_or_default(),
            v.priority.map(|p| format!(", priority {p}")).unwrap_or_default(),
            v.pp.map(|p| format!(", pp {p}")).unwrap_or_default(),
        );
        Some(v)
    }

    /// Restore the script knobs from settings.json: the post-processing
    /// deadline and the two pre-queue settings. Split out of
    /// `restore_runtime_state`, which was 514 lines on 10 Aug 2026, past
    /// the size gate's 500-line function ceiling.
    pub(in crate::serve) fn restore_script_knobs(&self, saved: &serde_json::Map<String, Value>) {
        if let Some(v) = saved.get("script_timeout_secs").and_then(Value::as_u64) {
            self.script_timeout.store(v, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("pre_queue_script").and_then(Value::as_str) {
            let p = v.trim();
            *self.pre_queue_script.lock_ok() = (!p.is_empty()).then(|| PathBuf::from(p));
        }
        if let Some(v) = saved.get("pre_queue_timeout_secs").and_then(Value::as_u64) {
            self.pre_queue_timeout.store(v, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_verdict_contract_parses() {
        // Full seven lines.
        let v = parse_verdict("1\nNew.Name\n2\ntv\nsort.py\n1\nalt.binaries.x\n").unwrap();
        assert!(v.accept);
        assert_eq!(v.name.as_deref(), Some("New.Name"));
        assert_eq!(v.pp, Some(2));
        assert_eq!(v.category.as_deref(), Some("tv"));
        assert_eq!(v.script.as_deref(), Some("sort.py"));
        assert_eq!(v.priority, Some(1));
        assert_eq!(v.group.as_deref(), Some("alt.binaries.x"));

        // Reject, nothing else said.
        let v = parse_verdict("0\n").unwrap();
        assert!(!v.accept);
        assert_eq!(v.name, None);

        // Blank lines keep defaults; a blank first line accepts.
        let v = parse_verdict("\n\n\nmovies\n").unwrap();
        assert!(v.accept);
        assert_eq!(v.category.as_deref(), Some("movies"));
        assert_eq!(v.pp, None);

        // Empty output = accept untouched (a script that says nothing).
        let v = parse_verdict("").unwrap();
        assert!(v.accept);
        assert_eq!(
            v,
            PreVerdict {
                accept: true,
                ..Default::default()
            }
        );

        // Junk verdicts are unusable, not misread: prose first line,
        // out-of-range pp and priority.
        assert!(parse_verdict("hello world\n1\n").is_none());
        let v = parse_verdict("1\n\n7\n\n\n5\n").unwrap();
        assert_eq!(v.pp, None, "pp 7 is out of range");
        assert_eq!(v.priority, None, "priority 5 is not a SAB priority");
    }
}
