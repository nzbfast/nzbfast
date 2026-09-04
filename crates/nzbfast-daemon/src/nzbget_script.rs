//! The NZBGet extension-script contract, as a shape rather than a
//! behaviour: the `NZBOP_*` option mirror, the 92/93/94/95 exit-code
//! vocabulary, the aggregate script status a chain carries between its
//! links, and the `[NZB] ` stdout command channel a link uses to tell
//! the next one what it did.
//!
//! Split out of script.rs (which is about process control: deadlines,
//! pipes, kills) because this file is about a THIRD party's contract.
//! Every constant and every name here was read off NZBGet's own source
//! rather than remembered, because a name that is nearly right is worse
//! than one that is absent: a script reading `os.environ['NZBOP_SCRIPTDIR']`
//! to decide "am I running under NZBGet" gets a KeyError and a clean
//! refusal when the variable is missing, and gets silently wrong
//! behaviour when it is present and lying.
//!
//! Sources (nzbgetcom/nzbget, develop, read 19 Aug 2026):
//! `daemon/extension/PostScript.cpp` (the codes, the env block, the
//! per-script status), `daemon/util/ScriptController.cpp`
//! (`PrepareEnvOptions` / `SetEnvVarSpecial`, i.e. the two spellings of
//! every option), `daemon/extension/NzbScript.cpp` (`ExecuteScriptList`,
//! i.e. the comma/semicolon split), `daemon/queue/DownloadInfo.cpp`
//! (`ScriptStatusList::CalcTotalStatus`).

use super::*;

/// NZBGet's post-processing exit codes, verbatim from
/// `PostScript.cpp:29-32`.
///
/// The one we do NOT copy is NZBGet's default arm: it treats every other
/// code, INCLUDING 0, as a failure. We cannot, because the same hook
/// runs SABnzbd-contract scripts, and a SAB script says "fine" with exit
/// 0. So 0 and 93 both mean success here and the divergence is
/// deliberate; everything else follows NZBGet.
pub(super) const POSTPROCESS_PARCHECK: i32 = 92;
pub(super) const POSTPROCESS_SUCCESS: i32 = 93;
pub(super) const POSTPROCESS_ERROR: i32 = 94;
pub(super) const POSTPROCESS_NONE: i32 = 95;

/// The version our NZBGet facade claims. Must match the `version` the
/// jsonrpc facade answers (sabcompat.rs), or a script that reads
/// `NZBOP_VERSION` and a script that calls `version` over the API
/// disagree about the same daemon.
pub(super) const NZBGET_VERSION: &str = "21.0";

/// What one script in a chain reported, and what the chain reports so
/// far. NZBGet spells these NONE / SUCCESS / FAILURE and passes the
/// running aggregate to each subsequent script as `NZBPP_SCRIPTSTATUS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum ScriptStatus {
    /// Ran and deliberately did nothing ("not for me"). Exit 95.
    #[default]
    None,
    Success,
    Failure,
}

impl ScriptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ScriptStatus::None => "NONE",
            ScriptStatus::Success => "SUCCESS",
            ScriptStatus::Failure => "FAILURE",
        }
    }

    /// `ScriptStatusList::CalcTotalStatus`, which is not "the last one
    /// wins" and not "the worst code": FAILURE overrides anything, and
    /// SUCCESS only upgrades a chain that is still at NONE. A chain of
    /// (SUCCESS, NONE) is therefore SUCCESS, and (SUCCESS, FAILURE) is
    /// FAILURE.
    pub fn fold(self, next: ScriptStatus) -> ScriptStatus {
        match next {
            ScriptStatus::Failure => ScriptStatus::Failure,
            ScriptStatus::Success if self == ScriptStatus::None => ScriptStatus::Success,
            _ => self,
        }
    }
}

/// What one link's exit code means, and the sentence the log should
/// carry. `already_checked` answers the one code whose meaning depends
/// on the job: 92 asks for a par-check that has not happened yet, and
/// one-pass has always already done it.
pub(super) fn analyse_exit(code: Option<i32>, already_checked: bool) -> (ScriptStatus, String) {
    match code {
        // SAB's contract, kept alongside NZBGet's (see the const block).
        Some(0) => (ScriptStatus::Success, "ok".into()),
        Some(POSTPROCESS_SUCCESS) => (ScriptStatus::Success, "ok (exit 93, nzbget success)".into()),
        Some(POSTPROCESS_NONE) => (
            ScriptStatus::None,
            "skipped (exit 95, nzbget none - the script declined this job)".into(),
        ),
        Some(POSTPROCESS_ERROR) => (
            ScriptStatus::Failure,
            "failed (exit 94, nzbget error)".into(),
        ),
        // NZBGet answers this one by asking whether par-check already
        // ran; under one-pass it always has, because verify and repair
        // happen inside the download rather than after it. So this is
        // the "already checked" arm, which NZBGet also calls a failure.
        Some(POSTPROCESS_PARCHECK) if already_checked => (
            ScriptStatus::Failure,
            "requested par-check/repair (exit 92), but one-pass verified and \
             repaired this job during the download - there is nothing left to \
             re-check"
                .into(),
        ),
        Some(POSTPROCESS_PARCHECK) => (
            ScriptStatus::Failure,
            "requested par-check/repair (exit 92), which this daemon cannot run \
             as a separate stage"
                .into(),
        ),
        Some(c) => (
            ScriptStatus::Failure,
            format!("exited {c} (not one of 0/93/94/95)"),
        ),
        // The deadline killed it. The caller has the timeout to quote.
        None => (ScriptStatus::Failure, "killed at the deadline".into()),
    }
}

/// One option of the `NZBOP_*` mirror, in NZBGet's own spelling.
///
/// The spelling matters twice over, because `SetEnvVarSpecial` exports
/// EVERY option under two names: the name exactly as NZBGet spells it
/// (`NZBOP_ControlIP`) and a normalised one, upper-cased with every
/// special character mapped to `_` (`NZBOP_CONTROLIP`). Scripts in the
/// wild read the second, but some configuration loaders walk the
/// environment looking for the first, so both are exported here too.
pub(super) type NzbOpt = (&'static str, String);

/// NZBGet's `ScriptController::SetEnvVarSpecial`: set `PREFIX_Name`, and
/// also `PREFIX_NAME` when normalising actually changes it.
pub(super) fn set_env_special(
    cmd: &mut std::process::Command,
    prefix: &str,
    name: &str,
    value: &str,
) {
    let raw = format!("{prefix}_{name}");
    let norm: String = raw
        .chars()
        .map(|c| {
            if ".:*!\"$%&/()=`+~#'{}[]@- ".contains(c) {
                '_'
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect();
    cmd.env(&raw, value);
    if norm != raw {
        cmd.env(norm, value);
    }
}

/// How much of a script's `[NZB] ` / `[ERROR] ` / `[WARNING] ` output is
/// kept. A chain link says a handful of these; a script in a loop can
/// say them forever, and the ring that holds stderr exists precisely
/// because one did.
const SIEVE_LINES: usize = 200;
/// Longest single line kept. Past this the line is dropped rather than
/// truncated: half a `[NZB] FINALDIR=` is a wrong path, not a partial
/// one.
const SIEVE_LINE_MAX: usize = 4 << 10;

/// Keeps only the stdout lines that are part of NZBGet's command
/// channel, and only [`SIEVE_LINES`] of them.
///
/// A sieve rather than the head [`super::script::SCRIPT_OUT_HEAD`] keeps
/// for the pre-queue verdict, because these lines arrive at the END of a
/// script's output: a sorter prints its whole progress log and then says
/// `[NZB] FINALDIR=...` on the last line. Keeping a head would reliably
/// miss exactly the lines this exists for.
#[derive(Default)]
pub(super) struct LineSieve {
    partial: Vec<u8>,
    pub(super) kept: Vec<String>,
    pub(super) dropped: usize,
}

impl LineSieve {
    fn interesting(line: &str) -> bool {
        let l = line.trim_start();
        l.starts_with("[NZB] ") || l.starts_with("[ERROR] ") || l.starts_with("[WARNING] ")
    }

    fn take_line(&mut self) {
        let line = String::from_utf8_lossy(&self.partial).into_owned();
        self.partial.clear();
        let line = line.trim_end_matches('\r').to_string();
        if !Self::interesting(&line) {
            return;
        }
        if self.kept.len() < SIEVE_LINES {
            self.kept.push(line);
        } else {
            self.dropped += 1;
        }
    }

    pub(super) fn push(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                self.take_line();
            } else if self.partial.len() < SIEVE_LINE_MAX {
                self.partial.push(b);
            } else {
                // Overlong: keep eating to the newline, but poison the
                // buffer so `take_line` cannot match a prefix.
                self.partial.clear();
                self.partial.push(b'\0');
            }
        }
    }

    /// A last line with no trailing newline still counts: a script that
    /// ends with `print("[NZB] FINALDIR=...", end="")` is unusual but
    /// not wrong.
    pub(super) fn finish(&mut self) {
        if !self.partial.is_empty() {
            self.take_line();
        }
    }
}

/// What a chain link told the daemon on its stdout, parsed.
///
/// NZBGet's channel is wider than this (`[NZB] MARK=BAD`, and the log
/// kinds that route into its own log). What is honoured here is what the
/// NEXT link in the chain needs to see, which is the whole point of an
/// ordered list: where the payload ended up, and any parameters the
/// earlier script set. Everything else is logged and otherwise ignored,
/// which is better than pretending: see the TODO note under §192.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct NzbCommands {
    /// `[NZB] FINALDIR=<path>` - where this script left the payload.
    pub(super) final_dir: Option<String>,
    /// `[NZB] DIRECTORY=<path>` - NZBGet's older spelling of the same
    /// idea, still emitted by scripts written against v13.
    pub(super) directory: Option<String>,
    /// `[NZB] NZBPR_<name>=<value>` - a post-processing parameter for
    /// every LATER script in the chain.
    pub(super) params: Vec<(String, String)>,
    /// `[NZB] MARK=BAD` - recognised so it can be reported rather than
    /// read as an unknown command. Not acted on (see the struct doc).
    pub(super) mark_bad: bool,
    /// Lines that named a command we do not implement, kept for one log
    /// line so "my script said X and nothing happened" is answerable.
    pub(super) unknown: Vec<String>,
    /// `[ERROR] ` / `[WARNING] ` lines, which NZBGet routes into its own
    /// log. Ours go into the daemon log at the matching level, because a
    /// script that explains its own failure and is never quoted is a
    /// script the operator has to re-run by hand to debug.
    pub(super) messages: Vec<String>,
}

impl NzbCommands {
    pub fn parse(lines: &[String]) -> Self {
        let mut out = NzbCommands::default();
        for line in lines {
            let l = line.trim_start();
            let Some(body) = l.strip_prefix("[NZB] ") else {
                out.messages.push(l.to_string());
                continue;
            };
            let body = body.trim();
            let Some((k, v)) = body.split_once('=') else {
                out.unknown.push(body.to_string());
                continue;
            };
            let (k, v) = (k.trim(), v.trim());
            // NZBGet compares these case-sensitively; so do we, so a
            // script that works there works here and one that does not
            // fails the same way in both.
            match k {
                "FINALDIR" => out.final_dir = Some(v.to_string()),
                "DIRECTORY" => out.directory = Some(v.to_string()),
                "MARK" if v.eq_ignore_ascii_case("BAD") => out.mark_bad = true,
                _ => match k.strip_prefix("NZBPR_") {
                    Some(name) if !name.is_empty() => {
                        out.params.push((name.to_string(), v.to_string()));
                    }
                    _ => out.unknown.push(body.to_string()),
                },
            }
        }
        out
    }
}

/// Split a script SETTING into the ordered chain it names.
///
/// NZBGet's `ExecuteScriptList` tokenises on `,` and `;`, so both work
/// here. Empty entries and an entry spelled `None` are dropped rather
/// than run: `None` is SAB's null choice, and a user who edits a chain
/// down to nothing should get no script, not a daemon trying to execute
/// a file called None.
///
/// Order is the LIST's, which is a deliberate divergence worth stating.
/// NZBGet iterates its installed-extension catalogue and asks of each
/// "is this one in the list", so the order a user actually gets is the
/// catalogue's (which is why NZBGet extensions are conventionally named
/// with numeric prefixes, and why `ScriptOrder` exists at all). We have
/// no catalogue - a script here is a path, not an installed extension -
/// so the only order we could honour is the one the user typed, and it
/// is also the one they expect.
pub fn script_chain(raw: &str) -> Vec<PathBuf> {
    raw.split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("none"))
        .map(PathBuf::from)
        .collect()
}

/// The chain as a setting value: what `script` reads back as, and what
/// the SAB facade publishes for a job.
pub(super) fn chain_str(chain: &[PathBuf]) -> String {
    chain
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(",")
}

impl Daemon {
    // §192: which script(s) a job runs. Moved here from daemon.rs with
    // the chain work - the ladder, the basename catalogue and the
    // add-param resolution are all one question ("what will run for
    // this job"), and daemon.rs was over its size-gate baseline.

    /// §129 2b follow-up: every script this daemon can actually run for
    /// a job - the global setting plus each category's own - keyed by
    /// the BASENAME clients name them by. `mode=get_scripts` serves
    /// these names, and `script=` on an add sends one back, so the two
    /// must resolve through one list or the round trip breaks (it did:
    /// the name came back and was run as a cwd-relative path). First
    /// entry wins a basename tie, global first.
    pub fn known_scripts(&self) -> Vec<(String, PathBuf)> {
        let mut out: Vec<(String, PathBuf)> = Vec::new();
        let mut push = |p: &std::path::Path| {
            if let Some(name) = p.file_name().map(|s| s.to_string_lossy().into_owned())
                && !out.iter().any(|(n, _)| *n == name)
            {
                out.push((name, p.to_path_buf()));
            }
        };
        for g in self.scripts.lock_ok().iter() {
            push(g);
        }
        for m in self.cat_meta.lock_ok().values() {
            // §192: a category's script setting is a CHAIN too, so each
            // of its links has to reach this list - otherwise
            // `mode=get_scripts` offers a name that resolve cannot find
            // and a client's round trip breaks on the second link.
            for p in script_chain(&m.script) {
                push(&p);
            }
        }
        out
    }

    /// §129 2b: which scripts this job runs, in order. Resolution order
    /// is the LADDER - the job's own `script=` param ("None" =
    /// explicitly none), the category's script, the global setting -
    /// and the first rung that has anything wins WHOLE. A category
    /// chain does not append to the global one: a rung is an answer to
    /// "what runs for this job", not a fragment of one, and merging
    /// them would make it impossible to say "this category runs nothing
    /// but its own sorter".
    ///
    /// Each rung's value is itself a comma-separated chain (§192), so
    /// the answer is a list. Empty = no script.
    pub fn resolve_scripts(&self, job: &Arc<Mutex<Job>>) -> Vec<PathBuf> {
        let (over, cat) = {
            let g = job.lock_ok();
            (g.script_override.clone(), g.category.clone())
        };
        if over.eq_ignore_ascii_case("none") {
            return Vec::new();
        }
        if !over.is_empty() {
            return script_chain(&over);
        }
        let cs = self
            .cat_meta
            .lock_ok()
            .get(&cat)
            .map(|m| m.script.clone())
            .unwrap_or_default();
        if !cs.trim().is_empty() {
            return script_chain(&cs);
        }
        self.scripts.lock_ok().clone()
    }

    /// §129 2b: record the SAB add params the API used to accept and
    /// silently drop (`pp=`, `script=`), and log the compatibility
    /// mapping for the ones one-pass cannot honor literally - never
    /// silently ignore (decision 5).
    ///
    /// `add_only` is true when the request authenticated with the
    /// add-only NZB key rather than the full API key. That credential is
    /// handed to browser push extensions by design, so it must not be
    /// able to choose which program the daemon runs.
    pub fn record_add_params(
        &self,
        nzo_id: &str,
        pp: Option<&str>,
        script: Option<&str>,
        add_only: bool,
    ) {
        let pp = sab_pp_param(pp);
        let script = script
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            // A bare name is what SAB clients send back from
            // mode=get_scripts, so it must resolve against the same
            // list that answer came from - stored verbatim it became a
            // cwd-relative path that ran nothing. A value with a path
            // separator is an operator-typed location and stays as
            // written; "none" is SAB's own null and suppresses the
            // category/global ladder in resolve_scripts.
            //
            // §192: the value may be a CHAIN, so every link goes
            // through the same rule. A chain that names one path is a
            // path-bearing value, which is why the add-only refusal
            // below drops the WHOLE parameter rather than the offending
            // link: silently running two of the three scripts the
            // caller asked for is a worse answer than running the
            // category's.
            .and_then(|s| {
                if s.eq_ignore_ascii_case("none") {
                    return Some(s);
                }
                let mut out: Vec<String> = Vec::new();
                for link in script_chain(&s) {
                    let link = link.to_string_lossy().into_owned();
                    if link.contains('/') || link.contains('\\') {
                        // An operator-typed absolute location, stored as
                        // written - but ONLY for a full-key caller.
                        // `addfile`/`addurl` are on the add-only
                        // allowlist, so without this test the NZB key
                        // reached `Command::new`: `resolve_scripts`
                        // returns `script_override` verbatim and the job
                        // tail executes it. That is the same escalation
                        // `m_config`'s bootstrap check already refuses
                        // ("an add-only credential escalating to
                        // arbitrary config, and from there to code
                        // execution, because `script` is run on the job
                        // tail and `addfile` is itself add-only") - this
                        // was the door left open beside it. The
                        // bare-name form below is safe for either
                        // caller: it resolves against the configured
                        // list and cannot name anything the operator has
                        // not already installed.
                        if add_only {
                            warn!(
                                target: "queue",
                                "{nzo_id}: ignoring script={s:?} - a path may only be \
                                 set with the full API key, and this add came in on \
                                 the add-only NZB key (name a configured script \
                                 instead, or set it on the category)"
                            );
                            return None;
                        }
                        out.push(link);
                        continue;
                    }
                    match self.known_scripts().into_iter().find(|(n, _)| *n == link) {
                        Some((_, p)) => out.push(p.to_string_lossy().into_owned()),
                        None => warn!(
                            target: "queue",
                            "{nzo_id}: script {link:?} is not configured on this \
                             daemon - it is dropped from this job's chain (set the \
                             script globally or on the category to use it)"
                        ),
                    }
                }
                (!out.is_empty()).then(|| out.join(","))
            });
        if pp.is_none() && script.is_none() {
            return;
        }
        // The queue first, then history: an add can be answered with an
        // id that never reached the queue at all - a pre-queue REJECT
        // and dupe_action="fail" both file the job straight to history -
        // and searching only the queue dropped the caller's pp/script on
        // exactly those two paths. The record is the one a History retry
        // brings back, so the params have to be on it or the retry runs
        // with different post-processing than the add asked for (M15,
        // 10 Aug sweep).
        let queued = self
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == nzo_id)
            .cloned();
        let parked = queued.is_none();
        let Some(job) = queued.or_else(|| {
            self.history
                .lock_ok()
                .iter()
                .find(|j| j.lock_ok().nzo_id == nzo_id)
                .cloned()
        }) else {
            return;
        };
        {
            let mut g = job.lock_ok();
            // §129 4a: fill, never clobber. At construction these are
            // empty unless the pre-queue hook set them, and the hook's
            // answer outranks the request's params (SAB semantics: the
            // pre-queue output overrides the add).
            let pp = pp.filter(|_| g.sab_pp.is_none());
            let script = script.filter(|_| g.script_override.is_empty());
            if let Some(p) = pp {
                g.sab_pp = Some(p);
                if p <= 1 {
                    info!(
                        target: "queue",
                        "{nzo_id}: pp={p} requested - repair and unpack are integral \
                         to the one-pass download, so the request is recorded and \
                         shown on the job, and the download runs normally"
                    );
                }
            }
            if let Some(s) = script {
                g.script_override = s.clone();
                info!(target: "queue", "{nzo_id}: script={s} for this job");
            }
        }
        if parked {
            // A history record persists through its own store, and it
            // is already filed - so this is the seam that has to see it.
            // `history_publish_change` rather than a `let _ =` upsert:
            // the answer was dropped, so a store that refused the append
            // left the script's pp/script override live in memory and
            // absent from disk, and the hook's whole contract is that its
            // answer OUTRANKS the request's params. The rescue files it
            // anyway on the commonest refusal there is, and where it
            // cannot the loss is exactly what this helper's sentence
            // says: the change goes back at the next start.
            self.history_publish_change(&job, "the post-processing script's request");
        } else {
            self.save_queue();
        }
    }
}

impl Daemon {
    /// The `NZBOP_*` mirror: NZBGet exports EVERY configuration option
    /// into a script's environment, and real scripts read a small,
    /// stable subset of it. This is that subset, mapped onto what this
    /// daemon actually has, in NZBGet's own spelling.
    ///
    /// Two of these carry more weight than the rest:
    ///
    ///  - `ScriptDir` is the near-universal "am I running under NZBGet"
    ///    gate. The idiom at the top of nzbToMedia, VideoSort and most
    ///    of the forum catalogue is `if 'NZBOP_SCRIPTDIR' not in
    ///    os.environ: sys.exit(POSTPROCESS_ERROR)`, so a chain that
    ///    exports everything else and not this one runs nothing at all.
    ///  - `ControlIP` is reported as `127.0.0.1` rather than the address
    ///    we bind. NZBGet's own default is `0.0.0.0`, which is a bind
    ///    wildcard and not a destination, and the scripts that use it to
    ///    build a callback URL all special-case it back to localhost. A
    ///    post-processing script runs on this host by definition, so
    ///    loopback is both the correct answer and the one that needs no
    ///    special case.
    ///
    /// Values we have no equivalent for are exported EMPTY rather than
    /// omitted. A missing key is a `KeyError` in Python; an empty one
    /// reads as "not configured", which is the truth.
    pub(super) fn nzbop_options(&self) -> Vec<NzbOpt> {
        let path = |p: Option<PathBuf>| {
            p.map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        let dest = crate::naming::out_dir(self);
        let exe = std::env::current_exe().ok();
        let cfg = self.settings_path.clone();
        // The folder the configured scripts live in, which is what
        // `mode=get_scripts` and the folder-open button already treat as
        // the script directory (api/system.rs).
        let script_dir = self
            .scripts
            .lock_ok()
            .first()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .filter(|d| !d.as_os_str().is_empty());
        vec![
            ("AppBin", path(exe.clone())),
            (
                "AppDir",
                path(exe.and_then(|p| p.parent().map(PathBuf::from))),
            ),
            ("Version", NZBGET_VERSION.to_string()),
            ("ConfigFile", cfg.to_string_lossy().into_owned()),
            ("MainDir", path(cfg.parent().map(PathBuf::from))),
            ("QueueDir", path(cfg.parent().map(PathBuf::from))),
            ("DestDir", dest.to_string_lossy().into_owned()),
            // One-pass writes decoded payload straight into the
            // destination, so there IS no intermediate directory. Empty
            // is NZBGet's own spelling of "not configured", and a script
            // that moves files out of InterDir must be told that rather
            // than handed DestDir under a second name.
            ("InterDir", String::new()),
            ("TempDir", path(Some(std::env::temp_dir()))),
            ("NzbDir", path(self.watch_dir.lock_ok().clone())),
            ("ScriptDir", path(script_dir)),
            ("WebDir", String::new()),
            ("LockFile", String::new()),
            ("LogFile", String::new()),
            ("ControlIP", "127.0.0.1".to_string()),
            ("ControlPort", self.port.to_string()),
            // NZBGet authenticates the RPC with a username/password
            // pair; ours is one API key, and the facade accepts it as
            // the password. The username is NZBGet's own default, so a
            // script that hardcodes it still authenticates.
            ("ControlUsername", "nzbget".to_string()),
            (
                "ControlPassword",
                self.apikey.lock_ok().clone().unwrap_or_default(),
            ),
            ("SecureControl", yes_no(self.tls_cert.is_some())),
            (
                "SecurePort",
                if self.tls_cert.is_some() {
                    self.port.to_string()
                } else {
                    "0".to_string()
                },
            ),
            // Behaviour options, answered for the one-pass engine. Par
            // check and repair are integral and cannot be turned off, so
            // the honest answer to both is "always" / "yes"; unpack the
            // same.
            ("ParCheck", "always".to_string()),
            ("ParRepair", "yes".to_string()),
            ("Unpack", "yes".to_string()),
            ("HealthCheck", "none".to_string()),
            ("DupeCheck", yes_no(true)),
            (
                "KeepHistory",
                // The same literal the NZBGet facade reports, and for
                // the same reason: we keep history forever, NZBGet
                // spells that 0, and the *arrs refuse a client that
                // says 0. See the `config` handler.
                "7".to_string(),
            ),
            (
                "DownloadRate",
                // NZBGet reports this in bytes/sec, as we store it.
                self.speed_ceiling.load(Ordering::Relaxed).to_string(),
            ),
        ]
    }
}

fn yes_no(b: bool) -> String {
    if b { "yes" } else { "no" }.to_string()
}

#[cfg(test)]
#[path = "nzbget_script_tests.rs"]
mod nzbget_script_tests;
