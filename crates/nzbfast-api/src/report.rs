//! "Create report": everything about ONE download, as text a user can
//! paste into a bug report.
//!
//! The design, in one clause: everything pertinent about a problematic
//! download - its log lines, the providers used, the timestamps -
//! shareable without handing over the entire log of the last N days. `mode=log` already hands over
//! the ring, and the ring is the daemon's, not the job's - so answering
//! "what happened to THIS download" meant sending thousands of lines
//! belonging to everything else, and the person reading it then had to
//! find the job in them. Every job now brackets its own output
//! (`Job::log_mark` / `log_end`) and this slices exactly that span.
//!
//! ## What is deliberately NOT in it
//!
//! The report exists to be shared, so it is assembled from a fixed list
//! of fields rather than by dumping the record: nothing new that lands
//! on `Job` can leak through it by default. On top of that,
//! [`scrub`] rewrites the two things that DO travel with paths and log
//! lines - the user's home directory, and anything shaped like a
//! credential in a URL - and the NZB is summarised rather than quoted,
//! with its `password` meta redacted.
//!
//! Server hostnames ARE included. That is a departure from
//! `diag::print_failure_diagnostics`, which anonymises them because it
//! writes to a log that gets pasted wholesale - here the user is
//! deliberately assembling a report, "which provider failed" is the
//! question they most often need answered, and a provider's hostname is
//! public. Their USERNAME and password are never read by this file.

use super::*;

/// Log lines a report may carry. Two thousand is the ring's whole
/// depth, so this only ever binds when one job printed more than the
/// ring holds - in which case the tail is the half worth keeping.
const REPORT_LOG_LINES: usize = 400;

/// NZB `<meta>` keys quoted in full. Everything else is named and its
/// value withheld - see the note where this is read.
const META_SHOWN: [&str; 4] = ["name", "title", "category", "indexer"];

/// Longest NZB file list worth spelling out. Past this the shape is
/// established and the rest is repetition; a 900-volume post would
/// otherwise be most of the report.
const NZB_FILES_SHOWN: usize = 40;

/// Rewrite what travels with paths and log lines and should not.
///
/// Two substitutions, both narrow on purpose. A blanket redactor over
/// free text removes the evidence as readily as the secrets - the log
/// slice is the most useful part of the report and it is full of
/// filenames, hostnames and byte counts that must survive intact.
///
/// 1. The home directory becomes `~`. Absolute paths are all over a
///    download's output, and on Windows and macOS they carry the user's
///    account name.
/// 2. `scheme://user:secret@host` becomes `scheme://[redacted]@host`.
///    That is the shape an indexer or provider URL takes when it has
///    credentials in it, and such URLs reach the log.
fn scrub(s: &str, home: Option<&str>) -> String {
    let mut out = match home.filter(|h| h.len() > 3) {
        Some(h) => s.replace(h, "~"),
        None => s.to_string(),
    };
    // `://` up to the next `@`, when that `@` arrives before the path
    // starts. Hand-rolled rather than a regex dependency, and bounded:
    // an `@` in a subject line has no `://` in front of it.
    let mut cursor = 0;
    while let Some(i) = out[cursor..].find("://") {
        let start = cursor + i + 3;
        let rest = &out[start..];
        let stop = rest.find(['/', '?', ' ', '"', '\'']).unwrap_or(rest.len());
        match rest[..stop].find('@') {
            Some(at) => {
                out.replace_range(start..start + at, "[redacted]");
                cursor = start + "[redacted]".len();
            }
            None => cursor = start,
        }
    }
    out
}

/// The layer token spelled out. Deliberately NOT the dashboard's
/// sentences: those are UI copy in 27 languages, this is an English
/// artefact for pasting, and the two drifting apart is harmless as long
/// as the token itself is printed beside it.
fn layer_said(layer: &str) -> &'static str {
    match layer {
        "limit" => "held at the configured speed limit",
        "line" => "running at line speed",
        "disk" => "storage is not keeping up",
        "cpu" => "at the CPU limit",
        "client" => "held up inside nzbfast (decode, verify or disk writes)",
        "provider" => "the providers are the limit",
        "missing" => "much of the post is not there, so requests come back empty",
        _ => "no verdict yet",
    }
}

/// TODO 309: which route a RESUMED run took, and what the gate weighed.
///
/// Nothing at all for a job that replayed nothing, which is every job
/// that was not a resume - see [`crate::streamhub::ResumeRoute`] for
/// why absence is the honest answer there and not a route of its own.
///
/// This is the one cost difference in the engine that the user did not
/// choose and could not see: 1.02x payload of device I/O against 2.53x,
/// measured on §94 A's rig, decided by a gate on a memory budget. The
/// figures are printed beside the verdict because the next question
/// after "it took the slow route" is always "why", and the answer is
/// two comparisons rather than one - the gate admits on either.
///
/// English, like the rest of this file, and deliberately not the
/// dashboard's sentences: this is an artefact for pasting, those are UI
/// copy in 27 languages.
///
/// Two sources, and the caller resolves them in the order
/// [`Daemon::report_whyslow`] resolves its own: the LIVE hub cell if
/// this job owns it, then the record. The live one has to win where
/// both exist. `Job::resume_route` is written by the postproc tail, so
/// on a job that is still Downloading it holds the PREVIOUS run's
/// answer or nothing at all - and a retry routed differently from the
/// attempt before it is exactly the case a user is looking at when they
/// press Create report on a slow job.
fn report_resume(r: Option<&crate::streamhub::ResumeRoute>) -> String {
    let Some(r) = r else {
        return String::new();
    };
    let mb = |b: u64| format!("{:.1} MB", b as f64 / 1e6);
    let mut o = String::from("\n== the resume ==\n");
    line(
        &mut o,
        "route",
        match r.mapped {
            true => "replayed the restored parts back through the one-pass path",
            false => "rebuilt the volume files on disk and unpacked from them",
        },
    );
    line(
        &mut o,
        "cost",
        match r.mapped {
            true => "about 1.02x the payload in device I/O (TODO 94 A)",
            false => {
                "about 2.53x the payload in device I/O, against 1.02x for the one-pass path (TODO 94 A)"
            }
        },
    );
    // Zero for a route restored from a record that predates the
    // figures, and `line` prints nothing for an empty value - so an old
    // record says which way it went and claims nothing else.
    if r.restored_bytes > 0 {
        line(&mut o, "already on disk", mb(r.restored_bytes));
    }
    if r.budget_bytes > 0 {
        line(&mut o, "held-span budget", mb(r.budget_bytes));
    }
    if r.widest_slot_bytes > 0 {
        line(
            &mut o,
            "widest part",
            format!(
                "{} (the budget a new pipeline could seat was {})",
                mb(r.widest_slot_bytes),
                mb(r.seatable_bytes)
            ),
        );
    }
    o
}

/// TODO 207: the same section for a job that is no longer on the wire,
/// off the record instead of off the core. No receipts - the samples
/// they came from are a process-global ring that means nothing after a
/// restart, which is exactly why the VERDICT is persisted and they are
/// not - so this prints the conclusion and how much of the run it
/// covers, and claims nothing else.
fn report_saved_whyslow(v: &WhyVerdict) -> String {
    let mut o = String::from("\n== why it was slow ==\n");
    line(
        &mut o,
        "verdict",
        match v.detail.is_empty() {
            true => format!("{} [{}]", layer_said(&v.layer), v.layer),
            false => format!("{} [{}: {}]", layer_said(&v.layer), v.layer, v.detail),
        },
    );
    // Longest-held, so the span is the claim's weight and the run
    // length is what stops it reading as the whole story.
    line(
        &mut o,
        "held for",
        format!("{}s of {}s on the wire", v.held_secs, v.total_secs),
    );
    line(
        &mut o,
        "measured",
        "during the download; the evidence behind it is not kept past the run",
    );
    o
}

/// A `key: value` line, skipped entirely when the value is empty - an
/// absent fact should read as absent, never as a field set to nothing.
fn line(out: &mut String, k: &str, v: impl AsRef<str>) {
    let v = v.as_ref();
    if !v.is_empty() {
        out.push_str(&format!("{k}: {v}\n"));
    }
}

fn secs(t: Option<i64>) -> String {
    match t {
        Some(t) if t > 0 => crate::logging::stamp_for_report(t),
        _ => String::new(),
    }
}

/// The report for one job, by id, from either store. `None` = no
/// such job.
pub(super) fn job_report(d: &Daemon, nzo_id: &str) -> Option<String> {
    // Through the sanctioned accessors, one container lock at a
    // time: "locking a Job while holding the queue is how this tree
    // deadlocks" (`Daemon::queue_job`), and a walk that held the
    // queue AND history while locking each record in turn would be
    // both halves of that at once.
    let job = d.queue_job(nzo_id).or_else(|| d.history_job(nzo_id))?;
    Some(render_report(d, nzo_id, &job))
}

fn render_report(d: &Daemon, nzo_id: &str, job: &Arc<Mutex<Job>>) -> String {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok();
    let mut o = String::new();
    // Composed BEFORE the job is locked: it reads the whyslow core
    // and the bench spool, and "locking a Job while holding" another
    // container's lock is the shape this tree deadlocks in. Cheap
    // either way - it is a string by the time the record is open.
    // ...and the persisted one it falls back to, read under its own
    // brief hold of the record for the same reason: nothing else is
    // locked here yet.
    let saved = job.lock_ok().whyslow.clone();
    let slow = report_whyslow(d, nzo_id, saved);
    // TODO 309: the LIVE route, read the same way and in the same
    // window - before the record is locked, because taking another
    // container's lock while holding a Job is the shape this tree
    // deadlocks in. Owner-tagged, so a job that does not own the hub
    // gets None here and falls back to its own record below.
    let live_route = d.hub.resume_route_for(nzo_id);
    let j = job.lock_ok();

    o.push_str("nzbfast download report\n");
    o.push_str(
        "Assembled for sharing. It carries this one download's own log lines, not the\n\
         daemon's whole log. Your provider usernames, passwords and API keys are not\n\
         read by it; your home folder is written as ~.\n\n",
    );

    o.push_str("== this build ==\n");
    line(&mut o, "nzbfast", env!("CARGO_PKG_VERSION"));
    line(
        &mut o,
        "platform",
        format!(
            "{} {} · {} cores · {} GB RAM",
            std::env::consts::OS,
            std::env::consts::ARCH,
            // cpu-workers-gate: reporting the machine, not sizing a pool.
            std::thread::available_parallelism().map_or(0, |n| n.get()),
            nzbkit::mem::physical_ram().map_or(0, |b| b / 1_000_000_000),
        ),
    );
    line(&mut o, "report made", secs(Some(unix_now())));

    o.push_str("\n== the download ==\n");
    line(&mut o, "name", &j.name);
    line(&mut o, "category", &j.category);
    line(&mut o, "added by", &j.origin);
    line(&mut o, "state", format!("{:?}", j.state));
    if j.total_bytes > 0 {
        line(
            &mut o,
            "size",
            format!("{:.1} MB", j.total_bytes as f64 / 1e6),
        );
    }
    if j.downloaded_bytes > 0 {
        line(
            &mut o,
            "downloaded",
            format!("{:.1} MB", j.downloaded_bytes as f64 / 1e6),
        );
    }
    line(&mut o, "archive", &j.archive_shape);
    line(&mut o, "identified as", &j.identity_name);
    line(&mut o, "identified by", &j.identity_src);
    if j.retries > 0 {
        line(&mut o, "retries", j.retries.to_string());
    }
    if j.password_required {
        line(&mut o, "password", "required, and none worked");
    }
    line(&mut o, "still packed", &j.unpack_blocked_by);
    // §282 item 14. Both attempts, on whichever of the two rows the
    // reader happens to have opened: what was tried, why it was
    // abandoned, what replaced it. Nothing is printed for the
    // overwhelming majority of downloads, which replaced nothing and
    // were replaced by nothing.
    //
    // These three are on the report's fixed field list like every
    // other line here - the module note above is the rule, and a
    // release name is exactly the kind of thing that has to be
    // asked for by name rather than swept in.
    for (k, v) in super::altcand::switch_lines(&j) {
        line(&mut o, k, v);
    }

    o.push_str("\n== timings ==\n");
    line(&mut o, "added", secs(j.queued_unix));
    line(&mut o, "finished", secs(j.finished_unix));
    if j.elapsed_secs > 0.0 {
        let mb = j.downloaded_bytes as f64 / 1e6;
        line(
            &mut o,
            "download",
            format!(
                "{:.1}s ({:.1} MB/s average)",
                j.elapsed_secs,
                mb / j.elapsed_secs.max(0.001)
            ),
        );
    }
    // The figure this whole feature's first case turned on: a tail
    // that outlasts its download is invisible everywhere else.
    if j.postproc_secs > 0.0 {
        // Two decimals, because the interesting readings are at both
        // ends: a healthy tail is hundredths of a second and the one
        // this feature was built for was 526.
        line(
            &mut o,
            "post-processing",
            format!("{:.2}s", j.postproc_secs),
        );
    }

    o.push_str(&report_resume(
        live_route.as_ref().or(j.resume_route.as_ref()),
    ));
    o.push_str(&slow);

    if !j.fail_message.is_empty() {
        o.push_str("\n== why it failed ==\n");
        o.push_str(&j.fail_message);
        o.push('\n');
        line(&mut o, "classified", format!("{:?}", j.fail_kind()));
        if let Some(at) = j.auto_retry_at {
            line(&mut o, "retrying at", secs(Some(at as i64)));
            line(
                &mut o,
                "retry reason",
                j.auto_retry_why.clone().unwrap_or_default(),
            );
        }
    }
    if !j.move_failed.is_empty() {
        o.push_str("\n== the move ==\n");
        line(&mut o, "failed", &j.move_failed);
        line(&mut o, "attempts", j.move_attempts.to_string());
        line(&mut o, "left split", &j.move_split);
    }

    o.push_str(&report_servers(d));
    o.push_str(&report_nzb(&j.nzb_path));

    // Last, because it is the longest and a reader scrolls past the
    // facts to reach it, not the other way round.
    o.push_str("\n== this download's log ==\n");
    // `log_mark == 0` is the documented "nothing to slice" sentinel
    // (see `Job::log_mark`): the marks are deliberately not
    // persisted, so every job restored across a restart carries 0.
    // It must be checked HERE, because `between_span` cannot see it
    // as anything but a valid `from` - 0 is in the past of anything
    // - and would return the tail of the whole daemon ring, i.e. 400
    // lines of other jobs' output presented as this one's.
    let span = if j.log_mark == 0 {
        Vec::new()
    } else {
        nzbkit::logtee::between(
            j.log_mark,
            // A job still running has no closing mark yet; the
            // present is the honest end of its span.
            if j.log_end > j.log_mark {
                j.log_end
            } else {
                nzbkit::logtee::mark()
            },
            REPORT_LOG_LINES,
        )
    };
    if !span.is_empty() {
        o.push_str(&span.join("\n"));
        o.push('\n');
    } else if !j.fail_detail.is_empty() {
        // The failure snapshot IS persisted, so it outlives the ring
        // and a restart. For a failed job it is the same block.
        o.push_str(&j.fail_detail);
        o.push('\n');
    } else {
        o.push_str(
            "No log lines for this download are still in memory. The ring holds the last\n\
             2000 lines and is emptied by a restart, so this happens for an older job or\n\
             after the daemon has been restarted.\n",
        );
    }
    drop(j);
    scrub(&o, home.as_deref())
}

/// The live shortfall verdict for this job, with the numbers behind
/// it. Empty unless the whyslow core is currently judging THIS job -
/// the diagnosis is live-only and belongs to whichever download owns
/// the wire, so a queued job, a finished one, and anything running
/// while another job is downloading all get nothing here rather than
/// somebody else's verdict.
///
/// Read out of `payload()`'s JSON rather than off the core directly.
/// That composition is where the bench corroboration and the
/// measured-vs-typed anchor are resolved, and a second path into the
/// core would be a second place for those rules to drift; the report
/// is a rare user-initiated action, so the Value costs nothing that
/// matters. Hostnames appear, for the same reason they do in
/// `report_servers` below: "which provider is the limit" is the
/// question being asked.
fn report_whyslow(d: &Daemon, nzo_id: &str, saved: Option<WhyVerdict>) -> String {
    let p = d.whyslow.payload(d);
    if p.get("nzo_id").and_then(|v| v.as_str()) != Some(nzo_id) {
        // TODO 207: not on the wire, so no receipts - but the
        // record may still carry the verdict its network leg
        // earned, which is the whole reason this section existed
        // only in the window where the user could read it on
        // screen anyway. Absent on a job nothing judged, and the
        // section is then absent too rather than saying "unknown".
        return match saved {
            Some(v) => report_saved_whyslow(&v),
            None => String::new(),
        };
    }
    let f = |k: &str| p.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0);
    let s = |k: &str| p.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let layer = s("layer");
    // The token, spelled out. Deliberately NOT the dashboard's
    // sentences: those are UI copy in 27 languages, this is an
    // English artefact for pasting, and the two drifting apart is
    // harmless as long as the token itself is printed beside it.
    let said = layer_said(layer);
    let mut o = String::from("\n== why it was slow ==\n");
    let detail = s("detail");
    line(
        &mut o,
        "verdict",
        match detail.is_empty() {
            true => format!("{said} [{layer}]"),
            false => format!("{said} [{layer}: {detail}]"),
        },
    );
    line(&mut o, "held for", format!("{:.0}s", f("secs")));
    let mbs = |k: &str| match f(k) > 0.0 {
        true => format!("{:.1} MB/s", f(k) / 1e6),
        false => String::new(),
    };
    line(&mut o, "right now", mbs("achieved_bps"));
    line(&mut o, "providers delivered", mbs("envelope_bps"));
    if f("hardware_bps") > 0.0 {
        line(
            &mut o,
            "line ceiling",
            format!("{} ({})", mbs("hardware_bps"), s("hardware_src")),
        );
    }
    line(
        &mut o,
        "waiting on decode or disk",
        format!("{:.1}%", f("blocked_pct")),
    );
    line(&mut o, "cpu", format!("{:.1}%", f("cpu_pct")));
    if f("storage_probe_ms") > 0.0 {
        line(
            &mut o,
            "test write to the download folder",
            format!("{:.2}s", f("storage_probe_ms") / 1000.0),
        );
    }
    // The receipts behind a `missing` verdict, which is the one that
    // invites the reader to abandon a download. Only when that is
    // the verdict talking: the counters exist either way.
    if layer == "missing" {
        line(
            &mut o,
            "articles that came back empty",
            format!("{:.1}%", f("missing_pct")),
        );
        if f("missing_backbones") > 1.0 {
            line(
                &mut o,
                "unrelated providers seeing the same gaps",
                format!("{:.0}", f("missing_backbones")),
            );
        }
        if f("post_unix") > 0.0 {
            line(&mut o, "posted", secs(Some(f("post_unix") as i64)));
        }
    }
    // Per-connection rate is the column that makes shaping visible
    // without an argument: one host at 2 MB/s per connection beside
    // another at 40 is the whole finding.
    for srv in p
        .get("servers")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let g = |k: &str| srv.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0);
        let host = srv.get("host").and_then(|v| v.as_str()).unwrap_or("");
        if host.is_empty() || (g("budget") == 0.0 && g("conns") == 0.0) {
            continue;
        }
        let mut bits = format!(
            "{:.0}/{:.0} connections · {:.2} MB/s per connection",
            g("conns"),
            g("budget"),
            g("per_conn_bps") / 1e6
        );
        if srv.get("refused").and_then(|v| v.as_bool()) == Some(true) {
            bits.push_str(" · refused");
        }
        if g("missing_pct") >= 0.5 {
            bits.push_str(&format!(" · {:.1}% missing", g("missing_pct")));
        }
        if g("reconnects") > 0.0 {
            bits.push_str(&format!(" · {:.0} reconnects", g("reconnects")));
        }
        line(&mut o, host, bits);
    }
    o
}

/// The providers, as they stand now. A finished job's own pool is
/// gone - `bank_refusals` is what survives it - so this is "your
/// servers, and what the last run said about them", which is what
/// someone diagnosing a provider problem needs. The per-run byte
/// split lives in the log slice below.
fn report_servers(d: &Daemon) -> String {
    let mut o = String::from("\n== your providers ==\n");
    let refusals = d.last_refusals.lock_ok().clone();
    // Read from the config file, the way every other consumer of
    // the server list does - the daemon holds no copy of it.
    let servers: Vec<nzbkit::config::ServerConfig> = nzbkit::config::Config::load(&d.cfg_path)
        .map(|c| c.servers)
        .unwrap_or_default();
    if servers.is_empty() {
        o.push_str("none configured\n");
        return o;
    }
    for s in servers.iter() {
        let retention = match s.retention_days {
            0 => "unlimited".to_string(),
            d => format!("{d}d"),
        };
        // Block accounts belong here more than anything else on the
        // line. A prepaid block that has run out takes its server
        // out of the pool entirely (the runner's job-start
        // exclusion), so "why was only one of my three providers
        // used" and "why did this fail on a post the fill server
        // has" both answer to a number that is otherwise only
        // visible in Settings.
        let block = match s.block_bytes.filter(|b| *b > 0) {
            Some(total) => {
                let used = d.block_spent(&s.host);
                format!(
                    " · block {:.1} of {:.0} GB used{}",
                    used as f64 / 1e9,
                    total as f64 / 1e9,
                    if used >= total {
                        " - EXHAUSTED, not in the pool"
                    } else {
                        ""
                    }
                )
            }
            None => String::new(),
        };
        o.push_str(&format!(
            "  {} · level {} · {} conns · tls={} · retention {}{}{}{}\n",
            s.host,
            s.level,
            s.connections,
            s.tls,
            retention,
            if s.block_account {
                " · billed per byte"
            } else {
                ""
            },
            block,
            if s.enabled { "" } else { " · TURNED OFF" },
        ));
        if let Some(r) = refusals.get(&s.host) {
            o.push_str(&format!(
                "      last refused: {}{}\n",
                r.line.trim(),
                if r.permanent { " (permanent)" } else { "" },
            ));
        }
    }
    o
}

/// What the NZB itself says, which is a different question from what
/// the download did - and the one that answers "is this post the
/// ordinary shape?".
///
/// Summarised, never quoted. The file is tens to hundreds of KB of
/// message-ids that tell a reader nothing, and it will not survive a
/// paste into a chat window. The `password` meta is redacted: on some
/// indexers it is a real archive password and on others it is an
/// account-scoped token, and this file cannot tell which.
fn report_nzb(path: &std::path::Path) -> String {
    let mut o = String::from("\n== the NZB ==\n");
    let Ok(xml) = std::fs::read(path) else {
        o.push_str("the spooled .nzb is no longer on disk\n");
        return o;
    };
    let Ok(nzb) = nzbkit::nzb::Nzb::parse(&xml) else {
        o.push_str("the spooled .nzb no longer parses\n");
        return o;
    };
    for (k, v) in &nzb.meta {
        // A WHITELIST, not a blacklist of `password`. Indexers put
        // whatever they like in here under keys of their own invention -
        // this NZB carried `<meta type="qxv4i">01432U5g...</meta>`
        // beside the ordinary fields, and nothing on this side can tell
        // an opaque per-account token from a harmless hint. The four
        // that describe the RELEASE are the four worth showing; the
        // rest are named but not quoted, which still answers "what else
        // did the indexer attach" without publishing it.
        line(
            &mut o,
            &format!("meta {k}"),
            if META_SHOWN.contains(&k.as_str()) {
                v.as_str()
            } else {
                "[not shown]"
            },
        );
    }
    let groups: std::collections::BTreeSet<&str> = nzb
        .files
        .iter()
        .flat_map(|f| f.groups.iter().map(String::as_str))
        .collect();
    line(
        &mut o,
        "groups",
        groups.into_iter().collect::<Vec<_>>().join(", "),
    );
    let posted = nzb.files.iter().map(|f| f.date).filter(|d| *d > 0).min();
    line(&mut o, "posted", secs(posted));
    let total = nzb.total_bytes();
    let eager = nzb.eager_bytes();
    o.push_str(&format!(
        "{} file(s), {:.1} MB total; eager set {:.1} MB ({:.1}% saved by deferring PAR2 volumes)\n",
        nzb.files.len(),
        total as f64 / 1e6,
        eager as f64 / 1e6,
        (total - eager) as f64 * 100.0 / total.max(1) as f64,
    ));
    let dropped: usize = nzb.files.iter().map(|f| f.dropped_segments).sum();
    if dropped > 0 {
        line(&mut o, "unusable segments declared", dropped.to_string());
    }
    for f in nzb.files.iter().take(NZB_FILES_SHOWN) {
        let kind = match f.kind() {
            nzbkit::nzb::FileKind::Data => "data",
            nzbkit::nzb::FileKind::Par2Main => "par2",
            nzbkit::nzb::FileKind::Par2Volume => "par2vol",
        };
        o.push_str(&format!(
            "  {:<7} {:>12} {:>5} seg  {}\n",
            kind,
            f.bytes(),
            f.segments.len(),
            f.filename_hint().unwrap_or(&f.subject),
        ));
    }
    if nzb.files.len() > NZB_FILES_SHOWN {
        o.push_str(&format!(
            "  … and {} more\n",
            nzb.files.len() - NZB_FILES_SHOWN
        ));
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The report is assembled to be pasted somewhere public, so the two
    /// things that travel with paths and log lines have to go.
    #[test]
    fn the_scrub_removes_the_account_name_and_url_credentials() {
        // The Windows shape, where every path in a report carries the
        // account name - in the log lines as much as in the fields.
        let home = Some(r"C:\Users\Someone");
        let s = scrub(
            r"wrote C:\Users\Someone\Downloads\nzbfast downloads\Some.Release\a.mkv",
            home,
        );
        assert!(!s.contains("Someone"), "{s}");
        assert!(s.contains(r"~\Downloads"), "{s}");

        // Credentials in a URL, which is how an indexer or a provider
        // reaches the log at all.
        assert_eq!(
            scrub("GET https://joe:hunter2@news.example.com/x?y=1 ok", None),
            "GET https://[redacted]@news.example.com/x?y=1 ok"
        );
        // Two of them in one line, and one without credentials in
        // between, so the walk cannot stop at the first.
        assert_eq!(
            scrub("a http://u:p@h1/ b https://h2/ c ftp://u2:p2@h3/", None),
            "a http://[redacted]@h1/ b https://h2/ c ftp://[redacted]@h3/"
        );
    }

    /// What the scrub must NOT do. The log slice is the most useful part
    /// of the report and it is made of filenames, hostnames and byte
    /// counts; a redactor that ate those would remove the evidence along
    /// with the secrets.
    #[test]
    fn the_scrub_leaves_the_evidence_alone() {
        let keep = "  news.tweaknews.eu  408.0 MB · 8 conns · Some.Release-GRP@posted.local";
        assert_eq!(scrub(keep, Some("/opt/testhome")), keep);
        // A short or empty HOME must not turn every "/" into a tilde.
        assert_eq!(scrub("/a/b", Some("/a")), "/a/b");
        assert_eq!(scrub("/a/b", Some("")), "/a/b");
    }

    /// The verdict section must never print somebody else's diagnosis.
    /// The core judges exactly one job - whichever owns the wire - so a
    /// report for any OTHER job, and every report at all while nothing
    /// is downloading, has to come back with nothing here rather than
    /// with the live verdict filed under the wrong name.
    #[test]
    fn the_verdict_section_is_silent_unless_the_core_is_judging_this_job() {
        let dir = std::env::temp_dir().join(format!("nzbfast-rep-why-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let d = super::super::testutil::test_daemon(&dir);
        // A default core owns no job at all, which is the idle daemon,
        // and the record carries no persisted verdict either.
        assert_eq!(report_whyslow(&d, "anything", None), "");
        // TODO 207: ...but a record that DOES carry one gets its
        // section back from the record, with no receipts attached and
        // both spans printed, however long ago the run was.
        let saved = WhyVerdict {
            layer: "provider".into(),
            detail: "news.example.invalid".into(),
            held_secs: 640,
            total_secs: 900,
        };
        let out = report_whyslow(&d, "anything", Some(saved));
        assert!(out.contains("== why it was slow =="), "{out}");
        assert!(
            out.contains("[provider: news.example.invalid]"),
            "the token and its detail: {out}"
        );
        assert!(out.contains("640s of 900s"), "{out}");
        assert!(
            !out.contains("right now"),
            "a finished job has no live receipts to print: {out}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TODO 309: the resume section, both ways, and the silence that is
    /// the whole point of the third case.
    ///
    /// The route is the largest per-job cost difference this engine has
    /// - 1.02x payload of device I/O against 2.53x - and it is decided
    /// by a gate on a memory budget with the user pressing nothing. The
    /// report is the artefact somebody actually sends when a job was
    /// slow, so it is where that has to be readable.
    #[test]
    fn the_report_names_the_resume_route_and_is_silent_when_there_was_none() {
        let dir = std::env::temp_dir().join(format!("nzbfast-rep-res-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let d = super::super::testutil::test_daemon(&dir);
        let job = Arc::new(Mutex::new(
            crate::job_from_json(&serde_json::json!({
                "nzo_id": "SABnzbd_nzo_nzbfast1",
                "name": "Some.Release-GRP",
                "nzb_path": dir.join("j.nzb"),
                "out_dir": &dir,
                "state": "Completed",
            }))
            .expect("job_from_json"),
        ));

        // The timestamp is the one line that legitimately moves between
        // two renders a millisecond apart, so the comparison below drops
        // it rather than racing it.
        let render = |d: &Daemon, job: &Arc<Mutex<Job>>| {
            render_report(d, "SABnzbd_nzo_nzbfast1", job)
                .lines()
                .filter(|l| !l.starts_with("report made:"))
                .collect::<Vec<_>>()
                .join("\n")
        };

        // A job that replayed nothing says nothing, and this is the
        // assertion the other two are measured against: without it a
        // reader cannot tell "this run took the one-pass route" from
        // "this was never a resume".
        let plain = render(&d, &job);
        assert!(!plain.contains("== the resume =="), "{plain}");

        // Mapped: the cheap route, named as such.
        job.lock_ok().resume_route = Some(crate::streamhub::ResumeRoute {
            mapped: true,
            restored_bytes: 800_000_000,
            budget_bytes: 1_930_000_000,
            widest_slot_bytes: 256_000_000,
            seatable_bytes: 1_930_000_000,
        });
        let mapped = render(&d, &job);
        assert!(mapped.contains("== the resume =="), "{mapped}");
        assert!(mapped.contains("one-pass path"), "{mapped}");
        assert!(mapped.contains("1.02x"), "{mapped}");
        assert!(mapped.contains("already on disk: 800.0 MB"), "{mapped}");
        assert!(
            mapped.contains("held-span budget: 1930.0 MB"),
            "the gate weighed it against this: {mapped}"
        );
        assert!(mapped.contains("widest part: 256.0 MB"), "{mapped}");
        // ...and NOTHING else about the report moved. A section that
        // also rewrote a neighbour would be reporting two runs at once.
        assert_eq!(
            mapped.replace(&report_resume(job.lock_ok().resume_route.as_ref()), ""),
            plain
        );

        // Declined: the 2.53x route, which is what the report exists
        // for. It must not read as an ordinary resume.
        job.lock_ok().resume_route = Some(crate::streamhub::ResumeRoute {
            mapped: false,
            restored_bytes: 2_236_500_000,
            budget_bytes: 970_000_000,
            widest_slot_bytes: 256_000_000,
            seatable_bytes: 270_000_000,
        });
        let declined = render(&d, &job);
        assert!(
            declined.contains("rebuilt the volume files on disk"),
            "{declined}"
        );
        assert!(declined.contains("2.53x"), "{declined}");
        assert!(
            declined.contains("already on disk: 2236.5 MB"),
            "over the 970.0 MB budget, which is arm 1 refusing: {declined}"
        );
        assert!(
            declined.contains("a new pipeline could seat was 270.0 MB"),
            "and arm 2 refusing, which is the other half of the why: {declined}"
        );
        // The cost line names the one-pass figure as the comparison, so
        // it is the ROUTE sentence that has to be absent, not the words.
        assert!(
            !declined.contains("replayed the restored parts"),
            "{declined}"
        );

        // A record restored from before the figures existed knows which
        // way it went and claims nothing else - `line` prints no clause
        // for a zero, so there are no 0.0 MB numbers to misread.
        job.lock_ok().resume_route = Some(crate::streamhub::ResumeRoute {
            mapped: false,
            ..Default::default()
        });
        let bare = render(&d, &job);
        assert!(bare.contains("rebuilt the volume files on disk"), "{bare}");
        assert!(!bare.contains("already on disk"), "{bare}");
        assert!(!bare.contains("0.0 MB"), "{bare}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TODO 309: the LIVE arm, which is the shape `report_whyslow`
    /// already has and this section shipped without.
    ///
    /// `Job::resume_route` is written by the postproc tail, so a report
    /// pulled while the job is still DOWNLOADING - which is when a user
    /// watching a slow job actually presses Create report - had nothing
    /// to print, even though the hub has held the verdict since intake.
    /// And where both exist the LIVE one wins: a retry can route
    /// differently from the attempt before it, and the record still
    /// holds that earlier attempt's answer until this run's tail runs.
    #[test]
    fn the_resume_section_reads_the_live_route_before_the_record() {
        let dir = std::env::temp_dir().join(format!("nzbfast-rep-live-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let d = super::super::testutil::test_daemon(&dir);
        let job = Arc::new(Mutex::new(
            crate::job_from_json(&serde_json::json!({
                "nzo_id": "SABnzbd_nzo_nzbfast1",
                "name": "Some.Release-GRP",
                "nzb_path": dir.join("j.nzb"),
                "out_dir": &dir,
                "state": "Downloading",
            }))
            .expect("job_from_json"),
        ));

        // Downloading, tail not run, so the record carries nothing - and
        // before the live arm this was the whole of the answer.
        assert!(
            !render_report(&d, "SABnzbd_nzo_nzbfast1", &job).contains("== the resume =="),
            "the fixture must start with nothing on the record"
        );

        // The run published its verdict at intake, which is where the
        // hub picks it up.
        *d.hub.resume_route.lock_ok() = Some((
            "SABnzbd_nzo_nzbfast1".into(),
            crate::streamhub::ResumeRoute {
                mapped: false,
                restored_bytes: 2_236_500_000,
                budget_bytes: 970_000_000,
                widest_slot_bytes: 256_000_000,
                seatable_bytes: 270_000_000,
            },
        ));
        let live = render_report(&d, "SABnzbd_nzo_nzbfast1", &job);
        assert!(live.contains("rebuilt the volume files on disk"), "{live}");
        assert!(live.contains("already on disk: 2236.5 MB"), "{live}");

        // A STALE record from the previous attempt must not win over
        // the run the reader is looking at.
        job.lock_ok().resume_route = Some(crate::streamhub::ResumeRoute {
            mapped: true,
            restored_bytes: 8_000_000,
            ..Default::default()
        });
        let both = render_report(&d, "SABnzbd_nzo_nzbfast1", &job);
        assert!(
            both.contains("rebuilt the volume files on disk"),
            "the live verdict wins: {both}"
        );
        assert!(!both.contains("already on disk: 8.0 MB"), "{both}");

        // ...and the hub is owner-tagged, so ANOTHER job's report falls
        // back to its own record rather than borrowing this verdict.
        let other = Arc::new(Mutex::new(
            crate::job_from_json(&serde_json::json!({
                "nzo_id": "SABnzbd_nzo_nzbfast2",
                "name": "Other.Release-GRP",
                "nzb_path": dir.join("o.nzb"),
                "out_dir": &dir,
                "state": "Completed",
            }))
            .expect("job_from_json"),
        ));
        let foreign = render_report(&d, "SABnzbd_nzo_nzbfast2", &other);
        assert!(
            !foreign.contains("== the resume =="),
            "a job that does not own the hub prints nothing: {foreign}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An indexer may attach `<meta>` under any key it likes, and this
    /// side cannot tell an opaque per-account token from a hint - so the
    /// list of what gets quoted is closed.
    #[test]
    fn only_the_four_release_metas_are_quoted() {
        assert!(META_SHOWN.contains(&"name"));
        assert!(META_SHOWN.contains(&"category"));
        assert!(!META_SHOWN.contains(&"password"), "never the password");
        // The real one from the reported NZB: NZBgeek's own key.
        assert!(!META_SHOWN.contains(&"qxv4i"), "nor an unknown token");
    }
}
