//! M29 availability-oracle backtest scoreboard: score the ledger's
//! predictions against direct STAT measurement of the same cells.
//!
//! The oracle predicts "backbone B no longer carries family F at age
//! bucket K" from counted article outcomes, and `oracle_route` steers a
//! job away from the servers it calls gone. On 14 Aug 2026 that took 4
//! of 6 providers off a job which then failed: the cell (highwinds, hdtv,
//! 7-30d) claimed a 4.8% carry rate, while direct STAT of 12
//! independent releases in that exact cell found the articles present
//! on every one of them. The ledger counts ARTICLES and Wilson assumes
//! they are independent, so two doomed postings of ~15k articles each,
//! re-counted on every retry, can pin a cell red for as long as the
//! index lives.
//!
//! What routing DOES with a verdict is a separate question from whether
//! the verdict is right (demoting a predicted-gone server rather than
//! dropping it makes a wrong verdict cost round trips instead of the
//! download - it does not make it right). This scores the verdict.
//!
//! Nothing in the codebase could surface that. This is the missing
//! instrument: it samples releases the ledger's own sampler would have
//! picked, STATs them against every configured server, and prints what
//! the ledger predicted beside what the network actually answered.
//!
//! It is a MEASUREMENT, never a writer: the index is opened read-only
//! and no sample it takes is ingested. Reading a live 42 GB index while
//! the daemon serves from it is the normal case, not the exception.
//!
//! Standing rule: no change to `MIN_SAMPLES`, `GREEN_LOW` or
//! `RED_HIGH` ships without a run of this. Tuned defaults move on
//! measurement, never on argument.

use anyhow::{Context, Result};
use nzbkit::config::{Config, ServerConfig};
use nzbkit::oracle::{self, Snapshot, Verdict};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::Duration;

/// Day range each age bucket covers, indexed by bucket. Mirrors
/// [`nzbkit::oracle::age_bucket`]; `bucket_window_checks_out` in the
/// tests below asserts the two never drift apart.
const BUCKET_DAYS: [(u32, u32); 7] = [
    (0, 1),
    (2, 7),
    (8, 30),
    (31, 90),
    (91, 365),
    (366, 1095),
    (1096, u32::MAX),
];

const DAY: i64 = 86_400;

pub struct Opts {
    pub db: PathBuf,
    /// Releases sampled per (family, bucket) cell.
    pub releases: usize,
    /// Message-ids STATted per release.
    pub msgids: usize,
    /// Restrict to these group families (empty = every family the
    /// ledger has evidence in).
    pub families: Vec<String>,
    /// Restrict to these age buckets (empty = every bucket).
    pub buckets: Vec<u8>,
    /// Cap on cells scored per run (most ledger evidence first).
    pub cells: usize,
    pub seed: u64,
    /// A release counts as CARRIED by a backbone when at least this
    /// fraction of its probed articles answered 223.
    pub truth: f64,
    /// Wall-clock budget for drawing one cell's sample out of the
    /// index. A family with no indexed releases in the bucket's window
    /// costs a full window scan per seek, so the draw loop is bounded
    /// by time as well as by attempts.
    pub sample_secs: u64,
    pub json: bool,
}

// ---------------------------------------------------------------------
// Scoring (pure - no network, no database; unit-tested below)
// ---------------------------------------------------------------------

/// The measured half of one (release × backbone) pair: what STAT
/// answered for that release's probe articles on that backbone's
/// servers. `hits + misses == 0` means unmeasured (every server of the
/// backbone errored) and the pair scores nothing at all - a connection
/// failure must never read as a takedown.
#[derive(Debug, Clone)]
pub struct Pair {
    pub release_id: i64,
    pub family: String,
    pub bucket: u8,
    pub age_days: u32,
    pub backbone: String,
    pub hits: u64,
    pub misses: u64,
}

impl Pair {
    pub fn probes(&self) -> u64 {
        self.hits + self.misses
    }

    /// Measured carry fraction, or None when nothing was measured.
    pub fn carry(&self) -> Option<f64> {
        let n = self.probes();
        (n > 0).then(|| self.hits as f64 / n as f64)
    }

    /// Ground truth for this pair: did the backbone carry the release?
    pub fn carried(&self, truth: f64) -> Option<bool> {
        self.carry().map(|c| c >= truth)
    }
}

/// One scored cell: the ledger's claim beside the network's answer.
#[derive(Debug, Clone)]
pub struct CellRow {
    pub backbone: String,
    pub family: String,
    pub bucket: u8,
    /// Ledger counts for the exact cell (0,0 = the cell does not exist).
    pub led_hits: u64,
    pub led_misses: u64,
    /// [`Snapshot::carry_rate`]: None = blind spot (under `MIN_SAMPLES`).
    pub pred_carry: Option<f64>,
    /// Wilson upper bound of the cell - what `backbone_gone` tests.
    pub pred_high: f64,
    /// [`Snapshot::backbone_gone`]: does `oracle_route` treat this
    /// backbone as gone for this family and age?
    pub gone: bool,
    pub meas_hits: u64,
    pub meas_misses: u64,
    /// Releases measured in this cell, and how many were carried.
    pub releases: usize,
    pub carried: usize,
}

impl CellRow {
    pub fn meas_carry(&self) -> Option<f64> {
        let n = self.meas_hits + self.meas_misses;
        (n > 0).then(|| self.meas_hits as f64 / n as f64)
    }

    /// Release-granular false-skip rate: of the releases this cell would
    /// have skipped, the fraction that were actually there.
    ///
    /// Release-granular deliberately. The prediction is article-counted,
    /// which is exactly the flaw under test, so scoring it by articles
    /// would inherit the flaw: one huge posting would dominate the
    /// measured side the same way it dominates the ledger side. One
    /// release, one vote.
    pub fn false_skip(&self) -> Option<f64> {
        (self.gone && self.releases > 0).then(|| self.carried as f64 / self.releases as f64)
    }
}

/// Confusion matrix over (release × backbone) pairs for the skip
/// decision. Positive = "the oracle would skip this backbone".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Skip {
    /// Skipped and the release was indeed not carried (a right skip).
    pub skipped_gone: usize,
    /// Skipped and the release WAS carried (a false skip - the bug).
    pub skipped_carried: usize,
    /// Kept, and the release was not carried (a skip the oracle missed).
    pub kept_gone: usize,
    /// Kept, and the release was carried (a right keep).
    pub kept_carried: usize,
}

impl Skip {
    pub fn predicted(&self) -> usize {
        self.skipped_gone + self.skipped_carried
    }

    pub fn actual_gone(&self) -> usize {
        self.skipped_gone + self.kept_gone
    }

    /// Of the skips the oracle makes, the fraction that were right.
    pub fn precision(&self) -> Option<f64> {
        let n = self.predicted();
        (n > 0).then(|| self.skipped_gone as f64 / n as f64)
    }

    /// Of the pairs that really were gone, the fraction the oracle skips.
    pub fn recall(&self) -> Option<f64> {
        let n = self.actual_gone();
        (n > 0).then(|| self.skipped_gone as f64 / n as f64)
    }

    /// The headline number: the fraction of the oracle's skips that
    /// denied a provider which would have served the release.
    pub fn false_skip(&self) -> Option<f64> {
        let n = self.predicted();
        (n > 0).then(|| self.skipped_carried as f64 / n as f64)
    }
}

/// Wall/verdict scoring for one predicted class over whole releases.
#[derive(Debug, Clone, Default)]
pub struct VerdictRow {
    /// None = the ledger declined to predict (too thin).
    pub verdict: Option<Verdict>,
    /// Releases with CONCLUSIVE ground truth for this predicted class.
    pub releases: usize,
    /// Measured completable: carried by at least one enabled backbone.
    pub completable: usize,
    /// Releases whose ground truth is inconclusive: no backbone carried
    /// them, but at least one enabled backbone was never measured for
    /// them (it failed to connect, or gave up mid-run). Counted apart
    /// from `releases` because "nobody we asked had it" is not "nobody
    /// has it" - and the backbone we could not ask is often exactly the
    /// one the ledger calls healthy.
    pub partial: usize,
}

#[derive(Debug, Clone)]
pub struct HostNote {
    pub host: String,
    pub backbone: String,
    pub hits: u64,
    pub misses: u64,
    pub errors: usize,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub generated: i64,
    pub db: String,
    pub truth: f64,
    pub msgids: usize,
    pub releases_per_cell: usize,
    pub seed: u64,
    pub backbones: Vec<String>,
    pub cells: Vec<CellRow>,
    pub skip: Skip,
    pub verdicts: Vec<VerdictRow>,
    pub hosts: Vec<HostNote>,
    /// Cells the index could not fill: (family, bucket, releases drawn).
    pub short_cells: Vec<(String, u8, usize)>,
}

/// Posting-time window `[lo, hi)` whose releases land in `bucket` when
/// aged at `now`. Inverse of [`nzbkit::oracle::age_bucket`], which reads
/// whole days: age = (now - first_posted) / 86400.
pub fn bucket_window(bucket: u8, now: i64) -> (i64, i64) {
    let (d_lo, d_hi) = BUCKET_DAYS[(bucket as usize).min(BUCKET_DAYS.len() - 1)];
    let hi = now - d_lo as i64 * DAY + 1;
    let lo = if d_hi == u32::MAX {
        0
    } else {
        now - (d_hi as i64 + 1) * DAY + 1
    };
    (lo.max(0), hi.max(0))
}

/// An age in days that falls in `bucket` - what the ledger is queried
/// with when scoring a whole cell rather than one release.
pub fn bucket_repr_age(bucket: u8) -> u32 {
    BUCKET_DAYS[(bucket as usize).min(BUCKET_DAYS.len() - 1)].0
}

/// Score measured pairs against the ledger. `backbones` is the enabled
/// set, in the order the verdict path sees them.
pub fn score(
    pairs: &[Pair],
    snap: &Snapshot,
    backbones: &[String],
    truth: f64,
) -> (Vec<CellRow>, Skip, Vec<VerdictRow>) {
    // Per-cell aggregation.
    let mut cells: BTreeMap<(String, String, u8), CellRow> = BTreeMap::new();
    let mut skip = Skip::default();
    for p in pairs {
        let key = (p.backbone.clone(), p.family.clone(), p.bucket);
        let row = cells.entry(key).or_insert_with(|| {
            let (led_hits, led_misses) = snap
                .cell(&p.backbone, &p.family, p.bucket)
                .unwrap_or((0, 0));
            let (_lo, hi) = oracle::wilson(led_hits, led_hits + led_misses);
            CellRow {
                backbone: p.backbone.clone(),
                family: p.family.clone(),
                bucket: p.bucket,
                led_hits,
                led_misses,
                pred_carry: snap.carry_rate(&p.backbone, &p.family, p.bucket),
                pred_high: hi,
                gone: snap.backbone_gone(&p.backbone, &p.family, bucket_repr_age(p.bucket)),
                meas_hits: 0,
                meas_misses: 0,
                releases: 0,
                carried: 0,
            }
        });
        let Some(carried) = p.carried(truth) else {
            continue; // unmeasured: scores nothing on either side
        };
        row.meas_hits += p.hits;
        row.meas_misses += p.misses;
        row.releases += 1;
        row.carried += usize::from(carried);
        // The skip decision is per (release, backbone), and uses the
        // release's own age rather than the cell's representative one.
        let gone = snap.backbone_gone(&p.backbone, &p.family, p.age_days);
        match (gone, carried) {
            (true, false) => skip.skipped_gone += 1,
            (true, true) => skip.skipped_carried += 1,
            (false, false) => skip.kept_gone += 1,
            (false, true) => skip.kept_carried += 1,
        }
    }
    let mut cells: Vec<CellRow> = cells.into_values().collect();
    cells.sort_by(|a, b| {
        (&a.family, a.bucket, &a.backbone).cmp(&(&b.family, b.bucket, &b.backbone))
    });

    // Per-release verdict scoring: a release is completable when any
    // enabled backbone carried it. The fourth field is WHICH backbones
    // answered, not merely whether any did: `Snapshot::verdict` spans
    // every enabled backbone, so scoring a "nobody carried it" against
    // it is only honest when every enabled backbone was measured. A
    // backbone that failed to connect contributes no pair at all, so
    // coverage gaps are silent unless they are counted here.
    let mut per_rel: BTreeMap<i64, (String, u32, bool, BTreeSet<String>)> = BTreeMap::new();
    for p in pairs {
        let e = per_rel
            .entry(p.release_id)
            .or_insert_with(|| (p.family.clone(), p.age_days, false, BTreeSet::new()));
        if let Some(c) = p.carried(truth) {
            e.3.insert(p.backbone.clone());
            e.2 |= c;
        }
    }
    let mut rows: BTreeMap<u8, VerdictRow> = BTreeMap::new();
    let key = |v: Option<Verdict>| match v {
        Some(Verdict::Ok) => 0u8,
        Some(Verdict::Maybe) => 1,
        Some(Verdict::Gone) => 2,
        None => 3,
    };
    for (_id, (family, age, completable, measured_bbs)) in per_rel {
        if measured_bbs.is_empty() {
            continue; // nothing measured at all
        }
        let v = snap.verdict(backbones, &family, age);
        let row = rows.entry(key(v)).or_insert(VerdictRow {
            verdict: v,
            ..Default::default()
        });
        if completable {
            // A measured carrier is proof, whatever went unprobed.
            row.releases += 1;
            row.completable += 1;
        } else if backbones.iter().all(|b| measured_bbs.contains(b)) {
            row.releases += 1;
        } else {
            // Asymmetric on purpose: dropping every partially covered
            // release would throw away valid positives and bias what
            // remains toward runs where every provider happened to be
            // reachable.
            row.partial += 1;
        }
    }
    (cells, skip, rows.into_values().collect())
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

fn pct(v: Option<f64>) -> String {
    match v {
        Some(f) => format!("{:.1}%", f * 100.0),
        None => "-".to_string(),
    }
}

pub fn render(r: &Report) -> String {
    let mut o = String::new();
    o.push_str("M29 availability oracle - backtest scoreboard\n");
    o.push_str(&format!("index   {} (read-only)\n", r.db));
    o.push_str(&format!(
        "gates   MIN_SAMPLES={}  GREEN_LOW={:.2}  RED_HIGH={:.2}\n",
        oracle::MIN_SAMPLES,
        oracle::GREEN_LOW,
        oracle::RED_HIGH
    ));
    o.push_str(&format!(
        "sample  {} releases/cell x {} message-ids, seed {}, carried at >= {:.0}% of probes\n",
        r.releases_per_cell,
        r.msgids,
        r.seed,
        r.truth * 100.0
    ));
    o.push_str(&format!("backbones  {}\n\n", r.backbones.join(", ")));

    o.push_str("per-cell: what the ledger claims vs what STAT answered\n");
    o.push_str(
        "backbone      family      bucket     ledger n   pred    measured  rel  ok   skip  false-skip\n",
    );
    o.push_str(
        "-------------------------------------------------------------------------------------------\n",
    );
    for c in &r.cells {
        o.push_str(&format!(
            "{:<13} {:<11} {:<10} {:>8}  {:>6}  {:>8}  {:>3} {:>3}  {:<4}  {}\n",
            c.backbone,
            c.family,
            oracle::bucket_label(c.bucket),
            c.led_hits + c.led_misses,
            pct(c.pred_carry),
            pct(c.meas_carry()),
            c.releases,
            c.carried,
            if c.gone { "yes" } else { "no" },
            pct(c.false_skip()),
        ));
    }
    if !r.short_cells.is_empty() {
        let list: Vec<String> = r
            .short_cells
            .iter()
            .map(|(f, b, n)| format!("{f}/{} ({n})", oracle::bucket_label(*b)))
            .collect();
        o.push_str(&format!(
            "\nshort of {} releases, index had no more to draw: {}\n",
            r.releases_per_cell,
            list.join(", ")
        ));
    }

    o.push_str("\nskip decisions (release x backbone pairs)\n");
    let s = &r.skip;
    o.push_str(&format!(
        "  predicted gone {:>4}   right {:>4}   FALSE SKIP {:>4}\n",
        s.predicted(),
        s.skipped_gone,
        s.skipped_carried
    ));
    o.push_str(&format!(
        "  measured gone  {:>4}   kept  {:>4}   right keep {:>4}\n",
        s.actual_gone(),
        s.kept_gone,
        s.kept_carried
    ));
    o.push_str(&format!(
        "  precision {}   recall {}   false-skip rate {}\n",
        pct(s.precision()),
        pct(s.recall()),
        pct(s.false_skip())
    ));
    if let Some(f) = s.false_skip() {
        o.push_str(&format!(
            "  {} of {} skipped provider attempts would have served the release\n",
            s.skipped_carried,
            s.predicted()
        ));
        if f >= 0.5 {
            o.push_str(
                "  READ THIS AS: the routing verdict is wrong more often than it is right.\n",
            );
        }
    }

    o.push_str("\nrelease verdicts (Snapshot::verdict vs measured completable)\n");
    for v in &r.verdicts {
        let label = v.verdict.map(|x| x.as_str()).unwrap_or("unknown");
        // The rate divides by the CONCLUSIVE count only. Folding the
        // partial ones back in would silently reintroduce the dilution
        // that counting them as incompletable caused in the first place.
        let rate = (v.releases > 0).then(|| v.completable as f64 / v.releases as f64);
        o.push_str(&format!(
            "  {:<8} {:>4} releases   completable {:>4}  ({})   partial {:>4}\n",
            label,
            v.releases,
            v.completable,
            pct(rate),
            v.partial
        ));
    }

    o.push_str("\nper host\n");
    for h in &r.hosts {
        let n = h.hits + h.misses;
        let carry = (n > 0).then(|| h.hits as f64 / n as f64);
        o.push_str(&format!(
            "  {:<26} {:<14} {:>6} probes  carry {:>7}  errors {}{}\n",
            h.host,
            h.backbone,
            n,
            pct(carry),
            h.errors,
            h.note
                .as_deref()
                .map(|s| format!("  [{s}]"))
                .unwrap_or_default(),
        ));
    }
    o
}

pub fn json(r: &Report) -> serde_json::Value {
    serde_json::json!({
        "generated": r.generated,
        "db": r.db,
        "gates": {
            "min_samples": oracle::MIN_SAMPLES,
            "green_low": oracle::GREEN_LOW,
            "red_high": oracle::RED_HIGH,
        },
        "sample": {
            "releases_per_cell": r.releases_per_cell,
            "msgids": r.msgids,
            "seed": r.seed,
            "truth": r.truth,
        },
        "backbones": r.backbones,
        "cells": r.cells.iter().map(|c| serde_json::json!({
            "backbone": c.backbone,
            "family": c.family,
            "bucket": c.bucket,
            "bucket_label": oracle::bucket_label(c.bucket),
            "ledger_hits": c.led_hits,
            "ledger_misses": c.led_misses,
            "predicted_carry": c.pred_carry,
            "predicted_wilson_high": c.pred_high,
            "gone": c.gone,
            "measured_hits": c.meas_hits,
            "measured_misses": c.meas_misses,
            "measured_carry": c.meas_carry(),
            "releases": c.releases,
            "carried": c.carried,
            "false_skip": c.false_skip(),
        })).collect::<Vec<_>>(),
        "skip": {
            "skipped_gone": r.skip.skipped_gone,
            "skipped_carried": r.skip.skipped_carried,
            "kept_gone": r.skip.kept_gone,
            "kept_carried": r.skip.kept_carried,
            "precision": r.skip.precision(),
            "recall": r.skip.recall(),
            "false_skip": r.skip.false_skip(),
        },
        "verdicts": r.verdicts.iter().map(|v| serde_json::json!({
            "verdict": v.verdict.map(|x| x.as_str()).unwrap_or("unknown"),
            "releases": v.releases,
            "completable": v.completable,
            "partial": v.partial,
        })).collect::<Vec<_>>(),
        "hosts": r.hosts.iter().map(|h| serde_json::json!({
            "host": h.host,
            "backbone": h.backbone,
            "hits": h.hits,
            "misses": h.misses,
            "errors": h.errors,
            "note": h.note,
        })).collect::<Vec<_>>(),
        "short_cells": r.short_cells.iter()
            .map(|(f, b, n)| serde_json::json!({"family": f, "bucket": b, "releases": n}))
            .collect::<Vec<_>>(),
    })
}

// ---------------------------------------------------------------------
// Sampling + probing
// ---------------------------------------------------------------------

/// One release's probe set.
#[derive(Debug, Clone)]
struct Job {
    release_id: i64,
    family: String,
    bucket: u8,
    age_days: u32,
    ids: Vec<String>,
}

/// What one host answered, per release.
struct HostResult {
    host: String,
    per_release: HashMap<i64, (u64, u64)>,
    errors: usize,
    note: Option<String>,
}

/// Cells worth scoring: the (family, bucket) pairs the ledger actually
/// has evidence in, most evidence first. A cell nothing has ever been
/// counted in cannot produce a wrong verdict, so it is not what this
/// tool is for.
fn pick_cells(snap: &Snapshot, o: &Opts) -> Vec<(String, u8)> {
    let fams: BTreeSet<String> = o.families.iter().map(|f| f.to_ascii_lowercase()).collect();
    let mut weight: BTreeMap<(String, u8), u64> = BTreeMap::new();
    for (_bb, family, bucket, h, m) in snap.iter_cells() {
        if !fams.is_empty() && !fams.contains(family) {
            continue;
        }
        if !o.buckets.is_empty() && !o.buckets.contains(&bucket) {
            continue;
        }
        *weight.entry((family.to_string(), bucket)).or_default() += h + m;
    }
    let mut v: Vec<((String, u8), u64)> = weight.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(o.cells);
    v.into_iter().map(|(k, _)| k).collect()
}

/// STAT every job's ids against one server on its own connection.
///
/// A protocol error drops the connection and reconnects once: reading
/// past an unexpected status line desyncs a pipelined stream, and a
/// desynced stream would attribute one release's answers to another.
/// Errored releases are recorded as unmeasured, never as misses.
async fn probe_host(s: ServerConfig, jobs: Vec<Job>) -> HostResult {
    let mut out = HostResult {
        host: s.host.clone(),
        per_release: HashMap::new(),
        errors: 0,
        note: None,
    };
    let mut conn = match nzbkit::nntp::Connection::connect(&s).await {
        Ok((c, _)) => c,
        Err(e) => {
            out.note = Some(format!("connect: {e}"));
            return out;
        }
    };
    let mut reconnects = 0usize;
    for j in &jobs {
        let probe = async {
            for id in &j.ids {
                conn.send_stat(id).await?;
            }
            conn.flush().await?;
            let (mut hits, mut misses) = (0u64, 0u64);
            for _ in &j.ids {
                match conn.read_stat().await? {
                    true => hits += 1,
                    false => misses += 1,
                }
            }
            Ok::<(u64, u64), nzbkit::nntp::NntpError>((hits, misses))
        };
        let res = tokio::time::timeout(Duration::from_secs(30), probe).await;
        match res {
            Ok(Ok(hm)) => {
                out.per_release.insert(j.release_id, hm);
                continue;
            }
            Ok(Err(e)) => {
                out.errors += 1;
                if out.note.is_none() {
                    out.note = Some(format!("{e}"));
                }
            }
            Err(_) => {
                out.errors += 1;
                if out.note.is_none() {
                    out.note = Some("probe timed out".to_string());
                }
            }
        }
        // Re-establish before the next release. Bounded, so a server
        // that has stopped answering ends the run instead of dialing it
        // once per release.
        reconnects += 1;
        if reconnects > 3 {
            out.note = Some(format!(
                "{} - gave up after {reconnects} reconnects",
                out.note.as_deref().unwrap_or("errored")
            ));
            return out;
        }
        match nzbkit::nntp::Connection::connect(&s).await {
            Ok((c, _)) => conn = c,
            Err(e) => {
                out.note = Some(format!("reconnect: {e}"));
                return out;
            }
        }
    }
    conn.quit().await;
    out
}

pub async fn run(config: &std::path::Path, o: Opts) -> Result<()> {
    let cfg = Config::load(config).with_context(|| format!("load config {}", config.display()))?;
    let servers: Vec<ServerConfig> = cfg.servers.into_iter().filter(|s| s.enabled).collect();
    if servers.is_empty() {
        anyhow::bail!("no enabled servers in {}", config.display());
    }
    // Read-only, always: the live index is the daemon's, and a
    // scoreboard that could write to it would be a scoreboard nobody
    // dares run.
    let ix = nzbkit::index::Index::open_read_only(&o.db)
        .with_context(|| format!("open index read-only: {}", o.db.display()))?;
    let snap = ix.oracle_snapshot().context("load oracle ledger")?;
    if snap.is_empty() {
        anyhow::bail!(
            "the oracle ledger in {} is empty - nothing to score",
            o.db.display()
        );
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);

    let mut backbones: Vec<String> = servers
        .iter()
        .map(|s| oracle::backbone_of(&s.host))
        .collect();
    backbones.sort();
    backbones.dedup();

    let cells = pick_cells(&snap, &o);
    if cells.is_empty() {
        anyhow::bail!("no ledger cells match the requested families/buckets");
    }

    // Sample releases per cell, then build the probe jobs.
    let mut jobs: Vec<Job> = Vec::new();
    let mut short_cells: Vec<(String, u8, usize)> = Vec::new();
    for (family, bucket) in &cells {
        let (lo, hi) = bucket_window(*bucket, now);
        let like = format!("%{family}%");
        // Over-draw: the LIKE narrowing is a substring match, so some
        // rows belong to a neighbouring family (hdtvx, not hdtv), and
        // some releases carry no segments to probe.
        let want = o.releases.saturating_mul(4).max(o.releases);
        let picked = ix
            .oracle_backtest_pick(
                lo,
                hi,
                Some(&like),
                o.seed ^ (*bucket as u64),
                want,
                Duration::from_secs(o.sample_secs),
            )
            .with_context(|| format!("sample {family}/{}", oracle::bucket_label(*bucket)))?;
        let mut taken = 0usize;
        for (id, grp, posted) in picked {
            if taken >= o.releases {
                break;
            }
            if oracle::group_family(&grp) != *family {
                continue;
            }
            let ids = ix.oracle_msgids(id, o.msgids).unwrap_or_default();
            if ids.is_empty() {
                continue;
            }
            let age_days = ((now - posted).max(0) / DAY) as u32;
            // The window is derived from age_bucket, but a release
            // whose date is broken can still land elsewhere - never
            // score a release into a cell it is not in.
            if oracle::age_bucket(age_days) != *bucket {
                continue;
            }
            jobs.push(Job {
                release_id: id,
                family: family.clone(),
                bucket: *bucket,
                age_days,
                ids,
            });
            taken += 1;
        }
        if taken < o.releases {
            // Short samples are reported, never silently averaged in:
            // a cell scored on 2 releases is not evidence about the
            // cell, and a reader has to be able to see that.
            short_cells.push((family.clone(), *bucket, taken));
        }
    }
    if jobs.is_empty() {
        anyhow::bail!("sampled no probeable releases - try --releases or a wider --family");
    }
    eprintln!(
        "probing {} releases x {} message-ids against {} servers ...",
        jobs.len(),
        o.msgids,
        servers.len()
    );

    // One connection per server, all servers at once: they are
    // independent accounts, and a serial sweep would take six times as
    // long for no extra truth.
    let mut set = tokio::task::JoinSet::new();
    for s in &servers {
        set.spawn(probe_host(s.clone(), jobs.clone()));
    }
    let mut results: Vec<HostResult> = Vec::new();
    while let Some(r) = set.join_next().await {
        results.push(r.context("probe task")?);
    }
    results.sort_by(|a, b| a.host.cmp(&b.host));

    // Fold hosts into backbones - the ledger's own key.
    let mut pairs: Vec<Pair> = Vec::new();
    let mut by_bb: BTreeMap<(i64, String), (u64, u64)> = BTreeMap::new();
    for r in &results {
        let bb = oracle::backbone_of(&r.host);
        for (rid, (h, m)) in &r.per_release {
            let e = by_bb.entry((*rid, bb.clone())).or_insert((0, 0));
            e.0 += *h;
            e.1 += *m;
        }
    }
    let job_of: HashMap<i64, &Job> = jobs.iter().map(|j| (j.release_id, j)).collect();
    for ((rid, bb), (h, m)) in by_bb {
        let Some(j) = job_of.get(&rid) else { continue };
        pairs.push(Pair {
            release_id: rid,
            family: j.family.clone(),
            bucket: j.bucket,
            age_days: j.age_days,
            backbone: bb,
            hits: h,
            misses: m,
        });
    }

    let (cell_rows, skip, verdicts) = score(&pairs, &snap, &backbones, o.truth);
    let hosts: Vec<HostNote> = results
        .iter()
        .map(|r| {
            let (h, m) = r
                .per_release
                .values()
                .fold((0u64, 0u64), |a, b| (a.0 + b.0, a.1 + b.1));
            HostNote {
                host: r.host.clone(),
                backbone: oracle::backbone_of(&r.host),
                hits: h,
                misses: m,
                errors: r.errors,
                note: r.note.clone(),
            }
        })
        .collect();
    let report = Report {
        generated: now,
        db: o.db.display().to_string(),
        truth: o.truth,
        msgids: o.msgids,
        releases_per_cell: o.releases,
        seed: o.seed,
        backbones,
        cells: cell_rows,
        skip,
        verdicts,
        hosts,
        short_cells,
    };
    if o.json {
        println!("{}", serde_json::to_string_pretty(&json(&report))?);
    } else {
        println!("{}", render(&report));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(id: i64, bb: &str, hits: u64, misses: u64) -> Pair {
        Pair {
            release_id: id,
            family: "hdtv".into(),
            bucket: 2,
            age_days: 20,
            backbone: bb.into(),
            hits,
            misses,
        }
    }

    /// The window a bucket is sampled from must contain exactly the ages
    /// that bucket. This is the one place the tool restates a rule
    /// nzbkit owns, so it is asserted against the owner.
    #[test]
    fn bucket_window_checks_out() {
        let now = 1_760_000_000i64;
        let age = |p: i64| ((now - p).max(0) / DAY) as u32;
        for b in 0..oracle::N_BUCKETS {
            let (lo, hi) = bucket_window(b, now);
            assert!(lo < hi, "bucket {b}: empty window");
            assert_eq!(oracle::age_bucket(age(hi - 1)), b, "bucket {b}: young edge");
            assert_eq!(oracle::age_bucket(age(lo)), b, "bucket {b}: old edge");
            // One second past either edge belongs to a neighbour.
            if b > 0 {
                assert_ne!(oracle::age_bucket(age(hi)), b, "bucket {b}: leaks young");
            }
            if b + 1 < oracle::N_BUCKETS {
                assert_ne!(oracle::age_bucket(age(lo - 1)), b, "bucket {b}: leaks old");
            }
            assert_eq!(oracle::age_bucket(bucket_repr_age(b)), b);
        }
    }

    /// The measured 14 Aug 2026 shape: a cell the ledger calls red at
    /// 4.8% carry, where 12 independent releases are all present. The
    /// scoreboard must report that as a ~100% false-skip rate, not as a
    /// good prediction.
    #[test]
    fn correlated_red_cell_scores_as_false_skip() {
        let mut snap = Snapshot::default();
        snap.insert("highwinds", "hdtv", 2, 2871, 57071);
        let backbones = vec!["highwinds".to_string()];
        let pairs: Vec<Pair> = (0..12).map(|i| pair(i, "highwinds", 3, 0)).collect();
        let (cells, skip, verdicts) = score(&pairs, &snap, &backbones, 0.5);
        assert_eq!(cells.len(), 1);
        let c = &cells[0];
        assert!(c.gone, "the ledger's own verdict is the input under test");
        assert!(c.pred_carry.unwrap() < 0.05);
        assert_eq!(c.meas_carry(), Some(1.0));
        assert_eq!((c.releases, c.carried), (12, 12));
        assert_eq!(c.false_skip(), Some(1.0));
        assert_eq!(skip.skipped_carried, 12);
        assert_eq!(skip.skipped_gone, 0);
        assert_eq!(skip.false_skip(), Some(1.0));
        assert_eq!(skip.precision(), Some(0.0));
        // Nothing was really gone, so recall is undefined, not zero.
        assert_eq!(skip.recall(), None);
        // The release-level verdict is red and every release completed.
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].verdict, Some(Verdict::Gone));
        assert_eq!((verdicts[0].releases, verdicts[0].completable), (12, 12));
    }

    /// One partly-carried backbone: 11 of 12 releases present is the
    /// ~92% false-skip shape from the live measurement.
    #[test]
    fn partial_carry_is_release_granular() {
        let mut snap = Snapshot::default();
        snap.insert("usenetexpress", "hdtv", 2, 922, 28511);
        let mut pairs: Vec<Pair> = (0..11).map(|i| pair(i, "usenetexpress", 3, 0)).collect();
        pairs.push(pair(11, "usenetexpress", 0, 3));
        let (cells, skip, _) = score(&pairs, &snap, &["usenetexpress".into()], 0.5);
        let c = &cells[0];
        assert_eq!((c.releases, c.carried), (12, 11));
        let fs = c.false_skip().unwrap();
        assert!((fs - 11.0 / 12.0).abs() < 1e-9, "false skip {fs}");
        assert_eq!(skip.skipped_gone, 1);
        assert_eq!(skip.skipped_carried, 11);
        // Article-weighted, the same data reads 91.7% too here, but the
        // release count is what the report leads with.
        assert_eq!(c.meas_hits, 33);
        assert_eq!(c.meas_misses, 3);
    }

    /// A blind spot must never score as a skip: no evidence is not a
    /// prediction, and the scoreboard has to keep that distinction
    /// visible or the fix for M29 cannot be told from the bug.
    #[test]
    fn blind_spot_predicts_nothing() {
        let mut snap = Snapshot::default();
        snap.insert("highwinds", "hdtv", 2, 2, 3); // under MIN_SAMPLES
        let pairs: Vec<Pair> = (0..4).map(|i| pair(i, "highwinds", 3, 0)).collect();
        let (cells, skip, verdicts) = score(&pairs, &snap, &["highwinds".into()], 0.5);
        assert_eq!(cells[0].pred_carry, None);
        assert!(!cells[0].gone);
        assert_eq!(cells[0].false_skip(), None);
        assert_eq!(skip.predicted(), 0);
        assert_eq!(skip.kept_carried, 4);
        assert_eq!(verdicts[0].verdict, None);
    }

    /// A right skip scores as a right skip: a genuinely dead cell gives
    /// precision 1 and a zero false-skip rate.
    #[test]
    fn true_takedown_scores_clean() {
        let mut snap = Snapshot::default();
        snap.insert("giganews", "hdtv", 2, 82, 15263);
        let pairs: Vec<Pair> = (0..12).map(|i| pair(i, "giganews", 0, 3)).collect();
        let (cells, skip, _) = score(&pairs, &snap, &["giganews".into()], 0.5);
        assert_eq!(cells[0].meas_carry(), Some(0.0));
        assert_eq!(cells[0].false_skip(), Some(0.0));
        assert_eq!(skip.precision(), Some(1.0));
        assert_eq!(skip.recall(), Some(1.0));
        assert_eq!(skip.false_skip(), Some(0.0));
    }

    /// An unmeasured pair (every server of the backbone errored) scores
    /// on neither side - a dead connection is not a takedown.
    #[test]
    fn unmeasured_pairs_score_nothing() {
        let mut snap = Snapshot::default();
        snap.insert("highwinds", "hdtv", 2, 2871, 57071);
        let pairs = vec![pair(1, "highwinds", 0, 0), pair(2, "highwinds", 3, 0)];
        let (cells, skip, verdicts) = score(&pairs, &snap, &["highwinds".into()], 0.5);
        assert_eq!(cells[0].releases, 1);
        assert_eq!(skip.predicted(), 1);
        assert_eq!(verdicts.iter().map(|v| v.releases).sum::<usize>(), 1);
    }

    /// Two enabled backbones, one never dialed. `Snapshot::verdict`
    /// spans BOTH, so a release the one probed backbone missed is not
    /// proof the release was incompletable - the unprobed backbone is
    /// exactly the one the ledger calls healthy. A connect failure on
    /// alpha used to score a correct green prediction as disproved.
    #[test]
    fn unprobed_backbone_does_not_disprove_a_green_verdict() {
        let mut snap = Snapshot::default();
        snap.insert("alpha", "hdtv", 2, 6000, 60); // green
        snap.insert("highwinds", "hdtv", 2, 2871, 57071); // red
        let backbones = vec!["alpha".to_string(), "highwinds".to_string()];
        // Only highwinds answered, and it missed. Alpha contributes no
        // pair at all: a failed connect is a MISSING pair, never a
        // zero-count one.
        let (_, _, verdicts) = score(&[pair(1, "highwinds", 0, 3)], &snap, &backbones, 0.5);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].verdict, Some(Verdict::Ok));
        assert_eq!(
            (
                verdicts[0].releases,
                verdicts[0].completable,
                verdicts[0].partial
            ),
            (0, 0, 1),
            "a green verdict scored wrong on a backbone that was never dialed"
        );

        // The other direction is preserved: a measured CARRIER is proof
        // whatever went unprobed, so partial coverage still scores.
        let (_, _, verdicts) = score(&[pair(1, "highwinds", 3, 0)], &snap, &backbones, 0.5);
        assert_eq!(
            (
                verdicts[0].releases,
                verdicts[0].completable,
                verdicts[0].partial
            ),
            (1, 1, 0)
        );

        // And full coverage with nobody carrying is conclusive.
        let full = vec![pair(1, "highwinds", 0, 3), pair(1, "alpha", 0, 3)];
        let (_, _, verdicts) = score(&full, &snap, &backbones, 0.5);
        assert_eq!(
            (
                verdicts[0].releases,
                verdicts[0].completable,
                verdicts[0].partial
            ),
            (1, 0, 0)
        );
    }

    /// Truth threshold: half-present is carried at 0.5, not at 0.9.
    #[test]
    fn truth_threshold_moves_the_line() {
        let mut snap = Snapshot::default();
        snap.insert("highwinds", "hdtv", 2, 2871, 57071);
        let pairs = vec![pair(1, "highwinds", 2, 2)];
        let (_, lenient, _) = score(&pairs, &snap, &["highwinds".into()], 0.5);
        assert_eq!(lenient.skipped_carried, 1);
        let (_, strict, _) = score(&pairs, &snap, &["highwinds".into()], 0.9);
        assert_eq!(strict.skipped_gone, 1);
    }

    #[test]
    fn cells_are_picked_by_ledger_evidence() {
        let mut snap = Snapshot::default();
        snap.insert("highwinds", "hdtv", 2, 2871, 57071);
        snap.insert("highwinds", "teevee", 2, 1389, 48746);
        snap.insert("highwinds", "boneless", 0, 46081, 40);
        let o = Opts {
            db: PathBuf::new(),
            releases: 12,
            msgids: 3,
            families: vec![],
            buckets: vec![],
            cells: 2,
            seed: 1,
            truth: 0.5,
            sample_secs: 15,
            json: false,
        };
        assert_eq!(
            pick_cells(&snap, &o),
            vec![("hdtv".to_string(), 2u8), ("teevee".to_string(), 2)]
        );
        let narrowed = Opts {
            families: vec!["BONELESS".into()],
            ..o
        };
        assert_eq!(pick_cells(&snap, &narrowed), vec![("boneless".into(), 0u8)]);
    }
}
