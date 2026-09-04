//! Longitudinal per-provider quality: what each news server has actually
//! delivered, over weeks rather than over one download.
//!
//! The daemon has always MEASURED this. `ServerLive` counts a run's
//! article tries, its 430s, its bytes and the connection ceiling the
//! provider granted at the instant it refused another session, and the
//! download report and "Why is this slow?" read those numbers while the
//! job is alive. Every one of them then went in the bin when the job
//! ended. The one thing that survived was `Daemon::add_reliability`, a
//! LIFETIME (tried, missing) pair per host with no window, no age and no
//! outcome attached - enough to print a completion percentage beside a
//! server row and not enough to answer a single question a person
//! actually asks about a subscription:
//!
//! - is this provider worse on OLD posts than on new ones (which is what
//!   retention is, as opposed to what the marketing page says it is)
//! - is it refusing me connections, and for how much of the day
//! - has the second account I pay for ever supplied an article the first
//!   one was missing, or am I paying twice for one spool
//!
//! So this is the ACCUMULATION layer, and it is deliberately an
//! aggregate rather than a log of jobs. A per-job table would answer the
//! same questions and grow without a bound anyone had chosen; counters
//! keyed by (day, host, age bucket) answer them in a file whose size is
//! set by the config, not by how much the user downloads. Today's whole
//! ledger for a five-provider install is under 30 kB at the far end of
//! the window.
//!
//! WHAT IT IS NOT. It is not a scoreboard between providers and must
//! never be read as one: two accounts asked for different articles at
//! different times are not comparable, and a provider the pool puts
//! LAST by design will show a miss rate the pool created (it is asked
//! only for what the one in front of it did not have). Every figure here
//! is a fact about what THIS install asked THIS provider for. That is
//! also why the reports name the user's own configured hosts back to
//! them and nothing else.
//!
//! Age buckets are `nzbkit::oracle::age_bucket`'s, not a second set:
//! that function is already the repo's answer to "how old is this post"
//! and a second spelling of the same boundaries is how two surfaces come
//! to disagree about what "a month old" means. The backbone key is
//! `nzbkit::oracle::backbone_of`, for the reason its own table gives -
//! a value there is a SPOOL, so two hosts under one key genuinely do
//! share their takedowns and are not a second opinion about anything.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::tools::MutexExt;

/// Days of history kept. A month is the window the questions are asked
/// over ("is my provider worse on old posts", "did the second account
/// earn its keep this month") and it is also long enough that one bad
/// week cannot dominate the answer.
pub(super) const WINDOW_DAYS: usize = 30;

/// Distinct hosts recorded in one day, at most. A real install has
/// fewer than ten; this exists so a config that churns hostnames - a
/// load balancer handed out per-session, a typo loop - cannot grow the
/// file without a bound somebody chose. Hosts past the cap are dropped
/// from THAT DAY's record and nothing else.
pub(super) const MAX_HOSTS_PER_DAY: usize = 32;

/// The age-bucket key used when the NZB carried no usable date.
///
/// Deliberately its own bucket and never bucket 0. `Hub::post_unix` is
/// explicit that unknown is NOT "posted just now", and folding it into
/// the newest bucket would put every undated post's misses on the
/// retention line where they would read as a provider losing brand new
/// articles.
const UNKNOWN_AGE: &str = "?";

/// Article tries a cell needs before its miss rate is allowed to drive
/// ADVICE. The FIGURES are always reported; this gates only the
/// sentences. A rate over a handful of articles is noise, and advice
/// that fires on noise is advice a user learns to scroll past.
pub(super) const ADVICE_MIN_TRIED: u64 = 2_000;

/// Miss rate, in percent, at which a provider is worth a sentence of its
/// own over the window.
///
/// A first cut chosen to be quiet rather than to be exactly right: the
/// retry ladder makes scattered misses ordinary, so this is set where a
/// month of them stops being scattered. It is not a measured constant
/// and nothing else in the daemon reads it - what would move it is a
/// campaign over real installs' ledgers, which cannot be run until
/// ledgers exist.
pub(super) const ADVICE_MISS_PCT: f64 = 2.0;

/// Percentage POINTS by which an older age bucket must miss more than
/// the newest measured one before the difference is called retention
/// rather than weather.
pub(super) const ADVICE_AGE_GAP_PCT: f64 = 5.0;

/// Hours of connection cap inside the window before it is worth saying.
/// Four hours is half a working evening: below it a provider bouncing
/// off its ceiling during one busy download is ordinary.
pub(super) const ADVICE_CAP_HOURS: u32 = 4;

/// How a finished job ended, as the ledger records it.
///
/// One job gets exactly one of these, in this order of precedence: a
/// job that arrived by replacing a different posting is `Rescued`
/// whatever else happened to it (the replacement is the fact worth
/// counting), then `Repaired`, then `Completed` or `Failed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Completed,
    /// Finished, but only because PAR2 rebuilt blocks that arrived bad
    /// or did not arrive at all.
    Repaired,
    Failed,
    /// Finished as a REPLACEMENT for another posting of the same
    /// release that could not be finished (`Job::alt_from`).
    Rescued,
}

/// One provider's part in one finished job.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostFacts {
    pub host: String,
    /// Article dispatches sent to this provider - retries and duplicate
    /// races each count as a try, exactly as `ServerLive` counts them.
    pub tried: u64,
    /// 430/423 "no such article" answers from it.
    pub missing: u64,
    /// Raw bytes it served.
    pub bytes: u64,
    /// Unix MILLISECONDS of this run's first connection-capacity
    /// refusal from this provider, 0 if it never refused one. Sampled
    /// only on a capacity-classified refusal - see
    /// `ServerLive::capped_since`, whose doc says at length why an idle
    /// provider must never be read as a capped one.
    pub capped_since_ms: u64,
    /// It refused the ACCOUNT rather than one more connection.
    pub refused: bool,
}

/// One finished job, as the ledger sees it.
#[derive(Clone, Debug)]
pub struct JobFacts {
    pub hosts: Vec<HostFacts>,
    /// Unix seconds of the YOUNGEST article in the job's NZB, 0 for
    /// "we do not know" - which is not the same as "posted just now"
    /// and is bucketed separately (see [`UNKNOWN_AGE`]).
    pub post_unix: i64,
    pub outcome: Outcome,
}

/// Counters for one (day, host, age bucket) cell.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cell {
    #[serde(default)]
    pub tried: u64,
    #[serde(default)]
    pub missing: u64,
    #[serde(default)]
    pub bytes: u64,
    /// Jobs that reached this cell - the denominator for "how much of
    /// what I download is this old", which is what makes a miss rate in
    /// an age bucket worth reading at all.
    #[serde(default)]
    pub jobs: u64,
}

/// One provider's day.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostDay {
    /// Age bucket index as a decimal string, or [`UNKNOWN_AGE`].
    #[serde(default)]
    pub age: BTreeMap<String, Cell>,
    /// Jobs in which this provider refused us another connection.
    #[serde(default)]
    pub cap_jobs: u64,
    /// Which HOURS of this day a connection cap was in force, as a
    /// 24-bit mask; `count_ones()` is the cap-limited hours.
    ///
    /// A mask and not a count because the same evening's cap is
    /// observed once per job, and three short jobs inside one hour are
    /// one capped hour, not three. Bounded by construction, which a
    /// list of timestamps would not be.
    #[serde(default)]
    pub cap_hours: u32,
    /// Jobs in which it refused the account outright.
    #[serde(default)]
    pub refused_jobs: u64,
}

/// A day's job outcomes, and the two backbone joins.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jobs {
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub completed: u64,
    #[serde(default)]
    pub repaired: u64,
    #[serde(default)]
    pub failed: u64,
    #[serde(default)]
    pub rescued: u64,
    /// Jobs where one backbone missed articles and a DIFFERENT one
    /// answered everything it was asked for - the second account
    /// earning its keep, countable.
    #[serde(default)]
    pub saved_by_second: u64,
    /// Jobs that needed repair or failed while only ONE backbone took
    /// part - the shortfall where a second opinion did not exist to be
    /// had.
    #[serde(default)]
    pub short_no_second: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Day {
    #[serde(default)]
    pub hosts: BTreeMap<String, HostDay>,
    #[serde(default)]
    pub jobs: Jobs,
}

/// The persisted ledger. `days` is keyed "YYYY-MM-DD" (UTC), which is
/// what makes the prune below a plain "drop the lowest key" - the same
/// arrangement, and for the same reason, as the usage store's date
/// buckets.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stored {
    #[serde(default)]
    pub v: u32,
    #[serde(default)]
    pub days: BTreeMap<String, Day>,
}

/// "YYYY-MM-DD" (UTC) for a unix second.
pub(super) fn day_key(unix: i64) -> String {
    let (y, m, d) = super::disk::civil_from_days(unix.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// The age-bucket key a post of this date falls in, judged at `now`.
///
/// `post_unix` of 0 is unknown and gets [`UNKNOWN_AGE`]; so does a date
/// in the FUTURE, which is what a poster's clock skew looks like and
/// which would otherwise land in the newest bucket carrying a real
/// measurement it has no business in.
pub(super) fn age_key(post_unix: i64, now: i64) -> String {
    if post_unix <= 0 || post_unix > now {
        return UNKNOWN_AGE.to_string();
    }
    let days = (now - post_unix) / 86_400;
    let days = u32::try_from(days).unwrap_or(u32::MAX);
    nzbkit::oracle::age_bucket(days).to_string()
}

/// Human label for an age key, for the report.
pub(super) fn age_label(key: &str) -> String {
    match key.parse::<u8>() {
        Ok(b) => nzbkit::oracle::bucket_label(b).to_string(),
        Err(_) => UNKNOWN_AGE.to_string(),
    }
}

/// Did a DIFFERENT backbone answer everything it was asked for while
/// one of them missed articles?
///
/// Folded to backbones first, never left per host: two hosts that are
/// one reseller and its parent share a spool, so "the other one had it"
/// is only true across the fold. A backbone that was asked for nothing
/// is not an opinion either way.
pub(super) fn saved_by_second_backbone(hosts: &[HostFacts]) -> bool {
    let by = fold_backbones(hosts);
    let missed = by.values().any(|(_, m)| *m > 0);
    let clean = by.values().any(|(t, m)| *t > 0 && *m == 0);
    // Two DISTINCT keys are needed, so a lone provider that missed
    // nothing cannot pair with itself.
    missed && clean && by.len() >= 2
}

/// How many distinct backbones actually took part - were asked for at
/// least one article.
pub(super) fn backbones_in_play(hosts: &[HostFacts]) -> usize {
    fold_backbones(hosts)
        .values()
        .filter(|(t, _)| *t > 0)
        .count()
}

/// Fold the job's per-host counters onto their backbone keys, as
/// `key -> (tried, missing)`.
fn fold_backbones(hosts: &[HostFacts]) -> BTreeMap<String, (u64, u64)> {
    let mut by: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for h in hosts {
        let e = by
            .entry(nzbkit::oracle::backbone_of(&h.host))
            .or_insert((0, 0));
        e.0 += h.tried;
        e.1 += h.missing;
    }
    by
}

/// Hours of `day` in which a cap that began at `since_ms` and was still
/// in force at `now` was live, as a 24-bit mask.
///
/// Both ends are clipped to the day, so a cap that began yesterday
/// marks today from midnight and a job that ran past midnight does not
/// mark tomorrow. The loop is bounded by the 24 hours of one day
/// whatever the timestamps say, which is what keeps a wrong clock from
/// costing anything but a wrong mask.
fn cap_hour_mask(since_ms: u64, now: i64, day_start: i64) -> u32 {
    let since = i64::try_from(since_ms / 1000).unwrap_or(i64::MAX);
    let lo = since.max(day_start);
    let hi = now.min(day_start + 86_399);
    if hi < lo {
        return 0;
    }
    let (a, b) = ((lo - day_start) / 3600, (hi - day_start) / 3600);
    let mut mask = 0u32;
    for h in a.clamp(0, 23)..=b.clamp(0, 23) {
        mask |= 1 << h;
    }
    mask
}

impl Stored {
    /// Fold one finished job in, then prune to the window.
    pub fn record(&mut self, f: &JobFacts, now: i64) {
        let key = day_key(now);
        let day_start = now.div_euclid(86_400) * 86_400;
        let age = age_key(f.post_unix, now);
        let day = self.days.entry(key).or_default();
        // One job may carry SEVERAL rows for one host - a prepaid block
        // account beside the main account on the same backbone is a
        // supported shape, and the facts are per-ROW on purpose. The
        // three per-JOB counters below are credited at most once per
        // host, however many of its rows took part (or tripped the
        // condition on a row that was not the first). The
        // tried/missing/bytes sums really are per-row accumulation, and
        // `cap_hours` is an idempotent mask whose union across rows is
        // the right answer - those stay as they are.
        let mut seen_job: std::collections::BTreeSet<&str> = Default::default();
        let mut seen_cap: std::collections::BTreeSet<&str> = Default::default();
        let mut seen_refused: std::collections::BTreeSet<&str> = Default::default();
        for h in &f.hosts {
            // Nothing was asked of this provider and it refused
            // nothing: it took no part in this job and recording a zero
            // row for it would make an idle account look measured.
            if h.tried == 0 && h.bytes == 0 && h.capped_since_ms == 0 && !h.refused {
                continue;
            }
            if !day.hosts.contains_key(&h.host) && day.hosts.len() >= MAX_HOSTS_PER_DAY {
                continue;
            }
            let hd = day.hosts.entry(h.host.clone()).or_default();
            let c = hd.age.entry(age.clone()).or_default();
            c.tried += h.tried;
            c.missing += h.missing;
            c.bytes += h.bytes;
            if seen_job.insert(h.host.as_str()) {
                c.jobs += 1;
            }
            if h.capped_since_ms > 0 {
                if seen_cap.insert(h.host.as_str()) {
                    hd.cap_jobs += 1;
                }
                hd.cap_hours |= cap_hour_mask(h.capped_since_ms, now, day_start);
            }
            if h.refused && seen_refused.insert(h.host.as_str()) {
                hd.refused_jobs += 1;
            }
        }
        let j = &mut day.jobs;
        j.total += 1;
        match f.outcome {
            Outcome::Completed => j.completed += 1,
            Outcome::Repaired => j.repaired += 1,
            Outcome::Failed => j.failed += 1,
            Outcome::Rescued => j.rescued += 1,
        }
        if saved_by_second_backbone(&f.hosts) {
            j.saved_by_second += 1;
        }
        if matches!(f.outcome, Outcome::Repaired | Outcome::Failed)
            && backbones_in_play(&f.hosts) <= 1
        {
            j.short_no_second += 1;
        }
        self.trim();
    }

    /// Keep the newest [`WINDOW_DAYS`] date buckets.
    ///
    /// By KEY and not by "days before now": a clock that jumps backwards
    /// - a container starting before NTP, a laptop waking in another
    /// timezone - would otherwise delete every real day at once, and
    /// there is no way to get them back.
    pub fn trim(&mut self) {
        while self.days.len() > WINDOW_DAYS {
            let Some(oldest) = self.days.keys().next().cloned() else {
                return;
            };
            self.days.remove(&oldest);
        }
    }
}

/// One provider's row in the report.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProviderRow {
    pub host: String,
    pub backbone: String,
    pub tried: u64,
    pub missing: u64,
    pub bytes: u64,
    pub jobs: u64,
    /// One entry per age bucket that has evidence, newest first.
    pub age: Vec<AgeRow>,
    pub cap_hours: u32,
    pub cap_jobs: u64,
    pub refused_jobs: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AgeRow {
    pub key: String,
    pub label: String,
    pub tried: u64,
    pub missing: u64,
    pub jobs: u64,
}

/// One piece of advice. `code` is a stable token and the numbers are
/// separate, because the sentence is written in the user's language by
/// whichever surface renders it - the daemon must not ship English
/// prose that a catalogue then cannot reach.
#[derive(Clone, Debug, PartialEq)]
pub struct Advice {
    pub code: &'static str,
    pub host: String,
    /// Percentage the sentence quotes, where it quotes one.
    pub pct: f64,
    /// Count the sentence quotes (jobs, or hours).
    pub n: u64,
    /// Age-bucket KEY the sentence names, where it names one - the
    /// key and not the label, because the surface rendering the
    /// sentence names the bucket in the reader's own language and a
    /// pre-formatted English label is unusable for that. The label
    /// rides beside it on the wire for a reader that has no catalogue.
    pub bucket: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Report {
    pub days: u32,
    /// Oldest day the window covers, "YYYY-MM-DD".
    pub since: String,
    pub providers: Vec<ProviderRow>,
    pub jobs: Jobs,
    pub advice: Vec<Advice>,
}

/// Miss rate in percent, or None when nothing was asked.
pub(super) fn miss_pct(tried: u64, missing: u64) -> Option<f64> {
    (tried > 0).then(|| 100.0 * missing as f64 / tried as f64)
}

/// Roll the window up into one report: a row per provider, the job
/// outcomes, and the advice those two together support.
///
/// `since` is derived from `now` rather than from the lowest key on
/// file, so an install that downloaded nothing for a fortnight reports
/// the window it was ASKED for and not the last day it happened to
/// record. Days outside it are ignored here as well as trimmed on
/// write, which is what makes a clock that jumped forward report
/// honestly instead of counting a month-old day as today's.
pub fn report(s: &Stored, now: i64) -> Report {
    let since = day_key(now - (WINDOW_DAYS as i64 - 1) * 86_400);
    let mut rows: BTreeMap<String, ProviderRow> = BTreeMap::new();
    let mut jobs = Jobs::default();
    for (day, d) in s.days.range(since.clone()..) {
        let _ = day;
        jobs.total += d.jobs.total;
        jobs.completed += d.jobs.completed;
        jobs.repaired += d.jobs.repaired;
        jobs.failed += d.jobs.failed;
        jobs.rescued += d.jobs.rescued;
        jobs.saved_by_second += d.jobs.saved_by_second;
        jobs.short_no_second += d.jobs.short_no_second;
        for (host, hd) in &d.hosts {
            let row = rows.entry(host.clone()).or_insert_with(|| ProviderRow {
                host: host.clone(),
                backbone: nzbkit::oracle::backbone_of(host),
                ..Default::default()
            });
            row.cap_jobs += hd.cap_jobs;
            // The masks are per DAY, so the hours add across days: a
            // provider capped for three hours on each of four evenings
            // is capped for twelve hours in the window, and that is the
            // figure worth reading. Within one day the mask is what
            // stops three jobs in one hour counting three times.
            row.cap_hours += hd.cap_hours.count_ones();
            row.refused_jobs += hd.refused_jobs;
            for (k, c) in &hd.age {
                row.tried += c.tried;
                row.missing += c.missing;
                row.bytes += c.bytes;
                row.jobs += c.jobs;
                match row.age.iter_mut().find(|a| a.key == *k) {
                    Some(a) => {
                        a.tried += c.tried;
                        a.missing += c.missing;
                        a.jobs += c.jobs;
                    }
                    None => row.age.push(AgeRow {
                        key: k.clone(),
                        label: age_label(k),
                        tried: c.tried,
                        missing: c.missing,
                        jobs: c.jobs,
                    }),
                }
            }
        }
    }
    let mut providers: Vec<ProviderRow> = rows.into_values().collect();
    for p in &mut providers {
        // Numeric buckets youngest-first, with the unknown one last:
        // the row reads as an age LADDER, which is the whole point of
        // splitting it, and "?" sorting between 6 and 7 as a string
        // would break that reading.
        p.age
            .sort_by_key(|a| a.key.parse::<u8>().unwrap_or(u8::MAX));
    }
    // Biggest contributor first, which is the order the usage card
    // already puts providers in.
    providers.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.host.cmp(&b.host)));
    let advice = advise(&providers, &jobs);
    Report {
        days: WINDOW_DAYS as u32,
        since,
        providers,
        jobs,
        advice,
    }
}

/// The join layer: what the numbers above are worth SAYING.
///
/// Every arm is gated on [`ADVICE_MIN_TRIED`] evidence in the cell it
/// speaks about, and every threshold is a named constant in this file
/// with its reasoning at its own site. Nothing here decides anything -
/// no download changes because a sentence appeared - so a threshold
/// that turns out to be wrong costs a user one line of text, which is
/// the right price for a first cut nobody has been able to measure yet.
fn advise(providers: &[ProviderRow], jobs: &Jobs) -> Vec<Advice> {
    let mut out = Vec::new();
    for p in providers {
        if let Some(pct) = miss_pct(p.tried, p.missing)
            && p.tried >= ADVICE_MIN_TRIED
            && pct >= ADVICE_MISS_PCT
        {
            out.push(Advice {
                code: "miss_high",
                host: p.host.clone(),
                pct,
                n: p.missing,
                bucket: String::new(),
            });
        }
        if let Some(a) = age_gap(p) {
            out.push(a);
        }
        if p.cap_hours >= ADVICE_CAP_HOURS {
            out.push(Advice {
                code: "capped",
                host: p.host.clone(),
                pct: 0.0,
                n: u64::from(p.cap_hours),
                bucket: String::new(),
            });
        }
        if p.refused_jobs > 0 {
            out.push(Advice {
                code: "refused",
                host: p.host.clone(),
                pct: 0.0,
                n: p.refused_jobs,
                bucket: String::new(),
            });
        }
    }
    if jobs.short_no_second > 0 {
        out.push(Advice {
            code: "one_backbone",
            host: String::new(),
            pct: 0.0,
            n: jobs.short_no_second,
            bucket: String::new(),
        });
    }
    if jobs.saved_by_second > 0 {
        out.push(Advice {
            code: "second_earned",
            host: String::new(),
            pct: 0.0,
            n: jobs.saved_by_second,
            bucket: String::new(),
        });
    }
    out
}

/// "This provider misses far more on old posts than on new ones", if
/// two buckets with real evidence say so.
///
/// The comparison is the YOUNGEST measured bucket against the OLDEST,
/// and both must clear [`ADVICE_MIN_TRIED`] on their own - which is
/// what stops the sentence appearing for an install that has downloaded
/// one archive post. The unknown-age bucket is excluded from both ends:
/// it is not a point on the age line at all.
fn age_gap(p: &ProviderRow) -> Option<Advice> {
    let mut measured: Vec<&AgeRow> = p
        .age
        .iter()
        .filter(|a| a.key != UNKNOWN_AGE && a.tried >= ADVICE_MIN_TRIED)
        .collect();
    measured.sort_by_key(|a| a.key.parse::<u8>().unwrap_or(u8::MAX));
    let young = measured.first()?;
    let old = measured.last()?;
    if young.key == old.key {
        return None;
    }
    let (yp, op) = (
        miss_pct(young.tried, young.missing)?,
        miss_pct(old.tried, old.missing)?,
    );
    (op - yp >= ADVICE_AGE_GAP_PCT).then(|| Advice {
        code: "miss_old",
        host: p.host.clone(),
        pct: op,
        n: old.missing,
        bucket: old.key.clone(),
    })
}

/// The ledger as the daemon holds it: the window, its file, and the
/// lock everything goes through.
///
/// The `LinkPeak` shape - `load` from the spool at startup, a `Mutex`
/// inside, and the save inside the mutation - so `Daemon` carries one
/// field and no caller can persist half a fold.
pub struct ProvQuality {
    pub stored: Mutex<Stored>,
    pub path: PathBuf,
}

impl ProvQuality {
    pub fn load(path: PathBuf) -> Self {
        let stored = crate::persist::load_json_with_backup(&path)
            .and_then(|v| serde_json::from_value::<Stored>(v).ok())
            .unwrap_or_default();
        ProvQuality {
            stored: Mutex::new(stored),
            path,
        }
    }

    /// Fold one finished job in and persist. Best-effort: a ledger that
    /// cannot be written is a report that is one job stale, and no
    /// download depends on it.
    pub fn record(&self, f: &JobFacts, now: i64) {
        let mut s = self.stored.lock_ok();
        s.v = 1;
        s.record(f, now);
        if let Ok(text) = serde_json::to_string(&*s) {
            let _ = crate::persist::write_atomic(&self.path, text.as_bytes());
        }
    }

    pub fn report(&self, now: i64) -> Report {
        report(&self.stored.lock_ok(), now)
    }

    /// The report as the API ships it.
    pub fn report_json(&self, now: i64) -> serde_json::Value {
        json_of(&self.report(now))
    }
}

/// The wire shape. Hand-written rather than derived so the field names
/// the dashboard reads are chosen here and are visible beside the
/// arithmetic that fills them.
pub(super) fn json_of(r: &Report) -> serde_json::Value {
    serde_json::json!({
        "days": r.days,
        "since": r.since,
        "jobs": {
            "total": r.jobs.total,
            "completed": r.jobs.completed,
            "repaired": r.jobs.repaired,
            "failed": r.jobs.failed,
            "rescued": r.jobs.rescued,
            "saved_by_second": r.jobs.saved_by_second,
            "short_no_second": r.jobs.short_no_second,
        },
        "providers": r.providers.iter().map(|p| serde_json::json!({
            "host": p.host,
            "backbone": p.backbone,
            "tried": p.tried,
            "missing": p.missing,
            "miss_pct": miss_pct(p.tried, p.missing),
            "bytes": p.bytes,
            "jobs": p.jobs,
            "cap_hours": p.cap_hours,
            "cap_jobs": p.cap_jobs,
            "refused_jobs": p.refused_jobs,
            "age": p.age.iter().map(|a| serde_json::json!({
                "key": a.key,
                "label": a.label,
                "tried": a.tried,
                "missing": a.missing,
                "miss_pct": miss_pct(a.tried, a.missing),
                "jobs": a.jobs,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "advice": r.advice.iter().map(|a| serde_json::json!({
            "code": a.code,
            "host": a.host,
            "pct": a.pct,
            "n": a.n,
            "bucket": a.bucket,
            "bucket_label": age_label(&a.bucket),
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
#[path = "provquality_tests.rs"]
mod provquality_tests;
