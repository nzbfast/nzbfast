//! `Daemon`'s provider ledger - what each server has cost us (TODO 106
//! code motion out of daemon.rs).
//!
//! One subject read as one thing: bytes billed per server per UTC day
//! (`add_usage`/`save_usage`), the delivered/missing tally behind the
//! reliability figure - lifetime in `"reliability"` and per day in
//! `"article_days"`, both written by `add_reliability` - and the §96.5
//! block-account arithmetic on top of both: lifetime bytes, what this
//! block has spent, the refill, and the 30-second flush that makes a
//! mid-run cutoff land on disk.
//!
//! A second `impl Daemon` in a child module of `daemon`, on the
//! daemon_index shape, so `Daemon`'s private fields and daemon.rs's
//! private types stay in scope exactly as they were inline. `pub(super)`
//! became `pub(crate)` for exactly that reason: `super` is
//! `daemon` here, and every call site is one level up.

use super::*;

impl Daemon {
    /// M18b: bill per-server bytes of a finished download to today's
    /// usage history (UTC days, like the quota) and persist. Best-effort.
    pub fn add_usage(&self, per_server: &[(String, u64)]) {
        let days = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.as_secs() / 86_400) as i64)
            .unwrap_or(0);
        let (y, m, d) = civil_from_days(days);
        let key = format!("{y:04}-{m:02}-{d:02}");
        let mut u = self.usage.lock_ok();
        for bucket in [key.as_str(), "lifetime"] {
            let day = u.entry(bucket.to_string()).or_insert_with(|| json!({}));
            if let Some(map) = day.as_object_mut() {
                for (host, bytes) in per_server {
                    if *bytes == 0 {
                        continue;
                    }
                    let cur = map.get(host).and_then(Value::as_u64).unwrap_or(0);
                    map.insert(host.clone(), json!(cur + bytes));
                }
            }
        }
        // Keep ~60 date buckets. The filter is what a key STARTS with,
        // so "lifetime" is never pruned - block accounts span years -
        // and "reliability", "block_base" and "article_days" survive it
        // the same way. The last of those is bounded per host inside
        // `add_reliability` instead, being a day map one level deeper.
        while u.keys().filter(|k| k.starts_with('2')).count() > 60 {
            let oldest = u.keys().find(|k| k.starts_with('2')).cloned();
            if let Some(k) = oldest {
                u.remove(&k);
            }
        }
        self.save_usage(&u);
    }

    pub(crate) fn save_usage(&self, u: &serde_json::Map<String, Value>) {
        let path = self.spool.join("usage.json");
        if let Ok(text) = serde_json::to_string_pretty(&Value::Object(u.clone())) {
            let _ = crate::persist::write_atomic(&path, text.as_bytes());
        }
    }

    /// Reliability ledger: accumulate a finished job's per-server article
    /// tries/430s under the never-pruned "reliability" usage bucket -
    /// completion% over lifetime is the keep-subscribing signal.
    ///
    /// TWO buckets, written together, because they answer two different
    /// questions and neither can be derived from the other.
    /// `"reliability"` is the LIFETIME pair `{host: {tried, missing}}`
    /// that `reliability()` and the provider-quality card read, and it
    /// is never pruned - a completion% is only worth reading over a
    /// long run. `"article_days"` is the same tally with a DAY
    /// dimension, `{host: {"YYYY-MM-DD": {tried, missing}}}`, and it
    /// exists because SABnzbd's `mode=server_stats` publishes
    /// `articles_tried`/`articles_success` as date-keyed MAPS
    /// (`bpsmeter.py`'s `article_stats_tried`/`article_stats_failed`,
    /// declared `dict[str, dict[str, int]]`) and we published a scalar.
    /// A statically-typed client deserializing `Map<String,Int>` from
    /// `0` throws at parse time, which is GitHub #69 / TODO 320.
    ///
    /// A NEW bucket rather than a day dimension bolted into
    /// `"reliability"`: an existing `usage.json` simply lacks it and
    /// starts filling from the next finished job, so there is no
    /// migration read and nothing that reads the lifetime pair moves.
    /// The cost is that the per-day maps are EMPTY on an install that
    /// upgrades into this, until the next download - stated rather than
    /// papered over by inventing a day key for lifetime data, which
    /// would attribute years of articles to today.
    pub fn add_reliability(&self, per_server: &[(String, u64, u64)]) {
        if per_server.iter().all(|(_, t, _)| *t == 0) {
            return;
        }
        let days = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.as_secs() / 86_400) as i64)
            .unwrap_or(0);
        let (y, m, d) = civil_from_days(days);
        let today = format!("{y:04}-{m:02}-{d:02}");
        let mut u = self.usage.lock_ok();
        let rel = u
            .entry("reliability".to_string())
            .or_insert_with(|| json!({}));
        if let Some(map) = rel.as_object_mut() {
            for (host, tried, missing) in per_server {
                if *tried == 0 {
                    continue;
                }
                let (ct, cm) = map
                    .get(host)
                    .map(|v| {
                        let g = |k| v.get(k).and_then(Value::as_u64).unwrap_or(0);
                        (g("tried"), g("missing"))
                    })
                    .unwrap_or((0, 0));
                map.insert(
                    host.clone(),
                    json!({"tried": ct + tried, "missing": cm + missing}),
                );
            }
        }
        let byday = u
            .entry("article_days".to_string())
            .or_insert_with(|| json!({}));
        if let Some(hosts) = byday.as_object_mut() {
            for (host, tried, missing) in per_server {
                if *tried == 0 {
                    continue;
                }
                let Some(dm) = hosts
                    .entry(host.clone())
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                else {
                    continue;
                };
                let (ct, cm) = dm
                    .get(&today)
                    .map(|v| {
                        let g = |k| v.get(k).and_then(Value::as_u64).unwrap_or(0);
                        (g("tried"), g("missing"))
                    })
                    .unwrap_or((0, 0));
                dm.insert(
                    today.clone(),
                    json!({"tried": ct + tried, "missing": cm + missing}),
                );
                // Bounded the same way `add_usage` bounds its date
                // buckets, and PER HOST because this map is nested one
                // level deeper. By `min()` rather than by first key:
                // "YYYY-MM-DD" sorts oldest-first lexicographically
                // either way, but a `serde_json::Map` is an insertion-
                // ordered IndexMap under the `preserve_order` feature,
                // where "the first key" is the oldest INSERT and not the
                // oldest DAY.
                while dm.len() > 60 {
                    let Some(oldest) = dm.keys().min().cloned() else {
                        break;
                    };
                    dm.remove(&oldest);
                }
            }
        }
        self.save_usage(&u);
    }

    /// Lifetime (tried, missing) article counts for `host`, from the
    /// reliability ledger. None until the first finished job recorded any.
    pub fn reliability(&self, host: &str) -> Option<(u64, u64)> {
        let u = self.usage.lock_ok();
        let v = u.get("reliability")?.get(host)?;
        let g = |k| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        let (t, m) = (g("tried"), g("missing"));
        (t > 0).then_some((t, m))
    }

    /// Lifetime bytes billed to `host` (block-account accounting).
    pub fn usage_lifetime(&self, host: &str) -> u64 {
        self.usage
            .lock_ok()
            .get("lifetime")
            .and_then(|v| v.get(host))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    }

    /// §96.5: bytes counted against `host`'s CURRENT prepaid block -
    /// lifetime usage minus the offset stamped when the user last
    /// marked the block refilled. This, not `usage_lifetime`, is what
    /// every exhausted-block check compares against `block_bytes`. The
    /// lifetime bucket itself is never rewound: it also answers the
    /// history totals and `jobs_ever`, and a refill does not unhappen
    /// the old spend.
    pub fn block_spent(&self, host: &str) -> u64 {
        let base = self
            .usage
            .lock_ok()
            .get("block_base")
            .and_then(|v| v.get(host))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        self.usage_lifetime(host).saturating_sub(base)
    }

    /// §96.5: the user bought a new block for `host` - restart its
    /// counter by stamping the current lifetime figure as the new base.
    /// Persisted in the usage store's never-pruned `"block_base"`
    /// bucket (not a date key, so the 60-day prune skips it the same
    /// way it skips `"lifetime"` and `"reliability"`).
    pub fn block_refilled(&self, host: &str) {
        let mut u = self.usage.lock_ok();
        let lifetime = u
            .get("lifetime")
            .and_then(|v| v.get(host))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let base = u
            .entry("block_base".to_string())
            .or_insert_with(|| json!({}));
        if let Some(map) = base.as_object_mut() {
            map.insert(host.to_string(), json!(lifetime));
        }
        self.save_usage(&u);
    }

    /// §96.5: bill the running download's per-server bytes accumulated
    /// SO FAR into the usage ledger. Idempotent at any cadence - the
    /// per-host high-water map remembers how much of the live counter
    /// is already billed, so the periodic flush task and the net-drain
    /// call each bill only their delta. This is what bounds the loss on
    /// a crash mid-job to one flush interval of paid bytes, where the
    /// old end-of-job-only billing lost the whole run's.
    ///
    /// Lock order is high-water map, then `pool_live`, then the usage
    /// store (inside `add_usage`) - both callers come through here, so
    /// the order cannot invert.
    ///
    /// THE FOLD BELOW IS LOAD-BEARING; see [`Daemon::fold_bytes_by_host`]
    /// for the whole story. A pool has one ROW per configured account and
    /// this map has one KEY per HOST, and two config rows may share a
    /// host, so comparing an unfolded row counter against the shared
    /// high-water mark silently stopped billing about half of all paid
    /// bytes for the life of the job.
    pub fn flush_run_usage(&self) {
        let mut flushed = self.run_usage_flushed.lock_ok();
        let per: Vec<(String, u64)> = self
            .hub
            .pool_live
            .lock_ok()
            .as_ref()
            .map(|l| {
                l.servers
                    .iter()
                    .map(|s| (s.host.clone(), s.bytes.load(Ordering::Relaxed)))
                    .collect()
            })
            .unwrap_or_default();
        let per = Self::fold_bytes_by_host(&per);
        let deltas: Vec<(String, u64)> = per
            .iter()
            .filter_map(|(h, b)| {
                let done = flushed.get(h).copied().unwrap_or(0);
                (*b > done).then(|| (h.clone(), b - done))
            })
            .collect();
        if deltas.is_empty() {
            return;
        }
        for (h, b) in &deltas {
            *flushed.entry(h.clone()).or_insert(0) += b;
        }
        self.add_usage(&deltas);
    }

    /// Sum a per-ROW list of cumulative bytes into one total per HOST,
    /// first-seen order preserved.
    ///
    /// TWO CONFIG ROWS MAY SHARE ONE HOST. That is a supported shape,
    /// not a misconfiguration - a prepaid block account beside the main
    /// account on the same backbone - and the config never dedupes it
    /// (`block_threshold_tick`'s latch comment below says the same thing
    /// about the crossing latch, and
    /// `block_threshold_tests::duplicate_host_entries_edge_trigger_independently`
    /// pins it). Every ledger here is keyed on the HOSTNAME and stays
    /// that way on purpose: `block_spent` is host-aggregated, and the
    /// pool's per-host budgets and exclusions are read back by host in
    /// `get::fleet` and `get::plan`. The pool, though, carries one ROW
    /// per account. This is the join between the two.
    ///
    /// WHAT IT FIXES, so nobody flattens it back. `flush_run_usage` used
    /// to compare EACH ROW's cumulative counter against the ONE
    /// host-keyed high-water mark that it then added EVERY row's delta
    /// into. With rows A and B on one host the first flush read both
    /// against zero, billed A+B and stored A+B - correct by accident.
    /// From the second flush on, neither row's own counter was ever
    /// larger than the pair's stored sum, so `b > done` was false for
    /// both, the delta list came out empty and the function returned
    /// having billed NOTHING. It converges on billing roughly half of
    /// all paid bytes, and the missing half is gone for good: out of
    /// usage.json, out of the day/lifetime/per-server totals, and out of
    /// every block-exhaustion decision that reads them.
    ///
    /// RE-KEYING THE LEDGER PER ACCOUNT WAS CONSIDERED AND REJECTED.
    /// `nzbkit::pool::handoff::ConnBudget::key` is host:port:username,
    /// and `port` has a serde default while `username` defaults to
    /// `None` - so two rows spelled `{"host":"h"}`, which is exactly
    /// what the duplicate-host test writes, collapse to ONE key and
    /// reproduce this bug unchanged. The fold closes it with no new
    /// field, no key change and no nzbkit change, and leaves every
    /// install whose hosts are all distinct byte-for-byte identical.
    ///
    /// An associated function rather than a free one so it sits inside
    /// the ledger's own `impl` and reaches both callers
    /// (`flush_run_usage` here and `tasks::runner::settle_job_tail`)
    /// without a re-export - the two halves MUST move together, because
    /// folding one and not the other leaves settle comparing a row
    /// counter against a key it can no longer match and billing the
    /// whole job a second time.
    pub fn fold_bytes_by_host(per: &[(String, u64)]) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = Vec::with_capacity(per.len());
        for (host, bytes) in per {
            match out.iter_mut().find(|(h, _)| h == host) {
                Some((_, total)) => *total = total.saturating_add(*bytes),
                None => out.push((host.clone(), *bytes)),
            }
        }
        out
    }

    /// §96.5: which hosts this pool build must rule out, and the
    /// remaining prepaid budget for the hosts it keeps.
    ///
    /// One place, two callers - `tasks::runner::reset_hub_for_job` for
    /// the main job and `sidecar::spawn_sidecar` for the prefetch fleet.
    /// They ran two hand-copied copies of this arithmetic until 28 Aug
    /// 2026, which is the shape this repo keeps paying for: the next
    /// copy is a copy of one of them, fine if it copies the rule and
    /// silently wrong if it does not.
    ///
    /// THE ANSWER IS KEYED BY HOST because every reader is - `get::plan`
    /// drops servers whose `host` is in `excluded_hosts` and `get::fleet`
    /// seeds each server's mid-run budget from `host_byte_budgets` by
    /// `host` - so nothing downstream changes. What changes is how a
    /// host with SEVERAL enabled rows is scored, and each of the three
    /// rules below closes a defect that was live:
    ///
    /// 1. DISABLED ROWS ARE SKIPPED. The snapshot is not filtered on
    ///    `enabled`, while `plan` drops disabled rows BEFORE applying
    ///    the exclusion - so a switched-off exhausted block row used to
    ///    delete its ENABLED sibling from the pool. Same shape as the
    ///    per-entry block latch already fixed for the notifications.
    /// 2. A HOST IS EXCLUDED ONLY IF EVERY enabled row on it is an
    ///    exhausted block row. One spent row used to exclude the whole
    ///    host, taking a funded sibling - or an unlimited FLAT-RATE
    ///    sibling with no block at all - out of the pool with it. If
    ///    they were the user's only provider, `plan` then bailed with
    ///    "no usable servers" while Settings still showed the sibling
    ///    healthy with bytes left.
    /// 3. THE BUDGET IS THE MAXIMUM remaining across the host's enabled
    ///    block rows, and there is NO budget at all if the host has any
    ///    enabled flat-rate row. `insert` was last-write-wins, so the
    ///    config's ORDER decided the cap and `fleet` then copied that
    ///    one value onto EVERY row on the host - including a flat-rate
    ///    row, which the pool would then release at a cap the user never
    ///    set. Spend is host-aggregated by design, so the host can keep
    ///    serving while any account on it still has allowance, and the
    ///    largest remaining is the only order-INDEPENDENT answer; an
    ///    unlimited account on the host means it never needs releasing
    ///    at all.
    ///
    /// STATED RESIDUE, deliberately not fixed here: two BLOCK rows on
    /// one host still share one host-aggregated `block_spent`, so each
    /// enforces against the same figure and the pair can spend more than
    /// the host really has left. Closing that means keying the ledger
    /// per ACCOUNT, which is a decision about the spend record itself
    /// (and not one `ConnBudget::key` can carry - see
    /// [`Daemon::fold_bytes_by_host`]), so it is out of scope here.
    ///
    /// Nothing account-identifying reaches either answer: both are
    /// `s.host` and only `s.host`, because `excluded_hosts` is what
    /// `plan` prints into the user-visible `sidelined` list and a
    /// username there would publish a credential fragment.
    pub fn block_pool_rules(
        &self,
        servers: &[nzbkit::config::ServerConfig],
    ) -> (Vec<String>, std::collections::HashMap<String, u64>) {
        /// What this host's ENABLED rows add up to. Deliberately not
        /// "the block row's state": a host is a set of accounts here.
        #[derive(Default)]
        struct HostRows {
            /// At least one enabled row with no block configured - an
            /// unlimited account, so the host never needs a cap.
            flat: bool,
            /// At least one enabled row that HAS a block.
            block: bool,
            /// At least one enabled block row with bytes left.
            live: bool,
            /// The largest remaining allowance among those.
            left: u64,
        }
        let mut order: Vec<String> = Vec::new();
        let mut by_host: std::collections::HashMap<String, HostRows> = Default::default();
        for s in servers {
            if !s.enabled {
                continue;
            }
            let e = by_host.entry(s.host.clone()).or_insert_with(|| {
                order.push(s.host.clone());
                HostRows::default()
            });
            match s.block_bytes.filter(|b| *b > 0) {
                None => e.flat = true,
                Some(b) => {
                    e.block = true;
                    let spent = self.block_spent(&s.host);
                    if spent < b {
                        e.live = true;
                        e.left = e.left.max(b - spent);
                    }
                }
            }
        }
        let mut excluded: Vec<String> = Vec::new();
        let mut budgets: std::collections::HashMap<String, u64> = Default::default();
        for host in order {
            let Some(e) = by_host.get(&host) else {
                continue;
            };
            if e.flat {
                // An unlimited account on this host: never excluded,
                // never capped, whatever a block sibling has spent.
                continue;
            }
            if e.live {
                budgets.insert(host, e.left);
            } else if e.block {
                excluded.push(host);
            }
        }
        (excluded, budgets)
    }
}

/// A prepaid block runs LOW at this percentage of the block spent.
///
/// One number, in one place. The Settings server list has coloured its
/// block line `warn` at 85% since §96.5, so this is that threshold read
/// out of Rust rather than a second one invented beside it - the dashboard
/// takes the band from [`Daemon::block_standings`] through the API instead
/// of computing its own. A second threshold would be two readings of one
/// question, which is exactly the shape F1 of the design was.
///
/// Design: research/BLOCK-ACCOUNT-ECONOMICS-2026-08-27.md, sections 5.2
/// and 5.3.
pub(crate) const BLOCK_LOW_PCT: u64 = 85;

/// One prepaid block account's standing, and the only place the readout
/// arithmetic is done.
///
/// FROM OUR OWN ACCOUNTING AND NOTHING ELSE. `spent` is
/// [`Daemon::block_spent`] - the never-pruned lifetime figure minus the
/// offset the user's last "Block refilled" stamped - and there is
/// deliberately no provider-reported input anywhere in this struct. The
/// design's section 3 is binding on that: a provider figure that stops
/// being emitted, or whose free-form format moves, would make a silent
/// account look like a full block, which is the failure this whole
/// subject exists to avoid. Our count is systematically LOW (it counts
/// `buf.len()` at the 222 body, so TLS framing, command lines and any
/// partial body killed mid-read are outside it), which is an argument
/// for warning with headroom and not for a fudge factor.
///
/// Keyed on `block_bytes > 0`, never on `block_account`: those answer
/// different questions (the design's section 2 table), and a metered
/// pay-as-you-go account has nothing to count down - section 5.4 records
/// that silence as correct rather than a bug to "fix" by warning on
/// lifetime spend, which never stops rising.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockStanding {
    pub host: String,
    /// A disabled server is downloading nothing whatever its ledger
    /// says. Reported rather than filtered, so a client can still show
    /// the figures on a server the user has switched off; the WARNING
    /// paths skip it.
    pub enabled: bool,
    /// What was bought, `block_bytes` (> 0, or this is not a standing).
    pub total: u64,
    /// What this block has cost so far.
    pub spent: u64,
    /// What is left of it. Saturating: an overspent block reads zero
    /// left rather than wrapping to something enormous.
    pub left: u64,
}

impl BlockStanding {
    /// Percent of the block spent, capped at 100 for display. The BAND
    /// below is what any decision reads; this is for the readout.
    pub fn pct(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (100.0 * self.spent as f64 / self.total as f64).min(100.0)
    }

    /// 0 = fine, 1 = low (>= [`BLOCK_LOW_PCT`]), 2 = spent.
    ///
    /// Integer arithmetic on purpose: this is the value the crossing
    /// latch compares, and a float rounding difference between two ticks
    /// would fire or swallow an edge.
    ///
    /// A `total` of ZERO is band 0 and not band 2. `block_bytes: 0` is
    /// how the config, the pool, the job planner and the settings UI all
    /// spell "no block configured" - an unlimited plan has nothing to run
    /// out of - and a naive `spent >= total` would call every flat-rate
    /// server on the install exhausted. Section 5.4.
    pub fn band(&self) -> u8 {
        if self.total == 0 {
            0
        } else if self.spent >= self.total {
            2
        } else if self.spent.saturating_mul(100) >= self.total.saturating_mul(BLOCK_LOW_PCT) {
            1
        } else {
            0
        }
    }

    /// The band as the word the API and the page use. Kept beside
    /// [`Self::band`] so the two cannot part company.
    pub fn band_word(&self) -> &'static str {
        match self.band() {
            2 => "spent",
            1 => "low",
            _ => "ok",
        }
    }
}

impl Daemon {
    /// One server's standing, block or no block. `total` of zero is the
    /// no-block answer and reads as band "ok" (see [`BlockStanding::band`]),
    /// which is what lets the servers payload carry the same two fields
    /// for every row without a second spelling of the arithmetic.
    pub fn block_standing(&self, s: &nzbkit::config::ServerConfig) -> BlockStanding {
        let total = s.block_bytes.unwrap_or(0);
        let spent = self.block_spent(&s.host);
        BlockStanding {
            host: s.host.clone(),
            enabled: s.enabled,
            total,
            spent,
            left: total.saturating_sub(spent),
        }
    }

    /// Every configured server that HAS a prepaid block, with what it
    /// has cost and what is left.
    ///
    /// The config is a parameter rather than loaded here because both
    /// callers already hold one: the API handlers load it once for the
    /// whole payload, and loading it twice would be two answers to one
    /// question inside one response.
    pub fn block_standings(&self, cfg: &nzbkit::config::Config) -> Vec<BlockStanding> {
        cfg.servers
            .iter()
            .filter(|s| s.block_bytes.is_some_and(|b| b > 0))
            .map(|s| self.block_standing(s))
            .collect()
    }

    /// The 85% and 100% crossings, as lifecycle events.
    ///
    /// EDGE-TRIGGERED, and that is the whole design. `server.block_low`
    /// and `server.block_spent` are MOMENTS, like `quota.reached`: the
    /// crossing is the thing worth delivering, and a webhook on the low
    /// one is how somebody automates "buy more data before it bites".
    /// The STATE at exhaustion is already carried by `sab_warnings`
    /// (which is what an *arr reads) and by the Settings list's colour,
    /// so re-announcing it every tick would be the noise the warnings
    /// pane's own contract refuses.
    ///
    /// THE FIRST TICK SEEDS SILENTLY. A daemon that starts up against an
    /// already-spent block has not watched it cross anything, and spend
    /// only ever accrues while the daemon is RUNNING - the 30 s flush is
    /// what makes it visible at all - so no real crossing is lost by
    /// declining to invent one at startup.
    ///
    /// A REFILL RE-ARMS IT. The band is stored, not a high-water mark,
    /// so a band that goes DOWN (the user topped up and pressed Block
    /// refilled) rewrites the latch and the next crossing fires again.
    ///
    /// AN UNREADABLE CONFIG EMITS NOTHING AND LATCHES NOTHING. It is not
    /// a spend decision, so the design's fail-closed rule has nothing to
    /// bite on here - what it does mean is that the latch must be left
    /// alone, so the crossing still fires from the next tick that can
    /// read the file.
    pub fn block_threshold_tick(&self) {
        let Ok(cfg) = nzbkit::config::Config::load(&self.cfg_path) else {
            return;
        };
        let standings = self.block_standings(&cfg);
        // Collected under the latch and emitted after it: `life_emit`
        // takes the event ring and offers the event to the webhook
        // dispatcher, and holding a second lock across that is how a
        // cheap tick becomes a lock-order question.
        let mut fire: Vec<(BlockStanding, u8)> = Vec::new();
        {
            // The latch key is PER CONFIG ENTRY, never per host: two
            // entries may share one host with different block sizes
            // (a block account beside the main account, which the
            // config never dedupes), and one host-keyed slot would
            // either re-fire the crossing on every 30 s tick or
            // suppress it for good - and a DISABLED entry's removal
            // would delete its enabled sibling's latch each tick. The
            // ordinal is the entry's position among same-host
            // standings, stable while the config stands still; an
            // edit that reorders them costs at most one silent
            // re-seed, which is the startup rule anyway.
            let mut seen: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
            let mut keys: Vec<String> = Vec::with_capacity(standings.len());
            let mut latch = self.block_band.lock_ok();
            for st in &standings {
                let n = seen.entry(st.host.as_str()).or_insert(0);
                let key = format!("{}#{n}", st.host);
                *n += 1;
                if !st.enabled {
                    // Not latched either: a server switched back on gets
                    // a silent re-seed on the next tick rather than a
                    // crossing it never made while it was off.
                    latch.remove(&key);
                    keys.push(key);
                    continue;
                }
                let band = st.band();
                match latch.insert(key.clone(), band) {
                    Some(prev) if band > prev => fire.push((st.clone(), band)),
                    _ => {}
                }
                keys.push(key);
            }
            // A server deleted from the config leaves the latch with it,
            // so a long-lived daemon cannot grow this map without bound
            // and an entry re-added later seeds silently rather than
            // firing off a band nobody has watched since.
            //
            // PRESENCE only, deliberately not `s.enabled` as well. The
            // disabled arm above already removes its own entry, and a
            // second sufficient guard on the same fact makes BOTH
            // unfalsifiable - break either one and a test still passes
            // on the strength of the other, which is how a check quietly
            // stops being a check.
            latch.retain(|k, _| keys.iter().any(|kk| kk == k));
        }
        for (st, band) in fire {
            // Both kinds spelled out at their own `life_emit`, never
            // through a `kind` variable: the kind IS a webhook
            // subscriber's whole filter vocabulary, and a dynamic one is
            // a kind nothing can census - `tools/event-arm-gate.py`
            // refuses it for exactly that reason, and the page arm it
            // holds this to would then be judged by nothing.
            let payload = |message: String| {
                json!({
                    "host": st.host,
                    "message": message,
                    "block_bytes": st.total,
                    "spent_bytes": st.spent,
                    "left_bytes": st.left,
                })
            };
            if band >= 2 {
                self.life_emit(
                    "server.block_spent",
                    payload(format!(
                        "{} has used all {:.0} GB of the block you bought, so it is \
                         not being used for downloads. Top the account up, then press \
                         Block refilled on that server in Settings.",
                        st.host,
                        st.total as f64 / 1e9,
                    )),
                );
            } else {
                self.life_emit(
                    "server.block_low",
                    payload(format!(
                        "{} has used {:.0}% of its {:.0} GB block - {:.0} GB left.",
                        st.host,
                        st.pct(),
                        st.total as f64 / 1e9,
                        st.left as f64 / 1e9,
                    )),
                );
            }
        }
    }
}

// The readout arithmetic and the crossing latch. Its own file for the
// size gate, and NOT unix-gated: nothing in it needs a mode bit, so
// gating it would only hide it from windows-clippy.
#[cfg(test)]
#[path = "block_threshold_tests.rs"]
mod block_threshold_tests;
