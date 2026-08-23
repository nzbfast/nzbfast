//! `Daemon`'s provider ledger - what each server has cost us (TODO 106
//! code motion out of daemon.rs).
//!
//! One subject read as one thing: bytes billed per server per UTC day
//! (`add_usage`/`save_usage`), the delivered/missing tally behind the
//! reliability figure, and the §96.5 block-account arithmetic on top of
//! both - lifetime bytes, what this block has spent, the refill, and the
//! 30-second flush that makes a mid-run cutoff land on disk.
//!
//! A second `impl Daemon` in a child module of `daemon`, on the
//! daemon_index shape, so `Daemon`'s private fields and daemon.rs's
//! private types stay in scope exactly as they were inline. `pub(super)`
//! became `pub(in crate::serve)` for exactly that reason: `super` is
//! `daemon` here, and every call site is one level up.

use super::*;

impl Daemon {
    /// M18b: bill per-server bytes of a finished download to today's
    /// usage history (UTC days, like the quota) and persist. Best-effort.
    pub(in crate::serve) fn add_usage(&self, per_server: &[(String, u64)]) {
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
        // Keep ~60 date buckets ("YYYY-…" sorts before "lifetime", which
        // is never pruned - block accounts span years; "reliability"
        // survives the prune the same way).
        while u.keys().filter(|k| k.starts_with('2')).count() > 60 {
            let oldest = u.keys().find(|k| k.starts_with('2')).cloned();
            if let Some(k) = oldest {
                u.remove(&k);
            }
        }
        self.save_usage(&u);
    }

    pub(in crate::serve) fn save_usage(&self, u: &serde_json::Map<String, Value>) {
        let path = self.spool.join("usage.json");
        if let Ok(text) = serde_json::to_string_pretty(&Value::Object(u.clone())) {
            let _ = crate::persist::write_atomic(&path, text.as_bytes());
        }
    }

    /// Reliability ledger: accumulate a finished job's per-server article
    /// tries/430s under the never-pruned "reliability" usage bucket -
    /// completion% over lifetime is the keep-subscribing signal.
    pub(in crate::serve) fn add_reliability(&self, per_server: &[(String, u64, u64)]) {
        if per_server.iter().all(|(_, t, _)| *t == 0) {
            return;
        }
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
        self.save_usage(&u);
    }

    /// Lifetime (tried, missing) article counts for `host`, from the
    /// reliability ledger. None until the first finished job recorded any.
    pub(in crate::serve) fn reliability(&self, host: &str) -> Option<(u64, u64)> {
        let u = self.usage.lock_ok();
        let v = u.get("reliability")?.get(host)?;
        let g = |k| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        let (t, m) = (g("tried"), g("missing"));
        (t > 0).then_some((t, m))
    }

    /// Lifetime bytes billed to `host` (block-account accounting).
    pub(in crate::serve) fn usage_lifetime(&self, host: &str) -> u64 {
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
    pub(in crate::serve) fn block_spent(&self, host: &str) -> u64 {
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
    pub(in crate::serve) fn block_refilled(&self, host: &str) {
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
    pub(in crate::serve) fn flush_run_usage(&self) {
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
}
