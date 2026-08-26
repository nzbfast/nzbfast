//! §290 (Codex sweep 24 Aug, findings F-09 and F-11): the one
//! reserve-then-admit primitive every door that spends a COPY of a
//! release has to pass through.
//!
//! `altcand::AltSettings` documents `alt_max_copies` and
//! `alt_max_extra_bytes` as limits on "this whole mechanism". Before
//! this file there was no such thing as the mechanism: the hunt had a
//! ceiling that read HISTORICAL spend off `Job::downloaded_bytes`, the
//! clicked pick shared it, and `daemon_park::promote_held_alternative`
//! - the one door that ships ON by default - consulted neither limit
//! nor the metered rule at the exact moment payload spend begins.
//!
//! Three holes, one shape, and all three are closed here.
//!
//! 1. **A queued copy at zero progress reserved nothing.** Two
//!    admissions for one target could both read a spend of 0 and both
//!    publish. The bytes a LIVE row commits are its `total_bytes`, not
//!    the bytes it has managed to fetch so far.
//! 2. **The parsed NZB was never weighed.** The byte gate trusted the
//!    indexer's advertised `Cand.size`, so a result that advertises
//!    1 MB and supplies a 100 GB NZB walked through a 1 GB ceiling.
//!    [`Daemon::alt_admit`] is handed the size of what is ACTUALLY
//!    about to start.
//! 3. **Promotion consulted nothing at all.** With the shipped defaults
//!    (`hold_count` 2, `max_copies` 2) the original fails, spare A is
//!    promoted, A fails, and the repointed spare B is promoted as a
//!    THIRD copy.
//!
//! # There is no ledger, and that is the design
//!
//! The obvious build is a table of reservations with a release on every
//! terminal path. It was rejected: a reservation that leaks is a cap
//! that tightens by itself over uptime, which is a worse bug than the
//! one being fixed, and the terminal paths here are many (completed,
//! failed, cancelled, deleted, tombstoned, replaced, restarted). One
//! missed path and the feature silently stops working on a daemon that
//! has been up for a week, with nothing to point at.
//!
//! So the commitment is DERIVED, at admission, from the queue and the
//! history - the two stores that already survive a restart and that
//! already lose a row the instant it is cancelled. **The queue is the
//! ledger.** Nothing can leak, because nothing is written: a deleted
//! row stops counting because it is gone, a completed one settles to
//! what it really spent because that is what its record says, and a
//! daemon that restarts recomputes the same answer off the same files.
//!
//! What a ledger would have bought - atomicity - is bought instead by
//! [`Daemon::alt_gate`]: one mutex, taken by every door, held across
//! the read AND the publication. Two admissions for one target cannot
//! both see pre-publication state, which is the whole of F-09's race.
//!
//! # What counts as a copy, and why it is not "everything named alike"
//!
//! The tempting rule - every row whose name parses to this episode - is
//! wrong in a way that would refuse the default. A user who downloaded
//! this episode last month has a history row for it, and counting that
//! would refuse the very first promotion on an install that has never
//! used the mechanism at all.
//!
//! So the population is the mechanism's OWN chain. Every alternate
//! carries `alt_from` naming the row it replaced - `hunt::hunt_enqueue`,
//! `daemon_park::promote_held_alternative` and `altcand::alt_switch` all
//! stamp it, which is what makes this possible - so the copies spent on
//! one target are the transitive closure of that link, walked in both
//! directions from the row being replaced. Backwards it reaches the
//! original the user actually asked for; forwards it reaches a sibling
//! another door published a moment ago, which is F-09's second racer.
//!
//! A HELD SPARE is not in it, and must not be: a spare is an NZB file
//! and never a byte of payload (`spare`'s header states that as the
//! reason the whole feature is affordable), and it carries no `alt_from`
//! until something promotes it. Promotion is the moment spend begins,
//! and therefore the moment to weigh it.
//!
//! Two things join the chain besides the link. A row carrying a
//! `hunt:<target>` origin for one of these keys joins even if its stamp
//! were somehow lost, because that origin is what the hunt's own byte
//! accounting has always keyed on. And the §96.3 breaker's stems for
//! these targets join the COPY count, which is where the cross-restart,
//! cross-retention evidence lives - it is the count the hunt already
//! shipped, kept rather than replaced, and it expires on its own after
//! 45 days.
//!
//! # The original is a copy but not a spend
//!
//! `max_copies` is "how many copies of one release this whole mechanism
//! may spend, the original included", so the row being replaced counts
//! toward the COPY count. `max_extra_bytes` is "bytes an alternate may
//! add on top of the original grab", so the original's bytes do NOT
//! count toward the BYTE total. The root of the chain is therefore in
//! one sum and out of the other, which is not an inconsistency: they
//! are two different settings answering two different questions.

use super::*;

use super::hunt::{NoHunt, Trigger, affordable, hunt_target};
use std::collections::{BTreeMap, BTreeSet};

/// The target one admission is accounted against: the row a new copy
/// would replace, plus the identity keys that row was parsed to.
///
/// A snapshot rather than the `Arc<Mutex<Job>>`, for the reason
/// `hunt::HuntRequest` gives: by the time an admission runs the record
/// may have been filed, retried or deleted, and every fact the decision
/// turns on is fixed at the moment the door was opened.
pub(super) struct AltCtx {
    /// The row being replaced.
    pub id: String,
    pub name: String,
    /// That row's OWN predecessor, when it is itself an alternate. The
    /// chain walk below can find this too, but only if the predecessor
    /// is still in a store; carrying it means a chain whose middle has
    /// been deleted from history still counts its stem.
    pub from_id: String,
    pub from_name: String,
    /// `giveup::target_keys` for the release. Empty for a name that
    /// carries no identity (obfuscated, music), which costs the
    /// hunt-origin and breaker arms and leaves the chain arm intact.
    pub keys: Vec<String>,
}

/// One row of the derived ledger, snapshotted out from under the store
/// locks so the arithmetic below holds none of them.
struct Row {
    id: String,
    name: String,
    from: String,
    from_name: String,
    origin: String,
    /// What this row has committed: its FULL size while it is live, and
    /// only what it actually fetched once it is terminal or cancelled.
    /// That difference is F-09's first hole - a live row at zero
    /// progress committing zero - and it is also the release: a
    /// cancelled row stops reserving the bytes it will now never spend.
    bytes: u64,
}

impl Daemon {
    /// Take the admission gate. Held across the ledger read AND the
    /// publication, by every door, or the read is a snapshot of a world
    /// that has already moved.
    ///
    /// Lock order is **gate before store**: every caller takes this,
    /// then the queue/history/job locks underneath. Nothing may take it
    /// while holding one of those.
    pub(in crate::serve) fn alt_gate(&self) -> std::sync::MutexGuard<'_, ()> {
        self.alt.admit.lock_ok()
    }

    /// Build the context for a row this daemon is about to replace,
    /// reading its `alt_from` stamp out of whichever store still has it.
    pub(in crate::serve) fn alt_ctx(&self, id: &str, name: &str, keys: Vec<String>) -> AltCtx {
        let found = self
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == id)
            .cloned()
            .or_else(|| self.history_job(id));
        let (from_id, from_name) = found
            .map(|j| {
                let g = j.lock_ok();
                (g.alt_from.clone(), g.alt_from_name.clone())
            })
            .unwrap_or_default();
        AltCtx {
            id: id.to_string(),
            name: name.to_string(),
            from_id,
            from_name,
            keys,
        }
    }

    /// Every alternate on record, live or terminal, as `Row`s.
    ///
    /// ALTERNATES ONLY - a row with no `alt_from` and no `hunt:` origin
    /// is either the original or an ordinary download, and neither is
    /// this mechanism's spending. That is also what keeps this cheap on
    /// a 15,000-row queue: the population is the handful of rows some
    /// door published, not the store.
    ///
    /// The queue reading WINS when a row is momentarily in both stores
    /// (park pushes to history before it retains out of the queue), so
    /// a job mid-park is weighed as live rather than settled twice.
    fn alt_rows(&self) -> Vec<Row> {
        let mut out: BTreeMap<String, Row> = BTreeMap::new();
        let take = |g: &Job, live: bool| -> Option<Row> {
            if g.alt_from.is_empty() && hunt_target(&g.origin).is_none() {
                return None;
            }
            // A tombstoned row is the user's own delete landing mid
            // flight: the bytes it has already fetched are spent, and
            // the ones it has not are released. Same arithmetic as a
            // terminal row, which is what it is about to become.
            let bytes = if live && !g.tombstone {
                g.total_bytes.max(g.downloaded_bytes)
            } else {
                g.downloaded_bytes
            };
            Some(Row {
                id: g.nzo_id.clone(),
                name: g.name.clone(),
                from: g.alt_from.clone(),
                from_name: g.alt_from_name.clone(),
                origin: g.origin.clone(),
                bytes,
            })
        };
        for j in self.queue.lock_ok().iter() {
            if let Some(r) = take(&j.lock_ok(), true) {
                out.insert(r.id.clone(), r);
            }
        }
        for j in self.history.lock_ok().iter() {
            if let Some(r) = take(&j.lock_ok(), false) {
                out.entry(r.id.clone()).or_insert(r);
            }
        }
        out.into_values().collect()
    }

    /// Copies spent and bytes committed for this target, right now.
    ///
    /// Returns `(distinct release stems, alternate bytes)`. Both are
    /// derived; neither is stored. See the module header for why.
    fn alt_committed(&self, ctx: &AltCtx) -> (u32, u64) {
        let rows = self.alt_rows();
        // Seed: the row being replaced, and its own predecessor.
        let mut ids: BTreeSet<String> = BTreeSet::new();
        ids.insert(ctx.id.clone());
        if !ctx.from_id.is_empty() {
            ids.insert(ctx.from_id.clone());
        }
        // A hunted row for one of these targets joins outright: the
        // `hunt:<target>` origin is what that road's accounting has
        // always keyed on, and it survives a lost stamp.
        for r in &rows {
            if hunt_target(&r.origin).is_some_and(|k| ctx.keys.iter().any(|w| w == k)) {
                ids.insert(r.id.clone());
            }
        }
        // Transitive closure of `alt_from`, BOTH ways. Forwards reaches
        // the sibling another door published a moment ago (F-09's
        // racer); backwards reaches the original the user asked for,
        // which is what stops a chain resetting its own budget at every
        // hop (F-11's third copy).
        loop {
            let mut add: Vec<String> = Vec::new();
            for r in &rows {
                if !r.from.is_empty() && ids.contains(&r.from) && !ids.contains(&r.id) {
                    add.push(r.id.clone());
                }
                if !r.from.is_empty() && ids.contains(&r.id) && !ids.contains(&r.from) {
                    add.push(r.from.clone());
                }
            }
            if add.is_empty() {
                break;
            }
            ids.extend(add);
        }
        // DISTINCT STEMS, not rows: a retry of one dead release is one
        // copy and not two, which is the rule `giveup::record_failure`
        // already applies to the evidence it keeps.
        let mut stems: BTreeSet<String> = BTreeSet::new();
        stems.insert(ctx.name.clone());
        if !ctx.from_name.is_empty() {
            stems.insert(ctx.from_name.clone());
        }
        let mut bytes: u64 = 0;
        for r in &rows {
            if !ids.contains(&r.id) {
                continue;
            }
            stems.insert(r.name.clone());
            if !r.from_name.is_empty() {
                stems.insert(r.from_name.clone());
            }
            bytes = bytes.saturating_add(r.bytes);
        }
        if !ctx.keys.is_empty() {
            let st = self.giveup.lock_ok();
            for k in &ctx.keys {
                if let Some(t) = st.targets.get(k) {
                    stems.extend(t.stems.iter().cloned());
                }
            }
        }
        (stems.len() as u32, bytes)
    }

    /// May one more copy of this target be started, costing `want`
    /// bytes? Call it under [`Daemon::alt_gate`], and publish before
    /// dropping that guard.
    ///
    /// `want` is the size of what is ACTUALLY about to run - the parsed
    /// NZB's `total_bytes`, never an indexer's advertised figure. 0
    /// means unknown, and `affordable` refuses an unknown size while a
    /// ceiling is in force, because a ceiling that cannot bound what it
    /// is spending is not a ceiling.
    ///
    /// `trigger` changes exactly one refusal, the same one it changes
    /// on the hunt road: an "unlimited" ceiling is refused on a metered
    /// install when the DAEMON decided, and honoured when a person just
    /// clicked. A ceiling the user actually set applies on both.
    pub(in crate::serve) fn alt_admit(
        &self,
        ctx: &AltCtx,
        want: u64,
        trigger: Trigger,
    ) -> std::result::Result<(), NoHunt> {
        let policy = self.hunt_policy();
        let (copies, spent) = self.alt_committed(ctx);
        if copies >= policy.max_copies {
            return Err(NoHunt::CopyCap(copies));
        }
        if policy.max_extra_bytes == 0 {
            return if trigger == Trigger::Auto && self.hunt_metered() {
                Err(NoHunt::MeteredNoBudget)
            } else {
                Ok(())
            };
        }
        if spent >= policy.max_extra_bytes {
            return Err(NoHunt::ByteCap);
        }
        if !affordable(want, Some(policy.max_extra_bytes - spent)) {
            return Err(NoHunt::ByteCap);
        }
        Ok(())
    }

    /// The clicked switch's admission, as one sentence or nothing.
    ///
    /// `altcand::alt_switch` is the door §282 item 12 calls "the default
    /// posture ... safe on any account type", and it stayed that way:
    /// the copy and byte ceilings are numbers the user CHOSE and apply
    /// here exactly as they do on the automatic road, while the metered
    /// refusal - which stands in for consent the daemon does not have -
    /// stands down, because a person is giving that consent right now
    /// about this one release. That is `hunt::Trigger`'s contract, and
    /// it is spelled once here rather than twice.
    ///
    /// `None` when either row cannot be resolved: the switch's own five
    /// refusal arms say what happened in the user's words, and a
    /// duplicate guess from here would be a worse sentence about the
    /// same fact.
    ///
    /// It also carries the post-fetch weighing for `hunt::hunt_pick`,
    /// which parks its fetched copy as a held spare and then promotes it
    /// through this same door: the spare's `total_bytes` is the parsed
    /// NZB's real size, so an indexer that under-reported is caught here
    /// with the row still held and nothing downloaded (F-09).
    pub(super) fn alt_switch_admit(&self, failed_id: &str, spare_id: &str) -> Option<String> {
        let find = |id: &str| -> Option<Arc<Mutex<Job>>> {
            self.queue
                .lock_ok()
                .iter()
                .find(|j| j.lock_ok().nzo_id == id)
                .cloned()
        };
        let failed = find(failed_id).or_else(|| self.history_job(failed_id))?;
        let want = find(spare_id)?.lock_ok().total_bytes;
        let name = failed.lock_ok().name.clone();
        let keys = super::giveup::target_keys(&crate::wall::parse_release(&name));
        let ctx = self.alt_ctx(failed_id, &name, keys);
        self.alt_admit(&ctx, want, Trigger::Clicked)
            .err()
            .map(|no| no.why())
    }
}

#[cfg(test)]
#[path = "altspend_tests.rs"]
mod altspend_tests;
