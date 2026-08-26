//! Which of the user's indexer accounts a background lane speaks to,
//! and what to say when the answer is none (TODO 106 code motion out of
//! daemon.rs).
//!
//! Two lanes ask the same question of the same list. The parity
//! scoreboard asks `scoreboard_reference` for a `(url, apikey)` pair,
//! and `scoreboard_categories` for how many requests a day that will
//! cost. The correctness-confirm lane asks `corr_confirm_reference` for
//! a whole `IndexerConfig`, `corr_confirm_source_state` for the display
//! state of the same verdict, and `corr_confirm_on` for whether it may
//! run at all. `enabled_indexers` is the posture question underneath
//! both: with none of these accounts there is nothing to search but the
//! local index.
//!
//! THE SHARED RULE IS THE REASON THESE ARE ONE MODULE, and it is a rule
//! about someone else's money. A stored SOURCE NAME is resolved to
//! credentials AT CALL TIME, so a key rotation or a URL edit in the
//! indexer editor carries over without either lane noticing; and a
//! named account that has been renamed, deleted or TURNED OFF is an
//! ERROR rather than a silent fall-through, because a disabled account
//! must not keep receiving traffic. `scoreboard_reference` and
//! `corr_confirm_reference` implement that rule twice with one
//! deliberate difference - the confirm lane has no manual URL+key
//! fallback at all, because it FETCHES NZBs, which most indexers meter
//! as grabs, so it may only ever run against an account the user
//! manages where those quotas are visible. Reading the two side by side
//! is what shows that difference is a decision.
//!
//! `corr_confirm_source_state` mirrors `corr_confirm_reference`'s
//! verdict as four display states rather than folding them into one,
//! because each wants a different fix from the user - and because the
//! picker deliberately keeps a vanished account listed, so without it
//! the stats card reads "0 of 24 checks used" while every worker tick
//! is being refused. `scoreboard_categories` FILTERS the built-in set
//! rather than reading a stored one, so no stored value can ever ADD a
//! category: the length of what it returns is the requests-per-day
//! figure the settings card promises.
//!
//! A second `impl Daemon` in a child module of `daemon`, so `Daemon`'s
//! private fields (`indexers`, `scoreboard_source`, `scoreboard_url`,
//! `scoreboard_key`, `scoreboard_cats`, `corr_confirm_source`,
//! `corr_confirm_enabled`, `predb_corr_enabled`) stay in scope exactly
//! as they were inline. `pub(super)` becomes `pub(in crate::serve)`
//! here, because `super` is `daemon` from inside a child; all six are
//! inherent methods on `Daemon`, so nothing needs re-exporting and no
//! call site moves.

use super::*;

impl Daemon {
    /// How many of the user's indexer accounts are configured and on.
    /// The posture question the UI asks in several places: with none of
    /// these there is nothing to search but the local index, and with one
    /// or more the local index is the optional extra.
    pub fn enabled_indexers(&self) -> usize {
        self.indexers.lock_ok().iter().filter(|i| i.enabled).count()
    }

    /// The parity scoreboard's effective reference: `(url, apikey)`.
    ///
    /// When `scoreboard_source` names one of the user's indexer
    /// accounts, that entry's saved URL and key are used - resolved
    /// here, at call time, so a key rotation or URL edit in the indexer
    /// editor carries over without the scoreboard noticing. A named
    /// entry that is missing (renamed, deleted) or turned off is an
    /// error, not a silent fall-through to the manual pair: a disabled
    /// account must not keep receiving traffic. With no name stored,
    /// the manual `scoreboard_url`/`scoreboard_key` pair is the
    /// reference, as before.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn scoreboard_reference(&self) -> Result<(String, String), String> {
        let source = self.scoreboard_source.lock_ok().trim().to_string();
        if !source.is_empty() {
            let list = self.indexers.lock_ok();
            let Some(i) = list.iter().find(|i| i.name == source) else {
                return Err(format!(
                    "the reference indexer \"{source}\" is no longer in your indexer list - pick another"
                ));
            };
            if !i.enabled {
                return Err(format!(
                    "the reference indexer \"{source}\" is turned off in your indexer list"
                ));
            }
            // TODO 297: the scoreboard samples BY CATEGORY with an empty
            // query - `SearchQuery { cats: vec![cat], .. }` once per
            // category - and nzbindex publishes no category space at
            // all. So an nzbindex account cannot be a reference, and
            // saying so here is the difference between one clear
            // sentence and a run that spends a request per category to
            // collect the same refusal each time. The picker lists every
            // indexer account, which is right for the confirm lane
            // beside it (that one is free text plus a grab, which this
            // source does fine) - so the refusal belongs at the use, not
            // in the list.
            if i.kind != crate::newznab::SourceKind::Newznab {
                return Err(format!(
                    "the reference indexer \"{source}\" is an nzbindex account, and the                      scoreboard samples by category - pick a Newznab account instead"
                ));
            }
            return Ok((i.url.clone(), i.apikey.clone()));
        }
        let url = self.scoreboard_url.lock_ok().trim().to_string();
        if url.is_empty() {
            return Err(
                "no reference indexer configured - pick one of your indexer accounts or paste a newznab URL and API key"
                    .to_string(),
            );
        }
        let key = self.scoreboard_key.lock_ok().clone().unwrap_or_default();
        Ok((url, key))
    }

    /// The indexer account the confirm lane searches, resolved by name
    /// at call time (a rotated key carries over). Unlike the
    /// scoreboard there is no manual URL+key fallback: this lane
    /// FETCHES NZBs, which most indexers meter as grabs, so it only
    /// ever runs against an account the user manages in the indexer
    /// editor where those quotas are visible.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn corr_confirm_reference(
        &self,
    ) -> Result<crate::newznab::IndexerConfig, String> {
        let source = self.corr_confirm_source.lock_ok().trim().to_string();
        if source.is_empty() {
            return Err(
                "no confirm indexer configured - pick one of your indexer accounts".to_string(),
            );
        }
        let list = self.indexers.lock_ok();
        let Some(i) = list.iter().find(|i| i.name == source) else {
            return Err(format!(
                "the confirm indexer \"{source}\" is no longer in your indexer list - pick another"
            ));
        };
        if !i.enabled {
            return Err(format!(
                "the confirm indexer \"{source}\" is turned off in your indexer list"
            ));
        }
        Ok(i.clone())
    }

    /// [`Self::corr_confirm_reference`]'s verdict as a display state
    /// for the stats card, mirroring its rule (exists AND enabled) the
    /// way `source_ok` mirrors `scoreboard_reference`. Four distinct
    /// states because each wants a different fix from the user: the
    /// picker deliberately keeps a vanished account listed, so without
    /// this the card reads "0 of 24 checks used" while every worker
    /// tick is refused.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn corr_confirm_source_state(&self) -> &'static str {
        let source = self.corr_confirm_source.lock_ok().trim().to_string();
        if source.is_empty() {
            return "none";
        }
        match self.indexers.lock_ok().iter().find(|i| i.name == source) {
            None => "missing",
            Some(i) if !i.enabled => "disabled",
            Some(_) => "ok",
        }
    }

    /// The categories today's sample will actually ask for, in
    /// [`SCOREBOARD_CATEGORIES`] order. One request each, so the length
    /// of this IS the scoreboard's requests-per-day figure.
    ///
    /// The stored list can only ever SHRINK this: it is filtered
    /// against the built-in set rather than read as one, so no stored
    /// value - not a hand-edited settings.json, not a stale entry from
    /// a future version - can add a category, and the empty default
    /// means "all of them", the most this ever asks for.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn scoreboard_categories(&self) -> Vec<(u32, &'static str)> {
        let picked = self.scoreboard_cats.lock_ok().clone();
        SCOREBOARD_CATEGORIES
            .iter()
            .copied()
            .filter(|(_, label)| picked.is_empty() || picked.iter().any(|p| p == label))
            .collect()
    }

    /// May the indexer-confirm lane spend an attempt right now?
    ///
    /// Two switches, both required - the same rule as the pre feed.
    /// The lane settles CORRELATION suggestions, and the dashboard
    /// presents it as a child of the correlation switch: with
    /// correlation off, the confirm controls grey out. The worker has
    /// to honour that hierarchy too, or it keeps spending the user's
    /// indexer quota (up to CONFIRM_PER_DAY lookups a day) on a lane
    /// the UI says is off and will not let them reach. Requiring both
    /// flags here, rather than having the correlation setter clear
    /// this one, keeps the user's confirm preference across a parent
    /// off/on cycle.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn corr_confirm_on(&self) -> bool {
        self.predb_corr_enabled.load(Ordering::Relaxed)
            && self.corr_confirm_enabled.load(Ordering::Relaxed)
    }
}
