//! The INDEXER block of `apply_setting`'s dispatch table.
//!
//! Third link in the chain the module doc of `settings_apply.rs`
//! describes: `apply_setting` -> `apply_setting_naming` -> here ->
//! `apply_setting_tail`. Every link's `_` arm delegates to the next and
//! only the last one refuses, so an unknown name still gets the same
//! three-way diagnosis it always did, and the arms themselves are
//! untouched - they are disjoint string literals, so which function holds
//! one cannot change what it does.
//!
//! Cut out of `settings.rs` on 7 Sep 2026 (claim
//! `debt-split-hot-files-7sep`): `apply_setting` was 474 lines of the
//! size gate's 500-line function ceiling, and this table only ever grows.
//!
//! A child module of `settings`, so `super::*` names the private `set_*`
//! validators exactly as the inline arms did.

use super::*;

/// The `index_*` settings. Same contract as [`super::apply_setting`]:
/// `(applied_live, persist_value)`. Only reached from
/// [`super::settings_apply_naming::apply_setting_naming`]'s `_` arm.
pub(super) fn apply_setting_index(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok(match name {
        "index_deepen" => {
            // Articles of history added per scan pass; 0 = off.
            let n = uint()?;
            d.index_deepen.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "index_coverage" => {
            // A8: scan the other backbones' tips too (their own marks).
            d.index_coverage.store(flag(), Ordering::Relaxed);
            (true, json!(d.index_coverage.load(Ordering::Relaxed)))
        }
        "index_gapfill" => set_index_gapfill(d, name, v)?,
        "index_fold_secs" => set_index_fold_secs(d, name, v)?,
        "index_probe7z" => {
            // TODO 131 B3: the byte-probe naming lane's kill switch.
            d.index_probe7z.store(flag(), Ordering::Relaxed);
            (true, json!(d.index_probe7z.load(Ordering::Relaxed)))
        }
        "index_probe7z_budget" => set_index_probe7z_budget(d, name, v)?,
        "index_pesto" => {
            // TODO 131 red-team 5a: the pesto rung's kill switch.
            d.index_pesto.store(flag(), Ordering::Relaxed);
            (true, json!(d.index_pesto.load(Ordering::Relaxed)))
        }
        "index_pesto_budget" => set_index_pesto_budget(d, name, v)?,
        "index_nzbimport" => {
            // §131 #6: the posted-NZB ingestion rung's kill switch.
            d.index_nzbimport.store(flag(), Ordering::Relaxed);
            (true, json!(d.index_nzbimport.load(Ordering::Relaxed)))
        }
        "index_nzbimport_budget" => set_index_nzbimport_budget(d, name, v)?,
        "index_search_log" => {
            // §131 D3 search-miss logging. Turning it OFF also clears
            // the table: a privacy switch that leaves the history
            // behind is not one, and this is the user's own search
            // history on the user's own box.
            let on = flag();
            d.index_search_log.store(on, Ordering::Relaxed);
            // TODO 166: _deferred, because this caller has no way to
            // report a busy index - the switch itself has already
            // landed - and an "off" that leaves the history behind is
            // not off. A busy index latches and the searchlog tick
            // retries it on the writer.
            #[cfg(feature = "indexer")]
            if !on {
                d.clear_search_log_deferred();
            }
            (true, json!(d.index_search_log.load(Ordering::Relaxed)))
        }
        _ => apply_setting_tail(d, name, v)?,
    })
}
