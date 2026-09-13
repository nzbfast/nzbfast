//! The NAMING block of `apply_setting`'s dispatch table: everything that
//! decides what a finished file ends up called - whether to rename at
//! all, whether to look an identity up, and which parts of the parsed
//! name each rendered filename carries.
//!
//! Second link in the chain the module doc of `settings_apply.rs`
//! describes: `apply_setting` -> here -> `apply_setting_index` ->
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

/// The renaming and identity settings. Same contract as
/// [`super::apply_setting`]: `(applied_live, persist_value)`. Only
/// reached from that function's `_` arm.
pub(super) fn apply_setting_naming(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok(match name {
        "auto_rename" => {
            let on = flag();
            d.auto_rename.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "identity_lookup" => {
            let on = flag();
            d.identity_lookup.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_resolution" => {
            let on = flag();
            d.rename.resolution.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_vcodec" => {
            let on = flag();
            d.rename.vcodec.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_acodec" => {
            let on = flag();
            d.rename.acodec.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_source" => {
            let on = flag();
            d.rename.source.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_group" => {
            let on = flag();
            d.rename.group.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_year_parens" => {
            let on = flag();
            d.rename.year_parens.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_quality_brackets" => {
            let on = flag();
            d.rename.quality_brackets.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_extra_words" => {
            let on = flag();
            d.rename.extra_words.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_identify" => {
            let on = flag();
            d.rename.identify.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_episode_titles" => {
            let on = flag();
            d.rename.episode_titles.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_junk" => {
            let on = flag();
            d.rename.junk.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_media_only" => {
            let on = flag();
            d.rename.media_only.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "skip_samples" => {
            let on = flag();
            d.skip_samples.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_from_nzb" => {
            let on = flag();
            d.rename.from_nzb.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        _ => apply_setting_index(d, name, v)?,
    })
}
