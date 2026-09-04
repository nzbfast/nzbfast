//! The supported UI locale tags.
//!
//! This is the one item in serve's browser-facing asset code that the
//! DAEMON layer reads: `settings_setters` validates `ui_lang` against it
//! on every build, dashboard feature or not, and refuses an unknown tag
//! with a message that lists this table so the two cannot drift. The
//! catalogues, the manuals and the pages themselves stay in `assets.rs`
//! behind `dashboard`; only the tag list is down here, so a settings
//! write does not make the settings module depend on the asset module.
//!
//! Adding a locale is still one edit here plus the catalogue and the
//! page table - `web/i18n/README.md` step 2 and `web/i18n/HANDOFF.md`
//! name this file for the tag and `assets.rs` for everything else.

/// §5 i18n phase 1: the supported UI locales. Their catalogues are
/// embedded beside the pages in [`super::assets`]; English is the source
/// language and lives inline in the pages, so it has no catalogue.
/// Adding a locale = drop web/i18n/<tag>.json, add it here and to
/// `assets::i18n_catalog` (and LOCALE_NAMES in dashboard.html - both
/// Interface <select>s are built from that one table at boot):
/// translation-only, no new engineering.
/// Tier 1b (21 Jul) added pt/sv/da/nb/fi/tr/ro - UI only; these have no
/// translated manual or website yet, so /manual/<tag> falls back to
/// English and they're absent from the site pickers.
/// Phase 2a added the Slavic set (ru/pl/cs/uk - CLDR one|few|many plurals,
/// handled by tn()'s Intl.PluralRules) plus Greek (el); likewise UI-only.
/// Phase 2c added Japanese (ja) - first CJK locale; no plural forms
/// (CLDR 'other' → .many), CJK font/wrapping rules live in the pages.
/// Phase 2b added Hebrew (he) - first RTL locale (dual .two plurals) - then
/// Arabic (ar, six CLDR plural categories: .zero/.two/.few added) and
/// Persian (fa, two-form) riding the same dir="rtl" + logical-property
/// layout the pages already had.
/// Phase 2a-ext (Central/SE Europe) added hu/sk/hr/sr (Serbian in Latin
/// script; `sh` aliases to it)/bg/sl - sk/hr/sr carry .few plural keys like
/// cs, Slovenian additionally carries the dual (.two); LTR, likewise UI-only.
pub const UI_LOCALES: [&str; 28] = [
    "en", "fr", "de", "it", "es", "nl", "pt", "sv", "da", "nb", "fi", "tr", "ro", "ru", "pl", "cs",
    "uk", "el", "ja", "he", "ar", "fa", "hu", "sk", "hr", "sr", "bg", "sl",
];
