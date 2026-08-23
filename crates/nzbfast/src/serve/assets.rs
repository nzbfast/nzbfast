use super::*;

/// The dashboard (web/dashboard.html), embedded at compile time so the
/// daemon binary stays a single self-contained file. Edit the html -
/// cargo tracks the include and rebuilds.
pub(super) const DASHBOARD_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../web/dashboard.html"
));

/// The one file in this module that is deliberately NOT embedded: the
/// user's own stylesheet, read from the config folder at request time
/// (issue #31, TODO §140).
///
/// Everything else here is `include_str!` so an install is a single
/// binary, and that is exactly what this file must not be. The whole
/// point is a stylesheet the user edits and reloads - baking it in would
/// mean a rebuild per tweak, which is the thing being asked for. It is
/// also why it is a SEPARATE file rather than an edit to the shipped CSS:
/// it holds only the user's own rules, so an upgrade never touches it.
pub(super) const USER_CSS_FILE: &str = "custom.css";

/// Refuse to serve a stylesheet larger than this. A hand-written CSS file
/// is kilobytes; anything past a megabyte is a mistake (a video dropped in
/// the config folder under the wrong name, a runaway generator), and this
/// body is read and gzipped on every page load.
const USER_CSS_MAX: u64 = 1 << 20;

/// The user's stylesheet, or an empty string when there isn't one.
///
/// Read from disk per request, not cached: the cost is one open+read of a
/// small file per PAGE LOAD (the 1 Hz dashboard polling is JSON on other
/// routes), and `respond_page` puts an ETag over the bytes, so a browser
/// that already has the file revalidates into a 304 instead of
/// re-fetching. An edit therefore shows up on the next reload with no
/// restart and no cache to invalidate.
///
/// A missing file is the normal case and is silent on purpose: it answers
/// with an empty body rather than a 404, so nobody who never wrote one
/// gets a red line in their browser console, and nothing is logged - this
/// path runs on every page load.
///
/// The path is FIXED - the config file's own directory, one hardcoded
/// name. No part of the request reaches it, so there is no traversal
/// surface to defend; a user-settable path would create one.
pub(super) fn user_css(cfg_path: &Path) -> String {
    use std::io::Read as _;
    let path = cfg_path.with_file_name(USER_CSS_FILE);
    let Ok(file) = std::fs::File::open(&path) else {
        return String::new();
    };
    let mut buf = Vec::new();
    // Bounded read: one byte past the cap is enough to know it is over.
    if file.take(USER_CSS_MAX + 1).read_to_end(&mut buf).is_err() {
        return String::new();
    }
    if buf.len() as u64 > USER_CSS_MAX {
        // Not silent, unlike the missing case: this one is a real
        // misconfiguration the user wants to hear about.
        warn!(
            "{} is over {} KB - ignoring it",
            path.display(),
            USER_CSS_MAX / 1024
        );
        return String::new();
    }
    // Lossy rather than strict UTF-8: a stray byte in a comment must not
    // throw away every rule in the file.
    String::from_utf8_lossy(&buf).into_owned()
}

/// Browser icons and the web manifest the pages link to, embedded like the
/// HTML so an install is still a single binary. Returns the body and its
/// content type, or None if the path is not one of ours.
///
/// The pages used to declare an emoji in a `data:` SVG as their only icon.
/// That draws in the tab strip and nowhere else: with no real bitmap, a
/// browser has nothing to hand the OS when a user pins the dashboard, so
/// Windows drew a generated letter tile instead. These are real PNGs, and
/// 16/32 are drawn from the small master rather than downscaled from the
/// large one (packaging/icon/make-favicons.sh).
pub(super) fn web_icon(path: &str) -> Option<(&'static [u8], &'static str)> {
    Some(match path {
        "/icons/favicon-16.png" => (
            &include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/icons/favicon-16.png"
            ))[..],
            "image/png",
        ),
        "/icons/favicon-32.png" | "/favicon.ico" => {
            // /favicon.ico is the path a browser probes when a page declares
            // no icon at all - some surfaces (bare API URLs, error pages)
            // still ask for it, so answer with the 32 px art.
            (
                &include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../web/icons/favicon-32.png"
                ))[..],
                "image/png",
            )
        }
        "/icons/apple-touch-icon.png" => (
            &include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/icons/apple-touch-icon.png"
            ))[..],
            "image/png",
        ),
        "/icons/icon-192.png" => (
            &include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/icons/icon-192.png"
            ))[..],
            "image/png",
        ),
        "/icons/icon-512.png" => (
            &include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/icons/icon-512.png"
            ))[..],
            "image/png",
        ),
        "/site.webmanifest" => (
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/site.webmanifest"
            ))
            .as_bytes(),
            "application/manifest+json",
        ),
        _ => return None,
    })
}

/// M13 poster wall (web/wall.html), embedded the same way.
/// §5 i18n phase 1: the supported UI locales and their catalogues,
/// embedded like the HTML so an install is still a single binary.
/// English is the source language and lives inline in the pages -
/// it has no catalogue. Adding a locale = drop web/i18n/<tag>.json,
/// add it here and to UI_LOCALES (and LOCALE_NAMES in dashboard.html -
/// both Interface <select>s are built from that one table at boot):
/// translation-only, no new engineering.
/// Tier 1b (21 Jul) added pt/sv/da/nb/fi/tr/ro - UI only; these have no
/// translated manual or website yet, so /manual/<tag> falls back to
/// English (below) and they're absent from the site pickers.
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
pub(super) const UI_LOCALES: [&str; 28] = [
    "en", "fr", "de", "it", "es", "nl", "pt", "sv", "da", "nb", "fi", "tr", "ro", "ru", "pl", "cs",
    "uk", "el", "ja", "he", "ar", "fa", "hu", "sk", "hr", "sr", "bg", "sl",
];
/// Name a build-time compressed asset by the key `precompress_pages`
/// wrote it under (crates/nzbfast/build.rs). Spelled out one locale at a
/// time rather than resolved by name at run time, so a translation that
/// loses its file is a compile error naming the key it wanted - not a
/// page that quietly stops being served.
macro_rules! precompressed {
    ($key:literal) => {
        Precompressed {
            gz: include_bytes!(concat!(env!("OUT_DIR"), "/", $key, ".gz")),
            etag: include_str!(concat!(env!("OUT_DIR"), "/", $key, ".etag")),
        }
    };
}

/// The catalogue for a UI locale. English is absent on purpose: it is
/// the source language, it lives inline in the pages, and its catalogue
/// is the empty object the route answers with directly.
pub(super) fn i18n_catalog(lang: &str) -> Option<Precompressed> {
    Some(match lang {
        "fr" => precompressed!("i18n-fr"),
        "de" => precompressed!("i18n-de"),
        "it" => precompressed!("i18n-it"),
        "es" => precompressed!("i18n-es"),
        "nl" => precompressed!("i18n-nl"),
        // Tier 1b - additional Latin-script locales.
        "pt" => precompressed!("i18n-pt"),
        "sv" => precompressed!("i18n-sv"),
        "da" => precompressed!("i18n-da"),
        "nb" => precompressed!("i18n-nb"),
        "fi" => precompressed!("i18n-fi"),
        "tr" => precompressed!("i18n-tr"),
        "ro" => precompressed!("i18n-ro"),
        // Phase 2a - Slavic (ru/pl/cs/uk use CLDR one|few|many plurals) + Greek.
        "ru" => precompressed!("i18n-ru"),
        "pl" => precompressed!("i18n-pl"),
        "cs" => precompressed!("i18n-cs"),
        "uk" => precompressed!("i18n-uk"),
        "el" => precompressed!("i18n-el"),
        // Phase 2c - CJK.
        "ja" => precompressed!("i18n-ja"),
        // Phase 2b - RTL (Hebrew dual; Arabic six-category; Persian two-form).
        "he" => precompressed!("i18n-he"),
        "ar" => precompressed!("i18n-ar"),
        "fa" => precompressed!("i18n-fa"),
        // Phase 2a-ext - hu/bg two-form, sk/hr/sr add .few, sl adds a dual (.two).
        "hu" => precompressed!("i18n-hu"),
        "sk" => precompressed!("i18n-sk"),
        "hr" => precompressed!("i18n-hr"),
        "sr" => precompressed!("i18n-sr"),
        "bg" => precompressed!("i18n-bg"),
        "sl" => precompressed!("i18n-sl"),
        _ => return None,
    })
}

/// The English manual - and the fallback for a UI locale whose manual is
/// not translated yet, so the dashboard's book pill never 404s.
pub(super) const MANUAL_EN: Precompressed = precompressed!("manual-en");

/// Translated manuals.
pub(super) fn manual_i18n(lang: &str) -> Option<Precompressed> {
    Some(match lang {
        "fr" => precompressed!("manual-fr"),
        "de" => precompressed!("manual-de"),
        "it" => precompressed!("manual-it"),
        "es" => precompressed!("manual-es"),
        "nl" => precompressed!("manual-nl"),
        "pt" => precompressed!("manual-pt"),
        "sv" => precompressed!("manual-sv"),
        "da" => precompressed!("manual-da"),
        "nb" => precompressed!("manual-nb"),
        "fi" => precompressed!("manual-fi"),
        "tr" => precompressed!("manual-tr"),
        "ro" => precompressed!("manual-ro"),
        // Phase 2b RTL - the translated pages carry <html dir="rtl">.
        "he" => precompressed!("manual-he"),
        "ar" => precompressed!("manual-ar"),
        "fa" => precompressed!("manual-fa"),
        "en" => MANUAL_EN,
        _ => return None,
    })
}
/// The one design system, shared by the dashboard, the wall and every
/// translation of the manual: the colour tokens plus the pre-paint theme
/// script. Each page carries a `__NZBFAST_UI_TOKENS__` placeholder in its
/// `<head>`; `ui_themed()` substitutes this in.
///
/// Inlined rather than served as `/ui.css` on purpose - an external
/// stylesheet costs a round trip before first paint, which is exactly the
/// flash the pre-paint script exists to avoid.
pub(super) const UI_TOKENS_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../web/ui-tokens.html"
));

/// Inline the shared design tokens into a page.
///
/// Only the two shell pages come through here now: the manuals carry the
/// same substitution, but build.rs folds it in for them (R10 / C9), so
/// nothing re-does it per request.
pub(super) fn ui_themed(page: &str) -> String {
    page.replace("__NZBFAST_UI_TOKENS__", UI_TOKENS_HTML)
}

#[cfg(feature = "indexer")]
pub(super) const WALL_HTML: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/wall.html"));

#[cfg(test)]
mod tests {
    use super::{DASHBOARD_HTML, USER_CSS_FILE, user_css};

    /// Body of `function NAME(` up to its balanced closing brace. The
    /// page has no runtime under `cargo test`, so the tests below read
    /// it as a string; `web/densepack_test.js` and `web/fmt_test.js`
    /// exercise the same code under node, where a developer has one.
    #[cfg(test)]
    fn fn_body(name: &str) -> &'static str {
        let at = DASHBOARD_HTML
            .find(&format!("function {name}("))
            .unwrap_or_else(|| panic!("no function {name} in the dashboard"));
        let start = at + DASHBOARD_HTML[at..].find('{').expect("no body brace");
        let mut depth = 0usize;
        for (i, b) in DASHBOARD_HTML.as_bytes()[start..].iter().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &DASHBOARD_HTML[start..start + i + 1];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced body for {name}");
    }

    /// The cap chip may not read the cap ledger where there is none.
    ///
    /// `renderServers` computed the windowed low with
    /// `kept.length ? min(...) : cl.granted_lo`, and `cl` is undefined
    /// for any server that has never been refused a connection - which
    /// is nearly every server, since the tuner map only gains a host
    /// from a ladder probe or a refusal. The TypeError escaped the
    /// row map, so `#srvlist` stayed blank and `loadSettings` never
    /// reached schedules, feeds, indexers, smart folders, categories,
    /// notifications or automation (Codex sweep 7, H1). The low is
    /// meaningless with no day to attach it to, so it belongs inside
    /// the guard that proves there is one.
    #[test]
    fn the_cap_chip_reads_the_ledger_only_where_it_is_known_to_exist() {
        let b = fn_body("capChip");
        // `cl` may be undefined, so only `cl &&` guarded reads of it are
        // safe anywhere in here. The one that shipped was an unguarded
        // ternary arm, which is what `web/capchip_test.js` exercises.
        for (i, _) in b.match_indices("cl.") {
            assert!(
                b[..i].ends_with("(cl&&") || b[..i].ends_with("cl&&"),
                "an unguarded read of the cap ledger, which most servers do not have: {}",
                &b[i.saturating_sub(60)..(i + 20).min(b.len())]
            );
        }
        assert!(
            b.contains("if(!cdays.length) return ''"),
            "with no day in the window there is nothing to say and nothing to read"
        );
    }

    /// Everything that owns the whole appearance owns every key of it.
    ///
    /// The two density booleans drive the `compact` and `dense` body
    /// classes but sat outside `LOOK_KEYS`, so Reset Appearance left
    /// `uiDense` behind and factory defaults came back dense, while an
    /// exported look could not carry the density it was chosen for
    /// (Codex sweep 7, M8).
    #[test]
    fn reset_export_and_import_own_every_appearance_key() {
        // Whatever `setDense` and `setUiCompact` write is appearance.
        for f in ["setDense", "setUiCompact"] {
            let body = fn_body(f);
            for key in ["uiDense", "uiCompact"] {
                if !body.contains(key) {
                    continue;
                }
                let list = DASHBOARD_HTML
                    .split("const LOOK_FLAGS = ")
                    .nth(1)
                    .and_then(|s| s.split(';').next())
                    .expect("the appearance flag list");
                assert!(
                    list.contains(key),
                    "{f} writes {key}, so reset/export/import must own it"
                );
            }
        }
        for f in ["exportLook", "importLook", "resetAppearance"] {
            assert!(
                fn_body(f).contains("LOOK_ALL"),
                "{f} enumerates appearance keys and must use the complete list"
            );
        }
        // A file that names no layout describes the shipped one. Leaving
        // the recipient's in place made a hybrid the file never was.
        assert!(
            fn_body("importLook").contains("removeItem('layoutPrefs')"),
            "an import with no layout must clear the receiving layout, not keep it"
        );
    }

    /// A compound help tooltip has to be rebuilt when the catalogue
    /// lands, and every one of them, not just the first.
    ///
    /// These are composed from TWO strings, so they carry no
    /// `data-i18n-title` for applyI18n to follow, and injectHelp runs
    /// before the fetch. The restamp named the Queue card by hand and
    /// History was never added, so its tooltip and its accessible label
    /// stayed English on all 27 translated locales while the key it
    /// needed was already in every catalogue (Codex sweep 7, L4).
    #[test]
    fn every_compound_help_label_is_restamped_after_the_catalogue() {
        let hints = fn_body("helpHints");
        let cards: Vec<&str> = hints
            .match_indices("Card:t(")
            .map(|(i, _)| {
                let line = &hints[..i];
                let start = line
                    .rfind(|c: char| !c.is_alphanumeric())
                    .map_or(0, |j| j + 1);
                &hints[start..i + 4]
            })
            .collect();
        assert!(
            cards.len() >= 2,
            "expected the queue and history hints in helpHints: {hints}"
        );
        // One loop over the same map is what makes a third card safe.
        assert!(
            DASHBOARD_HTML.contains("for(const [card,hint] of Object.entries(helpHints()))"),
            "the post-catalogue restamp must walk every compound hint, not name one"
        );
    }

    /// A stack of pinned cards resolves however deep it runs.
    ///
    /// `densePack` deferred a card whose anchor was not placed yet and
    /// drained that list exactly once, in DOM order - so a chain running
    /// backwards through the page (C under B, B under A, DOM reading C,
    /// B, A) auto-placed C while its menu still offered Unstack and the
    /// announcement had already said where it sat (Codex sweep 7, M9).
    #[test]
    fn deferred_card_pins_are_drained_to_a_fixpoint() {
        let b = fn_body("densePack");
        let drain = b
            .split("const wait=[]")
            .nth(1)
            .expect("the deferred-pin list");
        assert!(
            drain.contains("while(pend.length)"),
            "the deferred pins must be drained until a round places nothing, not once"
        );
    }

    /// The user stylesheet is read from disk, so an edit takes effect on
    /// the next page load. If this ever became an `include_str!` the
    /// feature would silently turn into "rebuild to restyle" (§140).
    #[test]
    fn the_user_stylesheet_is_read_from_the_config_folder_not_the_binary() {
        let dir = std::env::temp_dir().join(format!("nzbfast-usercss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.json");

        // No file is the normal case: empty, and nothing said about it.
        assert_eq!(user_css(&cfg), "");

        let css = dir.join(USER_CSS_FILE);
        std::fs::write(&css, "body{background:#123}").unwrap();
        assert_eq!(user_css(&cfg), "body{background:#123}");

        // Read per call, so the SECOND load sees the edit - the whole
        // point of not embedding it.
        std::fs::write(&css, "body{background:#456}").unwrap();
        assert_eq!(user_css(&cfg), "body{background:#456}");

        // Absurdly large is treated as a mistake, not as a stylesheet.
        std::fs::write(&css, "a".repeat((super::USER_CSS_MAX + 1) as usize)).unwrap();
        assert_eq!(user_css(&cfg), "");

        // Nothing in the binary carries the user's rules.
        assert!(!DASHBOARD_HTML.contains("body{background:#456}"));
        // ...and both pages ask for it, last, so it wins on ties.
        const WALL: &str =
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/wall.html"));
        for (page, name) in [(DASHBOARD_HTML, "dashboard"), (WALL, "wall")] {
            let link = page
                .find(r#"<link rel="stylesheet" href="/custom.css">"#)
                .unwrap_or_else(|| panic!("{name} does not link the user stylesheet"));
            let style = page.rfind("</style>").expect("no style block");
            assert!(link > style, "{name} links custom.css before its own CSS");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every API sender the dashboard knows how to NAME also has a glyph,
    /// and every glyph id resolves in the shared sprite. A typo here
    /// renders an empty box that looks like a missing origin (§140).
    #[test]
    fn origin_glyph_ids_resolve_in_the_sprite() {
        const TOKENS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/ui-tokens.html"
        ));
        // `key:'value'` pairs out of a one-line JS object literal.
        let table = |name: &str| -> Vec<(String, String)> {
            let at = DASHBOARD_HTML
                .find(&format!("const {name}="))
                .unwrap_or_else(|| panic!("no {name} table in the dashboard"));
            let body = &DASHBOARD_HTML[at..];
            let body = &body[body.find('{').expect("no table brace") + 1
                ..body.find("};").expect("unterminated table")];
            body.split(',')
                .filter_map(|p| p.split_once(":'"))
                .map(|(k, v)| {
                    (
                        k.trim().trim_matches(['\'', '\n', ' ']).to_string(),
                        v.trim_end_matches('\'').to_string(),
                    )
                })
                .collect()
        };
        let arr = table("ARR_ICON");
        assert!(arr.len() >= 10, "ARR_ICON looks unparsed: {arr:?}");
        for (client, icon) in arr.iter().chain(table("ORIGIN_ICON").iter()) {
            assert!(
                TOKENS.contains(&format!("<g id=\"{icon}\">")),
                "{client} points at {icon}, which is not in the icon sprite"
            );
        }
        // ...and the glyphs written straight into the markup, which the
        // two tables above cannot see. §202 put an `i-help` on the queue
        // row's whyslow verdict; a typo there is the same empty box, and
        // nothing would have caught it.
        // The wall belongs to the indexer stack, so `WALL_HTML` is gated
        // with it and has to be PUSHED rather than listed: as a plain
        // array this did not compile at all under
        // `--no-default-features`, and nothing noticed because
        // `slim-check` has no `--all-targets` and so has never built the
        // slim test targets. Same shape as
        // `every_shell_substitution_is_a_key_field` in webasset.rs.
        #[cfg_attr(not(feature = "indexer"), expect(unused_mut))]
        let mut pages: Vec<(&str, &str)> = vec![("dashboard", DASHBOARD_HTML)];
        #[cfg(feature = "indexer")]
        pages.push(("wall", super::WALL_HTML));
        for (name, page) in pages {
            for at in page.match_indices("<use href=\"#") {
                let rest = &page[at.0 + "<use href=\"#".len()..];
                let icon = &rest[..rest.find('"').expect("unterminated use href")];
                // `href="#${ic}"` is a template hole filled from one of
                // the tables above, which this same test already checks.
                if icon.contains('$') {
                    continue;
                }
                assert!(
                    TOKENS.contains(&format!("<g id=\"{icon}\">")),
                    "{name} references {icon}, which is not in the icon sprite"
                );
            }
        }
        let named = table("API_CLIENT_NAMES");
        assert!(named.len() >= 10, "API_CLIENT_NAMES looks unparsed");
        for (client, _) in &named {
            assert!(
                arr.iter().any(|(c, _)| c == client),
                "{client} has a display name but no glyph - it would fall back \
                 to the generic API mark"
            );
        }
    }

    /// UX §14: a byte formatter may not pair one base with the other's
    /// label.
    ///
    /// `fmtMB` divided by 1024 and printed "GB", so a 100 GiB job read
    /// "100.00 GB" in its own queue row while contributing "107.4 GB" to
    /// the decimal disk-space banner directly above it - the same
    /// download, two numbers, both called GB. The 1024 base is the right
    /// one for release sizes (it is what indexers and SABnzbd quote, and
    /// what the API's `mb` field measures) and stays; the label was the
    /// bug.
    ///
    /// Source-level rather than behavioural because the dashboard has no
    /// runtime under `cargo test` - `web/fmt_test.js` exercises the
    /// arithmetic under node. This one holds the line in CI, where the
    /// page is only ever a string.
    #[test]
    fn byte_formatters_label_the_base_they_divide_by() {
        // Body of `function NAME(` up to its balanced closing brace.
        let body = |name: &str| {
            let at = DASHBOARD_HTML
                .find(&format!("function {name}("))
                .unwrap_or_else(|| panic!("no function {name} in the dashboard"));
            let mut depth = 0usize;
            let bytes = DASHBOARD_HTML.as_bytes();
            let start = at + DASHBOARD_HTML[at..].find('{').expect("no body brace");
            for (i, b) in bytes[start..].iter().enumerate() {
                match b {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            return &DASHBOARD_HTML[start..start + i + 1];
                        }
                    }
                    _ => {}
                }
            }
            panic!("unbalanced body for {name}");
        };
        for name in ["fmtMB", "fmtSize"] {
            let b = body(name);
            assert!(
                !b.contains("unit('MB')") && !b.contains("unit('GB')") && !b.contains("unit('TB')"),
                "{name} is 1024-based and must say MiB/GiB/TiB, not MB/GB/TB"
            );
        }
        for name in ["fmtBytes", "fmtGB"] {
            let b = body(name);
            assert!(
                !b.contains("unit('MiB')")
                    && !b.contains("unit('GiB')")
                    && !b.contains("unit('TiB')"),
                "{name} is 1000-based and must say MB/GB/TB, not MiB/GiB/TiB"
            );
        }
        // Every symbol those formatters ask for has to be in the English
        // table, or unit()'s fallback renders "undefined" in every locale
        // that has no override of its own.
        let en = DASHBOARD_HTML
            .split("const UNIT_EN=")
            .nth(1)
            .and_then(|s| s.split('\n').next())
            .expect("UNIT_EN table");
        for k in ["MB:", "GB:", "TB:", "MiB:", "GiB:", "TiB:"] {
            assert!(en.contains(k), "UNIT_EN is missing {k}");
        }
    }

    /// Raising the queue page size actually refetches the queue.
    ///
    /// `qShowMore` zeroes `dashQRev` and calls `tick()`, but `tick()`
    /// returns early on its `ticking` guard while a poll is in flight,
    /// and that poll's answer overwrites `dashQRev` - so the next poll
    /// sent a live revision with the bigger limit, the daemon answered
    /// "unchanged" with `queue=null`, and the click did nothing. The
    /// window the cached queue was fetched FOR is the durable fact, the
    /// same way `histAppliedWin` guards history.
    #[test]
    fn the_queue_poll_sends_rev_zero_when_its_window_moved() {
        assert!(
            DASHBOARD_HTML.contains("const qrevSent=(qwin===qAppliedWin)?dashQRev:0;"),
            "the queue revision must be gated on the window it was adopted for"
        );
        assert!(
            DASHBOARD_HTML.contains("queue_rev=${qrevSent}")
                && !DASHBOARD_HTML.contains("queue_rev=${dashQRev}"),
            "the poll must send the gated revision, not the raw one"
        );
        assert!(
            DASHBOARD_HTML.contains("if(r.queue){ lastQFull=r.queue; qAppliedWin=qwin; }"),
            "adopting a queue payload must record the window it answered"
        );
    }
}
