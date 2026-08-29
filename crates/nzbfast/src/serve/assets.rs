// Every consumer of the parent module here (`Path` for the stylesheet,
// `warn!` for its size refusal, `Precompressed` for the catalogues and
// manuals) belongs to the browser-facing half, so with `dashboard` off
// this file needs nothing from `super` - while still owning UI_LOCALES,
// which the settings boundary reads on every build. Gating the IMPORT
// rather than waiving `unused_imports` over it: a waiver would suppress
// the lint for whatever this glob grows to import next, where the cfg
// says exactly what is true and nothing more.
#[cfg(feature = "dashboard")]
use super::*;

/// The dashboard (web/dashboard.html), embedded at compile time so the
/// daemon binary stays a single self-contained file. Edit the html -
/// cargo tracks the include and rebuilds.
#[cfg(feature = "dashboard")]
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
#[cfg(feature = "dashboard")]
pub(super) const USER_CSS_FILE: &str = "custom.css";

/// Refuse to serve a stylesheet larger than this. A hand-written CSS file
/// is kilobytes; anything past a megabyte is a mistake (a video dropped in
/// the config folder under the wrong name, a runaway generator), and this
/// body is read and gzipped on every page load.
#[cfg(feature = "dashboard")]
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
#[cfg(feature = "dashboard")]
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
///
/// The manifest also makes the dashboard installable as an app. Note what
/// that binds it to: a browser identifies an installed app by its manifest
/// `id` RESOLVED AGAINST THE ORIGIN, and the origin carries the port - so a
/// daemon that moves from 6789 to 6790 is a different app to the browser and
/// the old install is orphaned. Harmless (reinstall from the new port), but
/// it is why the port is persisted rather than re-scanned every launch. The
/// same rule is why plain-http access from another machine on the LAN offers
/// no install at all: 127.0.0.1 is a secure context by definition and
/// http://192.168.x.x is not.
#[cfg(feature = "dashboard")]
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
        // The maskable pair. A launcher that installs the dashboard as an
        // app draws the icon inside its own silhouette, and handed only
        // "any" art it insets the whole tile and fills the gap - so our
        // rounded tile ends up as a small square on a white or grey
        // circle. These bleed to the edge with the artwork inside the
        // safe zone instead (packaging/icon/icon-maskable.svg).
        "/icons/icon-192-maskable.png" => (
            &include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/icons/icon-192-maskable.png"
            ))[..],
            "image/png",
        ),
        "/icons/icon-512-maskable.png" => (
            &include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/icons/icon-512-maskable.png"
            ))[..],
            "image/png",
        ),
        // Manifest screenshots. Chromium shows these in the install
        // dialog, and WITHOUT a wide one it shows the plain one-line
        // prompt instead, so their absence is not a missing decoration -
        // it is a different dialog. Generated by
        // packaging/icon/make-screenshots.sh from the website's captures.
        "/screens/dash-wide.jpg" => (
            &include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/screens/dash-wide.jpg"
            ))[..],
            "image/jpeg",
        ),
        "/screens/dash-narrow.jpg" => (
            &include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/screens/dash-narrow.jpg"
            ))[..],
            "image/jpeg",
        ),
        // The web manifest. Its two colours are a judgement and not a
        // copy of the token pair in the pages: it paints an installed window
        // before this page has said anything: `background_color` is the
        // splash shown while the document loads, and `theme_color` is the
        // title bar (and, under display_override, the window-controls
        // overlay strip) until the page's own <meta name="theme-color">
        // takes over. Both are SINGLE values - a manifest carries no media
        // variants and no custom properties - so one theme has to be
        // chosen for the moment before there is a page to ask.
        //
        // Both are the DARK --bg, #0e1014, because that is what this app
        // is when nothing else is known: ui-tokens.html's bare `:root` is
        // the dark palette, and light arrives only from a
        // prefers-color-scheme match or an explicit data-theme. A
        // light-theme user therefore sees one dark frame before the page
        // paints; a dark-theme one sees no seam at all, and so does
        // everybody on the shipped default. The values before this
        // (#0f1116 splash, #5aa8ff bar) were in NEITHER theme and are not
        // any token's value at all, so an installed window painted a blue
        // title bar over a near-black page.
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
#[cfg(feature = "dashboard")]
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
#[cfg(feature = "dashboard")]
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
#[cfg(feature = "dashboard")]
pub(super) const MANUAL_EN: Precompressed = precompressed!("manual-en");

/// Translated manuals.
#[cfg(feature = "dashboard")]
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
#[cfg(feature = "dashboard")]
pub(super) const UI_TOKENS_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../web/ui-tokens.html"
));

/// The one press/warning/error sound engine, shared by the dashboard and
/// the wall: the master switch, the preferences, the WebAudio synth, the
/// sixteen press recipes, the classifier that picks one for a control,
/// and the four global hooks. Each shell page carries a
/// `__NZBFAST_UI_SOUND__` placeholder in its `<head>`; `ui_themed()`
/// substitutes this in.
///
/// NOT folded into `UI_TOKENS_HTML` beside it, and the reason is the
/// manuals: build.rs substitutes the tokens into all sixteen of them at
/// build time (R10 / C9), and a manual has no controls to acknowledge -
/// it would be carrying an audio engine sixteen times over for nothing.
/// The tokens reach every page nzbfast serves; this reaches every page
/// that has something to press.
#[cfg(feature = "dashboard")]
pub(super) const UI_SOUND_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../web/ui-sound.html"
));

/// Inline the shared design tokens and sound engine into a page.
///
/// Only the two shell pages come through here now: the manuals carry the
/// tokens substitution, but build.rs folds it in for them (R10 / C9), so
/// nothing re-does it per request - and they carry no sound placeholder
/// at all, which is why that half is only here.
#[cfg(feature = "dashboard")]
pub(super) fn ui_themed(page: &str) -> String {
    page.replace("__NZBFAST_UI_TOKENS__", UI_TOKENS_HTML)
        .replace("__NZBFAST_UI_SOUND__", UI_SOUND_HTML)
}

#[cfg(feature = "indexer")]
pub(super) const WALL_HTML: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/wall.html"));

#[cfg(all(test, feature = "dashboard"))]
mod tests {
    use super::{DASHBOARD_HTML, USER_CSS_FILE, user_css, web_icon};

    /// The web manifest, read the way a browser reads it.
    const MANIFEST: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../web/site.webmanifest"
    ));

    /// (width, height) of a PNG or JPEG, from its bytes.
    ///
    /// Hand-rolled because the alternative is an image crate in the
    /// dependency tree for two numbers. PNG carries them in the IHDR,
    /// which is always the first chunk; JPEG needs the segment walk,
    /// because the frame header sits after an arbitrary run of APPn
    /// and quantisation tables.
    fn png_or_jpeg_size(b: &[u8]) -> (u32, u32) {
        let be = |s: &[u8]| u32::from_be_bytes([s[0], s[1], s[2], s[3]]);
        if b.starts_with(b"\x89PNG\r\n\x1a\n") {
            assert_eq!(&b[12..16], b"IHDR", "PNG does not open with IHDR");
            return (be(&b[16..20]), be(&b[20..24]));
        }
        assert_eq!(&b[..2], &[0xff, 0xd8], "neither a PNG nor a JPEG");
        let mut i = 2;
        while i + 9 < b.len() {
            assert_eq!(b[i], 0xff, "lost JPEG segment alignment at {i}");
            let marker = b[i + 1];
            let len = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
            // Every SOFn but the four that are not frame headers
            // (0xc4 DHT, 0xc8 reserved, 0xcc DAC).
            if (0xc0..=0xcf).contains(&marker) && !matches!(marker, 0xc4 | 0xc8 | 0xcc) {
                let h = u16::from_be_bytes([b[i + 5], b[i + 6]]) as u32;
                let w = u16::from_be_bytes([b[i + 7], b[i + 8]]) as u32;
                return (w, h);
            }
            i += 2 + len;
        }
        panic!("no JPEG frame header");
    }

    /// Every asset the manifest names is actually served, with the type
    /// and the pixel size it claims.
    ///
    /// This is the whole install path's single point of silent failure.
    /// A browser that cannot fetch a manifest icon, or that finds one
    /// whose real size is not the `sizes` it declared, does not report
    /// an error anywhere a user or a log will see - it just stops
    /// offering to install, and the Settings row keys off that offer, so
    /// the symptom is a row that has quietly gone missing. Adding an
    /// icon or a screenshot and forgetting its `web_icon` arm is the
    /// easy way to cause it (they are two files apart), which is what
    /// this test is here to refuse.
    #[test]
    fn every_manifest_asset_is_served_at_the_size_it_declares() {
        let m: serde_json::Value = serde_json::from_str(MANIFEST).expect("manifest is not JSON");
        // `id` resolved against the origin is what a browser calls this
        // app. Without it the identity falls back to start_url, so a
        // later start_url change would orphan every existing install.
        assert_eq!(m["id"], "/", "the manifest must pin its own id");
        let mut checked = 0;
        for group in ["icons", "screenshots"] {
            let arr = m[group].as_array().unwrap_or_else(|| panic!("no {group}"));
            assert!(!arr.is_empty(), "{group} is empty");
            for e in arr {
                let src = e["src"].as_str().expect("asset with no src");
                let (body, mime) = web_icon(src)
                    .unwrap_or_else(|| panic!("{src} is in the manifest but web_icon serves it"));
                assert_eq!(e["type"].as_str(), Some(mime), "{src}: wrong content type");
                let (w, h) = png_or_jpeg_size(body);
                assert_eq!(
                    e["sizes"].as_str(),
                    Some(format!("{w}x{h}").as_str()),
                    "{src}: declared sizes do not match the file"
                );
                checked += 1;
            }
        }
        assert!(checked >= 6, "only {checked} manifest assets found");
        // Chromium shows the richer install dialog only when a WIDE
        // screenshot is present; with none it falls back to a one-line
        // prompt, so losing this entry is a UI regression with no error.
        assert!(
            m["screenshots"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["form_factor"] == "wide"),
            "no wide screenshot: the install dialog falls back to its plain form"
        );
        // A launcher handed only "any" art insets the whole tile inside
        // its mask and fills the gap, which is the icon bug these were
        // drawn to fix (packaging/icon/icon-maskable.svg).
        for want in ["192x192", "512x512"] {
            assert!(
                m["icons"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|i| i["purpose"] == "maskable" && i["sizes"] == want),
                "no {want} maskable icon"
            );
        }
    }

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

    /// §282 item 18: the switch MOMENT reaches an open tab, and it
    /// reads the keys the daemon actually sends.
    ///
    /// Three daemon doors swap the release the user queued for another
    /// one and every one of them announces it -
    /// `Daemon::promote_held_alternative` and `altcand::alt_switch` as
    /// `job.switched`, `hunt::hunt_enqueue` as `job.replaced`, all under
    /// one payload shape. A webhook subscriber heard all three from the
    /// day item 18 closed; `handleLifeEvents` dispatches on `e.kind`
    /// through a chain with NO fallthrough arm and carried neither kind,
    /// so an open dashboard heard none of it and a release name nobody
    /// clicked simply appeared in the queue.
    ///
    /// **WHAT THIS PINS THAT NOTHING ELSE DOES.** The i18n gate holds
    /// the four strings to 27 catalogues, and
    /// `hunt_tests::a_hunted_replacement_announces_itself_in_the_promote_doors_vocabulary`
    /// holds the EMIT to its key names - but nothing held the READER to
    /// them. A rename of `replaces_name` on the page is invisible to
    /// both: the toast simply renders "undefined could not finish", in
    /// 27 languages, with every gate green. So the key names are
    /// asserted here on the page side and there on the daemon side, and
    /// they meet in the middle at these literals. Move one and move the
    /// other in the same commit.
    #[test]
    fn the_dashboard_narrates_a_switch_with_the_keys_the_daemon_sends() {
        let body = fn_body("handleLifeEvents");
        assert!(
            body.contains("e.kind==='job.switched'") && body.contains("e.kind==='job.replaced'"),
            "handleLifeEvents must dispatch on both switch kinds"
        );
        for key in ["e.replaces_name", "e.replaces", "e.by", "e.name"] {
            assert!(
                body.contains(key),
                "the switch arm must read {key} - it is a key all three doors send"
            );
        }
        // The clicked door says nothing: `altSwitch()` already toasts
        // off the API response and its own `tick()` pulls this event in
        // the same breath, so an arm that fired here would clobber the
        // confirmation the user's own click earned.
        assert!(
            body.contains("e.by!=='user'"),
            "the user-clicked door must be suppressed by `by`, not narrated twice"
        );
        // A switch in the batch disarms the failure alarm for the row it
        // replaces. The toast would be clobbered anyway; the desktop
        // NOTIFICATION would not, and it said "Download FAILED" about a
        // download that had already been replaced.
        assert!(
            body.contains("switchedFor.set(e.replaces, e)")
                && body.contains("switchedFor.has(e.nzo_id)"),
            "a same-batch replacement must suppress the failed row's alarm"
        );
    }

    /// §129 1b(b)'s four cues reach the page, and each one reaches it
    /// through EVERY door the daemon can raise it from.
    ///
    /// The failure this pins is silence, which is the one thing no other
    /// check in this repo can see. `handleLifeEvents` dispatches on
    /// `e.kind` through a chain with NO fallthrough arm, so a kind it
    /// does not name is dropped without a word - that is exactly how
    /// `job.switched` and `job.replaced` were heard by every webhook
    /// subscriber and by no open dashboard for four hours. A cue lost
    /// this way leaves the emit test green, the i18n gate green (the
    /// string is still in all 27 catalogues, just never rendered) and
    /// every build-free gate green.
    ///
    /// THE ARRIVAL PAIR IS THE POINT. `job.added` alone looks like the
    /// whole of "a row reached the queue" and is not: a retry never goes
    /// near `enqueue`, it comes back through `commit_to_queue`, which is
    /// what emits `job.requeued`. Drop that half and a manual retry
    /// makes no sound at all - the specific regression §129 1b(b) was
    /// held back two days to avoid.
    #[test]
    fn the_dashboard_hears_every_cue_that_left_the_queue_payload() {
        let body = fn_body("handleLifeEvents");
        for kind in [
            // Both arrival doors, and both are load-bearing.
            "job.added",
            "job.requeued",
            // "All done", pause/resume, and the update chime.
            "queue.idle",
            "queue.paused",
            "queue.resumed",
            "update.available",
        ] {
            assert!(
                body.contains(&format!("e.kind==='{kind}'")),
                "handleLifeEvents must dispatch on {kind} - a kind it does not name \
                 is dropped in silence, with every other gate green"
            );
        }
        // The "all done" guard. `queue.idle` is every drain, including
        // the user deleting the last row; the cue is only for a drain
        // something FINISHED into, which `job.completed` stamps.
        assert!(
            body.contains("lastCompleteAt"),
            "the all-done cue must still be gated on a recent completion, or \
             deleting the last queued row announces that everything finished"
        );
        // The promote door plays the arrival sound by hand, because the
        // spare it promotes was enqueued when it was HELD and emits no
        // arrival now. The hunt door must NOT, because its replacement
        // is an enqueue and `job.added` is in the same batch.
        assert!(
            body.contains("if(e.kind==='job.switched') snd('added')"),
            "the promote door is the only switch door that owes its own arrival sound"
        );
    }

    /// A batch of lifecycle events may not clobber itself down to one
    /// sentence.
    ///
    /// `toast()` writes into ONE element: it clears the node, rebuilds
    /// it and resets one timer, so the last caller in a tick wins and
    /// every earlier one is destroyed without ever having been painted -
    /// not shortened, never shown at all. `handleLifeEvents` walks the
    /// whole batch since the page's cursor, which is routinely more than
    /// one event (two jobs failing into held spares in one poll is two
    /// `job.switched`; a completion racing a failover is two more), and
    /// every arm but the `kept[]` collapse used to call `toast()`
    /// inline. So the arms COLLECT and `toastRun` plays the batch.
    ///
    /// Pinned here because the defect is invisible from every other
    /// angle: a new arm written the obvious way - copying the `toast(`
    /// call from the arm above it, which is how the twelve got there -
    /// compiles, renders, translates and ships, and silently destroys
    /// whatever the batch had already said.
    #[test]
    fn a_batch_of_life_events_is_played_rather_than_clobbered() {
        let body = fn_body("handleLifeEvents");
        assert!(
            !body.contains("toast("),
            "no arm may toast directly - collect with notice() and let toastRun play the batch"
        );
        assert!(
            body.contains("toastRun(notices)"),
            "the collected batch must be handed to toastRun"
        );
        // Importance, not arrival. A red failure and "picked up a file
        // from the watch folder" are not equally worth the one box
        // there is, and an unsorted hand-off would give the slots to
        // whichever events the daemon happened to emit first.
        assert!(
            body.contains("notices.sort((a,b)=>b.prio-a.prio)"),
            "the batch must be ordered by importance before it is played"
        );
        // Every arm carries a tier. A `notice()` call that forgot one
        // would sort as 0 and lose its slot to a completion.
        // `const notice=(...)` is not a CALL, so the left side counts
        // exactly the arms; the right subtracts the one declaration of
        // each tier name.
        assert_eq!(
            body.matches("notice(").count(),
            body.matches("P_ACT").count()
                + body.matches("P_ENGINE").count()
                + body.matches("P_GOOD").count()
                - 3,
            "every notice() call must name a priority tier"
        );
    }

    /// The run player may not lose what `toast()` builds as NODES.
    ///
    /// The hidden `Error:` prefix is what makes an error toast an error
    /// for a screen reader (border colour alone is not), and the
    /// `- details` affordance is a separate node because the live region
    /// reads `textContent` - without its leading space a screen reader
    /// hears the last word run into it ("errors- details"). Both live in
    /// `toastShow` now, which is the ONE renderer: `toast()` and the run
    /// player both go through it, so a second code path cannot grow
    /// beside it and quietly ship a box with neither.
    #[test]
    fn every_toast_goes_through_the_one_renderer() {
        let show = fn_body("toastShow");
        assert!(
            show.contains("a11y.error") && show.contains("sr-only"),
            "the hidden error prefix must survive in the renderer"
        );
        assert!(
            show.contains("toast.details") && show.contains("' '+t('toast.details'"),
            "the details affordance must stay a NODE with its leading space"
        );
        // The public door is a thin wrapper, and it CANCELS a run: a
        // direct toast answers something the user just did, and making
        // them sit through the rest of a batch to see it would be the
        // clobber this whole change is about, pointed the other way.
        let outer = fn_body("toast");
        assert!(
            outer.contains("toastRunQ=[]") && outer.contains("toastMore=0"),
            "a direct toast must displace a run in flight"
        );
        assert!(
            outer.contains("toastShow(msg, bad, go, TOAST_MS)"),
            "the single-message lifetime must be unchanged"
        );
        // The overflow line is the last slot of a capped run, and it is
        // the only part of this that is a COUNT: it stands for several
        // messages with several different rows behind them, so it has no
        // `go` (a box that picks one of them at random is worse than a
        // box that picks none) and it is counted with the plural
        // machinery, not with a bare number.
        let next = fn_body("toastNext");
        assert!(
            next.contains("tn('toast.more'") && next.contains(", false, null,"),
            "the overflow line must be plural-aware and carry no destination"
        );
    }

    /// A toast that claims to be a button has to answer a key press.
    ///
    /// The click-through sets `role="button"` and `tabindex="0"`, so it
    /// announces itself as a button and takes a tab stop - and it
    /// answered a mouse click and nothing else. Surveyed 24 Aug 2026:
    /// every other `role="button"` in either page is reachable from the
    /// keyboard, four on the element and two through a delegated
    /// Enter/Space listener (the queue tbody's, and the wall's over
    /// `#wall`/`#strips`); this was the only one that was not. The
    /// argument for fixing it is already written down three lines from
    /// the layout drag handle in `renderCards` - a stop that leads
    /// nowhere is worse than not being focusable at all.
    ///
    /// ONE action reached two ways, never two copies: a `follow` that
    /// drifted from the click handler would end the run on one route
    /// and leave it playing on the other.
    #[test]
    fn the_toast_click_through_is_reachable_from_the_keyboard() {
        let show = fn_body("toastShow");
        assert!(
            show.contains("el.onkeydown=") && show.contains("e.key==='Enter'||e.key===' '"),
            "the click-through must answer Enter and Space, not just a click"
        );
        assert!(
            show.contains("const follow=") && show.contains("el.onclick=follow"),
            "click and key press must run the SAME action, not two copies of it"
        );
        // The affordance may not outlive the box. `role=button` plus a
        // tab stop on an INVISIBLE element is the same defect one step
        // worse, and the attributes used to come off only when the next
        // toast rendered - which on a quiet page is never.
        let inert = fn_body("toastInert");
        for attr in [
            "onclick=null",
            "onkeydown=null",
            "removeAttribute('role')",
            "removeAttribute('tabindex')",
        ] {
            assert!(inert.contains(attr), "toastInert must clear {attr}");
        }
        assert!(
            fn_body("toastNext").contains("toastInert(el)"),
            "the affordance must be stripped when the box goes dark, not at the next render"
        );
    }

    /// The retired cues stay retired, and the whole diff went with them.
    ///
    /// Before §282 item 18 the promote door was narrated by a
    /// queue-SNAPSHOT diff in `sndQueueEvents` - "this row stopped being
    /// a Duplicate, so say the copy it was held behind failed". It could
    /// not name the abandoned release or the reason, said nothing on a
    /// page that loaded after the promotion, could not see a hunt at all
    /// (that row was never held), and fired on any hand-edit of a held
    /// row's priority. It also ran AFTER `handleLifeEvents` in the tick,
    /// and the toast element holds exactly one message - so
    /// reintroducing it beside the event arm would silently overwrite
    /// the event's own sentence and leave every gate green.
    ///
    /// §129 1b(b) then took the last four cues off that function (25 Aug
    /// 2026) and the function itself with them, so this asserts the
    /// stronger thing: there is no queue-snapshot cue watcher on the
    /// page AT ALL. `qSeen` and `prevPaused2` were its two memories of
    /// the previous poll, and `updToldFor` was the per-PAGE "already
    /// told them" the ring's cursor replaced - a name reappearing here
    /// means somebody rebuilt a diff beside the arms that supersede it,
    /// which is the one change no gate above could see.
    #[test]
    fn the_queue_snapshot_diff_does_not_narrate_switches() {
        for gone in [
            "function sndQueueEvents",
            "qHeld",
            "qSeen",
            "prevPaused2",
            "updToldFor",
        ] {
            assert!(
                !DASHBOARD_HTML.contains(gone),
                "`{gone}` is retired - the lifecycle event ring replaced it, and a \
                 snapshot diff beside those arms would overwrite their sentences"
            );
        }
    }
}
