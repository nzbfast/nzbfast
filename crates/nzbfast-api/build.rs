// Gzip the immutable embedded pages into OUT_DIR, so the binary carries
// the compressed member rather than 9.0 MB of plain text.
//
// THIS FILE IS HALF OF `crates/nzbfast/build.rs`, moved here by lane 3
// of Option C in `research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md`. It
// had to move with the `include_bytes!` sites rather than stay where it
// was: `env!("OUT_DIR")` names the OUT_DIR of the package being
// compiled, so a member written by the bin's build script is not
// reachable from `assets.rs` once that file belongs to this crate. The
// bin's build.rs keeps the other half - the Windows icon, VERSIONINFO
// and manifest, and the beta serial - which is about the EXE and has
// nothing to embed here.
//
// `env!("CARGO_MANIFEST_DIR")` in the moved sources still resolves,
// because `crates/nzbfast-api` sits at the same depth as
// `crates/nzbfast` and every one of those paths is `../../web/...`.

fn main() {
    // Beta serial: local deploys and tester builds carry "beta N" after
    // the version so anyone can tell a between-releases build from the
    // published release it grew out of. packaging/beta-serial.txt is
    // bumped by the deploy-daemon / release-bundle workflows and RESET
    // TO 0 by publish-release, so a release build shows a bare version.
    // Missing file or 0 (or a public-repo build, which has no file)
    // means "not a beta": the suffix simply never appears.
    //
    // IT IS HERE AND NOT IN THE BIN since lane 3, for this file's own
    // reason: `env!("NZBFAST_BETA")` reads the environment of the
    // package being COMPILED, and its one reader - the `beta` field of
    // `mode=version` - is `api/system.rs`, which belongs to this crate.
    println!("cargo:rerun-if-changed=../../packaging/beta-serial.txt");
    let beta =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/beta-serial.txt");
    let beta = std::fs::read_to_string(beta)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .map(|n| n.to_string())
        .unwrap_or_default();
    println!("cargo:rustc-env=NZBFAST_BETA={beta}");

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // Only when the browser-facing pages are being compiled IN. Without
    // the `dashboard` feature (TODO 281 IO3b: the store build, and both
    // phones) nothing includes these members, so gzipping 11.5 MB of
    // catalogues and manuals into OUT_DIR is work whose whole output is
    // discarded. `CARGO_FEATURE_DASHBOARD` is cargo's own spelling of
    // the feature for a build script, and the `include_bytes!` sites
    // that read these keys carry the SAME cfg - so a build that skips
    // this cannot reach a missing file.
    if std::env::var_os("CARGO_FEATURE_DASHBOARD").is_some() {
        precompress_pages(&root, &out);
    }
}

/// Compress the embedded pages that CANNOT change between builds, and
/// compute their validators here rather than per request (R10 / Codex
/// C9).
///
/// The 27 i18n catalogues and the 16 manuals are 9.0 MB of plain text
/// in the binary's read-only data - a quarter of the whole executable -
/// and every byte of them goes to a browser that would have taken gzip.
/// Embedding the gzip MEMBER instead costs 2.8 MB (-69%), and the
/// request path stops deflating a 250 KB catalogue on every fetch: the
/// ETag lands beside it as a string constant, so a revalidation is a
/// header compare with no page to build and nothing to hash.
///
/// Only pages with no per-request input may pass through here. The
/// manuals have exactly two substitutions - `__NZBFAST_UI_TOKENS__`, the
/// shared design system, and `__NZBFAST_APP_NAV__`, the four
/// destinations - and both inputs are other compiled-in files, so they
/// are folded in HERE and the manual route no longer calls `ui_themed`.
/// The nav is injected rather than written into the source pages because
/// the same sixteen files are ALSO the public gh-pages site and the
/// offline copy in the DMG, where `/wall` is a 404 and a `file://` page
/// cannot follow an absolute app link. Their marker is an HTML comment,
/// so unsubstituted it renders as nothing; see web/ui-manualnav.html. The dashboard and the wall are deliberately NOT in this
/// set: they carry daemon state (locale, indexer switches) and are
/// cached at run time instead, keyed on those inputs.
///
/// The keys written here are named one by one in
/// `crates/nzbfast-api/src/assets.rs`, so a locale that loses its file
/// is a compile error naming the key, not a page that quietly stops
/// being served.
fn precompress_pages(root: &std::path::Path, out: &std::path::Path) {
    let tokens_at = root.join("web/ui-tokens.html");
    println!("cargo:rerun-if-changed={}", tokens_at.display());
    let tokens = std::fs::read_to_string(&tokens_at)
        .unwrap_or_else(|e| panic!("{}: {e}", tokens_at.display()));
    let nav_at = root.join("web/ui-manualnav.html");
    println!("cargo:rerun-if-changed={}", nav_at.display());
    let nav_tpl =
        std::fs::read_to_string(&nav_at).unwrap_or_else(|e| panic!("{}: {e}", nav_at.display()));

    // The DIRECTORY dependency catches an added or removed locale; the
    // per-file ones inside `emit_page` catch an edited translation.
    for (dir, key, prefix, suffix, themed) in [
        (root.join("web/i18n"), "i18n", "", ".json", false),
        (root.join("docs/i18n"), "manual", "MANUAL.", ".html", true),
    ] {
        println!("cargo:rerun-if-changed={}", dir.display());
        let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            // Two lowercase letters and nothing else, which is what every
            // UI locale tag is. It is also what keeps the translators'
            // own files out: `en.reference.json` sits in web/i18n and is
            // not a served catalogue.
            let Some(tag) = name
                .strip_prefix(prefix)
                .and_then(|n| n.strip_suffix(suffix))
                .filter(|t| t.len() == 2 && t.bytes().all(|b| b.is_ascii_lowercase()))
            else {
                continue;
            };
            let tokens = themed.then_some(tokens.as_str());
            // `themed` is true only for the manuals, which are the only
            // pages carrying the nav marker; the catalogues take neither.
            let nav = themed.then(|| manual_nav(&nav_tpl, root, tag));
            emit_page(
                &entry.path(),
                out,
                &format!("{key}-{tag}"),
                tokens,
                nav.as_deref(),
            );
        }
    }
    // English is the source language: its manual is the one at the top
    // of docs/, not a translation.
    emit_page(
        &root.join("docs/MANUAL.html"),
        out,
        "manual-en",
        Some(&tokens),
        Some(&manual_nav(&nav_tpl, root, "en")),
    );
}

/// The marker every manual carries where the four destinations go.
const NAV_MARK: &str = "<!--__NZBFAST_APP_NAV__-->";

/// Pull one string value out of a flat i18n catalogue.
///
/// A hand-rolled reader rather than a JSON crate on purpose: this is the
/// only JSON build.rs reads, the catalogues are machine-generated and
/// held flat by `web/i18n/check.py`, and a build-dependency is a cost
/// every lane pays on every clean build. It understands the escapes the
/// catalogues actually contain, `\uXXXX` included, and returns None
/// rather than guessing so the caller can fail by name.
fn catalogue_str(src: &str, key: &str) -> Option<String> {
    let at = src.find(&format!("\"{key}\""))?;
    let rest = &src[at + key.len() + 2..];
    let rest = &rest[rest.find(':')? + 1..];
    let mut it = rest[rest.find('"')? + 1..].chars();
    let mut out = String::new();
    loop {
        match it.next()? {
            '"' => return Some(out),
            '\\' => match it.next()? {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                'u' => {
                    let hex: String = it.by_ref().take(4).collect();
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                other => out.push(other),
            },
            c => out.push(c),
        }
    }
}

/// Render the manual's nav for one locale.
///
/// The labels are the SAME `hdr.*` keys the dashboard and the wall use,
/// so the three surfaces cannot drift apart and no new string is owed a
/// translation. A missing key is a build failure, not an English
/// fallback: a fallback would ship one English pill among three
/// translated ones and nothing would report it.
fn manual_nav(tpl: &str, root: &std::path::Path, lang: &str) -> String {
    // English is the SOURCE language and has no `en.json`: its strings
    // are the fallbacks written into the pages, and `en.reference.json`
    // is what extract.js regenerates from them. That file is the one the
    // i18n gate holds all 27 catalogues against, so taking English from
    // it keeps the manual's pills on the same four strings as every
    // other surface rather than on literals typed here.
    let at = if lang == "en" {
        root.join("web/i18n/en.reference.json")
    } else {
        root.join(format!("web/i18n/{lang}.json"))
    };
    println!("cargo:rerun-if-changed={}", at.display());
    let cat = std::fs::read_to_string(&at).unwrap_or_else(|e| panic!("{}: {e}", at.display()));
    let mut out = tpl.to_string();
    for (slot, key) in [
        ("@DASH@", "hdr.dash"),
        ("@WALL@", "hdr.wall"),
        ("@SETTINGS@", "hdr.settings"),
        ("@MANUAL@", "hdr.manual"),
    ] {
        let v = catalogue_str(&cat, key)
            .unwrap_or_else(|| panic!("{}: no {key} for the manual nav", at.display()));
        // The catalogues are translator-editable, so a label reaches
        // markup escaped rather than trusted.
        let v = v
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        out = out.replace(slot, &v);
    }
    assert!(
        !out.contains('@') || !out.contains("@DASH@"),
        "manual nav template still has an unfilled slot for {lang}"
    );
    out
}

/// Write one asset's gzip member and its ETag into OUT_DIR under `key`.
fn emit_page(
    src: &std::path::Path,
    out: &std::path::Path,
    key: &str,
    tokens: Option<&str>,
    nav: Option<&str>,
) {
    use std::io::Write as _;
    println!("cargo:rerun-if-changed={}", src.display());
    let body = std::fs::read(src).unwrap_or_else(|e| panic!("{}: {e}", src.display()));
    let body = match tokens {
        // The substitutions an immutable page has, folded in once here
        // instead of once per request - `ui_themed`'s job, done at build
        // time. A page that does not name the tokens placeholder simply
        // keeps its bytes.
        Some(t) => {
            let text = String::from_utf8(body)
                .unwrap_or_else(|e| panic!("{}: {e}", src.display()))
                .replace("__NZBFAST_UI_TOKENS__", t);
            // The nav, for the manuals only. A themed page that has lost
            // its marker is a manual that would ship WITHOUT the four
            // destinations and with nothing to say so, which is a build
            // failure rather than a quiet skip.
            let text = match nav {
                Some(n) => {
                    assert!(
                        text.contains(NAV_MARK),
                        "{}: no {NAV_MARK} - every manual carries one, see \
                         web/ui-manualnav.html",
                        src.display()
                    );
                    text.replace(NAV_MARK, n)
                }
                None => text,
            };
            text.into_bytes()
        }
        None => body,
    };

    // FNV-1a over the FINAL bytes, byte for byte the function
    // webasset.rs runs for the pages it still builds per request.
    // The two kinds of asset therefore carry the same shape of
    // validator, and a browser cannot tell them apart.
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in &body {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    let etag = out.join(format!("{key}.etag"));
    std::fs::write(&etag, format!("\"{h:016x}\""))
        .unwrap_or_else(|e| panic!("{}: {e}", etag.display()));

    // Level 9 rather than the request path's 6: this runs once per
    // build, not once per load, so there is no reason to leave bytes on
    // the table. flate2 stamps mtime 0, so the member is byte-identical
    // from one build of the same input to the next - a rebuild that
    // changes nothing must not change the ETag.
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(9));
    enc.write_all(&body).expect("gzip to a Vec");
    let gz = out.join(format!("{key}.gz"));
    std::fs::write(&gz, enc.finish().expect("gzip trailer"))
        .unwrap_or_else(|e| panic!("{}: {e}", gz.display()));
}
