//! DEV-ONLY `NZBFAST_DEV_WEB_DIR`: the daemon serves the web pages from
//! a directory on disk instead of the copies compiled into the binary.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//!
//! What is pinned, in the order the test drives it:
//!
//!   1. UNSET - which is every install, every release and every other
//!      test - serves the EMBEDDED bytes, with the ordinary headers.
//!      This is the arm that matters most: the override must be
//!      invisible to a daemon that did not ask for it, because the
//!      embedded copy is what actually ships.
//!   2. SET - the same routes serve what is on disk: the shell, the
//!      shared design tokens inlined into it, an i18n catalogue, the web
//!      manifest.
//!   3. A CHANGED file reaches the browser: a second GET after a write
//!      returns the new bytes under a NEW ETag, and a revalidation of
//!      the old one is answered 200 rather than 304 - with no restart.
//!      Serving changed bytes under a build-time validator would leave
//!      the loop as broken as the rebuild it replaces, and would do it
//!      invisibly, the browser 304-ing its way past every edit.
//!   4. A MISSING file falls back to the embedded copy PER ASSET rather
//!      than blanking the page, so a half-populated directory costs one
//!      asset and not the dashboard.
//!   5. It is NOT a file server. A file sitting in the directory under a
//!      name the embedded table does not know is not served, and neither
//!      is a traversal-shaped name - including one that reaches a real
//!      file just outside the directory.
//!
//! No NNTP server and no job: every assertion here is a GET.

use super::*;

/// Head and body of a GET, so the status line and the ETag can be read.
/// `raw` already retries a refusal-to-serve.
fn get(port: u16, path: &str) -> (String, String) {
    let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let out = String::from_utf8_lossy(&raw(port, req.as_bytes())).to_string();
    match out.split_once("\r\n\r\n") {
        Some((head, body)) => (head.to_string(), body.to_string()),
        None => (out, String::new()),
    }
}

/// The quoted validator from a response head, or "" if there is none.
fn etag_of(head: &str) -> String {
    head.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("etag:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default()
}

/// Launch a daemon under `dir`, with the override exported or removed.
/// No servers are configured: nothing here downloads.
async fn daemon_at(dir: &Path, web: Option<PathBuf>) -> Daemon {
    let cfg = dir.join("config.json");
    if !cfg.exists() {
        std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    }
    serve(dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        match &web {
            Some(p) => c.env("NZBFAST_DEV_WEB_DIR", p),
            // Explicitly CLEARED rather than merely not set: this suite
            // inherits the developer's environment, and a session that
            // exported the override for its own reload loop would
            // otherwise turn the control arm into a second dev-mode arm
            // and take the whole test green for the wrong reason.
            None => c.env_remove("NZBFAST_DEV_WEB_DIR"),
        };
        c
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn dev_web_dir_serves_from_disk_and_is_invisible_when_unset() {
    let dir = std::env::temp_dir().join(format!("nzbfast-devweb-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // ---- Arm 1: the override unset. The embedded pages, unchanged. ----
    let d = daemon_at(&dir, None).await;
    let plain = d.port;
    let embedded = tokio::task::spawn_blocking(move || {
        let (head, dash) = get(plain, "/");
        assert!(head.starts_with("HTTP/1.1 200"), "the dashboard: {head}");
        assert!(
            dash.to_ascii_lowercase().contains("<!doctype html>"),
            "the dashboard is not html"
        );
        // The shared tokens are INLINED into the shell, so finding the
        // disk copy later means finding a marker in this same body.
        assert!(
            !dash.contains("__NZBFAST_UI_TOKENS__"),
            "the tokens placeholder survived into the served page"
        );
        let (fr_head, fr) = get(plain, "/i18n/fr.json");
        assert!(fr_head.starts_with("HTTP/1.1 200"), "{fr_head}");
        assert!(fr.contains('{'), "the fr catalogue is not JSON: {fr_head}");
        let (de_head, de) = get(plain, "/i18n/de.json");
        assert!(de_head.starts_with("HTTP/1.1 200"), "{de_head}");
        let (mf_head, mf) = get(plain, "/site.webmanifest");
        assert!(mf_head.starts_with("HTTP/1.1 200"), "{mf_head}");
        assert!(
            mf_head.contains("max-age=86400"),
            "an ordinary run keeps the day-long icon cache: {mf_head}"
        );
        (dash, fr, de, mf)
    })
    .await
    .unwrap();
    // End this daemon before the next one starts, so the two arms cannot
    // be confused for one another in the log.
    drop(d);

    // ---- The dev directory: our own copies of four assets, each marked
    // so a served body says which copy it came from. ----
    let web = dir.join("web");
    std::fs::create_dir_all(web.join("i18n")).unwrap();
    let repo_web = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web");
    let marked = |name: &str, mark: &str| {
        let src = std::fs::read_to_string(repo_web.join(name))
            .unwrap_or_else(|e| panic!("this checkout has no web/{name}: {e}"));
        std::fs::write(web.join(name), format!("{src}\n<!-- {mark} -->\n")).unwrap();
    };
    marked("dashboard.html", "DISK-DASHBOARD-V1");
    marked("ui-tokens.html", "DISK-TOKENS-V1");
    std::fs::write(web.join("i18n/fr.json"), "{\"disk\":\"FR-V1\"}").unwrap();
    std::fs::write(web.join("site.webmanifest"), "{\"disk\":\"MANIFEST-V1\"}").unwrap();
    // wall.html is deliberately ABSENT - arm 4's fallback leg.
    // Two files under names the embedded table does not know - arm 5.
    std::fs::write(web.join("i18n/zz.json"), "{\"disk\":\"NOT-A-LOCALE\"}").unwrap();
    std::fs::write(web.join("secret.txt"), "NOT-AN-ASSET").unwrap();

    // ---- Arms 2-5: the override on. ----
    let d = daemon_at(&dir, Some(web.clone())).await;
    let port = d.port;
    let (embedded_dash, embedded_fr, embedded_de, embedded_mf) = embedded;
    tokio::task::spawn_blocking(move || {
        // -- Arm 2: the pages come off disk. --
        let (head, dash) = get(port, "/");
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(
            dash.contains("DISK-DASHBOARD-V1"),
            "the dashboard did not come from disk"
        );
        assert_ne!(dash, embedded_dash, "the served page did not change");
        assert!(
            dash.contains("DISK-TOKENS-V1"),
            "the shared design tokens did not come from disk"
        );
        assert!(
            !dash.contains("__NZBFAST_UI_TOKENS__") && !dash.contains("__NZBFAST_LOCALE__"),
            "a disk-served page must still have its placeholders substituted"
        );
        let first_etag = etag_of(&head);
        assert!(!first_etag.is_empty(), "no validator on a dev-served shell");

        let (fr_head, fr) = get(port, "/i18n/fr.json");
        assert_eq!(fr, "{\"disk\":\"FR-V1\"}", "the catalogue is not from disk");
        assert_ne!(fr, embedded_fr, "the catalogue did not change");
        let fr_etag = etag_of(&fr_head);
        assert!(
            !fr_etag.is_empty(),
            "no validator on a dev-served catalogue"
        );

        let (mf_head, mf) = get(port, "/site.webmanifest");
        assert_eq!(
            mf, "{\"disk\":\"MANIFEST-V1\"}",
            "the manifest is not from disk"
        );
        assert_ne!(mf, embedded_mf, "the manifest did not change");
        assert!(
            mf_head.contains("no-cache") && !mf_head.contains("max-age=86400"),
            "a dev-served icon route must not sit a day in the browser cache: {mf_head}"
        );

        // -- Arm 3: an edit reaches the next request, under a validator
        // that moved with it, with nothing restarted. --
        let dash_path = web.join("dashboard.html");
        let v1 = std::fs::read_to_string(&dash_path).unwrap();
        std::fs::write(
            &dash_path,
            v1.replace("DISK-DASHBOARD-V1", "DISK-DASHBOARD-V2"),
        )
        .unwrap();
        let (head2, dash2) = get(port, "/");
        assert!(
            dash2.contains("DISK-DASHBOARD-V2"),
            "an edit did not reach the next request - the shell cache is pinning it"
        );
        let second_etag = etag_of(&head2);
        assert_ne!(
            first_etag, second_etag,
            "changed bytes under the SAME ETag: every browser would 304 past the edit"
        );
        let cond = format!(
            "GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: {first_etag}\r\nConnection: close\r\n\r\n"
        );
        let out = String::from_utf8_lossy(&raw(port, cond.as_bytes())).to_string();
        assert!(
            out.starts_with("HTTP/1.1 200"),
            "a stale validator was answered 304: {}",
            out.lines().next().unwrap_or("")
        );

        std::fs::write(web.join("i18n/fr.json"), "{\"disk\":\"FR-V2\"}").unwrap();
        let (fr2_head, fr2) = get(port, "/i18n/fr.json");
        assert_eq!(
            fr2, "{\"disk\":\"FR-V2\"}",
            "the catalogue edit did not reach"
        );
        assert_ne!(
            fr_etag,
            etag_of(&fr2_head),
            "a changed catalogue kept its build-time validator"
        );

        // -- Arm 4: a missing file falls back PER ASSET. --
        let (wall_head, wall) = get(port, "/wall");
        assert!(
            wall_head.starts_with("HTTP/1.1 200"),
            "a missing web/wall.html must fall back, not fail: {wall_head}"
        );
        assert!(
            wall.to_ascii_lowercase().contains("<!doctype html>"),
            "the wall fallback served no page"
        );
        assert!(
            !wall.contains("DISK-DASHBOARD"),
            "the wall must not fall back to the dashboard"
        );
        // The fallback is per asset, not per page: the wall has no disk
        // copy, the tokens do, and the page it fell back to still gets
        // them.
        assert!(
            wall.contains("DISK-TOKENS-V1"),
            "one missing file took the whole page down the embedded path"
        );
        // A locale with no disk copy is served the embedded catalogue,
        // byte for byte - the fallback is per asset here too.
        let (de_head, de) = get(port, "/i18n/de.json");
        assert!(de_head.starts_with("HTTP/1.1 200"), "{de_head}");
        assert_eq!(
            de, embedded_de,
            "a locale with no disk copy did not fall back to its embedded catalogue"
        );

        // -- Arm 5: not a file server. --
        // A well-formed name that is not a UI locale: on disk in the dev
        // directory, and still not served - the only names that reach
        // the reader are the ones the embedded table knows.
        let (zz_head, zz) = get(port, "/i18n/zz.json");
        assert!(
            !zz.contains("NOT-A-LOCALE"),
            "a file in the dev directory under an unknown locale was served: {zz_head}"
        );
        // A file in the dev directory under a name no route claims.
        let (sec_head, sec) = get(port, "/secret.txt");
        assert!(
            !sec.contains("NOT-AN-ASSET"),
            "the dev directory is being served as a file tree: {sec_head}"
        );
        // Traversal, in the spellings a proxy or a browser might hand
        // over, at a file that really exists one level up.
        assert!(dir.join("config.json").is_file(), "fixture needs a target");
        for probe in [
            "/i18n/../config.json",
            "/i18n/../../config.json",
            "/i18n/..%2fconfig.json",
            "/i18n/%2e%2e%2fconfig.json",
            "/i18n/....json",
            "/../config.json",
        ] {
            let (head, body) = get(port, probe);
            assert!(
                !body.contains("\"servers\""),
                "{probe} reached a file outside web/: {head}\n{body}"
            );
        }
        println!(
            "NZBFAST_DEV_WEB_DIR: unset serves the embedded pages with the shipped headers; \
             set serves web/ from disk (shell, inlined tokens, catalogue, manifest); an edit \
             reaches the next request under a new ETag with no restart and no 304; a missing \
             file falls back per asset; and a name the embedded table does not know - on disk \
             or traversal-shaped - reaches nothing."
        );
    })
    .await
    .unwrap();
}
