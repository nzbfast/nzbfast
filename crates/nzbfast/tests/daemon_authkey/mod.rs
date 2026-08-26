//! What a credential may do: the full API key, the add-only `nzbkey`, and
//! the first-key bootstrap hatch between them.
//!
//! A sibling-dir child of daemon.rs (the daemon_chip6 pattern) so the
//! parent stays inside its size-gate baseline - it crossed again when the
//! #34 SAB-parity round landed. Declared from daemon.rs, so these still
//! run in that binary against those fixtures; harness via `super::*`.
//!
//! One subject, deliberately: every leg here answers "may this key do
//! that", and three of them are security regressions with a reproduced
//! escalation behind them (the POST-body key decision, the add-only
//! extension probe, and the bootstrap hatch that authorised `name=apikey`
//! from the query string while the handler wrote the body's name).

use super::*;

/// Revealing and rotating the API key are full-`apikey` operations. The
/// add-only `nzbkey` exists so a script can submit NZBs WITHOUT gaining
/// control; handing it the API key would promote it to exactly that in
/// one request, so these two modes must never join the add_only
/// allowlist. Also pins that a rotated key actually persists - it lives
/// in settings.json, written by the caller of apply_setting, and a miss
/// there would hand the user a key that stops working at the next
/// restart after they had already pasted it into Sonarr.
#[tokio::test(flavor = "multi_thread")]
async fn apikey_reveal_and_rotate_need_the_api_key() {
    let dir = std::env::temp_dir().join(format!("nzbfast-keyui-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("fullkey")
            .arg("--nzbkey")
            .arg("addkey")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // The add-only key gets nothing from either mode. A rotation is
        // POST-only (`credential_mutation_allowed`), so it is asked the
        // way the dashboard asks it - the point here is the KEY tier,
        // not the method.
        let body = |mode: &str| (mode == "apikey_new").then_some(("application/json", &b""[..]));
        for mode in ["apikey_show", "apikey_new"] {
            let r = http(
                port,
                &format!("/api?mode={mode}&apikey=addkey&output=json"),
                body(mode),
            );
            assert!(
                r.contains("\"status\":false"),
                "{mode} answered the add-only key: {r}"
            );
            assert!(
                !r.contains("fullkey"),
                "{mode} LEAKED the api key to the add-only key: {r}"
            );
            // And no key at all is refused too.
            let r = http(port, &format!("/api?mode={mode}&output=json"), body(mode));
            assert!(
                r.contains("\"status\":false"),
                "{mode} answered an unauthenticated caller: {r}"
            );
            assert!(
                !r.contains("fullkey"),
                "{mode} LEAKED the api key unauthenticated: {r}"
            );
        }

        // The real key can read it.
        let r = http(
            port,
            "/api?mode=apikey_show&apikey=fullkey&output=json",
            None,
        );
        assert!(
            r.contains("\"apikey\":\"fullkey\""),
            "reveal did not return the key: {r}"
        );

        // Rotate, then prove the OLD key is dead, the NEW one works, and
        // the new one reached settings.json rather than only memory.
        // A rotation must not be reachable by NAVIGATION: a keyless
        // install could otherwise be locked out by any page the user
        // visits, with a key nobody can read.
        let r = http(
            port,
            "/api?mode=apikey_new&apikey=fullkey&output=json",
            None,
        );
        assert!(
            r.contains("\"status\":false") && !r.contains("\"apikey\":\""),
            "apikey_new minted a key on a GET: {r}"
        );
        let r = http(
            port,
            "/api?mode=apikey_new&apikey=fullkey&output=json",
            Some(("application/json", b"")),
        );
        let new = r
            .split("\"apikey\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("no key in rotate response")
            .to_string();
        assert_ne!(new, "fullkey", "rotate returned the same key: {r}");

        let r = http(port, "/api?mode=version&apikey=fullkey&output=json", None);
        assert!(
            r.contains("\"status\":false"),
            "the old key still works after a rotate: {r}"
        );
        let r = http(
            port,
            &format!("/api?mode=version&apikey={new}&output=json"),
            None,
        );
        assert!(r.contains("\"nzbfast\""), "the new key does not work: {r}");

        let saved = std::fs::read_to_string(dir2.join("settings.json")).unwrap_or_default();
        assert!(
            saved.contains(&new),
            "rotated key never reached settings.json, so it dies on restart: {saved}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex sweep 2, 3 Aug H1 and M1: the /api body contract.
///
/// H1 - the previous sweep moved the credential snapshot to AFTER the
/// body read so a caller could not be authorized on key A, stall the
/// body, and complete a destructive write once the owner rotated to B.
/// But the pre-read only fired for three RECOGNIZED content types, and a
/// handler whose body had not been pre-read fell back to reading the
/// socket itself - after dispatch, which is after the authorization
/// decision. So the whole fix could be skipped by omitting
/// `Content-Type`, or by spelling it `Application/JSON` (media types are
/// case-insensitive; the classifier was not).
///
/// M1 - with the pre-read now covering everything, the handlers' own
/// caps live in a branch that can no longer run, so the gateway must
/// apply the endpoint's real limit or nothing does.
#[tokio::test(flavor = "multi_thread")]
async fn every_api_post_body_is_read_before_the_key_decision() {
    let dir = std::env::temp_dir().join(format!("nzbfast-apibody-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("fullkey")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // A JSON body sent with NO Content-Type at all. Before the fix
        // this skipped the pre-read entirely; the handler then read the
        // socket after auth, which is the whole rotation window. It has
        // to keep WORKING - the dashboard's own fetch() sends
        // text/plain - and it has to be read up front.
        let body = br#"{"target":{"name":"t","kind":"webhook","url":"http://127.0.0.1:1/x","token":"SEKRIT"}}"#;
        let r = http_once(port, "/api?mode=notify_test&apikey=fullkey&output=json", Some(("", &body[..])))
            .expect("no answer");
        assert!(
            !r.contains("bad target"),
            "an untyped JSON body must still reach the handler: {r}"
        );

        // Mixed-case spelling of the media type: standards-valid, and a
        // second way past a case-sensitive classifier.
        let r = http(
            port,
            "/api?mode=server_save&apikey=fullkey&output=json",
            Some(("Application/JSON", br#"{"index":-1,"server":{"host":"h.example","port":119}}"#)),
        );
        assert!(
            r.contains("\"status\":true"),
            "Application/JSON must be recognized as JSON: {r}"
        );

        // A body with no key and no mode is refused - and the refusal
        // must not depend on the handler having drained anything.
        let r = http(
            port,
            "/api?mode=server_save&output=json",
            Some(("application/json", br#"{"index":-1,"server":{"host":"x","port":119}}"#)),
        );
        assert!(!r.contains("\"status\":true"), "an unkeyed write succeeded: {r}");

        // M1: server_save's declared limit is 1 MiB. A body past it is
        // truncated at the gateway, so it arrives unparseable rather
        // than being buffered whole - the old flat 256 MiB pre-read
        // meant a nominal 1 MiB endpoint could take 256 of them.
        let mut fat = Vec::from(&br#"{"index":-1,"server":{"host":"h2.example","port":119,"pad":""#[..]);
        fat.resize(fat.len() + (2 << 20), b'A');
        fat.extend_from_slice(br#""}}"#);
        let r = http(
            port,
            "/api?mode=server_save&apikey=fullkey&output=json",
            Some(("application/json", &fat)),
        );
        assert!(
            !r.contains("\"status\":true"),
            "a 2 MiB body reached a 1 MiB endpoint intact: {r}"
        );

        // ...while addfile, which legitimately carries whole NZBs, is
        // still allowed well past that. Junk XML, so the ADD fails -
        // what matters is that the body was not cut off at 1 MiB, which
        // would have made it fail the same way and prove nothing. The
        // size is echoed back through the parse error path instead:
        // assert only that the daemon answered at all and did not
        // refuse the request outright.
        let mut big = Vec::from(&b"<?xml version=\"1.0\"?><nzb>"[..]);
        big.resize(big.len() + (3 << 20), b' ');
        big.extend_from_slice(b"</nzb>");
        let r = http(
            port,
            "/api?mode=addfile&apikey=fullkey&output=json",
            Some(("application/xml", &big)),
        );
        assert!(!r.is_empty(), "a 3 MiB addfile body got no answer at all: {r}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The add-only key's tier, from a push extension's point of view. NZB
/// Donkey tests a connection with mode=status and fills its category
/// dropdown from get_cats; NZB Unity tests with mode=fullstatus - so
/// those three reads must answer the NZB key or the key looks broken in
/// the exact tools it exists for. Everything with queue contents or
/// control stays full-key, refusals carry HTTP 403 like SABnzbd (a 200
/// refusal made NZB Unity's test read as success on a wrong key), and
/// rotating the NZB key itself is a full-key act with the same
/// no-self-promotion reasoning as apikey_show/apikey_new.
#[tokio::test(flavor = "multi_thread")]
async fn add_only_key_answers_extension_probes_but_nothing_more() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nzbkeytier-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("fullkey")
            .arg("--nzbkey")
            .arg("addkey")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // The three probes the push extensions send, on the add-only key.
        for (mode, marker) in [
            ("status", "\"uptime\""),
            ("fullstatus", "\"uptime\""),
            ("get_cats", "\"categories\""),
        ] {
            let r = http(port, &format!("/api?mode={mode}&apikey=addkey&output=json"), None);
            assert!(
                r.contains(marker),
                "{mode} refused the add-only key, so Donkey/Unity read the key as broken: {r}"
            );
        }

        // Queue contents and control stay full-key.
        for mode in ["queue", "history", "get_config", "pause"] {
            let r = http(port, &format!("/api?mode={mode}&apikey=addkey&output=json"), None);
            assert!(
                r.contains("\"status\":false"),
                "{mode} answered the add-only key: {r}"
            );
        }

        // Refusals are HTTP 403 (SAB parity): a 200 refusal parses as JSON
        // and NZB Unity's connection test then reports success on a wrong
        // key. The keyless version probe must stay 200 - the container
        // healthcheck curls it with -f.
        let out = raw(
            port,
            b"GET /api?mode=queue&apikey=addkey&output=json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        let head = String::from_utf8_lossy(&out);
        assert!(
            head.starts_with("HTTP/1.1 403"),
            "a refusal did not carry 403: {head}"
        );
        let out = raw(
            port,
            b"GET /api?mode=version&output=json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        let head = String::from_utf8_lossy(&out);
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "the keyless version probe lost its 200: {head}"
        );

        // The NZB key cannot rotate itself...
        let r = http(
            port,
            "/api?mode=nzbkey_new&apikey=addkey&output=json",
            Some(("application/json", b"")),
        );
        assert!(
            r.contains("\"status\":false"),
            "nzbkey_new answered the add-only key: {r}"
        );
        // ...the full key can, the old NZB key dies at once, and the new
        // one holds the same tier.
        // GET cannot mint one - see the apikey_new rotation above.
        let r = http(port, "/api?mode=nzbkey_new&apikey=fullkey&output=json", None);
        assert!(
            r.contains("\"status\":false") && !r.contains("\"nzbkey\":\""),
            "nzbkey_new minted a key on a GET: {r}"
        );
        let r = http(
            port,
            "/api?mode=nzbkey_new&apikey=fullkey&output=json",
            Some(("application/json", b"")),
        );
        let new = r
            .split("\"nzbkey\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("no key in nzbkey_new response")
            .to_string();
        assert_ne!(new, "addkey", "rotate returned the same key: {r}");
        let r = http(port, "/api?mode=status&apikey=addkey&output=json", None);
        assert!(
            r.contains("\"status\":false"),
            "the old NZB key still works after a rotate: {r}"
        );
        let r = http(port, &format!("/api?mode=status&apikey={new}&output=json"), None);
        assert!(r.contains("\"uptime\""), "the rotated NZB key does not work: {r}");
        let r = http(port, &format!("/api?mode=queue&apikey={new}&output=json"), None);
        assert!(
            r.contains("\"status\":false"),
            "the rotated NZB key gained full control: {r}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of a rotation: the write that FAILS. On a full disk or a
/// read-only settings folder the daemon is already on the new key (nothing
/// can put the old one back) but settings.json still holds the old one, so
/// the key dies at the next restart. The answer is `status: true` with the
/// key AND `saved: false` - the dashboard needs the key to keep talking to
/// this daemon, and the durability flag to say so on screen rather than in
/// a stdout line nobody reads on a NAS.
///
/// Pins the producer side of the contract the dashboard now consumes. Root
/// ignores the permission bits, so it can only run unprivileged.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_rotation_that_cannot_be_persisted_says_so() {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: geteuid(2) takes no arguments, touches no memory and
    // cannot fail; it is unsafe only because it is an extern "C" call.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root writes into a read-only directory anyway");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-keyro-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("fullkey")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    let (rot, ver, before, after) = tokio::task::spawn_blocking(move || {
        // Everything the daemon still needs lives in .spool, whose own bits
        // are untouched; only NEW files beside the config become impossible,
        // which is exactly settings.json's atomic temp file.
        let before = std::fs::read_to_string(dir2.join("settings.json")).unwrap_or_default();
        std::fs::set_permissions(&dir2, std::fs::Permissions::from_mode(0o555)).unwrap();
        let rot = http(
            port,
            "/api?mode=apikey_new&apikey=fullkey&output=json",
            Some(("application/json", b"")),
        );
        let new = rot
            .split("\"apikey\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_default()
            .to_string();
        let ver = http(
            port,
            &format!("/api?mode=version&apikey={new}&output=json"),
            None,
        );
        let after = std::fs::read_to_string(dir2.join("settings.json")).unwrap_or_default();
        // Restore before asserting, or the dir cannot be cleaned up.
        let _ = std::fs::set_permissions(&dir2, std::fs::Permissions::from_mode(0o755));
        (rot, ver, before, after)
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        rot.contains("\"status\":true"),
        "a live rotation reported failure: {rot}"
    );
    assert!(
        rot.contains("\"saved\":false"),
        "the un-persisted rotation claimed to be durable: {rot}"
    );
    assert!(
        ver.contains("\"nzbfast\""),
        "the daemon is not on the key it handed out: {ver}"
    );
    assert_eq!(
        before, after,
        "settings.json changed under a read-only directory"
    );
}

/// Security regression: the add-only `nzbkey` must not gain full control
/// through the NZBGet `/jsonrpc` facade. `append`/`version`/`status` are
/// allowed for it; queue/rate/config mutation (editqueue GroupFinalDelete,
/// rate, pausedownload) is full-`apikey` only. Before the fix, /jsonrpc
/// accepted either key with no tier check and the add-only key could wipe
/// the queue.
#[tokio::test(flavor = "multi_thread")]
async fn jsonrpc_add_only_key_cannot_control_queue() {
    let dir = std::env::temp_dir().join(format!("nzbfast-jrpc-tier-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
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
            .arg("--apikey")
            .arg("fullkey")
            .arg("--nzbkey")
            .arg("addkey")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        fn b64(data: &[u8]) -> String {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for c in data.chunks(3) {
                let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
                let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
                out.push(A[(n >> 18) as usize & 63] as char);
                out.push(A[(n >> 12) as usize & 63] as char);
                out.push(if c.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
                out.push(if c.len() > 2 { A[n as usize & 63] as char } else { '=' });
            }
            out
        }
        // POST /jsonrpc with HTTP Basic `x:<pw>`; return the HTTP status code.
        let rpc = |pw: &str, method: &str, params: &str| -> u16 {
            let cred = b64(format!("x:{pw}").as_bytes());
            let body = format!("{{\"method\":\"{method}\",\"params\":{params},\"id\":1}}");
            let mut request = Vec::new();
            write!(
                request,
                "POST /jsonrpc HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Basic {cred}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            request.extend_from_slice(body.as_bytes());
            let out = String::from_utf8_lossy(&raw(port, &request)).to_string();
            out.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
        };

        // Add-only key: the permitted methods work...
        assert_eq!(rpc("addkey", "version", "[]"), 200, "add-only version allowed");
        // ...but every control method is refused with 403.
        assert_eq!(
            rpc("addkey", "editqueue", "[\"GroupFinalDelete\",[1]]"),
            403,
            "add-only key must NOT delete the queue via /jsonrpc"
        );
        assert_eq!(rpc("addkey", "rate", "[100]"), 403, "add-only rate must be forbidden");
        assert_eq!(rpc("addkey", "pausedownload", "[]"), 403, "add-only pause must be forbidden");
        assert_eq!(rpc("addkey", "config", "[]"), 403, "add-only config must be forbidden");

        // Full key: control methods are NOT blocked (not 401/403).
        assert_ne!(rpc("fullkey", "editqueue", "[\"GroupFinalDelete\",[1]]"), 403);
        assert_ne!(rpc("fullkey", "editqueue", "[\"GroupFinalDelete\",[1]]"), 401);

        // Wrong password: rejected outright.
        assert_eq!(rpc("bogus", "version", "[]"), 401, "wrong key rejected");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir2);
}

/// Security regression: the add-only `nzbkey` must not reach arbitrary
/// config through the first-key bootstrap hatch.
///
/// The hatch exists so an admin who set the NZB key first is not locked
/// out of ever setting a full API key. It authorises `mode=config` for the
/// add-only key when it sees `name=apikey` - but it read that name from the
/// QUERY string while the handler prefers the POST BODY, so
/// `?name=apikey` + `{"name":"script"}` authorised one setting and wrote a
/// different one. `script` is executed on the job tail and `addfile` is
/// itself add-only, so that was an add-only credential escalating to code
/// execution. Reproduced against the published 1.0.10 image before the fix.
#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_hatch_cannot_write_a_setting_other_than_the_apikey() {
    let dir = std::env::temp_dir().join(format!("nzbfast-bootstrap-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();
    // NZBFAST_OPEN keeps first_run_apikey from minting one, which is what
    // puts the daemon in the exact state the hatch serves: an add-only key
    // set, no full apikey yet.
    let d = serve(&dir, |port| {
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
            .arg("--nzbkey")
            .arg("addkey")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let cfg2 = cfg.clone();
    tokio::task::spawn_blocking(move || {
        // POST /api?<query> with a JSON body; return the response body.
        let post = |query: &str, body: &str| -> String {
            let mut request = Vec::new();
            write!(
                request,
                "POST /api?{query} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            request.extend_from_slice(body.as_bytes());
            String::from_utf8_lossy(&raw(port, &request)).to_string()
        };

        // The escalation: the query names the one authorised setting, the
        // body names a different one.
        let out = post(
            "mode=config&name=apikey&apikey=addkey",
            "{\"name\":\"script\",\"value\":\"/tmp/pwn.sh\"}",
        );
        assert!(
            !out.contains("\"status\":true"),
            "add-only key wrote a non-apikey setting through the bootstrap hatch: {out}"
        );

        // ...and it really did not land.
        let settings = cfg2.with_file_name("settings.json");
        let saved = std::fs::read_to_string(&settings).unwrap_or_default();
        assert!(
            !saved.contains("pwn.sh"),
            "the escalated setting was persisted anyway: {saved}"
        );

        // The hatch itself must still work, or an admin who set the NZB key
        // first is locked out of ever setting a full key.
        let ok = post(
            "mode=config&name=apikey&apikey=addkey",
            "{\"name\":\"apikey\",\"value\":\"thefullkey123\"}",
        );
        assert!(ok.contains("\"status\":true"), "the legitimate bootstrap broke: {ok}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
