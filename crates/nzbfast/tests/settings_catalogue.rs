//! The settings lists agree.
//!
//! A setting is spread across three places that are kept in step BY HAND:
//!
//!  1. the `apply_setting` match in serve.rs - the allowlist, since its
//!     `_` arm is what rejects an unknown name;
//!  2. the settings table in serve.rs, which `get_config` is built by
//!     walking - what the dashboard reads back;
//!  3. the restore path in `serve()`/`apply_saved_settings` - what a
//!     restart puts back from settings.json.
//!
//! Miss one and it fails SILENTLY. Missing from (2), the control saves
//! and then reads back blank, so the UI shows the old value. Missing
//! from (3), it works until the daemon restarts and then quietly
//! reverts. Neither logs anything: there is no error path to hit,
//! because nothing went wrong - a key simply was not there.
//!
//! (2) has since been collapsed into the settings table, which
//! `get_config` is generated from and which `log_value` takes its rules
//! from - so that list can no longer be missed, and serve.rs's own
//! `apply_arms_match_the_table` holds (1) to the same table. (3) is the
//! one that genuinely resists collapsing: `apply_saved_settings` maps
//! saved JSON onto launch options before the daemon exists, so its work
//! is bespoke per setting and shares no shape with the others.
//!
//! These tests remain the check that the three AGREE at runtime, which
//! is worth keeping even where the source is now generated:
//!
//!  * `allowlist_and_get_config_agree` pins (1) against (2), by name,
//!    with the asymmetries listed and justified below;
//!  * `settings_survive_a_restart` pins (1) against (3) behaviourally,
//!    over every boolean setting the daemon reports - it discovers them
//!    from the live response, so a new flag is covered the day it is
//!    added, with no edit here.
//!
//! Adding a setting therefore needs no change to this file. Forgetting
//! one of the three lists fails it.

mod scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// Settable, but deliberately never echoed by `get_config`.
///
/// The three keys are credentials: `get_config` is a read anyone holding
/// the API key can make from a browser, so they surface as `has_*` flags
/// instead and the value never leaves the daemon. `index_interests_applied`
/// is a one-shot marker recording that the interest presets were expanded
/// into scan groups - it has no control on the settings page.
const SETTABLE_NOT_ECHOED: &[&str] = &[
    "apikey",
    "nzbkey",
    "omdb_key",
    "scoreboard_key",
    "index_interests_applied",
];

/// Echoed by `get_config`, but not settable through `mode=config`.
///
/// Everything here is either derived, reported for display only, or
/// written through its own dedicated endpoint rather than the settings
/// allowlist.
const ECHOED_READ_ONLY: &[&str] = &[
    // Where the daemon's own files live - reported so a user can find
    // them, moved only by launching differently.
    "config_path",
    "settings_path",
    // Resolved from mem_limit plus the machine's RAM.
    "mem_budget_total",
    // Owned by conntune.json and the tuner that writes it.
    "conntune",
    // The tuner's line-speed shortfall verdict - display only.
    "tune_hint",
    // The server list has its own editor endpoints (credentials must not
    // ride the settings allowlist), and this is its first-run signal.
    "servers",
    "servers_configured",
    // Derived from the queue, the history and the usage store: has this
    // install ever downloaded anything (§129 4c's second empty state).
    "jobs_ever",
    // Saved-but-not-yet-applied values, computed by diffing settings.json
    // against the running daemon.
    "pending",
    // Credential presence flags - see SETTABLE_NOT_ECHOED.
    "has_apikey",
    "has_nzbkey",
    "has_omdb",
    "has_scoreboard_key",
    // How many passwords the passwords file currently holds - display
    // only; the file itself (not this row) is what you edit.
    "password_file_count",
];

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Response body of a GET against the daemon (headers stripped).
///
/// A connection refused before it produced a single byte is retried:
/// under a full parallel `cargo test` tiny_http can fail to spawn a
/// thread and drop the socket unread, which reaches us as ECONNRESET.
/// Once any byte has come back it is an answer and is returned as-is - a
/// truncated body must never be retried away.
fn http(port: u16, req: &str) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * u64::from(attempt) + 50,
                ));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

fn http_once(port: u16, req: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        s,
        "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )?;
    let mut out = String::new();
    let read = s.read_to_string(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    Ok(out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

fn api(port: u16, q: &str) -> serde_json::Value {
    let body = http(port, &format!("/api?output=json&{q}"));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("bad JSON for {q:?}: {e}\n{body}"))
}

/// The `config.nzbfast` block, as the daemon serves it.
fn settings_block(port: u16) -> serde_json::Map<String, serde_json::Value> {
    let j = api(port, "mode=get_config");
    j["config"]["nzbfast"]
        .as_object()
        .unwrap_or_else(|| panic!("get_config has no config.nzbfast object: {j}"))
        .clone()
}

/// Every name `apply_setting` accepts, read out of the source.
///
/// The allowlist is the match itself - there is no const to compare
/// against - so this reads the arms. Deliberately strict about the shape
/// it recognises: a `"name" =>` arm at the function's own indent. If the
/// match is ever reformatted this stops finding arms and the count
/// assertion below fails loudly, which is the right direction to fail.
fn allowlist() -> Vec<String> {
    // The table lives in TWO functions since TODO 106 split it: names the
    // first half does not know fall through to `apply_setting_tail` in
    // settings_apply.rs. Reading only the first half silently halved the
    // allowlist - the count assertion below is what caught it, which is
    // exactly the direction it was written to fail in.
    let src = concat!(
        include_str!("../src/serve/settings.rs"),
        include_str!("../src/serve/settings_apply.rs"),
    );
    let mut names = Vec::new();
    let mut inside = false;
    for line in src.lines() {
        if line.starts_with("pub(super) fn apply_setting") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        // The function's own closing brace, at column 0. Deliberately
        // not the text of the fallthrough arm: that arm is prose, it has
        // been reworded once already, and when it changed this loop ran
        // on into the rest of the file and collected every JSON-RPC mode
        // and locale code in it as a "setting".
        // ...and STOP at it, rather than ending the scan: with both
        // halves concatenated there is a second `pub(super) fn
        // apply_setting_tail` further down, and breaking here would
        // collect only the first table.
        if line == "}" {
            inside = false;
            continue;
        }
        // `        "a" | "b" => {` at exactly two levels of indent.
        let Some(rest) = line.strip_prefix("        \"") else {
            continue;
        };
        let Some(head) = rest.split("=>").next().filter(|_| rest.contains("=>")) else {
            continue;
        };
        let head = format!("\"{head}");
        // Only an arm made purely of string literals and `|` separators.
        if head.split('|').all(|p| {
            let p = p.trim();
            p.len() > 2
                && p.starts_with('"')
                && p.ends_with('"')
                && !p[1..p.len() - 1].contains('"')
        }) {
            for p in head.split('|') {
                names.push(p.trim().trim_matches('"').to_string());
            }
        }
    }
    assert!(
        names.len() > 60,
        "only found {} settings in apply_setting - the arm shape this test \
         parses must have changed, so it is no longer checking anything",
        names.len()
    );
    names
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        // ...and reap it, or the pid is held for the rest of the run.
        let _ = self.0.wait();
    }
}

struct Running {
    _child: KillOnDrop,
    port: u16,
}

/// A scratch install. `settings.json` exists from the start so this
/// reads as an EXISTING install and no first-run API key is minted -
/// auth is not what these tests are about.
fn scratch(name: &str) -> scratch::ScratchDir {
    let dir = std::env::temp_dir().join(format!("nzbfast-setcat-{}-{name}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    std::fs::write(dir.join("settings.json"), "{}").unwrap();
    dir
}

/// Launch `nzbfast serve` against `dir` and wait until it is serving.
/// Called twice per restart test, against the same directory.
fn serve(dir: &Path) -> Running {
    serve_env(dir, &[])
}

/// `serve` as a launcher that owns the port (container / Synology package).
fn serve_locked(dir: &Path) -> Running {
    serve_env(dir, &[("NZBFAST_PORT_LOCKED", "1")])
}

/// `serve` as a Flatpak install. `FLATPAK_ID` is one of the two markers
/// `flatpak_install()` reads; the other is `/.flatpak-info`, which a test
/// cannot create.
fn serve_flatpak(dir: &Path) -> Running {
    serve_env(dir, &[("FLATPAK_ID", "io.github.nzbfast.nzbfast")])
}

fn serve_env(dir: &Path, env: &[(&str, &str)]) -> Running {
    for attempt in 0..3 {
        let port = free_port();
        // Per-port, so the restart cannot read the FIRST daemon's banner
        // out of a shared log and call the second one ready.
        let logfile = dir.join(format!("daemon-{port}.log"));
        let out = std::fs::File::create(&logfile).unwrap();
        let err = out.try_clone().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = cmd
            .env("NZBFAST_NO_ENRICH", "1")
            .env_remove("NZBFAST_OPEN")
            // Run the daemon IN the scratch directory. Every path it is
            // given here is absolute, so this changes nothing for the
            // existing tests - but anything the daemon resolves against
            // its own cwd now lands in scratch instead of in the crate
            // directory the test binary happens to run from. That is
            // what lets `a_relative_move_destination_is_refused_before_
            // it_is_created` assert on the stray folder without a failure
            // dropping one into the repo.
            .current_dir(dir)
            .arg("--config")
            .arg(dir.join("config.json"))
            .arg("serve")
            // Loopback only: these suites never need LAN reach, and
            // binding 0.0.0.0 raises a macOS firewall prompt for every
            // freshly built test binary.
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(dir.join("index.db"))
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .unwrap();
        let mut running = Running {
            _child: KillOnDrop(child),
            port,
        };
        if wait_ready(&mut running._child, port, &logfile) {
            return running;
        }
        // The daemon exited instead of binding: `free_port()` handed
        // :port to a parallel test between our bind(:0) and the daemon's
        // bind. Try a fresh port.
        assert!(
            attempt < 2,
            "daemon exited without binding :{port}\n{}",
            log(&logfile)
        );
    }
    unreachable!()
}

/// Wait for OUR daemon's own listener banner, not for "something answers
/// on :port" - under a parallel run those differ, and a bare connect
/// would happily run the test against a stranger's daemon.
fn wait_ready(child: &mut KillOnDrop, port: u16, logfile: &Path) -> bool {
    let banner = format!("open the dashboard at  http://localhost:{port}/");
    for _ in 0..600 {
        if log(logfile).contains(&banner) && TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        if child.0.try_wait().ok().flatten().is_some() {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("daemon never came up on :{port}\n{}", log(logfile));
}

fn log(logfile: &Path) -> String {
    std::fs::read_to_string(logfile).unwrap_or_default()
}

/// Every settable name is read back by `get_config`, and every key
/// `get_config` reports is settable - except the asymmetries listed at
/// the top of this file, which are there on purpose.
#[test]
fn allowlist_and_get_config_agree() {
    let dir = scratch("agree");
    let d = serve(&dir);
    let echoed = settings_block(d.port);
    let allow = allowlist();

    let missing: Vec<&String> = allow
        .iter()
        .filter(|n| !echoed.contains_key(n.as_str()) && !SETTABLE_NOT_ECHOED.contains(&n.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "settable but never read back by get_config: {missing:?}\n\
         The control saves and then reads back blank. Add it to the right \
         settings table in serve.rs, or to SETTABLE_NOT_ECHOED here if it \
         is a credential."
    );

    let orphan: Vec<&String> = echoed
        .keys()
        .filter(|k| !allow.contains(k) && !ECHOED_READ_ONLY.contains(&k.as_str()))
        .collect();
    assert!(
        orphan.is_empty(),
        "reported by get_config but not settable: {orphan:?}\n\
         The UI can show it but saving it fails. Add an arm to \
         apply_setting in serve.rs, or to ECHOED_READ_ONLY here if it is \
         display-only."
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A saved setting is still in force after a restart.
///
/// Covers the third list: a setting can validate, apply live and read
/// back correctly, and still be missing from the restore path in
/// `serve()` - at which point it silently reverts on the next launch,
/// which is exactly when nobody is watching.
///
/// Every boolean the daemon reports is flipped, so this needs no table
/// of names or values to maintain: a new flag joins the test as soon as
/// `get_config` reports it.
#[test]
fn settings_survive_a_restart() {
    let dir = scratch("restart");
    let allow = allowlist();

    // Flip every settable boolean away from whatever it is now.
    let flipped: Vec<(String, bool)> = {
        let d = serve(&dir);
        let before = settings_block(d.port);
        let targets: Vec<(String, bool)> = before
            .iter()
            .filter(|(k, _)| allow.contains(k))
            .filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), !b)))
            .collect();
        assert!(
            targets.len() > 15,
            "only {} boolean settings found - this test has stopped covering \
             the settings surface",
            targets.len()
        );

        for (name, want) in &targets {
            let r = api(
                d.port,
                &format!("mode=config&name={name}&value={}", u8::from(*want)),
            );
            assert_eq!(
                r["status"].as_bool(),
                Some(true),
                "setting {name} was rejected: {r}"
            );
        }

        // Live first: a setting that never reaches the daemon would
        // otherwise look like a restart failure below.
        let after = settings_block(d.port);
        let stale: Vec<&str> = targets
            .iter()
            .filter(|(k, want)| after.get(k).and_then(|v| v.as_bool()) != Some(*want))
            .map(|(k, _)| k.as_str())
            .collect();
        assert!(
            stale.is_empty(),
            "saved, but get_config still reports the old value: {stale:?}\n\
             The apply_setting arm validated it without applying it to the \
             running daemon."
        );
        targets
    }; // daemon killed here

    // Same directory, new process: settings.json is the only carrier.
    let d = serve(&dir);
    let restored = settings_block(d.port);
    let lost: Vec<&str> = flipped
        .iter()
        .filter(|(k, want)| restored.get(k).and_then(|v| v.as_bool()) != Some(*want))
        .map(|(k, _)| k.as_str())
        .collect();
    assert!(
        lost.is_empty(),
        "reverted across a restart: {lost:?}\n\
         Saved to settings.json but never read back at launch - add it to \
         the restore path in serve() (the boolean table) or to \
         apply_saved_settings."
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Turning fast verify off means full verify, and it stays off.
///
/// `fast_verify` and `verify_mode` are two controls over the same pair of
/// flags, so a write through one has to leave the other's saved value
/// consistent. It does not fall out of `settings_survive_a_restart`: that
/// starts from a settings.json with no verify_mode in it at all, and the
/// revert needs an install that has used the verify_mode control at some
/// point - after which the restore path applies the stale mode LAST and
/// the fast_verify write is undone on every launch.
#[test]
fn turning_fast_verify_off_survives_a_restart_after_lean_was_chosen() {
    let dir = scratch("verify");

    // An install that once chose lean, then asked for full verify.
    {
        let d = serve(&dir);
        let r = api(d.port, "mode=config&name=verify_mode&value=lean");
        assert_eq!(
            r["status"].as_bool(),
            Some(true),
            "verify_mode rejected: {r}"
        );
        assert_eq!(settings_block(d.port)["verify_mode"], "lean");

        let r = api(d.port, "mode=config&name=fast_verify&value=0");
        assert_eq!(
            r["status"].as_bool(),
            Some(true),
            "fast_verify rejected: {r}"
        );
        assert_eq!(
            settings_block(d.port)["verify_mode"],
            "full",
            "not applied live"
        );
    } // daemon killed here

    {
        let d = serve(&dir);
        let s = settings_block(d.port);
        assert_eq!(
            s["verify_mode"], "full",
            "the daemon came back on the old verify mode - the fast_verify \
             write left a stale verify_mode in settings.json, and the \
             restore path applies that one last"
        );
        assert_eq!(s["fast_verify"], false, "fast verify came back on: {s:?}");
    }

    // The other direction: turning it back ON must survive too, and must
    // not silently promote itself to lean.
    {
        let d = serve(&dir);
        let r = api(d.port, "mode=config&name=fast_verify&value=1");
        assert_eq!(
            r["status"].as_bool(),
            Some(true),
            "fast_verify rejected: {r}"
        );
        assert_eq!(
            settings_block(d.port)["verify_mode"],
            "fast",
            "not applied live"
        );
    }

    {
        let d = serve(&dir);
        let s = settings_block(d.port);
        assert_eq!(
            s["verify_mode"], "fast",
            "fast verify did not survive the restart"
        );
        assert_eq!(s["fast_verify"], true, "fast verify came back off: {s:?}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// A launcher that owns the port keeps it: the API refuses to save one,
/// and a `port` already in settings.json does not move the listener.
///
/// This is the container/SPK contract. Their port is named in a published
/// mapping, a healthcheck and DSM's own Open button - none of which
/// nzbfast can rewrite - so a port saved in the dashboard used to leave
/// the service unreachable through its mapping and unhealthy on restart,
/// with the UI reporting the change took.
#[test]
fn a_locked_port_cannot_be_moved_from_the_dashboard() {
    let dir = scratch("portlock");

    // `port` is a restart-only setting, so `get_config` reports the LIVE
    // port either way - settings.json is where the saved value shows up.
    let saved_port = || -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(
            &std::fs::read_to_string(dir.join("settings.json")).unwrap_or_default(),
        )
        .map(|v| v["port"].clone())
        .unwrap_or(serde_json::Value::Null)
    };

    // Unlocked (a desktop or plain CLI install): the setting is accepted
    // and saved, which is the behaviour this must not break.
    {
        let d = serve(&dir);
        let r = api(d.port, "mode=config&name=port&value=6999");
        assert_eq!(
            r["status"].as_bool(),
            Some(true),
            "port rejected while unlocked: {r}"
        );
        assert_eq!(saved_port(), 6999, "an accepted port was not saved");
    }

    // Locked: refused with an explanation, and settings.json still holds
    // the 6999 written above - which the daemon must now ignore.
    {
        let d = serve_locked(&dir);
        let r = api(d.port, "mode=config&name=port&value=7001");
        assert_eq!(
            r["status"].as_bool(),
            Some(false),
            "a locked port was accepted: {r}"
        );
        let err = r["error"].as_str().unwrap_or_default();
        assert!(
            err.contains("how it was started"),
            "the refusal has to say WHERE the port lives, got: {err:?}"
        );
        // The refusal must not rewrite what is already saved either.
        assert_eq!(
            saved_port(),
            6999,
            "a refused write still touched settings.json"
        );
        // `get_config` reports the LIVE port, so this is the assertion that
        // the saved 6999 was ignored at startup rather than applied.
        assert_eq!(
            settings_block(d.port)["port"].as_u64(),
            Some(d.port as u64),
            "the saved port won over the one this install was started with"
        );
        let q = api(d.port, "mode=queue");
        assert_eq!(
            q["queue"]["port_locked"].as_bool(),
            Some(true),
            "the dashboard is never told to disable the field: {q}"
        );
        // The listener answering us IS d.port - the saved 6999 did not win.
        assert_ne!(d.port, 6999);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The launcher handshake: `runtime.json` plus a challenge is what lets a
/// desktop wrapper tell this daemon from anything else that grabbed the
/// port, BEFORE it hands over the stored API key.
///
/// Not a settings test, but it needs exactly this file's daemon harness:
/// a real listener, started from a known data dir.
#[test]
fn the_daemon_proves_its_identity_to_a_launcher() {
    use sha2::{Digest, Sha256};

    let dir = scratch("handshake");
    let d = serve(&dir);

    // Written only once the listener exists, and only readable by us.
    let rt: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("runtime.json")).expect("no runtime.json"),
    )
    .unwrap();
    assert_eq!(
        rt["port"].as_u64(),
        Some(d.port as u64),
        "runtime.json names another port"
    );
    let token = rt["token"].as_str().unwrap_or_default().to_string();
    assert!(
        token.len() >= 32,
        "the token is not a credential: {token:?}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("runtime.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "runtime.json is readable by other accounts: {mode:o}"
        );
    }

    let proof_of = |token: &str, nonce: &str| {
        let mut h = Sha256::new();
        h.update(token.as_bytes());
        h.update(b":");
        h.update(nonce.as_bytes());
        h.finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };

    // The challenge rides the keyless probe - which is the ONLY reply a
    // wrapper gets, since sending the key to an unidentified listener is
    // the thing being prevented.
    let r = api(d.port, "mode=version&hs=0123456789abcdef");
    assert_eq!(
        r["hs_proof"].as_str(),
        Some(proof_of(&token, "0123456789abcdef").as_str()),
        "the daemon did not prove it holds its own token: {r}"
    );
    // A different nonce is a different answer - no replay.
    let again = api(d.port, "mode=version&hs=fedcba9876543210");
    assert_ne!(again["hs_proof"], r["hs_proof"]);
    // No challenge, no proof field - nothing leaks into ordinary replies.
    let plain = api(d.port, "mode=version");
    assert!(
        plain.get("hs_proof").is_none(),
        "a proof appeared unasked: {plain}"
    );
    // And a nonce that could not have come from a launcher is ignored
    // rather than hashed into the response.
    let junk = api(d.port, "mode=version&hs=short");
    assert!(
        junk.get("hs_proof").is_none(),
        "an out-of-shape nonce was answered: {junk}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--port 0` binds an OS-chosen port, and the daemon reports which one.
///
/// The caller that needs this cannot name a port in advance and must not
/// guess one: the Android app's on-device engine bound a hardcoded 6791,
/// and every app on a phone shares one loopback namespace, so a
/// predictable port is a port a sibling app can pre-bind (TODO 158 item
/// 4). The app passes 0 and reads the answer back out of runtime.json,
/// which is exactly what this asserts.
///
/// The two ends have to agree, so both are checked against the SAME
/// listener: runtime.json names a real port, the banner names that port,
/// and a request to it is answered by the daemon that wrote the file.
/// Asking for 0 and reporting 0 would satisfy any one of those alone.
#[test]
fn port_zero_binds_an_os_chosen_port_and_says_which() {
    let dir = scratch("portzero");
    let logfile = dir.join("daemon-portzero.log");
    let out = std::fs::File::create(&logfile).unwrap();
    let err = out.try_clone().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
        .env("NZBFAST_NO_ENRICH", "1")
        .env_remove("NZBFAST_OPEN")
        .current_dir(&dir)
        .arg("--config")
        .arg(dir.join("config.json"))
        .arg("serve")
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg("0")
        .arg("--out")
        .arg(dir.join("complete"))
        .arg("--index-db")
        .arg(dir.join("index.db"))
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap();
    let mut child = KillOnDrop(child);

    // No port to poll, so wait on the file that is supposed to tell us -
    // written only once the listener exists, which is the whole contract.
    let mut port = 0u16;
    for _ in 0..600 {
        let named = std::fs::read_to_string(dir.join("runtime.json"))
            .ok()
            .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok())
            .and_then(|rt| rt["port"].as_u64())
            .filter(|p| *p > 0);
        if let Some(p) = named {
            port = p as u16;
            break;
        }
        assert!(
            child.0.try_wait().ok().flatten().is_none(),
            "the daemon exited instead of binding an OS-chosen port\n{}",
            log(&logfile)
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_ne!(
        port,
        0,
        "runtime.json never named a bound port\n{}",
        log(&logfile)
    );

    // The banner is what every launcher and harness treats as readiness,
    // so it must name the same listener the file does - a banner reading
    // ":0" would send a user to a port nothing serves.
    let banner = format!("open the dashboard at  http://localhost:{port}/");
    for _ in 0..600 {
        if log(&logfile).contains(&banner) && TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        log(&logfile).contains(&banner),
        "the banner does not name the bound port {port}\n{}",
        log(&logfile)
    );

    // ...and the listener there really is this daemon: same token.
    let rt: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("runtime.json")).unwrap()).unwrap();
    let token = rt["token"].as_str().unwrap_or_default().to_string();
    assert!(
        token.len() >= 32,
        "the token is not a credential: {token:?}"
    );
    let nonce = "0123456789abcdef0123456789abcdef";
    let answer = api(port, &format!("mode=version&hs={nonce}"));
    let want = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(token.as_bytes());
        h.update(b":");
        h.update(nonce.as_bytes());
        h.finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        answer["hs_proof"].as_str(),
        Some(want.as_str()),
        "the listener on the reported port is not the daemon that wrote \
         runtime.json: {answer}"
    );

    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The recoverable-delete default follows the platform.
///
/// On macOS and Windows the Trash and the Recycle Bin are places the user
/// can see and empty, so cleanup routes deletes through them and a wrong
/// guess by the junk heuristics stays undoable.
///
/// On Linux it is not. When the download volume is not the volume the home
/// trash lives on - every NAS, every container, every seedbox - the
/// freedesktop rules make a hidden `.Trash-<uid>` directory at the TOP of
/// the download volume and move the files there. Nothing shows it, nothing
/// empties it, and the space never comes back: reported from Unraid on
/// 2 Aug 2026 as "reserving space on my SSD".
///
/// Read from a freshly launched daemon on purpose. The flag is a
/// process-global that defaults OFF under `cfg(test)` so the cleanup
/// suites cannot empty into a developer's real Trash, so an in-process
/// assertion would only ever see the test override. The real binary is
/// the only thing that can answer what a user gets.
#[test]
fn the_trash_default_follows_the_platform() {
    let dir = scratch("trashdefault");
    let d = serve(&dir);
    let echoed = settings_block(d.port);
    let on = echoed
        .get("delete_to_trash")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_else(|| panic!("get_config does not report delete_to_trash: {echoed:?}"));
    assert_eq!(
        on,
        !cfg!(target_os = "linux"),
        "cleanup's recoverable-delete default is wrong for this platform. \
         On Linux it must be OFF: the trash lands on the download volume \
         itself and fills the user's disk with files nothing will empty."
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Turning the low-disk floor OFF stays off across a restart.
///
/// `min_free` gained a non-zero launch default (MIN_FREE_DEFAULT) so a
/// fresh install protects the machine from a disk that fills to zero.
/// That default made an old shortcut dangerous: the restore path used to
/// read a saved 0 as "nothing was saved" and fall back to the default,
/// so the one person who had deliberately typed 0 got the floor handed
/// back on every launch - silently, since the queue only holds once the
/// disk is actually low.
///
/// Not covered by `settings_survive_a_restart`: that walks BOOLEANS, and
/// this is the numeric value whose "off" collides with "unset".
#[test]
fn a_min_free_of_zero_survives_a_restart() {
    let dir = scratch("minfree");

    {
        let d = serve(&dir);
        // The default is what a fresh install gets.
        let fresh = settings_block(d.port);
        assert_eq!(
            fresh.get("min_free").and_then(|v| v.as_u64()),
            Some(2_000_000_000),
            "a fresh install should carry the low-disk floor"
        );
        let r = api(d.port, "mode=config&name=min_free&value=0");
        assert_eq!(
            r["status"].as_bool(),
            Some(true),
            "min_free=0 rejected: {r}"
        );
        assert_eq!(
            settings_block(d.port)
                .get("min_free")
                .and_then(|v| v.as_u64()),
            Some(0),
            "0 did not reach the running daemon"
        );
    } // daemon killed here

    let d = serve(&dir);
    assert_eq!(
        settings_block(d.port)
            .get("min_free")
            .and_then(|v| v.as_u64()),
        Some(0),
        "an explicit 0 came back as the default - the restore path is \
         reading it as \"unset\" again"
    );

    // And a real value still round-trips, so the fix did not simply
    // stop reading the key.
    let r = api(d.port, "mode=config&name=min_free&value=25G");
    assert_eq!(
        r["status"].as_bool(),
        Some(true),
        "min_free=25G rejected: {r}"
    );
    drop(d);
    let d = serve(&dir);
    assert_eq!(
        settings_block(d.port)
            .get("min_free")
            .and_then(|v| v.as_u64()),
        Some(25_000_000_000),
        "a non-zero floor did not survive the restart"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A relative move destination is refused, and refused BEFORE the daemon
/// creates anything.
///
/// `create_dir_all` is happy to make a relative path, and it lands under
/// the daemon's WORKING DIRECTORY: `/var/lib/nzbfast` under the systemd
/// unit, the container's workdir under Docker, and wherever the launcher
/// happened to be otherwise. Typing `nas/movies` into the settings field
/// therefore created a real folder, passed `path_writable`, passed the
/// download-folder check, and was stored - and completed jobs were then
/// moved into a directory the user never chose and would not think to
/// look in.
///
/// Both the global destination and the per-category list reach the same
/// `move_tree`, so both are pinned. The ordering assertion is the point
/// of the test: a refusal that fires AFTER `create_dir_all` still leaves
/// the stray folder behind.
#[test]
fn a_relative_move_destination_is_refused_before_it_is_created() {
    let dir = scratch("relmove");
    let d = serve(&dir);

    // `serve_env` runs the daemon with its cwd here, so a relative
    // destination would materialise at exactly this path.
    let stray = dir.join("nas");

    for (name, value) in [
        ("move_completed", "nas/movies"),
        ("move_completed_cats", "movies=nas/movies"),
    ] {
        let r = api(
            d.port,
            &format!("mode=config&name={name}&value={}", urlenc(value)),
        );
        assert_eq!(
            r["status"].as_bool(),
            Some(false),
            "{name} accepted a relative destination: {r}"
        );
        let err = r["error"].as_str().unwrap_or_default();
        assert!(
            err.contains("relative path") && err.contains("full path"),
            "{name}'s refusal has to name what was expected, got: {err:?}"
        );
    }

    assert!(
        !stray.exists(),
        "a refused destination was created anyway at {}",
        stray.display()
    );

    // The guard must not have broken the case it is guarding. An
    // absolute destination is still accepted and still read back.
    let good = dir.join("library");
    let r = api(
        d.port,
        &format!(
            "mode=config&name=move_completed&value={}",
            urlenc(&good.to_string_lossy())
        ),
    );
    assert_eq!(
        r["status"].as_bool(),
        Some(true),
        "an absolute destination was refused: {r}"
    );
    assert_eq!(
        settings_block(d.port)
            .get("move_completed")
            .and_then(|v| v.as_str()),
        Some(good.to_string_lossy().as_ref()),
        "an accepted destination did not read back"
    );

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Percent-encode a query value. `/` is left alone so paths stay legible
/// in a failure message; `=` and the rest are escaped, which is what the
/// `category=path` value above needs.
fn urlenc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// #18: a rule says what its pattern will actually do, and saying it does
/// not change what gets stored.
///
/// Both halves matter. `pat_match` never fails - a pattern that will not
/// compile silently becomes a literal keyword search, and one that
/// compiles to "match anything" silently claims the whole queue - so the
/// verdict is the only way either is visible in the editor. And because
/// it describes a value rather than being one, it must never end up IN
/// the value: `Rule` is the persisted shape in settings.json, so a
/// verdict that round-tripped through a save would be written to disk and
/// then read back as part of the rule.
#[test]
fn a_rules_pattern_verdict_is_reported_but_never_stored() {
    let dir = scratch("ruleverdict");
    let d = serve(&dir);

    // One that will not compile, one that matches everything, and one
    // ordinary rule whose "but not" is the broken half.
    let rules = r#"[{"name":"a","match":"*anime*","category":"anime"},
                    {"name":"b","match":"!*","category":"junk"},
                    {"name":"c","match":"2160p","not_match":".*","category":"movies"}]"#;
    let r = api(
        d.port,
        &format!("mode=config&name=smart_folders&value={}", urlenc(rules)),
    );
    assert_eq!(r["status"].as_bool(), Some(true), "rules rejected: {r}");

    let read = settings_block(d.port);
    let got = read["smart_folders"].as_array().expect("smart_folders");
    assert_eq!(got.len(), 3, "{got:?}");
    assert_eq!(
        got[0]["match_verdict"].as_str(),
        Some("literal"),
        "a pattern that cannot compile was not reported: {}",
        got[0]
    );
    assert_eq!(
        got[1]["match_verdict"].as_str(),
        Some("matches_everything"),
        "a catch-all pattern was not reported: {}",
        got[1]
    );
    // An ordinary pattern says nothing at all - absent, not "ok".
    assert!(
        got[2].get("match_verdict").is_none(),
        "an ordinary rule was annotated: {}",
        got[2]
    );
    // ...and the verdict is per FIELD, so the "but not" is judged too.
    assert_eq!(
        got[2]["not_verdict"].as_str(),
        Some("matches_everything"),
        "but-not was not judged: {}",
        got[2]
    );

    // Now the half that is easy to get wrong. Save the rules back exactly
    // as the daemon just reported them - which is what an editor that
    // echoed its payload would do - and settings.json must still hold only
    // the rule's own fields.
    let echoed = serde_json::to_string(got).unwrap();
    let r = api(
        d.port,
        &format!("mode=config&name=smart_folders&value={}", urlenc(&echoed)),
    );
    assert_eq!(r["status"].as_bool(), Some(true), "re-save rejected: {r}");

    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("settings.json")).unwrap()).unwrap();
    let stored = saved["smart_folders"]
        .as_array()
        .expect("smart_folders missing from settings.json");
    for rule in stored {
        let keys: Vec<_> = rule
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| k.contains("verdict"))
            .collect();
        assert!(
            keys.is_empty(),
            "a verdict was written to settings.json: {rule}"
        );
    }
    // And the rules themselves survived the round trip intact.
    assert_eq!(stored.len(), 3);
    assert_eq!(stored[0]["match"].as_str(), Some("*anime*"));
    assert_eq!(stored[2]["not_match"].as_str(), Some(".*"));

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// #18, the save-time half: the answer to Apply carries the warning.
///
/// The row annotation above only surfaces on the next READ of the
/// settings; the moment the user is actually looking is the save. A rule
/// whose pattern will not compile is still accepted (the keyword
/// fallback is documented behaviour and refusing would change matching),
/// but the answer must name the rule and carry the engine's compile
/// error so the dashboard can toast it.
#[test]
fn saving_an_uncompilable_rule_warns_in_the_answer_without_refusing_the_save() {
    let dir = scratch("rulesavewarn");
    let d = serve(&dir);

    // One broken match, one broken "but not" on an unnamed rule, and one
    // fine rule. The dangerous-but-VALID catch-all must not warn here:
    // "everything else goes to misc" as a deliberate last rule would
    // otherwise toast on every re-save, teaching people to ignore it.
    let rules = r#"[{"name":"animes","match":"*anime*","category":"anime"},
                    {"match":"1080p","not_match":"[a-","category":"movies"},
                    {"name":"catchall","match":".*","category":"misc"}]"#;
    let r = api(
        d.port,
        &format!("mode=config&name=smart_folders&value={}", urlenc(rules)),
    );
    assert_eq!(
        r["status"].as_bool(),
        Some(true),
        "the save was refused: {r}"
    );
    let w = r["warning"].as_str().expect("no warning in the answer");
    assert!(w.contains("\"animes\""), "rule not named: {w}");
    assert!(w.contains("*anime*"), "pattern not shown: {w}");
    // The engine's own reason rides along, not a paraphrase.
    assert!(w.contains("repetition"), "compile error missing: {w}");
    // The nameless rule is still findable by its position...
    assert!(w.contains("rule 2"), "unnamed rule not located: {w}");
    assert!(w.contains("[a-"), "but-not pattern not shown: {w}");
    // ...and the valid catch-all said nothing.
    assert!(!w.contains("catchall"), "a valid pattern warned: {w}");

    // A list whose patterns all compile answers exactly as before.
    let clean = r#"[{"name":"ok","match":"2160p","category":"movies"}]"#;
    let r = api(
        d.port,
        &format!("mode=config&name=smart_folders&value={}", urlenc(clean)),
    );
    assert_eq!(r["status"].as_bool(), Some(true), "{r}");
    assert!(r["warning"].is_null(), "a clean save warned: {r}");

    // The custom-category editor rides the same engine and gets the same
    // save-time answer.
    let cats = r#"[{"slug":"anime","name":"Anime","match":"*anime*","base":"tv"}]"#;
    let r = api(
        d.port,
        &format!("mode=config&name=custom_categories&value={}", urlenc(cats)),
    );
    assert_eq!(r["status"].as_bool(), Some(true), "{r}");
    let w = r["warning"]
        .as_str()
        .expect("no warning for custom_categories");
    assert!(w.contains("\"Anime\"") && w.contains("*anime*"), "{w}");

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// #17: importing a sabnzbd.ini brings its categories over, merged.
///
/// Categories are not cosmetic on this side. `register_cat` exists
/// because Sonarr and Radarr validate their configured category against
/// our list and REFUSE TO CONNECT when it is missing, and it only runs
/// when a job carrying that category arrives - the wrong order for a
/// migration. Without this the *arrs fail their category check from the
/// moment the servers land until someone retypes every category by hand.
///
/// The folder half is applied per category ON PURPOSE, and this pins it:
/// the paths come from the machine SAB ran on, so on a real migration
/// some of them do not exist here. One unreachable path must not abandon
/// the overrides that would have worked, and the ones it drops must be
/// reported rather than left to a log line.
#[test]
fn importing_a_sabnzbd_ini_merges_its_categories_and_says_what_it_could_not_take() {
    let dir = scratch("sabcats");
    let reachable = dir.join("reach");
    std::fs::create_dir_all(&reachable).unwrap();
    let ini = dir.join("sabnzbd.ini");
    std::fs::write(
        &ini,
        format!(
            "[misc]\ncomplete_dir = {}\n\
             [categories]\n\
             [[*]]\nname = *\ndir = \"\"\n\
             [[movies_anime]]\nname = movies_anime\norder = 0\ndir = movies/anime\nnewzbin = *anime*\n\
             [[books]]\nname = books\ndir = books\n\
             [[series]]\nname = series\ndir = /nonexistent-root-for-this-test/series\n\
             [servers]\n[[news.example.com]]\nhost = news.example.com\nport = 563\n",
            reachable.display()
        ),
    )
    .unwrap();

    let d = serve(&dir);
    let before = settings_block(d.port)["categories"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(before.contains("books"), "built-ins missing: {before}");

    let r = api(
        d.port,
        &format!(
            "mode=import_apply&value={}&value2=sabnzbd",
            urlenc(&ini.to_string_lossy())
        ),
    );
    assert_eq!(r["status"].as_bool(), Some(true), "import failed: {r}");
    let cats = &r["categories"];

    // Merged, not replaced: the built-ins survive and the new ones join.
    let after = settings_block(d.port)["categories"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    for want in ["books", "movies", "music", "tv", "movies_anime", "series"] {
        assert!(after.contains(want), "{want} missing after import: {after}");
    }
    // `*` is SAB's default category, not a real one.
    assert!(!after.split(',').any(|c| c.trim() == "*"), "{after}");

    // The reachable override landed and is ABSOLUTE (the settings arm
    // refuses a relative path outright).
    let dests = settings_block(d.port)["move_completed_cats"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        dests.contains("movies_anime=") && dests.contains("/movies/anime"),
        "the resolvable override did not land: {dests}"
    );
    // `books`'s dir is just its own name, which is already what we do -
    // an override there would say nothing.
    assert!(
        !dests.contains("books="),
        "an override was emitted that changes nothing: {dests}"
    );
    // The unreachable one did NOT take the others down with it, and it
    // is reported with its reason.
    assert!(!dests.contains("series="), "{dests}");
    let failed = cats["folders_failed"].as_array().expect("folders_failed");
    assert_eq!(failed.len(), 1, "{cats}");
    assert_eq!(failed[0]["name"].as_str(), Some("series"));
    assert!(
        !failed[0]["error"].as_str().unwrap_or_default().is_empty(),
        "a dropped folder must say why: {cats}"
    );

    // Everything with nowhere to go is named, so the import cannot look
    // complete when it is not.
    let dropped = cats["dropped"]
        .as_array()
        .expect("dropped")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    for want in ["order", "indexer-category"] {
        assert!(dropped.contains(want), "{want:?} not reported: {dropped:?}");
    }

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// POST a JSON body and return the response body (headers stripped).
/// `server_save` is the one endpoint this suite writes through that
/// takes its payload in the body rather than the query string.
fn http_post(port: u16, req: &str, body: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    write!(
        s,
        "POST {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
}

/// TODO 110: the per-server address allowance (`max_source_ips`) is a
/// setting in three places - the server_save merge, the dashboard form,
/// and get_config's servers block - and this pins the round trip through
/// the two the daemon owns: saved, echoed back with the derived
/// `tight_ips` verdict (which drives the idle-release defaults and the
/// samplers' slots-full stand-down), and REMOVED from the config file
/// when cleared rather than written as a 0 that would pin the old
/// behavior.
#[test]
fn max_source_ips_round_trips_and_clears() {
    let dir = scratch("maxips");
    let d = serve(&dir);
    // The host is deliberately NOT in the caps_source_ips hostname
    // list, so any tight verdict below can only come from the declared
    // number - the eweka shape the setting exists for.
    let saved = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":-1,"server":{"host":"news.capped.example","port":563,"connections":8,"max_source_ips":2}}"#,
    );
    assert!(saved.contains("\"status\":true"), "save failed: {saved}");
    let srv = |port: u16| -> serde_json::Value {
        settings_block(port)["servers"]
            .as_array()
            .expect("servers array")
            .iter()
            .find(|s| s["host"] == "news.capped.example")
            .expect("saved server echoed")
            .clone()
    };
    let s = srv(d.port);
    assert_eq!(s["max_source_ips"], 2, "declared cap must echo: {s}");
    assert_eq!(
        s["idle_release_effective"]["tight_ips"], true,
        "a declared 2-address cap must read as tight: {s}"
    );
    assert_eq!(
        s["idle_release_effective"]["keep"], 0,
        "tight addresses derive an idle keep of zero: {s}"
    );

    // Clearing the field (the UI sends "" for an emptied box) removes
    // the key outright - back to the hostname heuristic, which knows
    // nothing about this host.
    let cleared = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"news.capped.example","port":563,"connections":8,"max_source_ips":""}}"#,
    );
    assert!(
        cleared.contains("\"status\":true"),
        "clear failed: {cleared}"
    );
    let s = srv(d.port);
    assert_eq!(s["max_source_ips"], serde_json::Value::Null, "cleared: {s}");
    assert_eq!(s["idle_release_effective"]["tight_ips"], false, "{s}");
    let disk = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(
        !disk.contains("max_source_ips"),
        "a cleared field must be removed, not stored as 0: {disk}"
    );

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// M32's route controls (`bind_ip`, `socks5`) shipped in the engine in
/// July and could only be set by hand-editing config.local.json until
/// the server editor grew rows for them. The SOCKS spec is stored as ONE
/// string that may end in a proxy password, so the editor edits it as
/// three fields - and this pins the property that makes that safe: the
/// password is never echoed, and a blank password box keeps the stored
/// one instead of wiping it, exactly like the server password beside it.
#[test]
fn socks5_and_bind_ip_round_trip_without_echoing_the_proxy_password() {
    let dir = scratch("socksbind");
    let d = serve(&dir);
    let srv = |port: u16| -> serde_json::Value {
        settings_block(port)["servers"]
            .as_array()
            .expect("servers array")
            .iter()
            .find(|s| s["host"] == "news.routed.example")
            .expect("saved server echoed")
            .clone()
    };
    let saved = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":-1,"server":{"host":"news.routed.example","port":563,"connections":8,
            "bind_ip":"192.168.1.50","socks5":"127.0.0.1:1080",
            "socks5_user":"pxu","socks5_pass":"pxsecret"}}"#,
    );
    assert!(saved.contains("\"status\":true"), "save failed: {saved}");
    let s = srv(d.port);
    assert_eq!(s["bind_ip"], "192.168.1.50", "bind address must echo: {s}");
    assert_eq!(
        s["socks5"], "127.0.0.1:1080",
        "only the proxy host:port may echo: {s}"
    );
    assert_eq!(s["socks5_user"], "pxu", "proxy user may echo: {s}");
    assert_eq!(s["has_socks5_pass"], true, "presence flag only: {s}");
    assert!(
        !serde_json::Value::Object(settings_block(d.port))
            .to_string()
            .contains("pxsecret"),
        "the proxy password must never reach the UI"
    );
    // What the connection actually uses, and the form the engine's
    // socks5_connect parses: creds welded back onto the address.
    let disk = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(
        disk.contains("pxu:pxsecret@127.0.0.1:1080"),
        "stored spec must recombine: {disk}"
    );

    // The editor round-trip: a blank password box (the UI never receives
    // the stored one, so it always posts blank) must not wipe it.
    let again = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"news.routed.example","port":563,"connections":8,
            "bind_ip":"192.168.1.50","socks5":"127.0.0.1:1081",
            "socks5_user":"pxu","socks5_pass":""}}"#,
    );
    assert!(again.contains("\"status\":true"), "resave failed: {again}");
    let disk = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(
        disk.contains("pxu:pxsecret@127.0.0.1:1081"),
        "a blank password box keeps the stored password: {disk}"
    );

    // Clearing the user name removes the whole credential - the stored
    // password must not survive the user it belonged to.
    let noauth = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"news.routed.example","port":563,"connections":8,
            "socks5":"127.0.0.1:1081","socks5_user":"","socks5_pass":"","bind_ip":""}}"#,
    );
    assert!(
        noauth.contains("\"status\":true"),
        "resave failed: {noauth}"
    );
    let disk = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(
        !disk.contains("pxsecret"),
        "clearing the user must drop the password too: {disk}"
    );
    assert!(
        !disk.contains("bind_ip"),
        "cleared field is removed: {disk}"
    );

    // A whole spec pasted into the address box would put the proxy
    // password in the echoed field, so it is refused rather than stored.
    let pasted = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"news.routed.example","port":563,"connections":8,
            "socks5":"u:p@127.0.0.1:1080"}}"#,
    );
    assert!(
        pasted.contains("\"status\":false"),
        "a spec with credentials must be refused: {pasted}"
    );
    let bad_ip = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"news.routed.example","port":563,"connections":8,
            "bind_ip":"not-an-ip"}}"#,
    );
    assert!(
        bad_ip.contains("\"status\":false"),
        "a bind address that is not an IP must be refused: {bad_ip}"
    );

    // Port 0 parses as a u16 and connects to nothing. Accepted, it saved
    // and then failed every fetch through this provider with an OS error
    // where the form should have said so (Codex sweep 7, L5). The
    // boundaries either side of it stay valid.
    let zero = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"news.routed.example","port":563,"connections":8,
            "socks5":"127.0.0.1:0"}}"#,
    );
    assert!(
        zero.contains("\"status\":false"),
        "a zero proxy port must be refused: {zero}"
    );
    let disk = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(
        !disk.contains("127.0.0.1:0\""),
        "a refused proxy address must not persist: {disk}"
    );
    for edge in ["127.0.0.1:1", "127.0.0.1:65535"] {
        let ok = http_post(
            d.port,
            "/api?mode=server_save&output=json",
            &format!(
                r#"{{"index":0,"server":{{"host":"news.routed.example","port":563,
                    "connections":8,"socks5":"{edge}"}}}}"#
            ),
        );
        assert!(
            ok.contains("\"status\":true"),
            "{edge} is a usable port: {ok}"
        );
    }

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A Flatpak install must be told apart from a container install, because
/// the dashboard shows a DIFFERENT update recipe for each and the
/// container one is Docker-specific to the last word - compose files,
/// Watchtower, the Synology Container Manager. Showing that to somebody
/// who installed from a software centre would be worse than showing
/// nothing.
///
/// The download page is equally wrong for both (a Flatpak cannot replace
/// its own files), which is the trap this guards: folding `flatpak` into
/// `container` makes the chip work and the advice nonsense, and nothing
/// downstream would fail.
#[test]
fn a_flatpak_install_is_reported_separately_from_a_container_one() {
    let dir = scratch("flatpak-flag");
    let d = serve_flatpak(&dir);
    let q = api(d.port, "mode=queue");

    assert_eq!(
        q["queue"]["flatpak"].as_bool(),
        Some(true),
        "a Flatpak install did not report itself: {q}"
    );
    assert_eq!(
        q["queue"]["container"].as_bool(),
        Some(false),
        "a Flatpak was reported as a container, which would show the \
         compose-file update recipe to a desktop user: {q}"
    );

    drop(d);
}

/// The same daemon with nothing set reports neither, so the assertion
/// above is about FLATPAK_ID and not about a field that is simply always
/// true.
#[test]
fn a_plain_install_reports_neither_flatpak_nor_container() {
    let dir = scratch("plain-flags");
    let d = serve(&dir);
    let q = api(d.port, "mode=queue");

    assert_eq!(q["queue"]["flatpak"].as_bool(), Some(false), "{q}");
    assert_eq!(q["queue"]["container"].as_bool(), Some(false), "{q}");

    drop(d);
}
