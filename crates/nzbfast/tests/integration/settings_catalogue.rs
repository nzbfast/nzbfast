//! The settings lists agree.
//!
//! A setting is spread across three places that are kept in step BY HAND:
//!
//!  1. the `apply_setting` match in settings.rs - the allowlist,
//!     since its `_` arm is what rejects an unknown name;
//!  2. the settings table in settings.rs, which `get_config` is
//!     built by walking - what the dashboard reads back;
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
//! from - so that list can no longer be missed, and the
//! `apply_arms_match_the_table` reflection test in tests_api.rs
//! holds (1) to the same table. (3) is the one that genuinely resists
//! collapsing: `apply_saved_settings` maps saved JSON onto launch
//! options before the daemon exists, so its work is bespoke per setting
//! and shares no shape with the others.
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

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Stdio};

// `KillOnDrop` for the one test that launches by hand: `--port 0` has no
// port to hand `harness::serve_blocking`, and it waits on runtime.json
// rather than on a banner.
use crate::harness::{Daemon, KillOnDrop};

/// Settable, but deliberately never echoed by `get_config`.
///
/// All but the last are credentials: `get_config` is a read anyone holding
/// the API key can make from a browser, so they surface as `has_*` flags
/// instead and the value never leaves the daemon. `index_interests_applied`
/// is a one-shot marker recording that the interest presets were expanded
/// into scan groups - it has no control on the settings page.
const SETTABLE_NOT_ECHOED: &[&str] = &[
    "apikey",
    "nzbkey",
    "omdb_key",
    "scoreboard_key",
    "tmdb_key",
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
    "local_link",
    // TODO 314 stage 1: which subprocess confinement mechanism this box
    // has, and one sentence about it. Nothing to set - it is what the
    // machine offers, not a choice. `script_confined` beside it IS the
    // choice and is a normal rw setting.
    "sandbox",
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
    "has_tmdb",
    // How many passwords the passwords file currently holds - display
    // only; the file itself (not this row) is what you edit.
    "password_file_count",
];

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
        include_str!("../../../nzbfast-daemon/src/settings.rs"),
        include_str!("../../../nzbfast-daemon/src/settings_apply.rs"),
    );
    let mut names = Vec::new();
    let mut inside = false;
    for line in src.lines() {
        if line.starts_with("pub fn apply_setting(")
            || line.starts_with("pub(super) fn apply_setting_tail")
        {
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
fn serve(dir: &Path) -> Daemon {
    serve_env(dir, &[])
}

/// `serve` as a launcher that owns the port (container / Synology package).
fn serve_locked(dir: &Path) -> Daemon {
    serve_env(dir, &[("NZBFAST_PORT_LOCKED", "1")])
}

/// `serve` as a Flatpak install. `FLATPAK_ID` is one of the two markers
/// `flatpak_install()` reads; the other is `/.flatpak-info`, which a test
/// cannot create.
fn serve_flatpak(dir: &Path) -> Daemon {
    serve_env(dir, &[("FLATPAK_ID", "io.github.nzbfast.nzbfast")])
}

fn serve_env(dir: &Path, env: &[(&str, &str)]) -> Daemon {
    crate::harness::serve_blocking(dir, |port| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.env("NZBFAST_NO_ENRICH", "1")
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
            .arg(dir.join("index.db"));
        cmd
    })
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
}

/// The §282 alternate-candidate NUMBERS survive a restart too.
///
/// `settings_survive_a_restart` above cannot see these. It discovers its
/// targets with `v.as_bool()`, which is what makes it maintenance-free
/// for flags - and which silently excludes every numeric key on the
/// settings surface. `alt_auto_switch` and `alt_auto_search` are covered
/// there; `alt_hold_count`, `alt_max_copies` and `alt_max_extra_bytes`
/// had no automated restore coverage at all.
///
/// TODO §282 item 19 is why that gap is worth a test of its own rather
/// than a note. While `alt_hold_count` defaulted to 0, a dropped restore
/// block reset a user's 3 to 0 and the feature visibly stopped holding
/// spares - loud, and someone would report it. Defaulting it to 2 makes
/// the same bug reset their 0 or their 5 to 2, which reads as a working
/// default rather than as a lost setting. And 2 is the number the whole
/// cost argument rides on: a user who set 0 because they are on a
/// metered account would be silently put back to holding spares.
///
/// Deliberately a NAMED LIST and not a reflective sweep of every number
/// `get_config` reports. A number is not a flag: `port`, `speedlimit`
/// and the tuner bounds carry ranges, clamps and meanings, so "set it to
/// something else" is not a safe universal move the way "flip it" is.
/// The values below are chosen to be inside each key's clamp and
/// different from every default, so a revert cannot pass by coincidence.
#[test]
fn the_alternate_candidate_numbers_survive_a_restart() {
    let dir = scratch("restart-altnums");
    // Each is away from its shipped default (2 / 2 / 0) and inside the
    // clamp its `apply_setting` arm applies (hold 0-10, copies 1-10).
    let want: [(&str, u64); 3] = [
        ("alt_hold_count", 5),
        ("alt_max_copies", 4),
        ("alt_max_extra_bytes", 21_474_836_480),
    ];
    {
        let d = serve(&dir);
        for (name, v) in &want {
            let r = api(d.port, &format!("mode=config&name={name}&value={v}"));
            assert_eq!(
                r["status"].as_bool(),
                Some(true),
                "setting {name} was rejected: {r}"
            );
        }
        // Live first, so a key that never reached the daemon does not
        // read as a restart failure below.
        let after = settings_block(d.port);
        for (name, v) in &want {
            assert_eq!(
                after.get(*name).and_then(serde_json::Value::as_u64),
                Some(*v),
                "saved, but get_config still reports the old value for {name} -                  the apply_setting arm validated it without applying it"
            );
        }
    } // daemon killed here

    // Same directory, new process: settings.json is the only carrier.
    let d = serve(&dir);
    let restored = settings_block(d.port);
    for (name, v) in &want {
        assert_eq!(
            restored.get(*name).and_then(serde_json::Value::as_u64),
            Some(*v),
            "{name} reverted across a restart. Saved to settings.json but \
             never read back at launch - add it to restore_ui_and_index_settings"
        );
    }
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
    // Through `spawn_under_test`, not a bare `.spawn()`: that is where
    // the cargo-uplift ENOENT grace lives AND where the child is told
    // which process to outlive by nothing. A daemon from THIS launcher
    // (`nzbfast-setcat-*-restart`) is in the 30 Aug leak set - see
    // `harness::leash`.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
    cmd.env("NZBFAST_NO_ENRICH", "1")
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
        .stderr(Stdio::from(err));
    let mut child = KillOnDrop(crate::harness::spawn_under_test(&mut cmd));

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
    let _log = d.stop();
    let d = serve(&dir);
    assert_eq!(
        settings_block(d.port)
            .get("min_free")
            .and_then(|v| v.as_u64()),
        Some(25_000_000_000),
        "a non-zero floor did not survive the restart"
    );
}

/// History retention round-trips in SECONDS, and a config written
/// before the unit changed still means what it meant.
///
/// The two knobs (§129 D5) existed for months with no control on the
/// settings page - the only way to set them was to hand-edit
/// settings.json, which is what issue #45 was told to do. That issue gave them
/// a card, and moved the age knob from DAYS to seconds so "20 minutes
/// after it finished" is expressible at all.
///
/// That is a unit change on a live key, and the thing it must never do
/// is reinterpret one. A settings.json holding `history_keep_days: 30`
/// has to keep meaning thirty days; read as thirty SECONDS it would wipe
/// the user's entire history the first time the daemon came up. So the
/// old key is still read - multiplied - and only when the new one is
/// absent, since the two are one setting and the one the dashboard
/// writes has to win.
///
/// Not covered by `settings_survive_a_restart` (booleans only), and the
/// same "0 is a real value, not unset" trap as `min_free` sits under
/// both halves: 0 means "this rule is off", and a restore path that read
/// it as "nothing saved" would quietly re-arm a deletion the user had
/// just turned off.
#[test]
fn history_retention_round_trips_in_seconds_and_reads_the_older_days_key() {
    let dir = scratch("histkeep");

    {
        let d = serve(&dir);
        // Ships OFF, by ruling: history is unlimited until asked otherwise.
        let fresh = settings_block(d.port);
        assert_eq!(
            fresh.get("history_keep_secs").and_then(|v| v.as_u64()),
            Some(0),
            "history retention must ship off"
        );
        assert_eq!(
            fresh.get("history_keep_count").and_then(|v| v.as_u64()),
            Some(0),
            "history retention must ship off"
        );
        // The value issue #45 actually asked for: minutes, not days.
        for (k, v) in [("history_keep_secs", 1200), ("history_keep_count", 50)] {
            let r = api(d.port, &format!("mode=config&name={k}&value={v}"));
            assert_eq!(r["status"].as_bool(), Some(true), "{k}={v} rejected: {r}");
        }
        let live = settings_block(d.port);
        assert_eq!(
            live.get("history_keep_secs").and_then(|v| v.as_u64()),
            Some(1200),
            "20 minutes did not reach the running daemon"
        );
        assert_eq!(
            live.get("history_keep_count").and_then(|v| v.as_u64()),
            Some(50)
        );
    } // daemon killed here

    {
        let d = serve(&dir);
        let back = settings_block(d.port);
        assert_eq!(
            back.get("history_keep_secs").and_then(|v| v.as_u64()),
            Some(1200),
            "the age rule did not survive the restart"
        );
        assert_eq!(
            back.get("history_keep_count").and_then(|v| v.as_u64()),
            Some(50),
            "the count rule did not survive the restart"
        );
        // Turning it back off has to STAY off - this is the control that
        // deletes things, so a 0 that reverts is the dangerous direction.
        for k in ["history_keep_secs", "history_keep_count"] {
            let r = api(d.port, &format!("mode=config&name={k}&value=0"));
            assert_eq!(r["status"].as_bool(), Some(true), "{k}=0 rejected: {r}");
        }
    }

    {
        let d = serve(&dir);
        let off = settings_block(d.port);
        assert_eq!(
            off.get("history_keep_secs").and_then(|v| v.as_u64()),
            Some(0),
            "an explicit 0 came back non-zero - retention re-armed itself"
        );
        assert_eq!(
            off.get("history_keep_count").and_then(|v| v.as_u64()),
            Some(0),
            "an explicit 0 came back non-zero - retention re-armed itself"
        );
    }

    // A settings.json written before the unit change: the old key, no new one.
    std::fs::write(dir.join("settings.json"), "{\"history_keep_days\": 30}").unwrap();
    {
        let d = serve(&dir);
        assert_eq!(
            settings_block(d.port)
                .get("history_keep_secs")
                .and_then(|v| v.as_u64()),
            Some(30 * 86_400),
            "an existing history_keep_days was not read as days - a config \
             from before the unit change now means something else entirely"
        );
    }

    // Both keys present: the one the dashboard writes wins, or a value
    // saved today would be overruled by one saved before the change.
    std::fs::write(
        dir.join("settings.json"),
        "{\"history_keep_days\": 30, \"history_keep_secs\": 600}",
    )
    .unwrap();
    {
        let d = serve(&dir);
        assert_eq!(
            settings_block(d.port)
                .get("history_keep_secs")
                .and_then(|v| v.as_u64()),
            Some(600),
            "the legacy days key overruled the current one"
        );
    }
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

    // One that will not compile, one that matches everything, one
    // ordinary rule whose "but not" is the broken half, and one wildcard
    // pattern - which does not compile either and must NOT be marked,
    // because it globs.
    let rules = r#"[{"name":"a","match":"(unclosed","category":"anime"},
                    {"name":"b","match":"!*","category":"junk"},
                    {"name":"c","match":"2160p","not_match":".*","category":"movies"},
                    {"name":"d","match":"*anime*","category":"anime"}]"#;
    let r = api(
        d.port,
        &format!("mode=config&name=smart_folders&value={}", urlenc(rules)),
    );
    assert_eq!(r["status"].as_bool(), Some(true), "rules rejected: {r}");

    let read = settings_block(d.port);
    let got = read["smart_folders"].as_array().expect("smart_folders");
    assert_eq!(got.len(), 4, "{got:?}");
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
    // A `*`/`?` pattern is a glob rather than dead text (§104.2), so it
    // is not marked either - the row mark exists to find rules that do
    // nothing, and this one works.
    assert!(
        got[3].get("match_verdict").is_none(),
        "a wildcard rule was marked as broken: {}",
        got[3]
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
    assert_eq!(stored.len(), 4);
    assert_eq!(stored[0]["match"].as_str(), Some("(unclosed"));
    assert_eq!(stored[3]["match"].as_str(), Some("*anime*"));
    assert_eq!(stored[2]["not_match"].as_str(), Some(".*"));

    drop(d);
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
    let rules = r#"[{"name":"animes","match":"(unclosed","category":"anime"},
                    {"match":"1080p","not_match":"[a-","category":"movies"},
                    {"name":"catchall","match":".*","category":"misc"},
                    {"name":"globbed","match":"*anime*","category":"anime"}]"#;
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
    assert!(w.contains("(unclosed"), "pattern not shown: {w}");
    // The engine's own reason rides along, not a paraphrase.
    assert!(w.contains("closing"), "compile error missing: {w}");
    // The nameless rule is still findable by its position...
    assert!(w.contains("rule 2"), "unnamed rule not located: {w}");
    assert!(w.contains("[a-"), "but-not pattern not shown: {w}");
    // ...and the valid catch-all said nothing.
    assert!(!w.contains("catchall"), "a valid pattern warned: {w}");
    // Nor did the wildcard rule: it does not compile as a regex, but that
    // is the glob arm working, not a mistake to report (§104.2).
    assert!(!w.contains("globbed"), "a wildcard pattern warned: {w}");

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
    let cats = r#"[{"slug":"anime","name":"Anime","match":"(unclosed","base":"tv"}]"#;
    let r = api(
        d.port,
        &format!("mode=config&name=custom_categories&value={}", urlenc(cats)),
    );
    assert_eq!(r["status"].as_bool(), Some(true), "{r}");
    let w = r["warning"]
        .as_str()
        .expect("no warning for custom_categories");
    assert!(w.contains("\"Anime\"") && w.contains("(unclosed"), "{w}");

    drop(d);
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
}

/// PLAN M32 / nzbget#359: the other half of the switcher funnel.
/// Importing an nzbget.conf brings servers (with their backup tiers),
/// categories, and NZBGet's `DownloadRate` speed limit over - the same
/// three the SAB counterpart test above pins, adapted to NZBGet's flat
/// `Key=Value` shape and its `${MainDir}`/`${DestDir}` substitution.
#[test]
fn importing_an_nzbget_conf_brings_servers_categories_and_the_speed_limit() {
    let dir = scratch("nzbgetimport");
    let main = dir.join("main");
    std::fs::create_dir_all(&main).unwrap();
    let conf = dir.join("nzbget.conf");
    std::fs::write(
        &conf,
        format!(
            "MainDir={}\nDestDir=${{MainDir}}/dst\nDownloadRate=1500\n\
             Server1.Active=yes\nServer1.Host=news.tier0.example.com\n\
             Server1.Port=563\nServer1.Username=u1\nServer1.Password=p1\n\
             Server1.Encryption=yes\nServer1.Connections=20\nServer1.Level=0\n\
             Server2.Active=yes\nServer2.Host=news.tier1.example.com\n\
             Server2.Encryption=no\nServer2.Level=1\n\
             Category1.Name=movies\nCategory1.DestDir=${{DestDir}}/Films\n\
             Category1.Unpack=yes\n\
             Category2.Name=tv\nCategory2.Aliases=television*, tv-*\n",
            main.display()
        ),
    )
    .unwrap();

    let d = serve(&dir);
    let r = api(
        d.port,
        &format!(
            "mode=import_apply&value={}&value2=nzbget",
            urlenc(&conf.to_string_lossy())
        ),
    );
    assert_eq!(r["status"].as_bool(), Some(true), "import failed: {r}");
    assert_eq!(r["added"].as_u64(), Some(2), "{r}");

    // Both servers landed, with their backup tier intact - Level 0 is
    // the primary, Level 1 the backup tier that only fills in.
    let servers = settings_block(d.port)["servers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let by_host = |h: &str| {
        servers
            .iter()
            .find(|s| s["host"].as_str() == Some(h))
            .unwrap_or_else(|| panic!("{h} missing: {servers:?}"))
            .clone()
    };
    assert_eq!(by_host("news.tier0.example.com")["level"].as_i64(), Some(0));
    assert_eq!(by_host("news.tier1.example.com")["level"].as_i64(), Some(1));
    // enabled is explicit, never absent - a redeploy onto an older
    // config must not silently pause a server it never heard of.
    assert_eq!(by_host("news.tier0.example.com")["enabled"], true);

    // Categories merged...
    let after = settings_block(d.port)["categories"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    for want in ["movies", "tv"] {
        assert!(after.contains(want), "{want} missing after import: {after}");
    }
    // ...and the resolvable folder override landed, absolute and built
    // out of NZBGet's own ${DestDir} substitution.
    let dests = settings_block(d.port)["move_completed_cats"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        dests.contains("movies=") && dests.contains("/dst/Films"),
        "{dests}"
    );

    // Fields with nowhere to go (Unpack, Aliases) are named, not
    // silently dropped.
    let dropped = r["categories"]["dropped"]
        .as_array()
        .expect("dropped")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(dropped.contains("unpack override"), "{dropped:?}");
    assert!(dropped.contains("external category names"), "{dropped:?}");

    // The speed limit came over, converted from NZBGet's 1024-byte
    // kilobytes/sec to nzbfast's own raw bytes/sec.
    assert_eq!(r["speedlimit_kbps"].as_u64(), Some(1500), "{r}");
    assert_eq!(
        settings_block(d.port)["speedlimit"].as_u64(),
        Some(1500 * 1024),
        "{r}"
    );

    drop(d);
}

/// A malformed or unreadable nzbget.conf refuses cleanly, with a
/// reason, rather than importing whatever it could half-parse.
#[test]
fn a_malformed_nzbget_conf_is_refused_not_partially_imported() {
    let dir = scratch("nzbgetbad");
    let d = serve(&dir);

    let apply = |path: &std::path::Path| {
        api(
            d.port,
            &format!(
                "mode=import_apply&value={}&value2=nzbget",
                urlenc(&path.to_string_lossy())
            ),
        )
    };

    // No readable file at all.
    let r = apply(&dir.join("does-not-exist.conf"));
    assert_eq!(r["status"].as_bool(), Some(false), "{r}");
    assert!(!r["error"].as_str().unwrap_or_default().is_empty(), "{r}");

    // A real file with no servers in it must not add anything, and must
    // not report success as if it had.
    let empty = dir.join("noservers.conf");
    std::fs::write(&empty, "MainDir=/tmp\nDownloadRate=500\n").unwrap();
    let r = apply(&empty);
    assert_eq!(r["added"].as_u64(), Some(0), "{r}");
    assert!(
        settings_block(d.port)["servers"]
            .as_array()
            .map(Vec::is_empty)
            .unwrap_or(true),
        "a server-less file must not have added one: {r}"
    );

    drop(d);
}

/// #46: probing a user-typed path says WHY it came up empty. There is
/// exactly one candidate in that mode, and the two empty answers have
/// opposite remedies - fix the path vs accept the file has no servers -
/// so the probe must tell them apart or the UI can only shrug.
#[test]
fn probing_a_typed_path_says_why_it_found_nothing() {
    let dir = scratch("probemiss");
    std::fs::create_dir_all(&dir).unwrap();
    let d = serve(&dir);

    let probe = |path: &str| api(d.port, &format!("mode=import_probe&value={}", urlenc(path)));

    let r = probe(&dir.join("nowhere.conf").to_string_lossy());
    assert_eq!(r["candidates"].as_array().map(Vec::len), Some(0), "{r}");
    assert_eq!(r["miss"].as_str(), Some("unreadable"), "{r}");

    let empty = dir.join("empty-nzbget.conf");
    std::fs::write(&empty, "MainDir=/tmp\n").unwrap();
    let r = probe(&empty.to_string_lossy());
    assert_eq!(r["candidates"].as_array().map(Vec::len), Some(0), "{r}");
    assert_eq!(r["miss"].as_str(), Some("no_servers"), "{r}");

    let real = dir.join("real-nzbget.conf");
    std::fs::write(&real, "Server1.Host=news.example.com\nServer1.Port=563\n").unwrap();
    let r = probe(&real.to_string_lossy());
    assert_eq!(r["candidates"].as_array().map(Vec::len), Some(1), "{r}");
    assert!(r["miss"].is_null(), "{r}");

    drop(d);
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
}

/// §291 box 2 (public issue #60): the per-server TLS name override, end
/// to end through the surface someone with a reverse-proxied or
/// self-hosted provider would actually use.
///
/// What is pinned here is the SURFACE only, and the distinction matters:
/// that the value survives a round trip, that a cleared box goes back to
/// the default rather than storing an empty name, that a partial save
/// leaves it alone, and that a value the handshake could not use is
/// refused at the form instead of stored. The property that the name
/// actually REACHES the handshake - as both the verified name and the
/// SNI - is asserted against a real rustls session in
/// `crates/nzbkit/tests/integration/tls.rs`
/// (`the_tls_name_override_is_what_the_handshake_verifies_and_announces`),
/// because a test that stops at the config struct is exactly the shape
/// that let the sibling box's `db2523936` defect sit green for a day.
///
/// The refusal arm is not symmetry with `address_family`. That one has a
/// lenient loader behind it; this one has none, so a stored name the
/// handshake cannot parse would fail every dial to this provider with a
/// `TlsName` error and nothing on screen tying it to the box that was
/// typed into.
#[test]
fn tls_hostname_round_trips_and_clears() {
    let dir = scratch("tlsname");
    let d = serve(&dir);
    let srv = |port: u16| -> serde_json::Value {
        settings_block(port)["servers"]
            .as_array()
            .expect("servers array")
            .iter()
            .find(|s| s["host"] == "10.0.0.7")
            .expect("saved server echoed")
            .clone()
    };
    // Saved without the field at all: blank, which is the editor's empty
    // box and the daemon's "check the host we dial".
    let saved = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":-1,"server":{"host":"10.0.0.7","port":563,"connections":8}}"#,
    );
    assert!(saved.contains("\"status\":true"), "save failed: {saved}");
    let s = srv(d.port);
    assert_eq!(s["tls_hostname"], "", "absent echoes blank: {s}");
    let disk = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(
        !disk.contains("tls_hostname"),
        "unset is not written: {disk}"
    );

    let saved = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"10.0.0.7","port":563,"connections":8,
            "tls_hostname":"news.cert.example"}}"#,
    );
    assert!(saved.contains("\"status\":true"), "save failed: {saved}");
    let s = srv(d.port);
    assert_eq!(s["tls_hostname"], "news.cert.example", "must echo: {s}");
    let disk = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(
        disk.contains(r#""tls_hostname""#) && disk.contains("news.cert.example"),
        "stored under the wire name: {disk}"
    );

    // A partial save - the "Apply N to this server" button posts only
    // the fields it knows - must leave a stored name alone.
    let partial = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"10.0.0.7","port":563,"connections":12}}"#,
    );
    assert!(
        partial.contains("\"status\":true"),
        "save failed: {partial}"
    );
    assert_eq!(
        srv(d.port)["tls_hostname"],
        "news.cert.example",
        "a partial save must not clear the name"
    );

    // A name the handshake could not use, and an ADDRESS, which is the
    // mistake the box invites and which gets its own message.
    for (bad, want) in [
        (r#""news cert example""#, "not a hostname"),
        (r#""1.2.3.4""#, "not an address"),
    ] {
        let refused = http_post(
            d.port,
            "/api?mode=server_save&output=json",
            &format!(
                r#"{{"index":0,"server":{{"host":"10.0.0.7","port":563,"connections":8,
                    "tls_hostname":{bad}}}}}"#
            ),
        );
        assert!(
            refused.contains("\"status\":false") && refused.contains(want),
            "{bad} must be refused saying {want:?}: {refused}"
        );
    }
    let disk = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(
        !disk.contains("1.2.3.4"),
        "a refused name must not be stored: {disk}"
    );

    // Cleared: back to checking the dialled host, and the key goes away
    // rather than being written empty - an empty TLS name would fail
    // every handshake instead of restoring the default.
    let saved = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"10.0.0.7","port":563,"connections":8,
            "tls_hostname":""}}"#,
    );
    assert!(saved.contains("\"status\":true"), "save failed: {saved}");
    let disk = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(
        !disk.contains("tls_hostname"),
        "a cleared box removes the key: {disk}"
    );
    assert_eq!(srv(d.port)["tls_hostname"], "", "and echoes blank again");
    d.stop();
}

/// §291 (public issue #60): the per-server address-family preference,
/// end to end through the surface the reporter would actually use.
///
/// Three properties, and each one is a bug that shipped in some other
/// setting before it was pinned here. The value ECHOES, or the editor
/// round-trip - which posts the whole form every time - would save
/// `auto` over whatever the user had chosen, the way an unechoed
/// `pin_connections` once silently unpinned a server. `auto` REMOVES the
/// key rather than writing it, because people hand-edit this file and a
/// key restating the default is noise. And a value outside the three is
/// REFUSED here rather than stored, because the loader reads an unknown
/// one as auto (it must not fail a whole config over one preference), so
/// storing it would be a save that silently did nothing.
#[test]
fn address_family_round_trips_and_clears() {
    let dir = scratch("addrfam");
    let d = serve(&dir);
    let srv = |port: u16| -> serde_json::Value {
        settings_block(port)["servers"]
            .as_array()
            .expect("servers array")
            .iter()
            .find(|s| s["host"] == "news.dualstack.example")
            .expect("saved server echoed")
            .clone()
    };
    // A server saved without the field at all: the echo still names a
    // value, so the editor's <select> has something to land on.
    let saved = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":-1,"server":{"host":"news.dualstack.example","port":563,"connections":8}}"#,
    );
    assert!(saved.contains("\"status\":true"), "save failed: {saved}");
    let s = srv(d.port);
    assert_eq!(s["address_family"], "auto", "absent means auto: {s}");

    let saved = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"news.dualstack.example","port":563,"connections":8,
            "address_family":"ipv6"}}"#,
    );
    assert!(saved.contains("\"status\":true"), "save failed: {saved}");
    let s = srv(d.port);
    assert_eq!(s["address_family"], "ipv6", "preference must echo: {s}");
    let disk = std::fs::read_to_string(dir.join("config.json")).unwrap();
    // The file is written pretty-printed, so match the two tokens
    // rather than a packed pair.
    assert!(
        disk.contains(r#""address_family""#) && disk.contains(r#""ipv6""#),
        "stored under the wire name: {disk}"
    );

    // Back to automatic: the key goes away rather than being written.
    let saved = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"news.dualstack.example","port":563,"connections":8,
            "address_family":"auto"}}"#,
    );
    assert!(saved.contains("\"status\":true"), "save failed: {saved}");
    let disk = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(
        !disk.contains("address_family"),
        "auto is removed, not written: {disk}"
    );
    assert_eq!(srv(d.port)["address_family"], "auto", "still echoes auto");

    // A partial save - the "Apply N to this server" button posts only
    // the fields it knows - must leave a stored preference alone.
    let saved = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"news.dualstack.example","port":563,"connections":8,
            "address_family":"ipv4"}}"#,
    );
    assert!(saved.contains("\"status\":true"), "save failed: {saved}");
    let partial = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"news.dualstack.example","port":563,"connections":12}}"#,
    );
    assert!(
        partial.contains("\"status\":true"),
        "save failed: {partial}"
    );
    let s = srv(d.port);
    assert_eq!(
        s["address_family"], "ipv4",
        "a partial save must not clear the preference: {s}"
    );

    // Outside the three: refused with a message, and nothing stored.
    let bad = http_post(
        d.port,
        "/api?mode=server_save&output=json",
        r#"{"index":0,"server":{"host":"news.dualstack.example","port":563,"connections":8,
            "address_family":"v6"}}"#,
    );
    assert!(
        bad.contains("\"status\":false"),
        "an unknown family must be refused: {bad}"
    );
    let disk = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(
        !disk.contains("\"v6\""),
        "the bad value must not be stored: {disk}"
    );
    d.stop();
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
}

/// TODO §20c: a feed url embeds the indexer's API key, and `get_config`
/// used to ship it whole to the browser. It is masked now - and the
/// thing that makes masking possible at all is the feed `id`, because
/// the url used to be the only key a saved edit could be matched on.
///
/// The three legs that have to hold together, since any one of them
/// alone is either a leak or a data-loss bug: the mask reaches the UI,
/// a settings.json written before the id existed is migrated silently
/// and the minted id PERSISTS (an id that changed at every launch would
/// make every masked save land on nothing), and a save carrying the mask
/// back keeps the stored url instead of storing the mask.
#[test]
fn a_feed_url_is_masked_in_get_config_and_round_trips_by_id() {
    let dir = scratch("feedmask");
    // A settings.json in the pre-id shape - which is every settings.json
    // that existed before this landed.
    let key = "b8f3c1d9e7a24601";
    let real = format!("https://idx.example/rss?t=tvsearch&cat=5030&apikey={key}");
    std::fs::write(
        dir.join("settings.json"),
        serde_json::json!({
            "feeds": [{"url": real, "interval_secs": 900, "category": "tv",
                       "rules": ["Accept: *1080p*"]}]
        })
        .to_string(),
    )
    .unwrap();

    let id = {
        let d = serve(&dir);
        let block = serde_json::Value::Object(settings_block(d.port));
        assert!(
            !block.to_string().contains(key),
            "the indexer key must not reach the settings UI: {block}"
        );
        let feed = &block["feeds"][0];
        assert_eq!(
            feed["url"].as_str(),
            Some("https://idx.example/rss?t=tvsearch&cat=5030&apikey=***"),
            "the row must still say which feed it is: {feed}"
        );
        assert_eq!(feed["category"], "tv", "{feed}");
        let id = feed["id"].as_str().unwrap_or_default().to_string();
        assert_eq!(id.len(), 16, "the migration mints an id: {feed}");

        // Migrated ON DISK, not just in memory: the id is a merge key,
        // and a key that is re-minted at every launch matches nothing
        // the browser saved yesterday. The real url stays where the
        // poller needs it.
        let disk = std::fs::read_to_string(dir.join("settings.json")).unwrap();
        assert!(disk.contains(&id), "the id must persist: {disk}");
        assert!(disk.contains(key), "the stored url is untouched: {disk}");
        id
    }; // daemon killed here

    // Same directory, new process: the id the browser was given is still
    // the id the daemon knows it by.
    let d = serve(&dir);
    let block = serde_json::Value::Object(settings_block(d.port));
    assert_eq!(
        block["feeds"][0]["id"].as_str(),
        Some(id.as_str()),
        "the id must survive a restart: {block}"
    );

    // The editor's round trip: the masked url comes back with the id and
    // an edited rule. The key must survive it.
    let saved = http_post(
        d.port,
        "/api?mode=config&output=json",
        &serde_json::json!({
            "name": "feeds",
            "value": serde_json::json!([{
                "id": id,
                "url": "https://idx.example/rss?t=tvsearch&cat=5030&apikey=***",
                "interval_secs": 900, "category": "tv", "rules": ["Accept: *2160p*"],
            }])
            .to_string(),
        })
        .to_string(),
    );
    assert!(saved.contains("\"status\":true"), "save failed: {saved}");
    let disk = std::fs::read_to_string(dir.join("settings.json")).unwrap();
    assert!(
        disk.contains(key),
        "saving a masked url must keep the stored key: {disk}"
    );
    assert!(
        !disk.contains("apikey=***"),
        "and must never store the mask itself: {disk}"
    );
    assert!(disk.contains("*2160p*"), "the edit itself landed: {disk}");

    // Half an edit - the user changed the category in the url and left
    // the *** where the key was - is refused, not stored.
    let half = http_post(
        d.port,
        "/api?mode=config&output=json",
        &serde_json::json!({
            "name": "feeds",
            "value": serde_json::json!([{
                "id": id,
                "url": "https://idx.example/rss?t=tvsearch&cat=5040&apikey=***",
            }])
            .to_string(),
        })
        .to_string(),
    );
    assert!(
        half.contains("\"status\":false"),
        "a half-edited masked url must be refused: {half}"
    );
    let disk = std::fs::read_to_string(dir.join("settings.json")).unwrap();
    assert!(disk.contains(key), "a refused save changes nothing: {disk}");

    drop(d);
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

/// §193 c: the listener's own bind address is settable, refused when it
/// is not an address, and reported as pending until a restart takes it.
///
/// `bind` was honoured from settings.json since the flag existed and was
/// absent from the settings table, so `get_config` never echoed it and
/// no UI row could exist. The three pieces the port has - table entry,
/// apply arm, pending diff - are what this pins.
///
/// The restart leg is deliberately NOT exercised. Applying a saved bind
/// means actually binding it, and the only address a test may safely ask
/// for is the loopback one the harness already passes: 0.0.0.0 raises a
/// macOS firewall prompt per test binary, and 127.0.0.2 is not assigned
/// on macOS at all. The overlay itself (`apply_saved_settings`) is
/// unchanged by this row.
#[test]
fn the_listener_bind_is_settable_and_reported_as_pending() {
    let dir = scratch("bindrow");
    let d = serve(&dir);

    // What THIS run bound with, echoed like the port beside it.
    let c = settings_block(d.port);
    assert_eq!(c["bind"], "127.0.0.1", "the live bind must echo: {c:?}");
    assert_eq!(
        c["pending"]["bind"],
        serde_json::Value::Null,
        "nothing saved yet, so nothing pending: {:?}",
        c["pending"]
    );

    // A name is refused rather than resolved - the refusal has to say
    // what a good value looks like, since getting this wrong is how the
    // dashboard disappears at the next restart.
    let r = api(d.port, "mode=config&name=bind&value=localhost");
    assert_eq!(r["status"].as_bool(), Some(false), "a name was taken: {r}");
    let err = r["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("0.0.0.0") && err.contains("127.0.0.1"),
        "the refusal must name the two values people actually want: {err:?}"
    );

    // Empty means the default, spelled out rather than stored as "".
    let r = api(d.port, "mode=config&name=bind&value=");
    assert_eq!(r["status"].as_bool(), Some(true), "empty refused: {r}");
    let saved = || -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(
            &std::fs::read_to_string(dir.join("settings.json")).unwrap_or_default(),
        )
        .map(|v| v["bind"].clone())
        .unwrap_or(serde_json::Value::Null)
    };
    assert_eq!(saved(), "0.0.0.0", "empty must normalise to the default");

    // Saved but not applied: the field keeps showing what is serving now,
    // and `pending` carries what the next restart will use.
    let c = settings_block(d.port);
    assert_eq!(
        c["bind"], "127.0.0.1",
        "the LIVE value must not move: {c:?}"
    );
    assert_eq!(
        c["pending"]["bind"], "0.0.0.0",
        "a saved-but-unapplied bind must be visible: {:?}",
        c["pending"]
    );

    // Saving back what is already serving clears the note.
    let r = api(d.port, "mode=config&name=bind&value=127.0.0.1");
    assert_eq!(r["status"].as_bool(), Some(true), "{r}");
    let c = settings_block(d.port);
    assert_eq!(
        c["pending"]["bind"],
        serde_json::Value::Null,
        "pending must clear once the saved value matches: {:?}",
        c["pending"]
    );

    drop(d);
}

/// §193 d: the TMDB key is settable, never echoed, and still reads the
/// two older homes it lived in before the row existed.
///
/// The dashboard used to tell people to hand-edit the config file for
/// this one key. It now has the omdb_key/scoreboard_key shape - a
/// write-only field plus a `has_*` flag - and the seed reads
/// settings.json FIRST, then the config file, so an install that already
/// had one keeps working and the row wins from the moment it is used.
#[test]
fn the_tmdb_key_is_write_only_and_migrates_from_the_config_file() {
    let dir = scratch("tmdbkey");
    // The old home: a key already in the config file, as the rename
    // card's hint used to instruct.
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.json"),
        // A server has to be present: `Config::load` refuses a file with
        // none, so a tmdb_key beside an empty list was never readable
        // from here - before this row or after it.
        r#"{"servers":[{"host":"news.example.com","port":563}],
            "tmdb_key":"from-the-config-file"}"#,
    )
    .unwrap();

    let d = serve(&dir);
    let c = settings_block(d.port);
    assert_eq!(
        c["has_tmdb"], true,
        "a key in the config file must still count as set: {c:?}"
    );
    assert!(
        !serde_json::Value::Object(c)
            .to_string()
            .contains("from-the-config-file"),
        "the key must never be echoed back to the UI"
    );

    // The row wins from here on, and lands in settings.json rather than
    // rewriting the config file.
    let r = api(d.port, "mode=config&name=tmdb_key&value=typed-in-the-ui");
    assert_eq!(r["status"].as_bool(), Some(true), "{r}");
    let stored = std::fs::read_to_string(dir.join("settings.json")).unwrap_or_default();
    assert!(
        stored.contains("typed-in-the-ui"),
        "the typed key must persist to settings.json: {stored}"
    );
    let disk = std::fs::read_to_string(dir.join("config.json")).unwrap_or_default();
    assert!(
        disk.contains("from-the-config-file"),
        "the config file is READ, never rewritten: {disk}"
    );
    assert_eq!(settings_block(d.port)["has_tmdb"], true);

    // Clearing removes the settings key instead of storing "", so the
    // config file's value is reachable again on the next start.
    let r = api(d.port, "mode=config&name=tmdb_key&value=");
    assert_eq!(r["status"].as_bool(), Some(true), "{r}");
    let stored = std::fs::read_to_string(dir.join("settings.json")).unwrap_or_default();
    assert!(
        !stored.contains("tmdb_key"),
        "an empty key must be removed, not stored: {stored}"
    );
    assert_eq!(
        settings_block(d.port)["has_tmdb"],
        false,
        "cleared live, whatever the file still holds"
    );

    drop(d);
}

/// The output-permission umask survives a restart, and "off" stays off.
///
/// #20 is a systemd-shaped problem: `UMask=0077` in the unit reaches
/// `--out`, so finished downloads land 0700/0600 and the *arr running as
/// another user cannot import them. The answer is this setting, and the
/// install that needs it is precisely the install that restarts - a
/// value that reverted at launch would fix imports until the next
/// `systemctl restart` and then stop, with nothing logged.
///
/// Not covered by `settings_survive_a_restart`: that walks BOOLEANS, and
/// this one is a STRING whose restore leg is hand-written in
/// `apply_saved_settings` rather than generated from the table. Two
/// values that a shortcut would collapse are pinned with it: `000` is a
/// real umask (777/666), not "unset", and clearing the field back to
/// empty must not be read as "nothing was saved" and answered with the
/// value it just replaced.
///
/// Not gated on unix. Applying the modes is (mode bits are the whole
/// subject), but storing and reporting the setting deliberately is not,
/// so a config survives a round trip through either platform.
#[test]
fn the_output_umask_survives_a_restart_including_zero_and_off() {
    let dir = scratch("outperm");
    let umask = |port| {
        settings_block(port)
            .get("out_umask")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };

    {
        let d = serve(&dir);
        // Ships OFF: the default is today's behaviour, by ruling.
        assert_eq!(
            umask(d.port).as_deref(),
            Some(""),
            "output permissions must ship off"
        );
        let r = api(d.port, "mode=config&name=out_umask&value=002");
        assert_eq!(r["status"].as_bool(), Some(true), "002 rejected: {r}");
        assert_eq!(
            umask(d.port).as_deref(),
            Some("002"),
            "002 did not reach the running daemon"
        );
    } // daemon killed here

    let d = serve(&dir);
    assert_eq!(
        umask(d.port).as_deref(),
        Some("002"),
        "the umask reverted across a restart - apply_saved_settings is \
         not reading out_umask back"
    );

    // 000 is a legitimate umask (777/666), and the one a shortcut in the
    // restore path would swallow as "unset".
    let r = api(d.port, "mode=config&name=out_umask&value=000");
    assert_eq!(r["status"].as_bool(), Some(true), "000 rejected: {r}");
    let _log = d.stop();
    let d = serve(&dir);
    assert_eq!(
        umask(d.port).as_deref(),
        Some("000"),
        "an explicit 000 came back as something else"
    );

    // And the documented way back to today's behaviour stays back.
    let r = api(d.port, "mode=config&name=out_umask&value=");
    assert_eq!(r["status"].as_bool(), Some(true), "clearing rejected: {r}");
    let _log = d.stop();
    let d = serve(&dir);
    assert_eq!(
        umask(d.port).as_deref(),
        Some(""),
        "clearing the field did not survive the restart"
    );

    drop(d);
}
