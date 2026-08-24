//! The tray's decisions that do not need win32.
//!
//! Recognising an nzbfast daemon from the body of an *unauthenticated*
//! `mode=version` probe, working out which API key to speak to it with,
//! and the two things it DRAWS off a queue poll - the hover tooltip and
//! the speed-limit menu. Lives outside the win32 `app` module, and off
//! `cfg(windows)`, so all of it is unit-testable on any host
//! (`cargo test -p nzbtray`) - `mod app` never compiles on the machines
//! these tests run on, so anything left in there is unguarded by
//! construction.
//!
//! Split out of main.rs on 24 Aug 2026, when the speed-limit menu took
//! that file over its line ceiling. Nothing moved but the braces.

use serde_json::Value;
use std::path::Path;

/// A stored credential is usable only after trimming. Older nzbfast
/// releases persisted `{"apikey":""}` when the user cleared the field;
/// the daemon now treats that as absent and falls through to its minted
/// key file, so the tray must do the same instead of shadowing the real
/// key with an empty query value.
pub fn stored_key(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Percent-encode a query value. Generated keys are hex, but user-chosen
/// keys may contain `&`, `+`, `%` or `#`; sending those raw changes the
/// parsed query and makes every tray action fail authentication.
pub fn query_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Read the daemon's API key from the data dir. Two sources, in the
/// daemon's own precedence order: a key the user set in the dashboard
/// (settings.json), else the one the daemon minted for itself on a
/// first run (the `apikey` file - see serve::first_run_apikey). Before
/// that minting existed a fresh install had no key at all and this
/// returned None, which is still the answer for an install that is
/// deliberately keyless.
pub fn apikey(data_dir: &Path) -> Option<String> {
    let from_settings = || -> Option<String> {
        let s = std::fs::read_to_string(data_dir.join("settings.json")).ok()?;
        let v: Value = serde_json::from_str(&s).ok()?;
        stored_key(v.get("apikey")?.as_str()?)
    };
    let from_keyfile = || -> Option<String> {
        let k = std::fs::read_to_string(data_dir.join("apikey")).ok()?;
        stored_key(&k)
    };
    from_settings().or_else(from_keyfile)
}

/// Evidence that THIS process proved the listener's identity - a
/// matching runtime.json token challenge, or a child this tray
/// spawned itself. Legacy adoption (an nzbfast-shaped reply with no
/// runtime.json to hold it to) attaches but never yields one:
/// sending the stored API key to a listener whose identity is only
/// a reply shape hands any local port-squatter daemon control and,
/// through `mode=server_secret`, the provider password (Codex sweep
/// 10 Aug M10).
///
/// The token is the WHOLE point of the type (§148): `keyed_url` /
/// `dash_url` demand one, the private field means no call site can
/// fabricate it, and the only mints are `record_identity_proven`
/// (called by the two paths that actually verify - the token
/// challenge in `probe`, and a spawn of our own child) read back
/// through [`identity_proof`]. v1.0.22 shipped a bool latch every
/// path had to remember to arm; the type replaces that discipline.
#[derive(Clone, Copy)]
pub struct IdentityProof(());

/// Test-only mint: the URL tests need a proof without a live
/// daemon to challenge. Does not exist in a shipping binary.
#[cfg(test)]
pub fn proof_minted_for_tests() -> IdentityProof {
    IdentityProof(())
}

// The per-process latch behind [`identity_proof`]. Private on
// purpose: the app reads it only as a token, so "armed" and "who
// may claim to be armed" cannot drift apart again.
#[cfg(windows)]
static IDENTITY_PROVEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The token, if this process has proven the listener (see
/// [`IdentityProof`]). None means keyed URLs go keyless and the
/// dashboard prompts instead.
#[cfg(windows)]
pub fn identity_proof() -> Option<IdentityProof> {
    IDENTITY_PROVEN
        .load(std::sync::atomic::Ordering::SeqCst)
        .then_some(IdentityProof(()))
}

#[cfg(windows)]
pub fn record_identity_proven(v: bool) {
    IDENTITY_PROVEN.store(v, std::sync::atomic::Ordering::SeqCst);
}

/// An API URL that already has a query string, plus our credential -
/// but ONLY with a proof of the listener's identity in hand (see
/// [`IdentityProof`]). A legacy-adopted listener gets the keyless
/// URL: the daemon refuses, which is strictly better than
/// disclosing the key to something we cannot tell from an impostor.
pub fn keyed_url(mut url: String, data_dir: &Path, proof: Option<IdentityProof>) -> String {
    if proof.is_none() {
        return url;
    }
    if let Some(k) = apikey(data_dir) {
        url.push_str("&apikey=");
        url.push_str(&query_value(&k));
    }
    url
}

/// Scheme + authority for everything the tray addresses at the
/// daemon: its own API calls, and the dashboard URL it hands the
/// browser.
///
/// `tls` comes from `runtime.json` (see [`Runtime`]), which the
/// daemon writes once its listener exists. Saving a valid
/// certificate pair and restarting makes the daemon bind HTTPS; the
/// tray used to keep probing `http://`, classify its own healthy
/// engine as a stranger, and then be unable to open, stop, upgrade
/// or quit it. One place decides the scheme so no call site can
/// drift back to a hardcoded one.
///
/// Orthogonal to `proven` below: this decides how to REACH the
/// listener, that decides what we are willing to SAY to it.
pub fn origin(port: u16, tls: bool) -> String {
    let scheme = if tls { "https" } else { "http" };
    format!("{scheme}://127.0.0.1:{port}")
}

/// Dashboard URL, carrying the API key when we know one AND hold a
/// proof of the listener's identity (same rule as [`keyed_url`]).
/// The page adopts the key into localStorage and strips it from the
/// address bar, so the tray's own "Open dashboard" does not land the
/// user on a prompt for a key that was generated for them and never
/// shown. Unproven, the plain URL: the dashboard prompts, and the
/// user pastes the key only if they trust what they see.
pub fn dash_url(port: u16, tls: bool, data_dir: &Path, proof: Option<IdentityProof>) -> String {
    let base = origin(port, tls);
    match apikey(data_dir).filter(|_| proof.is_some()) {
        Some(k) => format!("{base}/?apikey={}", query_value(&k)),
        None => format!("{base}/"),
    }
}

/// Is this the answer of an nzbfast daemon?
///
/// Two bodies count as ours:
/// - the plain `mode=version` answer, which carries an `nzbfast` field;
/// - the daemon's own refusal to answer without a key. Since 1.0.9 a
///   first run mints an API key for itself, so a fresh install answers
///   the anonymous probe with `{"status":false,"error":"API Key
///   Required"}` and never with the version body. Without this arm the
///   tray classified its own brand-new daemon as a stranger, waited out
///   the 15 s startup poll, and exited with an error box - on every
///   launch, since the installer, the Start Menu entry and autostart all
///   run the same exe.
///
/// The probe stays keyless on purpose: nothing has authenticated the far
/// side yet, and 6789 is well known, so sending the key would hand it to
/// whatever process bound the port first - and it unlocks
/// `mode=server_secret`, i.e. the Usenet password in cleartext. The
/// refusal shape is what makes the key unnecessary (same reasoning as
/// the Mac wrapper's `isNzbfast`).
///
/// Deliberately narrow: a match means attach-and-never-kill, so only the
/// two exact refusal phrases inside a `status:false` JSON object qualify
/// - never "anything that answered HTTP".
pub fn is_nzbfast(body: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    // `Value::get(&str)` is Some only for JSON objects, so both arms
    // below are object-only by construction.
    if v.get("nzbfast").is_some() {
        return true;
    }
    v.get("status").and_then(Value::as_bool) == Some(false)
        && matches!(
            v.get("error").and_then(Value::as_str),
            Some("API Key Required") | Some("API Key Incorrect")
        )
}

// ---- §98 upgrade handshake: version ordering ----------------------

/// An engine version as ordered for the §98 upgrade decision: the
/// semver components, then the beta serial. A beta build is made
/// AFTER the release its semver names (deploys bump
/// packaging/beta-serial.txt; publish resets it), so "1.0.14 beta 5"
/// is newer than "1.0.14" and older than "1.0.15". Mirrors the Mac
/// wrapper's `EngineVersion` - the two launchers must order releases
/// identically or an upgrade behaves differently per platform.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EngineVersion {
    nums: [u64; 3],
    beta: u64,
}

impl EngineVersion {
    /// `semver` like "1.0.14"; `beta` like "5" or "" (not a beta).
    /// None on anything unreadable - and the §98 rule is that an
    /// unreadable side means ATTACH, never restart.
    pub fn parse(semver: &str, beta: &str) -> Option<EngineVersion> {
        let mut nums = [0u64; 3];
        let mut parts = semver.split('.');
        for slot in nums.iter_mut() {
            *slot = parts.next()?.trim().parse().ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        let beta = beta.trim();
        let beta = if beta.is_empty() {
            0
        } else {
            beta.parse().ok()?
        };
        Some(EngineVersion { nums, beta })
    }
}

/// The version this tray ships: its own crate version (kept in
/// lockstep with the engine - the comment in Cargo.toml is the
/// contract) plus the beta serial its build embedded from the same
/// file the engine's build reads.
pub fn bundled_version() -> Option<EngineVersion> {
    EngineVersion::parse(env!("CARGO_PKG_VERSION"), env!("NZBTRAY_BETA"))
}

/// The version an AUTHENTICATED `mode=version` body reports. None on
/// a refusal (we hold no key for that daemon - another data dir's
/// install, not ours to restart) or anything else unreadable.
pub fn body_version(body: &str) -> Option<EngineVersion> {
    let v = serde_json::from_str::<Value>(body).ok()?;
    EngineVersion::parse(
        v.get("nzbfast").and_then(Value::as_str)?,
        v.get("beta").and_then(Value::as_str).unwrap_or(""),
    )
}

/// The port to look for first: what the DAEMON will bind, then what we
/// last spawned it on.
///
/// `settings.json` wins because the daemon's own precedence puts it
/// above the `--port` flag we pass. Reading only `tray.json` meant that
/// after a port change in the dashboard the tray probed the old port,
/// found it free, spawned a daemon that bound the NEW one, then polled
/// the old port for 15 s and gave up - leaving the daemon it had just
/// started running with nothing attached to it. The Mac wrapper has
/// always resolved the saved port this way.
///
/// Out here rather than in `mod app` so the precedence is tested on
/// every host, not only when someone builds for Windows.
pub fn load_port(data_dir: &Path) -> Option<u16> {
    let from_settings = || -> Option<u16> {
        let s = std::fs::read_to_string(data_dir.join("settings.json")).ok()?;
        let v: Value = serde_json::from_str(&s).ok()?;
        // Settings values arrive as numbers or strings depending on which
        // path wrote them; accept both, reject anything out of range.
        let port = v.get("port")?;
        port.as_u64()
            .or_else(|| port.as_str()?.trim().parse().ok())
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
    };
    let from_tray = || -> Option<u16> {
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(data_dir.join("tray.json")).ok()?)
                .ok()?;
        u16::try_from(v.get("port")?.as_u64()?)
            .ok()
            .filter(|p| *p != 0)
    };
    from_settings().or_else(from_tray)
}

/// What `runtime.json` tells us about the daemon we expect to find:
/// the port it bound, the scheme it bound with, and the per-start
/// secret it will prove it holds. Absent for an older daemon, or a
/// data dir it never started from.
pub struct Runtime {
    pub port: u16,
    pub token: String,
    /// §129 2a: does that listener speak TLS? Additive on the daemon
    /// side, so a `runtime.json` written before the key existed just
    /// reads false - which is what those daemons were.
    pub tls: bool,
}

pub fn runtime(data_dir: &Path) -> Option<Runtime> {
    let v: Value =
        serde_json::from_str(&std::fs::read_to_string(data_dir.join("runtime.json")).ok()?).ok()?;
    let port = u16::try_from(v.get("port")?.as_u64()?)
        .ok()
        .filter(|p| *p != 0)?;
    let token = stored_key(v.get("token")?.as_str()?)?;
    // Missing or non-boolean = plain HTTP. Only `true` opts in, so a
    // malformed file cannot talk the tray into a scheme the daemon
    // is not serving.
    let tls = v.get("tls").and_then(Value::as_bool).unwrap_or(false);
    Some(Runtime { port, token, tls })
}

/// Does the daemon on `port` speak TLS? `runtime.json` is the only
/// answer we have, and only when it names THIS port - an engine from
/// another data dir, or one older than the key, leaves us guessing,
/// and the probe resolves that by trying both (see `probe`).
pub fn tls_for(port: u16, data_dir: &Path) -> bool {
    runtime(data_dir).is_some_and(|r| r.port == port && r.tls)
}

/// A nonce for one probe. Not a secret and not a key - it only has to
/// differ between probes so a recorded answer cannot be replayed - so
/// process id, address entropy and a counter are enough, and this stays
/// free of a random-number dependency.
pub fn probe_nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let counter = N.fetch_add(1, Ordering::Relaxed);
    let stack = &counter as *const _ as usize as u64;
    let clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!(
        "{:016x}{:016x}",
        clock ^ stack,
        counter ^ std::process::id() as u64
    )
}

/// Does this reply prove the listener is the daemon `runtime.json`
/// describes?
///
/// The daemon answers `mode=version&hs=<nonce>` with
/// `sha256(token:nonce)`. The token itself never travels, so a probe
/// sent to an impostor teaches it nothing, and only a process that can
/// read our user-only `runtime.json` can produce the answer.
///
/// `false` for a reply with no proof at all, which is what an OLDER
/// daemon returns - the caller decides what to do about that (see
/// `probe`), because refusing outright would break attaching to a
/// daemon from the release before this one.
pub fn proof_matches(body: &str, token: &str, nonce: &str) -> bool {
    use sha2::{Digest, Sha256};
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let Some(got) = v.get("hs_proof").and_then(Value::as_str) else {
        return false;
    };
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.update(b":");
    h.update(nonce.as_bytes());
    let want = h.finalize();
    // Constant-time-ish: the token is not guessable from a comparison
    // here anyway (an attacker who can see this process's memory has
    // already won), but there is no reason to leak the prefix length.
    let want_hex = want.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });
    want_hex.len() == got.len()
        && want_hex
            .bytes()
            .zip(got.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// Is this listener the daemon we expect on this port?
///
/// `token` is `Some` only when `runtime.json` names THIS port. In that
/// case the proof is MANDATORY: a token in runtime.json can only have
/// been written by a daemon that also answers the challenge - the file
/// write and the proof reply shipped in the same release, and the
/// write is unconditional once the listener exists. So a shape-valid
/// reply carrying no proof is NOT an older daemon (an older daemon
/// leaves no runtime.json at all and takes the `None` arm); it is
/// something else holding the port, and attaching to it means handing
/// over the stored API key - which grants daemon control and, through
/// `mode=server_secret`, the provider password.
///
/// `None` - no runtime.json for this port, or one naming a different
/// port - stays permissive: that IS the pre-handshake daemon, and the
/// migration case.
pub fn identity_ok(body: &str, token: Option<&str>, nonce: &str) -> bool {
    match token {
        Some(t) => proof_matches(body, t, nonce),
        None => true,
    }
}

/// Does this install display speeds in bits rather than bytes?
///
/// The dashboard's `unit_bits` setting, read straight out of
/// settings.json the way [`apikey`] reads its key from the same file.
/// A tooltip that said MB/s while every number on the dashboard said
/// Mb/s would be the bits/bytes mess the unit convention exists to
/// stop, and reading the file costs nothing next to the API call the
/// tip is already making. Absent or unreadable = the daemon's own
/// default, bytes.
pub fn unit_bits(data_dir: &Path) -> bool {
    let read = || -> Option<bool> {
        let s = std::fs::read_to_string(data_dir.join("settings.json")).ok()?;
        let v: Value = serde_json::from_str(&s).ok()?;
        v.get("unit_bits")?.as_bool()
    };
    read().unwrap_or(false)
}

/// A speed, in the dashboard's own units and to its own precision.
///
/// The Rust twin of the dashboard's one speed formatter (rateParts in
/// web/dashboard.html): bytes below 1000 MB/s print whole, above it
/// they roll to GB/s with two decimals, and the bits arm is the same
/// shape on the value times eight. The tray cannot call that
/// function, so the rule is written out again here.
///
/// THIS IS NOT THE ONLY TWIN, and the sentence that said so stood
/// here for seven minutes: rateText in
/// macapp/Sources/NzbFast/StatusItem.swift is the mac menu bar's copy
/// of the same four thresholds, landed the same afternoon by a lane
/// that could not see this one (c6a2f8ecd 24 Aug 2026 17:13:14Z,
/// 27cc66897 17:20:30Z). So there are THREE: the
/// dashboard's, which is canonical, and one per native surface that
/// cannot reach it. Move a threshold in any of them and the other two
/// move in the same commit - a menu bar reading GB/s beside a
/// dashboard reading MB/s is exactly the bits/bytes mess the unit
/// convention exists to stop. Do not grow a FOURTH: a native surface
/// that needs a rate calls one of these.
///
/// `tools/rate-format-gate.py` refuses a tree where the three
/// disagree, and refuses a fourth copy. It pins this function BY
/// NAME, so a rename moves the gate's `SOURCES` in the same commit.
///
/// Unit symbols stay English here. Everything else the tray draws -
/// every menu item, every balloon - is English too; the localised
/// symbols belong to the dashboard's `unit()` and its catalogues.
pub fn fmt_rate(mb_per_sec: f64, bits: bool) -> String {
    let (v, d, u) = if bits {
        let mb = mb_per_sec * 8.0;
        if mb >= 1000.0 {
            (mb / 1000.0, 2, "Gb/s")
        } else {
            (mb, 0, "Mb/s")
        }
    } else if mb_per_sec >= 1000.0 {
        (mb_per_sec / 1000.0, 2, "GB/s")
    } else {
        (mb_per_sec, 0, "MB/s")
    };
    format!("{v:.d$} {u}", d = d as usize)
}

/// Below this the queue is not moving bytes in any sense a status
/// line can report, so the line drops the field rather than print
/// "0 MB/s", which reads as broken rather than as busy. The
/// post-network tail - verifying, repairing, unpacking - sits here
/// for minutes at a time on a job that is perfectly healthy, so
/// this is the common case and not the edge.
///
/// It is not a promise that the printed number is never 0:
/// [`fmt_rate`] prints MB/s whole, so anything under half a
/// megabyte a second still rounds down to it. That is what the
/// dashboard shows for the same sample, and one rounding rule
/// across the product is worth more than a second one invented in
/// the wrappers. The floor is only about telling "stopped" from
/// "slow".
///
/// The mac menu bar applies the same floor for the same reason; see
/// the wording note on [`tip_from_queue`].
const RATE_FLOOR_MBPS: f64 = 0.05;

/// The tray tooltip, from the body of one `mode=queue` call.
///
/// What the user wants off a hover is the answer to "is it doing
/// anything, how much of it, and how fast", and that is the order
/// the line puts them in:
///
/// ```text
/// nzbfast - Downloading · 3 jobs · 42 MB/s
/// nzbfast - Downloading · 2 jobs      (the tail: nothing measurable moving)
/// nzbfast - Paused · 4 jobs
/// nzbfast - Offline · 4 jobs
/// nzbfast - Idle
/// ```
///
/// THE SAME LINE IS DRAWN BY THE MAC MENU BAR, and keeping the two
/// in one voice is the whole point of the shape above: stateLine in
/// macapp/Sources/NzbFast/StatusItem.swift builds these same three
/// fields in this same order with this same separator, and differs
/// only in dropping the `nzbfast - ` prefix - it hangs under a menu
/// whose title already says the name, where this one labels a
/// nameless icon in a tray of nameless icons. The two landed hours
/// apart on 24 Aug 2026 from lanes that could not see each other
/// (c6a2f8ecd here, 27cc66897 there) and described the same five
/// states in different words, different field order and different
/// case; a user with both saw the product say two things. Change the
/// wording in one and change it in the other, in the same commit.
///
/// The three fields, and the rules that decide whether each appears:
///
/// * The STATE WORD is the daemon's own (`status` in the queue body
///   is one of Downloading / Idle / Paused), so the tooltip cannot
///   drift from what the dashboard's rows say. `offline` OUTRANKS
///   it: the two are different states - paused keeps indexing and
///   keeps the account occupied, offline hangs up and does neither -
///   and offline is the one that explains the silence, so it takes
///   the word. The derived fallback exists only for a body with no
///   `status` at all.
/// * The COUNT is omitted at zero rather than printed as "0 jobs",
///   which is a phrase for saying nothing loudly. `noofslots` is the
///   queue length AFTER the caller's category / nzo_ids filter; the
///   tray sends neither, so for it the two are the same number.
/// * The RATE appears only while the queue is actually downloading
///   and something measurable is moving (see [`RATE_FLOOR_MBPS`]).
///
/// None when the body is not a queue answer at all (an error page, a
/// refusal), which the caller shows as the plain product name.
pub fn tip_from_queue(q: &Value, bits: bool) -> Option<String> {
    let q = q.get("queue")?;
    let n = q.get("noofslots").and_then(Value::as_u64)?;
    // kB/s, as a string (the SAB field is decimal kilobytes, so
    // MB/s is a further thousand down).
    let mbps = q
        .get("kbpersec")
        .and_then(Value::as_str)
        .and_then(|s| s.trim().parse::<f64>().ok())
        .unwrap_or(0.0)
        / 1000.0;
    let flag = |k: &str| q.get(k).and_then(Value::as_bool).unwrap_or(false);
    let (offline, paused) = (flag("offline"), flag("paused"));
    let state = if offline {
        "Offline"
    } else {
        match q.get("status").and_then(Value::as_str).map(str::trim) {
            Some(s) if !s.is_empty() => s,
            _ if paused => "Paused",
            _ if n == 0 => "Idle",
            _ => "Downloading",
        }
    };
    // The literal, not `app::MSG_TITLE`: that const lives in the
    // win32 half, which does not compile on the machines these
    // tests run on.
    let mut tip = format!("nzbfast - {state}");
    if n > 0 {
        let s = if n == 1 { "" } else { "s" };
        tip.push_str(&format!(" · {n} job{s}"));
    }
    if !paused && !offline && mbps >= RATE_FLOOR_MBPS {
        tip.push_str(&format!(" · {}", fmt_rate(mbps, bits)));
    }
    Some(tip)
}

/// The absolute presets the speed-limit menu offers, bytes/sec, and
/// the percentage ones. Both lists are the dashboard header's own
/// (`#limitSel`'s options and `LIMIT_PCTS` in web/dashboard.html) -
/// see the wording note on [`limit_menu`].
const LIMIT_PRESETS: [u64; 5] = [
    50_000_000,
    100_000_000,
    250_000_000,
    500_000_000,
    1_000_000_000,
];
const LIMIT_PCTS: [u64; 3] = [25, 50, 75];

/// What clicking one row of the speed-limit menu asks the daemon for.
///
/// Every arm but [`LimitPick::Live`] is a `mode=config` call, and the
/// two-call arms are in that order for a reason: `auto_speed` off
/// FIRST, because the governor writes the rate every second and would
/// overwrite a ceiling set while it still holds the wheel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitPick {
    /// `speedlimit=0` - "off" in both of the daemon's conventions.
    None,
    /// `auto_speed=1`.
    Auto,
    /// `auto_speed=0`, then `speedlimit=<bytes/sec>`.
    Abs(u64),
    /// `auto_speed=0`, then `speedlimit=<percent>`. A BARE number of
    /// 100 or less is the daemon's percentage convention, not a byte
    /// count (`set_speedlimit` in serve/settings_setters.rs), which is
    /// why this arm exists rather than resolving the percentage here:
    /// the daemon anchors it against the line speed it holds, so the
    /// menu cannot pick a stale one.
    Pct(u64),
    /// NOT a pick, and the row is drawn disabled: the limit in force
    /// matches no row above - somebody typed it in the dashboard, a
    /// schedule entry applied it, or an *arr set it over the API - so
    /// the menu shows it rather than presenting every row unchecked
    /// and implying no limit is set.
    Live,
}

/// One row of the speed-limit menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitRow {
    pub label: String,
    pub pick: LimitPick,
    pub checked: bool,
}

/// The speed-limit menu, from the body of the same `mode=queue` call
/// the tooltip is built from.
///
/// ```text
/// No limit
/// Auto · yield to LAN        (or "Auto · 42 MB/s now" while it drives)
/// 50 MB/s · 100 MB/s · 250 MB/s · 500 MB/s · 1 GB/s
/// 25% of your line speed · 25 MB/s      (only once a line speed is set)
/// 37 MB/s (custom)                      (only when nothing above matches)
/// ```
///
/// THE SAME MENU IS DRAWN BY THE MAC MENU BAR: `limitRows` in
/// macapp/Sources/NzbFast/StatusItem.swift builds these same rows from
/// these same two lists with these same labels and the same checkmark
/// rule. Change the wording in one and change it in the other, in the
/// same commit - the reason is written out at length on
/// [`tip_from_queue`], and it is the same reason.
///
/// All three surfaces are one voice by construction here, because the
/// rules are the dashboard header's rules and not new ones:
///
/// * The PRESETS, the percentages, and the "only once a line speed is
///   configured" gate on the percentages are `syncLimitPresets`'s. The
///   daemon would in fact anchor a bare percentage against the learned
///   link peak when no line speed is set (§18), but the header does not
///   offer it there and neither does this: a menu entry whose outcome
///   the user cannot predict is worse than no entry.
/// * A percentage preset is stored as an ABSOLUTE limit, so it is
///   matched BACK to the percentage that produced it - `floor(line *
///   p / 100)`, the daemon's own arithmetic - and beats an absolute
///   preset of the same size. Without that a 25% pick comes back
///   labelled "(custom)" on the very next poll.
/// * The RATE in every label goes through [`fmt_rate`], so a bits
///   install reads "400 Mb/s" where a bytes install reads "50 MB/s",
///   exactly as `relabelLimitOptions` does it. The presets are byte
///   rates underneath either way.
///
/// Two things the header has that this deliberately does not. There is
/// no "custom…" row: typing a rate is not something a tray menu does
/// well, and the dashboard is one click away in the same menu - the
/// live value stays VISIBLE here either way, which is the half that
/// mattered. And a limit a schedule entry set is not attributed the
/// way the header's "your schedule" label attributes it; there is no
/// room beside a menu row for it, and the row still shows the rate in
/// force.
///
/// Empty when the body is not a queue answer at all, which the caller
/// draws as no submenu rather than as an empty one.
pub fn limit_menu(q: &Value, bits: bool) -> Vec<LimitRow> {
    let Some(q) = q.get("queue") else {
        return Vec::new();
    };
    // A STRING on the wire, as SAB sends every rate (see
    // `speedlimit_abs` in serve/sabcompat.rs) - but mode=status once
    // sent the same field as a number, so both are read.
    let abs = q
        .get("speedlimit_abs")
        .and_then(|v| {
            v.as_str()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .or_else(|| v.as_u64())
        })
        .unwrap_or(0);
    let line = q.get("line_speed").and_then(Value::as_u64).unwrap_or(0);
    let auto = q
        .get("auto_speed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let rate = |bps: u64| fmt_rate(bps as f64 / 1e6, bits);

    // What the daemon is doing now, in the vocabulary of the rows
    // below - computed ONCE so no two rows can both claim the check.
    let live = if auto {
        LimitPick::Auto
    } else if abs == 0 {
        LimitPick::None
    } else if let Some(p) = LIMIT_PCTS
        .iter()
        .find(|p| line > 0 && line * *p / 100 == abs)
    {
        LimitPick::Pct(*p)
    } else if LIMIT_PRESETS.contains(&abs) {
        LimitPick::Abs(abs)
    } else {
        LimitPick::Live
    };

    let mut rows = vec![
        LimitRow {
            label: "No limit".to_string(),
            pick: LimitPick::None,
            checked: live == LimitPick::None,
        },
        LimitRow {
            // The governor picks a real number every second, and a row
            // saying only "Auto" reads as "no limit" - the one thing it
            // is not. `speedlimit_abs` IS that live number while auto
            // is on, so the row can say what auto currently means.
            label: if auto && abs > 0 {
                format!("Auto · {} now", rate(abs))
            } else {
                "Auto · yield to LAN".to_string()
            },
            pick: LimitPick::Auto,
            checked: live == LimitPick::Auto,
        },
    ];
    for bps in LIMIT_PRESETS {
        rows.push(LimitRow {
            label: rate(bps),
            pick: LimitPick::Abs(bps),
            checked: live == LimitPick::Abs(bps),
        });
    }
    if line > 0 {
        for p in LIMIT_PCTS {
            rows.push(LimitRow {
                label: format!("{p}% of your line speed · {}", rate(line * p / 100)),
                pick: LimitPick::Pct(p),
                checked: live == LimitPick::Pct(p),
            });
        }
    }
    if live == LimitPick::Live {
        rows.push(LimitRow {
            label: format!("{} (custom)", rate(abs)),
            pick: LimitPick::Live,
            checked: true,
        });
    }
    rows
}

/// The `mode=config` calls one pick asks for, in the order they must
/// be made. Empty for [`LimitPick::Live`], which is not a pick.
pub fn limit_calls(pick: LimitPick) -> Vec<(&'static str, String)> {
    match pick {
        LimitPick::Live => Vec::new(),
        LimitPick::Auto => vec![("auto_speed", "1".to_string())],
        LimitPick::None => vec![
            ("auto_speed", "0".to_string()),
            ("speedlimit", "0".to_string()),
        ],
        LimitPick::Abs(bps) => vec![
            ("auto_speed", "0".to_string()),
            ("speedlimit", bps.to_string()),
        ],
        LimitPick::Pct(p) => vec![
            ("auto_speed", "0".to_string()),
            ("speedlimit", p.to_string()),
        ],
    }
}

/// A string as a win32 fixed-buffer wants it: UTF-16, NUL-terminated,
/// never longer than `cap` units in total.
///
/// The shell's buffers are arrays, not pointers, and an over-long copy
/// that fills the array leaves no room for the terminator - the shell
/// then reads whatever follows it in the struct. Truncating is also
/// not a plain `take`: a cut between the halves of a surrogate pair
/// leaves a lone unit that renders as a replacement glyph, so the
/// orphan comes back off.
pub fn wide_capped(s: &str, cap: usize) -> Vec<u16> {
    if cap == 0 {
        return Vec::new();
    }
    let mut v: Vec<u16> = s.encode_utf16().take(cap - 1).collect();
    if v.last().is_some_and(|u| (0xD800..0xDC00).contains(u)) {
        v.pop();
    }
    v.push(0);
    v
}

#[cfg(test)]
mod tests {
    use super::{
        EngineVersion, apikey, body_version, bundled_version, dash_url, is_nzbfast, keyed_url,
        proof_minted_for_tests, query_value, stored_key,
    };
    use std::path::PathBuf;

    #[test]
    fn version_body_is_ours() {
        assert!(is_nzbfast(r#"{"version":"4.5.0","nzbfast":"1.0.9"}"#));
    }

    /// The §98 ordering contract, shared with the Mac wrapper: a beta
    /// outranks the release it grew from and loses to the next one.
    #[test]
    fn beta_sits_between_its_release_and_the_next() {
        let rel = EngineVersion::parse("1.0.14", "").unwrap();
        let beta = EngineVersion::parse("1.0.14", "5").unwrap();
        let next = EngineVersion::parse("1.0.15", "").unwrap();
        assert!(rel < beta);
        assert!(beta < next);
        assert!(EngineVersion::parse("1.0.9", "9").unwrap() < rel);
        assert_eq!(rel, EngineVersion::parse("1.0.14", "0").unwrap());
    }

    /// Unreadable versions mean ATTACH, so parse must refuse rather
    /// than guess - and a refusal body (no key held) has no version.
    #[test]
    fn unreadable_versions_refuse_to_parse() {
        assert!(EngineVersion::parse("", "").is_none());
        assert!(EngineVersion::parse("1.0", "").is_none());
        assert!(EngineVersion::parse("1.0.14.2", "").is_none());
        assert!(EngineVersion::parse("1.0.x", "").is_none());
        assert!(EngineVersion::parse("1.0.14", "x").is_none());
        assert!(body_version(r#"{"status":false,"error":"API Key Required"}"#).is_none());
        assert!(body_version("not json").is_none());
    }

    /// The authenticated body carries both fields; a release build's
    /// beta arrives as "" (build.rs maps serial 0 to the empty string).
    #[test]
    fn body_versions_parse_like_the_daemon_answers() {
        let beta5 = body_version(r#"{"beta":"5","nzbfast":"1.0.14","version":"4.5.0"}"#);
        assert_eq!(beta5, EngineVersion::parse("1.0.14", "5"));
        let rel = body_version(r#"{"beta":"","nzbfast":"1.0.14","version":"4.5.0"}"#);
        assert_eq!(rel, EngineVersion::parse("1.0.14", ""));
        assert!(rel < beta5);
    }

    /// Whatever this tray was built as, its own version must parse -
    /// a tray that cannot read itself can never upgrade anything.
    #[test]
    fn the_bundled_version_parses() {
        assert!(bundled_version().is_some());
    }

    /// The 1.0.9 regression: a keyed daemon refuses the keyless probe.
    /// Both refusals are still unmistakably a daemon we may attach to.
    #[test]
    fn auth_refusals_are_ours() {
        assert!(is_nzbfast(r#"{"status":false,"error":"API Key Required"}"#));
        assert!(is_nzbfast(
            r#"{"status":false,"error":"API Key Incorrect"}"#
        ));
        // Field order and whitespace are the serialiser's business.
        assert!(is_nzbfast(
            "{ \"error\" : \"API Key Required\" , \"status\" : false }"
        ));
    }

    #[test]
    fn strangers_are_not_ours() {
        // Some other JSON service on the port.
        assert!(!is_nzbfast(r#"{"status":"ok","service":"grafana"}"#));
        // SABnzbd's own anonymous mode=version answer.
        assert!(!is_nzbfast(r#"{"version":"4.5.0"}"#));
        // Not JSON at all.
        assert!(!is_nzbfast("<html><body>hello</body></html>"));
        assert!(!is_nzbfast(""));
        // JSON, but not an object.
        assert!(!is_nzbfast(r#"["API Key Required"]"#));
        assert!(!is_nzbfast(r#""API Key Required""#));
    }

    /// The refusal arm must not become "any error body": attaching means
    /// never killing what we found, so a stranger's error page stays a
    /// stranger.
    #[test]
    fn other_error_bodies_are_not_ours() {
        assert!(!is_nzbfast(r#"{"status":false,"error":"Unauthorized"}"#));
        assert!(!is_nzbfast(
            r#"{"status":false,"error":"api key required"}"#
        ));
        assert!(!is_nzbfast(r#"{"status":false}"#));
        // The phrases only count as a refusal, not as success.
        assert!(!is_nzbfast(r#"{"status":true,"error":"API Key Required"}"#));
        assert!(!is_nzbfast(r#"{"error":"API Key Required"}"#));
    }

    #[test]
    fn legacy_blank_key_falls_through_and_query_keys_are_escaped() {
        assert_eq!(stored_key(" \r\n"), None);
        assert_eq!(stored_key("  chosen key  ").as_deref(), Some("chosen key"));
        assert_eq!(query_value("a+b&c%# d"), "a%2Bb%26c%25%23%20d");
        assert_eq!(query_value("hex-._~09"), "hex-._~09");
    }

    /// A scratch data dir holding whichever of the two key sources
    /// the case needs.
    fn data_dir(name: &str, settings: Option<&str>, keyfile: Option<&str>) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nzbtray-key-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(s) = settings {
            std::fs::write(dir.join("settings.json"), s).unwrap();
        }
        if let Some(k) = keyfile {
            std::fs::write(dir.join("apikey"), k).unwrap();
        }
        dir
    }

    /// The two sources in the daemon's own precedence order, and the
    /// case that broke every tray action on an upgraded install: an
    /// older release persisted `{"apikey":""}` when the user cleared
    /// the field, and an empty value that is treated as SET shadows
    /// the key the daemon minted for itself - so the tray sent
    /// `&apikey=` and was refused by its own daemon.
    #[test]
    fn a_blank_stored_key_does_not_shadow_the_minted_one() {
        let minted = "0123456789abcdef";
        let d = data_dir("blank", Some(r#"{"apikey":"  "}"#), Some(minted));
        assert_eq!(apikey(&d).as_deref(), Some(minted));

        // A key the user really did set wins over the minted one.
        let d = data_dir("chosen", Some(r#"{"apikey":"mine"}"#), Some(minted));
        assert_eq!(apikey(&d).as_deref(), Some("mine"));

        // No settings file at all: the minted key still applies.
        let d = data_dir("keyonly", None, Some(minted));
        assert_eq!(apikey(&d).as_deref(), Some(minted));

        // A deliberately keyless install stays keyless - the tray must
        // not invent a credential or refuse to talk.
        let d = data_dir("none", Some("{}"), None);
        assert_eq!(apikey(&d), None);
    }

    /// Whatever the key turns out to be, it has to survive the query
    /// string. A user-chosen key containing `&` or `%` sent raw is a
    /// different key by the time the daemon parses it.
    #[test]
    fn urls_carry_the_key_escaped() {
        let d = data_dir("url", Some(r#"{"apikey":"a b&c"}"#), None);
        let p = || Some(proof_minted_for_tests());
        assert_eq!(
            keyed_url("http://127.0.0.1:6789/api?mode=queue".into(), &d, p()),
            "http://127.0.0.1:6789/api?mode=queue&apikey=a%20b%26c"
        );
        assert_eq!(
            dash_url(6789, false, &d, p()),
            "http://127.0.0.1:6789/?apikey=a%20b%26c"
        );

        // Keyless: no empty parameter left dangling on either URL.
        let d = data_dir("urlnone", None, None);
        assert_eq!(
            keyed_url("http://127.0.0.1:6789/api?mode=queue".into(), &d, p()),
            "http://127.0.0.1:6789/api?mode=queue"
        );
        assert_eq!(dash_url(6789, false, &d, p()), "http://127.0.0.1:6789/");
    }

    /// M1: a TLS daemon is addressed as https everywhere, or the tray
    /// cannot manage its own engine. `origin` is the single decider,
    /// so pinning it pins every URL the tray builds.
    ///
    /// Scheme and proof are independent, and the last case here says
    /// so: `tls` picks the scheme, the proof token picks whether the
    /// key rides along. An unproven TLS listener gets https WITHOUT
    /// the key.
    #[test]
    fn a_tls_daemon_is_addressed_as_https() {
        use super::origin;
        assert_eq!(origin(6789, true), "https://127.0.0.1:6789");
        assert_eq!(origin(6789, false), "http://127.0.0.1:6789");

        let d = data_dir("urltls", Some(r#"{"apikey":"a b&c"}"#), None);
        let p = || Some(proof_minted_for_tests());
        assert_eq!(
            dash_url(6789, true, &d, p()),
            "https://127.0.0.1:6789/?apikey=a%20b%26c"
        );
        assert_eq!(dash_url(6789, true, &d, None), "https://127.0.0.1:6789/");
        let d = data_dir("urltlsnone", None, None);
        assert_eq!(dash_url(6789, true, &d, p()), "https://127.0.0.1:6789/");
    }

    /// Where that flag comes from: `runtime.json`, and only when the
    /// file names the port we are about to talk to.
    ///
    /// The default matters as much as the true case. `tls` is
    /// additive - a daemon older than §129 2a wrote a runtime.json
    /// without it - so anything that is not literally `true` has to
    /// read as plain HTTP, or the tray would upgrade a scheme the
    /// engine never bound and lose the very attach this fixes.
    #[test]
    fn the_scheme_comes_from_runtime_json_for_this_port_only() {
        use super::tls_for;
        let write = |name: &str, body: &str| {
            let d = data_dir(name, None, None);
            std::fs::write(d.join("runtime.json"), body).unwrap();
            d
        };
        let tok = r#""token":"aaaaaaaaaaaaaaaa""#;

        assert!(tls_for(
            6789,
            &write("rt-tls", &format!(r#"{{"port":6789,{tok},"tls":true}}"#))
        ));
        // Another port's daemon tells us nothing about this one.
        assert!(!tls_for(
            6790,
            &write(
                "rt-otherport",
                &format!(r#"{{"port":6789,{tok},"tls":true}}"#)
            )
        ));
        // Explicitly plain, pre-§129 2a (absent), and malformed all
        // mean http.
        assert!(!tls_for(
            6789,
            &write("rt-plain", &format!(r#"{{"port":6789,{tok},"tls":false}}"#))
        ));
        assert!(!tls_for(
            6789,
            &write("rt-old", &format!(r#"{{"port":6789,{tok}}}"#))
        ));
        assert!(!tls_for(
            6789,
            &write("rt-junk", &format!(r#"{{"port":6789,{tok},"tls":"yes"}}"#))
        ));
        // No file at all: nothing to read a scheme off.
        assert!(!tls_for(6789, &data_dir("rt-missing", None, None)));
    }

    /// Codex sweep 10 Aug M10: legacy adoption (a listener accepted
    /// on reply shape alone, with no runtime.json token to
    /// challenge) must be NON-SECRET-BEARING. A local port-squatter that
    /// printed our JSON used to receive the stored full API key on
    /// the very next keyed call; unproven identity now strips the
    /// key from every generated URL, and the daemon-side refusal
    /// (or the dashboard prompt) is the worst that can happen.
    #[test]
    fn an_unproven_listener_never_receives_the_stored_key() {
        let d = data_dir("unproven", Some(r#"{"apikey":"SECRETKEY123"}"#), None);
        let url = keyed_url("http://127.0.0.1:6789/api?mode=queue".into(), &d, None);
        assert_eq!(url, "http://127.0.0.1:6789/api?mode=queue");
        assert!(!url.contains("SECRETKEY123"));
        assert_eq!(dash_url(6789, false, &d, None), "http://127.0.0.1:6789/");
        // With a proof in hand, the same data dir carries the key as
        // before.
        let p = Some(proof_minted_for_tests());
        assert!(keyed_url("http://x/api?mode=queue".into(), &d, p).contains("SECRETKEY123"));
    }

    /// §148: the proof is a TYPE, not a call-site discipline. The
    /// bool latch this replaces had to be armed by every path
    /// before it built a keyed URL - v1.0.22's second-instance
    /// hand-off forgot, every add went keyless, and the fix was
    /// pinned by a source-reflection test (retired with this one).
    /// Now `keyed_url`/`dash_url` demand an `IdentityProof`, whose
    /// only shipping mints are the token challenge in `probe` and
    /// the tray's own spawn, read back through `identity_proof()` -
    /// and the app's `proof()` accessor PERFORMS the probe when the
    /// process has not proven yet, so there is no ordering left to
    /// forget. What a test can still pin is the fail-closed half:
    /// the latch unarmed, `identity_proof()` hands out nothing, so
    /// no key-bearing URL can exist in an unproven process.
    #[cfg(windows)]
    #[test]
    fn no_proof_token_exists_before_the_identity_is_recorded() {
        use super::{identity_proof, record_identity_proven};
        // Fresh-process default: unarmed. Other tests exercise the
        // URL builders with an explicit minted proof, never this
        // process-global latch, so the sequence below owns it.
        assert!(
            identity_proof().is_none(),
            "unproven process holds no token"
        );
        record_identity_proven(true);
        assert!(identity_proof().is_some(), "the recording is the only mint");
        record_identity_proven(false);
        assert!(identity_proof().is_none(), "a later legacy probe disarms");
    }

    /// The launcher handshake, which is what stands between "something
    /// answers on 6789 in our shape" and handing that something the API
    /// key (and with it `mode=server_secret`).
    #[test]
    fn only_the_daemon_holding_our_token_can_prove_it() {
        use super::{identity_ok, proof_matches, runtime};
        use sha2::{Digest, Sha256};

        let token = "3c2f0f9a5e1d4b8f7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e"; // leakcheck-allow-synthetic: hand-typed hex test vector
        let nonce = "0123456789abcdef";
        let proof = |t: &str| {
            let mut h = Sha256::new();
            h.update(t.as_bytes());
            h.update(b":");
            h.update(nonce.as_bytes());
            h.finalize().iter().fold(String::new(), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            })
        };

        let real = format!(
            r#"{{"status":false,"error":"API Key Required","nzbfast":"1.0.12","hs_proof":"{}"}}"#,
            proof(token)
        );
        assert!(proof_matches(&real, token, nonce));
        assert!(identity_ok(&real, Some(token), nonce));

        // An impostor can print our JSON - it cannot read the token file,
        // so it cannot answer the challenge.
        let impostor = r#"{"status":false,"error":"API Key Required","nzbfast":"1.0.12"}"#;
        assert!(!proof_matches(impostor, token, nonce));
        // The downgrade that used to let it through: omitting `hs_proof`
        // entirely was read as "an older daemon" and waived the check,
        // so binding the saved port while the real daemon was down was
        // enough to be handed the stored API key. A token in
        // runtime.json can only have been written by a daemon that
        // answers the challenge, so no-proof is now a stranger.
        assert!(
            !identity_ok(impostor, Some(token), nonce),
            "a proofless reply must not pass while runtime.json names this port"
        );
        // ...and the compatibility case it must NOT break: with no
        // runtime.json for this port there is nothing to hold it to.
        assert!(
            identity_ok(impostor, None, nonce),
            "a pre-handshake daemon still attaches"
        );

        // Nor can it guess one, or replay another nonce's answer.
        let forged = format!(
            r#"{{"status":false,"error":"API Key Required","hs_proof":"{}"}}"#,
            proof("some other token")
        );
        assert!(!proof_matches(&forged, token, nonce));
        assert!(!identity_ok(&forged, Some(token), nonce));
        assert!(!proof_matches(&real, token, "a-different-nonce"));

        // The daemon's own runtime.json is what supplies the pair.
        let d = data_dir("runtime", None, None);
        assert!(
            runtime(&d).is_none(),
            "no file means no expectation to hold it to"
        );
        std::fs::write(
            d.join("runtime.json"),
            format!(r#"{{"pid":42,"port":6790,"token":"{token}","version":"1.0.12"}}"#),
        )
        .unwrap();
        let rt = runtime(&d).expect("a written runtime.json is read back");
        assert_eq!(rt.port, 6790);
        assert!(proof_matches(&real, &rt.token, nonce));

        // Truncated or tokenless files are treated as absent rather than
        // as an empty token that everything matches.
        std::fs::write(d.join("runtime.json"), r#"{"pid":42,"port":6790}"#).unwrap();
        assert!(runtime(&d).is_none());
        std::fs::write(d.join("runtime.json"), r#"{"port":6790,"token":"  "}"#).unwrap();
        assert!(runtime(&d).is_none());
    }

    /// Which port the tray looks for first. Reading only `tray.json`
    /// is what made it probe the OLD port after a dashboard port
    /// change, spawn a daemon that bound the new one, and then exit on
    /// timeout leaving that daemon orphaned.
    #[test]
    fn the_daemon_port_beats_the_one_we_last_spawned_on() {
        use super::load_port;

        let write = |dir: &std::path::Path, name: &str, body: &str| {
            std::fs::write(dir.join(name), body).unwrap();
        };

        // Nothing saved anywhere: the caller's scan range decides.
        let d = data_dir("port-none", None, None);
        assert_eq!(load_port(&d), None);

        // Only the tray's own note - the pre-dashboard case.
        let d = data_dir("port-tray", None, None);
        write(&d, "tray.json", r#"{"port": 6789}"#);
        assert_eq!(load_port(&d), Some(6789));

        // Both: settings.json wins, because that is what the daemon
        // itself applies over the --port we pass it.
        write(&d, "settings.json", r#"{"port": 6790}"#);
        assert_eq!(load_port(&d), Some(6790));

        // A port saved as a string still counts (different writers,
        // different JSON types), and 0 or out of range does not.
        write(&d, "settings.json", r#"{"port": "6791"}"#);
        assert_eq!(load_port(&d), Some(6791));
        for bad in [
            r#"{"port": 0}"#,
            r#"{"port": 70000}"#,
            r#"{"port": true}"#,
            "{}",
            "not json",
        ] {
            write(&d, "settings.json", bad);
            assert_eq!(
                load_port(&d),
                Some(6789),
                "fell through to tray.json for {bad}"
            );
        }
    }

    /// Two probes must not share a nonce, or a recorded answer replays.
    #[test]
    fn probe_nonces_differ() {
        use super::probe_nonce;
        let a = probe_nonce();
        let b = probe_nonce();
        assert_ne!(a, b);
        assert!(
            a.len() >= 16 && a.bytes().all(|c| c.is_ascii_alphanumeric()),
            "{a}"
        );
    }

    /// The hover tooltip, which is the only live number the tray
    /// shows without opening a browser. Every arm of it, because the
    /// win32 half cannot be run on the machines these tests run on.
    #[test]
    fn the_tooltip_says_what_the_queue_is_doing() {
        use super::tip_from_queue;
        let q = |body: &str| serde_json::from_str::<serde_json::Value>(body).unwrap();
        let tip = |body: &str| tip_from_queue(&q(body), false).unwrap();

        // The field separator is spelled as its codepoint below, on
        // purpose: a middle dot, a period and a bullet are the same
        // three pixels in a diff, and this is the one place the
        // choice between them is pinned.
        //
        // Downloading: what it is doing, how much of it, how fast.
        // The mac menu bar draws this same line without the name in
        // front of it - see the note on tip_from_queue.
        assert_eq!(
            tip(
                r#"{"queue":{"noofslots":3,"kbpersec":"42300","paused":false,
                        "status":"Downloading"}}"#
            ),
            "nzbfast - Downloading \u{b7} 3 jobs \u{b7} 42 MB/s"
        );
        // One job is one job, not "1 jobs".
        assert_eq!(
            tip(r#"{"queue":{"noofslots":1,"kbpersec":"42300","status":"Downloading"}}"#),
            "nzbfast - Downloading \u{b7} 1 job \u{b7} 42 MB/s"
        );
        // A rate over 1000 MB/s rolls to GB/s with two decimals, as
        // the dashboard's own formatter does.
        assert_eq!(
            tip(r#"{"queue":{"noofslots":1,"kbpersec":"1250000","status":"Downloading"}}"#),
            "nzbfast - Downloading \u{b7} 1 job \u{b7} 1.25 GB/s"
        );
        // Bits, for an install whose dashboard is set that way.
        assert_eq!(
            tip_from_queue(
                &q(r#"{"queue":{"noofslots":1,"kbpersec":"42300","status":"Downloading"}}"#),
                true
            )
            .unwrap(),
            "nzbfast - Downloading \u{b7} 1 job \u{b7} 338 Mb/s"
        );
        // On the wire with nothing measurable moving - verifying,
        // repairing, unpacking. "0 MB/s" would read as broken, so
        // the field is dropped and the state word carries the line.
        assert_eq!(
            tip(r#"{"queue":{"noofslots":2,"kbpersec":"0","status":"Downloading"}}"#),
            "nzbfast - Downloading \u{b7} 2 jobs"
        );
        // ...and 0.04 MB/s is that same case, not a rate: it prints
        // as "0 MB/s" and the floor is what stops it.
        assert_eq!(
            tip(r#"{"queue":{"noofslots":2,"kbpersec":"40","status":"Downloading"}}"#),
            "nzbfast - Downloading \u{b7} 2 jobs"
        );
        // The three resting states. Offline and paused are different
        // things and the dashboard shows them separately, so the
        // tooltip does too.
        assert_eq!(
            tip(r#"{"queue":{"noofslots":0,"kbpersec":"0","status":"Idle"}}"#),
            "nzbfast - Idle"
        );
        assert_eq!(
            tip(r#"{"queue":{"noofslots":0,"paused":true,"status":"Paused"}}"#),
            "nzbfast - Paused"
        );
        assert_eq!(
            tip(r#"{"queue":{"noofslots":4,"paused":true,"status":"Paused"}}"#),
            "nzbfast - Paused \u{b7} 4 jobs"
        );
        // A paused queue keeps no rate, whatever the last sample
        // said - the daemon's own word for it is Paused, and a
        // speed beside it would contradict the word.
        assert_eq!(
            tip(r#"{"queue":{"noofslots":4,"paused":true,"kbpersec":"42300",
                        "status":"Paused"}}"#),
            "nzbfast - Paused \u{b7} 4 jobs"
        );
        // Offline outranks paused: pausing while offline is true of
        // both, and offline is the one that explains the silence. It
        // outranks the daemon's `status` word too.
        assert_eq!(
            tip(r#"{"queue":{"noofslots":4,"paused":true,"offline":true,
                        "status":"Paused"}}"#),
            "nzbfast - Offline \u{b7} 4 jobs"
        );
        // No `status` at all - an older daemon, or a body trimmed by
        // something in the middle. The word is derived rather than
        // left blank, because a line starting with the separator is
        // the one shape that reads as a bug.
        assert_eq!(
            tip(r#"{"queue":{"noofslots":3,"kbpersec":"42300"}}"#),
            "nzbfast - Downloading \u{b7} 3 jobs \u{b7} 42 MB/s"
        );
        assert_eq!(tip(r#"{"queue":{"noofslots":0}}"#), "nzbfast - Idle");
        assert_eq!(
            tip(r#"{"queue":{"noofslots":2,"paused":true}}"#),
            "nzbfast - Paused \u{b7} 2 jobs"
        );

        // Not a queue answer at all: an auth refusal, an error page,
        // a body with no count. The caller falls back to the plain
        // name rather than printing half a sentence.
        for body in [
            r#"{"status":false,"error":"API Key Required"}"#,
            r#"{"queue":{}}"#,
            "{}",
        ] {
            assert!(tip_from_queue(&q(body), false).is_none(), "{body}");
        }

        // Every arm fits the 64-unit tooltip buffer with room to
        // spare, so a real tip is never the truncation case.
        let long = tip(r#"{"queue":{"noofslots":999999,"kbpersec":"1250000",
                    "status":"Downloading"}}"#);
        assert!(long.chars().count() < 60, "{long}");
    }

    /// The tooltip follows the dashboard's bits/bytes setting,
    /// which lives in the same settings.json the API key comes out
    /// of. A default install, an install that never touched the
    /// control and an unreadable file all mean bytes.
    #[test]
    fn the_unit_setting_comes_out_of_settings_json() {
        use super::unit_bits;
        assert!(!unit_bits(&data_dir("units-none", None, None)));
        assert!(!unit_bits(&data_dir(
            "units-off",
            Some(r#"{"unit_bits":false}"#),
            None
        )));
        assert!(unit_bits(&data_dir(
            "units-on",
            Some(r#"{"unit_bits":true}"#),
            None
        )));
        // A value of the wrong type is not a preference.
        assert!(!unit_bits(&data_dir(
            "units-junk",
            Some(r#"{"unit_bits":"yes"}"#),
            None
        )));
        assert!(!unit_bits(&data_dir(
            "units-broken",
            Some("not json"),
            None
        )));
    }

    /// The win32 fixed buffers are arrays: an over-long copy that
    /// fills one leaves no NUL and the shell reads past the string.
    #[test]
    fn the_limit_menu_offers_the_header_s_own_choices() {
        use super::{LimitPick, limit_menu};
        let q = |body: &str| serde_json::from_str::<serde_json::Value>(body).unwrap();
        // label, checked - the shape a reader can compare to the
        // dashboard header at a glance.
        let rows = |body: &str, bits: bool| {
            limit_menu(&q(body), bits)
                .into_iter()
                .map(|r| (r.label, r.checked))
                .collect::<Vec<_>>()
        };
        let picks = |body: &str| {
            limit_menu(&q(body), false)
                .into_iter()
                .map(|r| r.pick)
                .collect::<Vec<_>>()
        };

        // No line speed configured, no limit set: the five absolute
        // presets and nothing else, with "No limit" holding the check.
        // The percentages are ABSENT rather than greyed - the header
        // does not render them without a line speed either.
        assert_eq!(
            rows(r#"{"queue":{"speedlimit_abs":"0","line_speed":0}}"#, false),
            vec![
                ("No limit".to_string(), true),
                ("Auto \u{b7} yield to LAN".to_string(), false),
                ("50 MB/s".to_string(), false),
                ("100 MB/s".to_string(), false),
                ("250 MB/s".to_string(), false),
                ("500 MB/s".to_string(), false),
                ("1.00 GB/s".to_string(), false),
            ]
        );
        // A preset in force takes the check, and only it.
        let r = rows(
            r#"{"queue":{"speedlimit_abs":"100000000","line_speed":0}}"#,
            false,
        );
        assert_eq!(
            r.iter()
                .filter(|(_, c)| *c)
                .map(|(l, _)| l.as_str())
                .collect::<Vec<_>>(),
            vec!["100 MB/s"]
        );
        // Auto says what auto currently MEANS. A row reading only
        // "Auto" reads as "no limit", which is the one thing it is not.
        let r = rows(
            r#"{"queue":{"speedlimit_abs":"42300000","auto_speed":true,"line_speed":0}}"#,
            false,
        );
        assert_eq!(r[1], ("Auto \u{b7} 42 MB/s now".to_string(), true));
        assert!(!r[0].1, "auto must not also check No limit");
        // ...and falls back to the plain words before it has picked a
        // number, rather than saying "Auto \u{b7} 0 MB/s now".
        assert_eq!(
            rows(
                r#"{"queue":{"speedlimit_abs":"0","auto_speed":true,"line_speed":0}}"#,
                false
            )[1],
            ("Auto \u{b7} yield to LAN".to_string(), true)
        );

        // With a line speed, the three percentages appear, each
        // labelled with what it comes to on THIS line.
        let r = rows(
            r#"{"queue":{"speedlimit_abs":"0","line_speed":1000000000}}"#,
            false,
        );
        assert_eq!(
            r[7..].iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>(),
            vec![
                "25% of your line speed \u{b7} 250 MB/s",
                "50% of your line speed \u{b7} 500 MB/s",
                "75% of your line speed \u{b7} 750 MB/s",
            ]
        );
        // A percentage is STORED as an absolute limit, so it has to be
        // matched back to the percentage that produced it - and it
        // beats the absolute preset of the same size. Without this a
        // 25% pick comes back "(custom)" on the very next poll, and
        // here it would come back as the 250 MB/s preset instead.
        let r = rows(
            r#"{"queue":{"speedlimit_abs":"250000000","line_speed":1000000000}}"#,
            false,
        );
        assert_eq!(
            r.iter()
                .filter(|(_, c)| *c)
                .map(|(l, _)| l.as_str())
                .collect::<Vec<_>>(),
            vec!["25% of your line speed \u{b7} 250 MB/s"]
        );

        // A limit that matches nothing - typed in the dashboard, set
        // by a schedule entry, pushed over the API - gets its own row
        // instead of leaving every row unchecked, which would read as
        // "no limit is set".
        let r = rows(
            r#"{"queue":{"speedlimit_abs":"37000000","line_speed":0}}"#,
            false,
        );
        assert_eq!(*r.last().unwrap(), ("37 MB/s (custom)".to_string(), true));
        assert_eq!(r.iter().filter(|(_, c)| *c).count(), 1);
        // ...and it is the only row that is not a pick.
        assert_eq!(
            *picks(r#"{"queue":{"speedlimit_abs":"37000000","line_speed":0}}"#)
                .last()
                .unwrap(),
            LimitPick::Live
        );

        // Bits install: the presets are byte rates underneath and the
        // labels follow the setting, exactly as relabelLimitOptions
        // does it on the page.
        let r = rows(r#"{"queue":{"speedlimit_abs":"0","line_speed":0}}"#, true);
        assert_eq!(
            r[2..].iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>(),
            vec![
                "400 Mb/s",
                "800 Mb/s",
                "2.00 Gb/s",
                "4.00 Gb/s",
                "8.00 Gb/s"
            ]
        );

        // Not a queue answer at all: no menu, rather than an empty one.
        assert!(limit_menu(&q(r#"{"error":"API Key Required"}"#), false).is_empty());
        // A body with none of the three fields is still a menu - a
        // daemon too old to send them has no limit set, which is what
        // the rows then say.
        assert!(limit_menu(&q(r#"{"queue":{}}"#), false)[0].checked);
    }

    #[test]
    fn a_pick_turns_the_governor_off_before_it_sets_a_ceiling() {
        use super::{LimitPick, limit_calls};
        // Order is the point: the governor writes the rate every
        // second, so a ceiling set while it still holds the wheel is
        // overwritten before the user's next poll.
        assert_eq!(
            limit_calls(LimitPick::Abs(50_000_000)),
            vec![
                ("auto_speed", "0".to_string()),
                ("speedlimit", "50000000".to_string())
            ]
        );
        assert_eq!(
            limit_calls(LimitPick::None),
            vec![
                ("auto_speed", "0".to_string()),
                ("speedlimit", "0".to_string())
            ]
        );
        // A percentage goes over the wire AS a percentage: the daemon
        // anchors it against the line speed it holds, so the menu
        // cannot pick a stale one. Bare and <= 100 is that convention.
        assert_eq!(
            limit_calls(LimitPick::Pct(25)),
            vec![
                ("auto_speed", "0".to_string()),
                ("speedlimit", "25".to_string())
            ]
        );
        // Auto is the one arm that does NOT clear itself first.
        assert_eq!(
            limit_calls(LimitPick::Auto),
            vec![("auto_speed", "1".to_string())]
        );
        // The custom row is a readout, not a button.
        assert!(limit_calls(LimitPick::Live).is_empty());
    }

    #[test]
    fn a_capped_wide_string_always_ends_in_a_nul() {
        use super::wide_capped;
        assert_eq!(wide_capped("hi", 8), vec![104, 105, 0]);
        // Exactly full, and one past.
        assert_eq!(wide_capped("abc", 4), vec![97, 98, 99, 0]);
        let cut = wide_capped("abcdef", 4);
        assert_eq!(cut, vec![97, 98, 99, 0]);
        assert_eq!(cut.len(), 4);
        // A cut through a surrogate pair drops the orphan rather
        // than leaving a replacement glyph in the tooltip.
        let pair = wide_capped("ab\u{1F680}", 4);
        assert_eq!(pair, vec![97, 98, 0], "the lone high surrogate came off");
        // ...and a whole pair that fits is kept (four units + NUL).
        assert_eq!(wide_capped("ab\u{1F680}", 5).len(), 5);
        // Degenerate cap: no room for even a terminator.
        assert!(wide_capped("abc", 0).is_empty());
    }
}
