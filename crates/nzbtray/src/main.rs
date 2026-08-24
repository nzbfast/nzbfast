//! nzbtray - the Windows wrapper around the nzbfast daemon.
//!
//! A no-console tray app: it
//! owns `nzbfast.exe serve` as a hidden child, the web dashboard stays
//! the only real UI. Hand-rolled win32 via windows-sys - a message
//! loop, one hidden window, Shell_NotifyIconW - because the tray-crate
//! ecosystem drags in GUI stacks the mingw static recipe doesn't need.
//!
//! Lifecycle rules (shared with the Mac wrapper):
//! - attach-or-spawn: if the persisted port answers a keyless
//!   mode=version as nzbfast - either the version body or our own
//!   "API Key Required/Incorrect" refusal, see `probe_body` - reuse it
//!   and NEVER kill it (we didn't spawn it); otherwise spawn on the
//!   first free port scanning up from 6789.
//! - spawn with NZBFAST_BUNDLED=1 (update self-swap gate), data in
//!   %LOCALAPPDATA%\nzbfast, downloads in %USERPROFILE%\Downloads\nzbfast.
//! - Quit = POST mode=shutdown, wait ≤5 s, then hard-kill; in-flight
//!   downloads resume from the journal next start.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("nzbtray is the Windows tray wrapper - nothing to do on this OS.");
}

#[cfg(windows)]
fn main() {
    app::run();
}

/// The tray's decisions that do not need win32: recognising an nzbfast
/// daemon from the body of an *unauthenticated* `mode=version` probe, and
/// working out which API key to speak to it with. Lives outside the win32
/// `app` module, and off `cfg(windows)`, so all of it is unit-testable on
/// any host (`cargo test -p nzbtray`) - `mod app` never compiles on the
/// machines these tests run on, so anything left in there is unguarded by
/// construction.
#[cfg(any(windows, test))]
mod probe_body {
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
    static IDENTITY_PROVEN: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

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
            serde_json::from_str(&std::fs::read_to_string(data_dir.join("runtime.json")).ok()?)
                .ok()?;
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
            let dir =
                std::env::temp_dir().join(format!("nzbtray-key-{}-{name}", std::process::id()));
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
}

#[cfg(windows)]
mod app {
    use serde_json::Value;
    use std::cell::RefCell;
    use std::io::Write as _;
    use std::os::windows::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Registry::*;
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::Shell::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const WM_TRAY: u32 = WM_APP + 1;
    /// Posted by a second `nzbtray.exe --quit` process to ask the running
    /// tray to shut down the way the menu item does. The installer uses it
    /// instead of terminating us, so the queue is persisted before an
    /// upgrade overwrites the exe.
    const WM_QUITAPP: u32 = WM_APP + 2;
    /// Must match nzbfast's serve::KEYLESS_MARKER. The tray cannot link
    /// against the daemon, so this is the one place the string is
    /// duplicated; a test in the daemon pins the pair together.
    const KEYLESS_MARKER: &str = "nzbfast cannot start: API key file";
    const TIMER_CHILD: usize = 1;
    /// Tooltip length, in UTF-16 units INCLUDING the terminator.
    ///
    /// The array is 128 and a modern shell reads all of it; 64 is the
    /// documented floor (the limit for the older, smaller form of the
    /// struct), and the smaller of the two is what a tray with nothing
    /// long to say should hold itself to. Every tip this one builds is
    /// under 60, which a test in `probe_body` pins, so this is a guard
    /// against a future tip growing rather than a working limit.
    const TIP_UNITS: usize = 64;
    /// Shortest gap between two tooltip refreshes. The refresh is
    /// hover-driven, and a hover is a stream of WM_MOUSEMOVEs, so
    /// without this one pass of the cursor would fire a request per
    /// mouse position.
    const TIP_MIN_GAP: Duration = Duration::from_millis(1500);
    /// How long a tooltip refresh may wait on the daemon. It runs ON the
    /// message pump, so this is also the longest the tray can appear
    /// stuck when the engine is wedged. Loopback to our own daemon
    /// answers in single-digit milliseconds; the menu's own refresh has
    /// blocked for up to 900 ms since the menu existed.
    const TIP_TIMEOUT_MS: u64 = 500;

    /// Window class + title of the hidden message window, shared by the
    /// running tray and the `--quit` helper that has to find it.
    const MSG_CLASS: &str = "nzbtray_msg";
    const MSG_TITLE: &str = "nzbfast";

    // Menu command ids (TrackPopupMenu with TPM_RETURNCMD).
    const ID_DASH: u16 = 1;
    const ID_DOWNLOADS: u16 = 2;
    const ID_PAUSE: u16 = 3;
    const ID_AUTOSTART: u16 = 4;
    const ID_MANUAL: u16 = 5;
    const ID_RESTART: u16 = 6;
    const ID_QUIT: u16 = 7;

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const RUN_VALUE: &str = "nzbfast";
    /// Ports to try above the base before giving up (50 is far beyond
    /// any realistic collision pile-up on a desktop).
    const BASE_PORT: u16 = 6789;
    const SCAN_SPAN: u16 = 50;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct App {
        port: u16,
        /// True when WE spawned the daemon (and may therefore stop it).
        owner: bool,
        child: Option<Child>,
        child_dead: bool,
        /// Last state seen when the menu opened - picks the Pause/Resume label.
        paused: bool,
        /// When the tooltip was last refreshed, for the hover throttle
        /// (see [`refresh_tip`]). None = never, so the first hover of
        /// the session always asks.
        tip_at: Option<Instant>,
        data_dir: PathBuf,
        out_dir: PathBuf,
        exe_dir: PathBuf,
    }

    thread_local! {
        static APP: RefCell<Option<App>> = const { RefCell::new(None) };
    }

    // ---- small helpers ------------------------------------------------

    /// The TLS settings for talking to OUR OWN daemon over loopback.
    ///
    /// It presents whatever certificate the operator configured, which in
    /// every real deployment is self-signed and issued for a public
    /// hostname rather than for 127.0.0.1 - so a verifying client refuses
    /// it, and refusing is what left the tray unable to manage a
    /// TLS-enabled daemon at all.
    ///
    /// Accepting it costs nothing here, because the certificate was never
    /// what identified this daemon. The connection is to 127.0.0.1, which
    /// no host on the network can sit in the middle of; the threat is a
    /// local process squatting the port, and that is what the
    /// `runtime.json` token handshake is for - a challenge only the engine
    /// that wrote a file our user alone can read is able to answer. The
    /// API key still rides behind that proof, exactly as on plain HTTP.
    /// So nothing we were relying on is given up here, and TLS keeps
    /// doing its real job: encrypting the hop, and letting the tray reach
    /// the same socket the LAN does.
    #[derive(Debug)]
    struct LoopbackCerts(std::sync::Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for LoopbackCerts {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        // The signature checks stay REAL: they prove the peer holds the
        // key for the certificate it just presented, which is what stops
        // the handshake being replayed from a recording. Only the "is
        // this certificate trusted for this name" question is waived.
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// Built once and shared: the handshake config is immutable and
    /// assembling it per request would re-do the provider setup on every
    /// menu click.
    fn loopback_tls() -> std::sync::Arc<rustls::ClientConfig> {
        static CFG: std::sync::OnceLock<std::sync::Arc<rustls::ClientConfig>> =
            std::sync::OnceLock::new();
        CFG.get_or_init(|| {
            // The provider is named, never defaulted: a process that links
            // more than one panics inside a provider-less `builder()`, and
            // ring is the one ureq's own rustls feature brings in.
            let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
            let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .expect("ring provider supports the default protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(LoopbackCerts(provider)))
                .with_no_client_auth();
            std::sync::Arc::new(cfg)
        })
        .clone()
    }

    fn agent(timeout_ms: u64, tls: bool) -> ureq::Agent {
        let b = ureq::AgentBuilder::new().timeout(Duration::from_millis(timeout_ms));
        if tls { b.tls_config(loopback_tls()) } else { b }.build()
    }

    use crate::probe_body::{dash_url, keyed_url, origin, query_value, tls_for};

    /// GET an API mode; None on any transport/JSON failure.
    fn api_get(port: u16, data_dir: &Path, mode: &str, timeout_ms: u64) -> Option<Value> {
        let tls = tls_for(port, data_dir);
        let url = keyed_url(
            format!("{}/api?mode={mode}&output=json", origin(port, tls)),
            data_dir,
            proof(port, data_dir),
        );
        let body = agent(timeout_ms, tls)
            .get(&url)
            .call()
            .ok()?
            .into_string()
            .ok()?;
        serde_json::from_str(&body).ok()
    }

    enum Probe {
        Nzbfast,
        Other,
        Free,
    }

    /// What lives on 127.0.0.1:port? Connection refused = free; a body
    /// `probe_body::is_nzbfast` recognises (the version answer OR the
    /// daemon's own auth refusal) is one of ours; anything else is a
    /// stranger. Sent WITHOUT the API key - see `probe_body::is_nzbfast`.
    ///
    /// A reply shape is not identity, though, and `Probe::Nzbfast` means
    /// attach-and-then-hand-over-the-API-key. So when `runtime.json` names
    /// THIS port, the listener must also prove it holds that file's
    /// per-start token (`probe_body::proof_matches`): any local account can
    /// print our JSON, but only our own user can read that file. A daemon
    /// too old to answer the challenge is accepted as before - refusing
    /// would break attaching across the upgrade - and everything else that
    /// fails the proof is a stranger.
    ///
    /// The scheme comes from `runtime.json` too. When it names this port
    /// its `tls` is authoritative - one request, as before. When it does
    /// NOT (an engine from another data dir, or one older than the key),
    /// we no longer assume plain HTTP: a TLS listener answers a plaintext
    /// GET with an alert and a close, which reads as a transport failure,
    /// so the tray called its own healthy engine a stranger and refused
    /// to attach. Only that miss costs a second request.
    fn probe(port: u16, data_dir: &Path) -> Probe {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_err() {
            return Probe::Free;
        }
        let rt = crate::probe_body::runtime(data_dir).filter(|r| r.port == port);
        let nonce = crate::probe_body::probe_nonce();
        let ask = |tls: bool| {
            let url = format!(
                "{}/api?mode=version&output=json&hs={nonce}",
                origin(port, tls)
            );
            agent(900, tls)
                .get(&url)
                .call()
                .ok()
                .and_then(|r| r.into_string().ok())
        };
        let body = match rt.as_ref() {
            Some(r) => ask(r.tls),
            None => ask(false).or_else(|| ask(true)),
        };
        let Some(body) = body else {
            return Probe::Other;
        };
        if !crate::probe_body::is_nzbfast(&body) {
            return Probe::Other;
        }
        // Proof is mandatory whenever runtime.json names this port - see
        // `probe_body::identity_ok`. It used to be waived for a reply that
        // simply omitted `hs_proof`, which any impostor can do.
        if crate::probe_body::identity_ok(&body, rt.as_ref().map(|r| r.token.as_str()), &nonce) {
            // Proven only when a runtime.json token was actually
            // challenged. The legacy `None` arm attaches but must not
            // carry the stored key (Codex sweep 10 Aug M10); a spawn we
            // performed ourselves overrides this at the spawn site.
            crate::probe_body::record_identity_proven(rt.is_some());
            Probe::Nzbfast
        } else {
            Probe::Other
        }
    }

    /// The proof token every keyed URL needs, establishing it when this
    /// process has not yet done so. v1.0.22 regressed because arming
    /// the latch was a separate step each path had to remember - the
    /// second-instance hand-off did not, so every file-association add
    /// went keyless and the daemon 403ed it. Now asking for the proof
    /// IS the step: unproven means one probe here, so the runtime.json
    /// token challenge can arm it, and a listener that fails the
    /// challenge still gets only keyless URLs. No path can skip this
    /// and still build a key-bearing URL: `keyed_url`/`dash_url` take
    /// the token, and this is the only place the app obtains one.
    fn proof(port: u16, data_dir: &Path) -> Option<crate::probe_body::IdentityProof> {
        crate::probe_body::identity_proof().or_else(|| {
            let _ = probe(port, data_dir);
            crate::probe_body::identity_proof()
        })
    }

    /// The user's real Downloads folder via the known-folder API - a
    /// OneDrive-redirected or relocated profile puts it far from
    /// %USERPROFILE%\Downloads, which stays as the fallback.
    fn downloads_dir() -> PathBuf {
        use windows_sys::Win32::System::Com::CoTaskMemFree;
        use windows_sys::core::GUID;
        const FOLDERID_DOWNLOADS: GUID = GUID {
            data1: 0x374DE290,
            data2: 0x123F,
            data3: 0x4565,
            data4: [0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B],
        };
        // SAFETY: p is read, measured and freed only after
        // SHGetKnownFolderPath returned 0 (S_OK) and set it non-null,
        // which per that API's contract makes it a NUL-terminated UTF-16
        // string allocated for the caller; the length walk stops at that
        // NUL, from_raw_parts stays inside it, and CoTaskMemFree is the
        // documented release for the allocation.
        unsafe {
            let mut p: *mut u16 = std::ptr::null_mut();
            if SHGetKnownFolderPath(&FOLDERID_DOWNLOADS, 0, std::ptr::null_mut(), &mut p) == 0
                && !p.is_null()
            {
                let mut len = 0usize;
                while *p.add(len) != 0 {
                    len += 1;
                }
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
                CoTaskMemFree(p as *const _);
                if !s.is_empty() {
                    return PathBuf::from(s);
                }
            }
        }
        let profile = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
        PathBuf::from(profile).join("Downloads")
    }

    fn prefs_path(data_dir: &Path) -> PathBuf {
        data_dir.join("tray.json")
    }

    fn save_port(data_dir: &Path, port: u16) {
        let tmp = prefs_path(data_dir).with_extension("json.tmp");
        if std::fs::write(&tmp, format!("{{\"port\": {port}}}\n")).is_ok() {
            let _ = std::fs::rename(&tmp, prefs_path(data_dir));
        }
    }

    fn open_url(url: &str) {
        // SAFETY: FFI call; the verb and URL are NUL-terminated UTF-16
        // from `w` whose buffers outlive the call, and the null
        // hwnd/parameters/directory arguments are documented as valid.
        unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                w("open").as_ptr(),
                w(url).as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            );
        }
    }

    fn message_box(text: &str, flags: u32) -> i32 {
        // SAFETY: FFI call; text and caption are NUL-terminated UTF-16
        // from `w` whose buffers outlive the call, and a null owner
        // window is documented as valid.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                w(text).as_ptr(),
                w("nzbfast").as_ptr(),
                flags,
            )
        }
    }

    /// Append one tray-stamped line to daemon.log, in the daemon's own
    /// timestamp format so the two interleave legibly. This exists for
    /// the child-death paths: a native Windows crash (access violation,
    /// heap corruption, a fail-fast) writes NOTHING to stderr, so
    /// without this line an engine death is indistinguishable in the
    /// log from a machine that went to sleep - which is exactly the
    /// hole Gary's silent idle crash fell through (TODO 165).
    fn log_note(data_dir: &Path, msg: &str) {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        // Civil-from-days (Hinnant): enough calendar for a log stamp
        // without pulling a date crate into the tray.
        let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(data_dir.join("daemon.log"))
        {
            let _ = writeln!(
                f,
                "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z WARN  [tray] {msg}",
                rem / 3600,
                (rem / 60) % 60,
                rem % 60
            );
        }
    }

    fn log_tail(data_dir: &Path, lines: usize) -> String {
        std::fs::read_to_string(data_dir.join("daemon.log"))
            .map(|s| {
                let v: Vec<&str> = s.lines().rev().take(lines).collect();
                v.into_iter().rev().collect::<Vec<_>>().join("\n")
            })
            .unwrap_or_default()
    }

    // ---- daemon lifecycle ---------------------------------------------

    /// Rotate daemon.log at ~5 MB (keep one generation), then spawn the
    /// daemon on `port` with the wrapper contract: bundled flag, hidden
    /// window, explicit data-dir paths, cwd = data dir.
    fn spawn_daemon(exe_dir: &Path, data_dir: &Path, out_dir: &Path, port: u16) -> Option<Child> {
        let log_path = data_dir.join("daemon.log");
        if std::fs::metadata(&log_path)
            .map(|m| m.len() > 5_000_000)
            .unwrap_or(false)
        {
            let _ = std::fs::remove_file(data_dir.join("daemon.log.1"));
            let _ = std::fs::rename(&log_path, data_dir.join("daemon.log.1"));
        }
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .ok()?;
        let log2 = log.try_clone().ok()?;
        Command::new(exe_dir.join("nzbfast.exe"))
            .args(["serve", "--port", &port.to_string()])
            .args([
                "--config",
                &data_dir.join("config.local.json").to_string_lossy(),
            ])
            .args(["--out", &out_dir.to_string_lossy()])
            // Watch the user's actual Downloads folder: save an .nzb the
            // way you save anything and it's queued automatically. Only
            // .nzb files are touched (consumed on ingest); the out dir
            // below it isn't scanned (non-recursive). A folder set in the
            // dashboard persists in settings.json and wins over this flag.
            .args(["--watch", &downloads_dir().to_string_lossy()])
            .args(["--index-db", &data_dir.join("index.db").to_string_lossy()])
            .env("NZBFAST_BUNDLED", "1")
            .current_dir(data_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .ok()
    }

    /// Attach to a running nzbfast or spawn our own. Returns
    /// (port, spawned child). Shows an error box and exits on failure.
    /// §98: is the nzbfast engine on `port` older than this tray - and if
    /// so, did we manage to stop it? True means the port is FREE and the
    /// caller should spawn the bundled engine on it. False means attach:
    /// same or newer engine, a version we could not read, a daemon whose
    /// key we do not hold, or an old engine that would not die (attaching
    /// to it beats stranding the user engineless).
    ///
    /// Shutdown is by authenticated API on the port it serves, which
    /// reaches the old engine wherever its binary lives. The wait is
    /// generous on purpose: `mode=shutdown` persists the queue first, and
    /// a busy engine has taken ~30 s to wind down (TODO §98 point 2), so
    /// an impatient deadline would turn every slow-but-clean shutdown
    /// into a stranded attach. Mirrors the Mac wrapper's upgradeRestart.
    fn upgrade_restart_if_older(port: u16, data_dir: &Path) -> bool {
        let Some(mine) = crate::probe_body::bundled_version() else {
            return false;
        };
        let tls = tls_for(port, data_dir);
        let base = origin(port, tls);
        let url = keyed_url(
            format!("{base}/api?mode=version&output=json"),
            data_dir,
            proof(port, data_dir),
        );
        let Some(running) = agent(3000, tls)
            .get(&url)
            .call()
            .ok()
            .and_then(|r| r.into_string().ok())
            .and_then(|b| crate::probe_body::body_version(&b))
        else {
            return false;
        };
        if running >= mine {
            return false;
        }
        let url = keyed_url(
            format!("{base}/api?mode=shutdown&output=json"),
            data_dir,
            proof(port, data_dir),
        );
        let _ = agent(5000, tls).post(&url).send_string("");
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(40) {
            if matches!(probe(port, data_dir), Probe::Free) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        false
    }

    fn ensure_daemon(exe_dir: &Path, data_dir: &Path, out_dir: &Path) -> (u16, Option<Child>) {
        // Persisted port first (the attach contract), then the scan range.
        let saved = crate::probe_body::load_port(data_dir);
        let candidates = saved
            .into_iter()
            .chain((BASE_PORT..BASE_PORT + SCAN_SPAN).filter(|p| Some(*p) != saved));
        let mut spawn_at = None;
        for p in candidates {
            match probe(p, data_dir) {
                Probe::Nzbfast => {
                    // §98: an engine that outlives the tray also outlives
                    // an UPGRADE - a winget/Scoop/zip upgrade replaces the
                    // exes without running the installer's --quit step, so
                    // this arm used to attach to the old engine and the
                    // dashboard kept serving the previous release with no
                    // hint. Restart it only when this tray is STRICTLY
                    // newer and both versions were readable; anything
                    // ambiguous - no key held (another data dir's
                    // install), unreadable versions - attaches as always,
                    // and so does a NEWER running engine (downgrading a
                    // daemon someone deliberately updated ahead of the
                    // tray would be the same silent surprise in reverse).
                    if upgrade_restart_if_older(p, data_dir) {
                        spawn_at = Some(p);
                        break;
                    }
                    return (p, None); // attach - not ours to manage
                }
                Probe::Free => {
                    spawn_at = Some(p);
                    break;
                }
                Probe::Other => continue,
            }
        }
        let Some(port) = spawn_at else {
            message_box(
                &format!(
                    "No free port found (tried {BASE_PORT}–{}).",
                    BASE_PORT + SCAN_SPAN
                ),
                MB_ICONERROR,
            );
            std::process::exit(1);
        };
        let Some(child) = spawn_daemon(exe_dir, data_dir, out_dir, port) else {
            message_box(
                &format!(
                    "Couldn't start nzbfast.exe from:\n{}\n\nReinstalling nzbfast should fix this.",
                    exe_dir.display()
                ),
                MB_ICONERROR,
            );
            std::process::exit(1);
        };
        // The daemon opens its index db and binds before answering; give
        // it 15 s of 250 ms polls like the Mac wrapper.
        let t0 = Instant::now();
        let mut child = child;
        while t0.elapsed() < Duration::from_secs(15) {
            if matches!(probe(port, data_dir), Probe::Nzbfast) {
                // Our own child on a port we just found free: identity
                // is established by the spawn itself, even if its
                // runtime.json write has not landed yet when the first
                // probe answers.
                crate::probe_body::record_identity_proven(true);
                return (port, Some(child));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        // Timed out: the daemon we started is still ours, and exiting without
        // it leaves an orphan holding the spool, the queue and a listening
        // socket - with no tray to stop it and nothing to attach to it.
        // Whatever the timeout was caused by, it is not a reason to walk away
        // from a child process.
        let _ = child.kill();
        let _ = child.wait();
        message_box(
            &format!(
                "nzbfast didn't come up on port {port} within 15 s.\n\nLast log lines:\n{}",
                log_tail(data_dir, 20)
            ),
            MB_ICONERROR,
        );
        std::process::exit(1);
    }

    /// Multipart POST of one .nzb to addfile. Returns the queued name.
    fn post_nzb(port: u16, data_dir: &Path, path: &Path) -> Result<String, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "job.nzb".into());
        let boundary = "nzbtray9f4c2b7e";
        let mut body = Vec::with_capacity(bytes.len() + 512);
        let _ = write!(
            body,
            "--{boundary}\r\nContent-Disposition: form-data; name=\"nzbfile\"; \
             filename=\"{name}\"\r\nContent-Type: application/x-nzb\r\n\r\n"
        );
        body.extend_from_slice(&bytes);
        let _ = write!(body, "\r\n--{boundary}--\r\n");
        let tls = tls_for(port, data_dir);
        let url = keyed_url(
            format!("{}/api?mode=addfile&output=json", origin(port, tls)),
            data_dir,
            proof(port, data_dir),
        );
        let resp = agent(10_000, tls)
            .post(&url)
            .set(
                "Content-Type",
                &format!("multipart/form-data; boundary={boundary}"),
            )
            .send_bytes(&body)
            .map_err(|e| format!("addfile: {e}"))?;
        let v: Value = serde_json::from_str(&resp.into_string().unwrap_or_default())
            .map_err(|e| format!("addfile parse: {e}"))?;
        if v.get("status").and_then(Value::as_bool) == Some(true) {
            Ok(name)
        } else {
            Err(v
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("rejected")
                .to_string())
        }
    }

    /// Hand a clicked `nzblnk:` link to mode=addnzblnk. Returns the
    /// queued name.
    ///
    /// The link crosses VERBATIM as one query value: `nzbkit::nzblnk` in
    /// the daemon is the only parser, and the only one that is fuzzed.
    ///
    /// A longer timeout than post_nzb's: resolving a header can mean a
    /// round of searches against the user's indexers, where posting an
    /// .nzb is a local write.
    fn post_nzblnk(port: u16, data_dir: &Path, link: &str) -> Result<String, String> {
        let tls = tls_for(port, data_dir);
        let url = keyed_url(
            format!(
                "{}/api?mode=addnzblnk&output=json&link={}",
                origin(port, tls),
                query_value(link)
            ),
            data_dir,
            proof(port, data_dir),
        );
        let resp = agent(45_000, tls)
            .get(&url)
            .call()
            .map_err(|e| format!("addnzblnk: {e}"))?;
        let v: Value = serde_json::from_str(&resp.into_string().unwrap_or_default())
            .map_err(|e| format!("addnzblnk parse: {e}"))?;
        if v.get("status").and_then(Value::as_bool) == Some(true) {
            Ok(v.get("name")
                .and_then(Value::as_str)
                .unwrap_or("download")
                .to_string())
        } else {
            Err(v
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("rejected")
                .to_string())
        }
    }

    // ---- graceful stop, for the installer -----------------------------

    /// Find the running tray's hidden window. It is a message-only window
    /// (HWND_MESSAGE parent), which the plain top-level FindWindowW search
    /// does not enumerate - the message-only pseudo-parent has to be named
    /// explicitly.
    fn find_tray_window() -> HWND {
        // SAFETY: FFI call; class and title are NUL-terminated UTF-16
        // from `w` whose buffers outlive the call, a null child-after
        // handle is documented as valid, and HWND_MESSAGE is the
        // documented pseudo-parent for the message-only search.
        unsafe {
            FindWindowExW(
                HWND_MESSAGE,
                std::ptr::null_mut(),
                w(MSG_CLASS).as_ptr(),
                w(MSG_TITLE).as_ptr(),
            )
        }
    }

    /// `nzbtray.exe --quit`: stop the stack cleanly and wait for it to be
    /// gone. Exists so the installer can replace the exes without killing
    /// processes - an unsigned installer running `taskkill /F` is exactly
    /// the pattern Defender's ML heuristics score as malware, and it also
    /// discarded the queue instead of persisting it.
    ///
    /// Preferred path is asking the running tray, because the tray owns
    /// the daemon child and already has the drain-then-kill logic. Falling
    /// back to a direct shutdown POST covers a daemon started some other
    /// way (a console `nzbfast serve`, or a tray that already died).
    fn quit_running_instance(data_dir: &Path) {
        let hwnd = find_tray_window();
        if !hwnd.is_null() {
            // SAFETY: FFI call carrying only a window handle and
            // integers, no pointers into our memory.
            unsafe { PostMessageW(hwnd, WM_QUITAPP, 0, 0) };
            // The tray gives its daemon 5 s to drain before hard-killing,
            // so allow a little more than that before giving up.
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(12) {
                // SAFETY: FFI call carrying only a window handle, no
                // pointers into our memory.
                if unsafe { IsWindow(find_tray_window()) } == 0 {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            // Still there: this is a tray from 1.0.8 or earlier. Those
            // register the same window class but have no WM_QUITAPP
            // handler, and their only route to a clean stop is the
            // tray-menu item, which nothing outside the process can
            // reach. So do by hand exactly what that menu item does -
            // drain the daemon over its own API, then close the window -
            // and fall through to the shared shutdown below.
            //
            // This is what makes an upgrade FROM a pre-1.0.9 install
            // possible at all: the Restart Manager cannot help, because
            // the tray's window is message-only (invisible to RM's
            // enumeration) and the daemon has no window whatsoever.
        }
        legacy_shutdown(data_dir);
    }

    /// Stop a running stack that cannot be asked nicely: shut the daemon
    /// down through the HTTP API it already exposes, then close the
    /// tray's window so its process exits and its image file unlocks.
    /// Both halves are cooperative - nothing here terminates a process.
    fn legacy_shutdown(data_dir: &Path) {
        if let Some(port) = crate::probe_body::load_port(data_dir)
            && matches!(probe(port, data_dir), Probe::Nzbfast)
        {
            let tls = tls_for(port, data_dir);
            let url = keyed_url(
                format!("{}/api?mode=shutdown&output=json", origin(port, tls)),
                data_dir,
                proof(port, data_dir),
            );
            let _ = agent(2000, tls).post(&url).send_string("");
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(8) {
                if matches!(probe(port, data_dir), Probe::Free) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        // The daemon is down (or was never up). Now the tray itself: an
        // old tray answers WM_CLOSE through DefWindowProc, which destroys
        // the window and ends its message loop.
        let hwnd = find_tray_window();
        if hwnd.is_null() {
            return;
        }
        // SAFETY: FFI call carrying only a window handle and integers, no
        // pointers into our memory.
        unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) };
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(8) {
            // SAFETY: FFI call carrying only a window handle, no pointers
            // into our memory.
            if unsafe { IsWindow(find_tray_window()) } == 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // ---- autostart (HKCU Run) -----------------------------------------

    fn autostart_enabled() -> bool {
        // SAFETY: FFI call; key and value names are NUL-terminated UTF-16
        // from `w` whose buffers outlive the call, ty and len point at
        // live locals, and a null data buffer is documented as a
        // size-only query.
        unsafe {
            let mut ty = 0u32;
            let mut len = 0u32;
            RegGetValueW(
                HKEY_CURRENT_USER,
                w(RUN_KEY).as_ptr(),
                w(RUN_VALUE).as_ptr(),
                RRF_RT_REG_SZ,
                &mut ty,
                std::ptr::null_mut(),
                &mut len,
            ) == ERROR_SUCCESS
        }
    }

    fn set_autostart(on: bool) {
        // SAFETY: FFI calls; all string arguments are NUL-terminated
        // UTF-16 from `w` whose buffers outlive each call, hkey points at
        // a live local, null security/class/disposition arguments are
        // documented as valid, the REG_SZ pointer/length pair describes
        // exactly val's buffer (val.len() u16s = twice that in bytes,
        // including the terminating NUL from `w`), and each key handle is
        // used and closed only on the ERROR_SUCCESS path that opened it.
        unsafe {
            if on {
                let exe = std::env::current_exe().unwrap_or_default();
                let val = w(&format!("\"{}\"", exe.display()));
                let mut hkey = std::ptr::null_mut();
                if RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    w(RUN_KEY).as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    KEY_SET_VALUE,
                    std::ptr::null(),
                    &mut hkey,
                    std::ptr::null_mut(),
                ) == ERROR_SUCCESS
                {
                    RegSetValueExW(
                        hkey,
                        w(RUN_VALUE).as_ptr(),
                        0,
                        REG_SZ,
                        val.as_ptr().cast(),
                        (val.len() * 2) as u32,
                    );
                    RegCloseKey(hkey);
                }
            } else {
                let mut hkey = std::ptr::null_mut();
                if RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    w(RUN_KEY).as_ptr(),
                    0,
                    KEY_SET_VALUE,
                    &mut hkey,
                ) == ERROR_SUCCESS
                {
                    RegDeleteValueW(hkey, w(RUN_VALUE).as_ptr());
                    RegCloseKey(hkey);
                }
            }
        }
    }

    // ---- tray icon ----------------------------------------------------

    fn nid(hwnd: HWND) -> NOTIFYICONDATAW {
        // SAFETY: NOTIFYICONDATAW is windows-sys's #[repr(C)] mirror of
        // the documented OS struct - integers, handles and u16 arrays -
        // so the all-zero bit pattern is a valid value for every field.
        let mut n: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        n.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        n.hWnd = hwnd;
        n.uID = 1;
        n
    }

    fn tray_add(hwnd: HWND) {
        let mut n = nid(hwnd);
        n.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        n.uCallbackMessage = WM_TRAY;
        // Resource id 1 (see build.rs); stock glyph if the resource is absent.
        // SAFETY: FFI calls; `1 as _` is the documented integer-resource
        // encoding of that id, and null module/instance arguments are
        // documented as valid.
        n.hIcon = unsafe {
            let h = LoadImageW(
                GetModuleHandleW(std::ptr::null()),
                1 as _,
                IMAGE_ICON,
                0,
                0,
                LR_DEFAULTSIZE,
            );
            if h.is_null() {
                LoadIconW(std::ptr::null_mut(), IDI_APPLICATION)
            } else {
                h as HICON
            }
        };
        put_w(&mut n.szTip, MSG_TITLE, TIP_UNITS);
        // SAFETY: FFI call; &n points at a live local NOTIFYICONDATAW
        // with cbSize set (see nid) for the duration of the call.
        unsafe { Shell_NotifyIconW(NIM_ADD, &n) };
    }

    fn tray_remove(hwnd: HWND) {
        // SAFETY: FFI call; the NOTIFYICONDATAW temporary from nid, with
        // cbSize set, lives for the duration of the call.
        unsafe { Shell_NotifyIconW(NIM_DELETE, &nid(hwnd)) };
    }

    /// Copy a string into one of the shell's fixed UTF-16 buffers.
    ///
    /// `cap` is what the SHELL will read, which is not always the
    /// array's length: see [`TIP_UNITS`]. `probe_body::wide_capped`
    /// guarantees the result fits and is terminated - the arms that used
    /// to be written inline here truncated with a plain `min`, which
    /// fills the array and leaves the shell reading whatever follows the
    /// string in the struct.
    fn put_w(dst: &mut [u16], s: &str, cap: usize) {
        let v = crate::probe_body::wide_capped(s, cap.min(dst.len()));
        dst[..v.len()].copy_from_slice(&v);
    }

    /// Put a live reading behind the tray icon's tooltip.
    ///
    /// Hover-driven, so nothing polls: the shell delivers WM_MOUSEMOVE
    /// through the icon's callback the moment the cursor enters it, and
    /// the tooltip is not drawn until the hover delay has elapsed - so a
    /// refresh started here lands before the text is shown. That is the
    /// same moment NIN_POPUPOPEN would give us without asking the icon
    /// to speak NOTIFYICON_VERSION_4, which would also move every mouse
    /// event into the low word of `lParam` and rewrite the click and
    /// menu contract this tray has always used.
    ///
    /// `force` skips the throttle for a state change the user just made
    /// themselves, where a stale tooltip reads as a failed command.
    ///
    /// The queue body answers the Pause/Resume label too, so the state
    /// the menu draws from is refreshed here rather than fetched twice.
    /// A daemon that does not answer in time leaves the plain product
    /// name, never a half-built sentence.
    fn refresh_tip(hwnd: HWND, force: bool) {
        let Some((port, data_dir)) = APP.with(|a| {
            let mut a = a.borrow_mut();
            let app = a.as_mut()?;
            let due = force || app.tip_at.is_none_or(|t| t.elapsed() >= TIP_MIN_GAP);
            // Stamped before the request, not after: the pump is
            // single-threaded, so a slow answer must not let the
            // mousemoves queued behind it each start another one.
            due.then(|| {
                app.tip_at = Some(Instant::now());
                (app.port, app.data_dir.clone())
            })
        }) else {
            return;
        };
        let q = api_get(port, &data_dir, "queue", TIP_TIMEOUT_MS);
        if let Some(p) = q
            .as_ref()
            .and_then(|v| v.pointer("/queue/paused"))
            .and_then(Value::as_bool)
        {
            APP.with(|a| {
                if let Some(app) = a.borrow_mut().as_mut() {
                    app.paused = p;
                }
            });
        }
        let tip = q
            .as_ref()
            .and_then(|v| {
                crate::probe_body::tip_from_queue(v, crate::probe_body::unit_bits(&data_dir))
            })
            .unwrap_or_else(|| MSG_TITLE.to_string());
        let mut n = nid(hwnd);
        n.uFlags = NIF_TIP;
        put_w(&mut n.szTip, &tip, TIP_UNITS);
        // SAFETY: FFI call; &n points at a live local NOTIFYICONDATAW
        // with cbSize set (see nid) for the duration of the call.
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &n) };
    }

    fn balloon(hwnd: HWND, title: &str, text: &str) {
        let mut n = nid(hwnd);
        n.uFlags = NIF_INFO;
        n.dwInfoFlags = NIIF_INFO;
        put_w(&mut n.szInfoTitle, title, 64);
        put_w(&mut n.szInfo, text, 256);
        // SAFETY: FFI call; &n points at a live local NOTIFYICONDATAW
        // with cbSize set (see nid) for the duration of the call.
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &n) };
    }

    // ---- menu ---------------------------------------------------------

    fn show_menu(hwnd: HWND) {
        let (port, data_dir, owner, child_dead, paused) = APP.with(|a| {
            let mut a = a.borrow_mut();
            let app = a.as_mut().unwrap();
            // Refresh the pause state while the user is mid-click; a slow
            // daemon just leaves the previous label.
            if let Some(q) = api_get(app.port, &app.data_dir, "queue", 900)
                && let Some(p) = q.pointer("/queue/paused").and_then(Value::as_bool)
            {
                app.paused = p;
            }
            (
                app.port,
                app.data_dir.clone(),
                app.owner,
                app.child_dead,
                app.paused,
            )
        });
        // SAFETY: FFI calls; menu labels are NUL-terminated UTF-16 from
        // `w` whose buffers outlive each AppendMenuW call, null pointers
        // are passed only where the API documents them as valid, &mut pt
        // points at a live local, and m is the menu handle created at the
        // top of this block and destroyed exactly once at the bottom.
        unsafe {
            let m = CreatePopupMenu();
            let add = |m, id: u16, label: &str, flags: u32| {
                AppendMenuW(m, flags, id as usize, w(label).as_ptr());
            };
            add(m, ID_DASH, "Open Dashboard", MF_STRING);
            add(m, ID_DOWNLOADS, "Open Downloads Folder", MF_STRING);
            AppendMenuW(m, MF_SEPARATOR, 0, std::ptr::null());
            add(
                m,
                ID_PAUSE,
                if paused { "Resume" } else { "Pause" },
                MF_STRING,
            );
            AppendMenuW(m, MF_SEPARATOR, 0, std::ptr::null());
            add(
                m,
                ID_AUTOSTART,
                "Start with Windows",
                MF_STRING | if autostart_enabled() { MF_CHECKED } else { 0 },
            );
            add(m, ID_MANUAL, "User Manual", MF_STRING);
            if owner && child_dead {
                AppendMenuW(m, MF_SEPARATOR, 0, std::ptr::null());
                add(m, ID_RESTART, "Restart nzbfast", MF_STRING);
            }
            AppendMenuW(m, MF_SEPARATOR, 0, std::ptr::null());
            add(m, ID_QUIT, "Quit nzbfast", MF_STRING);
            SetMenuDefaultItem(m, ID_DASH as u32, 0);

            let mut pt = POINT { x: 0, y: 0 };
            GetCursorPos(&mut pt);
            // Foreground first or the menu won't dismiss on outside-click
            // (the classic Shell_NotifyIcon menu gotcha).
            SetForegroundWindow(hwnd);
            let cmd = TrackPopupMenu(
                m,
                TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                pt.x,
                pt.y,
                0,
                hwnd,
                std::ptr::null(),
            );
            DestroyMenu(m);
            handle_command(hwnd, cmd as u16, port, &data_dir);
        }
    }

    fn handle_command(hwnd: HWND, cmd: u16, port: u16, data_dir: &Path) {
        match cmd {
            ID_DASH => open_url(&dash_url(
                port,
                tls_for(port, data_dir),
                data_dir,
                proof(port, data_dir),
            )),
            ID_DOWNLOADS => {
                // Prefer the daemon's live out_dir (an attached daemon may
                // download somewhere other than our default).
                let dir = api_get(port, data_dir, "get_config", 1500)
                    .and_then(|v| {
                        v.pointer("/config/nzbfast/out_dir")
                            .and_then(Value::as_str)
                            .map(PathBuf::from)
                    })
                    .unwrap_or_else(|| APP.with(|a| a.borrow().as_ref().unwrap().out_dir.clone()));
                let _ = std::fs::create_dir_all(&dir);
                open_url(&dir.to_string_lossy());
            }
            ID_PAUSE => {
                let paused = APP.with(|a| a.borrow().as_ref().unwrap().paused);
                let mode = if paused { "resume" } else { "pause" };
                if api_get(port, data_dir, mode, 2000).is_some() {
                    APP.with(|a| a.borrow_mut().as_mut().unwrap().paused = !paused);
                    // The user just changed the state; the next hover
                    // must not still describe the old one.
                    refresh_tip(hwnd, true);
                }
            }
            ID_AUTOSTART => set_autostart(!autostart_enabled()),
            ID_MANUAL => open_url(&format!("{}/manual", origin(port, tls_for(port, data_dir)))),
            ID_RESTART => restart_daemon(hwnd),
            ID_QUIT => quit(hwnd),
            _ => {}
        }
    }

    fn restart_daemon(hwnd: HWND) {
        APP.with(|a| {
            let mut a = a.borrow_mut();
            let app = a.as_mut().unwrap();
            if let Some(c) = spawn_daemon(&app.exe_dir, &app.data_dir, &app.out_dir, app.port) {
                app.child = Some(c);
                app.child_dead = false;
                balloon(hwnd, "nzbfast", "Restarting the download engine…");
            } else {
                balloon(
                    hwnd,
                    "nzbfast",
                    "Restart failed - see daemon.log in the data folder.",
                );
            }
        });
    }

    /// Graceful stop per the shared spec: POST mode=shutdown, give the
    /// daemon 5 s to persist and exit, then hard-kill. Attached daemons
    /// (not ours) are left running.
    fn quit(hwnd: HWND) {
        tray_remove(hwnd);
        APP.with(|a| {
            let mut a = a.borrow_mut();
            let app = a.as_mut().unwrap();
            if let Some(child) = app.child.as_mut()
                && child.try_wait().ok().flatten().is_none()
            {
                let tls = tls_for(app.port, &app.data_dir);
                let url = keyed_url(
                    format!("{}/api?mode=shutdown&output=json", origin(app.port, tls)),
                    &app.data_dir,
                    proof(app.port, &app.data_dir),
                );
                let _ = agent(2000, tls).post(&url).send_string("");
                let t0 = Instant::now();
                while t0.elapsed() < Duration::from_secs(5) {
                    if child.try_wait().ok().flatten().is_some() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                if child.try_wait().ok().flatten().is_none() {
                    // An engine that ignores an authenticated shutdown
                    // for 5 s is wedged, not slow - record that before
                    // the kill, or the log just stops mid-sentence and
                    // the death reads like a crash (TODO 165).
                    log_note(
                        &app.data_dir,
                        "engine did not answer the shutdown request within 5s - \
                         killed by the tray while quitting (the API was unresponsive)",
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        });
        // SAFETY: FFI call with no pointer arguments.
        unsafe { PostQuitMessage(0) };
    }

    // ---- window proc / message loop -----------------------------------

    // SAFETY: unsafe only to match the WNDPROC signature; the sole
    // registration is the WNDCLASSW in `run`, so the OS message
    // dispatcher is the only caller and supplies the arguments.
    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        // SAFETY: the FFI calls made here (DefWindowProcW,
        // PostQuitMessage) carry only the handles and integers the OS
        // dispatcher passed in, no pointers into our memory.
        unsafe {
            match msg {
                WM_TRAY => {
                    match lp as u32 {
                        WM_LBUTTONDBLCLK => {
                            let (port, data_dir) = APP.with(|a| {
                                let b = a.borrow();
                                let app = b.as_ref().unwrap();
                                (app.port, app.data_dir.clone())
                            });
                            open_url(&dash_url(
                                port,
                                tls_for(port, &data_dir),
                                &data_dir,
                                proof(port, &data_dir),
                            ));
                        }
                        WM_RBUTTONUP | WM_CONTEXTMENU => show_menu(hwnd),
                        // The cursor entered the icon: there are a few
                        // hundred milliseconds before the shell draws
                        // the tooltip, which is enough to put a live
                        // reading in it. Throttled inside.
                        WM_MOUSEMOVE => refresh_tip(hwnd, false),
                        _ => {}
                    }
                    0
                }
                // An `nzbtray.exe --quit` helper (the installer) asking for the
                // same clean stop the tray menu performs.
                WM_QUITAPP => {
                    quit(hwnd);
                    0
                }
                WM_TIMER if wp == TIMER_CHILD => {
                    // Child-death watchdog: single-threaded try_wait poll (no
                    // handle juggling across threads).
                    let died = APP.with(|a| {
                        let mut a = a.borrow_mut();
                        let app = a.as_mut().unwrap();
                        if app.child_dead {
                            return None;
                        }
                        match app.child.as_mut().map(|c| c.try_wait()) {
                            Some(Ok(Some(status))) => {
                                app.child_dead = true;
                                Some(status)
                            }
                            _ => None,
                        }
                    });
                    if let Some(status) = died {
                        // Stamp the death and its exit status into the
                        // log FIRST: a native crash said nothing to
                        // stderr, so this line is the only record of
                        // when and how the engine went (0xC0000005 is
                        // an access violation, 0xC0000374 heap
                        // corruption, 0xC00000FD stack overflow, 3 a
                        // CRT abort).
                        {
                            let dir = APP.with(|a| a.borrow().as_ref().unwrap().data_dir.clone());
                            let how = match status.code() {
                                Some(c) => format!("exit status {c} (0x{:08X})", c as u32),
                                None => "an unknown exit status".to_string(),
                            };
                            log_note(&dir, &format!("engine exited on its own with {how}"));
                        }
                        // Some deaths are not "try again" deaths. A missing
                        // or unusable API key stops startup deliberately and
                        // will do so every time, so telling this user to hit
                        // Restart sends them round a loop with no way out and
                        // no idea why. The daemon writes the whole
                        // explanation to daemon.log before it exits; if that
                        // is what happened, show it and say nothing about
                        // restarting.
                        let dir = APP.with(|a| a.borrow().as_ref().unwrap().data_dir.clone());
                        let tail = log_tail(&dir, 40);
                        if let Some(at) = tail.find(KEYLESS_MARKER) {
                            message_box(&tail[at..], MB_ICONERROR);
                        } else {
                            balloon(
                                hwnd,
                                "nzbfast stopped unexpectedly",
                                "The download engine exited. Right-click the tray icon → Restart nzbfast.",
                            );
                        }
                    }
                    0
                }
                WM_DESTROY => {
                    PostQuitMessage(0);
                    0
                }
                _ => DefWindowProcW(hwnd, msg, wp, lp),
            }
        }
    }

    pub fn run() {
        // An unrecognised flag must NEVER fall through to a normal
        // startup. Every tray up to 1.0.8 did, and it cost us the 1.0.9
        // upgrade: the 1.0.9 installer calls `{app}\nzbtray.exe --quit`
        // on the tray it is replacing and waits for it to exit, so an
        // older tray answered the request to shut down by starting a
        // resident tray plus a fresh daemon that re-locked the install
        // directory, and Setup hung on "Preparing to Install" until it
        // was force-closed. That installer now version-gates the call,
        // but the gate only protects trays that ship AFTER it - this
        // check is what makes the next flag we invent survivable.
        //
        // Bare paths are not flags: non-.nzb ones are filtered below and
        // a plain launch is the normal double-click case.
        let unknown: Vec<String> = std::env::args()
            .skip(1)
            .filter(|a| a.starts_with('-') || a.starts_with('/'))
            .filter(|a| {
                !["--open", "--quit"]
                    .iter()
                    .any(|k| a.eq_ignore_ascii_case(k))
            })
            .collect();
        if !unknown.is_empty() {
            // Exit silently, including for --version/--help. This is a
            // GUI-subsystem binary with no console to print to, and the
            // obvious alternative - a message box - would block forever
            // whenever there is no desktop to show it on: a silent
            // installer, a scheduled task, a remote shell. Hanging an
            // unattended caller is the failure this whole check exists
            // to prevent, so it must not be reintroduced here.
            return;
        }

        // --open: always end by opening the dashboard, first run or not.
        // The installer passes it so setup finishes with the user looking
        // at the web UI (a reinstall/upgrade box isn't a "first run", so
        // the prefs-file heuristic alone would stay silent there).
        let open_ui = std::env::args_os()
            .skip(1)
            .any(|a| a.eq_ignore_ascii_case("--open"));
        let args: Vec<PathBuf> = std::env::args_os()
            .skip(1)
            .map(PathBuf::from)
            .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("nzb")) && p.exists())
            .collect();
        // nzblnk: links, from the URL-scheme association the installer
        // writes. They cannot ride `args`: that filter demands a .nzb
        // extension AND that the path exists on disk, and a link is
        // neither a file nor a path. They survive the unknown-flag guard
        // above only because a link starts with neither `-` nor `/`.
        //
        // A scheme TEST, not a parse. The daemon owns the only NZBLNK
        // parser (nzbkit::nzblnk) and the tray deliberately does not
        // depend on nzbkit - pulling the engine crate in for a prefix
        // check would drag rusqlite and tokio into a tray that ships
        // with plain-HTTP ureq and nothing else. This is strictly
        // narrower than the daemon's own `looks_like`, which also peels
        // wrapping quotes and brackets; argv from the registry's "%1"
        // never has them. Narrower is the safe direction.
        let links: Vec<String> = std::env::args()
            .skip(1)
            .filter(|a| a.len() >= 7 && a.as_bytes()[..7].eq_ignore_ascii_case(b"nzblnk:"))
            .collect();

        let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
        let data_dir = PathBuf::from(local).join("nzbfast");

        // --quit: stop a running stack and exit. Handled before the
        // single-instance mutex, or we would take the "already running"
        // branch and open the dashboard instead of closing it. Creates
        // nothing on disk: an uninstall must not resurrect the data dir.
        if std::env::args_os()
            .skip(1)
            .any(|a| a.eq_ignore_ascii_case("--quit"))
        {
            quit_running_instance(&data_dir);
            return;
        }
        // Finished downloads land inside the user's Downloads folder.
        // Pre-1.0.2 installs used Downloads\nzbfast - keep that when it
        // already exists so an upgrade doesn't split the library.
        let dl = downloads_dir();
        let legacy = dl.join("nzbfast");
        let out_dir = if legacy.is_dir() {
            legacy
        } else {
            dl.join("nzbfast downloads")
        };
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."));
        let first_run = !prefs_path(&data_dir).exists();
        for d in [&data_dir, &out_dir] {
            let _ = std::fs::create_dir_all(d);
        }

        // Single instance: second launches hand their .nzb (or a dashboard
        // request) to the running stack and exit.
        // SAFETY: FFI calls; the mutex name is NUL-terminated UTF-16 from
        // `w` whose buffer outlives the call, and a null
        // security-attributes pointer is documented as valid.
        unsafe {
            CreateMutexW(
                std::ptr::null(),
                0,
                w("Local\\nzbfast-tray-single").as_ptr(),
            );
            if GetLastError() == ERROR_ALREADY_EXISTS {
                let port = crate::probe_body::load_port(&data_dir).unwrap_or(BASE_PORT);
                // The identity proof is per-PROCESS and this is a fresh
                // process: the tray holding the mutex proved the daemon
                // at its own startup, but that proof lives over there.
                // Each hand-off below establishes its own through
                // `proof()`, which probes on demand - v1.0.22 shipped a
                // latch this branch had to arm by hand, did not, and
                // every file-association add went keyless into the 403
                // dialog. An impostor on the port still fails the
                // challenge and still gets no key.
                if args.is_empty() && links.is_empty() {
                    open_url(&dash_url(
                        port,
                        tls_for(port, &data_dir),
                        &data_dir,
                        proof(port, &data_dir),
                    ));
                } else {
                    for p in &args {
                        if let Err(e) = post_nzb(port, &data_dir, p) {
                            message_box(
                                &format!("Couldn't queue {}:\n{e}", p.display()),
                                MB_ICONERROR,
                            );
                        }
                    }
                    for l in &links {
                        if let Err(e) = post_nzblnk(port, &data_dir, l) {
                            message_box(&format!("Couldn't add that link:\n{e}"), MB_ICONERROR);
                        }
                    }
                }
                return;
            }
        }

        let (port, child) = ensure_daemon(&exe_dir, &data_dir, &out_dir);
        save_port(&data_dir, port);

        // Hidden message window + tray icon.
        // SAFETY: FFI calls; cls and the title are NUL-terminated UTF-16
        // from `w` whose buffers outlive the RegisterClassW and
        // CreateWindowExW calls that read them, &wc points at a live
        // local, null handles/pointers are used only where documented as
        // valid, and HWND_MESSAGE is the documented message-only parent.
        let hwnd = unsafe {
            let hinst = GetModuleHandleW(std::ptr::null());
            let cls = w(MSG_CLASS);
            let wc = WNDCLASSW {
                style: 0,
                lpfnWndProc: Some(wndproc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: hinst,
                hIcon: std::ptr::null_mut(),
                hCursor: std::ptr::null_mut(),
                hbrBackground: std::ptr::null_mut(),
                lpszMenuName: std::ptr::null(),
                lpszClassName: cls.as_ptr(),
            };
            RegisterClassW(&wc);
            CreateWindowExW(
                0,
                cls.as_ptr(),
                w(MSG_TITLE).as_ptr(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                std::ptr::null_mut(),
                hinst,
                std::ptr::null(),
            )
        };

        APP.with(|a| {
            *a.borrow_mut() = Some(App {
                port,
                owner: child.is_some(),
                child,
                child_dead: false,
                paused: false,
                tip_at: None,
                data_dir: data_dir.clone(),
                out_dir,
                exe_dir,
            })
        });
        tray_add(hwnd);
        // SAFETY: FFI call carrying only handles and integers; a None
        // timer proc is documented as valid (WM_TIMER is posted to the
        // window instead).
        unsafe { SetTimer(hwnd, TIMER_CHILD, 1000, None) };

        // File-association / drag-onto-exe path: queue, then say so.
        for p in &args {
            match post_nzb(port, &data_dir, p) {
                Ok(name) => balloon(hwnd, "nzbfast", &format!("Queued {name}")),
                Err(e) => {
                    message_box(
                        &format!("Couldn't queue {}:\n{e}", p.display()),
                        MB_ICONERROR,
                    );
                }
            }
        }
        // Same, for a link clicked while nothing was running yet.
        for l in &links {
            match post_nzblnk(port, &data_dir, l) {
                Ok(name) => balloon(hwnd, "nzbfast", &format!("Queued {name}")),
                Err(e) => {
                    message_box(&format!("Couldn't add that link:\n{e}"), MB_ICONERROR);
                }
            }
        }
        // First run ever (or --open from the installer): open the
        // dashboard so the welcome banner (add your Usenet server) is
        // actually seen. ensure_daemon has already confirmed the daemon
        // answers on this port, so the page can't land on a dead socket.
        if first_run || open_ui {
            open_url(&dash_url(
                port,
                tls_for(port, &data_dir),
                &data_dir,
                proof(port, &data_dir),
            ));
        }
        // ...and say where it went. The window that just opened is an
        // ordinary browser tab, so a user who closes it has no reason to
        // think the download engine is still there, or that the tray
        // icon is the way back to it. Only on a genuine first run: an
        // upgrade takes the `--open` arm above and has been told this
        // once already.
        if first_run {
            balloon(
                hwnd,
                "nzbfast is in your tray",
                "It keeps running here after you close the page. Double-click the tray icon \
                 to open the dashboard again, or bookmark it in your browser - it is an \
                 ordinary web page. Hover the icon for the current speed.",
            );
        }

        // SAFETY: MSG is windows-sys's #[repr(C)] mirror of the
        // documented OS struct, for which the all-zero bit pattern is a
        // valid value, and &mut msg passed to the loop calls points at
        // that live local.
        unsafe {
            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}
