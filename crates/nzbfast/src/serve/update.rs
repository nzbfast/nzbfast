//! The update checker: manifest fetch, ed25519 signature verification,
//! the anti-rollback serial ratchet, and the install-shape probes that
//! decide whether an update may be offered at all.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// Where the update checker looks for the release manifest. GitHub's
/// /releases/latest/download/ path always serves the newest release's
/// signed manifest over its CDN, no auth. The manifest is ed25519-signed
/// and hard-verified against the baked-in key, so the origin is untrusted
/// anyway - controlling it (or a MITM) cannot forge an update. Overridable
/// via the live update_url setting; unreachable = silently up to date.
pub(super) const DEFAULT_UPDATE_URL: &str =
    "https://github.com/nzbfast/nzbfast/releases/latest/download/latest.json";

/// ed25519 public key that every accepted update manifest must be signed
/// with. The private half is held offline by the release manager and never
/// touches the repo, a build server, or the update origin - so controlling
/// the update origin (the GitHub account, or a MITM position) is
/// NOT enough to push code: an attacker would also need the offline signing
/// key. sha256 in the manifest only proves the payload matches the manifest;
/// this proves the manifest itself is ours. Rotate by generating a new pair
/// (examples/update_sign.rs `keygen`) and shipping a build with the new key
/// BEFORE signing the next release with the new private key.
pub(super) const UPDATE_PUBKEY_HEX: &str =
    "863349474b98569e9a00d06ad3a7385f564b76aed97a7ff60fca713b9c4731ba";

/// Verify a detached ed25519 signature (hex, 64 bytes) over the exact
/// manifest bytes using [`UPDATE_PUBKEY_HEX`]. Any failure - unparseable
/// key, bad signature length, or a signature that does not verify - is a
/// hard refusal: an unsigned or wrongly-signed manifest is treated as
/// hostile, never as "up to date".
pub(super) fn verify_manifest_sig(manifest: &[u8], sig_hex: &[u8]) -> Result<(), String> {
    verify_with_key(UPDATE_PUBKEY_HEX, manifest, sig_hex)
}

/// Signature check against an explicit hex public key. Split out from
/// [`verify_manifest_sig`] so tests can exercise the exact verification
/// path with an ephemeral key, without needing the production private key.
pub(super) fn verify_with_key(
    pubkey_hex: &str,
    manifest: &[u8],
    sig_hex: &[u8],
) -> Result<(), String> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let key_raw: [u8; 32] = hex::decode(pubkey_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("update key is malformed")?;
    let vk = VerifyingKey::from_bytes(&key_raw).map_err(|e| format!("update key: {e}"))?;
    let sig_txt = std::str::from_utf8(sig_hex).map_err(|_| "signature file is not text")?;
    let sig_raw: [u8; 64] = hex::decode(sig_txt.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("signature is not 64 hex-encoded bytes")?;
    let sig = Signature::from_bytes(&sig_raw);
    vk.verify_strict(manifest, &sig)
        .map_err(|_| "manifest signature does not verify - refusing update".to_string())
}

/// Dotted-numeric version compare: is `remote` newer than `local`?
/// Non-numeric fragments compare as 0 ("4.6.0-beta" == "4.6.0").
pub(super) fn version_newer(remote: &str, local: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.trim_start_matches(['v', 'V'])
            .split(['.', '-'])
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (r, l) = (parse(remote), parse(local));
    for i in 0..r.len().max(l.len()) {
        let (a, b) = (
            r.get(i).copied().unwrap_or(0),
            l.get(i).copied().unwrap_or(0),
        );
        if a != b {
            return a > b;
        }
    }
    false
}

/// GET a small update-channel resource (manifest or its signature) into
/// memory. Capped at 1 MiB - both are tiny; a huge body is a sign the URL
/// is wrong, not a real manifest.
pub(super) fn fetch_update_resource(url: &str) -> std::result::Result<Vec<u8>, String> {
    // GitHub's stable manifest URL (/releases/latest/download/...)
    // redirects TWICE - repo → tagged asset → CDN. Without an explicit
    // redirect budget the chain isn't followed to the end and the body
    // arrives empty ("expected value at line 1 column 1").
    // Through the SSRF guard like every other outbound fetch. `update_url` is
    // an operator-settable value (and settable by anyone at all on a keyless
    // install), and this was the one fetch path that dialled a raw agent - so
    // it reached exactly the cloud-metadata and link-local addresses
    // `is_forbidden_fetch_ip` exists to block, on a 6-hourly repeating loop,
    // and returned the transport error verbatim as a reachability oracle.
    let resp = ssrf_safe_agent(10, 15)
        .get(url)
        .call()
        .map_err(|e| format!("{e}"))?;
    use std::io::Read as _;
    let mut body = Vec::new();
    resp.into_reader()
        .take(1024 * 1024)
        .read_to_end(&mut body)
        .map_err(|e| format!("read: {e}"))?;
    Ok(body)
}

/// Fetch a manifest AND its detached `.sig`, verify the signature against
/// the embedded key, and only then parse the JSON. An unreachable manifest
/// surfaces as a distinct error so the caller can stay quiet about it
/// (default channel, no site yet); a manifest that is present but unsigned
/// or wrongly signed is a LOUD refusal - that is the attack we care about.
pub(super) fn fetch_manifest(url: &str) -> std::result::Result<Value, String> {
    let body = fetch_update_resource(url).map_err(|e| format!("update check: {e}"))?;
    let sig_url = sig_url_for(url);
    let sig = fetch_update_resource(&sig_url)
        .map_err(|e| format!("update manifest is unsigned (no {sig_url}: {e}) - refusing"))?;
    verify_manifest_sig(&body, &sig)?;
    serde_json::from_slice(&body).map_err(|e| format!("update manifest: {e}"))
}

/// The detached signature's URL: `.sig` appended to the manifest's PATH,
/// not to the string. A bare `format!("{url}.sig")` turned
/// `latest.json?token=abc` into `latest.json?token=abc.sig` - same path,
/// mutated query - so a custom mirror behind a token or presigned URL
/// fetched its manifest fine and then failed closed as "unsigned",
/// forever and quietly (Codex sweep 24 Aug, F-21). The default GitHub
/// URL has no query and never hit it. String surgery rather than a URL
/// parser: the setter already pins the scheme, and the first `?` or `#`
/// is where a path ends in any http(s) URL.
fn sig_url_for(url: &str) -> String {
    match url.find(['?', '#']) {
        Some(i) => format!("{}.sig{}", &url[..i], &url[i..]),
        None => format!("{url}.sig"),
    }
}

/// Record the `serial` of a signature-verified manifest, advancing the
/// local anti-rollback ratchet.
///
/// The attack this exists for: an attacker who can serve stale bytes -
/// a MITM, a cache, a hostile mirror, a stuck CDN edge - replays an OLD
/// but genuinely-signed manifest. Every signature checks out, because it
/// really was ours. Version comparison alone does not catch it either:
/// the client simply never learns a newer release exists and sits on a
/// version with known bugs indefinitely. The defence is a value inside
/// the SIGNED body that only ever goes up, plus the highest one seen
/// kept locally, so a replayed manifest is recognisable as older than
/// something this machine has already been told about.
///
/// Deliberately clock-free. The serial is compared only against our own
/// stored value, never against the local time, so a machine with a wrong
/// clock cannot lock itself out of updates - which is why this is a
/// serial and not a `not_before`.
///
/// **This build does not refuse anything.** It records, and it warns on a
/// regression so we can see in the field whether serials are actually
/// monotonic before any release depends on it. See `update_serial_seen`.
pub(super) fn note_manifest_serial(d: &Arc<Daemon>, m: &Value) {
    use std::sync::atomic::Ordering;
    let seen = d.update_serial_seen.load(Ordering::Relaxed);
    match serial_ratchet(seen, m) {
        SerialStep::Advance(serial) => {
            d.update_serial_seen.store(serial, Ordering::Relaxed);
            save_setting(&d.settings_path, "update_serial_seen", json!(serial));
        }
        SerialStep::Regressed { got, seen } => warn!(
            target: "update",
            "manifest serial {got} is older than {seen}, already seen from this \
             channel - a stale or replayed manifest. NOT refused: this build only records \
             serials, it does not enforce them yet."
        ),
        SerialStep::Hold => {}
    }
}

/// What a manifest's serial should do to the stored ratchet value. Split
/// out from [`note_manifest_serial`] so the decision can be tested without
/// building a whole `Daemon`, the same way [`verify_with_key`] is.
#[derive(Debug, PartialEq)]
pub(super) enum SerialStep {
    /// Higher than anything seen: store and persist it.
    Advance(u64),
    /// Lower than what we have seen. The replay signal - reported, and in
    /// this build nothing more than reported.
    Regressed { got: u64, seen: u64 },
    /// Unchanged, absent, or unusable: leave the stored value alone.
    Hold,
}

pub(super) fn serial_ratchet(seen: u64, m: &Value) -> SerialStep {
    // A missing serial means a manifest predating the serial rollout, which
    // is normal during it. Crucially it must HOLD rather than clear: if an
    // absent serial reset the ratchet, replaying a pre-serial manifest would
    // become the way to disarm this defence and re-open rollback.
    //
    // `as_u64` also does the validation - a string "999999", a float, or a
    // negative number all yield None and hold. That matters in the other
    // direction too: coercing junk into a huge serial would pin an install
    // above every real release it will ever be offered.
    let Some(serial) = m.get("serial").and_then(Value::as_u64) else {
        return SerialStep::Hold;
    };
    if serial < seen {
        SerialStep::Regressed { got: serial, seen }
    } else if serial == seen {
        SerialStep::Hold // steady state: same manifest as last check, no write
    } else {
        SerialStep::Advance(serial)
    }
}

pub(super) fn check_update(d: &Arc<Daemon>) -> std::result::Result<Option<Value>, String> {
    let url = d.update_url.lock_ok().clone();
    if url.is_empty() {
        return Ok(None);
    }
    let m: Value = fetch_manifest(&url)?;
    // Before the version comparison, and on EVERY verified manifest rather
    // than only on ones advertising an upgrade: the steady-state manifest
    // (same version as ours) is what establishes the ratchet floor, and it
    // is the one a replay attack has to beat.
    note_manifest_serial(d, &m);
    let remote = m
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let newer = !remote.is_empty() && version_newer(&remote, env!("CARGO_PKG_VERSION"));
    latch_update_manifest(d, if newer { Some(m.clone()) } else { None });
    Ok(if newer { Some(m) } else { None })
}

/// Latch the manifest the banner reads, and let open dashboards see it.
///
/// The banner rides the REVISIONED queue payload, which an idle
/// dashboard skips while its revision matches. Latching a change
/// without bumping the revision left every open page blind to it until
/// an unrelated queue mutation moved the number - a manual Settings ->
/// Check said "see the banner up top" and the banner stayed empty
/// (Gary, 14 Aug). Bump only on a CHANGE of the visible version: the
/// 6 h steady-state re-check must not invalidate the queue for nothing.
pub(super) fn latch_update_manifest(d: &Arc<Daemon>, latched: Option<Value>) {
    let ver = |v: &Option<Value>| {
        v.as_ref()
            .and_then(|m| m.get("version").and_then(Value::as_str).map(str::to_string))
    };
    let mut g = d.update_manifest.lock_ok();
    let changed = ver(&g) != ver(&latched);
    *g = latched;
    drop(g);
    if changed {
        d.queue_rev
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Where the update banner sends users. Hard-coded on purpose: the
/// manifest supplies only a version string, never a link, so a
/// compromised update channel cannot redirect anyone. Self-update was
/// removed in 1.0.5 (notify-only) - there is no code that downloads or
/// replaces the running binary.
pub(super) const DOWNLOAD_URL: &str = "https://github.com/nzbfast/nzbfast/releases/latest";

/// True when a native wrapper (Mac .app / Windows installer) owns this
/// binary: it sets NZBFAST_BUNDLED=1 at spawn.
pub(super) fn bundled_install() -> bool {
    std::env::var("NZBFAST_BUNDLED").is_ok_and(|v| v == "1")
}

/// True when we are running inside a container image.
///
/// Deliberately NOT `bundled_install()`: the Mac .app and the Windows
/// tray set NZBFAST_BUNDLED=1 too, and telling a Mac user to open
/// Container Manager would be nonsense. The runtime's own marker files
/// are the signal, and they are the only one that works for the images
/// already in the field - an env var we add to the entrypoint today only
/// exists after the update it is meant to explain how to install.
/// Cached: the answer cannot change while the process runs, and this is
/// read on every queue poll (once a second per open dashboard).
pub(super) fn container_install() -> bool {
    static IN_CONTAINER: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *IN_CONTAINER.get_or_init(|| {
        std::path::Path::new("/.dockerenv").exists()              // Docker
            || std::path::Path::new("/run/.containerenv").exists() // Podman
            // Escape hatch for runtimes that drop neither marker file,
            // and the only way to exercise the container UI off a NAS.
            || std::env::var("NZBFAST_CONTAINER").is_ok_and(|v| v == "1")
    })
}

/// True when this process is running inside a Flatpak sandbox.
///
/// Deliberately NOT folded into [`container_install`], even though both
/// mean "this install cannot replace its own binary". The container
/// recipe the dashboard shows is Docker-specific - compose files,
/// Watchtower, the Synology Container Manager - and every word of it is
/// wrong advice inside a Flatpak, where the update channel is
/// `flatpak update` and the user may never have seen a container. Two
/// flags, two recipes; the dashboard picks the one that applies.
///
/// `/.flatpak-info` is the canonical marker: flatpak-run mounts it into
/// every sandbox it starts, and nothing outside a sandbox has it.
/// `FLATPAK_ID` is checked as well because a `flatpak-spawn --host`
/// child inherits the variable without the mount, and such a child is
/// still an install whose binary comes from the Flatpak.
pub(super) fn flatpak_install() -> bool {
    static IN_FLATPAK: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *IN_FLATPAK.get_or_init(|| {
        std::path::Path::new("/.flatpak-info").exists() || std::env::var_os("FLATPAK_ID").is_some()
    })
}

/// True when the LAUNCHER owns the listening port and the dashboard must
/// not move it.
///
/// A saved `port` otherwise beats the `--port` flag on every later start,
/// which is right for a desktop or a plain CLI install and wrong
/// everywhere the port is baked in somewhere we cannot reach:
///
/// - a container publishes `6789:6789` and healthchecks that port, so an
///   internal move makes the service unreachable AND unhealthy;
/// - the Synology package bakes `adminport` at install time, so a move
///   takes the listener away from DSM's own Open button;
/// - a fixed system service or firewall rule has the same shape.
///
/// Detected from the environment rather than inferred from
/// `container_install()`: an operator running the image with
/// `--network host` and no published mapping legitimately owns their own
/// port, and the entrypoint knows which case it is. The images and the
/// SPK set it; nothing else does.
pub(super) fn port_locked() -> bool {
    static LOCKED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *LOCKED.get_or_init(|| std::env::var("NZBFAST_PORT_LOCKED").is_ok_and(|v| v == "1"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>)) {
        let dir = std::env::temp_dir().join(format!("nzbfast-upd-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = super::super::testutil::test_daemon(&dir);
        f(&d);
        drop(d);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The banner rides the revisioned queue payload: a manifest change
    /// must bump the queue revision or an idle open dashboard never
    /// hears about it, and a steady-state re-check must NOT bump it.
    #[test]
    fn a_manifest_change_bumps_the_queue_revision_and_steady_state_does_not() {
        with_daemon("latch", |d| {
            let m = serde_json::json!({"version": "9.9.9"});
            let rev = d.queue_rev.load(Ordering::Relaxed);
            latch_update_manifest(d, Some(m.clone()));
            let rev = {
                let now = d.queue_rev.load(Ordering::Relaxed);
                assert_ne!(now, rev, "a new version must invalidate the queue payload");
                now
            };
            // Same version again: the 6 h re-check steady state.
            latch_update_manifest(d, Some(m));
            assert_eq!(
                d.queue_rev.load(Ordering::Relaxed),
                rev,
                "an unchanged manifest must not churn the revision"
            );
            // The release caught up with us: banner comes down, rev moves.
            latch_update_manifest(d, None);
            assert_ne!(d.queue_rev.load(Ordering::Relaxed), rev);
            // And staying up to date is quiet too.
            let rev = d.queue_rev.load(Ordering::Relaxed);
            latch_update_manifest(d, None);
            assert_eq!(d.queue_rev.load(Ordering::Relaxed), rev);
        });
    }

    /// `.sig` lands on the PATH, with the query and fragment kept where
    /// they were - a token-bearing mirror URL must not have its token
    /// mutated into `abc.sig` (Codex sweep 24 Aug, F-21).
    #[test]
    fn the_sig_url_keeps_the_query_intact() {
        assert_eq!(
            sig_url_for("https://mirror/latest.json?token=abc"),
            "https://mirror/latest.json.sig?token=abc"
        );
        assert_eq!(
            sig_url_for("https://mirror/latest.json#frag"),
            "https://mirror/latest.json.sig#frag"
        );
        assert_eq!(
            sig_url_for("https://mirror/latest.json?a=1#frag"),
            "https://mirror/latest.json.sig?a=1#frag"
        );
        // The default URL's shape is unchanged.
        assert_eq!(
            sig_url_for(DEFAULT_UPDATE_URL),
            format!("{DEFAULT_UPDATE_URL}.sig")
        );
        // Percent-encoded paths pass through untouched.
        assert_eq!(
            sig_url_for("https://m/p%20a/latest.json?t=x%3Fy"),
            "https://m/p%20a/latest.json.sig?t=x%3Fy"
        );
    }
}
