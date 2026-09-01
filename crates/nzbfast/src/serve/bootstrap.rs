//! First-run bootstrap and the settings file that survives it: where
//! settings.json lives, how it is read and written, the API key mint and
//! its keyless-install refusal, the runtime file and launcher proof, and
//! the overlay of saved settings onto the launch flags.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// Settings keys the `nzbfast setup` wizard writes BEFORE the daemon has
/// ever run - it is a separate process, so its answers land in
/// settings.json ahead of first start.
///
/// They must not read as "an existing install" to the first-run API key
/// test: a user who answered "index sport" in the wizard would otherwise
/// get an unkeyed daemon, which is the exact hole that test exists to
/// close.
pub(super) const SETUP_ANSWER_KEYS: &[&str] = &["index_interests"];

/// Does settings.json hold anything beyond the wizard's own answers?
///
/// Only a file that is NOTHING BUT wizard answers reads as a first run.
/// A missing file is not this function's case (the caller's `exists`
/// test covers it), and an EMPTY object is deliberately "existing": it
/// carries no wizard answer to explain itself, so the old rule - the
/// file exists, therefore the install has run - is the safe reading.
/// Anything unparseable is existing too: never mint a key over a state
/// file we cannot read.
pub(super) fn settings_beyond_setup_answers(path: &std::path::Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(map)) => {
            map.is_empty() || map.keys().any(|k| !SETUP_ANSWER_KEYS.contains(&k.as_str()))
        }
        Ok(_) => true,
        Err(_) => true,
    }
}

/// Dashboard-saved settings live in `settings.json` next to the server
/// config (config.local.json). Flat {key: value} map holding ONLY keys
/// the user changed in the UI; on launch those override the matching CLI
/// flags, so a UI change survives restarts without touching launch
/// scripts. Delete the file (or a key) to fall back to the flags.
pub(super) fn settings_file(config: &std::path::Path) -> PathBuf {
    config.with_file_name("settings.json")
}

/// The two rename-punctuation toggles replaced hard-coded ON behavior.
/// Fresh installs ship them OFF, but an upgrade with no saved key must
/// retain the old shape: history cleanup recomputes a filed episode's
/// suffix, and silently changing it would orphan every pre-upgrade
/// bracketed file. Wizard-only settings are still a fresh install.
pub(super) fn legacy_rename_punctuation(
    config: &std::path::Path,
    out_root: &std::path::Path,
    settings: &std::path::Path,
) -> bool {
    settings_beyond_setup_answers(settings)
        || config.with_file_name(".spool").exists()
        || out_root.join(".spool").exists()
}

/// Where daemon state lives: queue + history, the usage ledger, watchlist
/// memory, RSS seen-ids, benchmark history, the poster-art cache and a
/// copy of each job's NZB.
///
/// Beside the config, NOT under the download directory. It used to be
/// `<downloads>/.spool`, sitting among finished downloads where it reads
/// as leftover clutter - and a leading dot hides nothing on Windows - so
/// users tidying up watched files deleted the daemon's entire state.
/// Tying it to the config also stops it being stranded when the download
/// directory is repointed from the dashboard.
///
/// What is at the new spool path, as the three answers `spool_dir` has
/// to tell apart. Its own function so the classification can be pinned
/// directly: it is the whole of the 31 Aug 2026 rename-occupancy
/// decision for this file, and driving it through `spool_dir` cannot
/// separate `Absent` from `Unusable` - both end up returning `old`, one
/// by declining and one by attempting a migration that fails.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NewSpool {
    /// A readable directory with something in it: a completed migration.
    Live,
    /// A readable EMPTY directory: a placeholder, not a migration.
    Placeholder,
    /// No entry at all: the ordinary pre-migration state.
    Absent,
    /// An entry that is not a directory this process can read.
    Unusable,
}

/// Classify `new`, by whether `read_dir` can actually READ it.
///
/// `read_dir` is what decides, and that is the point rather than an
/// implementation detail. The obvious spelling - classify by whether the
/// path exists - is what the census found wrong, and the obvious FIX is
/// wrong too. `Path::exists` follows symlinks and answers false on any
/// error, so a `.spool` symlinked onto a volume that is not mounted came
/// out `Absent` and a link resolving to a FILE came out occupied; but
/// asking `symlink_metadata` outright makes the first one occupied as
/// well, which sends the user's live queue at `old` off to
/// `legacy-spool/` inside a path nothing can create, logs it as "unused;
/// safe to delete", and hands the daemon a spool it cannot write. Only a
/// directory this process can read is a spool. `symlink_metadata` is
/// used for ONE thing here: separating "no entry at all", which migrates,
/// from "an entry we do not understand", which declines.
pub(super) fn new_spool_state(new: &std::path::Path) -> NewSpool {
    match std::fs::read_dir(new) {
        Ok(mut rd) => match rd.next() {
            Some(_) => NewSpool::Live,
            None => NewSpool::Placeholder,
        },
        Err(_) if std::fs::symlink_metadata(new).is_ok() => NewSpool::Unusable,
        Err(_) => NewSpool::Absent,
    }
}

/// An existing spool migrates once, on the first launch after the move.
/// Config and downloads are routinely on different filesystems - separate
/// volume mounts are the norm under Docker - so this cannot be a rename.
///
/// It is staged instead: copy the whole old spool to a sibling of the new
/// location, fsync it, then ONE atomic rename publishes it, and only then is
/// the old directory removed. Nothing touches the old spool until the new one
/// is complete.
///
/// It used to `move_tree`, which deletes each file as soon as its copy is
/// durable. A failure partway (ENOSPC, EIO, permissions) therefore left
/// `queue.json` at the new location and the rest at the old one, and this
/// function then returned the OLD path - where the queue was now missing, so
/// the daemon started empty and saved an empty queue over it. The next
/// restart saw a non-empty new directory, switched to it, and resurrected the
/// stale queue that had been copied before the failure. Both restarts were
/// self-consistent and both were wrong.
///
/// That is also why a populated `new` is trustworthy as "already
/// migrated": the new path only ever appears via the final rename, so it
/// cannot be a half-copy. An EMPTY `new` is one exception and is not a
/// migration at all; an entry at `new` that is not a readable directory
/// is the other, and declines. Both are classified in the body.
///
/// The `old.exists()` at the top is deliberately NOT the entry question
/// the body asks: it tests a SOURCE, and "there is a leftover spool to
/// migrate" is exactly a question about whether the path resolves to
/// something this daemon can read. A link there that dangles has no
/// state to move, and doing nothing is the right answer to it.
pub(super) fn spool_dir(config: &std::path::Path, out_root: &std::path::Path) -> PathBuf {
    let new = config.with_file_name(".spool");
    let old = out_root.join(".spool");
    if old == new || !old.exists() {
        return new;
    }
    // An empty `new` is a placeholder, not a migration: something created
    // the directory without any state in it (a packaging step, a first run
    // interrupted between mkdir and the first save), and returning it would
    // start the daemon on an empty queue while the real one sat in `old`.
    // `remove_dir` refuses a non-empty directory, so this can only ever drop
    // an empty one, and the migration below then runs as it should.
    // Decide by what the directory CONTAINS, not by whether it can be
    // removed. `remove_dir` also fails on EACCES/EPERM, and on Windows for
    // an empty directory someone still holds a handle to - and reading that
    // failure as "a real migrated spool" is not a harmless mistake: it sends
    // the user's actual queue at `old` off to legacy-spool/ and starts the
    // daemon on the empty `new`, which then SAVES that empty queue over it.
    // An unreadable `new` is treated as occupied, which is the safe way to
    // be wrong: it declines to migrate rather than moving live state aside.
    //
    // THAT LAST SENTENCE WAS THE INTENT AND NOT THE CODE, until the 31 Aug
    // 2026 rename-occupancy census. `read_dir` failing was classified with
    // `new.exists()`, which FOLLOWS symlinks and answers false on ANY
    // error, so the two states it has to separate both came out wrong. A
    // `.spool` symlinked onto a volume that is not mounted read as ABSENT
    // and fell into the migration, where the publishing rename answers
    // ENOTDIR (a directory onto a symlink, MEASURED on APFS 31 Aug 2026)
    // and the run ends in "could not move daemon state". A `.spool` link
    // that resolves to a FILE, or a directory `read_dir` cannot open, read
    // as OCCUPIED and took the branch below: the user's live queue at `old`
    // was retired into a path nothing can create, and the log then called
    // it "unused; safe to delete" while the daemon ran on a spool path that
    // cannot hold anything. That is the exact failure this comment already
    // named, reached from the other side.
    //
    // So the classification is three-way and `read_dir` is what decides it.
    // Only a directory this process can actually read is a spool; an entry
    // that is anything else is neither absent nor migrated, and the answer
    // the comment above asks for is to decline - keep running on `old`,
    // retire nothing, move nothing.
    match new_spool_state(&new) {
        NewSpool::Live => {
            // A real, migrated spool. Whatever is still at `old` is the
            // residue of that move, and it is sitting in the user's
            // download folder.
            retire_legacy_spool(&old, &new);
            return new;
        }
        NewSpool::Unusable => {
            warn!(
                target: "spool",
                "{} is not a directory this daemon can read, so the daemon \
                 state in the download folder is left exactly where it is \
                 and {} keeps being used (nothing was moved or retired)",
                new.display(),
                old.display()
            );
            return old;
        }
        // Empty placeholder: drop it so the migration below can publish
        // into its place. A failure here is not fatal - the rename simply
        // lands on an existing empty directory, or the migration declines.
        NewSpool::Placeholder => {
            let _ = std::fs::remove_dir(&new);
        }
        NewSpool::Absent => {}
    }
    // Beside `new`, so the publishing rename is same-filesystem and atomic.
    let staging = config.with_file_name(".spool.migrating");
    let _ = std::fs::remove_dir_all(&staging); // abandoned by an earlier crash
    let staged = crate::smart::copy_tree(&old, &staging)
        .and_then(|()| std::fs::rename(&staging, &new))
        .and_then(|()| {
            // Persist the new directory entry before we delete the source.
            crate::smart::sync_dir(new.parent().unwrap_or(&new))
        });
    match staged {
        Ok(()) => {
            let _ = std::fs::remove_dir_all(&old);
            info!(
                target: "spool",
                "moved daemon state out of the download directory: {} → {}",
                old.display(),
                new.display()
            );
            new
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            warn!(
                target: "spool",
                "could not move daemon state to {} ({e}) - continuing to use {} \
                 (unchanged; the move will be retried next start)",
                new.display(),
                old.display()
            );
            old
        }
    }
}

/// Clear away a `<downloads>/.spool` that outlived the move to the data dir.
///
/// `spool_dir` used to return the moment the new location existed, which is
/// right for the LIVE path and wrong for the old directory. Two ways it
/// survives the migration: the first version of that migration deleted each
/// file as it copied, so any failure partway left the remainder behind; and
/// even the staged version's closing `remove_dir_all` is best-effort, which
/// on Windows one open handle (a scanner, an Explorer preview) is enough to
/// defeat. Either way the leftover then sat in the user's own download
/// folder forever, and un-hidden - only the path `spool_dir` RETURNS is ever
/// passed to `hide_from_user` - reading exactly like junk we forgot to clean
/// up. It is the residue, not the state: this is a tester report, not a
/// theory.
///
/// It is dead by definition here (`new` exists and is non-empty, so the
/// daemon has been running off it, and every file below is a stale copy of
/// something already migrated). It is still not deleted. It moves inside the
/// live spool as `legacy-spool/`, out of the download folder but recoverable,
/// and the log says where it went and that it can be deleted. One volume - the
/// usual case, `%LOCALAPPDATA%` and `Downloads` both on C: - makes that a free
/// rename; only a genuinely separate downloads volume pays for a copy.
pub(super) fn retire_legacy_spool(old: &std::path::Path, new: &std::path::Path) {
    // First, and regardless of everything below: a leftover we fail to move
    // should at least stop being visible on Windows, where the leading dot
    // means nothing. Cheap, and it covers every failure path at once.
    nzbkit::disk::hide_from_user(old);
    let Some(dest) = free_legacy_spool_path(new) else {
        return;
    };
    let moved = std::fs::rename(old, &dest).is_ok()
        || match crate::smart::copy_tree(old, &dest) {
            // Separate volumes. The source goes only once the copy is whole.
            Ok(()) => std::fs::remove_dir_all(old).is_ok(),
            Err(e) => {
                // Leave nothing half-copied claiming to be the retired state.
                let _ = std::fs::remove_dir_all(&dest);
                warn!(
                    target: "spool",
                    "leftover daemon state at {} could not be retired ({e}); \
                     it is unused and safe to delete",
                    old.display()
                );
                false
            }
        };
    if moved {
        info!(
            target: "spool",
            "retired leftover daemon state from the download folder: {} → {} \
             (unused; safe to delete)",
            old.display(),
            dest.display()
        );
    }
}

/// A free `legacy-spool` name inside the live spool. Suffixed rather than
/// merged, because two leftovers are two separate installs' residue and
/// mixing them would produce a directory that never existed.
pub(super) fn free_legacy_spool_path(new: &std::path::Path) -> Option<PathBuf> {
    (0..100u32).find_map(|n| {
        let p = match n {
            0 => new.join("legacy-spool"),
            n => new.join(format!("legacy-spool-{n}")),
        };
        (!p.exists()).then_some(p)
    })
}

/// Fresh random hex secret without a rand dependency: RandomState is
/// OS-entropy-seeded, and the sha256 mix of several instances plus
/// pid/time is plenty for a stream-URL capability secret.
pub(super) fn fresh_secret() -> String {
    use sha2::Digest as _;
    use std::hash::{BuildHasher as _, Hasher as _};
    let mut h = sha2::Sha256::new();
    for i in 0u64..4 {
        let mut hs = std::collections::hash_map::RandomState::new().build_hasher();
        hs.write_u64(i);
        h.update(hs.finish().to_le_bytes());
    }
    h.update(std::process::id().to_le_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    h.update(now.as_nanos().to_le_bytes());
    hex::encode(h.finalize())[..32].to_string()
}

/// M29: JSON verdict for one release - "ok"/"maybe"/"gone", or null when
/// the ledger is too thin (or oracle context unavailable).
#[cfg(feature = "indexer")]
pub(super) fn oracle_verdict_json(
    ocx: &Option<(nzbkit::oracle::Snapshot, Vec<String>)>,
    grp: &str,
    first_posted: i64,
    now: i64,
) -> Value {
    let Some((snap, bbs)) = ocx else {
        return Value::Null;
    };
    // Undated release: age is unknown, not "20000 days old". Emit no
    // verdict rather than reading it out of the wrong (ancient) bucket.
    if first_posted <= 0 {
        return Value::Null;
    }
    let age = ((now - first_posted).max(0) / 86_400) as u32;
    match snap.verdict(bbs, &nzbkit::oracle::group_family(grp), age) {
        Some(v) => json!(v.as_str()),
        None => Value::Null,
    }
}

pub(super) fn load_settings(path: &std::path::Path) -> serde_json::Map<String, Value> {
    // Backup-aware: a torn settings.json loads the .bak of the last good
    // parse instead of {} - otherwise the next save_setting would erase
    // every other setting.
    crate::persist::load_json_with_backup(path)
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

/// Persist several related settings in one atomic rewrite. `Value::Null`
/// removes a key. Returning false lets multi-step live state avoid
/// recording a completion marker that never reached disk.
pub(super) fn save_settings(path: &std::path::Path, values: &[(&str, Value)]) -> bool {
    update_settings(path, |map| {
        for (key, v) in values {
            if v.is_null() {
                map.remove(*key);
            } else {
                map.insert((*key).to_string(), v.clone());
            }
        }
    })
}

/// Union two comma-separated category lists, in the settings file's own
/// shape. Order is stable (on-disk entries first, then anything new) so
/// a registration that adds nothing rewrites the same bytes.
pub(super) fn merge_cat_list(on_disk: &str, mine: &str) -> String {
    let mut all: Vec<&str> = Vec::new();
    for c in on_disk.split(',').chain(mine.split(',')).map(str::trim) {
        if !c.is_empty() && !all.contains(&c) {
            all.push(c);
        }
    }
    all.join(", ")
}

/// The read-modify-write behind [`save_settings`], with the modify step
/// left to the caller. Use this when the new value DEPENDS on what is
/// already on disk: `f` runs inside the same critical section as the
/// read and the write, so it sees the current file rather than a
/// snapshot taken before some other worker's save.
pub(super) fn update_settings(
    path: &std::path::Path,
    f: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> bool {
    // API requests are handled on a worker pool - serialize the
    // read-modify-write so concurrent saves can't drop each other's keys.
    static IO: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = IO.lock_ok();
    let mut map = load_settings(path);
    f(&mut map);
    match serde_json::to_string_pretty(&Value::Object(map)) {
        Ok(text) => {
            if let Err(e) = crate::persist::write_atomic(path, text.as_bytes()) {
                error!(target: "settings", "write {}: {e}", path.display());
                false
            } else {
                true
            }
        }
        Err(e) => {
            error!(target: "settings", "serialize: {e}");
            false
        }
    }
}

/// Persist one UI-changed setting. Best-effort: a failed write must never
/// take down a live daemon.
pub(super) fn save_setting(path: &std::path::Path, key: &str, v: Value) {
    let _ = save_settings(path, &[(key, v)]);
}

/// A fresh API key: 24 bytes of OS entropy as 48 lowercase hex chars -
/// the same shape and strength the container entrypoint mints, and the
/// shape every `apikey=` comparison in here already handles.
///
/// Deliberately NOT `fresh_secret()`: that mixes `RandomState` instances,
/// which are seeded once per thread and then bumped by a counter, so its
/// outputs are related. Good enough for a stream capability URL that
/// lives for one session; not good enough for the credential guarding
/// the whole control API.
pub(super) fn random_apikey() -> Option<String> {
    let mut buf = [0u8; 24];
    getrandom::fill(&mut buf).ok()?;
    Some(hex::encode(buf))
}

/// `runtime.json`, beside `settings.json`: how a LAUNCHER tells this
/// daemon apart from anything else that answers on the port.
///
/// The Mac wrapper and the Windows tray probe a port without a key (they
/// must: sending it would hand the key, and with it `mode=server_secret`,
/// to whatever bound the port first) and identify us from the reply
/// alone. But an unauthenticated product string is not identity - any
/// local process can print it, and on a shared desktop a second account
/// can bind an unprivileged loopback port before we do, then receive the
/// stored key on the next dashboard open.
///
/// So the wrapper reads a secret only OUR user can read, and the daemon
/// proves it holds the same one: `mode=version&hs=<nonce>` answers with
/// `hs_proof = sha256(token:nonce)`. The token never crosses the wire in
/// either direction, so sending the challenge to an impostor tells it
/// nothing, and a wrapper that gets no proof (or a wrong one) knows not
/// to hand over the key.
///
/// `pid` is recorded for diagnostics and for a spawning wrapper that
/// wants to bind its attach to the exact child it started. The file is
/// 0600 through [`crate::persist::write_atomic`] (LocalAppData and
/// Application Support are already user-only on the other two), and
/// rewritten on every start, so a stale one from a crashed run is
/// replaced rather than trusted - and the port it names is checked too.
pub(super) fn write_runtime_file(
    settings_path: &std::path::Path,
    port: u16,
    tls: bool,
    token: &str,
) {
    let path = settings_path.with_file_name("runtime.json");
    let body = json!({
        "pid": std::process::id(),
        "port": port,
        // §129 2a: which scheme this listener answers. Additive - wrappers
        // that predate it ignore unknown keys, and a wrapper probing http
        // against a TLS daemon fails its handshake exactly as it would
        // against a stranger holding the port, which is the safe reading.
        "tls": tls,
        "token": token,
        "version": env!("CARGO_PKG_VERSION"),
    });
    // Best-effort, like every other state write here: a daemon that cannot
    // write it still runs, and the wrappers fall back to the old
    // reply-shape check (which is what an older daemon gives them anyway).
    if let Err(e) = crate::persist::write_atomic(
        &path,
        serde_json::to_string(&body).unwrap_or_default().as_bytes(),
    ) {
        eprintln!(
            "⚠ could not write {} ({e}) - the desktop wrapper will fall back to \
             identifying this daemon by its reply alone",
            path.display()
        );
    }
}

/// The launcher-handshake answer for a challenge, or None if the caller
/// did not send one.
///
/// The nonce is bounded and charset-checked before it is hashed: it lands
/// in a JSON response and comes from an unauthenticated caller.
pub(super) fn launcher_proof(token: &str, nonce: Option<&str>) -> Option<String> {
    use sha2::{Digest, Sha256};
    if token.is_empty() {
        return None; // see the mint site: no token, no answer
    }
    let nonce = nonce
        .filter(|n| (8..=128).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_alphanumeric()))?;
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.update(b":");
    h.update(nonce.as_bytes());
    Some(hex::encode(h.finalize()))
}

/// First-run API key generation, for every launcher including the
/// container. The Docker entrypoint used to carry a second copy of this
/// (same file, same path, same resolution order); it now only pre-flights
/// the cases where the fallbacks below would leave a published port
/// keyless, and refuses to start instead (packaging/docker-entrypoint.sh).
///
/// Until now only Docker did this. systemd, launchd, homebrew services,
/// NzbFast.app, the tray and a bare `nzbfast serve` all started keyless
/// on 0.0.0.0, where the auth computation's `(None, None) => true` arm
/// makes every request fully authorized: anything on the LAN - or any
/// web page the user happens to visit, since the SAB-compatible API is
/// all GETs with no Origin check - could read the provider password back
/// in cleartext (`mode=server_secret`), point the post-processing script
/// at a program of its choice (`mode=config&name=script`), delete the
/// queue with its files, and shut the daemon down. Minting the key here
/// instead of in five launcher scripts covers every launcher at once.
///
/// Resolution order mirrors the container:
///   1. `--apikey` (or a dashboard-saved apikey) -> use it, untouched.
///   2. `NZBFAST_OPEN=1`                         -> deliberately keyless.
///   3. a previously generated key file          -> reuse it, so the key
///      is stable across restarts.
///   4. a FIRST run and none of the above        -> generate, persist, and
///      return it so the caller can print it once, prominently.
///
/// (4) is the load-bearing case, and its gate is deliberately narrow. An
/// install that is ALREADY running keyless must never have a key appear
/// underneath it: that would break the user's configured Sonarr/Radarr
/// and phone remotes on a restart they never connected to a config
/// change, with no error that points at the cause. So "first run" here
/// means the install has never completed a run at all - no dashboard
/// settings file AND no daemon spool. The config file itself is NOT part
/// of the test: the setup wizard writes it before the first `serve`, so a
/// fresh install has one.
///
/// Every signal is read from the DATA DIRECTORY, and only from there. The
/// download root is NOT a first-run signal, and must never be added as
/// one - it was, as belt and braces, and it was a security regression:
///
///   * A reinstall wipes the data dir but deliberately keeps downloads
///     (the uninstaller asks separately and defaults to keeping them). A
///     `.spool` left in the download root by an install from days earlier
///     then made a genuinely fresh install look established, so no key was
///     minted and the daemon came up open on 0.0.0.0. On Windows that is
///     invisible: no console, and the dashboard's log panel is unix-only.
///   * The test it was meant to strengthen cannot be strengthened this
///     way, because a credential can only live in `settings.json` or the
///     `apikey` file, and both are in the data dir. A spool in the
///     download root is evidence that downloads once happened there, not
///     evidence that a key is in use.
///
/// The pre-migration spool location is still honoured everywhere it
/// matters - `spool_dir` migrates it a few lines into `serve` - and a real
/// legacy install is still recognised here, by its data-dir settings file.
///
/// What to tell someone whose API key file is unusable.
///
/// Carried by both the console error and, on Windows, the tray's own
/// message box - the tray user never sees a console, and the generic
/// "stopped unexpectedly, try Restart" it used to show was worse than
/// nothing: restarting fails identically every time, forever.
///
/// `KEYLESS_MARKER` is what the tray greps the log for, through its own
/// copy of the same string in nzbtray. Keep the two in step.
pub const KEYLESS_MARKER: &str = "nzbfast cannot start: API key file";

pub(super) fn keyless_help(keyfile: &std::path::Path, what: &str) -> String {
    format!(
        "{KEYLESS_MARKER} {what}.\n\n\
         Your API key is what stops other machines on your network from \
         controlling nzbfast, so it will not start without one. Nothing \
         has been downloaded twice, and nothing has been lost: the queue, \
         history and settings are untouched.\n\n\
         File: {}\n\n\
         Pick whichever fits:\n\
         1. If you know your key (it is in Sonarr/Radarr under this \
            download client), put it back in that file on one line.\n\
         2. If you do not, DELETE the file and start nzbfast again. It \
            creates a new key and shows it to you. You will then need to \
            paste the new key into Sonarr, Radarr or any other app that \
            connects to nzbfast.\n\
         3. Only if this machine is not reachable by anyone else, set \
            NZBFAST_OPEN=1 to run with no key at all.\n\n\
         An empty file usually means the disk filled up or the machine \
         lost power while the file was being written.",
        keyfile.display()
    )
}

/// Returns `Some((key, keyfile))` only when a key was newly generated.
pub(super) fn first_run_apikey(
    opts: &mut ServeOpts,
    settings_path: &std::path::Path,
    config: &std::path::Path,
) -> Result<Option<(String, PathBuf)>> {
    // Normalise `--apikey ""` (and whitespace) to "no key given" FIRST.
    // Left as Some(""), it short-circuited every check below AND
    // suppressed the open-API banner, because `d.apikey` was not None -
    // then `ct_eq("", "")` authorised `?apikey=`. That was a quieter
    // fail-open than the ones this function exists to close. Empty
    // values from settings.json were already filtered this way.
    if opts.apikey.as_deref().is_some_and(|k| k.trim().is_empty()) {
        opts.apikey = None;
    }
    if opts.apikey.is_some() {
        return Ok(None); // explicit operator choice wins
    }
    if std::env::var("NZBFAST_OPEN").is_ok_and(|v| v == "1") {
        return Ok(None); // deliberately keyless, e.g. behind another auth layer
    }
    let keyfile = config.with_file_name("apikey");
    match std::fs::read_to_string(&keyfile) {
        // Reuse a key we minted earlier. Stable across restarts, which is
        // the whole point - the *arrs hold it.
        Ok(k) if !k.trim().is_empty() => {
            opts.apikey = Some(k.trim().to_string());
            return Ok(None);
        }
        // Present but empty or unreadable. Never continue keyless: the
        // default listener is 0.0.0.0 and `None` grants full control API
        // access, including provider-secret reads and config writes.
        // Refusing startup preserves the old credential and makes the
        // operator repair the explicit fault instead of silently failing
        // open.
        // The wording matters more than usual here: this is the only
        // message a user gets, it appears at the one moment the app will
        // not start, and the previous version named three remedies
        // without saying what any of them would cost. "Restore the key"
        // is not advice to someone whose key file just went empty - they
        // do not have it to restore. So: say what happened, say why we
        // stop, then give the options in the order most people want them,
        // each with its consequence attached.
        Ok(_) => {
            anyhow::bail!("{}", keyless_help(&keyfile, "is empty"));
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "{}",
                keyless_help(&keyfile, &format!("could not be read ({e})"))
            );
        }
        Err(_) => {} // no key file at all - fall through to the first-run test
    }
    // Data-dir signals ONLY. `opts.out_root` (the download root) must not
    // join this test - see the note above; a leftover spool there survives
    // an uninstall and would suppress minting on a fresh install.
    let spool = config.with_file_name(".spool");
    if spool.exists() || settings_beyond_setup_answers(settings_path) {
        // An existing install. Leave it EXACTLY as it was - EXCEPT when
        // the settings store itself failed to load. A key set in the
        // dashboard is written to settings.json and NOWHERE else (the
        // config handler only touches the keyfile to delete it), so an
        // unreadable or torn settings.json drops that key, load_settings
        // degrades to an empty map, and the daemon comes up wide open on
        // the default 0.0.0.0 listener. Same uid-change and torn-write
        // causes the keyfile branch above guards against, same answer.
        // The container entrypoint has refused this for a while; the
        // native launchers did not.
        if opts.apikey.is_none() && crate::persist::json_store_unreadable(settings_path) {
            anyhow::bail!(
                "{} could not be read, and any API key saved in Settings lives there; \
                 refusing to start the control API without authentication. Restore it \
                 (a .bak or .corrupt sibling may hold it), pass --apikey, or set \
                 NZBFAST_OPEN=1 to run deliberately keyless",
                settings_path.display()
            );
        }
        return Ok(None);
    }
    let key = match random_apikey() {
        Some(k) => k,
        None => anyhow::bail!(
            "could not read OS entropy for an API key; refusing to start the control API \
             without authentication"
        ),
    };
    // Persist first, so the key the user is about to paste into Sonarr
    // survives the next restart. write_atomic creates it 0600 on unix and
    // fsyncs before the rename, so a crash cannot leave a torn key.
    //
    // If it cannot be stored we still USE it for this session rather than
    // falling back to open: the daemon is then keyed (safe) but the key
    // changes on the next start, which the message says outright. On a
    // first run nothing has been wired up yet, so an unstable key costs
    // far less than an open control API.
    if let Err(e) = crate::persist::write_atomic(&keyfile, key.as_bytes()) {
        eprintln!(
            "⚠ generated an API key but could not save it to {} ({e}) - it will CHANGE on the \
             next start. Set one in Settings, or pass --apikey, to make it stick.",
            keyfile.display()
        );
    }
    opts.apikey = Some(key.clone());
    Ok(Some((key, keyfile)))
}

/// Install the daemon's live ingest policy on an Index connection. The
/// shared connection can be handed over wholesale at the end of a scan
/// pass (B4), so neither custom classification nor its gate closure can
/// be assumed to survive between uses - every ingest installs its own.
#[cfg(feature = "indexer")]
pub(super) fn install_live_ingest_policy(
    ix: &mut nzbkit::index::Index,
    gates: Option<crate::gates::Gates>,
    cats: Vec<nzbkit::categories::CustomCategory>,
) {
    let gate_cats = cats.clone();
    ix.set_gate(Box::new(move |stem| {
        gates
            .as_ref()
            .is_none_or(|g| g.allows_with(stem, &gate_cats))
    }));
    ix.set_custom(cats);
}

/// A `cat=` value the wall/browse APIs may filter on: a built-in kind or
/// a custom-category slug (lowercase alnum + '-'). The filter is a bound
/// SQL parameter, so this is a shape check, not a security boundary - an
/// unknown slug simply matches no rows.
#[cfg(feature = "indexer")]
pub(super) fn is_kind_slug(k: &str) -> bool {
    !k.is_empty()
        && k.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// A one-time, short-lived stand-in for the API key, handed to the
/// browser this daemon opens for itself.
///
/// The key used to ride the launch URL as `?apikey=`, and that URL is the
/// child process's ARGV. On Linux `/proc/<pid>/cmdline` is world-readable,
/// so every other local account could read the credential straight out of
/// the `xdg-open` we had just spawned - and with it `mode=server_secret`,
/// which is the Usenet password in cleartext. macOS `ps` shows other
/// users' arguments too, and the Windows `cmd /C start` line is readable
/// through WMI, so this was never only a Linux problem.
///
/// The token below goes in the URL instead. It is worth exactly one
/// exchange, from any caller, for the length of a browser cold start, and
/// the page trades it for the key over the loopback socket - a channel
/// only this process is on either end of.
///
/// One exchange is a race, not a fence: the token is still in argv for
/// the whole window, and a local reader quicker than the browser wins
/// it. So the slot does not forget the token when it is spent. It keeps
/// a hash until the TTL, and a SECOND presentation of the right token
/// is then known for what it is - exactly one of the two presenters was
/// the browser this daemon spawned, and the other one holds the key -
/// and `route_handoff` says so and rotates the key. (A `file://`
/// bootstrap page, so that only a path is in argv, was weighed and
/// rejected: `open` / `start` / `xdg-open` dispatch a file on its TYPE
/// handler, which on many boxes is an editor, not the browser.)
pub(super) struct Handoff {
    /// sha256 of the token, hex. Never the token itself, so a spent slot
    /// holds nothing a reader of process memory could present.
    token_hash: String,
    /// The key while the token is still worth one exchange; `None` once
    /// it has been traded, or once a request authenticated with the
    /// full key before any trade (`disarm_handoff_in`).
    key: Option<String>,
    born: std::time::Instant,
}

/// How long a handoff stays redeemable, and how long a spent one is
/// remembered so a second presentation can be recognised.
///
/// Was 300 s, sized for a cold browser behind a "choose your default
/// browser" dialog. That is also how long the token in argv stayed
/// worth a key, so it is now the high end of what such a launch takes;
/// a slower one costs the key prompt this path exists to avoid, which
/// is what every launch cost before the token existed.
const HANDOFF_TTL: std::time::Duration = std::time::Duration::from_secs(45);

/// What presenting a token to the slot came to.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Redeem {
    /// The right token, first time: here is the key.
    Key(String),
    /// The right token, but it has been traded already. Somebody else
    /// has the key.
    Replay,
    /// The right token, over loopback, but from a socket another local
    /// account owns: the token was read off the launch argv. Nothing is
    /// burned and the log names the account.
    Foreign(String),
    /// Nothing armed, expired, or a wrong token.
    Refused,
}

impl Handoff {
    /// True once the slot is only a mark: nothing left to hand over.
    #[cfg(test)]
    pub(super) fn holds_no_key(&self) -> bool {
        self.key.is_none()
    }
}

fn handoff_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// The armed handoff, if any.
///
/// Process-wide rather than a `Daemon` field because there is at most one
/// per process: it is armed on the single run that both minted a key and
/// opened a browser, before that browser has made its first request, and
/// it is gone again after one exchange. The functions below all take the
/// slot as an argument (the `note_auth_failure_in` shape) so the rule
/// they carry can be tested without standing up a daemon.
static HANDOFF: Mutex<Option<Handoff>> = Mutex::new(None);

/// Arm `slot` with a fresh handoff for `key`, returning the token to put
/// in the launch URL.
///
/// `None` if the system RNG refused, which is the same answer the key
/// mint gives in that case: no token, no `?handoff=`, and the page asks
/// for a key like any other browser would.
pub(super) fn arm_handoff_in(slot: &Mutex<Option<Handoff>>, key: &str) -> Option<String> {
    let token = random_apikey()?;
    *slot.lock_ok() = Some(Handoff {
        token_hash: handoff_hash(&token),
        key: Some(key.to_string()),
        born: std::time::Instant::now(),
    });
    HANDOFF_ARMED.store(true, Ordering::Relaxed);
    Some(token)
}

/// Process-wide "is there a key waiting in the slot", so the per-request
/// hook below costs one relaxed load on every run that armed nothing,
/// which is every run but the first.
static HANDOFF_ARMED: AtomicBool = AtomicBool::new(false);

/// A request has authenticated with the full key. Whoever sent it
/// already has what the token was minted to deliver, so the token stops
/// being worth a key from here on. The hash stays, so a later
/// presentation is still recognised, and a slot that was already
/// traded is left exactly as it is - in the sequence where a reader
/// traded first, that reader's own authenticated requests must not
/// erase the mark the browser's late arrival is judged against.
pub(super) fn disarm_handoff_in(slot: &Mutex<Option<Handoff>>) {
    if let Some(h) = slot.lock_ok().as_mut() {
        h.key = None;
    }
}

/// The hook `/api` calls once it has decided a request carries the full
/// key. See `disarm_handoff_in`.
pub(super) fn note_full_key_request() {
    if HANDOFF_ARMED.swap(false, Ordering::Relaxed) {
        disarm_handoff_in(&HANDOFF);
    }
}

/// Trade `token` for the key it stands in for, once.
///
/// A WRONG token does not burn the right one. The token is 192 bits, so
/// guessing is not the threat here, and burning on a miss would let any
/// local process disarm the handoff by posting a single byte - which
/// costs the user the launch they are in the middle of. A RIGHT one has
/// its key taken out of the slot before it is returned, so a second
/// caller (or a replayed request) gets `Replay`, never a key.
///
/// The presenter's account is taken as ours here; this is the shape the
/// tests of the slot rule use. Production goes through
/// `redeem_handoff_from`, which asks the kernel.
#[cfg(test)]
pub(super) fn redeem_handoff_in(slot: &Mutex<Option<Handoff>>, token: &str) -> Redeem {
    redeem_handoff_as(slot, token, || super::peeracct::PeerAccount::Ours)
}

/// `redeem_handoff_in` with the presenter's account judged by `account`,
/// which is asked only once the token has matched (so a process spraying
/// tokens never makes us walk the kernel's connection table) and BEFORE
/// the key is taken, so a presenter from another account burns nothing:
/// the browser this daemon spawned, arriving later, still trades. That
/// presenter is the argv reader every earlier step could only race or
/// report after the fact, and this is the step that refuses it outright
/// - including on the launch where the browser never arrives, which was
/// the one sequence nothing reported. `Unknown` (no table on this box,
/// or no row) keeps the loopback-only rule that held before.
pub(super) fn redeem_handoff_as(
    slot: &Mutex<Option<Handoff>>,
    token: &str,
    account: impl FnOnce() -> super::peeracct::PeerAccount,
) -> Redeem {
    use super::peeracct::PeerAccount;
    let mut slot = slot.lock_ok();
    let Some(h) = slot.as_mut() else {
        return Redeem::Refused;
    };
    if h.born.elapsed() > HANDOFF_TTL {
        *slot = None;
        HANDOFF_ARMED.store(false, Ordering::Relaxed);
        return Redeem::Refused;
    }
    if !ct_eq(&handoff_hash(token), &h.token_hash) {
        return Redeem::Refused;
    }
    if let PeerAccount::Other(who) = account() {
        return Redeem::Foreign(who);
    }
    match h.key.take() {
        Some(k) => {
            HANDOFF_ARMED.store(false, Ordering::Relaxed);
            Redeem::Key(k)
        }
        None => Redeem::Replay,
    }
}

/// Trade `token` for its key, but only for a caller on this machine.
///
/// The token exists in exactly one place: the argv of the browser this
/// daemon just spawned, on this box. A caller arriving from anywhere
/// else is by construction not that browser, so an install bound to
/// `0.0.0.0` must not put the redemption door on the network. The peer
/// is judged BEFORE the redeem, so a remote caller who somehow holds
/// the token cannot burn the launch the local browser is still on its
/// way to complete. An unknown peer address is refused for the same
/// reason: nothing about it says "this machine".
///
/// Loopback is necessary and not sufficient: every local account can
/// reach it, and the one that read the token off the launch argv is a
/// different account from ours (a process of our own account could read
/// the key file and needs no token). So the peer's SOCKET OWNER is asked
/// of the kernel too - `peeracct`, which needs the peer's port as well as
/// its address, hence the full `SocketAddr` - and a socket another
/// account owns is `Foreign`.
pub(super) fn redeem_handoff_from(
    slot: &Mutex<Option<Handoff>>,
    peer: Option<std::net::SocketAddr>,
    local_port: u16,
    token: &str,
) -> Redeem {
    let Some(peer) = peer.filter(|p| p.ip().to_canonical().is_loopback()) else {
        return Redeem::Refused;
    };
    redeem_handoff_as(slot, token, || {
        super::peeracct::peer_account(peer, local_port)
    })
}

/// The exact command line [`open_dashboard`] spawns.
///
/// Split out from the spawn, and given the key rather than a token, so a
/// test can read the argv the child would have been handed and assert the
/// thing that is invisible at the call site: the key is not in it. The
/// key is turned into a handoff token HERE, at the last moment before it
/// would have become a URL, so there is no route by which a caller's copy
/// reaches a process argument.
pub(super) fn dashboard_argv_in(
    slot: &Mutex<Option<Handoff>>,
    port: u16,
    tls: bool,
    key: Option<&str>,
) -> (&'static str, Vec<String>) {
    let q = key
        .and_then(|k| arm_handoff_in(slot, k))
        .map(|t| format!("?handoff={}", super::http::query_escape(&t)))
        .unwrap_or_default();
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{scheme}://localhost:{port}/{q}");
    #[cfg(target_os = "macos")]
    let argv = ("open", vec![url]);
    #[cfg(target_os = "windows")]
    let argv = (
        "cmd",
        vec!["/C".to_string(), "start".to_string(), String::new(), url],
    );
    #[cfg(all(unix, not(target_os = "macos")))]
    let argv = ("xdg-open", vec![url]);
    argv
}

/// `POST /handoff`: trade the one-time token from the launch URL for the
/// API key, over loopback where argv-reading neighbours cannot see it.
///
/// Unauthenticated by necessity - the token is what the page has INSTEAD
/// of a credential - and safe on the token's own terms: 192 bits of
/// randomness, dead after one exchange, expired minutes after the launch
/// that minted it, and armed at all only on the run that minted the
/// key. Every other run answers the refusal below.
///
/// No CORS headers, deliberately. A page on another origin can POST here
/// (a text body is a simple request, so nothing preflights), but it can
/// neither guess the token nor read the answer.
///
/// Loopback only, whatever the daemon is bound to - see
/// `redeem_handoff_from`.
///
/// A `Replay` is the one answer that is not about this request at all:
/// the right token has been traded once already, so somebody other
/// than the presenter holds the key that was minted for the browser.
/// Whichever of the two was the browser, the key is no longer only the
/// owner's, so it is rotated on the spot (the same three-store
/// transaction `config name=apikey` runs) and the log says where the
/// new one is.
pub(super) fn route_handoff(mut req: tiny_http::Request, d: &Arc<Daemon>) {
    use std::io::Read as _;
    if req.method() != &tiny_http::Method::Post {
        let _ = req.respond(tiny_http::Response::from_string("").with_status_code(405));
        return;
    }
    // A token is 48 hex characters. The cap is what stops an unauthorized
    // caller from making us buffer anything.
    let mut token = String::new();
    let _ = req.as_reader().take(256).read_to_string(&mut token);
    let peer = peer_ip(&req);
    match redeem_handoff_from(&HANDOFF, req.remote_addr().copied(), d.port, token.trim()) {
        Redeem::Key(key) => {
            let _ = req.respond(json_resp(json!({ "apikey": key })));
        }
        Redeem::Replay => {
            rotate_key_after_replay(d);
            let _ = req.respond(
                json_resp(json!({"status": false, "error": "API Key Required"}))
                    .with_status_code(403),
            );
        }
        Redeem::Foreign(who) => {
            // The token was right and it came over loopback, and the
            // socket it came over belongs to another local account: that
            // account read it off the launch argv. Refused without
            // burning it, so the browser still trades; said here, because
            // this is the only place the attempt is visible at all.
            warn!(
                target: "auth",
                "the first-run handoff token was presented from a loopback socket owned by \
                 another local account ({who}): that account read it off the browser launch \
                 command line. Refused; the token is still good for the browser. Other \
                 accounts on this machine can see process arguments, so consider a key of \
                 your own in Settings."
            );
            let _ = d.note_auth_failure(peer, "handoff");
            let _ = req.respond(
                json_resp(json!({"status": false, "error": "API Key Required"}))
                    .with_status_code(403),
            );
        }
        Redeem::Refused => {
            // Accounted like every other credentialed door, so a local
            // process spraying tokens leaves a trace and meets the same
            // per-IP limiter.
            let _ = d.note_auth_failure(peer, "handoff");
            let _ = req.respond(
                json_resp(json!({"status": false, "error": "API Key Required"}))
                    .with_status_code(403),
            );
        }
    }
}

/// The first-run token was presented twice, so the key it stood for is
/// in two hands. Mint a fresh one and make it the key everywhere at
/// once; the holder of the old one is locked out from the next request.
/// The browser that lost the race lands on the key modal either way,
/// and the warning below is what tells the user where to look.
fn rotate_key_after_replay(d: &Arc<Daemon>) {
    let keyfile = d.settings_path.with_file_name("apikey");
    let Some(fresh) = random_apikey() else {
        warn!(
            target: "auth",
            "the first-run handoff token was presented a second time, so another local \
             process traded it before the browser did and holds the API key - and the \
             system RNG refused a replacement. Set a new key in Settings now."
        );
        return;
    };
    match super::settings::apply_and_save(d, "apikey", &fresh) {
        Ok(_) => warn!(
            target: "auth",
            "the first-run handoff token was presented a second time, so another local \
             process traded it before the browser did and held the API key. The key has \
             been replaced; the new one is in {}",
            keyfile.display()
        ),
        Err(e) => warn!(
            target: "auth",
            "the first-run handoff token was presented a second time, so another local \
             process holds the API key, and replacing it failed ({e}). Set a new key in \
             Settings now."
        ),
    }
}

/// Open the dashboard in the user's default browser, shortly after the
/// listener is up (a small delay lets the accept loop start so the first
/// request doesn't race the bind). Best-effort - failures are ignored.
/// `key` is Some only on the run that MINTED it: the page adopts it into
/// localStorage and strips it from the address bar, so the first
/// double-click launch lands on a working dashboard instead of a prompt
/// for a credential the user has never seen (the .app and the Windows
/// installer send the banner to a log file nobody opens). A key already
/// in the browser needs no help, so it is never re-sent.
///
/// What actually travels is a [`Handoff`] token, never the key itself -
/// see [`dashboard_argv_in`], which is where that rule lives and where it
/// is tested.
pub(super) fn open_dashboard(port: u16, tls: bool, key: Option<String>) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(500));
        // Armed here rather than at the call site so the TTL clock starts
        // when the browser is actually being launched.
        let (prog, args) = dashboard_argv_in(&HANDOFF, port, tls, key.as_deref());
        let _ = std::process::Command::new(prog)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    });
}

/// Overlay dashboard-saved settings (settings.json) onto the launch
/// flags: a value once changed in the UI wins on every later launch,
/// until its key is deleted from the file.
pub(super) fn apply_saved_settings(opts: &mut ServeOpts, path: &std::path::Path) {
    let saved = load_settings(path);
    if saved.is_empty() {
        return;
    }
    info!(target: "settings", "applying saved settings from {}", path.display());
    let s = |k: &str| saved.get(k).and_then(Value::as_str);
    let n = |k: &str| saved.get(k).and_then(Value::as_u64);
    let b = |k: &str| saved.get(k).and_then(Value::as_bool);
    let list = |k: &str| {
        saved.get(k).and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
    };
    let opt_path = |v: &str| (!v.is_empty()).then(|| PathBuf::from(v));
    // Range-checked exactly as the settings writer checks it: this file
    // can be hand-edited, and `as u16` would silently turn a typo'd
    // 70000 into 4464 - a port nothing expects and the mac wrapper (which
    // validates 1-65535 before it connects) can never find. An
    // out-of-range value is ignored, keeping the CLI or default port.
    if let Some(v) = n("port").filter(|v| (1..=65535).contains(v)) {
        // Unless the launcher owns the port. The API refuses to save one
        // in that case, so this only fires for a file carried over from a
        // desktop install or hand-edited - and honouring it would move the
        // listener away from a published mapping, a healthcheck or DSM's
        // Open button, with nothing in the UI to explain where it went.
        if port_locked() {
            if v as u16 != opts.port {
                info!(
                    target: "settings",
                    "ignoring saved port {v}: this installation's port is set by \
                     how it was started ({}). Change the published/mapped port instead.",
                    opts.port
                );
            }
        } else {
            opts.port = v as u16;
        }
    }
    if let Some(v) = s("bind").filter(|v| !v.is_empty()) {
        opts.bind = v.to_string();
    }
    // §129 2a: an explicitly saved empty string means "TLS off" and must
    // beat a CLI flag, same as every other key here - a value once
    // changed in the UI wins on later launches.
    if let Some(v) = s("tls_cert") {
        opts.tls_cert = opt_path(v);
    }
    if let Some(v) = s("tls_key") {
        opts.tls_key = opt_path(v);
    }
    if let Some(v) = s("out_dir").filter(|v| !v.is_empty()) {
        opts.out_root = PathBuf::from(v);
    }
    if let Some(v) = s("watch") {
        opts.watch = opt_path(v);
    }
    if let Some(v) = s("script") {
        // Raw chain text (§192) - `serve()` parses it into the ordered
        // list. `opt_path` still does the right thing here: an empty
        // value clears, and a one-script value is a plain path.
        opts.script = opt_path(v);
    }
    if let Some(v) = n("connections") {
        opts.connections = (v as usize).max(1);
    }
    if let Some(v) = n("window") {
        opts.window = (v as usize).max(1);
    }
    if let Some(v) = n("decoders") {
        opts.decoders = (v as usize).max(1);
    }
    if let Some(v) = b("fast_verify") {
        opts.fast_verify = v;
    }
    if let Some(v) = s("verify_mode") {
        match v {
            "full" => (opts.fast_verify, opts.verify_lean) = (false, false),
            "fast" => (opts.fast_verify, opts.verify_lean) = (true, false),
            "lean" => (opts.fast_verify, opts.verify_lean) = (true, true),
            _ => {}
        }
    }
    if let Some(v) = n("min_free") {
        // `Some(0)`, NOT None: 0 is the user saying OFF, and the launch
        // default is non-zero (MIN_FREE_DEFAULT). Collapsing a saved 0
        // into "nothing was saved" handed those installs the default
        // back on every restart, which is the one answer the person who
        // typed 0 had ruled out.
        opts.min_free = Some(v);
    }
    if let Some(v) = n("auto_retry_mins") {
        opts.auto_retry_mins = v;
    }
    // Stored as the octal STRING the user typed ("002"), because that is
    // what every guide about this prints and what the field shows back.
    // Parsed here exactly as the settings writer parses it; anything else
    // is ignored and the install keeps its current behaviour rather than
    // silently adopting a mode nobody chose.
    if let Some(v) = s("out_umask") {
        opts.out_umask = if v.trim().is_empty() {
            None
        } else {
            u32::from_str_radix(v.trim(), 8)
                .ok()
                .filter(|m| *m <= 0o777)
        };
    }
    if let Some(v) = b("preflight") {
        opts.preflight = v;
    }
    if let Some(v) = n("quota") {
        opts.quota = (v > 0).then_some(v);
    }
    if let Some(v) = s("quota_period").and_then(|v| v.chars().next()) {
        opts.quota_period = v;
    }
    if let Some(v) = n("speedlimit") {
        opts.speedlimit = Some(v.to_string()); // parse_size takes bare bytes
    }
    if let Some(v) = b("auto_speed") {
        opts.auto_speed = v;
    }
    if let Some(v) = list("library_cats") {
        opts.library_cats = v;
    }
    if let Some(v) = n("library_recheck_secs") {
        opts.library_recheck_secs = v.max(1);
    }
    #[cfg(feature = "indexer")]
    if let Some(v) = s("index_db").filter(|v| !v.is_empty()) {
        opts.index_db = PathBuf::from(v);
    }
    #[cfg(feature = "indexer")]
    if let Some(v) = list("index_groups") {
        opts.index_groups = v;
    }
    #[cfg(feature = "indexer")]
    if let Some(v) = n("index_interval_secs") {
        opts.index_interval_secs = v;
    }
    #[cfg(feature = "indexer")]
    if let Some(v) = n("index_backfill") {
        opts.index_backfill = v;
    }
    if let Some(v) = b("group_desc_isc") {
        opts.group_desc_isc = v;
    }
    if let Some(v) = s("apikey") {
        opts.apikey = (!v.is_empty()).then(|| v.to_string());
    }
    if let Some(v) = s("nzbkey") {
        opts.nzbkey = (!v.is_empty()).then(|| v.to_string());
    }
    if let Some(v) = n("mem_limit") {
        opts.mem_budget = if v > 0 {
            // A figure a person typed into Settings, so the clamp is
            // reported rather than silent (`MemBudget::from_user_limit`).
            nzbkit::mem::MemBudget::from_user_limit(v, "the mem_limit setting")
        } else {
            nzbkit::mem::MemBudget::auto()
        };
    }
    #[cfg(feature = "indexer")]
    if let Some(v) = n("index_max_age_secs") {
        opts.index_max_age_secs = v;
    }
    #[cfg(feature = "indexer")]
    if let Some(v) = s("index_gates") {
        opts.index_gates = if v.trim().is_empty() {
            None
        } else {
            match crate::gates::Gates::from_json(v) {
                Ok(g) => Some(g),
                Err(e) => {
                    warn!(target: "settings", "ignoring saved index_gates: {e}");
                    opts.index_gates.take()
                }
            }
        };
    }
    // "schedule" and "feeds" (JSON text) are handled in serve(): they
    // need parsing and the daemon to exist.
}
