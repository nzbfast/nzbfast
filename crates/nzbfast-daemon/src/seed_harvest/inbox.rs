//! The INDEXER INBOX: the on-disk staging area an indexer hit lands in
//! before the harvester ever looks at it, and everything that guards it -
//! the directory and its cross-process lock, the meta/raw file pair and
//! its fingerprint, the count and byte ceilings, the orphan grace window,
//! the capacity and invalid HOLDS, and the one pass that drains it.
//!
//! It is a protocol with another process on the other end (an indexer
//! writes here, the daemon reads), which is why it owns a lock file, a
//! versioned meta format and a fingerprint check rather than trusting
//! what it finds. Nothing above it in `seed_harvest.rs` needs any of
//! that: the harvester's own candidates come from jobs already in the
//! queue.
//!
//! Cut out of `seed_harvest.rs` on 7 Sep 2026 (claim
//! `debt-split-hot-files-7sep`) at 3,298 of the size gate's 4,000-line
//! file ceiling. Verbatim move; the public items are re-exported beside
//! the `mod` line so callers keep their `seed_harvest::` paths.

use super::*;

pub(super) const INDEXER_INBOX_DIR: &str = "nzb-seed-inbox";
pub(super) const INDEXER_INBOX_CAP: usize = 128;
// Every committed item owns a raw file plus a marker. Count protocol-owned
// crash artifacts separately so zero-length orphans cannot bypass the byte
// ceiling during the cross-process grace window.
pub(super) const INDEXER_INBOX_ARTIFACT_CAP: usize = INDEXER_INBOX_CAP * 2;
pub(super) const INDEXER_INBOX_BYTES_CAP: u64 = 512 << 20;
pub(super) const INDEXER_META_CAP: u64 = 64 << 10;
pub(super) const INDEXER_ORPHAN_GRACE_SECS: u64 = 60 * 60;
pub(super) static INDEXER_INBOX_IO: Mutex<()> = Mutex::new(());
pub(super) const INDEXER_INBOX_LOCK_FILE: &str = ".lock";

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct IndexerInboxMeta {
    version: u8,
    guid: String,
    name: String,
    category: String,
    posted: i64,
    bytes: u64,
}

pub(super) struct IndexerInboxPrepared {
    pub(super) id: String,
    pub(super) meta_path: PathBuf,
    pub(super) raw_path: PathBuf,
    pub(super) meta: IndexerInboxMeta,
    pub(super) seed: nzbkit::index::NzbSeedPrepared,
}

pub(super) enum IndexerInboxSettle {
    Stored {
        stats: nzbkit::index::NzbSeedReplayStats,
        cleanup: std::io::Result<()>,
    },
    Deferred,
    Capacity {
        reason: &'static str,
        hold: std::io::Result<PathBuf>,
    },
    CatalogCorrupt {
        error: nzbkit::index::NzbSeedError,
        hold: std::io::Result<PathBuf>,
    },
    Terminal {
        error: nzbkit::index::NzbSeedError,
        hold: std::io::Result<PathBuf>,
    },
    Failed(nzbkit::index::NzbSeedError),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct IndexerInboxUsage {
    pub(super) items: usize,
    pub(super) artifacts: usize,
    pub(super) bytes: u64,
}

pub(super) fn indexer_inbox_dir(d: &Daemon) -> PathBuf {
    d.spool.join(INDEXER_INBOX_DIR)
}

pub(super) fn secure_indexer_inbox_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    // On Windows the inbox INHERITS its parent's ACL instead of being
    // narrowed by an explicit call, and that is ENOUGH here - checked
    // 2 Sep 2026, so nobody spends a session re-deriving it. The spool
    // sits under `%USERPROFILE%` (`config::home_dir`, which reads
    // USERPROFILE on Windows), whose default ACL already grants only
    // that user, SYSTEM and Administrators and denies other standard
    // users. The delta against the unix `0700` above is that an
    // Administrator can read it - and on unix root can read a 0700
    // directory too, so the two platforms end up in the same place.
    //
    // The equivalent explicit call would be a `SetNamedSecurityInfo`
    // DACL. That would be the FIRST Windows ACL code in this repo (no
    // precedent anywhere in crates/), a new windows-sys API surface
    // that has to keep compiling on windows-arm64 and both phone
    // targets, and it is verifiable only on a real Windows box. Priced
    // and DECLINED against a gap that inheritance already closes.
    //
    // The binding below is what keeps `dir` used on non-unix; without
    // it `windows-clippy` reds on `unused_variables` and no host gate
    // sees it (2 Sep 2026).
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

pub(super) fn ensure_indexer_inbox_dir(d: &Daemon) -> std::io::Result<PathBuf> {
    let dir = indexer_inbox_dir(d);
    let newly_created = !dir.exists();
    std::fs::create_dir_all(&dir)?;
    secure_indexer_inbox_dir(&dir)?;
    if newly_created
        && let Some(parent) = dir.parent()
        && let Err(error) = crate::smart::sync_dir(parent)
    {
        // Leave the next preflight able to retry the parent-directory
        // durability step instead of mistaking this uncommitted empty path
        // for a previously settled inbox.
        let _ = std::fs::remove_dir(&dir);
        return Err(error);
    }
    Ok(dir)
}

/// The daemon-wide serve lock is advisory and deliberately fails open on
/// filesystems that cannot lock. Paid-proof admission must fail closed there:
/// otherwise two daemons can each scan below the cap and publish above it.
pub(super) fn lock_indexer_inbox_process(dir: &Path) -> std::io::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(INDEXER_INBOX_LOCK_FILE))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "commercial NZB seed inbox is busy in another process",
        )),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

pub(super) fn indexer_inbox_paths(d: &Daemon, id: &str) -> (PathBuf, PathBuf) {
    let dir = indexer_inbox_dir(d);
    (
        dir.join(format!("{id}.json")),
        dir.join(format!("{id}.nzb")),
    )
}

pub(super) fn indexer_inbox_id(guid: &str, name: &str, category: &str) -> String {
    use sha2::Digest as _;
    let mut digest = sha2::Sha256::new();
    digest.update(b"nzbfast-indexer-seed-inbox-v1\0");
    for value in [guid, name, category] {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value.as_bytes());
    }
    hex::encode(digest.finalize())
}

pub(super) fn is_indexer_inbox_temp_name(name: &str) -> bool {
    let mut parts = name.split('.');
    let Some(id) = parts.next() else {
        return false;
    };
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && matches!(parts.next(), Some("nzb" | "json"))
        && parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && parts.next() == Some("tmp")
        && parts.next().is_none()
}

pub(super) fn indexer_inbox_entries_locked(d: &Daemon) -> std::io::Result<IndexerInboxUsage> {
    let dir = indexer_inbox_dir(d);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(IndexerInboxUsage::default());
        }
        Err(error) => return Err(error),
    };
    let mut usage = IndexerInboxUsage::default();
    let mut removed_orphan = false;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        match path.extension().and_then(|value| value.to_str()) {
            Some("json" | "hold" | "capacity" | "catalog") => {
                usage.items = usage.items.saturating_add(1);
                usage.artifacts = usage.artifacts.saturating_add(1);
            }
            Some("nzb") => {
                // The metadata rename is the commit point. A crash after the
                // raw rename, or after marker removal during settlement, can
                // leave an uncommitted raw orphan. In-process callers hold
                // INDEXER_INBOX_IO; the age grace protects a second process.
                if path.with_extension("json").is_file()
                    || path.with_extension("hold").is_file()
                    || path.with_extension("capacity").is_file()
                    || path.with_extension("catalog").is_file()
                {
                    usage.artifacts = usage.artifacts.saturating_add(1);
                    usage.bytes = usage.bytes.saturating_add(metadata.len());
                } else if metadata.modified().ok().is_some_and(|modified| {
                    modified
                        .elapsed()
                        .is_ok_and(|age| age.as_secs() >= INDEXER_ORPHAN_GRACE_SECS)
                }) {
                    std::fs::remove_file(path)?;
                    removed_orphan = true;
                } else {
                    // A second process may be between the raw and marker
                    // renames. Count the fresh file against the cap and wait
                    // through a generous grace before treating it as stale.
                    usage.artifacts = usage.artifacts.saturating_add(1);
                    usage.bytes = usage.bytes.saturating_add(metadata.len());
                }
            }
            Some("tmp")
                if path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(is_indexer_inbox_temp_name) =>
            {
                // write_atomic removes its temp on ordinary errors. A strict
                // inbox temp can therefore survive only a process crash, but
                // another process does not share our mutex. Count fresh temps
                // and reclaim only files older than the cross-process grace.
                if metadata.modified().ok().is_some_and(|modified| {
                    modified
                        .elapsed()
                        .is_ok_and(|age| age.as_secs() >= INDEXER_ORPHAN_GRACE_SECS)
                }) {
                    std::fs::remove_file(path)?;
                    removed_orphan = true;
                } else {
                    usage.artifacts = usage.artifacts.saturating_add(1);
                    usage.bytes = usage.bytes.saturating_add(metadata.len());
                }
            }
            _ => {}
        }
    }
    if removed_orphan {
        let _ = crate::smart::sync_dir(&dir);
    }
    Ok(usage)
}

pub(super) fn indexer_inbox_capacity_held_locked(d: &Daemon) -> std::io::Result<bool> {
    let dir = indexer_inbox_dir(d);
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    for entry in entries {
        if entry?.path().extension().and_then(|value| value.to_str()) == Some("capacity") {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Why `indexer_inbox_has_room` said no. Four different situations used to
/// collapse into that one bool, and from outside the confirm lane they were
/// indistinguishable: a routine same-process lock handoff, a real capacity
/// hold, and two flavours of "the inbox directory could not even be read"
/// all wore the same "full or unavailable" sentence. Measured on the live
/// daemon (2 Sep 2026): 14 stand-downs across ~110 minutes with no test or
/// competing daemon running nearby - see
/// research/CONFIRM-LANE-YIELD-PREWINDOW-2026-09-02.md sections 1b/1c for
/// the measurement and why the leading "full" and "test interference"
/// hypotheses were both ruled out before this landed.
pub enum IndexerInboxRoom {
    Available,
    /// The advisory `.lock` file is held by another open file description.
    /// `try_lock` contends within one process too - each `OpenOptions::open`
    /// call gets its own file description - so this daemon's own harvest
    /// worker draining the inbox is the ordinary holder, not necessarily a
    /// second daemon. Self-clearing.
    Busy,
    /// A real cap is holding: a durable `.capacity` marker, or the item /
    /// artifact / byte count itself. Carries the numbers so a log line can
    /// say which cap and how close.
    AtCapacity(String),
    /// `ensure_indexer_inbox_dir`, the process-lock open, the capacity-marker
    /// scan, or the entry scan hit a real io error. Previously folded into
    /// "false" (via `unwrap_or(true)` and `Result::is_ok_and`) and read
    /// identically to a genuine capacity hold.
    Unreadable(std::io::Error),
}

/// Whether another commercial acquisition may start without risking an
/// unbounded local backlog. This is checked before spending an external query;
/// the stage function repeats the byte/count check with the actual body.
pub fn indexer_inbox_room(d: &Daemon) -> IndexerInboxRoom {
    let _io = INDEXER_INBOX_IO.lock_ok();
    let dir = match ensure_indexer_inbox_dir(d) {
        Ok(dir) => dir,
        Err(error) => return IndexerInboxRoom::Unreadable(error),
    };
    let _process = match lock_indexer_inbox_process(&dir) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            return IndexerInboxRoom::Busy;
        }
        Err(error) => return IndexerInboxRoom::Unreadable(error),
    };
    match indexer_inbox_capacity_held_locked(d) {
        Ok(true) => {
            return IndexerInboxRoom::AtCapacity(
                "a durable logical-capacity marker is held".to_string(),
            );
        }
        Ok(false) => {}
        Err(error) => return IndexerInboxRoom::Unreadable(error),
    }
    match indexer_inbox_entries_locked(d) {
        Ok(usage) => {
            if usage.items < INDEXER_INBOX_CAP
                && usage.artifacts.saturating_add(2) <= INDEXER_INBOX_ARTIFACT_CAP
                && usage.bytes.saturating_add(crate::FETCH_MAX_BYTES) <= INDEXER_INBOX_BYTES_CAP
            {
                IndexerInboxRoom::Available
            } else {
                IndexerInboxRoom::AtCapacity(format!(
                    "items {}/{INDEXER_INBOX_CAP}, artifacts {}/{INDEXER_INBOX_ARTIFACT_CAP}, bytes {}/{INDEXER_INBOX_BYTES_CAP}",
                    usage.items, usage.artifacts, usage.bytes
                ))
            }
        }
        Err(error) => IndexerInboxRoom::Unreadable(error),
    }
}

/// Bool projection of [`indexer_inbox_room`] for tests that only need
/// yes/no. Production code wants the reason and calls `indexer_inbox_room`
/// directly (the confirm lane, for its log line).
#[cfg(test)]
pub(super) fn indexer_inbox_has_room(d: &Daemon) -> bool {
    matches!(indexer_inbox_room(d), IndexerInboxRoom::Available)
}

/// Publish fetched commercial evidence before relying on the index writer.
/// The raw file lands first and the small metadata file is the commit marker.
/// A crash can therefore leave an ignorable raw orphan, never metadata that
/// points at a partially written NZB.
pub fn stage_indexer_seed(
    d: &Daemon,
    raw: &[u8],
    name: &str,
    category: &str,
    posted: i64,
    bytes: u64,
) -> std::io::Result<String> {
    let _io = INDEXER_INBOX_IO.lock_ok();
    let dir = ensure_indexer_inbox_dir(d)?;
    let _process = lock_indexer_inbox_process(&dir)?;
    if raw.len() as u64 > crate::FETCH_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "commercial NZB exceeds the fetch ceiling",
        ));
    }
    let guid = nzb_sha(raw);
    nzbkit::index::validate_nzb_seed_spec(nzbkit::index::NzbSeedSpec {
        source: INDEXER_SOURCE,
        source_guid: &guid,
        name,
        category,
        posted,
        bytes,
    })
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let id = indexer_inbox_id(&guid, name, category);
    let (meta_path, raw_path) = indexer_inbox_paths(d, &id);
    let hold_path = meta_path.with_extension("hold");
    let capacity_path = meta_path.with_extension("capacity");
    let catalog_path = meta_path.with_extension("catalog");
    if hold_path.is_file() || capacity_path.is_file() || catalog_path.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "commercial NZB seed is quarantined",
        ));
    }
    let usage = indexer_inbox_entries_locked(d)?;
    let already_present = meta_path.is_file();
    let new_artifacts = usize::from(!raw_path.exists()) + usize::from(!meta_path.exists());
    let old_raw_bytes = std::fs::metadata(&raw_path)
        .map(|meta| meta.len())
        .unwrap_or(0);
    if !already_present && usage.items >= INDEXER_INBOX_CAP {
        return Err(std::io::Error::other("commercial NZB seed inbox is full"));
    }
    if usage.artifacts.saturating_add(new_artifacts) > INDEXER_INBOX_ARTIFACT_CAP {
        return Err(std::io::Error::other(
            "commercial NZB seed inbox artifact cap reached",
        ));
    }
    if usage
        .bytes
        .saturating_sub(old_raw_bytes)
        .saturating_add(raw.len() as u64)
        > INDEXER_INBOX_BYTES_CAP
    {
        return Err(std::io::Error::other(
            "commercial NZB seed inbox byte cap reached",
        ));
    }
    let meta = IndexerInboxMeta {
        version: 1,
        guid,
        name: name.to_string(),
        category: category.to_string(),
        posted,
        bytes,
    };
    let encoded = serde_json::to_vec(&meta)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    crate::persist::write_atomic(&raw_path, raw)?;
    if let Err(error) = crate::persist::write_atomic(&meta_path, &encoded) {
        // Preserve a prior committed item on an idempotent restage. For a
        // brand-new item there is no marker, so the raw rename is only an
        // orphan and can be removed immediately.
        if !already_present {
            let _ = std::fs::remove_file(&raw_path);
        }
        return Err(error);
    }
    // Generic state persistence treats directory fsync as best effort. This
    // lane may retire a paid one-shot pick once staging returns, so require
    // both published names to survive a power cut before reporting success.
    crate::smart::sync_dir(&dir)?;
    if let Some(parent) = dir.parent() {
        // Always repeat the parent sync here. Another process may have died
        // after mkdir but before publishing the directory entry durably.
        crate::smart::sync_dir(parent)?;
    }
    Ok(id)
}

#[derive(Debug)]
pub(super) enum IndexerInboxError {
    Invalid {
        /// BOXED, and it has to stay boxed - this is a WINDOWS-ONLY
        /// clippy red that no host gate can see (2 Sep 2026). The
        /// fingerprint is two `Option<{u64, [u8; 32]}>` = 96 bytes, and
        /// `PathBuf` is 24 bytes on unix but 32 on windows (`Wtf8Buf`
        /// carries an extra `is_known_utf8` flag). That puts this
        /// variant just under `result_large_err`'s 128-byte threshold
        /// on the host and just over it on
        /// `x86_64-pc-windows-gnu`, so `cargo clippy` here passes and
        /// the `windows-clippy` CI job fails. Unboxing it to tidy up
        /// reds main for whoever pushes next; the local probe is the
        /// `--target x86_64-pc-windows-gnu` clippy line in CONTRIBUTING.md.
        fingerprint: Option<Box<IndexerInboxFingerprint>>,
        meta_path: PathBuf,
    },
    Transient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IndexerInboxFileFingerprint {
    bytes: u64,
    sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IndexerInboxFingerprint {
    meta: Option<IndexerInboxFileFingerprint>,
    raw: Option<IndexerInboxFileFingerprint>,
}

pub(super) fn indexer_inbox_file_fingerprint(
    path: &Path,
    cap: u64,
) -> std::io::Result<Option<IndexerInboxFileFingerprint>> {
    use sha2::Digest as _;

    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let bytes = metadata.len();
    let mut digest = sha2::Sha256::new();
    digest.update(bytes.to_le_bytes());
    if bytes <= cap {
        let mut file = std::fs::File::open(path)?;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
    }
    Ok(Some(IndexerInboxFileFingerprint {
        bytes,
        sha256: digest.finalize().into(),
    }))
}

pub(super) fn indexer_inbox_fingerprint(
    meta_path: &Path,
) -> std::io::Result<IndexerInboxFingerprint> {
    Ok(IndexerInboxFingerprint {
        meta: indexer_inbox_file_fingerprint(meta_path, INDEXER_META_CAP)?,
        raw: indexer_inbox_file_fingerprint(
            &meta_path.with_extension("nzb"),
            crate::FETCH_MAX_BYTES,
        )?,
    })
}

pub(super) fn invalid_indexer_inbox(meta_path: &Path) -> IndexerInboxError {
    IndexerInboxError::Invalid {
        meta_path: meta_path.to_path_buf(),
        fingerprint: indexer_inbox_fingerprint(meta_path).ok().map(Box::new),
    }
}

pub(super) fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, IndexerInboxError> {
    let file = std::fs::File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            IndexerInboxError::Invalid {
                meta_path: path.to_path_buf(),
                fingerprint: None,
            }
        } else {
            IndexerInboxError::Transient
        }
    })?;
    let mut bytes = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| IndexerInboxError::Transient)?;
    if bytes.len() as u64 > cap {
        return Err(IndexerInboxError::Invalid {
            meta_path: path.to_path_buf(),
            fingerprint: None,
        });
    }
    Ok(bytes)
}

pub(super) fn next_indexer_inbox(
    d: &Daemon,
) -> Result<Option<IndexerInboxPrepared>, IndexerInboxError> {
    let _io = INDEXER_INBOX_IO.lock_ok();
    let dir = indexer_inbox_dir(d);
    if !dir.exists() {
        return Ok(None);
    }
    let _process = lock_indexer_inbox_process(&dir).map_err(|_| IndexerInboxError::Transient)?;
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(IndexerInboxError::Transient),
    };
    secure_indexer_inbox_dir(&dir).map_err(|_| IndexerInboxError::Transient)?;
    let mut metadata_paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| IndexerInboxError::Transient)?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            metadata_paths.push(path);
        }
    }
    metadata_paths.sort();
    let Some(meta_path) = metadata_paths.into_iter().next() else {
        return Ok(None);
    };
    let Some(id) = meta_path.file_stem().and_then(|value| value.to_str()) else {
        return Err(invalid_indexer_inbox(&meta_path));
    };
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_indexer_inbox(&meta_path));
    }
    let id = id.to_string();
    let (_, raw_path) = indexer_inbox_paths(d, &id);
    let encoded = read_capped(&meta_path, INDEXER_META_CAP).map_err(|error| match error {
        IndexerInboxError::Invalid { .. } => IndexerInboxError::Invalid {
            meta_path: meta_path.clone(),
            fingerprint: indexer_inbox_fingerprint(&meta_path).ok().map(Box::new),
        },
        IndexerInboxError::Transient => IndexerInboxError::Transient,
    })?;
    let meta: IndexerInboxMeta =
        serde_json::from_slice(&encoded).map_err(|_| invalid_indexer_inbox(&meta_path))?;
    if meta.version != 1 || indexer_inbox_id(&meta.guid, &meta.name, &meta.category) != id {
        return Err(invalid_indexer_inbox(&meta_path));
    }
    nzbkit::index::validate_nzb_seed_spec(nzbkit::index::NzbSeedSpec {
        source: INDEXER_SOURCE,
        source_guid: &meta.guid,
        name: &meta.name,
        category: &meta.category,
        posted: meta.posted,
        bytes: meta.bytes,
    })
    .map_err(|_| invalid_indexer_inbox(&meta_path))?;
    let raw = read_capped(&raw_path, crate::FETCH_MAX_BYTES).map_err(|error| match error {
        IndexerInboxError::Invalid { .. } => IndexerInboxError::Invalid {
            meta_path: meta_path.clone(),
            fingerprint: indexer_inbox_fingerprint(&meta_path).ok().map(Box::new),
        },
        IndexerInboxError::Transient => IndexerInboxError::Transient,
    })?;
    if nzb_sha(&raw) != meta.guid {
        return Err(invalid_indexer_inbox(&meta_path));
    }
    drop(_io);
    let nzb = nzbkit::nzb::Nzb::parse(&raw).map_err(|_| invalid_indexer_inbox(&meta_path))?;
    drop(raw);
    let seed = nzbkit::index::NzbSeedPrepared::from_nzb(&nzb).map_err(|error| {
        if terminal_seed_error(&error) {
            invalid_indexer_inbox(&meta_path)
        } else {
            IndexerInboxError::Transient
        }
    })?;
    Ok(Some(IndexerInboxPrepared {
        id,
        meta_path,
        raw_path,
        meta,
        seed,
    }))
}

pub(super) fn remove_indexer_inbox(
    meta_path: &Path,
    raw_path: Option<&Path>,
) -> std::io::Result<()> {
    let _io = INDEXER_INBOX_IO.lock_ok();
    let dir = meta_path.parent();
    let _process = match dir {
        Some(dir) if dir.exists() => Some(lock_indexer_inbox_process(dir)?),
        _ => None,
    };
    match std::fs::remove_file(meta_path) {
        Ok(()) => {
            if let Some(dir) = dir {
                let _ = crate::smart::sync_dir(dir);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if let Some(raw_path) = raw_path {
        match std::fs::remove_file(raw_path) {
            Ok(()) => {
                if let Some(dir) = raw_path.parent() {
                    let _ = crate::smart::sync_dir(dir);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(super) fn move_indexer_inbox_marker_locked(
    meta_path: &Path,
    extension: &str,
) -> std::io::Result<PathBuf> {
    let hold_path = meta_path.with_extension(extension);
    if hold_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "commercial NZB seed quarantine already exists",
        ));
    }
    std::fs::rename(meta_path, &hold_path)?;
    if let Some(dir) = hold_path.parent() {
        crate::smart::sync_dir(dir)?;
    }
    Ok(hold_path)
}

pub(super) fn move_indexer_inbox_marker(
    meta_path: &Path,
    extension: &str,
) -> std::io::Result<PathBuf> {
    let _io = INDEXER_INBOX_IO.lock_ok();
    let _process = match meta_path.parent() {
        Some(dir) if dir.exists() => Some(lock_indexer_inbox_process(dir)?),
        _ => None,
    };
    move_indexer_inbox_marker_locked(meta_path, extension)
}

pub(super) fn hold_invalid_indexer_inbox_if_unchanged(
    meta_path: &Path,
    expected: Option<&IndexerInboxFingerprint>,
) -> std::io::Result<Option<PathBuf>> {
    let Some(expected) = expected else {
        return Ok(None);
    };
    let _io = INDEXER_INBOX_IO.lock_ok();
    let _process = match meta_path.parent() {
        Some(dir) if dir.exists() => Some(lock_indexer_inbox_process(dir)?),
        _ => None,
    };
    if indexer_inbox_fingerprint(meta_path)? != *expected {
        return Ok(None);
    }
    move_indexer_inbox_marker_locked(meta_path, "hold").map(Some)
}

pub(super) fn hold_indexer_inbox(meta_path: &Path) -> std::io::Result<PathBuf> {
    move_indexer_inbox_marker(meta_path, "hold")
}

pub(super) fn capacity_hold_indexer_inbox(meta_path: &Path) -> std::io::Result<PathBuf> {
    move_indexer_inbox_marker(meta_path, "capacity")
}

/// A capacity verdict belongs to one index generation. An explicit index wipe
/// starts a fresh proof ledger, so make every retained marker live again while
/// the wipe still owns the index lock. Raw NZBs never move.
pub fn reactivate_indexer_generation_holds(d: &Daemon) -> std::io::Result<usize> {
    let _io = INDEXER_INBOX_IO.lock_ok();
    let dir = indexer_inbox_dir(d);
    if !dir.exists() {
        return Ok(0);
    }
    let _process = lock_indexer_inbox_process(&dir)?;
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut held = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("capacity" | "catalog")
        ) {
            let live = path.with_extension("json");
            if live.exists() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "commercial NZB seed live marker already exists",
                ));
            }
            held.push((path, live));
        }
    }
    held.sort();
    let mut moved = 0usize;
    let result: std::io::Result<()> = (|| {
        for (capacity, live) in held {
            std::fs::rename(capacity, live)?;
            moved += 1;
        }
        Ok(())
    })();
    if moved > 0 {
        crate::smart::sync_dir(&dir)?;
    }
    result?;
    Ok(moved)
}

pub(super) fn tick_indexer_inbox(
    d: &Arc<Daemon>,
    index_pass_gate: Option<&tokio::sync::Mutex<()>>,
    item: IndexerInboxPrepared,
    report: &mut HarvestReport,
) {
    let _index_pass = if let Some(gate) = index_pass_gate {
        match gate.try_lock() {
            Ok(guard) => Some(guard),
            Err(_) => {
                report.deferred += 1;
                report.blocked = true;
                return;
            }
        }
    } else {
        None
    };
    if !d.db_maintenance_ok() || d.index_jobs_active.load(Ordering::Acquire) > 0 {
        report.deferred += 1;
        report.blocked = true;
        return;
    }
    let now = epoch_secs() as i64;
    let selection_era = d.index_era();
    let outcome = d.try_with_index_mut_retiring_ddl(|index| {
        if d.index_era() != selection_era
            || d.index_jobs_active.load(Ordering::Acquire) > 0
            || d.offline.load(Ordering::Relaxed)
            || d.index_paused.load(Ordering::Relaxed)
            || !d.index_db_wanted()
        {
            return None;
        }
        let settled = (|| {
            let stored = index.nzb_seed_store_prepared_durable(
                nzbkit::index::NzbSeedSpec {
                    source: INDEXER_SOURCE,
                    source_guid: &item.meta.guid,
                    name: &item.meta.name,
                    category: &item.meta.category,
                    posted: item.meta.posted,
                    bytes: item.meta.bytes,
                },
                &item.seed,
                now,
            )?;
            let replay = index.nzb_seed_reconcile_set_guarded(stored.set_id, now, || {
                d.index_jobs_active.load(Ordering::Acquire) == 0
                    && !d.offline.load(Ordering::Relaxed)
                    && !d.index_paused.load(Ordering::Relaxed)
                    && d.index_db_wanted()
            })?;
            Ok::<_, nzbkit::index::NzbSeedError>((stored, replay))
        })();
        Some(match settled {
            Ok((_stored, Some(stats))) => IndexerInboxSettle::Stored {
                stats,
                // Keep settlement in the same index-lock generation as the
                // durable proof commit. A wipe is therefore ordered wholly
                // before this attempt (which leaves the marker live) or wholly
                // after it, never between commit and spool retirement.
                cleanup: remove_indexer_inbox(&item.meta_path, Some(&item.raw_path)),
            },
            Ok((_stored, None)) => IndexerInboxSettle::Deferred,
            Err(nzbkit::index::NzbSeedError::Capacity(reason)) => IndexerInboxSettle::Capacity {
                reason,
                hold: capacity_hold_indexer_inbox(&item.meta_path),
            },
            Err(error) if matches!(error, nzbkit::index::NzbSeedError::Corrupt(_)) => {
                IndexerInboxSettle::CatalogCorrupt {
                    hold: move_indexer_inbox_marker(&item.meta_path, "catalog"),
                    error,
                }
            }
            Err(error) if terminal_seed_error(&error) => IndexerInboxSettle::Terminal {
                hold: hold_indexer_inbox(&item.meta_path),
                error,
            },
            Err(error) => IndexerInboxSettle::Failed(error),
        })
    });
    match outcome {
        Some(IndexerInboxSettle::Stored { stats, cleanup }) => {
            report.stored += 1;
            report.named += stats.claims_applied + stats.claims_replaced;
            if let Err(error) = cleanup {
                report.deferred += 1;
                report.blocked = true;
                warn!(target: "seed", "commercial NZB seed cleanup deferred: {error}");
            }
            if report.named > 0 {
                info!(
                    target: "seed",
                    "commercial exact NZB seed named {} release(s)",
                    report.named
                );
            } else if stats.sets_fragmented > 0 {
                info!(
                    target: "seed",
                    "commercial exact NZB seed {} recorded a fragmented collection",
                    item.id
                );
            }
        }
        Some(IndexerInboxSettle::Deferred) => {
            report.stored += 1;
            report.deferred += 1;
            report.blocked = true;
        }
        Some(IndexerInboxSettle::Capacity { reason, hold }) => {
            // The configured proof budget is a durable administrative limit,
            // not a transient writer failure. Move the marker out of the live
            // queue while retaining the raw NZB for a deliberate later import;
            // otherwise the first lexicographic item blocks every seed behind
            // it forever.
            match hold {
                Ok(hold_path) => warn!(
                    target: "seed",
                    "held commercial NZB seed and paused paid acquisition at {} after reaching {reason}",
                    hold_path.display()
                ),
                Err(hold_error) => {
                    report.deferred += 1;
                    report.blocked = true;
                    warn!(
                        target: "seed",
                        "commercial NZB seed capacity hold deferred: {hold_error}"
                    );
                }
            }
        }
        Some(IndexerInboxSettle::CatalogCorrupt { error, hold }) => {
            report.invalid += 1;
            match hold {
                Ok(hold_path) => warn!(
                    target: "seed",
                    "held commercial NZB seed at {} for replay after index repair: {error}",
                    hold_path.display()
                ),
                Err(hold_error) => {
                    report.deferred += 1;
                    report.blocked = true;
                    warn!(
                        target: "seed",
                        "commercial NZB seed catalog hold deferred: {hold_error}"
                    );
                }
            }
        }
        Some(IndexerInboxSettle::Terminal { error, hold }) => {
            report.invalid += 1;
            match hold {
                Ok(hold_path) => warn!(
                    target: "seed",
                    "quarantined invalid commercial NZB seed at {}: {error}",
                    hold_path.display()
                ),
                Err(hold_error) => {
                    report.deferred += 1;
                    report.blocked = true;
                    warn!(
                        target: "seed",
                        "commercial NZB seed quarantine deferred: {hold_error}"
                    );
                }
            }
        }
        Some(IndexerInboxSettle::Failed(error)) => {
            report.deferred += 1;
            report.blocked = true;
            warn!(target: "seed", "commercial NZB seed deferred: {error}");
        }
        None => {
            report.deferred += 1;
            report.blocked = true;
        }
    }
}
