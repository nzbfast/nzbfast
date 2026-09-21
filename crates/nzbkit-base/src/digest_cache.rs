//! The validated digest cache: a per-user record of a large file's
//! whole-file MD5 beside its BLAKE3, so a repeat create or a whole-file
//! (`--slow`) verify of an UNCHANGED file can skip the MD5 chain - once a
//! multi-threaded BLAKE3 pass has re-proved the content, and never on the
//! strength of a length or a timestamp.
//!
//! Behind the `digest-cache` feature; without it, `digest_cache_off.rs`
//! stands in, an inert stub with the same crate-internal surface, so the
//! create and verify paths never branch on the feature themselves.
//!
//! The MD5 chain is the one sequential cost of a single-file create: one
//! core over every byte, ~11 s of an ~12 s create of 8.86 GB. BLAKE3 is a
//! tree hash and runs on every core, so re-proving the same bytes costs
//! 0.4-1.0 s on eight threads, and a repeat create measured -46% (EPYC)
//! and -50% (Core Ultra) wall with byte-identical output (Codex's study,
//! 13 Sep 2026). Design, threat model and the decisions taken on 15 Sep
//! 2026: `research/DESIGN-DIGEST-CACHE-2026-09-15.md` (private tree).
//!
//! # The one rule
//!
//! The whole-file MD5 an engine pass uses comes from the chain over the
//! bytes that pass read, or from a record THIS store wrote whose BLAKE3
//! matched the bytes that pass read. Nothing in this module accepts an MD5
//! from outside: no constructor takes one, and there is no option or
//! environment variable that supplies one. `MemberDigest` is the only
//! thing that hands a record's MD5 to the engine, and it does so only
//! after the BLAKE3 of the open member matched the record's.
//!
//! A record pairs two digests computed over ONE byte sequence, so it is
//! true of that sequence; a file whose BLAKE3 matches IS that sequence
//! (second preimage is 2^128 work), so its MD5 is the recorded one.
//!
//! # Where records live, and why not beside the file
//!
//! In a per-user cache directory ([`default_dir`]), one 128-byte file per
//! record, named by the member's file identity (device and inode, or
//! volume serial and file index). A sidecar file or an extended attribute
//! TRAVELS with a file - through a copy, an archive, a download - and a
//! record that arrives beside a file is exactly the "trusted MD5 on an
//! arbitrary file" this module must never allow. Keyed by identity, a
//! rename keeps its record and a replace-by-rename is a clean miss.
//!
//! # Opt-in, and only by a front end
//!
//! Nothing reads a store until an entry point [`publish`]es one:
//! `parfast --digest-cache` and the parfast app's setting. The daemon never
//! does, so every daemon create and verify is unchanged by this module.
//!
//! # Failure is always a miss
//!
//! A record that is absent, torn, of another format version, or whose
//! BLAKE3 no longer matches is a miss, and the chain runs as it always
//! did. A store that cannot be read or written turns the cache off for
//! that member. Nothing here can fail a create or a verify that would
//! otherwise have succeeded; the one error it raises is a member that
//! changed while a record for it was being consumed, which is the same
//! refusal the create already makes for a member that changed under it.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

pub(crate) use crate::disk::Identity;

/// Members under this many bytes are never looked up or enrolled: their
/// chain is well under half a second on any MD5 core in the fleet, and a
/// many-file set would otherwise fill the store with records worth
/// nothing. `NZBFAST_DIGEST_CACHE_FLOOR` (bytes) overrides it, for the
/// tests and the measurement rounds.
pub const DEFAULT_FLOOR: u64 = 256 << 20;

/// Records kept before the least recently used are pruned. At 128 bytes
/// each the store never passes ~520 KB.
pub const MAX_RECORDS: usize = 4096;

const RECORD_LEN: usize = 128;
/// The bytes the trailing checksum covers: everything before it.
const CHECKED_LEN: usize = 96;
const MAGIC: [u8; 8] = *b"PFDIGEST";
const FORMAT_VERSION: u32 = 1;

/// Record flag: enrolled by a create's scan.
pub(crate) const FLAG_CREATE: u32 = 1;
/// Record flag: enrolled by a whole-file verify.
pub(crate) const FLAG_VERIFY: u32 = 2;

/// BLAKE3 is fed in pieces of this size so a cancel reaches the helper
/// within one piece. A power of two, so every piece boundary is a subtree
/// boundary and `update_rayon` loses no parallelism at it.
const HASH_PIECE: usize = 256 << 20;
/// Threads for a validation: the whole point is to finish in about a
/// second beside a create, and past eight the memory bus is the limit.
const VALIDATE_THREADS: usize = 8;
/// Threads for an enrolment. It runs beside a whole chain and is MEANT to
/// finish before it, and on every part measured it does - at ONE thread as
/// well as at this one, which is why this number buys margin rather than
/// wall.
///
/// Measured 16 Sep 2026, an `ENROL_THREADS` ladder on the 8.86 GB
/// single-member fixture over four parts and three silicon families
/// (research/DIGEST-CACHE-ENROL-THREADS-2026-09-16.md; the Apple arms and
/// the correction are sections 8 and 9). The second thread is real work: the
/// enrolment's OWN finish goes 6.31 s -> 3.42 s on an M1 Ultra and
/// 4.52 s -> 2.38 s on an M3 Ultra, 1.84x and 1.90x, near-linear on to eight.
/// It buys no create wall anywhere that matters, because at one thread the
/// enrolment is already done inside the chain's window on every part: 41% of
/// it on the M3, 46% on the M1, 66% on the Core Ultra 9, and ahead of the
/// chain on the Snapdragon too. So all
/// five rungs land inside each box's own leg-to-leg noise, and on the Core
/// Ultra 9, where chain and enrolment split one saturated ~2.1 GB/s read
/// budget, a WIDER enrolment is strictly worse: its medians climb monotonically
/// with the rung (9.184 / 9.242 / 9.281 / 9.370 s) because every extra thread
/// is taken from the chain.
///
/// So the +2% enrol gate that the Core Ultra 9 misses at +2.8-3.3%
/// (research/PARFAST-DIGEST-CACHE-SMALL-CORE-2026-09-16.md section 5) is NOT
/// fixed by moving this: every rung misses it there, and the miss is
/// structural rather than tunable.
///
/// It stays at 2 for the MARGIN, which is the only thing the rung actually
/// changes. At this value the enrolment occupies 21-48% of the chain's window
/// across the three parts measured; at one thread it occupies 41-66%. The
/// tightest is the Core Ultra 9 at 66.4%, tightest because its second thread
/// buys the least (1.39x, against 1.84x and 1.90x on Apple silicon) while its
/// MD5 chain is the fleet's fastest at 0.990 GB/s: a part with a chain that
/// fast and a flatter BLAKE3 ladder would put the enrolment ON the critical
/// path at one thread, where it costs whole seconds instead of nothing.
///
/// THE COST OF THAT CHOICE, because it is not free and the file records it as
/// a judgement rather than a forced move: rung 1 is about 1.3% of create wall
/// faster on the Core Ultra 9 and costs nothing on the Macs, and it lets
/// `blake3_of` skip building a rayon pool. What it does not buy is the gate -
/// rung 1 misses the +2% enrol gate there too (+1.67%, +2.66%, +1.66%) - so
/// the trade is 1.3% of one already-failing create against half the margin on
/// the fleet's tightest part. Section 9 of the round has both sides.
const ENROL_THREADS: usize = 2;

/// A store of validated digest records, at one directory.
pub struct DigestCache {
    dir: PathBuf,
    floor: u64,
    stats: Stats,
}

#[derive(Default)]
struct Stats {
    hits: AtomicU64,
    misses: AtomicU64,
    stale: AtomicU64,
    corrupt: AtomicU64,
    enrolled: AtomicU64,
    store_errors: AtomicU64,
}

/// What a store has done since it was built, for the route marker and the
/// tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DigestStats {
    /// A record validated and its MD5 was used.
    pub hits: u64,
    /// No usable record: none, or one for a different length.
    pub misses: u64,
    /// A record whose BLAKE3 no longer matched the file: deleted, and
    /// replaced from the pass that found it.
    pub stale: u64,
    /// A record that failed its checksum, magic or version: deleted.
    pub corrupt: u64,
    /// Records written.
    pub enrolled: u64,
    /// The store could not be read or written.
    pub store_errors: u64,
}

impl std::fmt::Debug for DigestCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DigestCache")
            .field("dir", &self.dir)
            .field("floor", &self.floor)
            .field("stats", &self.stats())
            .finish()
    }
}

impl DigestCache {
    /// A store at `dir`, created on first write. The floor is
    /// [`DEFAULT_FLOOR`] unless `NZBFAST_DIGEST_CACHE_FLOOR` names another.
    pub fn new(dir: impl Into<PathBuf>) -> DigestCache {
        let floor = std::env::var("NZBFAST_DIGEST_CACHE_FLOOR")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_FLOOR);
        DigestCache {
            dir: dir.into(),
            floor,
            stats: Stats::default(),
        }
    }

    /// The store at [`default_dir`], or `None` where this platform or
    /// environment names no per-user cache directory.
    pub fn at_default_location() -> Option<DigestCache> {
        default_dir().map(DigestCache::new)
    }

    /// The same store with another size floor.
    pub fn with_floor(mut self, floor: u64) -> DigestCache {
        self.floor = floor;
        self
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn floor(&self) -> u64 {
        self.floor
    }

    pub fn stats(&self) -> DigestStats {
        let s = &self.stats;
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        DigestStats {
            hits: load(&s.hits),
            misses: load(&s.misses),
            stale: load(&s.stale),
            corrupt: load(&s.corrupt),
            enrolled: load(&s.enrolled),
            store_errors: load(&s.store_errors),
        }
    }

    /// Delete every record (and any temp file a crashed writer left).
    /// Returns how many files went. A store that was never created is
    /// already clear.
    pub fn clear(&self) -> std::io::Result<usize> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let mut removed = 0usize;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if (name.ends_with(".pfd") || name.ends_with(".tmp"))
                && std::fs::remove_file(entry.path()).is_ok()
            {
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn bump(&self, counter: fn(&Stats) -> &AtomicU64) {
        counter(&self.stats).fetch_add(1, Ordering::Relaxed);
    }

    fn record_path(&self, id: &Identity) -> PathBuf {
        self.dir.join(id.record_name())
    }

    fn load(&self, id: &Identity) -> Lookup {
        let path = self.record_path(id);
        match std::fs::read(&path) {
            Ok(bytes) => match Record::decode(&bytes) {
                Some(record) => Lookup::Found(record),
                None => {
                    self.bump(|s| &s.corrupt);
                    let _ = std::fs::remove_file(&path);
                    Lookup::Absent
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && self.can_hold_records() => {
                Lookup::Absent
            }
            Err(_) => {
                self.bump(|s| &s.store_errors);
                Lookup::Unreadable
            }
        }
    }

    /// Whether a record that is not there is a plain miss: the store
    /// directory, or its nearest ancestor that exists (a store not yet
    /// created), is a directory. The error kind alone cannot say. Unix
    /// answers a path through a plain file with ENOTDIR, but Windows answers
    /// it with ERROR_PATH_NOT_FOUND, which std maps to NotFound, the same
    /// kind a fresh store's missing directory gets. Without this a store
    /// that can never be read took part on Windows: it ran an enrolment
    /// beside every member and failed every write (windows-unit, d1515d22).
    fn can_hold_records(&self) -> bool {
        self.dir
            .ancestors()
            .map(|p| {
                if p.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    p
                }
            })
            .find_map(|p| std::fs::metadata(p).ok())
            .is_some_and(|m| m.is_dir())
    }

    fn remove(&self, id: &Identity) {
        let _ = std::fs::remove_file(self.record_path(id));
    }

    /// Mark a record used, for the least-recently-used prune.
    fn touch(&self, id: &Identity) {
        if let Ok(f) = File::options().write(true).open(self.record_path(id)) {
            let _ = f.set_modified(std::time::SystemTime::now());
        }
    }

    /// Write a record by rename, so a reader never sees half of one. No
    /// fsync, deliberately: a torn or lost record fails its checksum or its
    /// validation and is a miss, so durability has no bearing on
    /// correctness, and two writers racing to the rename each leave a true
    /// record.
    fn write(&self, id: &Identity, record: &Record) -> std::io::Result<()> {
        create_private_dir(&self.dir)?;
        let target = self.record_path(id);
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let tmp = self.dir.join(format!(
            ".{}.{}.{}.tmp",
            id.record_name(),
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut options = File::options();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut f = options.open(&tmp)?;
            f.write_all(&record.encode())?;
            drop(f);
            std::fs::rename(&tmp, &target)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// Keep at most `cap` records, dropping the least recently used, and
    /// sweep temp files a crashed writer left more than an hour ago.
    fn prune_to(&self, cap: usize) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let now = std::time::SystemTime::now();
        let mut records: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Ok(modified) = entry.metadata().and_then(|m| m.modified()) else {
                continue;
            };
            if name.ends_with(".pfd") {
                records.push((modified, entry.path()));
            } else if name.starts_with('.')
                && name.ends_with(".tmp")
                && now
                    .duration_since(modified)
                    .is_ok_and(|age| age.as_secs() > 3600)
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        if records.len() <= cap {
            return;
        }
        records.sort();
        let excess = records.len() - cap;
        for (_, path) in records.into_iter().take(excess) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The per-user cache directory records live in:
/// `~/Library/Caches/parfast/digests` on macOS,
/// `$XDG_CACHE_HOME/parfast/digests` (else `~/.cache/...`) on other unix,
/// `%LOCALAPPDATA%\parfast\digests` on Windows. `None` when the variable
/// that names it is unset, empty or relative.
pub fn default_dir() -> Option<PathBuf> {
    fn absolute(var: &str) -> Option<PathBuf> {
        std::env::var_os(var)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    }
    #[cfg(target_os = "macos")]
    let base = absolute("HOME").map(|h| h.join("Library").join("Caches"));
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = absolute("XDG_CACHE_HOME").or_else(|| absolute("HOME").map(|h| h.join(".cache")));
    #[cfg(windows)]
    let base = absolute("LOCALAPPDATA");
    #[cfg(not(any(unix, windows)))]
    let base: Option<PathBuf> = {
        let _ = absolute;
        None
    };
    base.map(|b| b.join("parfast").join("digests"))
}

static PUBLISHED: RwLock<Option<Arc<DigestCache>>> = RwLock::new(None);

/// Publish the store every create and whole-file verify in this process
/// consults, or `None` to turn it off. Process-global for the reason the
/// verify tier (`par2::set_fast_check`) and the pool width are: the engine
/// is reached through free functions with no handle to carry it, and a
/// front end decides once. An entry point should set it in BOTH directions
/// so an in-process caller that runs twice does not inherit the first
/// run's store.
pub fn publish(cache: Option<DigestCache>) {
    *PUBLISHED.write().unwrap_or_else(|p| p.into_inner()) = cache.map(Arc::new);
}

/// The published store, if any.
pub fn published() -> Option<Arc<DigestCache>> {
    PUBLISHED.read().unwrap_or_else(|p| p.into_inner()).clone()
}

#[cfg(test)]
thread_local! {
    /// The store a unit test hands the engine, on the test's own thread.
    /// Unit tests never read [`PUBLISHED`]: this crate's whole lib runs in
    /// ONE process on the one-process line, and a test that published a
    /// store would hand it to every create running beside it.
    static TEST_STORE: std::cell::RefCell<Option<Arc<DigestCache>>> =
        const { std::cell::RefCell::new(None) };
}

/// Give the engine `cache` on this thread until the guard drops.
#[cfg(test)]
pub(crate) fn use_on_this_thread(cache: Arc<DigestCache>) -> TestStoreGuard {
    TEST_STORE.with(|s| *s.borrow_mut() = Some(cache));
    TestStoreGuard(())
}

#[cfg(test)]
pub(crate) struct TestStoreGuard(());

#[cfg(test)]
impl Drop for TestStoreGuard {
    fn drop(&mut self) {
        TEST_STORE.with(|s| *s.borrow_mut() = None);
    }
}

/// The store an engine entry point should use: the published one, or in a
/// unit test the one installed on the calling thread. Read once, on the
/// entry point's own thread, and passed down.
pub(crate) fn active() -> Option<Arc<DigestCache>> {
    #[cfg(test)]
    {
        TEST_STORE.with(|s| s.borrow().clone())
    }
    #[cfg(not(test))]
    {
        published()
    }
}

/// Whether the store holds a record for the member at `path`, `length`
/// bytes long - NOT whether it will validate, which only its BLAKE3 pass
/// can say. The create asks this before choosing its scan: a single member
/// that is about to skip its chain is faster on the split scan, whose block
/// digests run on every core, than on the fused pass, whose reader thread
/// digests every block alone once the chain is gone (measured 15 Sep 2026,
/// 8.86 GB: 3.4-4.4 s split against 11.1-11.7 s fused, a fresh create
/// 12.2-13.1 s; `research/DESIGN-DIGEST-CACHE-2026-09-15.md` section 9b).
pub(crate) fn has_record(cache: Option<&Arc<DigestCache>>, path: &Path, length: u64) -> bool {
    let Some(cache) = cache else {
        return false;
    };
    if length == 0 || length < cache.floor {
        return false;
    }
    let Ok(id) = File::open(path).and_then(|f| Identity::of(&f)) else {
        return false;
    };
    id.length == length && matches!(cache.load(&id), Lookup::Found(r) if r.length == length)
}

impl Identity {
    /// The record's file name in the store.
    fn record_name(&self) -> String {
        format!("{:016x}-{:016x}.pfd", self.volume, self.index)
    }
}

/// One record: the two digests of one byte sequence, and the identity it
/// was taken under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) flags: u32,
    pub(crate) length: u64,
    pub(crate) mtime: i64,
    pub(crate) ctime: i64,
    pub(crate) enrolled_unix_s: u64,
    pub(crate) blake3: [u8; 32],
    pub(crate) md5: [u8; 16],
}

enum Lookup {
    Absent,
    Unreadable,
    Found(Record),
}

impl Record {
    /// The fixed little-endian layout; the last 32 bytes are the BLAKE3 of
    /// the first 96, which catches a torn or edited record (a corruption
    /// check, not a MAC - see the design note for why there is no key).
    fn encode(&self) -> [u8; RECORD_LEN] {
        let mut b = [0u8; RECORD_LEN];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        b[12..16].copy_from_slice(&self.flags.to_le_bytes());
        b[16..24].copy_from_slice(&self.length.to_le_bytes());
        b[24..32].copy_from_slice(&self.mtime.to_le_bytes());
        b[32..40].copy_from_slice(&self.ctime.to_le_bytes());
        b[40..48].copy_from_slice(&self.enrolled_unix_s.to_le_bytes());
        b[48..80].copy_from_slice(&self.blake3);
        b[80..96].copy_from_slice(&self.md5);
        let sum = blake3::hash(&b[..CHECKED_LEN]);
        b[CHECKED_LEN..].copy_from_slice(sum.as_bytes());
        b
    }

    fn decode(b: &[u8]) -> Option<Record> {
        if b.len() != RECORD_LEN
            || blake3::hash(&b[..CHECKED_LEN]).as_bytes()[..] != b[CHECKED_LEN..]
            || b[0..8] != MAGIC
            || u32::from_le_bytes(b[8..12].try_into().ok()?) != FORMAT_VERSION
        {
            return None;
        }
        let u64_at =
            |at: usize| -> Option<u64> { Some(u64::from_le_bytes(b[at..at + 8].try_into().ok()?)) };
        Some(Record {
            flags: u32::from_le_bytes(b[12..16].try_into().ok()?),
            length: u64_at(16)?,
            mtime: u64_at(24)? as i64,
            ctime: u64_at(32)? as i64,
            enrolled_unix_s: u64_at(40)?,
            blake3: b[48..80].try_into().ok()?,
            md5: b[80..96].try_into().ok()?,
        })
    }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// BLAKE3 of `length` bytes of `file`, off a mapping of it, on `threads`
/// threads of a pool of its own (never the process's global rayon pool,
/// whose workers a create's fold may be holding). `Ok(None)` when `stop`
/// was raised before it finished.
fn blake3_of(
    file: &File,
    length: u64,
    threads: usize,
    stop: &AtomicBool,
) -> std::io::Result<Option<[u8; 32]>> {
    let Some(map) = crate::par2gen::MappedMember::from_file(file.try_clone()?, length)? else {
        return Ok(Some(*blake3::hash(&[]).as_bytes()));
    };
    map.prefetch();
    let pool = if threads > 1 {
        Some(
            rayon_core::ThreadPoolBuilder::new()
                .num_threads(threads)
                .thread_name(|i| format!("digest-blake3-{i}"))
                .build()
                .map_err(std::io::Error::other)?,
        )
    } else {
        None
    };
    let mut hasher = blake3::Hasher::new();
    for piece in map.bytes().chunks(HASH_PIECE) {
        if stop.load(Ordering::Relaxed) {
            return Ok(None);
        }
        match &pool {
            Some(pool) => pool.install(|| {
                hasher.update_rayon(piece);
            }),
            None => {
                hasher.update(piece);
            }
        }
    }
    Ok(Some(*hasher.finalize().as_bytes()))
}

fn timing() -> bool {
    std::env::var_os("NZBFAST_REPAIR_TIMING").is_some()
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// One member's digest-cache pass: a BLAKE3 validation of a record, or an
/// enrolment, running on a helper thread beside the member's MD5 chain -
/// or nothing, which is every member when no store is active.
///
/// The chain polls [`MemberDigest::chain_abandoned`]: it turns true only
/// after the helper's BLAKE3 matched a record, and from then the chain may
/// stop. [`MemberDigest::resolve`] then turns whatever the chain produced
/// into the member's MD5 and, where the store should change, a
/// [`Pending`] write the caller commits once its own work has succeeded.
///
/// Dropped without resolving (an error, a cancel), it stops the helper
/// and joins it, so no thread outlives the pass that started it.
pub(crate) struct MemberDigest(Option<Box<Active>>);

struct Active {
    cache: Arc<DigestCache>,
    file: Arc<File>,
    path: PathBuf,
    id: Identity,
    flags: u32,
    /// The record being validated; `None` when enrolling.
    record: Option<Record>,
    abandon: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    helper: Option<std::thread::JoinHandle<std::io::Result<Option<[u8; 32]>>>>,
    /// The helper's BLAKE3 of the content, once joined.
    content: Option<[u8; 32]>,
    started: std::time::Instant,
}

impl Active {
    fn join(&mut self) {
        if let Some(h) = self.helper.take() {
            self.content = h.join().ok().and_then(|r| r.ok()).flatten();
        }
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.helper.take() {
            let _ = h.join();
        }
    }
}

impl MemberDigest {
    /// No store, or a member the store does not take.
    pub(crate) fn off() -> MemberDigest {
        MemberDigest(None)
    }

    /// Start the pass for the member open as `file` at `path`, `length`
    /// bytes long: validate its record if the store has one of the same
    /// length, otherwise enrol it.
    pub(crate) fn begin(
        cache: Option<&Arc<DigestCache>>,
        file: &File,
        path: &Path,
        length: u64,
        flags: u32,
    ) -> MemberDigest {
        let Some(cache) = cache else {
            return MemberDigest::off();
        };
        if length == 0 || length < cache.floor {
            return MemberDigest::off();
        }
        let (Ok(id), Ok(file)) = (Identity::of(file), file.try_clone()) else {
            cache.bump(|s| &s.store_errors);
            return MemberDigest::off();
        };
        if id.length != length {
            // Changed since the caller measured it; the caller's own
            // length checks refuse it, and this pass takes no part.
            return MemberDigest::off();
        }
        let record = match cache.load(&id) {
            Lookup::Found(r) if r.length == length => Some(r),
            Lookup::Found(_) | Lookup::Absent => {
                cache.bump(|s| &s.misses);
                None
            }
            Lookup::Unreadable => return MemberDigest::off(),
        };
        let machine = crate::mem::cpu_workers().max(1);
        let threads = if record.is_some() {
            VALIDATE_THREADS
        } else {
            ENROL_THREADS
        }
        .min(machine);
        let file = Arc::new(file);
        let abandon = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let expected = record.as_ref().map(|r| r.blake3);
        let helper = {
            let (file, abandon, stop) = (file.clone(), abandon.clone(), stop.clone());
            std::thread::Builder::new()
                .name("digest-cache".into())
                .spawn(move || {
                    let got = blake3_of(&file, length, threads, &stop)?;
                    if got.is_some() && got == expected {
                        abandon.store(true, Ordering::Relaxed);
                    }
                    Ok(got)
                })
        };
        let Ok(helper) = helper else {
            cache.bump(|s| &s.store_errors);
            return MemberDigest::off();
        };
        MemberDigest(Some(Box::new(Active {
            cache: cache.clone(),
            file,
            path: path.to_path_buf(),
            id,
            flags,
            record,
            abandon,
            stop,
            helper: Some(helper),
            content: None,
            started: std::time::Instant::now(),
        })))
    }

    /// May the MD5 chain stop? True only once a record's BLAKE3 matched
    /// the content. One relaxed load; poll it per chunk.
    #[inline]
    pub(crate) fn chain_abandoned(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(|a| a.abandon.load(Ordering::Relaxed))
    }

    /// Wait for a validation and return the record's MD5 if the content
    /// matched it. `None` at once when there is no record to validate (an
    /// enrolment keeps running beside the caller's chain).
    pub(crate) fn validated_md5(&mut self) -> Option<[u8; 16]> {
        let a = self.0.as_mut()?;
        let md5 = a.record.as_ref()?.md5;
        a.join();
        a.abandon.load(Ordering::Relaxed).then_some(md5)
    }

    /// Say, in the timing log, that this pass is ending WITHOUT a
    /// [`Self::resolve`] - the caller found nothing worth recording -
    /// and return the route so a test can read it without a subscriber.
    ///
    /// The gap this closes: a verify whose member turns out damaged
    /// never reaches its `resolve`, so before 16 Sep 2026 the enrolled
    /// case printed `hit` and every other case printed NOTHING AT ALL,
    /// and which route a `v --slow --digest-cache` took had to be
    /// inferred from the wall clock (research/DESIGN-DIGEST-CACHE-
    /// 2026-09-15.md section 9b-3, last bullet). `why` is the caller's
    /// one clause for why nothing was recorded.
    ///
    /// DIAGNOSTICS ONLY. It changes nothing about what is validated or
    /// when: the `join` below has already happened at both call sites
    /// (each asks [`Self::validated_md5`] first, which joins whenever
    /// there is a record to validate), and with no record there is
    /// nothing to wait for - the drop still stops the helper.
    pub(crate) fn unresolved(&mut self, why: &str) -> Option<&'static str> {
        let a = self.0.as_mut()?;
        let validated = a.record.is_some() && {
            a.join();
            a.abandon.load(Ordering::Relaxed)
        };
        let route = match (a.record.is_some(), validated) {
            (true, true) => "record validated, nothing recorded",
            (true, false) => "stale record, not re-enrolled",
            (false, _) => "miss, not enrolled",
        };
        if timing() {
            tracing::info!(
                target: "repair-timing",
                "digest-cache {}: {route}, {why} ({:.2?})",
                display_name(&a.path),
                a.started.elapsed()
            );
        }
        Some(route)
    }

    /// The member's whole-file MD5, given what its chain produced (`None`
    /// when the chain stopped on [`Self::chain_abandoned`]), and the store
    /// change the caller should commit once its own work succeeds.
    ///
    /// `Err` only for a member that changed while a validated record was
    /// being consumed: its chain disagrees with the record, or its identity
    /// moved. The caller refuses it as it refuses any member that changed
    /// under it.
    pub(crate) fn resolve(
        mut self,
        chain: Option<[u8; 16]>,
    ) -> Result<([u8; 16], Option<Pending>), String> {
        let Some(mut a) = self.0.take() else {
            return chain.map(|md5| (md5, None)).ok_or_else(|| {
                "a whole-file chain stopped with no digest record behind it".into()
            });
        };
        a.join();
        let validated = a.abandon.load(Ordering::Relaxed);
        let name = display_name(&a.path);
        match (a.record.clone(), a.content, chain) {
            (Some(record), _, chain) if validated => {
                if chain.is_some_and(|c| c != record.md5) || !a.id.still_holds(&a.file, &a.path) {
                    a.cache.remove(&a.id);
                    return Err(format!(
                        "{} changed while its digest record was being checked",
                        a.path.display()
                    ));
                }
                a.cache.bump(|s| &s.hits);
                if timing() {
                    tracing::info!(
                        target: "repair-timing",
                        "digest-cache {name}: hit (content validated in {:.2?})",
                        a.started.elapsed()
                    );
                }
                Ok((record.md5, Some(Pending::new(a, None))))
            }
            (record, Some(content), Some(md5)) => {
                if record.is_some() {
                    a.cache.bump(|s| &s.stale);
                    a.cache.remove(&a.id);
                }
                if timing() {
                    tracing::info!(
                        target: "repair-timing",
                        "digest-cache {name}: {} ({:.2?})",
                        if record.is_some() { "stale record, re-enrolling" } else { "miss, enrolling" },
                        a.started.elapsed()
                    );
                }
                let r = Record {
                    flags: a.flags,
                    length: a.id.length,
                    mtime: a.id.mtime,
                    ctime: a.id.ctime,
                    enrolled_unix_s: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                    blake3: content,
                    md5,
                };
                Ok((md5, Some(Pending::new(a, Some(r)))))
            }
            (_, None, Some(md5)) => Ok((md5, None)),
            (_, _, None) => {
                Err("a whole-file chain stopped with no validated record behind it".into())
            }
        }
    }
}

/// A store change a resolved [`MemberDigest`] owes, held until the caller's
/// own work has succeeded: a create commits after its set is completely
/// written, a verify after its verdict. Dropped uncommitted, it changes
/// nothing.
pub(crate) struct Pending {
    cache: Arc<DigestCache>,
    file: Arc<File>,
    path: PathBuf,
    id: Identity,
    /// `None` refreshes a record that was used; `Some` writes one.
    write: Option<Record>,
}

impl Pending {
    fn new(a: Box<Active>, write: Option<Record>) -> Pending {
        let a = *a;
        Pending {
            cache: a.cache.clone(),
            file: a.file.clone(),
            path: a.path.clone(),
            id: a.id,
            write,
        }
    }

    /// Apply it - only if the member still carries the identity both
    /// digests were taken under, which is what keeps a record from pairing
    /// an MD5 of one content with a BLAKE3 of another.
    pub(crate) fn commit(self) {
        if !self.id.still_holds(&self.file, &self.path) {
            if timing() {
                tracing::info!(
                    target: "repair-timing",
                    "digest-cache {}: not recorded, the file changed during the pass",
                    display_name(&self.path)
                );
            }
            return;
        }
        match &self.write {
            None => self.cache.touch(&self.id),
            Some(record) => match self.cache.write(&self.id, record) {
                Ok(()) => {
                    self.cache.bump(|s| &s.enrolled);
                    self.cache.prune_to(MAX_RECORDS);
                }
                Err(e) => {
                    self.cache.bump(|s| &s.store_errors);
                    if timing() {
                        tracing::info!(
                            target: "repair-timing",
                            "digest-cache {}: could not write the record: {e}",
                            display_name(&self.path)
                        );
                    }
                }
            },
        }
    }
}

#[cfg(test)]
#[path = "digest_cache_tests.rs"]
mod tests;
