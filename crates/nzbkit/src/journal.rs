//! Article-level download journal (design: M4, placement since the
//! crash-resume round): crash/kill resume.
//!
//! A header binds the journal to its NZB (md5 of the NZB bytes). On
//! restart with a matching header, recorded articles are skipped instead
//! of refetched. Two line shapes follow the header:
//!
//! - `<message-id>` - the v1 form: the article's bytes sit at their final
//!   offsets in the slot's own plain file (kept for journals written by
//!   older binaries; par2-main articles still record this way).
//! - Placement lines - `S`/`F`/`R` - record WHERE an article's bytes
//!   physically went, so direct-extracted articles (whose bytes live in
//!   the extracted inner file, not in any volume file) survive a crash
//!   too. [`restore`] copies those fragments back into the volume files
//!   the resume run works with; the live verifier then hashes every
//!   restored byte against the PAR2 block map before it is trusted.
//!
//!   ```text
//!   S <slot> <size> <volume-file-name>     restore destination for a slot
//!   F <idx> <file-name>                    file table (append-ordered;
//!                                          later runs may redefine idx)
//!   H <crc32-hex> <message-id>             content commitment over the
//!                                          article's payload, emitted
//!                                          directly ahead of its own
//!                                          R/D line (X5-02)
//!   R <slot> <fidx>:<file_off>:<vol_off>:<len>[,…] <message-id>
//!   X <file-name>                          the journal's claim over this
//!                                          file is retired. No producer
//!                                          since TODO 27 phase 3 (the
//!                                          finish decrypt that wrote it
//!                                          is gone); the PARSER stays,
//!                                          so an older run's journal
//!                                          still resumes correctly.
//!   M <slot>                               the slot demoted to a
//!                                          materialized volume (see
//!                                          [`Journal::record_materialized`])
//!   V <slot> <votes> <yenc-name>           how many of this slot's
//!                                          articles declared that name,
//!                                          for a slot whose articles
//!                                          DISAGREE (see
//!                                          [`Journal::record_name_votes`])
//!   ```
//!
//!   G <token>                              this open's generation claim
//!                                          (X5-01): `Journal::remove`
//!                                          unlinks only while the LAST
//!                                          one is its own
//!
//! - Crypto lines - `E`/`K`/`T`/`D` - the plaintext-once records: an
//!   in-stream decrypted (encrypted store) output holds PLAINTEXT, so
//!   its placements cannot be copied back as posted bytes. `D` is `R`'s
//!   grammar under another letter, and [`restore`] honors it by
//!   RE-ENCRYPTING the on-disk plaintext (CBC is deterministic) using
//!   the facts the other three record. The name rides last so it may
//!   contain spaces; binary values are lowercase hex.
//!
//!   ```text
//!   E <salt> <lg2> <iv> <unp> <check|-> <name>  crypt params + password
//!                                          check of one output
//!   K <cipher-off> <block> <name>          chain checkpoint (one/MiB)
//!   T <pad|-> <name>                       final-block padding beyond unp
//!   D <slot> <fidx>:<file_off>:<vol_off>:<len>[,…] <message-id>
//!   ```
//!
//! Appends are one `write(2)` per line (no fsync): a killed process
//! loses nothing (the kernel has the data); only power loss can cost the
//! tail, and PAR2 verification catches that too. `X` is the exception -
//! it fsyncs, because something is about to mutate a file these records
//! describe and the retirement has to be on disk first. Older binaries
//! reading a placement journal see the S/F/R/X (and E/K/T/D) lines as
//! unknown message-ids and simply refetch - safe in both directions, and
//! in particular a DOWNGRADE resume of a plaintext-once journal refetches
//! encrypted files instead of copying plaintext into volume files.

use crate::sync::MutexExt;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::disk::sanitize_out_name;
use crate::extract::{CryptoJournalEvent, Frag};

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn from_hex16(s: &str) -> Option<[u8; 16]> {
    from_hex(s)?.try_into().ok()
}

/// Reused per-thread composition buffers for the record writers. Every
/// decode consumer records one line per placed article; reusing the
/// buffers keeps the per-article cost to formatting alone (no
/// allocations), and thread-locality keeps them entirely outside the
/// shared `WriteState` mutex.
#[derive(Default)]
struct Compose {
    /// The record's full byte image - what one `write_all` lands.
    out: String,
    /// Per-fragment offset tails (`:file_off:vol_off:len[:c]`),
    /// concatenated - the state-free part of a placement line, composed
    /// before the lock is taken.
    tails: String,
    /// End offset of each fragment's tail within `tails`.
    ends: Vec<usize>,
    /// Each fragment's resolved `F`-table index (needs the lock).
    fidxs: Vec<usize>,
}

thread_local! {
    static COMPOSE: std::cell::RefCell<Compose> = std::cell::RefCell::new(Compose::default());
}

/// The journal's leaf name inside a job's output directory. One
/// spelling, because every guard below is about THIS leaf and a second
/// literal is a guard that misses one of them - `pub` since 31 Aug 2026
/// so X5-03's deferred retirement (`nzbfast`'s `JournalOwner::Caller`,
/// which never holds an open handle) names this rather than its own.
pub const JOURNAL_LEAF: &str = ".nzbfast.journal";

/// Open the journal leaf as a PRIVATE REGULAR FILE, or refuse.
///
/// The whole point is that the returned descriptor, not the path, is
/// what everything afterwards uses - see [`Journal::open`] for the
/// measured cost of the path-based opens this replaces. Three refusals,
/// each for a different way the name can stop naming a private regular
/// leaf:
///
/// * `O_NOFOLLOW` (and, on Windows, opening the reparse point itself and
///   then refusing it) turns a planted SYMLINK into an error at the open
///   rather than a write through it;
/// * the `fstat` refuses anything that is not a regular file. That is
///   what catches a FIFO. `O_NONBLOCK` rides beside it so the open
///   RETURNS at all, and what that flag is worth is worth stating
///   exactly, because the pin cannot tell you: measured on this fleet
///   30 Aug 2026, `open(fifo, O_RDONLY)` on a reader-less FIFO blocks
///   and `open(fifo, O_RDWR)` returns immediately - and this helper
///   asks for read+append, which IS `O_RDWR`. So today the flag is
///   removable and the FIFO pin stays green without it. It stays
///   because POSIX leaves `O_RDWR` on a FIFO UNSPECIFIED, so without it
///   the guarantee rests on a behaviour no standard promises. Do not
///   read the green pin as evidence the flag is doing work here, and do
///   not delete it on the strength of that green either;
/// * the link count refuses a second directory entry for the same inode.
///   No open flag can see a HARDLINK: it is not a link object, it is the
///   file, so the only tell is that the file is reachable by another
///   name.
///
/// STATED LIMIT, in the docs rather than left to be found: this guards
/// the LEAF. The parent components are resolved by the kernel as
/// ordinary path lookup, so a hostile directory component is a
/// different question (X5-06/X5-08, `disk.rs`, another lane) and this
/// helper does not answer it.
fn open_private_leaf(path: &Path, create: bool) -> std::io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).append(true).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // FILE_FLAG_OPEN_REPARSE_POINT: open the link itself instead of
        // its target, so the check below can refuse it.
        opts.custom_flags(0x0020_0000);
    }
    let f = opts.open(path)?;
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is not a regular file - refusing to use it as a journal",
                path.display()
            ),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        // FILE_ATTRIBUTE_REPARSE_POINT
        if md.file_attributes() & 0x0000_0400 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{} is a reparse point - refusing to use it as a journal",
                    path.display()
                ),
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if md.nlink() > 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{} has {} links - another name reaches this inode, so it is \
                     not a private journal",
                    path.display(),
                    md.nlink()
                ),
            ));
        }
    }
    Ok(f)
}

/// Truncate to zero the file `f` is already open on, WITHOUT resolving a
/// path - the in-place restart [`Journal::open`] does when the journal
/// on disk belongs to a different NZB.
///
/// `f.set_len(0)` is the whole of this on Unix and CANNOT be on Windows,
/// which is what took all six `windows-unit` shards red on 30 Aug 2026
/// with `Error: Access is denied. (os error 5)`. `open_private_leaf`
/// opens APPEND, and Rust spells Windows append as `FILE_GENERIC_WRITE &
/// !FILE_WRITE_DATA` - the missing `FILE_WRITE_DATA` is precisely how the
/// kernel forces every write to the end. `set_len` is
/// `SetFileInformationByHandle(FileEndOfFileInfo)`, which REQUIRES
/// `FILE_WRITE_DATA`, so the handle that guarantees the appends is the
/// one that may not truncate. Measured on a Windows box, three arms: the
/// append handle refuses `set_len` with error 5 with the reparse-point
/// flag and without it alike, and a read+write handle accepts it - so it
/// is the access mask and never `custom_flags`. `nzbkit`'s own
/// `Cargo.toml` already records the same fact for `logtee`.
///
/// `logtee`'s answer is to reopen BY PATH, which is right there and wrong
/// here: X5-04/X5-05 exist because the journal path is the thing that
/// cannot be trusted, so a second `CreateFileW` on it reintroduces
/// exactly the window `open_private_leaf` closed. `ReOpenFile` takes the
/// HANDLE and not the name - a new access mask on the same file object,
/// with no path lookup to race - so it is the faithful port of "the
/// truncate is on the descriptor we already hold". Do NOT replace it with
/// a path reopen, and do NOT drop the append mode to make `set_len` work
/// directly: two generations may legitimately hold this file at once
/// (X5-01), and append is what keeps their writes from landing on each
/// other.
fn truncate_leaf(f: &File) -> std::io::Result<()> {
    #[cfg(not(windows))]
    {
        f.set_len(0)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, ReOpenFile,
        };
        // GENERIC_WRITE rather than a bare FILE_WRITE_DATA: it carries
        // SYNCHRONIZE, which a handle opened without FILE_FLAG_OVERLAPPED
        // needs to do synchronous I/O at all, and it is the mask the
        // measurement above actually used. The share mode is the one
        // Rust's own `OpenOptions` defaults to, so this second handle
        // cannot refuse the first one its existing access.
        //
        // SAFETY: `f` is a live `File`, so `as_raw_handle` is a valid
        // open handle for the duration of the call, which is the only
        // thing `ReOpenFile` requires of it; the remaining arguments are
        // plain integers. The returned handle is a fresh one this call
        // owns, checked for both failure spellings before it is used, and
        // `from_raw_handle` takes ownership of it exactly once - nothing
        // else ever closes it, so the `File`'s own `Drop` is that
        // handle's only close.
        let h = unsafe {
            ReOpenFile(
                f.as_raw_handle(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
            )
        };
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `h` is the handle `ReOpenFile` just returned and this
        // is its only owner; the checks above have ruled out both values
        // the API uses for failure.
        let w = unsafe { File::from_raw_handle(h) };
        w.set_len(0)
    }
}

/// Whether `path` still names the very inode `f` is open on (Unix). A
/// belt beside the `G` generation token in [`Journal::remove`]: the
/// token says "this file is still mine", and this says "this NAME is
/// still that file".
///
/// Always true off Unix, where there is no cheap stable inode identity
/// to compare and the generation token carries the whole check.
fn path_still_names(f: &File, path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        match (f.metadata(), std::fs::symlink_metadata(path)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        // Discharged rather than waived with an `#[allow]`: both
        // parameters are read on Unix and neither is here, so no single
        // lint expectation is true in every build - and an `#[allow]`
        // that suppresses nothing in the build you happen to run is
        // invisible forever.
        let _ = (f, path);
        true
    }
}

/// A token unique to one [`Journal::open`], for the `G` line X5-01 turns
/// on. Process id pins it across processes, the clock pins it across pid
/// reuse, and the counter pins it across two opens in one process within
/// one clock tick - none of the three is sufficient alone.
fn next_generation() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("{:x}-{:x}-{:x}", std::process::id(), t, n)
}

struct WriteState {
    file: File,
    /// Placement records composed but not yet landed - see
    /// [`WriteState::queue`]. Every line here is complete; only the
    /// `write(2)` is deferred.
    pending: Vec<u8>,
    /// When `pending` last landed (or the journal opened): the age half
    /// of the batch rule.
    last_land: std::time::Instant,
    /// Slots whose `S` line is already emitted this run.
    slots_emitted: HashSet<usize>,
    /// File name → index in this run's `F` table.
    files: HashMap<String, usize>,
    /// Destination names already claimed by an `S` line this run.
    used_names: HashSet<String>,
}

/// The batch rule for placement records (TODO 30a, Finding 6 - full
/// measurement in `research/PROFILE-30a-store-path-2026-08-22.md`): a
/// record lands when the queue holds `BATCH_BYTES`, or when the last
/// landing is `BATCH_AGE` old, whichever comes first. One `write(2)`
/// per article was 6-10% of decode-thread CPU (the write plus the
/// mutex-wait behind it) - an APFS file-extending append costs the same
/// 15-85 us whether it carries one record or 400. A kill loses at most
/// `BATCH_AGE` of placements, refetched on resume, never corrupting
/// anything; power loss already lost the page cache (this path is not
/// fsynced), so the bound is for a kill.
const BATCH_BYTES: usize = 32 << 10;
const BATCH_AGE: std::time::Duration = std::time::Duration::from_millis(100);

impl WriteState {
    /// Queue one complete record behind the batch rule. Ordering holds
    /// by construction: every record passes through this one queue under
    /// the one mutex, and a must-land-now line goes through
    /// [`WriteState::land`], which drains the queue ahead of itself.
    fn queue(&mut self, rec: &[u8]) {
        self.pending.extend_from_slice(rec);
        if self.pending.len() >= BATCH_BYTES || self.last_land.elapsed() >= BATCH_AGE {
            self.flush();
        }
    }

    /// Land everything queued. Errors are dropped exactly as the
    /// per-record write dropped them - the journal is an optimisation
    /// over a refetch, never a correctness dependency.
    fn flush(&mut self) {
        if !self.pending.is_empty() {
            let _ = self.file.write_all(&self.pending);
            self.pending.clear();
        }
        self.last_land = std::time::Instant::now();
    }

    /// Land `rec` immediately, behind whatever is queued - for the rare
    /// non-placement lines (`M`, `E`/`K`/`T`) whose callers read the file
    /// back or fsync it, where a deferred write would reorder the journal
    /// or void the durability they promise. `X` belonged on that list
    /// until TODO 27 phase 3 deleted its only producer; the parser stays
    /// for older journals, so nothing lands one any more.
    fn land(&mut self, rec: &[u8]) -> std::io::Result<()> {
        self.flush();
        self.file.write_all(rec)
    }
}

pub struct Journal {
    state: Mutex<WriteState>,
    pub path: PathBuf,
    /// This open's `G` token (X5-01). [`Journal::remove`] unlinks only
    /// while this is still the LAST `G` line in the file, so a stale
    /// generation cannot retire a live one's journal.
    generation: String,
}

/// One journaled article: every fragment must restore for the article
/// to count as completed. `crypto` marks a `D` record; `crypto_frag`
/// says per fragment whether it restores by re-encryption (plaintext-
/// once file) or by ordinary copy (a plain neighbor the span straddled
/// into). Empty for `R` records.
pub struct Article {
    pub(crate) id: String,
    pub(crate) frags: Vec<Frag>,
    pub(crate) crypto_frag: Vec<bool>,
    pub(crate) crypto: bool,
    /// X5-02's content commitment: the crc32 the POST declared over this
    /// article's payload, verified against the decoded bytes by
    /// [`crate::yenc`] before the record was written. `None` for a
    /// journal an older binary wrote, and for the handful of articles
    /// that reach the record site without one - and `None` means the
    /// article REFETCHES, because an unauthenticated record is exactly
    /// what this exists to stop being trusted. See [`restore`].
    pub(crate) crc: Option<u32>,
}

/// Per-slot placement parsed from a journal.
pub struct SlotPlacement {
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) articles: Vec<Article>,
}

/// Crypt facts for one plaintext-once output (`E`/`K`/`T` records).
#[derive(Default, Clone)]
pub struct CryptoFileMeta {
    pub(crate) salt: [u8; 16],
    pub(crate) lg2: u8,
    pub(crate) iv: [u8; 16],
    pub(crate) unp: u64,
    /// Stored password check: a resume derives keys and PROVES the
    /// password against it before re-encrypting a single byte. Absent
    /// (archiver wrote none) means the password cannot be proven, so
    /// nothing restores and the articles refetch.
    pub(crate) check: Option<[u8; 12]>,
    /// Final-block plaintext beyond `unp` (`T` record; None until the
    /// tail block decrypted in the recorded run). Fragments touching the
    /// last cipher block are unrestorable without it.
    pub(crate) pad: Option<Vec<u8>>,
    /// Chain checkpoints: cipher offset -> cipher block [off-16, off).
    pub(crate) checkpoints: HashMap<u64, [u8; 16]>,
}

/// Everything a resume run learns from an existing journal.
#[derive(Default)]
pub struct ResumeState {
    /// v1-form articles: bytes trusted at final offsets in the slot's own
    /// file (includes par2-main records, which resume ignores anyway).
    pub completed: HashSet<String>,
    /// Placement-form articles, grouped by slot.
    pub(crate) slots: HashMap<usize, SlotPlacement>,
    /// Plaintext-once outputs by name (`E`/`K`/`T` facts).
    pub crypto_files: HashMap<String, CryptoFileMeta>,
    /// M4-70 across a crash: what an earlier run's articles declared
    /// each slot's file was called, as `(yEnc name, votes)`, for the
    /// slots whose articles DISAGREED. Empty for every ordinary post -
    /// see [`Journal::record_name_votes`] for why only a contested slot
    /// is ever written down.
    pub name_votes: HashMap<usize, Vec<(String, u32)>>,
}

impl ResumeState {
    /// Upper bound on the bytes a [`restore`] would move: every fragment
    /// of every placement record, before any article is admitted. §94 A's
    /// admission gate reads this BEFORE the restore, because what it
    /// decides is whether the restore materialises volumes at all.
    pub fn placement_bytes(&self) -> u64 {
        self.slots
            .values()
            .flat_map(|r| r.articles.iter())
            .flat_map(|a| a.frags.iter())
            .map(|f| f.len)
            .sum()
    }

    /// Every article id this journal carries a record for - the v1
    /// `completed` set plus every placement record's article - as the
    /// measured size of what run 1 got DURABLE before it died.
    ///
    /// WHAT THIS IS NOT, said here because the difference is the whole
    /// reason it is a separate question from [`restore`]: a record is
    /// not a promise the article will be trusted. `restore` re-reads the
    /// bytes and checks them against [`Article::crc`], so a record whose
    /// crc is absent (an older binary) or whose bytes were torn by the
    /// very crash that ended run 1 is recorded here and REFETCHES
    /// anyway. So this is an upper bound on what a resume can reuse and
    /// a lower bound on nothing. It exists so a test can price the gap a
    /// crash left - the quantity `contract_crash_in_fault_window`
    /// measures - without growing a second reader of the record grammar
    /// beside [`parse_lines`], which is what [`Journal::peek`]'s own
    /// header refuses.
    pub fn recorded_ids(&self) -> HashSet<String> {
        self.completed
            .iter()
            .cloned()
            .chain(
                self.slots
                    .values()
                    .flat_map(|s| s.articles.iter())
                    .map(|a| a.id.clone()),
            )
            .collect()
    }

    /// The FULL size of the widest slot the journal has placements for -
    /// in a volume set, the largest volume that will be replayed.
    ///
    /// TODO 309(a), 27 Aug 2026: this is the quantity the replay's held
    /// bytes actually track, and `placement_bytes` above is not. Measured
    /// on the F4 rig at a fixed ~2.1 GB replayed, four volume sizes, 48
    /// resumed legs: the peak held is `0` to about SEVEN volumes and never
    /// more, so at 32 MB volumes it topped out at 9 MB and at 256 MB
    /// volumes at 1782 MB - a 200x spread in a quantity that
    /// `placement_bytes` reports as identical. `plan.rs
    /// resume_map_admits` is the one reader; its doc comment carries the
    /// budget ladder that turned that into a rule.
    ///
    /// The slot's RECORDED size, not the bytes restored of it: a slot
    /// half on disk still holds up to a whole volume once the rest of it
    /// arrives from the wire, so the restored fraction is the wrong
    /// bound and it is the wrong one in the unsafe direction.
    pub fn largest_slot_bytes(&self) -> u64 {
        self.slots.values().map(|r| r.size).max().unwrap_or(0)
    }
}

/// What [`restore`] managed to rebuild from a placement journal.
#[derive(Default)]
pub struct Restored {
    /// Articles whose every fragment restored - skip refetching these.
    pub ids: HashSet<String>,
    /// Per-slot seeds for the extractor/verifier: the volume file to
    /// adopt and the (offset, len) spans now on disk in it.
    pub seeds: Vec<SlotSeed>,
    /// The crypto ROUTE every output the journal names was committed to
    /// by the run that wrote it, derived from the records rather than
    /// journaled as its own line (TODO 158 item 2, closed 22 Aug 2026).
    /// An output a resumed run writes under the OTHER route mixes
    /// domains on disk while the records keep describing the old one,
    /// and the run after that restores garbage - so the resumed
    /// extractor is seeded with this before its first span and holds
    /// each output to the route recorded for it.
    ///
    /// Wire-domain outputs: every file a plain placement fragment names
    /// (an `R` record, or the `:0` plain-neighbour fragment of a `D`),
    /// with the bytes those fragments cover. For an encrypted entry
    /// that is the ciphertext route; for a plain entry or a volume
    /// file it is merely true, and harmless to assert. Counted over
    /// every record, admitted or not - the bytes are on disk either way
    /// and the route was latched at enqueue in the run that wrote them.
    pub wire_outputs: HashMap<String, u64>,
    /// Plaintext-once outputs whose `D` articles were ADMITTED by this
    /// restore, with the `(salt, iv)` of the head record their `E` fact
    /// was taken from. Only an admitted article pins the route: an
    /// output none of whose `D` records restored is refetched whole and
    /// re-recorded under whatever route the resumed run takes, and the
    /// last `R`/`D` per id wins at the next parse. A file that is ALSO
    /// a wire output is a contradiction only a pre-fix journal can hold
    /// (a run that wrote ciphertext over plaintext and recorded neither
    /// change); its `D` articles are refused admission, so it lands here
    /// never and in `wire_outputs` always.
    pub plaintext_outputs: HashMap<String, ([u8; 16], [u8; 16])>,
    /// Articles the journal recorded a placement for and that this
    /// restore REFUSED, because the file their bytes were written into
    /// no longer opens or is no longer long enough to hold the span
    /// ([`restore_for`]'s admission check, pinned by `a source too short
    /// for its span must drop its article`), with the bytes those
    /// articles covered.
    ///
    /// TODO 309(b), 28 Aug 2026. Nothing in the engine reads this - a
    /// dropped article simply refetches, which is the correct and safe
    /// outcome and is why the drop is not an error. It is counted
    /// because the SYMPTOM was indistinguishable from an ordinary
    /// resume: the restore banner reports what it restored, so bytes
    /// that went back on the wire because something outside nzbfast
    /// moved, truncated or deleted a job's partial output showed up
    /// only as a smaller number, with nothing anywhere naming the
    /// cause. `get/plan.rs` is the one reader and it prints a line.
    ///
    /// Deliberately NOT merged with `dropped_crypto` below: the two
    /// have different causes and different remedies, and a single
    /// counter would make a passwordless resume of an encrypted set
    /// report that something had touched the user's files.
    pub dropped_source: (usize, u64),
    /// Articles refused because their plaintext-once (`D`) fragments
    /// could not be re-encrypted - no password, missing `E` facts, or an
    /// output whose domain the records contradict. Same TODO 309(b)
    /// disclosure, separate cause: these bytes refetch because the
    /// resume cannot reconstruct what the wire sent, not because
    /// anything on disk moved.
    pub dropped_crypto: usize,
    /// Articles refused by X5-02's content check: their bytes ARE on
    /// disk at the recorded offsets and at the recorded length, and they
    /// are not the bytes the wire sent - or the record carries no
    /// commitment to compare them against, which an older binary's
    /// journal never does.
    ///
    /// A third counter rather than a third meaning for `dropped_source`,
    /// for that field's own stated reason: the two have different causes
    /// and different remedies. "Your partial output moved" sends a user
    /// looking at their disk; this one is either a crash they already
    /// know about (the common case - a preallocated slot whose bytes
    /// never landed) or an upgrade from a journal format that had no
    /// commitment, and neither is a question about their filesystem.
    pub dropped_unauthenticated: (usize, u64),
}

pub struct SlotSeed {
    pub slot: usize,
    pub name: String,
    pub size: u64,
    pub spans: Vec<(u64, u64)>,
    /// Parallel to `spans`: where each span's bytes physically ARE, as
    /// `(file, offset)` relative to the out-dir. Populated only when
    /// [`restore_for`] was told not to materialise volumes (§94 A's
    /// replay reads the placements directly instead, so the bytes are
    /// still in the output file run 1 put them in). Empty otherwise,
    /// which means every span is at `vol_off` in `name` itself.
    pub sources: Vec<(std::sync::Arc<str>, u64)>,
    /// Parallel to `spans`: the message-id of the article each span
    /// was restored from, one `Arc` shared by every span of the same
    /// article. TODO 158 item 2 (belt-and-braces half, 23 Aug 2026):
    /// §94 A's replay feeds these spans back through the extractor and
    /// re-journals each article under the route the RESUMED run took,
    /// which it can only do if it still knows which article a span
    /// belonged to - the journal's records are per article, the seeds
    /// per fragment. Populated in both restore modes.
    pub article_ids: Vec<std::sync::Arc<str>>,
}

impl Journal {
    /// Parse an existing journal WITHOUT opening it for append.
    ///
    /// [`Journal::open`] is the only other reader of this file and it is
    /// a WRITE: it creates the directory, opens the file for append, and
    /// TRUNCATES it outright when the fingerprint does not match. So
    /// nothing that merely wants to LOOK at a journal may call it - and
    /// the caller this exists for (TODO 309(d): the demotion watchdog
    /// asking what a requeue will cost) is looking at the journal a
    /// RUNNING job still holds open.
    ///
    /// Three things it deliberately does not do, each stated rather than
    /// left to be found:
    ///
    /// * **It does not check the fingerprint against an NZB.** A caller
    ///   holding the NZB bytes calls `open`; this one does not have them,
    ///   and the journal it is asking about is the one the job in front
    ///   of it is writing, which matches by construction. What it does
    ///   require is a v1 header, so a file that is not a journal at all
    ///   answers `None` rather than parsing as an empty one.
    /// * **It sees only what has been FLUSHED.** [`Journal`] batches its
    ///   records, so a peek taken mid-run undercounts by up to one
    ///   pending batch. Bounded, and in the direction that under-reports
    ///   a cost rather than inventing one.
    /// * **It costs what a resume costs.** This is [`parse_lines`], the
    ///   same parser `open` runs, so the transient allocation is the one
    ///   the very next run of this job makes anyway. A second, cheaper
    ///   parser that summed fragment lengths without building the state
    ///   was considered and refused: it would be a copy-paste sibling of
    ///   the record grammar, free to drift, for a saving nobody measured.
    pub fn peek(dir: &Path) -> Option<ResumeState> {
        // Same inode discipline as `open`, minus the create: a peek
        // that followed a planted symlink would read an outside file
        // and report its contents as this job's resume cost.
        let f = open_private_leaf(&dir.join(JOURNAL_LEAF), false).ok()?;
        let mut lines = utf8_lines(std::io::BufReader::new(f));
        lines
            .next()?
            .starts_with("nzbfast-journal v1 ")
            .then_some(())?;
        let mut resume = ResumeState::default();
        parse_lines(lines, &mut resume);
        Some(resume)
    }

    /// Open (or create) the journal for an NZB. Returns the journal and
    /// the resume state parsed from it (empty on a fresh run or when the
    /// existing journal belongs to a different NZB).
    ///
    /// **The journal is bound to an INODE, not to a path** (X5-04/X5-05,
    /// 30 Aug 2026). Everything below runs on ONE descriptor: it is
    /// opened no-follow, its type and link count are checked through
    /// `fstat` on that descriptor, the header is read positionally from
    /// it, and a fingerprint mismatch truncates THAT DESCRIPTOR rather
    /// than re-creating the path. The three path-based opens this
    /// replaces (`File::open`, an append-open, `File::create`) each
    /// followed whatever the name resolved to at the instant they ran,
    /// and the measured cost of that was total: with a symlink planted
    /// at `<out>/.nzbfast.journal`, an outside file's bytes afterwards
    /// were literally `nzbfast-journal v1 <fingerprint>` - the header
    /// written straight through the link by the `File::create` arm. A
    /// hardlink did the same with no symlink anywhere to notice, and a
    /// FIFO wedged `File::open` in the kernel, unbounded, before the job
    /// reached any networking at all.
    ///
    /// So a journal path that is not a private regular leaf is a typed
    /// REFUSAL and never a silent adaptation:
    ///
    /// * a symlink is refused by `O_NOFOLLOW` at the open itself;
    /// * a FIFO (or any other non-regular file) is refused by the
    ///   `fstat`, and `O_NONBLOCK` is what lets the open return at all
    ///   so there is something to refuse - without it the open never
    ///   comes back;
    /// * a second directory entry for the same inode - a hardlink, which
    ///   no flag can see - is refused by the link count.
    ///
    /// Do NOT "fix" a refusal here by dropping a check and reopening by
    /// path: the path is exactly what cannot be trusted. Move the
    /// hostile file aside instead.
    pub fn open(dir: &Path, nzb_bytes: &[u8]) -> std::io::Result<(Journal, ResumeState)> {
        use crate::md5fast::{Digest, Md5};
        let fp = format!("{:x}", Md5::digest(nzb_bytes));
        let path = dir.join(JOURNAL_LEAF);
        std::fs::create_dir_all(dir)?;

        let mut file = open_private_leaf(&path, true)?;

        let mut resume = ResumeState::default();
        let mut valid = false;
        if file.metadata()?.len() > 0 {
            // Read through a CLONE of the same descriptor, never a
            // second open by path: `dup` cannot land on a different
            // inode the way a re-open can. Sharing the file offset with
            // the writer is safe here and only here - nothing else holds
            // this `Journal` yet, so no write can interleave, and every
            // write below is `O_APPEND` and ignores the cursor anyway.
            let mut rd = file.try_clone()?;
            rd.seek(std::io::SeekFrom::Start(0))?;
            let mut lines = utf8_lines(std::io::BufReader::new(rd));
            if let Some(header) = lines.next()
                && header.strip_prefix("nzbfast-journal v1 ") == Some(fp.as_str())
            {
                valid = true;
                parse_lines(lines, &mut resume);
            }
        }
        if !valid {
            // Fresh or mismatched: restart the journal IN PLACE. The
            // truncate is on the descriptor we already hold, so it can
            // only ever reach the inode this call opened - see
            // `truncate_leaf`, which is where the Windows half of "the
            // descriptor we already hold" lives.
            truncate_leaf(&file)?;
            writeln!(file, "nzbfast-journal v1 {fp}")?;
            resume = ResumeState::default();
        }
        // X5-01: this generation's claim on the file. `remove` unlinks
        // only while this is still the LAST `G` line, so a stale
        // generation reaching its own retirement cannot unlink the
        // journal a LIVE generation is still appending to - which cost
        // the live run every record it had (`completed = {}` on the next
        // open, every recorded article refetched) and, on Unix, went on
        // silently appending to an unlinked inode nothing would ever
        // read.
        let generation = next_generation();
        writeln!(file, "G {generation}")?;
        // The leading dot is invisible to Windows, where this file sits
        // in the user's own download folder looking like junk we forgot
        // to clean up. It is not junk - a failed job keeps it so a retry
        // fetches only what is missing - so hide it rather than drop it.
        crate::disk::hide_from_user(&path);
        Ok((
            Journal {
                state: Mutex::new(WriteState {
                    file,
                    pending: Vec::with_capacity(BATCH_BYTES + 512),
                    last_land: std::time::Instant::now(),
                    slots_emitted: HashSet::new(),
                    files: HashMap::new(),
                    used_names: HashSet::new(),
                }),
                path,
                generation,
            },
            resume,
        ))
    }

    /// Record one terminal article the v1 way (bytes at final offsets in
    /// the slot's own file) - used for par2-main slots.
    pub fn record(&self, id: &str) {
        COMPOSE.with_borrow_mut(|c| {
            c.out.clear();
            c.out.push_str(id);
            c.out.push('\n');
            let mut st = self.state.lock_ok();
            st.queue(c.out.as_bytes());
        });
    }

    /// Land every queued placement record now. Called where the stream
    /// pauses or ends (a decoder about to block on an empty channel, the
    /// end of the network phase, the finish tail) so the age bound holds
    /// across a stall, and by `Drop`.
    pub fn flush(&self) {
        self.state.lock_ok().flush();
    }

    /// Record one terminal article with its physical placement.
    /// `slot_file` is the slot's on-disk (name, size) when a writer
    /// exists; otherwise `name`/`size` (the yEnc header values) predict
    /// what a resume run will create.
    ///
    /// `crc` is X5-02's content commitment: the crc32 the post declared
    /// over exactly this article's payload, which [`crate::yenc`] has
    /// already verified against the decoded bytes. It costs nothing to
    /// record - it is a number the decode already computed - and it is
    /// the whole of what lets a resume tell bytes that ARRIVED from
    /// bytes that merely have the right length. Pass `None` only where
    /// no such number exists; the article then refetches on resume
    /// rather than being trusted.
    #[expect(clippy::too_many_arguments)]
    pub fn record_placed(
        &self,
        slot: usize,
        id: &str,
        slot_file: Option<(String, u64)>,
        name: &str,
        size: u64,
        frags: &[Frag],
        crc: Option<u32>,
    ) {
        self.record_letter('R', slot, id, slot_file, name, size, frags, None, crc);
    }

    /// Record a plaintext-once placement: `R`'s grammar under the `D`
    /// letter with a per-fragment crypto marker (`:1` = restores by
    /// re-encryption, `:0` = ordinary copy of a plain neighbor), so
    /// [`restore`] re-encrypts instead of copying and an old binary
    /// refetches instead of copying plaintext into volume files.
    #[expect(clippy::too_many_arguments)]
    pub fn record_placed_crypto(
        &self,
        slot: usize,
        id: &str,
        slot_file: Option<(String, u64)>,
        name: &str,
        size: u64,
        frags: &[Frag],
        crypto_mask: &[bool],
        crc: Option<u32>,
    ) {
        self.record_letter(
            'D',
            slot,
            id,
            slot_file,
            name,
            size,
            frags,
            Some(crypto_mask),
            crc,
        );
    }

    #[expect(clippy::too_many_arguments)]
    fn record_letter(
        &self,
        letter: char,
        slot: usize,
        id: &str,
        slot_file: Option<(String, u64)>,
        name: &str,
        size: u64,
        frags: &[Frag],
        crypto_mask: Option<&[bool]>,
        crc: Option<u32>,
    ) {
        if frags.is_empty() {
            return;
        }
        // Compose the record's lines (S table entry, new F entries, the
        // placement itself) into ONE buffer and land them with ONE
        // write(2): the kill-safety contract is per-record, and writeln!
        // on a raw File issues a syscall per format fragment - several
        // per article, all inside this mutex the decoders share.
        //
        // The buffers are thread-local and reused, and everything that
        // does not need `state` - the per-fragment offset tails, which
        // are the bulk of the formatting - is composed BEFORE taking the
        // lock. Only the dedup lookups (slots_emitted / files /
        // used_names), the fidx interleave they feed, and the write
        // itself sit inside it: releasing the lock between fidx
        // assignment and the write could let another decoder's record
        // for the same slot land ahead of its `S` line.
        use std::fmt::Write as _;
        COMPOSE.with_borrow_mut(|c| {
            let Compose {
                out,
                tails,
                ends,
                fidxs,
            } = c;
            out.clear();
            tails.clear();
            ends.clear();
            for (i, f) in frags.iter().enumerate() {
                let _ = write!(tails, ":{}:{}:{}", f.file_off, f.vol_off, f.len);
                if let Some(mask) = crypto_mask {
                    tails.push_str(if mask.get(i).copied().unwrap_or(true) {
                        ":1"
                    } else {
                        ":0"
                    });
                }
                ends.push(tails.len());
            }
            let mut st = self.state.lock_ok();
            if !st.slots_emitted.contains(&slot) {
                let (dest, dsize) = match slot_file {
                    Some((n, s)) => (n, s),
                    None => {
                        let mut n = sanitize_out_name(name);
                        if st.used_names.contains(&n) {
                            // Capped at composition, and the record is
                            // why: `parse_lines` runs `sanitize_out_name`
                            // over this `S` destination again on load, so
                            // a raw prefix on a name already at the cap
                            // is re-spelled by the reader and the record
                            // stops naming the file it describes.
                            n = crate::disk::disambiguated_out_name(&n, slot, 0);
                        }
                        (n, size)
                    }
                };
                st.used_names.insert(dest.clone());
                st.slots_emitted.insert(slot);
                let _ = writeln!(out, "S {slot} {dsize} {dest}");
            }
            // F lines first (a placement may only reference an already
            // defined index), then the placement line in one piece.
            fidxs.clear();
            for f in frags {
                fidxs.push(match st.files.get(&f.file) {
                    Some(&i) => i,
                    None => {
                        let i = st.files.len();
                        st.files.insert(f.file.clone(), i);
                        let _ = writeln!(out, "F {i} {}", f.file);
                        i
                    }
                });
            }
            // X5-02: the commitment rides in its OWN line directly
            // ahead of the record it authenticates, and never as a
            // fifth field of the fragment tail. Two reasons, both about
            // what an OLDER binary does with it: a fragment gains a
            // field and that parser refuses the whole record (its
            // `nums.next().is_some()` arm), while a line it has never
            // heard of falls through to the v1 arm as a message-id that
            // can never match a real one - inert. Ahead of the record so
            // ordering settles last-wins for free: `R`/`D` is what the
            // parser keys on, and the commitment it takes is the one
            // that arrived immediately before it.
            if let Some(crc) = crc {
                let _ = writeln!(out, "H {crc:08x} {id}");
            }
            let _ = write!(out, "{letter} {slot} ");
            let mut start = 0usize;
            for (i, fidx) in fidxs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(out, "{fidx}");
                out.push_str(&tails[start..ends[i]]);
                start = ends[i];
            }
            let _ = writeln!(out, " {id}");
            st.queue(out.as_bytes());
        });
    }

    /// Record that a slot demoted to a materialized volume, with its
    /// reconstruction fully on disk (the extractor fires its
    /// `MaterializedHook` only after the header stash, inner-file
    /// read-back, and held-span drain all landed). From this line back,
    /// every placement recorded for the slot - fragments naming inner
    /// files the fallback deletes right after - ALSO sits at its final
    /// offsets in the slot's own volume file, so [`parse_lines`]
    /// rewrites them to identity form and a retry restores those
    /// articles instead of refetching the whole post. Positional like
    /// `X`: records appended after this line already describe the
    /// materialized file and need no rewrite.
    ///
    /// `name`/`size` describe the file the demote actually created. A
    /// PAR2 report can rename a WRITERLESS slot after its `S` line was
    /// written, and the volume then materializes under the verified
    /// name; recording the demote against the stale posted name pointed
    /// every rewritten placement at a file that does not exist, so the
    /// retry refetched a post it was already holding on disk. The demote
    /// therefore re-states the slot's metadata first and lets the
    /// grammar's "last S wins" rule carry it. Both lines land in ONE
    /// write - the rewrite is only correct if the fresh `S` precedes the
    /// `M`.
    pub fn record_materialized(&self, slot: usize, name: &str, size: u64) {
        use std::fmt::Write as _;
        let dest = sanitize_out_name(name);
        let mut st = self.state.lock_ok();
        let mut out = String::new();
        if !dest.is_empty() {
            st.used_names.insert(dest.clone());
            st.slots_emitted.insert(slot);
            let _ = writeln!(out, "S {slot} {size} {dest}");
        }
        let _ = writeln!(out, "M {slot}");
        let _ = st.land(out.as_bytes());
    }

    /// Record how many of a slot's articles have declared each yEnc
    /// name, for a slot whose articles DISAGREE about it.
    ///
    /// M4-70 decides a contested file's published name at settle, off
    /// the whole post's majority (`nzbfast::get::yencname`), and it can
    /// only count the articles THIS run decoded. A resume never refetches
    /// what run 1 already placed, so without this the tally comes back
    /// EMPTY: `contested_yenc_name` reads "every article agreed", the
    /// re-decision never runs, and a decoy name that run 1's first
    /// article latched stays on the disk for good. Crash after the decoy,
    /// resume, finish - and smart filing and every *arr see `x.dat`.
    ///
    /// ONLY A CONTESTED SLOT IS EVER WRITTEN, which is what makes this
    /// affordable: the caller asks the slot first, and the answer for the
    /// ordinary post - every article of every file agreeing - is one
    /// relaxed load and no line at all. A contested slot pays two lines
    /// per article, against the `R` line it was already paying.
    ///
    /// LAST WINS PER `(slot, name)`, the same rule as `S`: each line
    /// carries a RUNNING total rather than an increment, so a torn tail
    /// costs at most the newest count of one name and never double-counts
    /// a replayed one. A count that comes back one article short cannot
    /// change a verdict that a whole-post majority was going to reach.
    ///
    /// NOT `sanitize_out_name`d, unlike every other name this grammar
    /// carries. `S`/`E`/`K`/`T` name a FILE the restore has to find on
    /// disk; this names what an ARTICLE DECLARED, which is evidence and
    /// not a path - the settle tier sanitizes it at the moment it
    /// compares it with what is on disk (`nzbfast::get::yencname`), and
    /// sanitizing it here would record a different string from the one
    /// the un-crashed run counts votes for.
    ///
    /// Growth is bounded by the ARTICLE count and not by how many names
    /// a hostile poster spends: the caller hands back at most two
    /// entries per article whatever the tally holds, so a slot that
    /// disagrees costs 2 lines per article against the `R` line it was
    /// already writing, and a poster who spends one name per article
    /// still gets no rename out of it.
    ///
    /// An older binary reading these lines takes them for unknown v1
    /// message-ids that never match a real bracketed id, so it simply
    /// refetches - safe in both directions, as the module header
    /// promises for every line shape after the header.
    pub fn record_name_votes(&self, slot: usize, votes: &[(String, u32)]) {
        if votes.is_empty() {
            return;
        }
        use std::fmt::Write as _;
        let mut out = String::new();
        for (name, n) in votes {
            // A yEnc header name is the poster's own bytes and rides
            // LAST for that reason - it may hold spaces, and the parser
            // splits three ways. A name carrying a newline would end the
            // record early, so it is dropped rather than written: the
            // cost is one uncounted vote in a tally the majority decides.
            if name.is_empty() || name.contains(['\n', '\r']) {
                continue;
            }
            let _ = writeln!(out, "V {slot} {n} {name}");
        }
        if out.is_empty() {
            return;
        }
        let _ = self.state.lock_ok().land(out.as_bytes());
    }

    /// Write the drained [`CryptoJournalEvent`]s as `E`/`K`/`T` lines.
    pub fn record_crypto_events(&self, events: &[CryptoJournalEvent]) {
        if events.is_empty() {
            return;
        }
        // Formatted entirely outside the lock (nothing here reads the
        // write state), landed as one write.
        use std::fmt::Write as _;
        let mut out = String::new();
        for ev in events {
            match ev {
                CryptoJournalEvent::Params {
                    name,
                    salt,
                    lg2,
                    iv,
                    unp,
                    check,
                } => {
                    let ck = check.map(|c| to_hex(&c)).unwrap_or_else(|| "-".into());
                    let _ = writeln!(
                        out,
                        "E {} {lg2} {} {unp} {ck} {name}",
                        to_hex(salt),
                        to_hex(iv)
                    );
                }
                CryptoJournalEvent::Checkpoint { name, off, block } => {
                    let _ = writeln!(out, "K {off} {} {name}", to_hex(block));
                }
                CryptoJournalEvent::TailPad { name, pad } => {
                    let p = if pad.is_empty() {
                        "-".to_string()
                    } else {
                        to_hex(pad)
                    };
                    let _ = writeln!(out, "T {p} {name}");
                }
            }
        }
        let mut st = self.state.lock_ok();
        let _ = st.land(out.as_bytes());
    }

    /// Download finished and verified - the journal has served its purpose.
    ///
    /// **Only while the journal is still THIS generation's** (X5-01,
    /// 30 Aug 2026). The unconditional path-based `remove_file` this
    /// replaces let a STALE generation, reaching its own successful
    /// retirement, unlink the journal a LIVE generation was still
    /// appending to. Measured: the next open then parsed
    /// `completed = {}` and every recorded article went back on the
    /// wire, and on Unix the live generation went on writing into an
    /// unlinked inode nothing would ever read - so the loss was silent
    /// at both ends.
    ///
    /// A fence after the fetch does not close that, which is why the
    /// claim is written INTO the file: the two generations are two
    /// handles that may legitimately overlap, so the question is not
    /// "has the fetch ended" but "is the journal on disk still mine".
    /// The last `G` line answers it, and `path_still_names` answers the
    /// narrower one beside it - that this NAME is still that inode.
    ///
    /// Not retiring is always safe: the journal is an optimisation over
    /// a refetch, so a lingering one is at worst a file the next run
    /// resumes correctly from and the live generation retires when it
    /// finishes.
    pub fn remove(self) {
        // Nothing queued is worth landing in a file about to be unlinked.
        self.state.lock_ok().pending.clear();
        if !self.is_current_generation() {
            return;
        }
        let _ = std::fs::remove_file(&self.path);
    }

    /// Whether the file this journal holds open is still the one the
    /// path names AND still carries this generation's `G` line last.
    ///
    /// Read through our OWN descriptor, so the answer is about the inode
    /// we have been writing to and never about whatever the path
    /// resolves to now.
    fn is_current_generation(&self) -> bool {
        let st = self.state.lock_ok();
        if !path_still_names(&st.file, &self.path) {
            return false;
        }
        let Ok(mut rd) = st.file.try_clone() else {
            return false;
        };
        if rd.seek(std::io::SeekFrom::Start(0)).is_err() {
            return false;
        }
        let mut last: Option<String> = None;
        for line in utf8_lines(std::io::BufReader::new(rd)) {
            if let Some(g) = line.strip_prefix("G ") {
                last = Some(g.to_string());
            }
        }
        last.as_deref() == Some(self.generation.as_str())
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Line iterator that survives a torn record. `BufRead::lines()` yields
/// `Err(InvalidData)` at the first invalid-UTF-8 line, and the
/// `map_while(Result::ok)` this replaces turned that into a permanent
/// stop: one record torn mid-multibyte-filename (ENOSPC, power loss)
/// hid every VALID record appended after it, on every later open, so
/// completed ranges were refetched forever. Journal records can carry
/// Unicode filenames, so the torn byte can land anywhere. This reads
/// raw lines, SKIPS a malformed one (the parser ignores unknown lines
/// anyway, so skipping is conservative in the same direction), and
/// stops only on a real I/O error.
fn utf8_lines<R: std::io::BufRead>(mut r: R) -> impl Iterator<Item = String> {
    let mut buf = Vec::new();
    std::iter::from_fn(move || {
        loop {
            buf.clear();
            match r.read_until(b'\n', &mut buf) {
                Ok(0) => return None,
                Ok(_) => {
                    if buf.last() == Some(&b'\n') {
                        buf.pop();
                        if buf.last() == Some(&b'\r') {
                            buf.pop();
                        }
                    }
                    match std::str::from_utf8(&buf) {
                        Ok(s) => return Some(s.to_owned()),
                        Err(_) => continue,
                    }
                }
                Err(_) => return None,
            }
        }
    })
}

fn parse_lines(lines: impl Iterator<Item = String>, resume: &mut ResumeState) {
    // File table + per-id placements resolve in stream order: a later run
    // appends its own F table (reusing indexes) and its R lines must bind
    // to ITS definitions, so fidx→name is resolved per line, not at the end.
    let mut ftable: HashMap<usize, String> = HashMap::new();
    let mut placed: HashMap<String, (usize, Vec<Frag>, Vec<bool>, bool, Option<u32>)> =
        HashMap::new();
    // X5-02 commitments seen so far, by article id. An `H` line always
    // rides directly ahead of the record it authenticates, so the entry
    // standing when an `R`/`D` is parsed is that record's own - and a
    // re-record (last R/D wins) brings its own `H` with it.
    let mut digests: HashMap<String, u32> = HashMap::new();
    let mut slot_meta: HashMap<usize, (String, u64)> = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("E ") {
            // E <salt> <lg2> <iv> <unp> <check|-> <name>
            let mut it = rest.splitn(6, ' ');
            if let (Some(salt), Some(lg2), Some(iv), Some(unp), Some(ck), Some(name)) = (
                it.next(),
                it.next(),
                it.next(),
                it.next(),
                it.next(),
                it.next(),
            ) && let (Some(salt), Ok(lg2), Some(iv), Ok(unp)) = (
                from_hex16(salt),
                lg2.parse::<u8>(),
                from_hex16(iv),
                unp.parse::<u64>(),
            ) && !name.is_empty()
            {
                let check: Option<[u8; 12]> = match ck {
                    "-" => None,
                    _ => match from_hex(ck).and_then(|v| v.try_into().ok()) {
                        Some(c) => Some(c),
                        None => continue, // malformed check: drop the record
                    },
                };
                let name = sanitize_out_name(name);
                let m = resume.crypto_files.entry(name).or_default();
                (m.salt, m.lg2, m.iv, m.unp, m.check) = (salt, lg2, iv, unp, check);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("K ") {
            // K <cipher-off> <block> <name>
            let mut it = rest.splitn(3, ' ');
            if let (Some(off), Some(block), Some(name)) = (it.next(), it.next(), it.next())
                && let (Ok(off), Some(block)) = (off.parse::<u64>(), from_hex16(block))
                && !name.is_empty()
            {
                resume
                    .crypto_files
                    .entry(sanitize_out_name(name))
                    .or_default()
                    .checkpoints
                    .insert(off, block);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("T ") {
            // T <pad|-> <name>
            let mut it = rest.splitn(2, ' ');
            if let (Some(pad), Some(name)) = (it.next(), it.next())
                && !name.is_empty()
            {
                let pad = if pad == "-" {
                    Some(Vec::new())
                } else {
                    from_hex(pad)
                };
                if let Some(pad) = pad {
                    resume
                        .crypto_files
                        .entry(sanitize_out_name(name))
                        .or_default()
                        .pad = Some(pad);
                }
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("V ") {
            // V <slot> <votes> <yenc-name>. Last wins per (slot, name):
            // every line carries a running total, so a slot re-recorded
            // by a later run overwrites rather than accumulating.
            let mut it = rest.splitn(3, ' ');
            if let (Some(slot), Some(votes), Some(name)) = (it.next(), it.next(), it.next())
                && let (Ok(slot), Ok(votes)) = (slot.parse::<usize>(), votes.parse::<u32>())
                && !name.is_empty()
            {
                let tally = resume.name_votes.entry(slot).or_default();
                match tally.iter_mut().find(|(n, _)| n == name) {
                    Some(e) => e.1 = votes,
                    None => tally.push((name.to_string(), votes)),
                }
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("H ") {
            // H <crc32-hex> <message-id>
            if let Some((hex, id)) = rest.split_once(' ')
                && !id.is_empty()
                && let Ok(crc) = u32::from_str_radix(hex, 16)
            {
                digests.insert(id.to_string(), crc);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("F ") {
            if let Some((idx, name)) = rest.split_once(' ')
                && let Ok(idx) = idx.parse::<usize>()
                && !name.is_empty()
            {
                ftable.insert(idx, sanitize_out_name(name));
            }
        } else if let Some(rest) = line.strip_prefix("S ") {
            let mut it = rest.splitn(3, ' ');
            if let (Some(slot), Some(size), Some(name)) = (it.next(), it.next(), it.next())
                && let (Ok(slot), Ok(size)) = (slot.parse::<usize>(), size.parse::<u64>())
                && !name.is_empty()
            {
                // Last S wins - a later run knows the actual file.
                slot_meta.insert(slot, (sanitize_out_name(name), size));
            }
        } else if let Some((rest, crypto)) = line
            .strip_prefix("R ")
            .map(|r| (r, false))
            .or_else(|| line.strip_prefix("D ").map(|r| (r, true)))
        {
            let mut it = rest.splitn(3, ' ');
            let (Some(slot), Some(list), Some(id)) = (it.next(), it.next(), it.next()) else {
                continue;
            };
            let Ok(slot) = slot.parse::<usize>() else {
                continue;
            };
            if id.is_empty() {
                continue;
            }
            let mut frags: Vec<Frag> = Vec::new();
            let mut crypto_frag: Vec<bool> = Vec::new();
            let mut ok = true;
            for part in list.split(',') {
                let mut nums = part.split(':');
                let (Some(fi), Some(fo), Some(vo), Some(ln)) =
                    (nums.next(), nums.next(), nums.next(), nums.next())
                else {
                    ok = false;
                    break;
                };
                let (Ok(fi), Ok(fo), Ok(vo), Ok(ln)) = (
                    fi.parse::<usize>(),
                    fo.parse::<u64>(),
                    vo.parse::<u64>(),
                    ln.parse::<u64>(),
                ) else {
                    ok = false;
                    break;
                };
                let Some(file) = ftable.get(&fi) else {
                    ok = false;
                    break;
                };
                // D fragments carry a 5th field marking how they restore
                // (missing = conservative crypto). R fragments never do.
                let cf = if crypto {
                    match nums.next() {
                        Some("0") => false,
                        Some("1") | None => true,
                        Some(_) => {
                            ok = false;
                            break;
                        }
                    }
                } else {
                    false
                };
                if ln == 0 || nums.next().is_some() {
                    ok = false;
                    break;
                }
                frags.push(Frag {
                    file: file.clone(),
                    file_off: fo,
                    vol_off: vo,
                    len: ln,
                });
                crypto_frag.push(cf);
            }
            if ok && !frags.is_empty() {
                // Last R/D wins (a failed restore refetches, re-records).
                let crc = digests.get(id).copied();
                placed.insert(id.to_string(), (slot, frags, crypto_frag, crypto, crc));
            }
        } else if let Some(name) = line.strip_prefix("X ") {
            // Claim retired: from here on this file is no longer the
            // bytes the records above describe, so every placement with a
            // fragment naming it - as a copy source, or as its own
            // identity destination - is dropped and those articles
            // refetch. Positional by construction: R lines after this
            // point describe the file as it is now and still count.
            //
            // Nothing writes an `X` any more. Its only producer was the
            // legacy finish decrypt, which mutated an output the records
            // pointed into; plaintext-once never mutates one, so TODO 27
            // phase 3 deleted the producer and kept this arm, because a
            // journal an OLDER build left behind must still resume
            // correctly - and the answer it encodes (refetch) is the
            // conservative one in every case.
            if name.is_empty() {
                continue;
            }
            let name = sanitize_out_name(name);
            placed.retain(|_, (_, frags, _, _, _)| !frags.iter().any(|f| f.file == name));
        } else if line.starts_with("G ") {
            // X5-01 generation claim: a fact about WHO owns the journal,
            // never about an article. Ignored by the resume, and named
            // here rather than left to fall through - the `else` arm
            // below takes an unknown line for a v1 message-id, and a
            // `completed` set carrying `G <token>` is a lie about what
            // arrived even if nothing ever matches it.
            continue;
        } else if let Some(rest) = line.strip_prefix("M ") {
            // Slot demoted to a materialized volume: everything recorded
            // for it SO FAR also sits at final offsets in the slot's own
            // file (the volume was reconstructed from those very
            // sources, which the fallback then deleted), so rewrite the
            // fragments to identity form. `D` records lose their crypto
            // marking too - the reconstruction wrote POSTED bytes.
            // Positional on purpose, mirroring `X`: a record appended
            // after this line already describes the materialized file,
            // and a later `X` over the volume file must still drop the
            // rewritten placements, which now name it.
            let Ok(mslot) = rest.trim().parse::<usize>() else {
                continue;
            };
            let Some((name, _)) = slot_meta.get(&mslot) else {
                continue; // no S yet: nothing recorded, nothing to rewrite
            };
            for (slot, frags, crypto_frag, crypto, _) in placed.values_mut() {
                if *slot != mslot {
                    continue;
                }
                for f in frags.iter_mut() {
                    f.file = name.clone();
                    f.file_off = f.vol_off;
                }
                crypto_frag.iter_mut().for_each(|c| *c = false);
                *crypto = false;
            }
        } else {
            resume.completed.insert(line);
        }
    }
    for (id, (slot, frags, crypto_frag, crypto, crc)) in placed {
        let Some((name, size)) = slot_meta.get(&slot) else {
            continue;
        };
        resume
            .slots
            .entry(slot)
            .or_insert_with(|| SlotPlacement {
                name: name.clone(),
                size: *size,
                articles: Vec::new(),
            })
            .articles
            .push(Article {
                id,
                frags,
                crypto_frag,
                crypto,
                crc,
            });
    }
}

// TODO 106: the read-back half - the plaintext-once re-encryption, the
// partial-quarantine dance that must precede it, and the placement
// replay itself - came out whole to journal/restore.rs. Free functions
// with their own private helpers, so nothing changed visibility; the
// re-export below puts every name back under `journal::` for the
// callers in nzbfast, the sibling extract tests and this file's own
// test module.
mod restore;

/// X5-01/02/04/05: the journal's identity invariants - bound to an
/// inode rather than to a path, and admitting only bytes it can
/// authenticate. Its own file because the pins are a family and this
/// one is already the workspace's largest module.
#[cfg(test)]
mod identity_tests;
pub use self::restore::{
    PARTIAL_SUFFIX, quarantine_partials, quarantine_paths, restore, restore_for,
    unquarantine_partials,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "journal_bench_tests.rs"]
mod journal_bench_tests;
