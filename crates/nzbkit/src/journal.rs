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
//!   ```
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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::disk::sanitize_filename;
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
        let f = File::open(dir.join(".nzbfast.journal")).ok()?;
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
    pub fn open(dir: &Path, nzb_bytes: &[u8]) -> std::io::Result<(Journal, ResumeState)> {
        use md5::{Digest, Md5};
        let fp = format!("{:x}", Md5::digest(nzb_bytes));
        let path = dir.join(".nzbfast.journal");
        std::fs::create_dir_all(dir)?;

        let mut resume = ResumeState::default();
        let mut valid = false;
        if let Ok(f) = File::open(&path) {
            let mut lines = utf8_lines(std::io::BufReader::new(f));
            if let Some(header) = lines.next()
                && header.strip_prefix("nzbfast-journal v1 ") == Some(fp.as_str())
            {
                valid = true;
                parse_lines(lines, &mut resume);
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        if !valid {
            // Fresh or mismatched: restart the journal.
            drop(file);
            file = File::create(&path)?;
            writeln!(file, "nzbfast-journal v1 {fp}")?;
            resume = ResumeState::default();
        }
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
    pub fn record_placed(
        &self,
        slot: usize,
        id: &str,
        slot_file: Option<(String, u64)>,
        name: &str,
        size: u64,
        frags: &[Frag],
    ) {
        self.record_letter('R', slot, id, slot_file, name, size, frags, None);
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
                        let mut n = sanitize_filename(name);
                        if st.used_names.contains(&n) {
                            n = format!("{slot:03}-{n}");
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
        let dest = sanitize_filename(name);
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
    pub fn remove(self) {
        // Nothing queued is worth landing in a file about to be unlinked.
        self.state.lock_ok().pending.clear();
        let _ = std::fs::remove_file(&self.path);
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
    let mut placed: HashMap<String, (usize, Vec<Frag>, Vec<bool>, bool)> = HashMap::new();
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
                let name = sanitize_filename(name);
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
                    .entry(sanitize_filename(name))
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
                        .entry(sanitize_filename(name))
                        .or_default()
                        .pad = Some(pad);
                }
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("F ") {
            if let Some((idx, name)) = rest.split_once(' ')
                && let Ok(idx) = idx.parse::<usize>()
                && !name.is_empty()
            {
                ftable.insert(idx, sanitize_filename(name));
            }
        } else if let Some(rest) = line.strip_prefix("S ") {
            let mut it = rest.splitn(3, ' ');
            if let (Some(slot), Some(size), Some(name)) = (it.next(), it.next(), it.next())
                && let (Ok(slot), Ok(size)) = (slot.parse::<usize>(), size.parse::<u64>())
                && !name.is_empty()
            {
                // Last S wins - a later run knows the actual file.
                slot_meta.insert(slot, (sanitize_filename(name), size));
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
                placed.insert(id.to_string(), (slot, frags, crypto_frag, crypto));
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
            let name = sanitize_filename(name);
            placed.retain(|_, (_, frags, _, _)| !frags.iter().any(|f| f.file == name));
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
            for (slot, frags, crypto_frag, crypto) in placed.values_mut() {
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
    for (id, (slot, frags, crypto_frag, crypto)) in placed {
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
pub use self::restore::{
    PARTIAL_SUFFIX, quarantine_partials, quarantine_paths, restore, restore_for,
    unquarantine_partials,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// [`Journal::peek`] is what the demotion watchdog reads (TODO
    /// 309(d)), and the whole of its value is that it agrees with
    /// [`Journal::open`] without WRITING - `open` creates the file,
    /// opens it for append and truncates it on a fingerprint mismatch,
    /// none of which may happen to a journal a running job still holds.
    ///
    /// So the three claims: it agrees on `placement_bytes`, it leaves
    /// the file byte-identical, and it refuses a file that is not a
    /// journal rather than parsing it as an empty one - which is what
    /// stops a stray file in an out_dir reading as "nothing restored".
    #[test]
    fn peek_agrees_with_open_and_writes_nothing() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-peek-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(Journal::peek(&dir).is_none(), "no journal, no answer");

        let (j, _) = Journal::open(&dir, b"<nzb/>").unwrap();
        for i in 0..3u64 {
            j.record_placed(
                0,
                &format!("<a{i}@x>"),
                None,
                "vol.part01.rar",
                3_000,
                &[Frag::identity("vol.part01.rar", i * 1_000, 1_000)],
            );
        }
        j.flush();
        let path = dir.join(".nzbfast.journal");
        let before = std::fs::read(&path).unwrap();

        let peeked = Journal::peek(&dir).expect("a journal we just wrote");
        assert_eq!(peeked.placement_bytes(), 3_000);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "a peek must not touch the file the running job is appending to"
        );
        // And it agrees with the reader the rerun itself will use.
        drop(j);
        let (_j2, resume) = Journal::open(&dir, b"<nzb/>").unwrap();
        assert_eq!(resume.placement_bytes(), peeked.placement_bytes());

        // Not a journal: refused, not read as empty.
        std::fs::write(&path, b"hello\nR 0 <a@x>\n").unwrap();
        assert!(Journal::peek(&dir).is_none(), "no v1 header, no answer");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn journal_roundtrip_and_fingerprint() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let nzb = b"<nzb>fake</nzb>";
        let (j, resume) = Journal::open(&dir, nzb).unwrap();
        assert!(resume.completed.is_empty());
        j.record("<a@x>");
        j.record("<b@x>");
        drop(j);

        // Same NZB: completed ids come back.
        let (j2, resume) = Journal::open(&dir, nzb).unwrap();
        assert_eq!(resume.completed.len(), 2);
        assert!(resume.completed.contains("<a@x>"));
        j2.record("<c@x>");
        drop(j2);
        let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
        assert_eq!(resume.completed.len(), 3);

        // Different NZB: journal resets.
        let (_j4, resume) = Journal::open(&dir, b"<nzb>other</nzb>").unwrap();
        assert!(resume.completed.is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// TODO 309(a): `largest_slot_bytes` reports the widest slot's FULL
    /// recorded size, and `placement_bytes` the sum of the fragments -
    /// two numbers a resumed run needs separately, because the replay's
    /// held bytes track the first and the admission gate used to be
    /// written against only the second.
    #[test]
    fn the_widest_slot_is_its_recorded_size_and_not_its_restored_bytes() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-wide-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let nzb = b"<nzb>wide</nzb>";

        let (j, resume) = Journal::open(&dir, nzb).unwrap();
        assert_eq!(resume.placement_bytes(), 0);
        assert_eq!(resume.largest_slot_bytes(), 0, "no placements, no slots");

        // Slot 0 is a big volume with a SMALL restored fragment; slot 1 a
        // small volume that happens to be fully restored. The sum of the
        // fragments makes slot 1 look like the larger of the two, and it
        // is the one that can hold less.
        j.record_placed(
            0,
            "<a@x>",
            None,
            "big.part01.rar",
            256_000_000,
            &[Frag::identity("big.part01.rar", 0, 1_000)],
        );
        j.record_placed(
            1,
            "<b@x>",
            None,
            "small.part01.rar",
            8_000_000,
            &[Frag::identity("small.part01.rar", 0, 8_000)],
        );
        drop(j);

        let (_j, resume) = Journal::open(&dir, nzb).unwrap();
        assert_eq!(resume.placement_bytes(), 9_000);
        assert_eq!(
            resume.largest_slot_bytes(),
            256_000_000,
            "the widest slot is the 256 MB volume, however little of it is on disk"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// One record torn mid-multibyte (ENOSPC, power loss) must not hide
    /// the valid records appended after it. `lines()` +
    /// `map_while(Result::ok)` stopped permanently at the first
    /// invalid-UTF-8 line, so every later completion was re-fetched on
    /// every retry, forever.
    #[test]
    fn a_torn_journal_line_does_not_hide_the_records_after_it() {
        // NOT "-torn-": `malformed_and_torn_lines_are_ignored` already
        // owns that directory, and two tests sharing one journal dir in
        // one process clobber each other's records (found 27 Aug 2026
        // as a parallel-run flake, len 3 vs 2).
        let dir =
            std::env::temp_dir().join(format!("nzbfast-journal-tornafter-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let nzb = b"<nzb>torn</nzb>";
        let (j, _) = Journal::open(&dir, nzb).unwrap();
        j.record("<a@x>");
        drop(j);
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(dir.join(".nzbfast.journal"))
                .unwrap();
            f.write_all(b"F 0 \xff\xfe torn\n").unwrap();
        }
        // This open must still see <a@x>, and the record IT appends
        // lands after the torn line.
        let (j2, resume) = Journal::open(&dir, nzb).unwrap();
        assert!(resume.completed.contains("<a@x>"));
        j2.record("<c@x>");
        drop(j2);

        let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
        assert!(
            resume.completed.contains("<c@x>"),
            "a record appended after a torn line must restore: {:?}",
            resume.completed
        );
        assert_eq!(resume.completed.len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn qdir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-quarantine-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The round trip that makes the rename free: a failed job's payload
    /// goes aside under a name nothing imports, and the next attempt
    /// gets the ORIGINAL name back with the bytes untouched. If either
    /// half broke, a retry would refetch the whole post instead of the
    /// one article it is missing.
    #[test]
    fn a_quarantined_partial_comes_back_under_its_own_name_with_its_bytes() {
        let d = qdir("roundtrip");
        std::fs::write(d.join("movie.mkv"), b"holed payload").unwrap();
        let (done, failed) = quarantine_partials(&d, &["movie.mkv".to_string()]);
        assert_eq!(done, vec!["movie.mkv".to_string()]);
        assert!(failed.is_empty());
        assert!(
            !d.join("movie.mkv").exists(),
            "the payload name must not survive a failed job"
        );
        assert!(d.join(format!("movie.mkv{PARTIAL_SUFFIX}")).exists());

        assert_eq!(unquarantine_partials(&d), vec!["movie.mkv".to_string()]);
        assert_eq!(
            std::fs::read(d.join("movie.mkv")).unwrap(),
            b"holed payload",
            "the bytes are the resume state - they must survive the round trip"
        );
        assert!(!d.join(format!("movie.mkv{PARTIAL_SUFFIX}")).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Volume files and every other resident are none of this pass's
    /// business: they are the classic resume target and nothing mistakes
    /// a holed `.part02.rar` for a finished download. Only the names the
    /// caller passes - the direct-extracted payload - move.
    #[test]
    fn quarantine_touches_only_the_named_payload() {
        let d = qdir("scope");
        for f in ["a.part01.rar", "a.par2", ".nzbfast.journal", "inner.mkv"] {
            std::fs::write(d.join(f), b"x").unwrap();
        }
        let (done, _) = quarantine_partials(&d, &["inner.mkv".to_string()]);
        assert_eq!(done, vec!["inner.mkv".to_string()]);
        for f in ["a.part01.rar", "a.par2", ".nzbfast.journal"] {
            assert!(d.join(f).exists(), "{f} must be left exactly where it is");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A payload the extractor reported but never wrote (a group that
    /// fell back, a name that lost a race) is not an error: there is
    /// nothing on disk to mislead anyone.
    #[test]
    fn a_payload_that_was_never_written_is_not_a_failure() {
        let d = qdir("absent");
        let (done, failed) = quarantine_partials(&d, &["never-written.mkv".to_string()]);
        assert!(done.is_empty() && failed.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A traversal name cannot reach outside the output directory -
    /// the same rule `drop_spared_metadata` relies on, and it matters
    /// more here because this end RENAMES rather than deletes.
    #[test]
    fn a_traversal_payload_name_stays_inside_the_out_dir() {
        let parent = qdir("traverse");
        let out = parent.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(parent.join("evil.mkv"), b"keep me").unwrap();
        quarantine_partials(&out, &["../evil.mkv".to_string()]);
        assert!(
            parent.join("evil.mkv").exists(),
            "sanitize_filename must keep the rename inside the output dir"
        );
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// The live file wins. If something else already owns the base name
    /// - a re-add into an occupied directory, a copy the user made -
    /// the quarantined bytes must NOT clobber it, and must not vanish
    /// either: guessing between two candidates is how a resume gets
    /// seeded with the wrong bytes.
    #[test]
    fn unquarantine_never_clobbers_a_file_that_already_holds_the_name() {
        let d = qdir("clobber");
        std::fs::write(d.join(format!("m.mkv{PARTIAL_SUFFIX}")), b"old").unwrap();
        std::fs::write(d.join("m.mkv"), b"live").unwrap();
        assert!(unquarantine_partials(&d).is_empty());
        assert_eq!(std::fs::read(d.join("m.mkv")).unwrap(), b"live");
        assert!(
            d.join(format!("m.mkv{PARTIAL_SUFFIX}")).exists(),
            "the loser is kept, not deleted"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// An ordinary directory has nothing to undo, and a bare suffix with
    /// no base name in front of it is not ours to rename to "".
    #[test]
    fn unquarantine_is_a_no_op_without_quarantined_files() {
        let d = qdir("noop");
        std::fs::write(d.join("a.mkv"), b"x").unwrap();
        std::fs::write(d.join(PARTIAL_SUFFIX), b"x").unwrap();
        assert!(unquarantine_partials(&d).is_empty());
        assert!(d.join("a.mkv").exists() && d.join(PARTIAL_SUFFIX).exists());
        assert!(unquarantine_partials(Path::new("/nonexistent/nzbfast-q")).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// §94 A: `restore_for(.., materialize_volumes = false)` must not
    /// write the volume file at all, and must say where each span's
    /// bytes actually are so the replay can read them from there.
    ///
    /// This is the whole disk saving. Materialising first writes a full
    /// extra copy of the resumed fraction and the replay then reads it
    /// back - the difference between a resumed job costing 2.02x
    /// payload of device I/O and 1.5x. If this test ever passes with a
    /// volume file on disk, that saving has been quietly given back.
    #[test]
    fn a_no_materialise_restore_writes_no_volume_and_names_the_real_source() {
        let dir = qdir("nomat");
        let inner: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.join("inner.bin"), &inner).unwrap();
        let plain: Vec<u8> = (0..30_000u32).map(|i| (i % 13) as u8).collect();
        std::fs::write(dir.join("plain.bin"), &plain).unwrap();

        let nzb = b"<nzb>nomat</nzb>";
        let (j, _) = Journal::open(&dir, nzb).unwrap();
        // Direct-extracted: volume bytes [5000,15000) live in inner.bin
        // at [10000,20000). Under materialisation this is the copy.
        j.record_placed(
            0,
            "<vol@x>",
            None,
            "vol.part1.rar",
            25_000,
            &[frag("inner.bin", 10_000, 5_000, 10_000)],
        );
        // Identity: the bytes never moved, so this one reports its own
        // file either way - which is also every PAR2 recovery volume,
        // and why the issue-#14 resume sniff still finds them on disk.
        j.record_placed(
            1,
            "<pl@x>",
            Some(("plain.bin".to_string(), 30_000)),
            "ignored",
            0,
            &[frag("plain.bin", 2_000, 2_000, 4_000)],
        );
        // A source that is too SHORT for its span must still fail its
        // article. The read happens later under no-materialise, so an
        // article admitted here would never refetch and the replay
        // would simply lose those bytes.
        j.record_placed(
            2,
            "<short@x>",
            None,
            "short.rar",
            9_000,
            &[frag("plain.bin", 29_000, 0, 8_000)],
        );
        drop(j);

        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore_for(&dir, &resume, None, false);
        assert!(restored.ids.contains("<vol@x>"));
        assert!(restored.ids.contains("<pl@x>"));
        assert!(
            !restored.ids.contains("<short@x>"),
            "a source too short for its span must drop its article"
        );
        assert!(
            !dir.join("vol.part1.rar").exists(),
            "the volume was materialised anyway - the replay's saving is gone"
        );

        let vol = restored.seeds.iter().find(|s| s.slot == 0).unwrap();
        assert_eq!(vol.spans, [(5_000, 10_000)]);
        assert_eq!(
            vol.sources
                .iter()
                .map(|(f, o)| (&**f, *o))
                .collect::<Vec<_>>(),
            [("inner.bin", 10_000)],
            "the span must name the file its bytes are really in"
        );
        let pl = restored.seeds.iter().find(|s| s.slot == 1).unwrap();
        assert_eq!(
            pl.sources
                .iter()
                .map(|(f, o)| (&**f, *o))
                .collect::<Vec<_>>(),
            [("plain.bin", 2_000)],
            "an identity span stays in its own file at its own offset"
        );

        // 27 Aug 2026 sweep F1: a §293 donation lands AFTER the
        // map-shape restore and forces the run onto the adopt shape,
        // whose seeds assert their spans are in the volume files - so
        // `get()` re-runs the restore MATERIALISING on the SAME state
        // the no-materialise pass already walked. Pin what that re-run
        // relies on: same admissions, and the volume bytes really land.
        let redone = restore_for(&dir, &resume, None, true);
        assert_eq!(
            redone.ids, restored.ids,
            "the re-run admits the same articles"
        );
        assert_eq!(
            std::fs::read(dir.join("vol.part1.rar")).unwrap()[5_000..15_000],
            inner[10_000..20_000],
            "the re-run put the span's bytes into the volume"
        );
        assert!(
            redone.seeds.iter().all(|s| s.sources.is_empty()),
            "re-run seeds are volume-resident, exactly what the adopt path asserts"
        );

        // And the twin: with materialisation ON, nothing changes from
        // what every earlier caller has always got.
        let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
        let mat = restore(&dir, &resume, None);
        assert!(dir.join("vol.part1.rar").exists(), "the volume is rebuilt");
        assert_eq!(
            std::fs::read(dir.join("vol.part1.rar")).unwrap()[5_000..15_000],
            inner[10_000..20_000],
            "and holds the bytes the placement points at"
        );
        assert!(
            mat.seeds.iter().all(|s| s.sources.is_empty()),
            "materialised seeds carry no source list - every span is in the volume"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TODO 309(b), 28 Aug 2026: a refused article is COUNTED, so the
    /// resume can say the bytes went back on the wire.
    ///
    /// The refusal itself is right and is pinned above; what was wrong
    /// is that it was invisible. `get/plan.rs` reports what it
    /// restored, so an out-dir something outside nzbfast had moved,
    /// truncated or deleted resumed looking exactly like an ordinary
    /// resume with less on disk.
    ///
    /// Both directions, and the zero side is the one that matters: a
    /// counter that fires on a clean resume would put a "your files
    /// moved" warning in front of every user who ever pauses, which is
    /// worse than the silence it replaces.
    #[test]
    fn a_refused_article_is_counted_so_the_resume_can_say_the_bytes_refetch() {
        let dir = qdir("dropcount");
        let plain: Vec<u8> = (0..30_000u32).map(|i| (i % 13) as u8).collect();
        std::fs::write(dir.join("plain.bin"), &plain).unwrap();
        let nzb = b"<nzb>dropcount</nzb>";

        let (j, _) = Journal::open(&dir, nzb).unwrap();
        // Admitted: an identity span wholly inside the file.
        j.record_placed(
            0,
            "<ok@x>",
            Some(("plain.bin".to_string(), 30_000)),
            "ignored",
            0,
            &[frag("plain.bin", 2_000, 2_000, 4_000)],
        );
        drop(j);
        let (_j, resume) = Journal::open(&dir, nzb).unwrap();
        let clean = restore_for(&dir, &resume, None, false);
        assert!(clean.ids.contains("<ok@x>"));
        assert_eq!(
            clean.dropped_source,
            (0, 0),
            "an ordinary resume must report nothing dropped, or every pause warns"
        );
        assert_eq!(clean.dropped_crypto, 0);

        // Now the shape the disclosure exists for: a second article
        // whose bytes are past the end of the file they were written
        // into. Two fragments, one of them fine, because an article is
        // admitted only whole - the honest figure is BOTH fragments,
        // since the whole article refetches.
        let (j, _) = Journal::open(&dir, nzb).unwrap();
        j.record_placed(
            1,
            "<gone@x>",
            None,
            "vol.part1.rar",
            40_000,
            &[
                frag("plain.bin", 1_000, 0, 500),
                frag("plain.bin", 29_000, 500, 8_000),
            ],
        );
        drop(j);
        let (_j, resume) = Journal::open(&dir, nzb).unwrap();
        let dropped = restore_for(&dir, &resume, None, false);
        assert!(
            dropped.ids.contains("<ok@x>") && !dropped.ids.contains("<gone@x>"),
            "the readable article still restores - one bad article is not a failed resume"
        );
        assert_eq!(
            dropped.dropped_source,
            (1, 8_500),
            "the refused article is counted whole, both fragments"
        );
        assert_eq!(
            dropped.dropped_crypto, 0,
            "a source that moved is not a password problem - the two causes stay apart"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn frag(file: &str, file_off: u64, vol_off: u64, len: u64) -> Frag {
        Frag {
            file: file.to_string(),
            file_off,
            vol_off,
            len,
        }
    }

    /// N5 moved record composition out of the shared lock into reused
    /// thread-local buffers. The grammar is a compatibility surface (an
    /// old binary resumes from these bytes), so pin the exact lines: S
    /// before any placement of its slot, every F before the first line
    /// that references its index, one record per line.
    #[test]
    fn record_letter_emits_the_exact_line_grammar() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-journal-golden-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (j, _) = Journal::open(&dir, b"<nzb>golden</nzb>").unwrap();
        j.record_placed(
            3,
            "<a@x>",
            None,
            "vol.rar",
            100,
            &[frag("in.bin", 1, 2, 3), frag("in2.bin", 40, 50, 60)],
        );
        j.record_placed_crypto(
            3,
            "<b@x>",
            None,
            "vol.rar",
            100,
            &[frag("in.bin", 7, 8, 9)],
            &[false],
        );
        j.record("<c@x>");
        let path = j.path.clone();
        drop(j);
        let text = std::fs::read_to_string(path).unwrap();
        let mut lines = text.lines();
        assert!(lines.next().unwrap().starts_with("nzbfast-journal v1 "));
        assert_eq!(lines.next(), Some("S 3 100 vol.rar"));
        assert_eq!(lines.next(), Some("F 0 in.bin"));
        assert_eq!(lines.next(), Some("F 1 in2.bin"));
        assert_eq!(lines.next(), Some("R 3 0:1:2:3,1:40:50:60 <a@x>"));
        assert_eq!(lines.next(), Some("D 3 0:7:8:9:0 <b@x>"));
        assert_eq!(lines.next(), Some("<c@x>"));
        assert_eq!(lines.next(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn placement_roundtrip_restore_and_copyback() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-v2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // "Run 1": inner.bin carries a direct-extracted article's bytes at
        // a translated offset; plain.bin holds an identity article.
        let inner: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.join("inner.bin"), &inner).unwrap();
        let plain: Vec<u8> = (0..30_000u32).map(|i| (i % 13) as u8).collect();
        std::fs::write(dir.join("plain.bin"), &plain).unwrap();

        let nzb = b"<nzb>v2</nzb>";
        let (j, _) = Journal::open(&dir, nzb).unwrap();
        // Direct-extracted: volume bytes [5000, 15000) live in inner.bin
        // at [10000, 20000).
        j.record_placed(
            0,
            "<vol@x>",
            None,
            "vol.part1.rar",
            25_000,
            &[frag("inner.bin", 10_000, 5_000, 10_000)],
        );
        // Identity (plain slot, writer existed).
        j.record_placed(
            1,
            "<pl@x>",
            Some(("plain.bin".to_string(), 30_000)),
            "ignored",
            0,
            &[frag("plain.bin", 2_000, 2_000, 4_000)],
        );
        // Fragment pointing at a file that will not exist → must drop.
        j.record_placed(
            2,
            "<gone@x>",
            None,
            "ghost.rar",
            9_000,
            &[frag("deleted.bin", 0, 0, 100)],
        );
        drop(j);

        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        assert_eq!(resume.slots.len(), 3);
        let restored = restore(&dir, &resume, None);
        assert!(
            restored.ids.contains("<vol@x>"),
            "copy-back article restored"
        );
        assert!(restored.ids.contains("<pl@x>"), "identity article restored");
        assert!(
            !restored.ids.contains("<gone@x>"),
            "missing source must drop"
        );

        // The copied bytes really moved: vol.part1.rar[5000..15000] ==
        // inner.bin[10000..20000], and the file spans the recorded size.
        let vol = std::fs::read(dir.join("vol.part1.rar")).unwrap();
        assert_eq!(vol.len(), 25_000);
        assert_eq!(&vol[5_000..15_000], &inner[10_000..20_000]);

        let seed = restored.seeds.iter().find(|s| s.slot == 0).unwrap();
        assert_eq!(seed.name, "vol.part1.rar");
        assert_eq!(seed.spans, vec![(5_000, 10_000)]);
        // Identity slot seeds too (its spans are trusted in place).
        assert!(restored.seeds.iter().any(|s| s.slot == 1));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The materialized-volume gap, measured 13 Aug 2026: a job whose
    /// direct extraction fell back to volumes-on-disk left complete
    /// volume files in the output directory, but its R records named the
    /// inner files the fallback had just deleted - so a retry refetched
    /// the ENTIRE post. The `M` line records that the fallback put those
    /// bytes at final offsets in the volume file, and parse rewrites the
    /// slot's placements to identity form.
    #[test]
    fn materialized_slot_restores_placements_as_identity() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-m-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>mat</nzb>";

        let (j, _) = Journal::open(&dir, nzb).unwrap();
        // Two direct-extracted articles whose fragments name an inner
        // file; a third on a slot that never demotes.
        j.record_placed(
            0,
            "<a@x>",
            None,
            "vol.part01.rar",
            20_000,
            &[frag("inner.bin", 7_000, 3_000, 5_000)],
        );
        j.record_placed(
            0,
            "<b@x>",
            None,
            "vol.part01.rar",
            20_000,
            &[frag("inner.bin", 12_000, 8_000, 5_000)],
        );
        j.record_placed(
            1,
            "<c@x>",
            None,
            "vol.part02.rar",
            20_000,
            &[frag("inner.bin", 0, 0, 100)],
        );
        // The demote: slot 0's bytes reconstructed into the volume file,
        // inner.bin deleted right after (so it does NOT exist here).
        j.record_materialized(0, "vol.part01.rar", 20_000);
        std::fs::write(dir.join("vol.part01.rar"), vec![0xAAu8; 20_000]).unwrap();
        drop(j);

        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore(&dir, &resume, None);
        assert!(
            restored.ids.contains("<a@x>") && restored.ids.contains("<b@x>"),
            "materialized slot's articles restore as identity, no inner file needed"
        );
        assert!(
            !restored.ids.contains("<c@x>"),
            "a slot that never demoted still needs its copy source"
        );
        let seed = restored.seeds.iter().find(|s| s.slot == 0).unwrap();
        assert_eq!(seed.name, "vol.part01.rar");
        let mut spans = seed.spans.clone();
        spans.sort();
        assert_eq!(spans, vec![(3_000, 5_000), (8_000, 5_000)]);
        // Identity means trusted in place: the volume's bytes are untouched.
        assert_eq!(
            std::fs::read(dir.join("vol.part01.rar")).unwrap(),
            vec![0xAAu8; 20_000]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The rewrite is positional, mirroring `X`: a record appended after
    /// the `M` line describes the file as it is now and is NOT rewritten,
    /// and an `X` retiring the volume file after the `M` drops the
    /// rewritten placements (which now name it).
    /// Codex sweep D, 13 Aug 2026: a PAR2 report renames a writerless
    /// slot after its `S` line landed, and the volume materializes
    /// under the VERIFIED name. Replay must rewrite the slot's
    /// placements onto the file that exists - the stale posted name
    /// restored nothing and the retry refetched the whole post.
    #[test]
    fn a_materialized_slot_renamed_after_its_s_line_restores_under_the_new_name() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-mren-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>matren</nzb>";

        let (j, _) = Journal::open(&dir, nzb).unwrap();
        // Recorded under the obfuscated posted name…
        j.record_placed(
            0,
            "<a@x>",
            None,
            "0Bf3qZlM8kTn4dWx",
            20_000,
            &[frag("inner.bin", 7_000, 3_000, 5_000)],
        );
        // …renamed from a PAR2 report while still writerless, then
        // materialized under that verified name.
        j.record_materialized(0, "verified.part01.rar", 20_000);
        std::fs::write(dir.join("verified.part01.rar"), vec![0xAAu8; 20_000]).unwrap();
        drop(j);

        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore(&dir, &resume, None);
        assert!(
            restored.ids.contains("<a@x>"),
            "the article is on disk under the verified name"
        );
        let seed = restored.seeds.iter().find(|s| s.slot == 0).unwrap();
        assert_eq!(seed.name, "verified.part01.rar");
        assert_eq!(seed.spans, vec![(3_000, 5_000)]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Codex sweep 13 Aug R3: the reverse ordering - the slot
    /// MATERIALIZES under its posted name, and the PAR2 verify renames
    /// it afterwards. The extractor re-fires the materialized hook on
    /// that rename, which lands here as a second `S new-name` + `M`
    /// pair: last-S-wins retargets the destination and the positional
    /// rewrite carries every earlier placement onto the file that now
    /// exists. Replay against a directory holding ONLY the verified
    /// name must restore every placement - it used to find nothing and
    /// refetch the whole post.
    #[test]
    fn a_rename_after_materialize_restores_under_the_new_name() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-renm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>renafter</nzb>";

        let (j, _) = Journal::open(&dir, nzb).unwrap();
        // Placed under the obfuscated posted name, demoted under it...
        j.record_placed(
            0,
            "<a@x>",
            None,
            "0Bf3qZlM8kTn4dWx",
            20_000,
            &[frag("inner.bin", 7_000, 3_000, 5_000)],
        );
        j.record_materialized(0, "0Bf3qZlM8kTn4dWx", 20_000);
        // ...one more placement while the demote-time name stands...
        j.record_placed(
            0,
            "<b@x>",
            None,
            "0Bf3qZlM8kTn4dWx",
            20_000,
            &[frag("0Bf3qZlM8kTn4dWx", 20_000, 9_000, 1_000)],
        );
        // ...and then the verified-name publish (the re-fired hook).
        j.record_materialized(0, "verified.part01.rar", 20_000);
        std::fs::write(dir.join("verified.part01.rar"), vec![0xAAu8; 20_000]).unwrap();
        drop(j);

        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore(&dir, &resume, None);
        assert!(
            restored.ids.contains("<a@x>") && restored.ids.contains("<b@x>"),
            "every placement is on disk under the verified name: {:?}",
            restored.ids
        );
        let seed = restored.seeds.iter().find(|s| s.slot == 0).unwrap();
        assert_eq!(seed.name, "verified.part01.rar");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Append the retirement lines an older build's finish decrypt
    /// would have written. Its producer (`Journal::invalidate`) went
    /// with TODO 27 phase 3 - nothing mutates an output under live
    /// records any more - but the PARSER stays, because a journal that
    /// build left behind must still resume correctly. So the tests that
    /// cover the parser write the record by hand.
    ///
    /// Append mode, and every caller DROPS its `Journal` first. Two
    /// reasons, and both bite: placement records sit in
    /// [`WriteState::pending`] behind the batch rule until a flush, so
    /// an `X` written past a live journal lands AHEAD of records that
    /// were composed before it and the retirement stops being
    /// positional; and the open handle's own offset does not move with
    /// these writes either, so a record appended through it afterwards
    /// would land on top of them.
    fn append_retirement(dir: &Path, files: &[&str]) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join(".nzbfast.journal"))
            .unwrap();
        for n in files {
            writeln!(f, "X {n}").unwrap();
        }
    }

    #[test]
    fn materialized_rewrite_is_positional_and_x_still_retires() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-mx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>matx</nzb>";

        // Before-M and after-M articles on the demoting slot.
        let (j, _) = Journal::open(&dir, nzb).unwrap();
        j.record_placed(
            0,
            "<pre@x>",
            None,
            "vol.rar",
            10_000,
            &[frag("gone.bin", 500, 100, 400)],
        );
        j.record_materialized(0, "vol.rar", 10_000);
        j.record_placed(
            0,
            "<post@x>",
            None,
            "vol.rar",
            10_000,
            &[frag("gone.bin", 500, 4_000, 400)],
        );
        std::fs::write(dir.join("vol.rar"), vec![0u8; 10_000]).unwrap();
        {
            let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
            let r = restore(&dir, &resume, None);
            assert!(r.ids.contains("<pre@x>"), "pre-M record rewrites");
            assert!(
                !r.ids.contains("<post@x>"),
                "post-M record keeps its own fragment sources"
            );
        }
        // Retire the volume file itself: the rewritten placements name it
        // now, so they must drop with it.
        drop(j);
        append_retirement(&dir, &["vol.rar"]);
        let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
        let r = restore(&dir, &resume, None);
        assert!(
            !r.ids.contains("<pre@x>"),
            "X after M retires the rewritten identity placements"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A `D` (plaintext-once) record on a materialized slot rewrites to
    /// PLAIN identity: the fallback reconstruction wrote POSTED bytes
    /// into the volume, so no crypt facts or password are needed.
    #[test]
    fn materialized_slot_restores_crypto_placements_as_plain_identity() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-md-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>matd</nzb>";

        let (j, _) = Journal::open(&dir, nzb).unwrap();
        j.record_placed_crypto(
            0,
            "<d@x>",
            None,
            "vol.rar",
            10_000,
            &[frag("secret.mkv", 2_000, 1_000, 3_000)],
            &[true],
        );
        j.record_materialized(0, "vol.rar", 10_000);
        std::fs::write(dir.join("vol.rar"), vec![0u8; 10_000]).unwrap();
        drop(j);

        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        // No password, no E facts on disk - identity needs neither.
        let r = restore(&dir, &resume, None);
        assert!(
            r.ids.contains("<d@x>"),
            "D record restores as plain identity after materialization"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An `M` line for a slot with no records (or a truncated volume
    /// file) must not fabricate restores: identity is still gated on the
    /// pre-restore file length.
    #[test]
    fn materialized_identity_still_respects_the_length_ceiling() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-ml-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>matl</nzb>";

        let (j, _) = Journal::open(&dir, nzb).unwrap();
        j.record_materialized(9, "", 0); // no S line for slot 9: harmless no-op
        j.record_placed(
            0,
            "<t@x>",
            None,
            "vol.rar",
            10_000,
            &[frag("gone.bin", 0, 6_000, 4_000)],
        );
        j.record_materialized(0, "vol.rar", 10_000);
        // The volume survived only truncated: the identity span [6000,
        // 10000) is past the end, so the bytes cannot be there.
        std::fs::write(dir.join("vol.rar"), vec![0u8; 5_000]).unwrap();
        drop(j);

        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        let r = restore(&dir, &resume, None);
        assert!(
            !r.ids.contains("<t@x>"),
            "identity past the pre-restore length must refetch"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Finding A8, the restart half. A run that publishes decrypted
    /// plaintext over an encrypted store output stops that file from being
    /// the ciphertext its placement records describe. The next run must
    /// refetch those articles from the provider rather than copy the
    /// mutated bytes into the volume files and call them restored - which
    /// is what poisoned the retry loop, since without PAR2 nothing was
    /// ever going to notice.
    #[test]
    fn retired_claim_refetches_instead_of_restoring_mutated_bytes() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-x-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>retire</nzb>";

        // Run 1 direct-extracts two articles into movie.mkv (ciphertext at
        // store offsets) and one into an untouched sibling.
        let cipher: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.join("movie.mkv"), &cipher).unwrap();
        std::fs::write(dir.join("extra.bin"), &cipher).unwrap();
        let (j, _) = Journal::open(&dir, nzb).unwrap();
        for (id, off) in [("<a@x>", 0u64), ("<b@x>", 10_000)] {
            j.record_placed(
                0,
                id,
                None,
                "v.part1.rar",
                30_000,
                &[frag("movie.mkv", off, off, 10_000)],
            );
        }
        j.record_placed(
            1,
            "<c@x>",
            None,
            "v.part2.rar",
            30_000,
            &[frag("extra.bin", 0, 0, 10_000)],
        );

        // Without the barrier those all come back - the intact-ciphertext
        // resume, the fast path a crash before the publish still gets.
        // (Records are batched - land them, as a decoder's idle flush
        // would have, before modelling the crash with a re-open.)
        j.flush();
        {
            let (_j, resume) = Journal::open(&dir, nzb).unwrap();
            let r = restore(&dir, &resume, None);
            assert!(r.ids.contains("<a@x>") && r.ids.contains("<b@x>") && r.ids.contains("<c@x>"));
            // Clear that probe's copy-back so the run below measures only
            // what the retirement allows.
            std::fs::remove_file(dir.join("v.part1.rar")).unwrap();
            std::fs::remove_file(dir.join("v.part2.rar")).unwrap();
        }

        // Now the decrypt publishes: the claim over movie.mkv is retired,
        // and only then do its bytes change.
        drop(j);
        append_retirement(&dir, &["movie.mkv"]);
        let plaintext: Vec<u8> = (0..40_000u32).map(|i| (i % 97) as u8).collect();
        std::fs::write(dir.join("movie.mkv"), &plaintext).unwrap();

        let (j2, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore(&dir, &resume, None);
        assert!(
            !restored.ids.contains("<a@x>") && !restored.ids.contains("<b@x>"),
            "articles recorded into a mutated file were treated as restored"
        );
        assert!(
            restored.ids.contains("<c@x>"),
            "retiring one file must not cost every other file its resume"
        );
        // Nothing was copied out of the mutated file either.
        assert!(!dir.join("v.part1.rar").exists());

        // Retirement is positional: the refetched articles re-record and
        // are trusted again, so a second crash still resumes locally.
        j2.record_placed(
            0,
            "<a@x>",
            None,
            "v.part1.rar",
            30_000,
            &[frag("movie.mkv", 0, 0, 10_000)],
        );
        drop(j2);
        let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore(&dir, &resume, None);
        assert!(
            restored.ids.contains("<a@x>"),
            "a placement recorded AFTER the retirement must still count"
        );
        assert!(
            !restored.ids.contains("<b@x>"),
            "the stale one stays retired"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An older binary reading a journal that carries retirement lines
    /// must not mistake them for message ids (it refetches everything,
    /// which is safe in both directions - the journal's forward/backward
    /// compatibility contract).
    #[test]
    fn retirement_lines_are_never_read_as_message_ids() {
        let mut resume = ResumeState::default();
        parse_lines(
            ["X movie.mkv".to_string(), "<real@id>".to_string()].into_iter(),
            &mut resume,
        );
        assert_eq!(resume.completed.len(), 1);
        assert!(resume.completed.contains("<real@id>"));
    }

    #[test]
    fn identity_without_existing_file_refetches() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>id</nzb>";
        let (j, _) = Journal::open(&dir, nzb).unwrap();
        j.record_placed(
            0,
            "<a@x>",
            Some(("data.bin".to_string(), 1_000)),
            "",
            0,
            &[frag("data.bin", 0, 0, 1_000)],
        );
        drop(j);
        // data.bin was deleted between runs (user cleanup): the identity
        // fragment must NOT be trusted against a file we'd create fresh.
        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore(&dir, &resume, None);
        assert!(restored.ids.is_empty());
        assert!(!dir.join("data.bin").exists(), "restore must not create it");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The path surviving is not the bytes surviving. A destination that
    /// was truncated between runs (a partial write, an interrupted move, an
    /// external tool) still passes an existence probe, so presence alone
    /// would accept its identity fragments; `seed_slot` then grows the file
    /// back to the recorded size and marks those spans covered, and with no
    /// PAR2 behind the job the zeros ship. Refetch instead.
    #[test]
    fn identity_against_truncated_file_refetches() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-journal-trunc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>trunc</nzb>";
        // Run 1 placed two identity articles into a 1,000-byte data.bin.
        std::fs::write(dir.join("data.bin"), vec![7u8; 1_000]).unwrap();
        let (j, _) = Journal::open(&dir, nzb).unwrap();
        j.record_placed(
            0,
            "<a@x>",
            Some(("data.bin".to_string(), 1_000)),
            "",
            0,
            &[frag("data.bin", 0, 0, 400)],
        );
        j.record_placed(
            0,
            "<b@x>",
            Some(("data.bin".to_string(), 1_000)),
            "",
            0,
            &[frag("data.bin", 400, 400, 600)],
        );
        drop(j);

        // Between runs the file is truncated to 400 bytes: only the first
        // article's span survives.
        std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("data.bin"))
            .unwrap()
            .set_len(400)
            .unwrap();
        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore(&dir, &resume, None);
        assert!(
            restored.ids.contains("<a@x>"),
            "a span the file still holds stays restored"
        );
        assert!(
            !restored.ids.contains("<b@x>"),
            "a span past the end of the file must refetch"
        );
        // Nothing past the truncation is handed to `seed_slot` as covered.
        let seeded: Vec<(u64, u64)> = restored
            .seeds
            .iter()
            .flat_map(|s| s.spans.iter().copied())
            .collect();
        assert_eq!(seeded, vec![(0, 400)]);
        assert!(
            seeded.iter().all(|&(off, len)| off + len <= 400),
            "no uncovered byte may be marked complete"
        );
        assert_eq!(
            std::fs::metadata(dir.join("data.bin")).unwrap().len(),
            400,
            "restore must not grow the file back"
        );

        // Truncated to nothing at all is the same verdict for both.
        std::fs::write(dir.join("data.bin"), b"").unwrap();
        let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore(&dir, &resume, None);
        assert!(restored.ids.is_empty(), "an empty file holds no span");
        assert!(restored.seeds.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn malformed_and_torn_lines_are_ignored() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-torn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>torn</nzb>";
        {
            let (j, _) = Journal::open(&dir, nzb).unwrap();
            j.record("<good@x>");
            drop(j);
        }
        // Simulate a torn tail + garbage placement lines.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(dir.join(".nzbfast.journal"))
                .unwrap();
            write!(f, "R 0 0:1:2:3 <no-ftable@x>\nS x y\nR 1 junk\nF 0\n<torn@").unwrap();
        }
        let (_j, resume) = Journal::open(&dir, nzb).unwrap();
        assert!(resume.completed.contains("<good@x>"));
        assert!(resume.slots.is_empty());
        // The torn bare line parses as a (harmless, never-matching) id.
        assert!(resume.completed.contains("<torn@"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
#[path = "journal_bench_tests.rs"]
mod journal_bench_tests;
