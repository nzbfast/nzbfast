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
//!                                          file is retired (see
//!                                          [`Journal::invalidate`])
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
    /// Slots whose `S` line is already emitted this run.
    slots_emitted: HashSet<usize>,
    /// File name → index in this run's `F` table.
    files: HashMap<String, usize>,
    /// Destination names already claimed by an `S` line this run.
    used_names: HashSet<String>,
}

pub struct Journal {
    state: Mutex<WriteState>,
    /// The finish decrypt's retire/publish bookkeeping. One mutex over
    /// all three fields: the workers run concurrently and every rule in
    /// [`Journal::record_decrypted`] reads one field against another.
    decrypt_stash: Mutex<DecryptStash>,
    pub path: PathBuf,
}

/// State shared by the finish decrypt's retire and publish halves.
#[derive(Default)]
struct DecryptStash {
    /// Placements parked by [`Journal::retire_for_decrypt`], keyed by the
    /// retired output name, waiting for [`Journal::record_decrypted`] to
    /// republish them as `D` records. An entry whose publish never comes
    /// (rename failed, job died first) just dies with the journal - the
    /// conservative refetch the bare retirement always meant.
    parked: HashMap<String, Vec<StashedArticle>>,
    /// Every name handed to [`Journal::retire_for_decrypt`] this run:
    /// files the decrypt is about to replace with plaintext. Registered
    /// BEFORE the `X` line is written, so any parse that can see the
    /// retirement can also see that we are the ones who wrote it.
    mutating: HashSet<String>,
    /// The subset of `mutating` whose plaintext is published AND whose
    /// crypt facts landed - the only files a `D` fragment may claim
    /// restore-by-re-encryption for.
    restorable: HashSet<String>,
}

/// One placement parked between retirement and decrypt-publish: enough
/// to re-emit the article as a `D` record under the slot's real
/// destination name.
struct StashedArticle {
    slot: usize,
    slot_name: String,
    slot_size: u64,
    id: String,
    frags: Vec<Frag>,
    /// Parsed per-fragment crypto markers (empty for `R` records).
    mask: Vec<bool>,
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

/// What [`restore`] managed to rebuild from a placement journal.
#[derive(Default)]
pub struct Restored {
    /// Articles whose every fragment restored - skip refetching these.
    pub ids: HashSet<String>,
    /// Per-slot seeds for the extractor/verifier: the volume file to
    /// adopt and the (offset, len) spans now on disk in it.
    pub seeds: Vec<SlotSeed>,
}

pub struct SlotSeed {
    pub slot: usize,
    pub name: String,
    pub size: u64,
    pub spans: Vec<(u64, u64)>,
}

impl Journal {
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
                    slots_emitted: HashSet::new(),
                    files: HashMap::new(),
                    used_names: HashSet::new(),
                }),
                decrypt_stash: Mutex::new(DecryptStash::default()),
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
            let _ = st.file.write_all(c.out.as_bytes());
        });
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
    #[allow(clippy::too_many_arguments)]
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

    #[allow(clippy::too_many_arguments)]
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
            let _ = st.file.write_all(out.as_bytes());
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
        let _ = st.file.write_all(out.as_bytes());
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
        let _ = st.file.write_all(out.as_bytes());
    }

    /// Retire this journal's claim over `files` - call it BEFORE their
    /// bytes stop being a faithful copy of what the `R` lines recorded,
    /// and only trust it once it returns `Ok`.
    ///
    /// The finish decrypt is the case that needs it: it replaces an
    /// encrypted RAR5 store output with its plaintext, and that output is
    /// exactly the file the placement records point INTO. Left claimed, a
    /// resume run would copy translated fragments out of the mutated file
    /// into the volume files and mark those message ids restored - so the
    /// articles are skipped instead of refetched, and without PAR2 the
    /// retry grinds on poisoned local bytes forever while the provider
    /// still holds every original article.
    ///
    /// Ordering is the whole point, so this is durable before it returns
    /// (one write, then fsync): a crash on either side of the call leaves
    /// a consistent pair. Before it, the file still IS the recorded bytes
    /// and the claim still stands (resume locally, no refetch); after it,
    /// the claim is gone whether or not the mutation ever landed (refetch,
    /// conservative but always correct).
    ///
    /// Retirement is positional, not global: it drops the placements
    /// recorded EARLIER in the journal, so a later run that refetches
    /// those articles and re-records them is trusted again.
    pub fn invalidate(&self, files: &[String]) -> std::io::Result<()> {
        if files.is_empty() {
            return Ok(());
        }
        // One buffer, one write: a power cut can then only lose the whole
        // batch (nothing was published yet, so the claim is still true) -
        // never tear a name into a line that retires the wrong file.
        let mut buf = String::new();
        for f in files {
            // Names can't carry a newline - `sanitize_filename` maps every
            // control character - so one line per file stays unambiguous.
            buf.push_str("X ");
            buf.push_str(f);
            buf.push('\n');
        }
        let mut st = self.state.lock_ok();
        st.file.write_all(buf.as_bytes())?;
        st.file.sync_data()
    }

    /// [`Journal::invalidate`] for the finish decrypt: retire the claim
    /// over `files` exactly as `invalidate` does, but first park every
    /// placement the retirement drops, so a decrypt that goes on to
    /// PUBLISH (verified plaintext renamed over the ciphertext) can hand
    /// them back via [`Journal::record_decrypted`] as `D` records - and a
    /// later failure in the same job (another file's ENOSPC, the nested
    /// pass) then costs the retry a local re-encrypt instead of a
    /// near-full refetch (TODO 100, Gary's 14.87 GB re-download).
    ///
    /// The parse happens under the writer lock, so the snapshot is
    /// consistent with every record already appended; the durable `X` is
    /// written before this returns, same contract as `invalidate`.
    pub fn retire_for_decrypt(&self, files: &[String]) -> std::io::Result<()> {
        if files.is_empty() {
            return Ok(());
        }
        let mut st = self.state.lock_ok();
        // Register the names BEFORE the parse and before the `X` line
        // lands: the write below happens under this same lock, so a
        // concurrent worker that can see our retirement in the file can
        // always see it here too. That ordering is what makes the parse
        // filter next deterministic rather than a race.
        let mine: Vec<String> = files.iter().map(|f| sanitize_filename(f)).collect();
        let mutating = {
            let mut d = self.decrypt_stash.lock_ok();
            d.mutating.extend(mine.iter().cloned());
            d.mutating.clone()
        };
        let mut resume = ResumeState::default();
        if let Ok(f) = File::open(&self.path) {
            let mut lines = utf8_lines(std::io::BufReader::new(f));
            let _ = lines.next(); // header: fingerprint already matched at open
            // Read THROUGH this run's own decrypt retirements. A sibling
            // worker's `X` drops every placement that names its file -
            // including an article whose span straddles into ours, which
            // is exactly the one we must park: our publish is what
            // re-records it, and if we let the sibling's `X` hide it the
            // article survives only in the sibling's snapshot, with our
            // fragment frozen as "ordinary copy" from before we were
            // decrypted. `record_decrypted` re-adjudicates every
            // fragment against `restorable`, so nothing parked here can
            // publish a claim the file cannot honour.
            parse_lines_through(lines, &mut resume, &mutating);
        }
        let mut stash = Vec::new();
        for name in mine {
            let mut arts = Vec::new();
            for (slot, sp) in &resume.slots {
                for a in &sp.articles {
                    if a.frags.iter().any(|f| f.file == name) {
                        arts.push(StashedArticle {
                            slot: *slot,
                            slot_name: sp.name.clone(),
                            slot_size: sp.size,
                            id: a.id.clone(),
                            frags: a.frags.clone(),
                            mask: a.crypto_frag.clone(),
                        });
                    }
                }
            }
            stash.push((name, arts));
        }
        // The durable X, before the caller mutates a byte - identical to
        // `invalidate` (one write, then fsync).
        let mut buf = String::new();
        for f in files {
            buf.push_str("X ");
            buf.push_str(f);
            buf.push('\n');
        }
        st.file.write_all(buf.as_bytes())?;
        st.file.sync_data()?;
        drop(st);
        #[cfg(test)]
        {
            // Test seam: the window between the durable retirement and
            // the parked snapshot. A sibling worker's whole retire +
            // publish can land in here, which is the interleaving the
            // `mutating`/`restorable` rules exist for. One-shot - the
            // first retirement to reach it consumes the pair, so the
            // sibling released into the window does not re-park here.
            let pair = RETIRE_STASH_BARRIER.lock_ok().take();
            if let Some((open, go)) = pair {
                open.wait();
                go.wait();
            }
        }
        let mut parked = self.decrypt_stash.lock_ok();
        for (name, arts) in stash {
            parked.parked.insert(name, arts);
        }
        Ok(())
    }

    /// The decrypt PUBLISHED `name` (plaintext verified and renamed into
    /// place): write its crypt facts (`E`/`K`/`T` events, collected from
    /// the ciphertext before the rename destroyed it) and republish the
    /// placements [`Journal::retire_for_decrypt`] parked as `D` records -
    /// the plaintext-once grammar, which a resume run restores by
    /// RE-ENCRYPTING the on-disk plaintext instead of refetching.
    ///
    /// Ordering makes this safe without an fsync: it runs only after the
    /// rename landed, so a kill anywhere leaves either the bare
    /// retirement (conservative refetch) or records that truthfully
    /// describe the published plaintext. Only power loss can reorder the
    /// two, the same exposure the in-stream `D` path already accepts -
    /// and the resume's full-hash verification is the backstop there.
    pub fn record_decrypted(&self, name: &str, events: &[CryptoJournalEvent]) {
        self.record_crypto_events(events);
        let key = sanitize_filename(name);
        // Snapshot the batch's state with the stash, under one lock.
        // Reading `restorable` at EMIT time - rather than flipping the
        // other parked stashes as each file publishes - is what makes
        // this independent of how the concurrent workers interleaved:
        // a stash that is still in flight when its neighbor publishes
        // cannot be flipped, and it used to publish the pre-decrypt
        // mask afterwards. Last R/D wins, so that stale record was the
        // one a resume obeyed: plain-copy PUBLISHED PLAINTEXT into a
        // volume as if it were the posted bytes, article marked
        // restored.
        let (arts, mutating, restorable) = {
            let mut d = self.decrypt_stash.lock_ok();
            // Before the early return: a file with nothing parked (its
            // placements were all retired by a sibling first) is still
            // published plaintext, and neighbors must see that.
            d.restorable.insert(key.clone());
            let Some(arts) = d.parked.remove(&key) else {
                return;
            };
            (arts, d.mutating.clone(), d.restorable.clone())
        };
        for a in arts {
            // A fragment in a sibling of this decrypt batch that has not
            // published its facts is unadjudicable HERE: it is either
            // still ciphertext (mask `false`) or already plaintext whose
            // facts never landed (unrestorable), and this side cannot
            // tell which. Park the whole article instead of guessing -
            // it refetches, the conservative outcome the bare retirement
            // always meant. The sibling's own publish re-emits it with
            // both fragments adjudicated, so nothing is lost when the
            // batch succeeds.
            if a.frags.iter().any(|f| {
                f.file != key && mutating.contains(&f.file) && !restorable.contains(&f.file)
            }) {
                continue;
            }
            // A fragment inside the published file now restores by
            // re-encryption, and so does one in any sibling that has
            // already published its facts; a genuinely plain neighbor
            // (never in this batch) keeps the ordinary copy.
            let mask: Vec<bool> = a
                .frags
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    a.mask.get(i).copied().unwrap_or(false)
                        || f.file == key
                        || restorable.contains(&f.file)
                })
                .collect();
            self.record_placed_crypto(
                a.slot,
                &a.id,
                Some((a.slot_name.clone(), a.slot_size)),
                &a.slot_name,
                a.slot_size,
                &a.frags,
                &mask,
            );
        }
    }

    /// Download finished and verified - the journal has served its purpose.
    pub fn remove(self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Test seam for [`Journal::retire_for_decrypt`]: two-stage, the house
/// shape (first barrier says the window is open, second releases it).
#[cfg(test)]
static RETIRE_STASH_BARRIER: Mutex<
    Option<(
        std::sync::Arc<std::sync::Barrier>,
        std::sync::Arc<std::sync::Barrier>,
    )>,
> = Mutex::new(None);

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
    parse_lines_through(lines, resume, &HashSet::new());
}

/// [`parse_lines`], but reading THROUGH the `X` retirements named in
/// `through` - the ones this run's own finish decrypt wrote. Only
/// [`Journal::retire_for_decrypt`] passes a non-empty set, and only to
/// build a stash that `record_decrypted` re-adjudicates; the resume
/// parse at open time always honours every `X`.
fn parse_lines_through(
    lines: impl Iterator<Item = String>,
    resume: &mut ResumeState,
    through: &HashSet<String>,
) {
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
            // Claim retired ([`Journal::invalidate`]): from here on this
            // file is no longer the bytes the records above describe, so
            // every placement with a fragment naming it - as a copy source,
            // or as its own identity destination - is dropped and those
            // articles refetch. Positional by construction: R lines after
            // this point describe the file as it is now and still count.
            if name.is_empty() {
                continue;
            }
            let name = sanitize_filename(name);
            if through.contains(&name) {
                continue;
            }
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

/// One plaintext-once fragment restore job for [`restore_crypto`]:
/// re-encrypt plaintext `[file_off, file_off+len)` of `file` and write
/// the resulting posted bytes at `vol_off` of the slot's volume file.
struct CryptoRestoreJob {
    article: usize, // index into a per-run article table
    file_off: u64,
    vol_off: u64,
    len: u64,
    dest: PathBuf,
    dest_size: u64,
}

/// Re-encrypt plaintext-once fragments back into volume files. Returns
/// per-article success (indexed like the caller's table). Walks each
/// file once in offset order with a rolling CBC chain, reseeding from
/// the journaled checkpoints across coverage holes and CROSS-VERIFYING
/// the rolling chain against every checkpoint it passes - a mismatch
/// (plaintext holes read as zeros, a truncated file) fails the fragment
/// and reseeds, so at most one checkpoint stride of garbage can ever be
/// written, and the resume run's full-hash verification catches even
/// that (restored bytes are never trusted unhashed).
fn restore_crypto(
    out_dir: &Path,
    resume: &ResumeState,
    password: Option<&str>,
    jobs_by_file: HashMap<&str, Vec<CryptoRestoreJob>>,
    article_ok: &mut [bool],
) {
    let Some(pw) = password else {
        for jobs in jobs_by_file.values() {
            for j in jobs {
                article_ok[j.article] = false;
            }
        }
        return;
    };
    for (fname, mut jobs) in jobs_by_file {
        let Some(meta) = resume.crypto_files.get(fname) else {
            for j in &jobs {
                article_ok[j.article] = false;
            }
            continue;
        };
        let fail_all = |jobs: &[CryptoRestoreJob], article_ok: &mut [bool]| {
            for j in jobs {
                article_ok[j.article] = false;
            }
        };
        let Some(keys) = crate::rarcrypt::derive_keys(pw, &meta.salt, meta.lg2) else {
            fail_all(&jobs, article_ok);
            continue;
        };
        // Prove the password before re-encrypting a single byte: a wrong
        // key would faithfully rebuild GARBAGE posted bytes for every
        // fragment, which the full-hash pass then damages wholesale. No
        // stored check means no proof - refetch instead of guessing.
        match meta.check {
            Some(stored) if crate::rarcrypt::make_check(&keys) == stored => {}
            _ => {
                fail_all(&jobs, article_ok);
                continue;
            }
        }
        let Ok(src) = File::open(out_dir.join(fname)) else {
            fail_all(&jobs, article_ok);
            continue;
        };
        let src_len = src.metadata().map(|m| m.len()).unwrap_or(0);
        let cipher_len = crate::rarcrypt::align16(meta.unp);
        let mut ckpts: Vec<(u64, [u8; 16])> =
            meta.checkpoints.iter().map(|(&o, &b)| (o, b)).collect();
        ckpts.sort_unstable();
        jobs.sort_by_key(|j| j.file_off);
        let mut dests: HashMap<PathBuf, Option<File>> = HashMap::new();
        // Rolling chain state: cipher block [cpos-16, cpos).
        let (mut cpos, mut chain): (u64, [u8; 16]) = (0, meta.iv);
        let mut walk = vec![0u8; 64 << 10];
        // Advance the rolling chain to `target` (16-aligned) by
        // encrypting the plaintext between, reseeding from the best
        // anchor at or below it; verify against every checkpoint passed.
        // Returns false when the stretch cannot be walked faithfully.
        let mut chain_to = |cpos: &mut u64, chain: &mut [u8; 16], target: u64| -> bool {
            if *cpos == target {
                return true;
            }
            // Best anchor at or below the target: the rolling state or
            // the nearest checkpoint, whichever is CLOSER. Every
            // decrypted region begins at a journaled K (the writer emits
            // one per decrypt boundary), so the nearest anchor is always
            // inside the target's own region and the walk can never
            // cross a coverage hole - the shape that used to re-encrypt
            // zero-filled plaintext into garbage posted bytes. The
            // password itself is proven against the stored check before
            // any of this runs.
            let (mut at, mut c) = (0u64, meta.iv);
            if *cpos <= target {
                (at, c) = (*cpos, *chain);
            }
            let below = ckpts.partition_point(|&(ko, _)| ko <= target);
            if let Some(&(ko, kb)) = ckpts[..below].iter().rev().find(|&&(ko, _)| ko > at) {
                (at, c) = (ko, kb);
            }
            let mut next_ck = ckpts.partition_point(|&(ko, _)| ko <= at);
            while at < target {
                let n = walk.len().min((target - at) as usize);
                if at + (n as u64) > src_len
                    || crate::disk::read_exact_at(&src, &mut walk[..n], at).is_err()
                {
                    return false;
                }
                let mut enc = crate::rarcrypt::CbcEncStream::new(&keys.aes(), &c);
                enc.encrypt(&mut walk[..n]);
                c = walk[n - 16..n].try_into().unwrap();
                at += n as u64;
                // Cross-verify each checkpoint the walk passes.
                while next_ck < ckpts.len() && ckpts[next_ck].0 <= at {
                    let (ko, kb) = ckpts[next_ck];
                    if ko > 0 && ko <= at {
                        let s = (n as u64 - (at - ko)) as usize;
                        let got: [u8; 16] = if s >= 16 {
                            walk[s - 16..s].try_into().unwrap()
                        } else {
                            c // ko == at edge: the rolling block
                        };
                        if got != kb {
                            return false;
                        }
                    }
                    next_ck += 1;
                }
            }
            (*cpos, *chain) = (at, c);
            true
        };
        for j in jobs {
            let lo = j.file_off & !15;
            let hi = (j.file_off + j.len).next_multiple_of(16).min(cipher_len);
            if hi <= lo || j.file_off + j.len > cipher_len {
                article_ok[j.article] = false;
                continue;
            }
            if !chain_to(&mut cpos, &mut chain, lo) {
                article_ok[j.article] = false;
                // Reseed for the next job from scratch.
                (cpos, chain) = (0, meta.iv);
                continue;
            }
            // Encrypt [lo, hi): plaintext from disk below unp, the
            // journaled padding beyond it.
            let n = (hi - lo) as usize;
            let mut buf = vec![0u8; n];
            let disk_end = hi.min(meta.unp);
            let mut ok = disk_end <= src_len;
            if ok && disk_end > lo {
                ok = crate::disk::read_exact_at(&src, &mut buf[..(disk_end - lo) as usize], lo)
                    .is_ok();
            }
            if ok && hi > meta.unp {
                match &meta.pad {
                    Some(pad) if pad.len() as u64 >= hi - meta.unp => {
                        let a = (meta.unp - lo) as usize;
                        buf[a..].copy_from_slice(&pad[..(hi - meta.unp) as usize]);
                    }
                    _ => ok = false,
                }
            }
            if !ok {
                article_ok[j.article] = false;
                continue;
            }
            let mut enc = crate::rarcrypt::CbcEncStream::new(&keys.aes(), &chain);
            enc.encrypt(&mut buf);
            let new_chain: [u8; 16] = buf[n - 16..].try_into().unwrap();
            let dest = dests.entry(j.dest.clone()).or_insert_with(|| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    // Never truncate: the writes below land at offsets
                    // inside a file this may be re-opening, and set_len
                    // only ever grows it.
                    .truncate(false)
                    .open(&j.dest)
                    .ok()
                    .inspect(|d| {
                        let cur = d.metadata().map(|m| m.len()).unwrap_or(0);
                        if j.dest_size > cur {
                            let _ = d.set_len(j.dest_size);
                        }
                    })
            });
            let Some(dest) = dest.as_ref() else {
                article_ok[j.article] = false;
                continue;
            };
            let a = (j.file_off - lo) as usize;
            if crate::disk::write_all_at(dest, &buf[a..a + j.len as usize], j.vol_off).is_err() {
                article_ok[j.article] = false;
                continue;
            }
            (cpos, chain) = (hi, new_chain);
        }
    }
}

/// Suffix worn by a failed job's unverified payload while it waits for a
/// retry. Chosen to be inert everywhere it might be seen: it is not a
/// media, archive or par2 extension, so no *arr import rule, media
/// scanner, unpack ladder or `looks_like_named_rar` scan claims it, and
/// a user reading their download folder can see at a glance that it is
/// not the file they asked for.
pub const PARTIAL_SUFFIX: &str = ".nzbfast-partial";

/// Take a failed job's direct-extracted payload out of circulation
/// WITHOUT throwing its bytes away.
///
/// A one-pass job writes the inner file straight to the output
/// directory, so a job that fails on missing articles leaves a payload
/// of exactly the right name and exactly the right size with a
/// zero-filled hole in the middle of it. That is the same false artifact
/// `drop_spared_metadata` deletes on the success path - "a holed .nfo
/// looks exactly like a real .nfo" - one level up, and it is worse here
/// because it is the deliverable itself: an *arr importing on name and
/// size takes it, a player opens it, and nothing about the directory
/// says otherwise.
///
/// Renamed rather than deleted, because those bytes are also the ONLY
/// resume state a retry has. The journal's placement (`R`) records
/// address fragments by their offsets INSIDE this file - direct-extracted
/// articles never touched a volume file - so deleting it turns a retry
/// that refetches one missing article into a retry that refetches the
/// whole post. [`unquarantine_partials`] puts the name back at the start
/// of the next attempt, before [`restore`] reads it, so the rename costs
/// a resume nothing.
///
/// This function's scope is payload NAMES the extraction reported; the
/// failing finish holds the downloaded volume files the same way
/// through [`quarantine_paths`] (TODO 159 item 1c - a failed job's
/// partial download must not keep wearing real volume names in the
/// output directory either). The discrimination over which downloaded
/// files are held lives with the caller, which can tell a volume from
/// a plain file the job proved whole.
///
/// Returns `(quarantined, failed)` by on-disk name. A failure is
/// reported, never swallowed - the caller is already failing the job,
/// but a payload that could not be renamed is still sitting there
/// looking real.
pub fn quarantine_partials(out_dir: &Path, payload: &[String]) -> (Vec<String>, Vec<String>) {
    let paths: Vec<PathBuf> = payload
        .iter()
        .map(|n| out_dir.join(sanitize_filename(n)))
        .collect();
    quarantine_paths(&paths)
}

/// Path-level half of [`quarantine_partials`]: rename each existing
/// file aside to `<name>.nzbfast-partial`, returning `(renamed,
/// failed)` by file name. Callers hand it the on-disk paths a failing
/// job must take out of circulation - the get tail's downloaded volume
/// files - where [`quarantine_partials`] builds paths from payload
/// names. A path already wearing the suffix is left alone, so a
/// second pass over the same directory cannot stack suffixes.
pub fn quarantine_paths(paths: &[PathBuf]) -> (Vec<String>, Vec<String>) {
    let (mut done, mut failed) = (Vec::new(), Vec::new());
    for from in paths {
        let Some(name) = from.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        if name.ends_with(PARTIAL_SUFFIX) || !from.exists() {
            continue;
        }
        let mut to = from.clone().into_os_string();
        to.push(PARTIAL_SUFFIX);
        match std::fs::rename(from, PathBuf::from(to)) {
            Ok(()) => done.push(name),
            Err(_) => failed.push(name),
        }
    }
    (done, failed)
}

/// Undo [`quarantine_partials`] at the start of an attempt, so the
/// journal's placement records find the file they address.
///
/// Must run BEFORE [`restore`]: a `.nzbfast-partial` file is invisible to
/// the restore pass, which would drop every article whose bytes live in
/// it and refetch them.
///
/// A base name that already exists is left alone and its quarantined
/// copy is NOT clobbered. That case means something other than this
/// mechanism put a file there - a re-add into an occupied directory, a
/// user's own copy - and the live file wins; guessing between two
/// candidates is how a resume ends up seeded with the wrong bytes.
/// Returns the names it restored.
pub fn unquarantine_partials(out_dir: &Path) -> Vec<String> {
    let mut back = Vec::new();
    let Ok(rd) = std::fs::read_dir(out_dir) else {
        return back;
    };
    for e in rd.flatten() {
        let p = e.path();
        let Some(n) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(base) = n.strip_suffix(PARTIAL_SUFFIX) else {
            continue;
        };
        if base.is_empty() {
            continue;
        }
        let dest = out_dir.join(base);
        if dest.exists() {
            continue;
        }
        if std::fs::rename(&p, &dest).is_ok() {
            back.push(base.to_string());
        }
    }
    back
}

/// Rebuild the volume files a resume run works with from a placement
/// journal: identity fragments (bytes already at their final offsets in
/// the destination) are trusted in place; translated fragments (bytes in
/// an extracted inner file) are COPIED back into the volume file - a
/// local disk copy instead of a network refetch - and plaintext-once
/// fragments (`D` records) are RE-ENCRYPTED back into posted bytes via
/// [`restore_crypto`]. An article counts as restored only when every
/// fragment succeeds; anything else refetches. Never fails: a missing
/// source file just drops its articles.
pub fn restore(out_dir: &Path, resume: &ResumeState, password: Option<&str>) -> Restored {
    let mut out = Restored::default();
    let mut buf = vec![0u8; 4 << 20];
    // Phase A: the crypto fragments, per file in offset order.
    let mut article_ids: Vec<(usize, &str)> = Vec::new(); // (slot, id)
    let mut jobs_by_file: HashMap<&str, Vec<CryptoRestoreJob>> = HashMap::new();
    let mut meta_missing: Vec<usize> = Vec::new();
    for (&slot, rec) in &resume.slots {
        if rec.name.is_empty() {
            continue;
        }
        for a in &rec.articles {
            if !a.crypto {
                continue;
            }
            let article = article_ids.len();
            article_ids.push((slot, &a.id));
            for (i, f) in a.frags.iter().enumerate() {
                if !a.crypto_frag.get(i).copied().unwrap_or(true) {
                    continue; // plain neighbor: phase B copies it
                }
                // A crypto fragment whose E facts are missing can only
                // refetch - falling through to a copy would put
                // PLAINTEXT into a volume file.
                if resume.crypto_files.contains_key(f.file.as_str()) {
                    jobs_by_file
                        .entry(f.file.as_str())
                        .or_default()
                        .push(CryptoRestoreJob {
                            article,
                            file_off: f.file_off,
                            vol_off: f.vol_off,
                            len: f.len,
                            dest: out_dir.join(&rec.name),
                            dest_size: rec.size,
                        });
                } else {
                    meta_missing.push(article);
                }
            }
        }
    }
    let mut article_ok = vec![true; article_ids.len()];
    for a in meta_missing {
        article_ok[a] = false;
    }
    // How long each destination already was, taken BEFORE phase A: phase A
    // opens every crypto slot's destination with `create(true)` + `set_len`,
    // so a file that was deleted between runs (user cleanup, or a spent-
    // volume sweep) is recreated as a hole and a phase-B existence probe
    // would then read true. Its identity fragments - "the bytes are already
    // where the resume expects them" - are zeros, and they would be accepted
    // instead of refetched, so with no PAR2 behind the job those zeros ship.
    //
    // The LENGTH, not just the existence, because a file that survived but
    // was truncated (a partial write, an interrupted move, an external tool)
    // fails the same way one step in: the path is there, so presence alone
    // says yes, but the bytes an identity fragment names are past the end.
    // `seed_slot` grows the file back to the recorded size and marks those
    // spans covered, so the hole ships. An identity fragment is trusted only
    // when the pre-restore file reached past the end of its span.
    // `identity_without_existing_file_refetches` and
    // `identity_against_truncated_file_refetches` are the tests for the intent.
    let pre_len: HashMap<&str, u64> = resume
        .slots
        .values()
        .filter(|r| !r.name.is_empty())
        .filter_map(|r| {
            Some((
                r.name.as_str(),
                std::fs::metadata(out_dir.join(&r.name)).ok()?.len(),
            ))
        })
        .collect();
    restore_crypto(out_dir, resume, password, jobs_by_file, &mut article_ok);
    let crypto_verdict: HashMap<(usize, &str), bool> = article_ids
        .iter()
        .zip(&article_ok)
        .map(|(&(slot, id), &ok)| ((slot, id), ok))
        .collect();
    // Phase B: per-article accounting + the plain copies.
    for (&slot, rec) in &resume.slots {
        if rec.name.is_empty() {
            continue;
        }
        let dest_path = out_dir.join(&rec.name);
        // `None` = no such file before this restore; `Some(n)` = it was n
        // bytes long, the ceiling an identity fragment has to fit under.
        let dest_len = pre_len.get(rec.name.as_str()).copied();
        let mut dest: Option<File> = None; // opened lazily, only for copies
        let mut srcs: HashMap<&str, Option<File>> = HashMap::new();
        let mut spans: Vec<(u64, u64)> = Vec::new();
        let mut restored_here = false;
        for Article {
            id,
            frags,
            crypto_frag,
            crypto,
        } in &rec.articles
        {
            if *crypto && crypto_verdict.get(&(slot, id.as_str())) != Some(&true) {
                continue;
            }
            let mut all_ok = true;
            for (fi, f) in frags.iter().enumerate() {
                // A crypto article's plaintext-once fragments were
                // written in phase A; only its plain-file fragments (a
                // span straddling into a neighboring unencrypted output)
                // still need the copy below.
                if *crypto && crypto_frag.get(fi).copied().unwrap_or(true) {
                    continue;
                }
                let identity = f.file == rec.name && f.file_off == f.vol_off;
                if identity {
                    // Bytes are already where the resume run expects them -
                    // nothing to move, but only if the file predates us AND
                    // was long enough to hold the span. A shorter file cannot
                    // be holding these bytes, whatever the journal says.
                    let held = dest_len.is_some_and(|n| f.file_off.saturating_add(f.len) <= n);
                    if !held {
                        all_ok = false;
                        break;
                    }
                    continue;
                }
                let src = srcs
                    .entry(f.file.as_str())
                    .or_insert_with(|| File::open(out_dir.join(&f.file)).ok());
                let Some(src) = src.as_ref() else {
                    all_ok = false;
                    break;
                };
                if dest.is_none() {
                    dest = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        // Never truncate - same reason as the encrypt
                        // path above: offset writes into a file that may
                        // already hold earlier records.
                        .truncate(false)
                        .open(&dest_path)
                        .ok()
                        .inspect(|d| {
                            let cur = d.metadata().map(|m| m.len()).unwrap_or(0);
                            if rec.size > cur {
                                let _ = d.set_len(rec.size);
                            }
                        });
                }
                let Some(dest) = dest.as_ref() else {
                    all_ok = false;
                    break;
                };
                let (mut done, mut ok) = (0u64, true);
                while done < f.len {
                    let n = ((f.len - done) as usize).min(buf.len());
                    if crate::disk::read_exact_at(src, &mut buf[..n], f.file_off + done).is_err() {
                        ok = false;
                        break;
                    }
                    if crate::disk::write_all_at(dest, &buf[..n], f.vol_off + done).is_err() {
                        ok = false;
                        break;
                    }
                    done += n as u64;
                }
                if !ok {
                    all_ok = false;
                    break;
                }
            }
            if all_ok {
                out.ids.insert(id.clone());
                for f in frags {
                    spans.push((f.vol_off, f.len));
                }
                restored_here = true;
            }
        }
        if restored_here {
            out.seeds.push(SlotSeed {
                slot,
                name: rec.name.clone(),
                size: rec.size,
                spans,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// One record torn mid-multibyte (ENOSPC, power loss) must not hide
    /// the valid records appended after it. `lines()` +
    /// `map_while(Result::ok)` stopped permanently at the first
    /// invalid-UTF-8 line, so every later completion was re-fetched on
    /// every retry, forever.
    #[test]
    fn a_torn_journal_line_does_not_hide_the_records_after_it() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-torn-{}", std::process::id()));
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
        j.invalidate(&["vol.rar".to_string()]).unwrap();
        drop(j);
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
        j.invalidate(&["movie.mkv".to_string()]).unwrap();
        let plaintext: Vec<u8> = (0..40_000u32).map(|i| (i % 97) as u8).collect();
        std::fs::write(dir.join("movie.mkv"), &plaintext).unwrap();
        drop(j);

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

    /// TODO 100, the publish half of the retirement handshake. The finish
    /// decrypt retires the claim over its output, mutates it to
    /// plaintext, and - once the rename LANDED - republishes the parked
    /// placements as `D` records with the crypt facts. A resume run then
    /// rebuilds the POSTED bytes by re-encrypting the local plaintext:
    /// zero refetch for a file that was already done, instead of the
    /// near-full re-download Gary watched.
    #[test]
    fn decrypt_publish_republishes_placements_as_restorable_d_records() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-dp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>decpub</nzb>";

        // A real RAR5-shaped crypt: password-derived key, IV, stored
        // check, 40 plaintext bytes -> 48 cipher bytes (8 pad).
        let pw = "s3cret";
        let (salt, lg2, iv) = ([7u8; 16], 4u8, [9u8; 16]);
        let keys = crate::rarcrypt::derive_keys(pw, &salt, lg2).unwrap();
        let unp = 40u64;
        let plain: Vec<u8> = (0..40u8).collect();
        let pad = vec![0xAAu8; 8];
        let mut cipher = plain.clone();
        cipher.extend_from_slice(&pad);
        crate::rarcrypt::CbcEncStream::new(&keys.aes(), &iv).encrypt(&mut cipher);

        // Run 1: the whole cipher stream direct-extracted into movie.mkv,
        // posted at volume offset 8 (behind a header).
        let (j, _) = Journal::open(&dir, nzb).unwrap();
        j.record_placed(
            0,
            "<enc@x>",
            None,
            "v.part1.rar",
            8 + cipher.len() as u64,
            &[frag("movie.mkv", 0, 8, cipher.len() as u64)],
        );
        // The finish decrypt: retire, mutate, publish.
        j.retire_for_decrypt(&["movie.mkv".to_string()]).unwrap();
        std::fs::write(dir.join("movie.mkv"), &plain).unwrap();
        j.record_decrypted(
            "movie.mkv",
            &[
                CryptoJournalEvent::Params {
                    name: "movie.mkv".into(),
                    salt,
                    lg2,
                    iv,
                    unp,
                    check: Some(crate::rarcrypt::make_check(&keys)),
                },
                CryptoJournalEvent::TailPad {
                    name: "movie.mkv".into(),
                    pad,
                },
            ],
        );
        drop(j);

        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        // A wrong password must prove out and refetch, never rebuild
        // garbage posted bytes.
        let r = restore(&dir, &resume, Some("wrong"));
        assert!(r.ids.is_empty(), "wrong password must refetch");
        // The right one restores the article with byte-exact posted bytes.
        let restored = restore(&dir, &resume, Some(pw));
        assert!(
            restored.ids.contains("<enc@x>"),
            "published plaintext must resume locally"
        );
        let vol = std::fs::read(dir.join("v.part1.rar")).unwrap();
        assert_eq!(
            &vol[8..],
            &cipher[..],
            "re-encrypted posted bytes must be byte-exact"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Sweep 2 M1: the finish decrypt runs its files on concurrent
    /// workers, and an article whose span straddles TWO encrypted
    /// outputs is parked by both. The dangerous interleaving is a whole
    /// retire+publish landing between a sibling's durable `X` and its
    /// parked snapshot: the sibling has no stash to be updated in, so it
    /// used to publish its pre-decrypt mask afterwards - "re-encrypt my
    /// half, plain-copy the neighbour's" - and last R/D wins, so a
    /// resume copied the neighbour's PUBLISHED PLAINTEXT into the volume
    /// as posted bytes and marked the article restored.
    ///
    /// Deterministic seam, not timing: `RETIRE_STASH_BARRIER` parks the
    /// first retirement exactly in that window.
    #[test]
    fn concurrent_decrypt_retirement_marks_both_straddled_fragments() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-dr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>decrace</nzb>";
        let pw = "s3cret";
        let lg2 = 4u8;

        // Two encrypted outputs, one salt each. Both plaintexts are a
        // whole number of AES blocks, so the cipher stream is the same
        // LENGTH as the plaintext - a wrong "plain copy" then produces
        // wrong volume BYTES rather than a short read, which is the
        // damage the finding describes.
        let build = |salt: [u8; 16], iv: [u8; 16], plain: Vec<u8>| {
            let keys = crate::rarcrypt::derive_keys(pw, &salt, lg2).unwrap();
            let mut cipher = plain.clone();
            crate::rarcrypt::CbcEncStream::new(&keys.aes(), &iv).encrypt(&mut cipher);
            (keys, plain, cipher)
        };
        let (keys_a, plain_a, cipher_a) = build([7u8; 16], [9u8; 16], (0..32u8).collect());
        let (keys_b, plain_b, cipher_b) = build([11u8; 16], [13u8; 16], (32..80u8).collect());
        let plain_c = b"a genuinely plain neighbour".to_vec();

        let la = cipher_a.len() as u64;
        let lb = cipher_b.len() as u64;
        let lc = plain_c.len() as u64;
        let vol_size = la + lb + lc;
        std::fs::write(dir.join("plain.bin"), &plain_c).unwrap();

        let (j, _) = Journal::open(&dir, nzb).unwrap();
        let j = std::sync::Arc::new(j);
        // One article, three fragments: the two encrypted outputs it
        // straddles plus a plain neighbour that must STAY an ordinary
        // copy (the fix must not over-mark).
        j.record_placed(
            0,
            "<span@x>",
            None,
            "v.part1.rar",
            vol_size,
            &[
                frag("a.bin", 0, 0, la),
                frag("b.bin", 0, la, lb),
                frag("plain.bin", 0, la + lb, lc),
            ],
        );

        let facts = |name: &str,
                     salt: [u8; 16],
                     iv: [u8; 16],
                     keys: &crate::rarcrypt::Rar5Keys,
                     unp: u64| {
            vec![
                CryptoJournalEvent::Params {
                    name: name.into(),
                    salt,
                    lg2,
                    iv,
                    unp,
                    check: Some(crate::rarcrypt::make_check(keys)),
                },
                CryptoJournalEvent::TailPad {
                    name: name.into(),
                    pad: Vec::new(),
                },
            ]
        };

        let open = std::sync::Arc::new(std::sync::Barrier::new(2));
        let go = std::sync::Arc::new(std::sync::Barrier::new(2));
        *RETIRE_STASH_BARRIER.lock_ok() = Some((open.clone(), go.clone()));

        // Worker A: retires a.bin, then parks in the window until the
        // whole of B has retired AND published.
        let ja = j.clone();
        let dir_a = dir.clone();
        let facts_a = facts("a.bin", [7u8; 16], [9u8; 16], &keys_a, plain_a.len() as u64);
        let wa = std::thread::spawn(move || {
            ja.retire_for_decrypt(&["a.bin".to_string()]).unwrap();
            std::fs::write(dir_a.join("a.bin"), &plain_a).unwrap();
            ja.record_decrypted("a.bin", &facts_a);
        });

        open.wait(); // A is past its durable `X`, before its snapshot parks
        j.retire_for_decrypt(&["b.bin".to_string()]).unwrap();
        std::fs::write(dir.join("b.bin"), &plain_b).unwrap();
        j.record_decrypted(
            "b.bin",
            &facts(
                "b.bin",
                [11u8; 16],
                [13u8; 16],
                &keys_b,
                plain_b.len() as u64,
            ),
        );
        go.wait(); // release A, which now parks and publishes last
        wa.join().unwrap();
        drop(j);

        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore(&dir, &resume, Some(pw));
        assert!(
            restored.ids.contains("<span@x>"),
            "the straddling article must still resume locally"
        );
        let vol = std::fs::read(dir.join("v.part1.rar")).unwrap();
        let mut want = cipher_a.clone();
        want.extend_from_slice(&cipher_b);
        want.extend_from_slice(&plain_c);
        assert_eq!(
            vol, want,
            "every straddled fragment must rebuild the POSTED bytes: \
             a fragment left marked as an ordinary copy plain-copies \
             published plaintext into the volume"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The conservative half stays conservative: a retirement whose
    /// publish never came (rename failed, process died between the two)
    /// keeps refetching exactly as the bare invalidate always did.
    #[test]
    fn retire_for_decrypt_without_publish_still_refetches() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-rp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>retire-park</nzb>";
        std::fs::write(dir.join("movie.mkv"), vec![1u8; 64]).unwrap();

        let (j, _) = Journal::open(&dir, nzb).unwrap();
        j.record_placed(
            0,
            "<a@x>",
            None,
            "v.part1.rar",
            64,
            &[frag("movie.mkv", 0, 0, 64)],
        );
        j.retire_for_decrypt(&["movie.mkv".to_string()]).unwrap();
        drop(j);

        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore(&dir, &resume, None);
        assert!(
            restored.ids.is_empty(),
            "an unpublished retirement must refetch"
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
