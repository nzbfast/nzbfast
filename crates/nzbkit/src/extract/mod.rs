//! Store-mode direct extraction (design: M3): decoded article spans are
//! written straight into the *extracted* files; RAR volumes never touch
//! disk on the happy path.
//!
//! The extractor owns all data-file writing in `get`:
//! - A slot is sniffed at its offset-0 article: RAR signature → mapping
//!   mode; anything else → plain mode (ordinary file, exactly the old
//!   behavior). Pre-sniff spans are held in memory (bounded).
//! - Mapping mode feeds the volume's [`VolumeMapper`]; spans intersecting
//!   known data areas `pwrite` into the inner file at
//!   `piece_base + offset_in_piece`; spans beyond the parsed region are
//!   held until more headers arrive.
//! - Volumes group by their FIRST inner-file name - obfuscation-proof
//!   (subjects lie, archive contents don't). Order within a group comes
//!   from RAR5 volume numbers, falling back to natural name sort
//!   (.partNN.rar, .rar < .r00 < .r01).
//! - Non-split pieces extract immediately (base 0); split continuations
//!   wait for every earlier volume's piece length (base resolution).
//! - Any blocker (compressed, encrypted, corrupt, holds cap) falls the
//!   whole group back to materialized volumes - already-extracted bytes
//!   are reconstructed into the volume files via the map, so nothing is
//!   lost and PAR2 repair sees ordinary files. The holds cap gets one
//!   relief valve first: held spans page to a scratch file
//!   ([`HoldSpan`]/[`HoldsScratch`]) and the set stays one-pass; only a
//!   breach of the scratch ceiling too demotes.
//! - [`Extractor::read_at`] serves byte-exact volume reads for the live
//!   verifier's read-back path (header stash + inner-file pread), so
//!   in-stream PAR2 verification of the *volume* blocks works even though
//!   volumes were never written.
//! - Nested store archives (a store-mode RAR whose payload is itself a
//!   store-mode RAR) route through a lazily-created CHILD extractor: each
//!   level-1 inner file becomes a dynamically-allocated child slot, and
//!   the child's own offset-0 sniff classifies it - RAR store magic means
//!   nested mapping (the inner archive never touches disk either), while
//!   anything else goes Plain (a real file, byte-identical to the
//!   single-level output). Read-back and coverage compose by delegation,
//!   so verifier settle, mapped repair, and fallback materialization keep
//!   working unchanged. Depth-capped; any blocker at a nested level
//!   demotes that level to a materialized file, never a failure.
//! - COMPRESSED RAR5 nested archives decompress while their bytes arrive
//!   (the chasing decompressor): the chased slot's spans feed a frontier
//!   buffer, a worker drives the RAR engine's streaming reader over the
//!   group's volumes in order, and extracted members route back through
//!   the same child seam - so store archives below a compressed layer
//!   still stream. Any chase failure demotes to the materialize path.
//! - 7z nested archives extract in-stream via tail prefetch: a child slot
//!   sniffing 7z magic parses the 32-byte start header, asks the promote
//!   hook to front-load the articles carrying the end header (the archive
//!   map lives at the tail), and a worker drives the 7z engine through a
//!   blocking Read+Seek view of the arriving bytes - entries stream into
//!   fresh child slots (the same routing seam). Header-encrypted without
//!   a password, unsupported codecs, budget breach, and missing bytes all
//!   demote to a materialized .7z for the disk post-pass.

use crate::sync::MutexExt;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};

use crate::disk::{FileWriter, out_name_of, sanitize_out_name};
use crate::rar::{ArchiveMap, ArithGate, EntryCrypt, MapBlocker, Method, RarVersion, VolumeMapper};
use crate::rarcrypt;

mod chase;
mod config;
mod crypto;
mod deliver;
mod frontier;
mod gate;
mod holds;
mod holds_ledger;
mod names;
mod park;
mod prevalence;
mod reader;
mod reasons;
mod routing;
mod settle;
mod sevenz;
mod shape;
mod split;
mod tar;
#[cfg(test)]
mod testutil;
mod zip;
mod zip_split;

use chase::*;
pub use chase::{DroppedVolume, LossDoubt};
use config::*;
pub use config::{
    NESTED_MAX_DEPTH_HARD_CEILING, nested_cap_after_store_layer, nested_depth_cap,
    prefer_external_unrar, set_nested_depth_cap, set_prefer_external_unrar,
};
pub use crypto::CryptoJournalEvent;
use crypto::*;
use frontier::*;
use holds::*;
pub use holds_ledger::{HoldsLedger, install_process_ledger, process_ledger};
// `archive_sniff_eligible_name` and its path form are public rather than
// `pub(crate)` on purpose: the DISK post-pass asks the identical
// question, and it must reach for these rather than write a second
// grammar for one question. It carried that second grammar until 31 Aug
// 2026 - nine sites spelling `!is_final_file(p) && magic(p)`, which is
// the same rule with the payload-content half missing - and all nine
// now call `archive_sniff_eligible`. The roll-call, and which one
// actually loses the file, is at `archive_sniff_eligible_name`.
pub use names::{
    archive_sniff_eligible, archive_sniff_eligible_name, is_final_file, is_final_name,
    release_stem, vol_sort_key,
};
pub use park::{ParkHook, WireGauge};
use reasons::*;
pub use reasons::{
    SEVENZ_DISK_FALLBACK_PREFIX, SFX_DISK_FALLBACK_PREFIX, TAR_DISK_FALLBACK_PREFIX,
    ZIP_DISK_FALLBACK_PREFIX,
};
mod resume;
pub use resume::ResumeOutput;
use routing::Sniffed;
use settle::*;
use sevenz::*;
use shape::*;
pub use shape::{
    ArchiveShape, DiskArchive, NestedDisposition, NestedPrevalence, nested_prevalence,
    note_nested_level, reset_nested_prevalence, shape_word,
};
use split::*;
pub use split::{RAR_SPLIT_MISALIGNED, rar_split_part_name};

/// Article-promotion hook (nested 7z tail prefetch, offset-0 probe):
/// `(output name, file size, byte spans, urgent)` of a file at THIS
/// extractor's level - the daemon wires the root's hook to its
/// seek/promote ladder, which front-loads the pending articles carrying
/// those bytes. `urgent` promotes may also flip the pool into stream
/// mode (shallow pipelines, 60 s linger) because a worker is BLOCKED on
/// the bytes (the 7z chase reading its footer); non-urgent ones (the
/// offset-0 classification probe) just reorder the queue - a scrambled
/// many-volume set probes once per slot, and stream mode for the whole
/// download would cost real throughput on long links.
pub type PromoteHook = Arc<dyn Fn(&str, u64, &[(u64, u64)], bool) + Send + Sync>;

/// Slot demoted to a materialized volume: its reconstruction (header
/// stash + inner-file read-back + held-span drain) has fully landed, so
/// every placement the journal recorded for this ROOT slot - fragments
/// naming inner files the fallback is about to delete - now also sits at
/// its final offsets in the slot's own volume file. The daemon wires
/// this to `Journal::record_materialized`, whose `M` line lets a resume
/// restore those articles as identity instead of refetching the whole
/// post (the measured 13 Aug 2026 gap: a retry over volumes-on-disk
/// pulled every article again). Root level only, deliberately not
/// inherited by children: the journal's slot space is the root's, and a
/// nested demote materializes an inner file, not a volume.
///
/// Called with (slot, the slot's CURRENT filename, its size). The name
/// matters: a PAR2 report can rename a writerless slot between the `S`
/// line that first recorded it and this demote, and the volume is then
/// materialized under the verified name. Recording the demote against
/// the stale posted name pointed every rewritten placement at a file
/// that does not exist, so the retry refetched the post it was holding.
pub type MaterializedHook = Arc<dyn Fn(usize, &str, u64) + Send + Sync>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SlotMode {
    /// Waiting for the offset-0 article to sniff.
    Unknown,
    /// Ordinary file - write through.
    Plain,
    /// RAR volume in mapping mode.
    Rar,
    /// Compressed RAR5 volume being chased: spans feed the slot's
    /// frontier buffer, the chase worker decodes behind the frontier.
    RarChase,
    /// Inner 7z archive being chased (child slots only): spans feed the
    /// slot's frontier buffer, the 7z worker parses/decodes through a
    /// blocking Read+Seek view (footer first, via tail prefetch).
    SevenZ,
    /// RAR volume after fallback - volume file materialized.
    RarFallback,
    /// TODO 211 (b): continuation part of a declared `.rar.NNN` byte
    /// split, aliased onto its head - every byte it receives feeds the
    /// head's mapper at `split_alias`'s logical offset (see `split.rs`).
    SplitPart,
    /// Source-protected fallback: the slot's bytes already live in a real
    /// file the caller owns (re-extraction reads volumes off disk), so a
    /// fallback must never materialize - writes are dropped instead.
    Discard,
}

struct Slot {
    mode: SlotMode,
    name: String,
    size: u64,
    /// `vol_sort_key(&name)`, computed once - `reresolve` runs per volume
    /// arrival over EVERY group slot, and recomputing the key allocated
    /// 2-3 Strings per slot per call (quadratic on many-volume sets).
    sort_key: Option<(u64, String)>,
    /// Pre-sniff / unmappable spans (RAM or paged to scratch).
    holds: Vec<(u64, HoldSpan)>,
    /// Bytes held while still Unknown (pre-classification). Bounded by
    /// the per-slot spill: an NZB with synthesized segment numbering
    /// ("segment 1" is not the yEnc offset-0 article - seen live on a
    /// fully-obfuscated 9.6 GB single-file post) would otherwise hold the
    /// entire file in RAM waiting for a sniff that may come last.
    pre_bytes: usize,
    /// Lowest offset this slot has ever held, and the estimator the
    /// rotation guess is derived from ([`Extractor::probe_offset0`]).
    /// `u64::MAX` until the first out-of-order span arrives.
    probe0_min: u64,
    /// Offset-0 promotes fired for this slot, capped at
    /// [`holds::PROBE0_MAX`]. Nonzero is the old `probe0_sent` latch -
    /// the late-head grace reads it as "this slot asked for its head".
    probe0_promotes: u8,
    /// This slot is Plain because the offset-0 sniff LOOKED and found no
    /// archive shape worth mapping or chasing - an ordinary payload file
    /// (or an archive bound for a post-pass, which reads the same file
    /// off disk either way). False for the other road to Plain: the
    /// spill/overflow give-up, where classification never ran and the
    /// bytes may be a RAR volume whose header article was lost.
    ///
    /// The distinction exists for exactly one caller,
    /// [`Extractor::is_plain_patchable`] (TODO 160): a sniffed-plain
    /// slot's file IS its own output, so mapped repair may patch damage
    /// straight into it, while a given-up volume keeps declining to the
    /// materialize + `repair_dir` path that has always owned it.
    plain_by_sniff: bool,
    /// Plain-file or materialized-volume writer.
    writer: Option<Arc<FileWriter>>,
    mapper: Option<VolumeMapper>,
    /// Raw header/meta bytes (offset, bytes) kept for reconstruction
    /// (RAM or paged to scratch, like `holds`).
    header_spans: Vec<(u64, HoldSpan)>,
    /// Canonical group key (the archive's identity), set once entries
    /// parse. Groups start keyed by a volume's first inner-file name and
    /// merge when split pieces prove two keys are one archive.
    group: Option<String>,
    /// Chase attachment (modes RarChase and SevenZ): the slot's
    /// in-flight bytes.
    chase: Option<ChaseSlot>,
    /// 7z chase control (mode SevenZ): the worker and its sink slots.
    sevenz: Option<Arc<SevenZCtl>>,
    /// Which container format the SevenZ-mode chase is driving (see
    /// [`ChaseFormat`]). Set at attach; meaningless outside that mode.
    container_fmt: ChaseFormat,
    /// Entry index → composed CRC32 of the routed piece bytes, for the
    /// finish-time check against the RAR5 header CRC. That check is the
    /// only verifier a store payload has - the download's PAR2 vouches
    /// for the OUTER bytes as posted, damage the poster packed in
    /// included. Nested levels always compose; level 0 composes under
    /// the verify_output_crc gate.
    piece_crcs: HashMap<usize, CrcRuns>,
    /// Increment A (one-pass encrypted plan): the mapper hit a
    /// password-shaped blocker while a candidate probe may still find
    /// the password (a sidecar in this very NZB, the release stem).
    /// While set, spans park in `holds` (same budget, same read_at
    /// visibility) instead of demoting; a Verified probe hit rebuilds
    /// the mapper keyed and re-feeds them, a miss demotes through the
    /// exact path this state deferred - the stored reason keeps the
    /// finish ladder's remediation keyed the same either way.
    pw_await: Option<&'static str>,
    /// §156.1: an article of this slot got a terminal verdict. Sticky;
    /// what lets a chase attaching (or a member routing) AFTER the
    /// verdict still learn its volume is doomed - see
    /// `Extractor::mark_slot_lost`.
    article_lost: bool,
    /// Consumed prefix ranges a dropping drop-behind trim released with
    /// no disk copy, carried here by the demote that materialized the
    /// rest of the volume: the file on disk has holes exactly here, and
    /// the caller re-fetches them (`Extractor::dropped_volumes`). Empty
    /// on every slot that was never demoted after a drop.
    dropped: Vec<(u64, u64)>,
    /// The posted name those ranges were dropped under (see
    /// `ChaseSlot::dropped_as`).
    dropped_as: String,
    /// TODO 211 (b): this Unknown slot sniffed headless at offset 0 and
    /// is a continuation part waiting for its declared set's head.
    split_wait: bool,
    /// Mode `SplitPart`: `(head slot, logical offset of this part's byte
    /// 0)` - the one translation every slot-addressed path applies.
    split_alias: Option<(usize, u64)>,
    /// Part 1 of a declared split: the set's base (key into
    /// `Inner::rar_splits`). Its mapper spans the whole joined volume.
    split_head: Option<String>,
}

struct Group {
    slots: Vec<usize>,
    /// (slot, entry) → inner-file base offset, rebuilt as mappers progress.
    bases: HashMap<(usize, usize), u64>,
    /// (slot count, numbered-mapper count, total parsed entries) at the
    /// last `reresolve` recompute. Order and bases are pure functions of
    /// these, so an unchanged stamp skips the sort + resolve entirely -
    /// `reresolve` fires on every parse progression, roughly twice per
    /// volume, and recomputing from scratch each time was O(V^2) per set.
    resolve_stamp: Option<(usize, usize, u64)>,
    /// (slot, entry) bases placed by the ARITHMETIC gate (uniform
    /// single-file store sets, `ArchiveMap::resolve_arithmetic`) that
    /// nothing else has confirmed yet: valid under the uniform premise,
    /// but beyond what chain resolution has reached. Confirmed (removed)
    /// when the chain independently derives the same value or when the
    /// complete set closes at settle; a contradiction, or leftovers at
    /// settle, demote the whole group ("non-uniform store set"). Bytes
    /// may already sit at these offsets, so an entry here must keep its
    /// value in `bases` until confirmed or demoted - fallback read-back
    /// reconstructs volumes through the base each byte was WRITTEN under.
    arith_provisional: HashMap<(usize, usize), u64>,
    /// Latched when the arithmetic gate ever placed beyond the chain -
    /// test introspection (the multi-file regression asserts it stays
    /// unset on the chain path).
    arith_ever: bool,
    fallback: bool,
    fallback_reason: Option<String>,
    /// sanitized inner-file name → actual output filename. Output files
    /// are OWNED by their group: another archive in the same NZB reusing
    /// an inner name gets its own (disambiguated) file, and a fallback
    /// deletes only the files listed here - never another group's.
    out_names: HashMap<String, String>,
    /// raw inner-file name → the child's stable Plain writer (Finding 4):
    /// once a routed child classifies as Plain that mode never changes, so
    /// later articles write straight to its file from the parent's job
    /// drain instead of walking the parent-lock / child-lock /
    /// revalidation ladder per article. `routed` stays authoritative for
    /// fallback, finish, and merge; this cache is cleared whenever those
    /// paths touch the route, and the post-write RarFallback recheck in
    /// write_impl still guards the race.
    routed_plain: HashMap<String, (usize, Arc<FileWriter>)>,
    /// sanitized inner-file name → CHILD slot, for inner files routed
    /// into the nested child extractor. Group-owned for the same reason
    /// as `out_names`: two archives reusing an inner name must not share
    /// a destination, and a fallback abandons only its own child slots.
    routed: HashMap<String, usize>,
    /// Live chasing decompressor over this group's volumes (compressed
    /// RAR5 inner archive). Cleared at finish once the worker is joined.
    chase: Option<Arc<ChaseCtl>>,
    /// §94 D: lowercased bases of byte-split zip sets this group has
    /// routed into the child and not yet closed (counted or refused).
    /// Empty for every ordinary set, which is what keeps the close walk
    /// off the per-volume `reresolve` path entirely.
    zip_splits_open: Vec<String>,
}

pub struct ExtractReport {
    /// Inner files written via direct extraction (name, size).
    pub extracted: Vec<(String, u64)>,
    /// Groups that fell back to materialized volumes (key, why).
    pub fallbacks: Vec<(String, String)>,
    /// Bytes that went through the direct-extraction path.
    pub extracted_bytes: u64,
    /// Extracted files that were AES-decrypted natively - no unrar
    /// involved. Decryption happens at article-write time
    /// (plaintext-once); this is the list finish ADJUDICATED, so a name
    /// here means its plaintext was checked against what the archive
    /// stored for it and published.
    pub decrypted: Vec<String>,
    /// Partial in-stream outputs a budget-forfeited chase LEFT on disk,
    /// with the byte count each is good to - see [`ResumeOutput`]. Empty
    /// for every other job shape.
    pub resume_outputs: Vec<ResumeOutput>,
}

/// Where one piece of an article's decoded bytes landed on disk: `len`
/// bytes at `file_off` of `file` (a name in the out dir), carrying the
/// volume-view bytes at `vol_off` (article yEnc offset + span offset).
/// The crash-resume journal records these so a later run can rebuild the
/// volume file from wherever the bytes physically went - identity for
/// plain files, translated for direct-extracted inner files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frag {
    pub(crate) file: String,
    pub(crate) file_off: u64,
    pub vol_off: u64,
    pub len: u64,
}

impl Frag {
    /// An identity fragment: `len` bytes of volume-view `[vol_off, ..)`
    /// sitting at that very offset in `file`. What a materialized
    /// volume's own coverage vouches for - see
    /// [`Extractor::materialized_span_on_disk`].
    pub fn identity(file: &str, vol_off: u64, len: u64) -> Frag {
        Frag {
            file: file.to_string(),
            file_off: vol_off,
            vol_off,
            len,
        }
    }

    /// Rebase this fragment to identity form in `file`: the bytes sit at
    /// their volume offset in the named file itself. The journal writer
    /// uses it for articles that complete after their slot demoted to a
    /// materialized volume, whose original fragments may name inner
    /// files the fallback deleted.
    pub fn rebase_identity(&mut self, file: &str) {
        self.file = file.to_string();
        self.file_off = self.vol_off;
    }
}

/// What [`Extractor::write`] did with a span, for the crash-resume
/// journal. `Placed` means EVERY byte of the article is durably on disk
/// at the recorded fragments - the only state a plain `R` record may
/// describe. `PlacedCrypto` is the same coverage claim for a span that
/// fed an in-stream-decrypted (plaintext-once) file: what is on disk is
/// PLAINTEXT, so it journals as a `D` record that a resume can only
/// honor by re-encrypting through the file's journaled `E`/`K`/`T`
/// facts - an old binary parses `D` as an unknown message-id and simply
/// refetches. Header bytes retained in memory and discarded spans
/// return `No`.
///
/// `Held` means bytes of THIS span were parked for a later re-feed
/// (pre-classification hold, unresolved split base, beyond the mapped
/// window) - the article is not on disk yet, but may become so when the
/// holds drain. It carries the span's partial plain placements (may be
/// empty); the caller parks the article and completes its journal
/// record from [`Extractor::drain_late_placements`] once the drained
/// writes cover the rest. Without this, an article that arrived before
/// the offset-0 sniff established the store mapper was fully written by
/// the drain yet never journaled, so every crash/ENOSPC resume
/// refetched it for no reason.
pub enum Persist {
    No,
    Placed(Vec<Frag>),
    PlacedCrypto(Vec<Frag>),
    Held(Vec<Frag>),
}

/// One placement a held-span re-feed performed: the slot, the fragment
/// in that slot's volume address space, and whether the bytes reached
/// an in-stream-decrypted (plaintext-once) file rather than landing as
/// a verbatim copy of the posted bytes.
///
/// The crypto fact is captured AT THE WRITE, where the route is known
/// for certain, and not re-derived at record time from the file name:
/// it is what keeps such a placement out of an `R` record - the
/// invariant a `D` record exists to protect - independently of what the
/// chain's crypto map happens to hold when the article completes.
#[derive(Debug, Clone)]
pub struct LatePlacement {
    pub slot: usize,
    pub frag: Frag,
    /// The bytes are PLAINTEXT on disk: restorable only by
    /// re-encryption through the file's journaled `E`/`K`/`T` facts, so
    /// the article completes into a `D` record and never an `R`.
    pub crypto: bool,
}

/// One deferred pwrite: performed after the routing lock drops.
struct WriteJob {
    writer: Arc<FileWriter>,
    file_off: u64,
    src_start: usize,
    len: usize,
    /// In-stream decrypt state when this span belongs to an encrypted
    /// store entry under plaintext-once: the executor routes the bytes
    /// through [`CryptoState::ingest`]/[`CryptoState::patch`] instead of
    /// a raw pwrite, and the article is never journaled (Persist::No -
    /// what lands on disk is plaintext, not the posted bytes a resume
    /// would copy into volume files).
    crypto: Option<Arc<CryptoState>>,
    repair: bool,
}

/// §94 A: where the resume journal says a replayed span's bytes already
/// are, and the running count of bytes the replay left in place. See
/// [`Extractor::write_in_place`].
struct InPlace<'a> {
    /// The journal's `Frag::file` for this span: the out_dir-RELATIVE
    /// output name, `out_name_of`'s form, which is what every producer
    /// of a `Frag` records since the 30 Aug 2026 relpath sweep.
    file: &'a str,
    /// Offset in `file` of the span's FIRST byte; a job's source offset
    /// within the span (`src_start`) is added to it.
    off: u64,
    covered: u64,
}

impl InPlace<'_> {
    /// Does this derived placement land on its own source bytes? The
    /// file is compared the way the journal recorded it - the
    /// out_dir-relative name - and the offset by `src_start` arithmetic
    /// that cannot overflow a span that fit in memory.
    ///
    /// It compared `file_name()` until the 31 Aug 2026 read-only sweep's
    /// finding 11. Once `Frag::file` became tree-relative, a resume of a
    /// tree payload matched NOTHING here, so every overlapping span took
    /// the write path instead of being noted in place: the same bytes,
    /// the same result, and the whole of §94 A's saved I/O thrown away
    /// on exactly the shape (a disc tree) that has the most of it.
    fn matches(&self, out_dir: &Path, j: &WriteJob) -> bool {
        out_name_of(out_dir, &j.writer.path) == self.file
            && self.off.checked_add(j.src_start as u64) == Some(j.file_off)
    }
}

/// One deferred child forward from the hot write path: `len` bytes of the
/// caller's span (at `src_start`) go to the child slot the routing map
/// names at DELIVERY time, at `file_off` of the level-1 file - executed
/// after the routing lock drops, exactly like the deferred pwrites (the
/// child takes its own lock and defers its own pwrites; running that
/// under our lock would serialize disk I/O behind routing again). The
/// destination is re-resolved rather than captured: a group merge in the
/// window can displace (and abandon) the slot routing picked.
struct FwdSpan {
    name: String,
    size: u64,
    file_off: u64,
    src_start: usize,
    len: usize,
    /// Mapped-repair rewrite: the bytes may DIFFER from an earlier
    /// delivery of the same range, so the child must overwrite (not
    /// clip) its piece-CRC composition - see [`CrcRuns::overwrite`].
    repair: bool,
}

/// An OWNED child forward, queued by the under-the-lock re-feed paths
/// (drain_holds / reresolve / settle) that cannot call into the child
/// while the lock is held. Delivered by `flush_pending_fwd` once the lock
/// drops; `parent_slot`/`vol_off` let delivery re-route the bytes into a
/// materialized volume if the slot fell back in the meantime.
struct FwdJob {
    parent_slot: usize,
    vol_off: u64,
    name: String,
    size: u64,
    file_off: u64,
    bytes: Vec<u8>,
    /// See [`FwdSpan::repair`].
    repair: bool,
    /// Queued by a held-span re-feed: no caller composes this job's
    /// child Persist into an article record, so `deliver_fwd` surfaces
    /// a Placed result through `late_placements` instead.
    refeed: bool,
}

/// Translation window for a forward whose child write returned `Held`:
/// the child parked (some of) the bytes and will write them inside its
/// OWN drain, where only child-space placements exist. The window maps
/// a child placement `(child_slot, child vol range)` back to the parent
/// slot's volume address space so `drain_late_placements` can report it
/// against the article that carried the bytes.
struct FwdWindow {
    parent_slot: usize,
    parent_vol_off: u64,
    child_slot: usize,
    child_off: u64,
    len: u64,
}

/// Where an inner file's bytes go: a real output writer, or a slot of the
/// nested child extractor.
enum Dest {
    Writer(Arc<FileWriter>),
    Child(Arc<Extractor>, usize),
}

// ---------------------------------------------------------------------------
// The chasing decompressor (nested one-pass, phase 2): a COMPRESSED RAR5
// inner archive decompresses while its bytes arrive, instead of demoting
// to a materialized file. Each chased volume feeds a frontier buffer the
// routing path appends to; a chase worker thread drives the RAR engine's
// streaming reader over those buffers in volume order, and its extracted
// member bytes route back through the same seam - a child-extractor slot
// per member - so a store archive UNDER the compressed layer still
// streams. Any failure demotes the group to today's materialize path.
// ---------------------------------------------------------------------------

/// Sort and coalesce touching/overlapping `[a, b)` ranges. Every
/// coverage answer in this file ends with this shape; it was written out
/// four times before the trim split made it five.
fn merge_intervals(mut ivs: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ivs.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (a, b) in ivs {
        if let Some(last) = out.last_mut()
            && a <= last.1
        {
            last.1 = last.1.max(b);
            continue;
        }
        out.push((a, b));
    }
    out
}

/// Job-wide extraction limits, shared by every level of one nesting
/// chain (like `HoldsBudget`), so a bomb split across nested archives or
/// many inner files can never hand itself a fresh allowance.
///
/// Both numbers default to "no limit", so an `Extractor` built without
/// them behaves exactly as it did before they existed.
#[derive(Debug)]
pub struct Limits {
    /// PREALLOCATION ceiling for inner-file writers. An inner file's
    /// declared `unpacked_size` is an attacker-controlled RAR header
    /// vint, and on Linux preallocation is a real `fallocate` - so a
    /// few-hundred-KB post could reserve the whole volume until the
    /// finish-time gates demoted it. The defensible bound is the NZB's
    /// own posted byte count: a STORE archive cannot legitimately unpack
    /// to more than what was posted. Applied to the RESERVATION only -
    /// never to `FileWriter.size`, which feeds resume truncation and the
    /// reported extracted size (see `disk::preallocate_capped`).
    prealloc_cap: AtomicU64,
    /// Distinct extracted bytes the whole chain may write - the in-stream
    /// half of the decompression-bomb guard the disk/post-pass sinks have
    /// always had. Separate from `prealloc_cap` on purpose: one bounds a
    /// reservation and is deliberately soft (writes past it still
    /// succeed), the other bounds bytes actually landed and is hard.
    budget: Arc<crate::disk::WriteBudget>,
}

impl Limits {
    fn unlimited() -> Limits {
        Limits {
            prealloc_cap: AtomicU64::new(u64::MAX),
            budget: Arc::new(crate::disk::WriteBudget::unlimited()),
        }
    }

    fn prealloc_cap(&self) -> u64 {
        self.prealloc_cap.load(Ordering::Relaxed)
    }
}

pub struct Extractor {
    out_dir: PathBuf,
    enabled: bool,
    /// Crash-resume: open existing files without truncating.
    resume: bool,
    /// Nesting level: 0 = the top-level extractor over the download's
    /// volume slots, +1 per child. A child created AT the depth cap
    /// (`inner.nested_max_depth`) is disabled (everything materializes
    /// Plain).
    depth: usize,
    /// The extractor one level up (dead for the root, and for children
    /// created before the root's [`Self::set_promote_hook`] anchored the
    /// chain). Carries the tail-prefetch promote walk: a child's file
    /// ranges translate level by level up to the root's hook.
    parent: Weak<Extractor>,
    /// What this set turned out to be, shared with every nested level.
    /// Deliberately outside `inner`: the daemon polls it once a second
    /// while the routing lock is the hot path.
    shape: Arc<ShapeLatch>,
    /// §156.3b stalled-chase pager: coalesced wake flags for the
    /// detached paging thread (`Extractor::wake_pager`). Outside `inner`
    /// on purpose - the arrival path and the blocking readers touch
    /// them without the routing lock.
    pager_armed: AtomicBool,
    pager_active: AtomicBool,
    /// Held-bytes backpressure (TODO 94 item E): true while the root has
    /// slots parked at the pool. Outside `inner` for the same reason as
    /// the pager flags - the chase worker reads it on every progress
    /// mark, from a thread that must never take the routing lock, to
    /// decide whether to wake the pager for a park re-evaluation.
    park_live: AtomicBool,
    /// Bytes a drop-behind trim spilled through the OFF-LOCK route
    /// ([`Self::spill_trimmed`]) and then committed. The lock-placement
    /// oracle for the trim, on the route-counter principle of
    /// `HoldsScratch::locked_reads`: the under-lock route is
    /// `plain_span`, which never bumps this, so a spill that advanced
    /// `base` without advancing this counter ran under the lock.
    trim_spilled_off_lock: AtomicU64,
    /// Signalled when `spills_in_flight` drops to zero.
    spill_settled: Condvar,
    inner: Mutex<Inner>,
}

struct Inner {
    /// Copy of [`Extractor::out_dir`], for the lock-held static helpers
    /// (`drop_slot_file`) that must turn a writer's path back into the
    /// out_dir-relative output name it claimed.
    out_dir: PathBuf,
    slots: Vec<Slot>,
    groups: HashMap<String, Group>,
    /// Inner-file name → canonical group key. Entries are added when a
    /// split piece links a name to an archive; following the chain maps
    /// any name to the group that owns it.
    alias: HashMap<String, String>,
    /// Extracted inner-file writers, keyed by OUTPUT filename (see
    /// `Group::out_names` for the entry-name → output-name step).
    inner_writers: HashMap<String, Arc<FileWriter>>,
    /// M15: held-span budget, SHARED down the child chain (nested holds
    /// charge the same slice; beyond it groups spill to materialized
    /// volumes).
    budget: Arc<HoldsBudget>,
    /// Held-span scratch file, SHARED down the child chain like the
    /// budget it relieves (see [`HoldsScratch`]).
    scratch: Arc<HoldsScratch>,
    /// Holds-paging gate (`NZBFAST_NO_HOLDS_PAGE` / runtime setter).
    /// Off: a budget breach demotes exactly as before paging existed.
    holds_page_on: bool,
    /// Late-head grace gate (`NZBFAST_NO_HEAD_GRACE` / runtime setter).
    /// Off: an unclassified slot spills at `unclassified_spill` even
    /// while its offset-0 probe is outstanding. See `head_grace`.
    head_grace_on: bool,
    /// One line per chain the first time the grace defers a spill.
    grace_announced: bool,
    /// §94 B: verified-block watermark handle. Set only on the ROOT
    /// extractor (nested levels' bytes are outside the PAR2 set, so child
    /// chases stay ungated), and only when the run opted in (attached, and
    /// its WAIT env-gated, in get/vrig.rs). Chase frontier buffers created
    /// while this is Some are gated on it.
    verify_gate: Option<Arc<crate::live::VerifyGate>>,
    /// Does the chase DECODE park on the gate (§94 B proper, opt-in while
    /// it soaks)? The handle is attached unconditionally since 22 Aug 2026
    /// (the dropping trim reads its watermark, see `rar_trim_volume`).
    /// Default true for the tests. Inherited by children, see `gate.rs`.
    verify_gate_waits: bool,
    /// Preallocation ceiling + extracted-byte budget, SHARED down the
    /// child chain (see [`Limits`]).
    limits: Arc<Limits>,
    /// Output-name claims, SHARED down the child chain so name
    /// disambiguation spans nesting levels (a child's plain file must not
    /// collide with a parent-level output). Leaf lock: only ever taken
    /// with no other lock acquired after it.
    names_taken: Arc<Mutex<std::collections::HashSet<String>>>,
    /// §94 A: names claimed by [`Extractor::preclaim_name`] on behalf of
    /// a specific slot, keyed exactly like `names_taken`. Deliberately
    /// NOT shared with the child chain - only the root preclaims (for
    /// restored files the replay reads as sources), and a child level
    /// reusing a parent's slot numbering must keep colliding with those
    /// names, which is the whole point of the preclaim.
    preclaimed: HashMap<String, usize>,
    /// Whether `names_taken` keys are case-folded, i.e. whether the OUTPUT
    /// VOLUME is case-insensitive. Probed once at the root and threaded down
    /// with `names_taken` so every level keys that shared set the same way.
    fold_names: bool,
    /// Lazily-created nested child extractor (level+1 inner files become
    /// its slots).
    child: Option<Arc<Extractor>>,
    /// Child forwards queued by under-the-lock re-feed paths; delivered
    /// by `flush_pending_fwd` after the lock drops.
    pending_fwd: Vec<FwdJob>,
    /// Promotes raised while the routing lock is held (a 7z part joining
    /// its set, a held slot's offset-0 probe). `promote_file` walks UP
    /// the chain taking each level's own lock, so it can never be called
    /// from under one - these are queued here and flushed off-lock. The
    /// bool is the hook's `urgent` flag (see [`PromoteHook`]).
    pending_promote: Vec<(usize, Vec<(u64, u64)>, bool)>,
    /// Held-bytes backpressure (TODO 94 item E): the pool-side park the
    /// root raises near its holds cap, see `extract::park`.
    park: park::ParkState,
    /// Drop-behind trim spills planned under the routing lock, written
    /// by [`Extractor::flush_pending_spills`] once it drops. Up to half
    /// the holds cap each - the pwrite that used to run under the lock.
    pending_spills: Vec<TrimSpill>,
    /// Trim spills planned but not yet settled (queued or being written
    /// by some thread). While non-zero, a holds-cap breach is RELIEF IN
    /// FLIGHT, not a forfeit: see `defer_breach`.
    spills_in_flight: usize,
    /// Set by a chase breach that found `spills_in_flight > 0` and
    /// stood down instead of forfeiting. Read and cleared by the write
    /// that carried it, which then waits off-lock for the spills to
    /// settle - the same arrival throttle the under-lock write imposed
    /// on EVERY thread, paid only by the one that breached and with the
    /// routing lock free.
    defer_breach: bool,
    /// Nested routing gate (env escape hatch / rollout setting). With it
    /// off, level-1 inner files write directly to disk as before the
    /// child path existed.
    nested_on: bool,
    /// RAR chasing-decompressor gate (`NZBFAST_NO_NESTED_CHASE` /
    /// runtime setter). Off: a compressed inner RAR demotes to a
    /// materialized file exactly as before the chase existed. The 7z
    /// and zip chases have their own gates (`sevenz_on`,
    /// `nested_zip_on`) and are untouched by this one.
    chase_on: bool,
    /// 7z-chase gate (`NZBFAST_NO_NESTED_7Z` / runtime setter). Off: an
    /// inner .7z materializes exactly as before the 7z path existed.
    sevenz_on: bool,
    /// Nested-zip gate (`NZBFAST_NO_NESTED_ZIP` / runtime setter), the
    /// zip twin of `sevenz_on`. Off: an inner zip materializes exactly
    /// as it did before the depth guard came off.
    nested_zip_on: bool,
    /// Tar-chase gate (`NZBFAST_NO_TAR` / runtime setter). One gate at
    /// EVERY depth, where zip has a nested/top pair - see
    /// `try_attach_tar` for why. Off: a `.tar` materializes as an
    /// ordinary file, exactly as it did before the arm existed.
    tar_on: bool,
    /// Top-level 7z gate (`NZBFAST_NO_TOP_7Z` / runtime setter). Only
    /// depth 0 reads it, so children carry it unused. Off: a posted
    /// `.7z` materializes for the disk post-pass, the pre-TODO-37
    /// behaviour.
    top_sevenz_on: bool,
    /// Top-level RAR chase gate (`NZBFAST_NO_TOP_RAR_CHASE` / the
    /// `prefer_external_unrar` setting / runtime setter). Only depth 0
    /// reads it, so children carry it unused. Off: a posted compressed
    /// RAR materializes for the unrar ladder, the pre-lift behaviour.
    top_chase_on: bool,
    /// Top-level zip gate (`NZBFAST_NO_TOP_ZIP` / runtime setter). Only
    /// depth 0 reads it, so children carry it unused. Off: a posted
    /// `.zip` materializes for the disk post-pass, the phase-1
    /// behaviour.
    top_zip_on: bool,
    /// Drop-behind trim gate (`NZBFAST_NO_7Z_TRIM` / runtime setter).
    /// Off: a 7z chase retains everything and an archive over the
    /// retention cap demotes, as it did before trimming existed.
    sevenz_trim_on: bool,
    /// Drop-behind trim gate for the RAR chase (`NZBFAST_NO_RAR_TRIM` /
    /// runtime setter). Off: a chased RAR set retains everything and a
    /// set over the retention cap demotes to the unrar ladder, as it did
    /// before the incremental split decode existed.
    rar_trim_on: bool,
    /// Drop-not-spill gate for the RAR trim (`NZBFAST_NO_RAR_DROP` /
    /// runtime setter). On (default): a healthy top-level chase DROPS
    /// its consumed prefix instead of spilling it to the volume file,
    /// and a later demote re-fetches it. Off: every trim spills, as
    /// before 22 Aug 2026.
    rar_drop_on: bool,
    /// Bytes the RAR drop-behind released without a disk copy, a subset
    /// of `chase_trimmed`.
    chase_dropped: u64,
    /// Bytes a RAR chase drop-behind trim has spilled out of RAM in this
    /// extractor. Chain-wide totals come from
    /// [`Extractor::chase_trimmed_bytes`].
    chase_trimmed: u64,
    /// [`ResumeOutput`] records in the making: `chase_teardown` registers
    /// one per kept partial (member name, and the writer taken out of the
    /// child slot), and `finish` measures and truncates them. Depth 0
    /// only. See `extract::resume` for the whole contract.
    resume_pending: Vec<(String, Arc<FileWriter>)>,
    /// True once the caller reported an article with a TERMINAL verdict
    /// (430 everywhere, out of retention, transport dead) - the job can
    /// no longer complete from the wire alone. Sticky, and SHARED down
    /// the child chain like the budget: a chase wedged on such a gap
    /// holds bytes nothing will decode, and this flag is what arms
    /// their proactive spill ([`Extractor::run_stalled_page_pass`]).
    lost_articles: Arc<AtomicBool>,
    /// The caller's DOUBT about an article whose terminal verdict it is
    /// holding back - the same veto as `lost_articles`, one round trip
    /// earlier, and SHARED down the child chain for the same reason.
    /// Raised by the fetch pool, read only by the drop-behind trim's
    /// gate; [`LossDoubt`] carries the whole story and the measurement.
    loss_doubt: Arc<LossDoubt>,
    /// `NZBFAST_NO_LOSS_DOUBT=1` is unset: the drop-behind trim honours
    /// `loss_doubt` above as well as `lost_articles`. Latched at
    /// construction, per extractor - see `loss_doubt_env_off`.
    loss_doubt_on: bool,
    /// Live split-7z sets, keyed by `sevenz_part_name` base, so a
    /// `.7z.002` classifying later can find the container `.7z.001`
    /// opened and join it. Cleared as each set settles. Zip splits
    /// share the map (the base grammars are disjoint: `.7z.NNN` vs
    /// `.zip.NNN`).
    sevenz_sets: HashMap<String, Arc<SevenZCtl>>,
    /// Byte-split zip sets the CALLER declared from the NZB's own file
    /// list: `split_part_name` base -> part count. A zip split needs
    /// this where a 7z split does not, because no zip part carries a
    /// header that sizes the container - the count says when every
    /// part's decoded size is in and the geometry can resolve. A part
    /// whose base is not declared here never chases (it materializes
    /// for the disk pass, the phase-1 behaviour).
    ///
    /// `None` is a set the PARENT level has opened but not yet counted
    /// (§94 D, nested): a byte-split inside a store RAR has no NZB list
    /// to declare it, so the parent opens the set as it routes the
    /// first sibling and closes it with the count once the outer
    /// archive's entry list has run past the run of siblings - see
    /// `zip_split.rs`. A part joins an open set on trust and the late
    /// count resolves it.
    zip_split_decl: HashMap<String, Option<u32>>,
    /// §94 D: split-set verdicts for the CHILD, queued under this
    /// level's lock and delivered off it (`flush_pending_promote`):
    /// the delivery resolves the child's set and raises its tail
    /// promote, which walks the chain's locks upward. `Some(n)` closes
    /// the set with its part count, `None` refuses it.
    pending_child_decl: Vec<(String, Option<u32>)>,
    /// TODO 211 (b): declared `.rar.NNN` byte splits by lowercased base
    /// (`declare_rar_split`), each mapped one-pass as a single volume
    /// through its part-1 head. See `split.rs`.
    rar_splits: HashMap<String, RarSplit>,
    /// One-pass `.rar.NNN` split gate (`NZBFAST_NO_RAR_SPLIT`).
    rar_split_on: bool,
    /// Nested depth cap for this chain: the child created AT this depth is
    /// disabled, so the deepest layer materializes (never a hard failure).
    /// Resolved from the daemon setting / env at construction, and
    /// inherited by every child EXCEPT across a proven store-only layer -
    /// see [`Extractor::ensure_child`] and the two flags below.
    nested_max_depth: usize,
    /// Whether this layer's archive was seen to COMPRESS anything, and
    /// whether it was seen to store anything. Latched off the RAR
    /// mapper's per-entry `Method` at header-parse time (`chase.rs`),
    /// which is the only place in this tree that reports it.
    ///
    /// Only COMPRESSING layers count against the nested depth cap: the
    /// cap is a decompression-bomb backstop, and a STORE ladder cannot be
    /// a bomb - its every level is the same bytes with a header on the
    /// front, so it cannot expand. The benign 10-deep store ladder in the
    /// bench corpus (`x2-depth10-ladder`) was stopping at the default cap
    /// of 5 for a reason that does not apply to it.
    ///
    /// Read as `saw_store && !saw_compressed`, so the raise needs POSITIVE
    /// evidence and everything else counts normally: a ZIP, 7z or tar
    /// layer sets neither flag (nothing outside the RAR mapper reports a
    /// method here), an unparsed layer sets neither, and both count
    /// against the cap exactly as before. That is the conservative
    /// direction - the failure mode of getting this wrong is a bomb guard
    /// that does not guard.
    saw_compressed: bool,
    saw_store: bool,
    /// Final-output CRC gate (`NZBFAST_NO_OUTPUT_CRC` / runtime setter).
    /// On (the default): level 0 composes and checks its store payloads'
    /// header CRCs exactly like the nested levels, so a payload the
    /// poster packed damaged (outer PAR2 accepts it as-posted) demotes
    /// to materialized volumes instead of shipping silently corrupt.
    /// Off: level 0 skips composition and the check, today's behavior.
    verify_output_crc: bool,
    /// Tail-prefetch promote hook, installed on the ROOT only (main.rs
    /// wires it to the seek/promote ladder). Levels below reach it by
    /// walking `parent` and translating ranges as they go.
    promote: Option<PromoteHook>,
    /// Weak self-handle (set by `ensure_child` - only children chase, and
    /// children are always Arc-owned). The chase worker upgrades per
    /// callback so a cancelled extractor can actually drop: its Drop
    /// aborts the buffers and the worker's next upgrade fails.
    self_weak: Weak<Extractor>,
    /// A [`ChaseReadPause`] is in force: every chase buffer registered
    /// while this is set is born paused, so the hold covers volumes that
    /// arrive DURING the pause and not only the ones already registered
    /// when it was taken. Cleared by the guard's `Drop`, which then
    /// re-reads the registry rather than the snapshot it took.
    chase_reads_paused: bool,
    extracted_bytes: u64,
    /// Reusable buffer for `map_span_into` - one heap allocation per
    /// ARTICLE under the routing lock otherwise. Taken (empty) during
    /// `extract_span`, returned cleared; a re-entrant taker just works
    /// on a fresh empty vector.
    map_scratch: Vec<(usize, u64, u64, u64)>,
    /// Fallbacks of slots that never joined a group (blocker before any
    /// entry parsed) - reported alongside group fallbacks.
    slot_fallbacks: Vec<(String, String)>,
    /// Slot bytes come from real files in `out_dir` (re-extraction): a
    /// fallback must never create a slot writer - `FileWriter::create`
    /// truncates, and the slot's name IS the source file being read.
    /// Fallback slots discard instead; the sources are the deliverable.
    protect_sources: bool,
    /// Archive password (M23a plumbing): lets mappers accept RAR5
    /// encrypted headers / encrypted store entries. Entries decrypt at
    /// article-write time, so the inner files hold PLAINTEXT during the
    /// download; verifier read-back and fallback reconstruction go
    /// through [`CryptoState::read_posted`], which re-encrypts it back
    /// into the posted bytes.
    password: Option<std::sync::Arc<str>>,
    /// Materialized-volume journal notification, root only (never
    /// inherited). See [`MaterializedHook`].
    materialized: Option<MaterializedHook>,
    /// In-stream decrypt state per OUTPUT name (same key space as
    /// `inner_writers`). Presence marks the file plaintext-on-disk:
    /// posted-bytes readers go through [`CryptoState::read_posted`],
    /// its articles journal as `D` records (restorable only by
    /// re-encryption), and the finish verdict adjudicates it.
    crypto_files: HashMap<String, Arc<CryptoState>>,
    /// The OTHER route's latch, same key space: outputs with an
    /// encrypted span COMMITTED to the ciphertext route, stamped at
    /// enqueue under the routing lock (C1). Why `written()` alone cannot
    /// carry this: rule 2 of [`Extractor::instream_decrypt_allowed`].
    /// Never removed for the life of the chain, like `crypto_files`.
    ciphertext_files: std::collections::HashSet<String>,
    /// The routes a RESUMED run inherits from its journal, seeded by
    /// [`Extractor::seed_resumed_routes`] before the first span (TODO
    /// 158 item 2). Wire outputs, with the bytes a prior run left in
    /// them: stamped into `ciphertext_files` at seed time, and the
    /// counter half of rule 2 is seeded when the writer opens. Empty
    /// on a fresh run.
    resumed_wire: HashMap<String, u64>,
    /// ...and the plaintext-once outputs the restore admitted `D`
    /// articles for, with the `(salt, iv)` their `E` fact recorded. Such
    /// an output may re-latch plaintext-once only on a head record that
    /// carries the same pair and a password that proves against its
    /// check; anything else REFUSES the write rather than putting
    /// ciphertext under records that say plaintext.
    resumed_plaintext: HashMap<String, ([u8; 16], [u8; 16])>,
    /// Resume-journal events from every [`CryptoState`] in the chain
    /// (children share it like the holds budget); drained by
    /// [`Extractor::drain_crypto_events`].
    crypto_events: CryptoEventSink,
    /// Increment A: candidate-password probe hook, installed by the
    /// caller (the daemon's harvest over the job's own sidecars and
    /// stems). Called OFF the routing lock with the archive's crypt
    /// parameters; a `Some` return is a check-VERIFIED password (the
    /// hook does the KDFs and only surrenders a candidate the stored
    /// check accepts). Root level only - a nested level's sidecars are
    /// inner files the disk pass's password-chain already covers.
    pw_probe: Option<PwProbeHook>,
    /// True while any slot is `pw_await` and a probe attempt is due:
    /// set at blocker onset and re-armed by the cadence check in
    /// [`Extractor::flush_pw_probe`]; cleared by every flush.
    pw_probe_due: bool,
    /// Last probe attempt, for the re-probe cadence (a sidecar that
    /// lands AFTER the archive blocked must still be seen mid-run, not
    /// only at finish).
    pw_probe_last: Option<std::time::Instant>,
    /// True while [`Extractor::drain_holds`] is re-feeding held spans.
    /// The under-lock write sites capture their placements into
    /// `late_placements` only in this state, and the hold-push sites
    /// leave `span_held` alone (a re-held subrange belongs to an
    /// article that was already reported `Held` when it arrived).
    refeed_active: bool,
    /// Writes performed by held-span re-feeds, in volume address
    /// space, drained by [`Extractor::drain_late_placements`]. The
    /// journal writer joins these against the articles it parked on a
    /// `Held` return - a held-then-drained article's PLAIN bytes are
    /// durably on disk the moment the entry lands here (the re-feed
    /// writes run under the routing lock, before the drain call
    /// returns). A crypto entry ([`LatePlacement::crypto`]) makes the
    /// weaker claim its route can: the span was fed to the file's
    /// [`CryptoState`], which may still hold a seam sliver in RAM, so
    /// the journal writer gates it on `crypto_span_on_disk` exactly as
    /// it gates a directly-placed `D` (TODO 27.2).
    late_placements: Vec<LatePlacement>,
    /// Set when the CURRENT top-level write parked bytes of its own
    /// span in `holds` (reset at write entry; re-feed pushes are
    /// excluded via `refeed_active`). Read by the write tail to return
    /// `Persist::Held` instead of `No`.
    span_held: bool,
    /// Child-to-parent translation windows for forwards the child
    /// parked (see [`FwdWindow`]). Grows only while a child is holding
    /// spans; never pruned - bounded by the count of held forwards.
    fwd_windows: Vec<FwdWindow>,
}

/// Increment A: caller-supplied candidate probe. Given the blocked
/// archive's RAR5 crypt parameters, harvest + test candidates and
/// return one the stored check VERIFIES (never an unverified guess -
/// a wrong password past this point writes garbage).
pub type PwProbeHook =
    std::sync::Arc<dyn Fn(&crate::rar::CryptProbe) -> Option<String> + Send + Sync>;

impl Extractor {
    /// `n_slots` = number of slots in the download; `enabled=false` makes
    /// every slot Plain (the pre-M3 behavior, e.g. --no-extract).
    pub fn new(out_dir: &Path, n_slots: usize, enabled: bool) -> Extractor {
        Self::with_resume(out_dir, n_slots, enabled, false)
    }

    /// §94 A: can this slot's arriving bytes be PLACED rather than
    /// held? True once the slot has classified and, if it mapped, every
    /// parsed entry of it has a resolved base offset - which for a
    /// split member means the volumes ahead of it have been parsed too.
    ///
    /// This is the exact condition the crash-resume replay waits on. A
    /// restored volume fed before it holds every byte in RAM until
    /// `reresolve` catches up, and that peak is what the held-bytes cap
    /// is judged against; fed after it, the same bytes go straight to
    /// the output. `Unknown` is false (nothing has classified yet);
    /// a plain slot is true (it places by definition); a discarded or
    /// materialized slot is true as well, since neither holds.
    pub fn slot_can_place(&self, slot: usize) -> bool {
        let inner = self.inner.lock_ok();
        if slot >= inner.slots.len() {
            return false;
        }
        let (slot, _) = Self::split_target(&inner, slot, 0);
        match inner.slots[slot].mode {
            SlotMode::Unknown => false,
            SlotMode::Rar => {
                let Some(m) = inner.slots[slot].mapper.as_ref() else {
                    return false;
                };
                (0..m.entries.len())
                    .filter(|&ei| !m.entries[ei].is_dir)
                    .all(|ei| Self::base_for(&inner, slot, ei).is_some())
            }
            _ => true,
        }
    }

    /// §94 A: has this slot not classified yet? The replay uses it to
    /// tell "waiting on an offset-0 sniff" from "waiting on a base":
    /// a restored seed that CARRIES offset 0 is its own sniff, and
    /// nothing else will ever supply one (that article is complete, so
    /// the pool never refetches it).
    pub fn slot_unclassified(&self, slot: usize) -> bool {
        let inner = self.inner.lock_ok();
        slot < inner.slots.len() && matches!(inner.slots[slot].mode, SlotMode::Unknown)
    }

    /// Test hook: is every parsed piece of each named inner file placed
    /// (a base derived for it)? Distinguishes "resolution reached these
    /// bytes" from "the job happened to succeed".
    #[cfg(test)]
    pub(crate) fn bases_known(&self, names: &[&str]) -> bool {
        let inner = self.inner.lock().unwrap();
        for si in 0..inner.slots.len() {
            let Some(m) = inner.slots[si].mapper.as_ref() else {
                continue;
            };
            for (ei, e) in m.entries.iter().enumerate() {
                if !names.contains(&e.name.as_str()) || e.is_dir {
                    continue;
                }
                if Self::base_for(&inner, si, ei).is_none() {
                    return false;
                }
            }
        }
        true
    }

    /// Test hook: did the offset-0 sniff LOOK at this slot and find no
    /// container shape to map or chase? The output tree cannot answer
    /// that on its own - a slot the sniff DECLINED and one it attached,
    /// chased and then demoted both end as the same byte-exact file on
    /// disk - so a test that only reads the tree cannot tell a name gate
    /// that held from a container engine that happened to fail. This
    /// reports the routing DECISION, which is the thing the eligibility
    /// predicates in `names.rs` actually control.
    #[cfg(test)]
    pub(crate) fn slot_plain_by_sniff(&self, slot: usize) -> bool {
        let inner = self.inner.lock_ok();
        slot < inner.slots.len() && inner.slots[slot].plain_by_sniff
    }

    /// Test hook: keys of groups whose pieces the arithmetic gate ever
    /// placed beyond what chain resolution had confirmed. The multi-file
    /// regressions assert this stays empty - those sets must live and
    /// die on the chain path.
    #[cfg(test)]
    pub(crate) fn arith_engaged_groups(&self) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        inner
            .groups
            .iter()
            .filter(|(_, g)| g.arith_ever)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Test hook: a depth-1 extractor, the shape a chase sink's CHILD
    /// has in production. The resume-ledger unit tests need it because
    /// the prefix hash arms on nested plain writers only
    /// (`ensure_plain_writer`), and a depth-0 extractor's plain writers
    /// are downloaded volumes that never hash - so driving the ledger
    /// seam through one would test a shape `chase_teardown` never makes.
    #[cfg(test)]
    pub(super) fn new_nested_for_tests(out_dir: &Path, n_slots: usize) -> Extractor {
        sweep_holds_scratch(out_dir);
        Self::build(
            out_dir,
            n_slots,
            true,
            false,
            1,
            Weak::new(),
            Arc::new(HoldsBudget::new(default_holds_cap())),
            Arc::new(HoldsScratch::new(out_dir)),
            Arc::new(Limits::unlimited()),
            Arc::new(Mutex::new(Default::default())),
            crate::disk::case_insensitive_dir(out_dir),
            !nested_env_off(),
            !chase_env_off(),
            !sevenz_env_off(),
            !nested_zip_env_off(),
            !tar_env_off(),
            !holds_page_env_off(),
            !head_grace_env_off(),
            nested_depth_cap(),
            !output_crc_env_off(),
            None,
            Arc::new(ShapeLatch::default()),
        )
    }

    pub fn with_resume(out_dir: &Path, n_slots: usize, enabled: bool, resume: bool) -> Extractor {
        // Crash leftovers from a killed run: at most one extractor owns a
        // job dir at a time, so a stale scratch here is provably dead.
        sweep_holds_scratch(out_dir);
        Self::build(
            out_dir,
            n_slots,
            enabled,
            resume,
            0,
            Weak::new(),
            Arc::new(HoldsBudget::new(default_holds_cap())),
            Arc::new(HoldsScratch::new(out_dir)),
            Arc::new(Limits::unlimited()),
            Arc::new(Mutex::new(Default::default())),
            crate::disk::case_insensitive_dir(out_dir),
            !nested_env_off(),
            !chase_env_off(),
            !sevenz_env_off(),
            !nested_zip_env_off(),
            !tar_env_off(),
            !holds_page_env_off(),
            !head_grace_env_off(),
            nested_depth_cap(),
            !output_crc_env_off(),
            None,
            Arc::new(ShapeLatch::default()),
        )
    }

    /// Full constructor - the public ctors and `ensure_child` both land
    /// here. Children share the parent's holds budget and name claims.
    #[expect(clippy::too_many_arguments)]
    fn build(
        out_dir: &Path,
        n_slots: usize,
        enabled: bool,
        resume: bool,
        depth: usize,
        parent: Weak<Extractor>,
        budget: Arc<HoldsBudget>,
        scratch: Arc<HoldsScratch>,
        limits: Arc<Limits>,
        names_taken: Arc<Mutex<std::collections::HashSet<String>>>,
        fold_names: bool,
        nested_on: bool,
        chase_on: bool,
        sevenz_on: bool,
        nested_zip_on: bool,
        tar_on: bool,
        holds_page_on: bool,
        head_grace_on: bool,
        nested_max_depth: usize,
        verify_output_crc: bool,
        password: Option<std::sync::Arc<str>>,
        shape: Arc<ShapeLatch>,
    ) -> Extractor {
        Extractor {
            out_dir: out_dir.to_path_buf(),
            enabled,
            resume,
            depth,
            parent,
            shape,
            pager_armed: AtomicBool::new(false),
            pager_active: AtomicBool::new(false),
            park_live: AtomicBool::new(false),
            trim_spilled_off_lock: AtomicU64::new(0),
            spill_settled: Condvar::new(),
            inner: Mutex::new(Inner {
                out_dir: out_dir.to_path_buf(),
                slots: (0..n_slots).map(|_| Self::new_slot()).collect(),
                groups: HashMap::new(),
                alias: HashMap::new(),
                inner_writers: HashMap::new(),
                budget,
                scratch,
                holds_page_on,
                head_grace_on,
                grace_announced: false,
                limits,
                names_taken,
                preclaimed: HashMap::new(),
                fold_names,
                child: None,
                pending_fwd: Vec::new(),
                pending_promote: Vec::new(),
                park: park::ParkState::new(),
                pending_spills: Vec::new(),
                spills_in_flight: 0,
                defer_breach: false,
                nested_on,
                chase_on,
                sevenz_on,
                nested_zip_on,
                tar_on,
                // Read here rather than threaded through `build`: only
                // depth 0 consults it, and depth 0 is exactly what the
                // public constructors make. Same construction-time
                // latching as every other gate.
                top_sevenz_on: !top_sevenz_env_off(),
                // A user preferring their own unrar latches the RAR
                // chase off too: the set materializes and the disk
                // ladder (where that preference picks the engine) gets
                // it, instead of the native decoder streaming it here.
                top_chase_on: !top_chase_env_off() && !prefer_external_unrar(),
                top_zip_on: !top_zip_env_off(),
                sevenz_trim_on: !sevenz_trim_env_off(),
                rar_trim_on: !rar_trim_env_off(),
                rar_drop_on: !rar_drop_env_off(),
                chase_dropped: 0,
                chase_trimmed: 0,
                resume_pending: Vec::new(),
                lost_articles: Arc::new(AtomicBool::new(false)),
                loss_doubt: Arc::new(LossDoubt::default()),
                loss_doubt_on: !loss_doubt_env_off(),
                sevenz_sets: HashMap::new(),
                zip_split_decl: HashMap::new(),
                rar_splits: HashMap::new(),
                rar_split_on: !rar_split_env_off(),
                pending_child_decl: Vec::new(),
                nested_max_depth: nested_max_depth.max(1),
                saw_compressed: false,
                saw_store: false,
                verify_output_crc,
                promote: None,
                self_weak: Weak::new(),
                chase_reads_paused: false,
                extracted_bytes: 0,
                map_scratch: Vec::new(),
                slot_fallbacks: Vec::new(),
                protect_sources: false,
                password,
                materialized: None,
                verify_gate: None,
                verify_gate_waits: true,
                crypto_files: HashMap::new(),
                ciphertext_files: std::collections::HashSet::new(),
                resumed_wire: HashMap::new(),
                resumed_plaintext: HashMap::new(),
                crypto_events: Arc::new(Mutex::new(Vec::new())),
                pw_probe: None,
                pw_probe_due: false,
                pw_probe_last: None,
                refeed_active: false,
                late_placements: Vec::new(),
                span_held: false,
                fwd_windows: Vec::new(),
            }),
        }
    }

    /// Drain the placements held-span re-feeds performed since the last
    /// call: one [`LatePlacement`] per write that landed while
    /// `drain_holds` replayed parked spans, in THIS level's slot/volume
    /// address space. A nested child's drained holds are folded in,
    /// translated back through the forward windows recorded when the
    /// child parked them ([`FwdWindow`]); a child placement with no
    /// window (structurally unexpected) is dropped, which errs toward a
    /// refetch on resume. The journal writer joins these against
    /// articles parked on a [`Persist::Held`] return; a PLAIN entry's
    /// bytes are already durably written when it appears here, while a
    /// crypto one carries the weaker claim its route can make and is
    /// gated on [`Extractor::crypto_span_on_disk`] at record time.
    pub fn drain_late_placements(&self) -> Vec<LatePlacement> {
        let (mut out, child) = {
            let mut inner = self.inner.lock_ok();
            let placed = std::mem::take(&mut inner.late_placements);
            // TODO 211 (b): a split head's placements are in its joined
            // volume's offsets; the journal wants the part's.
            (
                Self::split_translate_placements(&inner, placed),
                inner.child.clone(),
            )
        };
        if let Some(c) = child {
            // Child lock inside its own call, ours re-taken after -
            // parent and child locks stay unnested, in either order.
            let child_placed = c.drain_late_placements();
            if !child_placed.is_empty() {
                let inner = self.inner.lock_ok();
                for lp in child_placed {
                    let cf = lp.frag;
                    // A child hold is a subrange of exactly one
                    // forwarded write, so one containing window is the
                    // translation (duplicated windows carry identical
                    // mappings - routing is deterministic).
                    if let Some(w) = inner.fwd_windows.iter().find(|w| {
                        w.child_slot == lp.slot
                            && cf.vol_off >= w.child_off
                            && cf.vol_off + cf.len <= w.child_off + w.len
                    }) {
                        out.push(LatePlacement {
                            slot: w.parent_slot,
                            frag: Frag {
                                vol_off: w.parent_vol_off + (cf.vol_off - w.child_off),
                                ..cf
                            },
                            crypto: lp.crypto,
                        });
                    }
                }
            }
        }
        out
    }

    /// What this download's archives turned out to be, as far as the
    /// mappers and the routing have got. `None` until something
    /// archive-shaped is recognized (loose files never report a shape).
    ///
    /// Safe to call from any thread at any time - it reads the latch, not
    /// the routing lock - and it is the same answer during the download
    /// and after finish(), so the live badge and the history entry agree.
    pub fn archive_shape(&self) -> Option<ArchiveShape> {
        let (outer, nested) = self.shape.snapshot();
        ArchiveShape::from_bits(outer, nested)
    }

    /// `(inner file name, CRC32)` for the first inner file whose header
    /// stated one - an exact identity key for the open release
    /// databases, available for free because the mappers read those
    /// headers anyway.
    ///
    /// `None` for a set with no readable archive headers, which includes
    /// every header-encrypted (`-hp`) post. Same lifetime as
    /// [`Self::archive_shape`]: readable during the download and still
    /// true after finish().
    pub fn inner_crc(&self) -> Option<(String, u32)> {
        self.shape.crc.lock_ok().clone()
    }

    fn new_slot() -> Slot {
        Slot {
            mode: SlotMode::Unknown,
            name: String::new(),
            size: 0,
            sort_key: None,
            holds: Vec::new(),
            pre_bytes: 0,
            probe0_min: u64::MAX,
            probe0_promotes: 0,
            plain_by_sniff: false,
            writer: None,
            mapper: None,
            header_spans: Vec::new(),
            group: None,
            chase: None,
            sevenz: None,
            container_fmt: ChaseFormat::SevenZ,
            piece_crcs: HashMap::new(),
            pw_await: None,
            article_lost: false,
            split_wait: false,
            split_alias: None,
            split_head: None,
            dropped: Vec::new(),
            dropped_as: String::new(),
        }
    }

    /// Dynamically add a slot (nested routing: every level-1 inner file
    /// becomes one slot of the child extractor). Returns its index.
    pub fn alloc_slot(&self) -> usize {
        let mut inner = self.inner.lock_ok();
        inner.slots.push(Self::new_slot());
        inner.slots.len() - 1
    }

    /// The nested child extractor, created on first use. Shares the holds
    /// budget, the name claims, the password, and the routing gate; a
    /// child AT the depth cap is created disabled, so every deeper file
    /// simply materializes Plain.
    ///
    /// A layer PROVEN store-only does not spend a level of the cap - see
    /// `Inner::saw_compressed` for why a stored layer cannot be a
    /// decompression bomb. It is spelled as a raise of the CHILD'S cap
    /// rather than as a second counter, so there is still exactly one
    /// number to reason about at any depth, and each store layer hands
    /// its child one more level than it had.
    ///
    /// [`NESTED_MAX_DEPTH_HARD_CEILING`] is what stops that being
    /// unbounded. Store levels are individually harmless and a million of
    /// them is still an attack - each one is a real extractor with real
    /// buffers - so the raise is clamped rather than open-ended. A store
    /// ladder deeper than the ceiling materializes at it, which is the
    /// same graceful outcome the cap has always produced.
    fn ensure_child(&self, inner: &mut Inner) -> Arc<Extractor> {
        if inner.child.is_none() {
            let depth = self.depth + 1;
            // Positive evidence only: `saw_store` without `saw_compressed`
            // means the mapper read this layer's entries and every one of
            // them was stored. No mapper, a ZIP/7z/tar layer, or any
            // compressed entry all leave the cap where it was.
            let store_only = inner.saw_store && !inner.saw_compressed;
            let cap = if store_only {
                nested_cap_after_store_layer(inner.nested_max_depth)
            } else {
                inner.nested_max_depth
            };
            let child = Arc::new(Self::build(
                &self.out_dir,
                0,
                depth < cap,
                self.resume,
                depth,
                inner.self_weak.clone(),
                inner.budget.clone(),
                inner.scratch.clone(),
                inner.limits.clone(),
                inner.names_taken.clone(),
                inner.fold_names,
                inner.nested_on,
                inner.chase_on,
                inner.sevenz_on,
                inner.nested_zip_on,
                inner.tar_on,
                inner.holds_page_on,
                inner.head_grace_on,
                cap,
                inner.verify_output_crc,
                inner.password.clone(),
                // One latch per chain: the child's observations land in
                // the nested word of the same summary the root publishes.
                self.shape.clone(),
            ));
            {
                let mut ci = child.inner.lock_ok();
                // The child knows its own Arc (weakly): the chase worker
                // reaches its extractor through this without pinning it.
                ci.self_weak = Arc::downgrade(&child);
                // One event sink per chain: a nested encrypted output's
                // E/K/T records drain through the root exactly like its
                // placements fold into the root's frags.
                ci.crypto_events = inner.crypto_events.clone();
                // One terminal-verdict flag per chain: a nested chase
                // (the common shape - the chase lives in the child) arms
                // its stalled-frontier spill off the same report the
                // root received.
                ci.lost_articles = inner.lost_articles.clone();
                // And the doubt that stands in front of it, for the same
                // reason: the trim gate a nested chase runs is the same
                // gate, and the pool reports per JOB, not per depth.
                ci.loss_doubt = inner.loss_doubt.clone();
                ci.verify_gate_waits = inner.verify_gate_waits;
            }
            inner.child = Some(child);
        }
        inner.child.clone().unwrap()
    }

    /// Write one decoded span. `name`/`size` from the yEnc header.
    ///
    /// The global lock covers only routing/mapping decisions - the actual
    /// `pwrite`s run after it drops, so concurrent decoders don't
    /// serialize on disk I/O (measured: the locked-write version capped
    /// `get` ~2 Gbps below the network on London).
    ///
    /// Returns [`Persist::Placed`] with the physical fragments when EVERY
    /// byte of the span is durably on disk after this call - at its final
    /// offset in a plain/materialized file, or translated into an
    /// extracted inner file. Held spans, retained header bytes, and
    /// discards return [`Persist::No`] (their articles refetch on resume).
    pub fn write(
        &self,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
    ) -> io::Result<Persist> {
        self.write_impl(slot, name, size, offset, data, false, None, None)
    }

    /// [`Self::write`] carrying what the decode established about this
    /// article: `article_crc` is the pcrc32 that was present, calculated
    /// and MATCHED, over exactly `data`. Passing it lets a STORE span
    /// that is byte-for-byte this article compose from the verified value
    /// instead of hashing the same bytes a second time. `None` is always
    /// safe and simply hashes.
    pub fn write_verified(
        &self,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
        article_crc: Option<u32>,
    ) -> io::Result<Persist> {
        self.write_impl(slot, name, size, offset, data, false, article_crc, None)
    }

    /// [`Self::write`] for a span the §94 A replay READ BACK from this
    /// job's own output: `src` is `(file name, offset)` where the resume
    /// journal says these exact bytes already sit, in the output
    /// directory. The span is routed and mapped precisely as `write`
    /// routes it - headers parse, entries resolve, piece CRCs compose,
    /// holds hold - and only then, per derived placement, the pwrite is
    /// SKIPPED when and only when this run's map puts the piece at the
    /// very `(file, offset)` the journal read it from; the range is
    /// marked covered instead ([`FileWriter::note_covered`]). A
    /// placement anywhere else, a crypto placement (the source is
    /// ciphertext, the destination plaintext), a repair, a forward to a
    /// child, a held span - all write, exactly as before.
    ///
    /// That is what makes the skip verifiable rather than trusted: the
    /// journal is never consulted for WHERE the bytes go, only checked
    /// against where the map derived from headers this run parsed says
    /// they go. A different derivation (a different password, a
    /// renamed member, a changed sanitizer) simply fails the match and
    /// writes, and the PAR2 read-back still hashes the actual bytes on
    /// disk either way. Returns the `Persist` and how many bytes were
    /// marked in place without a write.
    #[expect(clippy::too_many_arguments)]
    pub fn write_in_place(
        &self,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
        src_file: &str,
        src_off: u64,
    ) -> io::Result<(Persist, u64)> {
        let mut in_place = InPlace {
            file: src_file,
            off: src_off,
            covered: 0,
        };
        let p = self.write_impl(
            slot,
            name,
            size,
            offset,
            data,
            false,
            None,
            Some(&mut in_place),
        )?;
        Ok((p, in_place.covered))
    }

    /// [`Self::write`] with the repair marker exposed: parity-as-a-source
    /// reconstruction feeds whole recreated files through this normal
    /// arrival path, so a rebuilt volume one-passes through whatever
    /// route its shape earns (store map, RAR chase, zip chase, plain).
    /// Unlike [`Self::patch_volume_span`] - which requires an
    /// already-mapped slot - this starts from an untouched (or freshly
    /// allocated) slot and lets routing classify it from the
    /// reconstructed offset-0 bytes. The repair marker still matters:
    /// a range whose earlier (wire-damaged) arrival already composed
    /// into the piece CRCs must REPLACE it, not be clipped as a
    /// duplicate (see [`CrcRuns::overwrite`]).
    pub fn write_repair(
        &self,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
    ) -> io::Result<Persist> {
        self.write_impl(slot, name, size, offset, data, true, None, None)
    }

    /// [`Self::write`] with the repair marker: `repair` says this span is
    /// a mapped-repair rewrite (patch_volume_span), whose bytes may
    /// DIFFER from an earlier arrival of the same range. Everything on
    /// disk overwrites naturally; the piece-CRC composition is the one
    /// consumer that must be told, or it keeps the stale pre-repair
    /// value (first-writer-wins) and the finish gate demotes a job whose
    /// output healed cleanly.
    #[expect(clippy::too_many_arguments)]
    fn write_impl(
        &self,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
        repair: bool,
        article_crc: Option<u32>,
        in_place: Option<&mut InPlace<'_>>,
    ) -> io::Result<Persist> {
        if repair {
            // A repair rewrite invalidates every kept chase prefix in
            // this job - see [`Self::drop_resume_ledger`]. Cheap on the
            // ordinary job: the ledger is empty and this reads one field.
            self.drop_resume_ledger();
        }
        // Per-thread scratch for the span's job/forward queues - filled
        // under the routing lock, so their per-article allocation was
        // lock-held. A STACK of pairs, not one pair: a forwarded span
        // re-enters write_impl on the child extractor from this same
        // thread, and each nesting level needs its own buffers.
        thread_local! {
            static SPAN_SCRATCH: std::cell::RefCell<Vec<(Vec<WriteJob>, Vec<FwdSpan>)>> =
                const { std::cell::RefCell::new(Vec::new()) };
        }
        let (mut jobs, mut fwd) = SPAN_SCRATCH
            .with(|s| s.borrow_mut().pop())
            .unwrap_or_default();
        let result = self.write_impl_scratched(
            &mut jobs,
            &mut fwd,
            slot,
            name,
            size,
            offset,
            data,
            repair,
            article_crc,
            in_place,
        );
        jobs.clear();
        fwd.clear();
        SPAN_SCRATCH.with(|s| s.borrow_mut().push((jobs, fwd)));
        result
    }

    #[expect(clippy::too_many_arguments)]
    fn write_impl_scratched(
        &self,
        jobs: &mut Vec<WriteJob>,
        fwd: &mut Vec<FwdSpan>,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
        repair: bool,
        article_crc: Option<u32>,
        in_place: Option<&mut InPlace<'_>>,
    ) -> io::Result<Persist> {
        let mut pending: Vec<FwdJob> = Vec::new();
        let mut routed_rar = false;
        let span_held;
        let wait_spill;
        {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            inner.span_held = false;
            {
                let s = &mut inner.slots[slot];
                let fresh = s.name.is_empty() && !name.is_empty();
                if fresh {
                    s.name = name.to_string();
                }
                if s.size == 0 {
                    s.size = size;
                }
                if fresh {
                    // TODO 211 (b): a declared split learns this part's
                    // exact size here, whichever offset arrived first.
                    self.split_note_size(inner, slot)?;
                }
            }

            match inner.slots[slot].mode {
                SlotMode::Unknown => {
                    if !self.enabled {
                        // No mapping possible - no reason to wait for the
                        // offset-0 sniff (crucial on resume, where segment
                        // 1 may never be refetched).
                        inner.slots[slot].mode = SlotMode::Plain;
                        self.plain_job(inner, slot, offset, data, &mut *jobs)?;
                        self.drain_holds(inner, slot)?;
                    } else if offset != 0 {
                        self.hold_presniff_span(inner, slot, offset, data)?;
                        // This branch returns before the function's
                        // shared off-lock flush, and the next write for
                        // a still-Unknown slot lands right back here -
                        // the probe would sit queued until the sniff it
                        // exists to fetch. Flush it now, off the lock.
                        drop(g);
                        self.flush_pending_promote();
                        // Whole span parked pre-classification: the
                        // caller keeps the article's identity and joins
                        // it with drain_late_placements once the sniff
                        // establishes a mode and the drain writes it.
                        return Ok(Persist::Held(Vec::new()));
                    } else {
                        // The offset-0 sniff and the routing it picks
                        // live in `routing::sniff_and_route`; the two
                        // exits it cannot take under the lock come back
                        // as `Sniffed` and are taken here.
                        let sniffed = self.sniff_and_route(
                            inner,
                            slot,
                            offset,
                            data,
                            &mut *jobs,
                            &mut *fwd,
                            repair,
                            article_crc,
                        )?;
                        match sniffed {
                            Sniffed::Routed { rar } => routed_rar |= rar,
                            Sniffed::Parked => {
                                drop(g);
                                self.flush_pending_promote();
                                return Ok(Persist::Held(Vec::new()));
                            }
                            Sniffed::Discarded => return Ok(Persist::No),
                        }
                        self.drain_holds(inner, slot)?;
                    }
                }
                SlotMode::Plain | SlotMode::RarFallback => {
                    self.plain_job(inner, slot, offset, data, &mut *jobs)?;
                }
                SlotMode::Rar => {
                    routed_rar = true;
                    self.rar_span(
                        inner,
                        slot,
                        offset,
                        data,
                        Some((&mut *jobs, &mut *fwd)),
                        repair,
                        article_crc,
                    )?;
                }
                // TODO 211 (b): an alias feeds its head at the logical
                // offset. `slot`/`offset` stay the PART's for everything
                // below (jobs, forwards, the journal frags), which is
                // what keeps the article's record in its own file's
                // address space.
                SlotMode::SplitPart => {
                    routed_rar = true;
                    self.split_forward_span(
                        inner,
                        slot,
                        offset,
                        data,
                        Some((&mut *jobs, &mut *fwd)),
                        repair,
                        article_crc,
                    )?;
                }
                // Chased slot (RAR or 7z): the span feeds the frontier
                // buffer (RAM, budget-charged) - not on disk, so never
                // journalable.
                SlotMode::RarChase | SlotMode::SevenZ => {
                    self.chase_span(inner, slot, offset, data)?
                }
                SlotMode::Discard => return Ok(Persist::No),
            }
            // Held-bytes backpressure: one load against the water marks
            // per article at the root (see `extract::park`).
            self.park_reeval(inner)?;
            if !fwd.is_empty() || !inner.pending_fwd.is_empty() {
                pending = std::mem::take(&mut inner.pending_fwd);
            }
            span_held = inner.span_held;
            wait_spill = std::mem::take(&mut inner.defer_breach);
        }
        // The routing lock is down: a 7z part that joined its set above
        // can have its tail articles front-loaded now (the promote walk
        // takes locks up the chain and must not be called from under
        // one). Cheap and usually empty.
        self.flush_pending_promote();
        // Drop-behind trim spills the routing above planned (this
        // span's, or one an earlier error left queued): up to half the
        // holds cap of pwrite, off the lock like the jobs below. FIRST
        // among the fallible steps, so an error further down can never
        // strand a queued spill - `spills_in_flight` counts it until
        // it runs, and a stranded count would defer every later breach.
        self.flush_pending_spills()?;
        // Candidate-password probe for parked encrypted slots (Increment
        // A) - KDF work, so off the lock; cadence-gated to a no-op lock
        // peek on the hot path.
        self.flush_pw_probe(false)?;
        let mut in_place = in_place;
        for j in jobs.iter() {
            let part = &data[j.src_start..j.src_start + j.len];
            // §94 A in-place replay: the piece's DERIVED destination is
            // exactly where the journal says these bytes already are.
            // Plain pwrites only - a crypto job's destination holds the
            // plaintext of a ciphertext source, and a repair's bytes
            // may differ from what is on disk - and the match is on the
            // same (file name, offset) the journal's R frags are
            // recorded from, below. Anything else falls through and
            // writes.
            if let Some(ip) = in_place.as_deref_mut()
                && j.crypto.is_none()
                && !j.repair
                && ip.matches(&self.out_dir, j)
            {
                j.writer.note_covered(j.file_off, j.len as u64)?;
                ip.covered += j.len as u64;
                continue;
            }
            match &j.crypto {
                // The AES runs here, outside the routing lock, under the
                // file's own crypto mutex.
                Some(cs) if j.repair => cs.patch(&j.writer, j.file_off, part)?,
                Some(cs) => cs.ingest(&j.writer, j.file_off, part)?,
                // A REPAIR rewrite's bytes differ from the damaged ones
                // it replaces by design, so it keeps the plain door.
                None if j.repair => j.writer.write_at(j.file_off, part)?,
                // The article-delivery door: two articles that claim one
                // range and disagree about it latch a conflict for settle
                // to fail on (`FileWriter::write_article_at`).
                None => j.writer.write_article_at(j.file_off, part)?,
            }
        }
        // This span breached the cap while another thread's spill was
        // still landing: hold the ARTICLE (not the lock) until it has,
        // so arrivals cannot run the budget away during the write.
        if wait_spill {
            self.await_spills_settled();
        }
        // Owned forwards queued by the re-feed paths inside the lock
        // (drain_holds / reresolve) deliver now, then this span's own
        // forwards. Each child call runs lock-free here and returns the
        // child's Persist for the frag composition below.
        if !pending.is_empty() {
            self.deliver_fwd(pending)?;
        }
        let mut fwd_persist: Vec<Persist> = Vec::with_capacity(fwd.len());
        for f in fwd.iter() {
            // The in-place source travels with the forward. With nested
            // routing on, a store member the root maps is WRITTEN by
            // the child extractor, and a source that stopped here would
            // make every such resumed member write itself back: measured
            // 0 of 100,000 bytes left in place on a single-volume store
            // set before this rode along, 100,000 after. The forwarded
            // piece starts `src_start` into this span, so its source
            // offset does too; the child's count folds back in.
            let mut child_ip = in_place.as_deref().map(|ip| InPlace {
                file: ip.file,
                off: ip.off.saturating_add(f.src_start as u64),
                covered: 0,
            });
            fwd_persist.push(self.deliver_routed(
                slot,
                offset + f.src_start as u64,
                &f.name,
                f.size,
                f.file_off,
                &data[f.src_start..f.src_start + f.len],
                f.repair,
                child_ip.as_mut(),
            )?);
            if let (Some(ip), Some(c)) = (in_place.as_deref_mut(), child_ip) {
                ip.covered += c.covered;
            }
        }
        // A child that parked a forwarded piece writes it inside ITS
        // OWN drain later: the article must be parked exactly like a
        // parent-level hold, or the late placement it eventually
        // surfaces has no article to join.
        let child_held = fwd_persist.iter().any(|p| matches!(p, Persist::Held(_)));
        let span_held = span_held || child_held;
        // The pwrites above ran without the lock. If a fallback flipped
        // this slot meanwhile, its read-back could not see these bytes
        // (interval-gated) and may already have unlinked the inner files
        // the jobs targeted - so the materialized volume is missing this
        // span. Re-route it through the slot's current mode: duplicate
        // writes are harmless, a lost span is silent corruption. The
        // journal skips the article (Persist::No) - its fragments may
        // name just-deleted inner files, and a refetch on resume is the
        // safe outcome for a span that raced a fallback. Forwards to the
        // child already re-resolved their destination in deliver_routed;
        // the whole-span rewrite here duplicates their bytes into the
        // materialized volume, which is harmless (identical offsets,
        // identical bytes).
        if routed_rar && (!jobs.is_empty() || !fwd.is_empty()) {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            if matches!(inner.slots[slot].mode, SlotMode::RarFallback) {
                self.plain_span(inner, slot, offset, data)?;
                return Ok(Persist::No);
            }
        }
        Ok(Self::compose_persist(
            &self.out_dir,
            jobs,
            fwd,
            fwd_persist,
            offset,
            data.len() as u64,
            span_held,
        ))
    }

    /// Compose the article's journal verdict from the placements this
    /// span produced: this level's queued writes, plus the fragments the
    /// forwards' children reported back, folded into THIS volume's
    /// address space. Journalable only when the fragments cover the whole
    /// span; a partially held span returns its plain fragments so the
    /// caller's drain can complete it later. `out_dir_for_frags` is here
    /// only to NAME those fragments: a `Frag.file` is out_dir-relative,
    /// so composing one needs the root to measure against. Still pure -
    /// no lock, no I/O; `out_name_of` is a `strip_prefix`. Split out of
    /// `write_impl_scratched` (TODO 106 function ceiling).
    fn compose_persist(
        out_dir_for_frags: &Path,
        jobs: &[WriteJob],
        fwd: &[FwdSpan],
        fwd_persist: Vec<Persist>,
        offset: u64,
        span_len: u64,
        span_held: bool,
    ) -> Persist {
        // Spans that fed an in-stream-decrypted file journal as `D`
        // records (restore-by-re-encryption), never as `R` - a plain
        // copy of the plaintext into a volume file would rebuild
        // silently corrupt volumes on a downgrade resume.
        let crypto_span = jobs.iter().any(|j| j.crypto.is_some());
        // Journalable only if the queued writes cover the whole span - a
        // span partially held (or with header bytes kept in memory) is not
        // fully on disk and must refetch on resume.
        let mut frags: Vec<Frag> = jobs
            .iter()
            .map(|j| Frag {
                // The out_dir-RELATIVE name, never the bare one (30 Aug 2026
                // sweep): the resume journal resolves a fragment's file by
                // joining this onto out_dir, and matches it against the `S`/`M`
                // records, which carry `sanitize_out_name`'s tree form. A bare
                // basename sent restore to `out_dir/x.vob` for a payload living
                // at `out_dir/VIDEO_TS/x.vob` - every article whose bytes were
                // in it refetched, and its crypto facts unfindable.
                file: out_name_of(out_dir_for_frags, &j.writer.path),
                file_off: j.file_off,
                vol_off: offset + j.src_start as u64,
                len: j.len as u64,
            })
            .collect();
        // The partial view a `Held` return carries: plain fragments
        // only. Crypto fragments are deliberately left out, and stay
        // out after TODO 27.2 (24 Aug 2026) taught the DRAIN to report
        // its crypto placements: this is the view of what was already
        // on disk when the article arrived, and the caller's join adds
        // the crypto fact per fragment from the drain, where the route
        // is known. A span whose crypto part landed on the DIRECT path
        // and whose remainder was held therefore still never completes,
        // and refetches on resume - the safe direction.
        let mut plain_frags: Vec<Frag> = if span_held {
            jobs.iter()
                .filter(|j| j.crypto.is_none())
                .map(|j| Frag {
                    // The same out_dir-RELATIVE name the Placed arm
                    // twenty lines up records, and for the identical
                    // reason - this map was left on the bare basename by
                    // the 30 Aug relpath sweep and named by the 31 Aug
                    // read-only sweep as finding 6. `jobs_to_persist`
                    // writing tree form for Placed and a basename for
                    // the Held remainder means a resumed held span of a
                    // tree payload replays into `out_dir/x.vob` while
                    // the writer is at `out_dir/VIDEO_TS/x.vob`.
                    file: out_name_of(out_dir_for_frags, &j.writer.path),
                    file_off: j.file_off,
                    vol_off: offset + j.src_start as u64,
                    len: j.len as u64,
                })
                .collect()
        } else {
            Vec::new()
        };
        let held = |mut pf: Vec<Frag>| {
            pf.sort_by_key(|f| f.vol_off);
            Persist::Held(pf)
        };
        // Fold the child placements in: a child frag names a child-level
        // output file (already final for the journal); its vol_off is in
        // the CHILD slot's address space, translated back through the
        // affine forward window. Any child part not fully placed makes
        // the whole article refetch on resume (a child's OWN held spans
        // are not tracked across levels - only this level's drain
        // reports late placements).
        let mut crypto_span = crypto_span;
        for (f, p) in fwd.iter().zip(fwd_persist) {
            let (cfrags, child_plain) = match p {
                Persist::No | Persist::Held(_) => {
                    return if span_held {
                        held(plain_frags)
                    } else {
                        Persist::No
                    };
                }
                Persist::Placed(cfrags) => (cfrags, true),
                // A nested plaintext-once output: the whole article's
                // record must be a D line, since at least one fragment
                // can only restore by re-encryption.
                Persist::PlacedCrypto(cfrags) => {
                    crypto_span = true;
                    (cfrags, false)
                }
            };
            for cf in cfrags {
                let nf = Frag {
                    file: cf.file,
                    file_off: cf.file_off,
                    vol_off: offset + f.src_start as u64 + (cf.vol_off - f.file_off),
                    len: cf.len,
                };
                if span_held && child_plain {
                    plain_frags.push(nf.clone());
                }
                frags.push(nf);
            }
        }
        frags.sort_by_key(|f| f.vol_off);
        let mut covered_to = offset;
        for f in &frags {
            if f.vol_off > covered_to {
                return if span_held {
                    held(plain_frags)
                } else {
                    Persist::No
                };
            }
            covered_to = covered_to.max(f.vol_off + f.len);
        }
        if !frags.is_empty() && covered_to >= offset + span_len {
            if crypto_span {
                Persist::PlacedCrypto(frags)
            } else {
                Persist::Placed(frags)
            }
        } else if span_held {
            held(plain_frags)
        } else {
            Persist::No
        }
    }

    /// Poison-tolerant lock acquisition for the READ-ONLY accessors
    /// (`read_at` / `covered` / `covered_intervals` /
    /// `writers_snapshot` / `map_output_range`). The daemon's stream
    /// server and verifier call these concurrently with the decode
    /// threads, so a single panic on a thread holding the routing lock
    /// would otherwise turn every later accessor call into a poison
    /// panic - wedging live /stream and stats reads for the rest of the
    /// job. Recovering the guard here is sound because these paths only
    /// OBSERVE a snapshot: whatever partial mutation the panicking
    /// thread left behind is exactly the state Drop-side recovery
    /// already exposes, a subsequent read cannot make it worse, and
    /// poisoning is purely advisory (no memory safety is at stake - the
    /// worst case is a read that reflects a half-applied routing step,
    /// which the interval/coverage checks already treat as "not there
    /// yet"). Write/mutate paths keep the strict unwrap on purpose: a
    /// poisoned lock there signals state too suspect to EXTEND, and
    /// failing loud beats folding more data into it.
    fn inner_read(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock_ok()
    }

    /// Close the OS handle on every output file this extractor holds, at this
    /// level and every nested one, so an EXTERNAL process can open them
    /// exclusively. Pair with [`unpark_outputs`] - always, and on every exit
    /// path - and see [`FileWriter::park`] for what parking does and does not
    /// disturb.
    ///
    /// This exists for the external-par2 repair fallback: par2cmdline opens
    /// its targets with share mode 0, so on Windows any handle we still hold
    /// makes its open fail and it reports the file missing and declines to
    /// repair (measured: `Could not open "payload.bin"` → `Target: missing` →
    /// `Repair is not possible`). Nested levels wrote into the same tree and
    /// pin it too, hence the recursion.
    ///
    /// Needed because [`Self::finish`] syncs the writers but KEEPS them: the
    /// extractor holds output handles for the streaming endpoint's benefit,
    /// and it stays alive well past completion (the daemon leaves it
    /// installed for post-completion streaming, and the fetch task holds its
    /// own `Arc` until it returns). So the handles are still there at repair
    /// time, which runs BEFORE `finish` - and that ordering is why these park
    /// rather than close: `finish` has yet to settle groups, verify inner
    /// CRCs and run the decrypt pass, all of which need live writers.
    ///
    /// Deliberately NOT used for the Windows folder rename that first
    /// motivated closing handles at all: that went in as
    /// `smart::move_dir_contents`, which moves the directory's CONTENTS and
    /// needs no handles closed. Parking is visible to a concurrent /stream
    /// read (it gets `NotConnected` instead of bytes), which is the honest
    /// answer while an external tool rewrites those very bytes, but it is not
    /// something to inflict on a path that has a handle-free alternative.
    ///
    /// [`unpark_outputs`]: Extractor::unpark_outputs
    /// [`FileWriter::park`]: crate::disk::FileWriter::park
    pub fn park_outputs(&self) -> io::Result<()> {
        self.each_output(&|w| w.park())
    }

    /// [`park_outputs`] plus the live-reader custody an EXTERNAL tool
    /// needs (sweep 8, M4): new by-path reader opens are held off, and
    /// on Windows the responses already holding a handle are revoked
    /// and drained, because par2cmdline opens its targets with share
    /// mode 0 and one reading player is enough to make it report a
    /// repairable file as missing. [`unpark_outputs`] hands the files
    /// back, and repair.rs calls it on every path.
    ///
    /// What this does NOT reach, measured 22 Aug 2026 on the shape that
    /// motivated the question (`stream_repair.rs` leg 2): an output the
    /// set has already DEMOTED away. A damaged multi-volume RAR set
    /// materializes its volumes for repair first, and that demote runs
    /// `fallback_group` -> `abandon_slot` over the extracted media file,
    /// which takes the writer out of its slot and unlinks it. So by the
    /// time this walks the tree there is no writer to claim and no file
    /// to claim it over - par2's targets here are the VOLUMES, and the
    /// extracted output is not even in the directory (the probe showed
    /// `r.part1-3.rar` + the par2 set, and nothing else). Custody is not
    /// the mechanism that speaks for those files; [`FileWriter::abandon`]
    /// is, and it is set on that same demote path.
    ///
    /// [`park_outputs`]: Extractor::park_outputs
    /// [`unpark_outputs`]: Extractor::unpark_outputs
    /// [`FileWriter::abandon`]: crate::disk::FileWriter::abandon
    pub fn park_outputs_for_repair(&self) -> io::Result<()> {
        self.each_output(&|w| w.park_for_repair())
    }

    /// Reopen everything [`park_outputs`] closed, at this level and every
    /// nested one. Idempotent, so it is safe to call on an error path that may
    /// or may not have parked.
    ///
    /// [`park_outputs`]: Extractor::park_outputs
    pub fn unpark_outputs(&self) -> io::Result<()> {
        self.each_output(&|w| w.unpark())
    }

    /// Apply `f` to every live output writer at this level and below,
    /// attempting ALL of them and returning the first error. Attempting all
    /// matters on the unpark side: bailing at the first failure would leave
    /// the rest of the tree parked and every later write to them failing.
    fn each_output(&self, f: &dyn Fn(&FileWriter) -> io::Result<()>) -> io::Result<()> {
        let (writers, child) = {
            let g = self.inner.lock_ok();
            let mut ws: Vec<Arc<FileWriter>> = g.inner_writers.values().cloned().collect();
            ws.extend(g.slots.iter().filter_map(|s| s.writer.clone()));
            (ws, g.child.clone())
        };
        // Cloned out from under the lock: park/unpark do file I/O (an fsync on
        // a multi-GB output is not instant), and holding the routing lock
        // across it would block the daemon's stats and stream calls.
        let mut first_err: Option<io::Error> = None;
        for w in &writers {
            if let Err(e) = f(w) {
                first_err.get_or_insert(e);
            }
        }
        if let Some(c) = child
            && let Err(e) = c.each_output(f)
        {
            first_err.get_or_insert(e);
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// End-of-download: settle groups that never finished mapping, flush
    /// stray holds, sync writers, and report. A nested child finishes
    /// BEFORE this level's sync phase - its own settle demotes any
    /// unfinished child slot to a materialized level-1 file (today's
    /// output), and its report folds into ours.
    pub fn finish(&self) -> io::Result<ExtractReport> {
        // Parked password-awaits resolve FIRST (Increment A): a hit here
        // re-keys and re-feeds while every held byte is still in RAM -
        // the set then settles/decrypts below like any start-time
        // password job - and a miss demotes before the group settle
        // reasons about volumes.
        self.resolve_pw_awaits()?;
        // Chase workers join FIRST: their sink writes must have landed
        // before the child settles/finishes, and a chase still blocked
        // here (bytes never arrived) aborts and demotes. The 7z workers
        // follow the same contract.
        self.chase_finish()?;
        self.sevenz_finish()?;
        self.settle_groups()?;
        // Settle re-fed holds under the lock; any child forwards it
        // queued must land before the child settles itself.
        self.flush_pending_fwd()?;
        // Every byte is routed now; check nested store payloads against
        // their header CRCs BEFORE the decrypt pass (a demoting group
        // must still materialize exact volume bytes) and before the
        // child finishes (the demote abandons its routed child slots).
        self.verify_inner_crcs()?;
        // The finish verdict on the encrypted outputs: their plaintext
        // is already on disk, so this only adjudicates it and demotes
        // the groups that fail.
        let mut decrypted = self.verify_encrypted_outputs()?;
        // §94 D: every byte is in, so a nested split set the entry walk
        // could not close (the archive ends on it) closes on what it
        // has, before the child's own finish judges the set.
        self.close_zip_splits_at_finish();
        let child = self.inner.lock_ok().child.clone();
        let child_fold = match &child {
            Some(c) => Some((c.finish()?, c.slot_output_files())),
            None => None,
        };
        let mut g = self.inner.lock_ok();
        let inner = &mut *g;

        // A sync failure (ENOSPC/EIO) means buffered pwrites never reached
        // disk - swallowing it here let a job exit 0 with corrupt output
        // and a journal that recorded those articles persisted. Sync
        // everything, then fail loud if anything failed.
        let mut sync_err: Option<io::Error> = None;
        let mut extracted: Vec<(String, u64)> = Vec::new();
        for (name, w) in &inner.inner_writers {
            extracted.push((name.clone(), w.size));
            if let Err(e) = w.sync() {
                sync_err.get_or_insert(e);
            }
        }
        for s in &inner.slots {
            if let Some(w) = &s.writer
                && let Err(e) = w.sync()
            {
                sync_err.get_or_insert(e);
            }
        }
        if let Some(e) = sync_err {
            return Err(e);
        }
        let mut fallbacks: Vec<(String, String)> = inner
            .groups
            .iter()
            .filter(|(_, g)| g.fallback)
            .map(|(s, g)| (s.clone(), g.fallback_reason.clone().unwrap_or_default()))
            .collect();
        fallbacks.extend(inner.slot_fallbacks.iter().cloned());
        // Phase 0(b): one prevalence line per inner archive this level
        // streamed. Runs on THIS level's own groups/slots (self.depth);
        // each child level already reported its own via c.finish() above.
        self.report_nested_prevalence(inner);
        // Fold the child chain in: its slot files (Plain level-1 files
        // and materialized nested demotions) and its own extracted list
        // are all outputs of THIS extraction; its fallbacks are demotions
        // that already produced today's output, reported distinctly so
        // volume-level remediation never keys off them.
        if let Some((crep, cfiles)) = child_fold {
            extracted.extend(crep.extracted);
            extracted.extend(cfiles);
            for (key, why) in crep.fallbacks {
                fallbacks.push((key, nested_reason(&why)));
            }
            decrypted.extend(crep.decrypted);
            decrypted.sort();
        }
        extracted.sort();
        // The chain's holds scratch has done its job: every hold drained
        // at settle, and what is still paged (a healthy group's header
        // stash) stays readable through the kept handle. Root only - the
        // file is chain-shared.
        if self.depth == 0 {
            inner.scratch.cleanup();
        }
        Ok(ExtractReport {
            extracted,
            fallbacks,
            extracted_bytes: inner.extracted_bytes,
            decrypted,
            // Root only, and nothing folds up from the child: a nested
            // chase's partial is a member of a member, and the pass that
            // would resume it works another directory (see
            // `chase_resume_ok`, which refuses below depth 0).
            resume_outputs: Self::settle_resume_ledger(inner),
        })
    }
}

impl Drop for Extractor {
    /// Cancel path: a dropped extractor must not leave chase workers
    /// blocked on frontiers that will never fill. Abort every live chase
    /// and join - except from the worker's own thread (a worker holding
    /// the last transient Arc would otherwise join itself; after the
    /// abort it exits on its own anyway).
    fn drop(&mut self) {
        let inner = match self.inner.get_mut() {
            Ok(i) => i,
            Err(p) => p.into_inner(),
        };
        // Cancel path for the holds scratch (finish() already unlinked on
        // the normal path; a second unlink is a harmless miss).
        if self.depth == 0 {
            inner.scratch.cleanup();
        }
        let mut handles = Vec::new();
        for g in inner.groups.values_mut() {
            if let Some(ctl) = g.chase.take() {
                ctl.abort("extractor dropped");
                ctl.shared.lock_ok().no_more = true;
                ctl.cv.notify_all();
                if let Some(h) = ctl.worker.lock_ok().take() {
                    handles.push(h);
                }
            }
        }
        for s in inner.slots.iter_mut() {
            // A split set's parts share one ctl, so `take()` on the
            // worker yields a handle for the first member only - which
            // is exactly right, there is one thread per container.
            if let Some(ctl) = s.sevenz.take() {
                ctl.set.abort();
                if let Some(h) = ctl.worker.lock_ok().take() {
                    handles.push(h);
                }
            }
        }
        for h in handles {
            if h.thread().id() != std::thread::current().id() {
                let _ = h.join();
            }
        }
    }
}

// The inline `mod tests` was 3,018 lines - moved out bodily (TODO 106) and
// split at its own nested-one-pass banner, since either half alone would
// otherwise want a size-gate entry.
#[cfg(test)]
mod mod_tests;

// mod_tests.rs regrew past its own ceiling (TODO 106); this is its tail
// (payload provenance, preclaimed names, replay spans) split out whole.
#[cfg(test)]
mod replay_tests;

#[cfg(test)]
mod nested_tests;

#[cfg(test)]
mod sfx_tests;

#[cfg(test)]
mod zip_split_tests;

#[cfg(test)]
mod trim_spill_tests;

#[cfg(test)]
mod polyglot_tests;
