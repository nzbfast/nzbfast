//! What the archive set turned out to BE, and how often nesting is real:
//! the latched shape bits and their token/English rendering
//! ([`ArchiveShape`]), and the process-global nested-archive prevalence
//! tally the daemon stats API surfaces ([`note_nested_level`]).
//!
//! Both are instrumentation over the same facts the mappers already learn
//! while headers parse, published live rather than at finish(). Split out
//! of `extract/mod.rs` under the TODO 106 recipe: a verbatim move, not a
//! redesign.

use super::*;
use tracing::info;

// ---- Phase 0(b): nested-archive prevalence instrumentation ----
//
// Learn real-world nesting prevalence from live daemons and testers.
// Every nested level processed (an archive INSIDE another archive - depth
// > 0) emits one concise, greppable log line and bumps a process-global
// tally the daemon stats API can surface. A single-layer job (depth 0)
// never reaches this path, so the common case pays nothing. Two paths
// feed the ONE counter set: the in-stream child extractor here (store /
// chase / 7z inners that stream in RAM) and the disk post-pass in nzbfast
// (materialized inners the stream demoted, plus never-streamed shapes
// like RAR4 and resumed jobs).
//
// Counting model (kept consistent across both call sites so a demoted
// inner is never double-counted):
//   * an inner that STAYS in-stream          -> `in_stream` (this crate)
//   * an inner handled by the disk post-pass -> `disk`      (nzbfast)
//   * an in-stream attempt that DEMOTES      -> `demoted` only
// A demoted inner materializes and is then re-extracted by the disk
// post-pass, where it is tallied once under `disk`; the `demoted` bump is
// a diagnostic that records WHY a `disk` line exists. Hence the invariant
// `levels == in_stream + disk`, with `demoted <= disk`.

static NESTED_LEVELS: AtomicU64 = AtomicU64::new(0);
static NESTED_IN_STREAM: AtomicU64 = AtomicU64::new(0);
static NESTED_DEMOTED: AtomicU64 = AtomicU64::new(0);
static NESTED_DISK: AtomicU64 = AtomicU64::new(0);
static NESTED_RAR_STORE: AtomicU64 = AtomicU64::new(0);
static NESTED_RAR_COMPRESSED: AtomicU64 = AtomicU64::new(0);
static NESTED_RAR_ENCRYPTED: AtomicU64 = AtomicU64::new(0);
static NESTED_SEVENZ: AtomicU64 = AtomicU64::new(0);
static NESTED_OTHER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Archive shape: what the set turned out to BE, published live.
//
// The mappers already learn every fact here the moment a volume's headers
// parse - RAR version, per-entry method, encryption - and the routing
// decisions know whether the bytes are being extracted as they arrive or
// materialized for a disk unpack. None of it used to leave the extractor
// before finish(). The latch below collects it into a small token list
// the daemon can poll mid-download and the dashboard can translate.
//
// Bits are LATCHED, never cleared: a set that starts on the fast path and
// later demotes reads as "partly on disk", which is what actually
// happened. One latch is shared by a whole extractor chain, with nested
// levels writing a separate word, so an inner 7z inside a RAR5 store set
// shows up as "7z inside" rather than overwriting the outer format.
// ---------------------------------------------------------------------------

pub(super) const SH_RAR4: u32 = 1 << 0;
pub(super) const SH_RAR5: u32 = 1 << 1;
pub(super) const SH_7Z: u32 = 1 << 2;
pub(super) const SH_STORE: u32 = 1 << 3;
pub(super) const SH_COMPRESSED: u32 = 1 << 4;
pub(super) const SH_ENCRYPTED: u32 = 1 << 5;
/// At least one inner file was routed to direct extraction.
pub(super) const SH_ONE_PASS: u32 = 1 << 7;
/// At least one group/slot fell back to volumes on disk.
pub(super) const SH_MATERIALIZED: u32 = 1 << 8;
/// The outer container is a zip (one-pass zip, phase 2).
pub(super) const SH_ZIP: u32 = 1 << 9;

/// Shared observations for one extractor chain (see the section note).
#[derive(Default)]
pub(super) struct ShapeLatch {
    outer: AtomicU32,
    nested: AtomicU32,
    /// The first whole-file CRC32 an inner entry's header stated, with
    /// the entry's name. Latched from the same parse the shape bits come
    /// from, because it is the same fact: what the archive says it
    /// contains.
    ///
    /// It rides here rather than in a field of its own so a nested level
    /// contributes to it without a second Arc through `build` - and
    /// because a naming oracle wants the OUTERMOST content it can get, a
    /// first-writer-wins latch is the right shape as well as the cheap
    /// one.
    pub(super) crc: Mutex<Option<(String, u32)>>,
}

impl ShapeLatch {
    pub(super) fn note(&self, depth: usize, bits: u32) {
        let w = if depth == 0 {
            &self.outer
        } else {
            &self.nested
        };
        w.fetch_or(bits, Ordering::Relaxed);
    }

    /// First writer wins: the volumes of one set repeat their entries in
    /// every header, and re-latching would just churn the lock at line
    /// rate for the same answer.
    pub(super) fn note_crc(&self, name: &str, crc: u32) {
        let mut g = self.crc.lock_ok();
        if g.is_none() {
            *g = Some((name.to_string(), crc));
        }
    }

    pub(super) fn snapshot(&self) -> (u32, u32) {
        (
            self.outer.load(Ordering::Relaxed),
            self.nested.load(Ordering::Relaxed),
        )
    }
}

/// What an archive set turned out to be, as an ordered list of stable
/// tokens: format, then how the content is packed, then how it is being
/// unpacked, then what was found inside.
///
/// The tokens are the wire format - the daemon persists them and the
/// dashboard translates them - so they must stay stable. [`Self::display`]
/// renders the English the CLI prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveShape {
    tokens: Vec<&'static str>,
}

impl ArchiveShape {
    pub(super) fn from_bits(outer: u32, nested: u32) -> Option<ArchiveShape> {
        let mut t: Vec<&'static str> = Vec::new();
        if outer & SH_RAR5 != 0 {
            t.push("rar5");
        } else if outer & SH_RAR4 != 0 {
            t.push("rar4");
        } else if outer & SH_7Z != 0 {
            t.push("7z");
        } else if outer & SH_ZIP != 0 {
            t.push("zip");
        } else {
            // Nothing archive-shaped has been recognized yet (or the job
            // is loose files) - no badge rather than a guess.
            return None;
        }
        match (outer & SH_STORE != 0, outer & SH_COMPRESSED != 0) {
            (true, true) => t.push("mixed"),
            (true, false) => t.push("store"),
            (false, true) => t.push("compressed"),
            (false, false) => {}
        }
        if outer & SH_ENCRYPTED != 0 {
            t.push("encrypted");
        }
        let one_pass = outer & SH_ONE_PASS != 0;
        let on_disk = outer & SH_MATERIALIZED != 0;
        if one_pass && on_disk {
            t.push("mixed-pass");
        } else if on_disk {
            t.push("on-disk");
        } else if one_pass {
            // No encrypted special case since TODO 27 phase 3. Every
            // encrypted set that stays one-pass now unlocks as its bytes
            // arrive (plaintext-once), and the one shape that still
            // assembles ciphertext always demotes at finish, so it is
            // caught by `on_disk` above and never reaches here. The
            // "unlock-at-end" token it used to earn survives in
            // [`shape_word`] alone, for tags older runs persisted.
            t.push("one-pass");
        }
        if nested & SH_7Z != 0 {
            t.push("inner-7z");
        } else if nested & (SH_RAR4 | SH_RAR5) != 0 {
            t.push("inner-rar");
        }
        Some(ArchiveShape { tokens: t })
    }

    pub fn tokens(&self) -> &[&'static str] {
        &self.tokens
    }

    /// The space-separated form carried by the API and the history file.
    pub fn tag(&self) -> String {
        self.tokens.join(" ")
    }

    /// English, for the CLI and as the dashboard's fallback.
    pub fn display(&self) -> String {
        self.tokens
            .iter()
            .map(|t| shape_word(t))
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

/// English for one [`ArchiveShape`] token. Unknown tokens pass through so
/// an older daemon's persisted tag still reads sensibly.
pub fn shape_word(token: &str) -> &str {
    match token {
        "rar5" => "RAR5",
        "rar4" => "RAR4",
        "7z" => "7z",
        "zip" => "zip",
        "store" => "stored",
        "compressed" => "compressed",
        "mixed" => "mixed",
        "encrypted" => "encrypted",
        "one-pass" => "one-pass",
        // No longer emitted (TODO 27 phase 3 retired the route that
        // earned it); kept so a tag an older run persisted still reads.
        "unlock-at-end" => "unlocked at the end",
        "on-disk" => "unpacked after download",
        "mixed-pass" => "partly on disk",
        "inner-7z" => "7z inside",
        "inner-rar" => "RAR inside",
        other => other,
    }
}

/// An archive family that a pass OUTSIDE the extractor unpacked from the
/// output directory, for [`Extractor::note_disk_archive`].
///
/// Only the FAMILY, not how it was packed: the disk arms find their
/// archive by signature and hand the whole thing to a reader, so nothing
/// on that route ever parses a per-entry method the way the mappers do.
/// A missing store/compressed token is what [`ArchiveShape::from_bits`]
/// already renders for an unknown packing, so the badge simply says less
/// rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskArchive {
    Rar4,
    Rar5,
    SevenZ,
    Zip,
}

impl DiskArchive {
    fn bits(self) -> u32 {
        match self {
            DiskArchive::Rar4 => SH_RAR4,
            DiskArchive::Rar5 => SH_RAR5,
            DiskArchive::SevenZ => SH_7Z,
            DiskArchive::Zip => SH_ZIP,
        }
    }
}

impl Extractor {
    /// Latch an archive family that a DISK pass unpacked after the
    /// download finished, so a job the mappers never classified still
    /// reports what its payload turned out to be.
    ///
    /// The one caller is nzbfast's SFX arm. A self-extractor whose stub
    /// runs past the first article is a plain data file to the in-stream
    /// sniff, so nothing archive-shaped is ever recognized for it and
    /// [`Self::archive_shape`] answered `None` for the whole job - the
    /// queue row, the history entry and the download report all said
    /// nothing about a payload that was demonstrably an archive. The two
    /// other SFX routes (the offset-0 sniff, and a mapped volume that
    /// demotes) latch through the mappers and always did.
    ///
    /// [`SH_MATERIALIZED`] rides along because it is the same fact: these
    /// bytes were written to disk and unpacked afterwards, which is
    /// exactly what that bit means and what "unpacked after download"
    /// renders it as. Latched like every other shape bit, so a set that
    /// ALSO streamed something reads as "partly on disk" rather than
    /// overwriting the one-pass half.
    pub fn note_disk_archive(&self, what: DiskArchive) {
        self.shape.note(self.depth, what.bits() | SH_MATERIALIZED);
    }
}

/// How a nested inner archive was handled, for [`note_nested_level`].
pub enum NestedDisposition<'a> {
    /// Extracted entirely in-stream - its volumes never touched disk.
    InStream,
    /// An in-stream attempt fell back to materialized volumes; the reason
    /// is the demote cause (a mixed set, a budget breach, a bad CRC, ...).
    Demoted(&'a str),
    /// Handled by the disk post-pass (a demoted inner, or one never
    /// eligible for streaming - RAR4, multipart 7z, a resumed job).
    Disk,
}

/// A snapshot of the nested-prevalence tally, for the stats API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NestedPrevalence {
    /// Distinct nested inner archives processed (`in_stream + disk`).
    pub levels: u64,
    pub in_stream: u64,
    pub demoted: u64,
    pub disk: u64,
    pub rar_store: u64,
    pub rar_compressed: u64,
    pub rar_encrypted: u64,
    pub sevenz: u64,
    pub other: u64,
}

/// Record one processed nested level: log a line and bump the tally. Cheap
/// and non-spammy - called once per nested archive at a terminal seam, not
/// per span. `kind` is one of `rar-store` / `rar-compressed` /
/// `rar-encrypted` / `7z` / `other`.
pub fn note_nested_level(depth: usize, kind: &str, disposition: NestedDisposition) {
    let bump_kind = || {
        match kind {
            "rar-store" => &NESTED_RAR_STORE,
            "rar-compressed" => &NESTED_RAR_COMPRESSED,
            "rar-encrypted" => &NESTED_RAR_ENCRYPTED,
            "7z" => &NESTED_SEVENZ,
            _ => &NESTED_OTHER,
        }
        .fetch_add(1, Ordering::Relaxed)
    };
    match disposition {
        NestedDisposition::InStream => {
            NESTED_LEVELS.fetch_add(1, Ordering::Relaxed);
            NESTED_IN_STREAM.fetch_add(1, Ordering::Relaxed);
            bump_kind();
            info!(target: "extract", "nested-prevalence: depth={depth} type={kind} stream=in-stream");
        }
        NestedDisposition::Disk => {
            NESTED_LEVELS.fetch_add(1, Ordering::Relaxed);
            NESTED_DISK.fetch_add(1, Ordering::Relaxed);
            bump_kind();
            info!(target: "extract", "nested-prevalence: depth={depth} type={kind} stream=disk");
        }
        NestedDisposition::Demoted(reason) => {
            // Diagnostic only - the archive is tallied under `disk` when
            // the post-pass re-extracts the volumes this demote produced.
            NESTED_DEMOTED.fetch_add(1, Ordering::Relaxed);
            info!(
                target: "extract",
                "nested-prevalence: depth={depth} type={kind} stream=demoted reason=\"{reason}\""
            );
        }
    }
}

/// Current nested-prevalence tally (process lifetime). Surfaced by the
/// daemon stats API and asserted by the prevalence tests.
pub fn nested_prevalence() -> NestedPrevalence {
    NestedPrevalence {
        levels: NESTED_LEVELS.load(Ordering::Relaxed),
        in_stream: NESTED_IN_STREAM.load(Ordering::Relaxed),
        demoted: NESTED_DEMOTED.load(Ordering::Relaxed),
        disk: NESTED_DISK.load(Ordering::Relaxed),
        rar_store: NESTED_RAR_STORE.load(Ordering::Relaxed),
        rar_compressed: NESTED_RAR_COMPRESSED.load(Ordering::Relaxed),
        rar_encrypted: NESTED_RAR_ENCRYPTED.load(Ordering::Relaxed),
        sevenz: NESTED_SEVENZ.load(Ordering::Relaxed),
        other: NESTED_OTHER.load(Ordering::Relaxed),
    }
}

/// Reset the tally to zero. Test-only: the counters are process-global, so
/// a test that asserts exact counts must isolate itself first.
#[doc(hidden)]
pub fn reset_nested_prevalence() {
    for c in [
        &NESTED_LEVELS,
        &NESTED_IN_STREAM,
        &NESTED_DEMOTED,
        &NESTED_DISK,
        &NESTED_RAR_STORE,
        &NESTED_RAR_COMPRESSED,
        &NESTED_RAR_ENCRYPTED,
        &NESTED_SEVENZ,
        &NESTED_OTHER,
    ] {
        c.store(0, Ordering::Relaxed);
    }
}
