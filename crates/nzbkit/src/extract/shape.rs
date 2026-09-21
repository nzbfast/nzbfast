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

// ---- Stage 0a: the tally has to survive a restart ----
//
// The counters above are process-global and nothing outside this process
// ever read them back, so two months of "soaking on the live daemon"
// banked nothing: a restart zeroed the tally and the only durable copy
// was the `info!` line in a log the Mac app rotates on every spawn,
// keeping exactly one `.1`. Measured 20 Sep 2026 over the whole surviving
// window - two daemon lifetimes, 17 archive jobs - and it held no
// `nested-prevalence:` line at all
// (`research/NESTED-ONE-PASS-PLAN-2026-09-20.md` section 2).
//
// So the tally gets a BASELINE: whatever previous daemon runs banked,
// loaded once at startup by the layer that owns daemon state
// (`nzbfast_core::nestedstat`). This crate holds no path and opens no
// file - it holds the number and the hook.
//
// Two figures, deliberately, because a reader wants both and the
// existing tests assert deltas within ONE process:
//   * [`nested_prevalence`]       - this process only, unchanged.
//   * [`nested_prevalence_total`] - baseline + this process, which is the
//                                   running total the item needs.
//
// The SINK is how the total banks. It is called once per counted level,
// after the bump, so the file on disk is written exactly when there is
// something new in it - nested levels are rare (zero in those 17 jobs),
// so this is not a hot path and does not need a timer, a tick or a
// shutdown hook to be correct against a `kill -9`.
static NESTED_BASE: Mutex<NestedPrevalence> = Mutex::new(NestedPrevalence {
    levels: 0,
    in_stream: 0,
    demoted: 0,
    disk: 0,
    rar_store: 0,
    rar_compressed: 0,
    rar_encrypted: 0,
    sevenz: 0,
    other: 0,
});
static NESTED_SINK: Mutex<Option<fn()>> = Mutex::new(None);

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
/// A missing store/compressed token is what `ArchiveShape::from_bits`
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
    /// `SH_MATERIALIZED` rides along because it is the same fact: these
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

/// What ONE counted level contributes to the tally: the single source the
/// statics and the recorder both read.
///
/// The two relational invariants TODO 13 carries (`levels == in_stream +
/// disk`, `demoted <= disk`) are properties of this mapping and nothing
/// else - a Demoted bumps `demoted` alone, because the archive
/// materializes and the disk post-pass counts it under `disk`. Before
/// 20 Sep 2026 the mapping lived inline in [`note_nested_level`]'s match
/// arms, where the only way to check it was to read the arms: the
/// counters are process-global, so a test that measured them under the
/// parallel runner could assert monotonic lower bounds and nothing more
/// (TODO 13's "NOT runtime-testable" note). Naming the mapping once lets
/// a recorder capture exactly what was applied, so the invariants are
/// asserted over a buffer that no other test can reach.
///
/// Read this with [`note_nested_level`]'s section comment: the counting
/// model is stated there, and this is that model as a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NestedBumps {
    pub levels: u64,
    pub in_stream: u64,
    pub demoted: u64,
    pub disk: u64,
    /// Whether the per-kind counter (`rar_store`, `7z`, ...) was bumped.
    /// A demote does not bump one: the kind is recorded when the
    /// materialized archive is counted under `disk`.
    pub kind_counted: bool,
}

/// The counting model as a value. The ONLY place a disposition becomes
/// numbers - see [`NestedBumps`].
fn bumps_for(disposition: &NestedDisposition) -> NestedBumps {
    let zero = NestedBumps {
        levels: 0,
        in_stream: 0,
        demoted: 0,
        disk: 0,
        kind_counted: false,
    };
    match disposition {
        NestedDisposition::InStream => NestedBumps {
            levels: 1,
            in_stream: 1,
            kind_counted: true,
            ..zero
        },
        NestedDisposition::Disk => NestedBumps {
            levels: 1,
            disk: 1,
            kind_counted: true,
            ..zero
        },
        // Diagnostic only - the archive is tallied under `disk` when the
        // post-pass re-extracts the volumes this demote produced.
        NestedDisposition::Demoted(_) => NestedBumps { demoted: 1, ..zero },
    }
}

/// One emitted nested-prevalence event, as captured by
/// [`record_nested_events`]. Carries the bumps that were APPLIED, not a
/// second derivation of them, so an invariant asserted over a buffer of
/// these is an assertion about [`note_nested_level`] rather than about
/// the test's own arithmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedEvent {
    pub depth: usize,
    pub kind: String,
    /// `in-stream` / `disk` / `demoted`, the same word the log line uses.
    pub disposition: &'static str,
    /// The demote cause, for a `demoted` event only.
    pub reason: Option<String>,
    pub bumps: NestedBumps,
}

type EventBuf = std::sync::Arc<Mutex<Vec<NestedEvent>>>;

thread_local! {
    /// The recorder installed on THIS thread, if any. Thread-local on
    /// purpose: a process-global buffer would be corrupted by every
    /// parallel test in the same process, which is the whole defect the
    /// recorder exists to get out from under.
    static NESTED_RECORDER: std::cell::RefCell<Option<EventBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// A per-test capture of the nested-prevalence events emitted on THIS
/// thread, and the way the two relational invariants are tested at all.
///
/// The counters [`nested_prevalence`] reports are process-global, and
/// `cargo test` puts a whole crate in ONE process, so a neighbour test
/// moves them mid-assertion: only monotonic lower-bound deltas are
/// race-safe there. A recorder is local to the thread that installs it,
/// so `levels == in_stream + disk` and `demoted <= disk` can be asserted
/// EXACTLY over what this test emitted, under both runners.
///
/// **Stated limit:** it captures emissions on the installing thread
/// only. Every `note_nested_level` call site today is reached
/// synchronously from `feed`/`finish` on the caller's thread; if one
/// ever moves to a worker, the tests that assert exact event contents go
/// red with an empty or short buffer rather than passing over nothing.
/// That is the intended failure - do not "fix" it by widening the
/// recorder to a global.
///
/// Installed for the guard's lifetime and removed on drop, so the test
/// beside it is unaffected even on a panic. A nested install replaces
/// the outer one and restores it on drop.
#[doc(hidden)]
#[must_use = "the recorder is uninstalled when the guard drops"]
pub struct NestedRecorder {
    buf: EventBuf,
    prev: Option<EventBuf>,
}

/// Start capturing nested-prevalence events on this thread. See
/// [`NestedRecorder`].
#[doc(hidden)]
pub fn record_nested_events() -> NestedRecorder {
    let buf: EventBuf = std::sync::Arc::new(Mutex::new(Vec::new()));
    let prev = NESTED_RECORDER.with(|r| r.borrow_mut().replace(buf.clone()));
    NestedRecorder { buf, prev }
}

impl NestedRecorder {
    /// Everything emitted on this thread since the guard was taken.
    pub fn events(&self) -> Vec<NestedEvent> {
        self.buf.lock_ok().clone()
    }

    /// The captured events folded back up the way the process-global
    /// counters fold them - the tally this test, and only this test,
    /// produced.
    pub fn tally(&self) -> NestedPrevalence {
        let mut t = NestedPrevalence::default();
        for e in self.buf.lock_ok().iter() {
            t.levels += e.bumps.levels;
            t.in_stream += e.bumps.in_stream;
            t.demoted += e.bumps.demoted;
            t.disk += e.bumps.disk;
            if e.bumps.kind_counted {
                match e.kind.as_str() {
                    "rar-store" => t.rar_store += 1,
                    "rar-compressed" => t.rar_compressed += 1,
                    "rar-encrypted" => t.rar_encrypted += 1,
                    "7z" => t.sevenz += 1,
                    _ => t.other += 1,
                }
            }
        }
        t
    }
}

impl Drop for NestedRecorder {
    fn drop(&mut self) {
        let prev = self.prev.take();
        NESTED_RECORDER.with(|r| *r.borrow_mut() = prev);
    }
}

/// Record one processed nested level: log a line and bump the tally. Cheap
/// and non-spammy - called once per nested archive at a terminal seam, not
/// per span. `kind` is one of `rar-store` / `rar-compressed` /
/// `rar-encrypted` / `7z` / `other`.
pub fn note_nested_level(depth: usize, kind: &str, disposition: NestedDisposition) {
    let bumps = bumps_for(&disposition);
    for (c, n) in [
        (&NESTED_LEVELS, bumps.levels),
        (&NESTED_IN_STREAM, bumps.in_stream),
        (&NESTED_DEMOTED, bumps.demoted),
        (&NESTED_DISK, bumps.disk),
    ] {
        if n > 0 {
            c.fetch_add(n, Ordering::Relaxed);
        }
    }
    if bumps.kind_counted {
        match kind {
            "rar-store" => &NESTED_RAR_STORE,
            "rar-compressed" => &NESTED_RAR_COMPRESSED,
            "rar-encrypted" => &NESTED_RAR_ENCRYPTED,
            "7z" => &NESTED_SEVENZ,
            _ => &NESTED_OTHER,
        }
        .fetch_add(1, Ordering::Relaxed);
    }
    let (word, reason) = match disposition {
        NestedDisposition::InStream => ("in-stream", None),
        NestedDisposition::Disk => ("disk", None),
        NestedDisposition::Demoted(r) => ("demoted", Some(r)),
    };
    match reason {
        Some(r) => info!(
            target: "extract",
            "nested-prevalence: depth={depth} type={kind} stream={word} reason=\"{r}\""
        ),
        None => {
            info!(target: "extract", "nested-prevalence: depth={depth} type={kind} stream={word}")
        }
    }
    NESTED_RECORDER.with(|r| {
        if let Some(buf) = r.borrow().as_ref() {
            buf.lock_ok().push(NestedEvent {
                depth,
                kind: kind.to_string(),
                disposition: word,
                reason: reason.map(str::to_string),
                bumps,
            });
        }
    });
    // Bank the running total. OUTSIDE the bump block on purpose: the
    // mapping in `bumps_for` is what enforces `levels == in_stream + disk`
    // and `demoted <= disk` (a Demoted bumps nothing but the demoted
    // counter, because the archive materializes and is re-counted under
    // `disk`), it was audited adversarially on 24 Jul, and TODO 13 carries
    // a standing RISK note asking for it to be re-read on any change here.
    // One call after it touches none of that and fires for every
    // disposition, including a demote - which is the one this file's own
    // invariant note says is only ever a diagnostic, and is therefore the
    // one most easily lost.
    let sink = *NESTED_SINK.lock_ok();
    if let Some(f) = sink {
        f();
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

/// Seed the tally with what previous daemon runs banked, so
/// [`nested_prevalence_total`] answers "ever" rather than "since this
/// process started".
///
/// Called once at daemon startup by `nzbfast_core::nestedstat`, which
/// owns the file. Replaces rather than accumulates: calling it twice with
/// the same load must not double the history.
pub fn set_nested_prevalence_baseline(base: NestedPrevalence) {
    *NESTED_BASE.lock_ok() = base;
}

/// The baseline alone, as last set. The stats API reports it beside the
/// process figure so a reader can tell the two apart without arithmetic.
pub fn nested_prevalence_baseline() -> NestedPrevalence {
    *NESTED_BASE.lock_ok()
}

/// The running total: what previous runs banked plus what this process
/// has counted. This is the figure TODO 13 stage 0 needs - prevalence is
/// a question about the field, and no single daemon lifetime answers it.
///
/// Saturating, not wrapping: a corrupt or hand-edited baseline near
/// `u64::MAX` must not make a live count read as zero.
pub fn nested_prevalence_total() -> NestedPrevalence {
    let base = nested_prevalence_baseline();
    let now = nested_prevalence();
    NestedPrevalence {
        levels: base.levels.saturating_add(now.levels),
        in_stream: base.in_stream.saturating_add(now.in_stream),
        demoted: base.demoted.saturating_add(now.demoted),
        disk: base.disk.saturating_add(now.disk),
        rar_store: base.rar_store.saturating_add(now.rar_store),
        rar_compressed: base.rar_compressed.saturating_add(now.rar_compressed),
        rar_encrypted: base.rar_encrypted.saturating_add(now.rar_encrypted),
        sevenz: base.sevenz.saturating_add(now.sevenz),
        other: base.other.saturating_add(now.other),
    }
}

/// Install the hook [`note_nested_level`] calls after each counted level,
/// so the running total reaches disk when it changes rather than when a
/// process happens to exit cleanly.
///
/// A plain `fn()` and not a closure: the one caller is a daemon-state
/// module that keeps its own path in a static of its own, this crate has
/// no business holding either, and a bare function pointer is `Copy`, so
/// the call below takes no allocation and holds no lock while running.
/// `None` - every CLI run, every test that does not opt in - is a no-op.
pub fn set_nested_prevalence_sink(f: fn()) {
    *NESTED_SINK.lock_ok() = Some(f);
}

/// Drop the sink. Test-only, and the second half of what makes a test
/// that installs one safe for the test beside it.
#[doc(hidden)]
pub fn clear_nested_prevalence_sink() {
    *NESTED_SINK.lock_ok() = None;
}

/// Reset the tally to zero, BASELINE INCLUDED. Test-only: the counters are
/// process-global, so a test that asserts exact counts must isolate itself
/// first.
#[doc(hidden)]
pub fn reset_nested_prevalence() {
    *NESTED_BASE.lock_ok() = NestedPrevalence::default();
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
