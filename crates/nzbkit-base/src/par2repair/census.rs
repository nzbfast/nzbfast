//! The retention ADMISSION census: which outer call site asked the
//! retaining repair entry for a corpus, whether one was admitted,
//! whether anything ever read it, and what the attempt then did.
//!
//! # Why this exists rather than a log grep
//!
//! Retention is admitted BEFORE the verify pass learns whether the set
//! is damaged, so on a clean set the whole corpus is allocated,
//! memcpy'd into and dropped untouched - measured at +8.1..+13.7% on an
//! M1 Ultra and +50..+272% on the two x86 boxes, one of those four
//! columns inside its own A/A floor and so inconclusive
//! (`research/PAR2-VERIFY-RETENTION-2026-09-08.md`). What prices that
//! tax is the DAMAGED FRACTION OF CALLS AT THIS ENTRY, and
//! `research/PAR2-RETENTION-CALLER-CENSUS-2026-09-08.md` shows in six
//! numbered failures why nothing already emitted can supply it:
//!
//! 1. A clean late set's `NoDamage` return logs nothing at all.
//! 2. The one retention line that exists counts CONSUMPTION, not
//!    admission - it sits inside `blocks_rebuilt > 0 &&
//!    shortfall.is_none()` and needs `NZBFAST_REPAIR_TIMING`.
//! 3. `NoDamage` doubles as the observer-stop sentinel, so it is not a
//!    clean classification.
//! 4. An NTT verify-failure retry pays for two corpora under one final
//!    verdict.
//! 5. Set size does not prove admission - the budget, the dimensions
//!    and the explicit override all decide too.
//! 6. Logs are truncated and rotated and carry no join key.
//!
//! So this module records the decision ITSELF, at the site that takes
//! it, with a stable invocation id and a separate attempt number, and
//! with the caller label passed down explicitly from the outer call
//! site ([`RetentionCaller`]). It is NOT a thread-local: the label has
//! to survive the survey and the worker threads, and a library caller
//! that does not set one lands in an explicit `unknown` bucket rather
//! than silently inheriting whatever ran last on this thread.
//!
//! # It is OFF by default and costs nothing when off
//!
//! `NZBFAST_RETENTION_CENSUS` arms it: `log` writes to the
//! `retention-census` log target, any other non-empty non-`0` value is
//! a file path that receives one JSON object per line.
//! `NZBFAST_RETENTION_CENSUS_TRAFFIC` labels the run `production`,
//! `synthetic` or `benchmark` (default `unknown`), because a benchmark
//! corpus chooses its clean/damaged arm and must never be pooled with
//! observed traffic. Disarmed, an invocation costs a completed `Once`
//! check, one relaxed atomic load and a monotonic clock read; each
//! attempt costs one more clock read and a handful of `Cell` inits; and
//! every event site returns on the same flag before it formats
//! anything. Measured against origin/main in the round below.
//!
//! # Durations in here are not yet evidence
//!
//! Read `research/PAR2-RETENTION-ADMISSION-CENSUS-2026-09-08.md` before using
//! `verify_ms` or `elapsed_ms` to choose a policy: the census must be
//! A/A'd against itself first, on the host being measured, exactly as
//! `bench/component/par2-round.sh`'s protocol header requires - a bench
//! flag that measured its own sampler is already in this repo's
//! history (memory topic `nzbfast-par-bench-noise-flag-measures-itself`).

use super::retain::{Admission, RetainedCorpus};
use super::status::RepairStatus;
use super::{RepairError, Target};
use serde_json::{Map, Value, json};
use std::cell::Cell;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, Once, OnceLock};
use std::time::Instant;
use tracing::{info, warn};

/// The record layout version. Bump it when a field changes MEANING; a
/// reader that cannot recognise it must refuse the file rather than
/// average two schemas together.
const SCHEMA: u32 = 1;

// ---------------------------------------------------------------------------
// The caller label
// ---------------------------------------------------------------------------

/// Which outer call site opened this directory repair.
///
/// The retaining entry is reached by six speculative callers and by
/// `parfast r`; ordinary download settlement does NOT reach it
/// (`get::settle` calls `run_set_repair` only once damage is known, and
/// the no-active-set route uses a verifier with no retention sink). A
/// census that cannot tell them apart cannot price a caller-specific
/// default, which is the whole point of collecting it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CallerSite {
    /// A library caller that did not label itself. An explicit bucket,
    /// never folded into a named one.
    #[default]
    Unknown,
    /// `nzbfast-unpack`'s offline `extract_local`.
    OfflineExtraction,
    /// The nested layer's pre-extraction pass. Carries its depth.
    NestedExtraction,
    /// The download's native disk-repair fallback.
    DownloadDiskRepair,
    /// The pre-purchase adoption probe, which enters the same native
    /// pass before more recovery is fetched.
    AdoptionProbe,
    /// `get::latesets`, applying a set that never activated in-stream.
    LateSet,
    /// `parfast r`, the main surveyed route.
    ParfastRepair,
    /// `parfast r`, the unmatched-survey resurvey fallback.
    ParfastResurvey,
    /// A test fixture. Never production traffic.
    Test,
}

impl CallerSite {
    fn as_str(self) -> &'static str {
        match self {
            CallerSite::Unknown => "unknown",
            CallerSite::OfflineExtraction => "offline_extraction",
            CallerSite::NestedExtraction => "nested_extraction",
            CallerSite::DownloadDiskRepair => "download_disk_repair",
            CallerSite::AdoptionProbe => "adoption_probe",
            CallerSite::LateSet => "late_set",
            CallerSite::ParfastRepair => "parfast_repair",
            CallerSite::ParfastResurvey => "parfast_resurvey",
            CallerSite::Test => "test",
        }
    }
}

/// A native pass runs twice over one set on the adoption route - once
/// as a probe, once for real - and those are two paid attempts, not one
/// job seen twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CallerStage {
    /// The site does not make the distinction.
    #[default]
    Unspecified,
    /// A speculative pass whose verdict may be discarded.
    Probe,
    /// The pass whose verdict the caller acts on.
    Final,
}

impl CallerStage {
    fn as_str(self) -> &'static str {
        match self {
            CallerStage::Unspecified => "unspecified",
            CallerStage::Probe => "probe",
            CallerStage::Final => "final",
        }
    }
}

/// The full caller label: the site, its nesting depth where it has one,
/// and its probe/final stage where it has one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RetentionCaller {
    /// The outer call site.
    pub site: CallerSite,
    /// Extraction nesting depth. 0 for every site that has no nesting.
    pub depth: u32,
    /// The probe/final distinction, where the site makes one.
    pub stage: CallerStage,
}

impl RetentionCaller {
    /// A label naming only the site.
    pub const fn new(site: CallerSite) -> RetentionCaller {
        RetentionCaller {
            site,
            depth: 0,
            stage: CallerStage::Unspecified,
        }
    }

    /// The same label at extraction depth `depth`.
    pub const fn at_depth(self, depth: u32) -> RetentionCaller {
        RetentionCaller { depth, ..self }
    }

    /// The same label at a probe/final stage.
    pub const fn at_stage(self, stage: CallerStage) -> RetentionCaller {
        RetentionCaller { stage, ..self }
    }

    fn to_json(self) -> Value {
        json!({
            "site": self.site.as_str(),
            "depth": self.depth,
            "stage": self.stage.as_str(),
        })
    }
}

// ---------------------------------------------------------------------------
// The sink
// ---------------------------------------------------------------------------

enum Out {
    File(std::fs::File),
    Log,
    /// The test recorder. Carries the thread that installed it and
    /// keeps only that thread's records: the sink is process-global,
    /// and under `cargo test --lib` - one process, many threads - a
    /// neighbouring repair test lands its own admission in whichever
    /// recorder happens to be armed. Every census event is emitted on
    /// the invocation's OWN thread (the driver: admission, survey,
    /// disposition and both finishes), so this is an exact filter and
    /// not a heuristic. A filtered line is not a DROP - nobody asked
    /// for it - so it does not touch `dropped`.
    #[cfg(any(test, feature = "test-support"))]
    Mem(std::thread::ThreadId, Vec<String>),
}

struct Sink {
    out: Out,
    /// Opaque per-process run id - the join key for every record, and
    /// the only thing that says two files came from one process.
    run: String,
    started: Instant,
    /// Events this run could not write. Carried on EVERY subsequent
    /// record as `dropped_before`, so a reader never has to assume a
    /// missing line means a missing event.
    dropped: u64,
}

impl Sink {
    /// `false` when the line could not be written; the caller counts it.
    fn write_line(&mut self, line: &str) -> bool {
        match &mut self.out {
            Out::File(f) => writeln!(f, "{line}").is_ok(),
            Out::Log => {
                info!(target: "retention-census", "{line}");
                true
            }
            #[cfg(any(test, feature = "test-support"))]
            Out::Mem(owner, v) => {
                if std::thread::current().id() == *owner {
                    v.push(line.to_string());
                }
                true
            }
        }
    }
}

static ARMED: AtomicBool = AtomicBool::new(false);
static SINK: OnceLock<Mutex<Option<Sink>>> = OnceLock::new();
static ENV_ARM: Once = Once::new();
static NEXT_INV: AtomicU64 = AtomicU64::new(1);

fn sink_cell() -> &'static Mutex<Option<Sink>> {
    SINK.get_or_init(|| Mutex::new(None))
}

/// Whether anything is listening. The whole cost of the census in a
/// build that never arms it.
fn armed() -> bool {
    ENV_ARM.call_once(arm_from_env);
    ARMED.load(Ordering::Relaxed)
}

fn arm_from_env() {
    let v = match std::env::var("NZBFAST_RETENTION_CENSUS") {
        Ok(v) if !v.is_empty() && v != "0" => v,
        _ => return,
    };
    let out = if v == "log" {
        Out::Log
    } else {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&v)
        {
            Ok(f) => Out::File(f),
            Err(e) => {
                // Loud, once: a census that silently wrote nowhere would
                // hand back an empty file and a denominator of zero,
                // which is the exact failure this module exists to stop.
                warn!(target: "retention-census", "cannot open {v}: {e} - census disarmed");
                return;
            }
        }
    };
    install(out, traffic_from_env());
}

fn traffic_from_env() -> String {
    std::env::var("NZBFAST_RETENTION_CENSUS_TRAFFIC").unwrap_or_else(|_| "unknown".into())
}

/// Point the census at `out` and write the run-open boundary.
fn install(out: Out, traffic: String) {
    let run = format!(
        "{:x}{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let mut sink = Sink {
        out,
        run,
        started: Instant::now(),
        dropped: 0,
    };
    let open = json!({
        "schema": SCHEMA,
        "kind": "run_open",
        "run": sink.run,
        "pid": std::process::id(),
        "build": env!("CARGO_PKG_VERSION"),
        "host": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "cpus": crate::mem::cpu_workers(),
        },
        "traffic": traffic,
        "unix_ms": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        "mono_ms": 0,
        "dropped_before": 0,
    })
    .to_string();
    if !sink.write_line(&open) {
        sink.dropped += 1;
    }
    *sink_cell().lock().unwrap_or_else(|e| e.into_inner()) = Some(sink);
    ARMED.store(true, Ordering::Relaxed);
}

/// Close the observation window: writes the `run_close` boundary with
/// the run's total dropped-event count and stops the census.
///
/// A file with no `run_close` is an UNBOUNDED window - a reader must
/// treat its tail as unknown rather than complete. Nothing in the
/// engine calls this on its own; a tool that owns its process (or a
/// test) closes the window it opened.
pub fn close_retention_census() {
    if !armed() {
        return;
    }
    let mut g = sink_cell().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = g.as_mut() {
        let line = json!({
            "schema": SCHEMA,
            "kind": "run_close",
            "run": s.run,
            "mono_ms": s.started.elapsed().as_millis() as u64,
            "dropped_before": s.dropped,
        })
        .to_string();
        let _ = s.write_line(&line);
    }
    ARMED.store(false, Ordering::Relaxed);
    *g = None;
}

/// Stamp the shared fields on `obj` and write it.
fn emit(kind: &'static str, mut obj: Map<String, Value>) {
    let mut g = sink_cell().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = g.as_mut() else { return };
    obj.insert("schema".into(), json!(SCHEMA));
    obj.insert("kind".into(), json!(kind));
    obj.insert("run".into(), json!(s.run));
    obj.insert(
        "mono_ms".into(),
        json!(s.started.elapsed().as_millis() as u64),
    );
    obj.insert("dropped_before".into(), json!(s.dropped));
    let line = Value::Object(obj).to_string();
    if !s.write_line(&line) {
        s.dropped += 1;
    }
}

fn fields(pairs: Value) -> Map<String, Value> {
    match pairs {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

// ---------------------------------------------------------------------------
// Invocation and attempt
// ---------------------------------------------------------------------------

/// One call into the repair entry, whatever it costs internally. An
/// NTT verify-failure retry is a second ATTEMPT of the same invocation,
/// never a second invocation.
pub(super) struct Invocation {
    id: u64,
    caller: RetentionCaller,
    t0: Instant,
    attempts: Cell<u32>,
    finished: Cell<bool>,
    on: bool,
}

impl Invocation {
    /// Open an invocation. Disarmed, this is a completed `Once`
    /// check, one relaxed load and a clock read.
    pub(super) fn start(caller: RetentionCaller) -> Invocation {
        let on = armed();
        let id = if on {
            NEXT_INV.fetch_add(1, Ordering::Relaxed)
        } else {
            0
        };
        let inv = Invocation {
            id,
            caller,
            t0: Instant::now(),
            attempts: Cell::new(0),
            finished: Cell::new(false),
            on,
        };
        if on {
            emit(
                "invocation_start",
                fields(json!({ "inv": id, "caller": caller.to_json() })),
            );
        }
        inv
    }

    /// The next paid attempt of this invocation.
    pub(super) fn attempt(&self) -> Attempt {
        let no = self.attempts.get() + 1;
        self.attempts.set(no);
        Attempt {
            inv: self.id,
            no,
            on: self.on,
            t0: Instant::now(),
            verify_t0: Cell::new(None),
            verify_ms: Cell::new(0),
            admitted: Cell::new(false),
            corpus_bytes: Cell::new(0),
            budget: Cell::new(0),
            explicit: Cell::new(false),
            refusal: Cell::new(None),
            retained_blocks: Cell::new(0),
            retained_bytes: Cell::new(0),
            consumed: Cell::new(false),
            consumed_blocks: Cell::new(0),
            consumed_bytes: Cell::new(0),
            observer: Cell::new(Observer::None),
            arbitrated: Cell::new(0),
            finished: Cell::new(false),
        }
    }

    /// The invocation's own verdict, after every attempt and after the
    /// retained buffers have been dropped.
    pub(super) fn finish(&self, out: &Result<RepairStatus, RepairError>) {
        if self.finished.replace(true) || !self.on {
            return;
        }
        let (outcome, rebuilt, adopted) = classify(out);
        emit(
            "invocation_finish",
            fields(json!({
                "inv": self.id,
                "caller": self.caller.to_json(),
                "attempts": self.attempts.get(),
                "outcome": outcome,
                "blocks_rebuilt": rebuilt,
                "blocks_adopted": adopted,
                "elapsed_ms": self.t0.elapsed().as_millis() as u64,
            })),
        );
    }
}

impl Drop for Invocation {
    /// An invocation that unwound past [`Invocation::finish`] is
    /// recorded as explicitly unfinished, for the same reason an
    /// attempt is: a start with no finish must be visible AS a start
    /// with no finish, never as silence a reader can round to clean.
    fn drop(&mut self) {
        if !self.on || self.finished.get() {
            return;
        }
        emit(
            "invocation_finish",
            fields(json!({
                "inv": self.id,
                "caller": self.caller.to_json(),
                "attempts": self.attempts.get(),
                "outcome": "unfinished",
                "panicking": std::thread::panicking(),
                "elapsed_ms": self.t0.elapsed().as_millis() as u64,
            })),
        );
    }
}

/// What the surveying caller said, kept apart from the verdict: an
/// observer STOP returns `NoDamage` and is not a clean set.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Observer {
    None,
    Continue,
    Stop,
}

impl Observer {
    fn as_str(self) -> &'static str {
        match self {
            Observer::None => "none",
            Observer::Continue => "continue",
            Observer::Stop => "stop",
        }
    }
}

/// One paid verify+repair pass. Lives on the driver thread only.
pub(super) struct Attempt {
    inv: u64,
    no: u32,
    on: bool,
    t0: Instant,
    verify_t0: Cell<Option<Instant>>,
    verify_ms: Cell<u64>,
    admitted: Cell<bool>,
    corpus_bytes: Cell<u64>,
    budget: Cell<u64>,
    explicit: Cell<bool>,
    refusal: Cell<Option<&'static str>>,
    retained_blocks: Cell<u64>,
    retained_bytes: Cell<u64>,
    consumed: Cell<bool>,
    consumed_blocks: Cell<u64>,
    consumed_bytes: Cell<u64>,
    observer: Cell<Observer>,
    arbitrated: Cell<u32>,
    finished: Cell<bool>,
}

impl Attempt {
    /// Take the retention admission decision and RECORD IT, before the
    /// paid verify pass runs - so an attempt that is interrupted, or
    /// that returns clean without ever logging anything, is still
    /// visible as a corpus somebody paid for.
    pub(super) fn admit(&self, n_inputs: usize, block_size: usize) -> Option<RetainedCorpus> {
        let a: Admission = super::retain::admit(n_inputs, block_size);
        self.verify_t0.set(Some(Instant::now()));
        if !self.on {
            return a.corpus;
        }
        self.admitted.set(a.corpus.is_some());
        self.corpus_bytes.set(a.corpus_bytes);
        self.budget.set(a.budget as u64);
        self.explicit.set(a.explicit_override);
        self.refusal.set(a.refusal);
        emit(
            "admission",
            fields(json!({
                "inv": self.inv,
                "attempt": self.no,
                "input_blocks": n_inputs,
                "block_bytes": block_size,
                "corpus_bytes": a.corpus_bytes,
                "budget_bytes": a.budget,
                "explicit_override": a.explicit_override,
                "admitted": a.corpus.is_some(),
                "refusal": a.refusal,
            })),
        );
        a.corpus
    }

    /// A PROVISIONAL verify pass was thrown away: the surveying entry
    /// point verified under the packet scan before the directory's
    /// contested names were known, found some, and is about to rerun
    /// with them settled (`DirContext::settle_names_after_scan`). The
    /// rerun admits again, so without this record the attempt would
    /// carry two `admission` lines and no word on why - and the corpus
    /// the first one bought was read by nobody.
    pub(super) fn provisional_discarded(&self, contested_names: usize) {
        if !self.on {
            return;
        }
        emit(
            "provisional_discarded",
            fields(json!({
                "inv": self.inv,
                "attempt": self.no,
                "contested_names": contested_names,
                "verify_ms": self
                    .verify_t0
                    .get()
                    .map_or(0, |t| t.elapsed().as_millis() as u64),
            })),
        );
    }

    /// The verify pass is done. Taken HERE and not in
    /// [`Attempt::survey`] below, because the survey record is written
    /// after the observer has answered and a surveying caller may do
    /// real work in that answer (`parfast` copies each damaged original
    /// aside) - which is the observer's time, not the pass's.
    pub(super) fn verify_done(&self) {
        if self.on {
            self.verify_ms.set(
                self.verify_t0
                    .get()
                    .map_or(0, |t| t.elapsed().as_millis() as u64),
            );
        }
    }

    /// The verify pass is done and nothing has been written. `stopped`
    /// is the surveying caller's answer, recorded SEPARATELY from the
    /// verdict because the engine spells a stop `NoDamage`.
    pub(super) fn survey(
        &self,
        targets: &[Target],
        retained: Option<&RetainedCorpus>,
        observed: bool,
        stopped: bool,
    ) {
        // Disarmed, this whole method is a branch: the two counts below
        // walk the corpus's batch list under its lock, and nothing reads
        // them except the records this returns before writing.
        if !self.on {
            return;
        }
        self.observer.set(match (observed, stopped) {
            (false, _) => Observer::None,
            (true, false) => Observer::Continue,
            (true, true) => Observer::Stop,
        });
        if let Some(r) = retained {
            self.retained_blocks.set(r.retained_blocks() as u64);
            self.retained_bytes.set(r.retained_bytes() as u64);
        }
        let blocks_total: usize = targets.iter().map(|t| t.n_slices).sum();
        let proved: usize = targets
            .iter()
            .map(|t| t.present.iter().filter(|&&ok| ok).count().min(t.n_slices))
            .sum();
        emit(
            "survey",
            fields(json!({
                "inv": self.inv,
                "attempt": self.no,
                "verify_ms": self.verify_ms.get(),
                "members": targets.len(),
                "members_intact": targets.iter().filter(|t| t.intact).count(),
                "members_present": targets.iter().filter(|t| t.exists).count(),
                "members_md5_unfinished": targets.iter().filter(|t| t.md5_unfinished).count(),
                "blocks_total": blocks_total,
                "blocks_proved": proved,
                "blocks_remaining": blocks_total.saturating_sub(proved),
                "retained_blocks": self.retained_blocks.get(),
                "retained_bytes": self.retained_bytes.get(),
                "observer": self.observer.get().as_str(),
            })),
        );
    }

    /// Members the shortfall arbitration took back out of `missing`
    /// after finishing a whole-file digest the verify pass cut short.
    pub(super) fn arbitrated(&self, members: usize) {
        if self.on {
            self.arbitrated.set(members as u32);
        }
    }

    /// The syndrome pass took the corpus.
    pub(super) fn consumed(&self, blocks: usize, bytes: usize) {
        if !self.on {
            return;
        }
        self.consumed.set(true);
        self.consumed_blocks.set(blocks as u64);
        self.consumed_bytes.set(bytes as u64);
    }

    /// The attempt's verdict. Emits the buffer disposition first,
    /// because the corpus is gone by the time the caller sees this.
    /// `continuing` says a retry follows, so a reader never has to
    /// guess whether the last attempt it can see is the verdict.
    pub(super) fn finish(&self, out: &Result<RepairStatus, RepairError>, continuing: bool) {
        if self.finished.replace(true) || !self.on {
            return;
        }
        let (outcome, rebuilt, adopted) = classify(out);
        self.disposition(discard_reason(outcome, self.observer.get()));
        emit(
            "attempt_finish",
            fields(json!({
                "inv": self.inv,
                "attempt": self.no,
                "outcome": outcome,
                "state": if continuing { "continuing" } else { "terminal" },
                "retry_reason": continuing.then_some("ntt_verify_failed"),
                "blocks_rebuilt": rebuilt,
                "blocks_adopted": adopted,
                "arbitrated_members": self.arbitrated.get(),
                "elapsed_ms": self.t0.elapsed().as_millis() as u64,
            })),
        );
    }

    fn disposition(&self, reason: &'static str) {
        emit(
            "disposition",
            fields(json!({
                "inv": self.inv,
                "attempt": self.no,
                "admitted": self.admitted.get(),
                "consumed": self.consumed.get(),
                "retained_blocks": self.retained_blocks.get(),
                "retained_bytes": self.retained_bytes.get(),
                "consumed_blocks": self.consumed_blocks.get(),
                "consumed_bytes": self.consumed_bytes.get(),
                // An admitted corpus that held nothing is its own
                // population: it paid the allocation and the decision
                // and could not have saved a byte of reread.
                "admitted_zero_useful": self.admitted.get() && self.retained_bytes.get() == 0,
                "reason": reason,
            })),
        );
    }
}

impl Drop for Attempt {
    /// An attempt that never reached [`Attempt::finish`] - a panic, an
    /// observer that unwound, a process taken down mid-pass - is
    /// recorded as EXPLICITLY unfinished. Pairing starts with finishes
    /// is how the collector exposes what it did not see; silence would
    /// read as a clean attempt.
    fn drop(&mut self) {
        if self.finished.replace(true) || !self.on {
            return;
        }
        let panicking = std::thread::panicking();
        self.disposition("attempt_unfinished");
        emit(
            "attempt_finish",
            fields(json!({
                "inv": self.inv,
                "attempt": self.no,
                "outcome": "unfinished",
                "state": "unfinished",
                "panicking": panicking,
                "elapsed_ms": self.t0.elapsed().as_millis() as u64,
            })),
        );
    }
}

/// The verdict vocabulary. `no_damage` is the CLEAN set only - an
/// observer stop spells itself `NoDamage` in the engine and is
/// separated by [`discard_reason`] and the survey's own `observer`
/// field, never counted here.
fn classify(out: &Result<RepairStatus, RepairError>) -> (&'static str, usize, usize) {
    match out {
        Ok(RepairStatus::NoDamage) => ("no_damage", 0, 0),
        Ok(RepairStatus::Repaired(r)) => (
            if r.blocks_rebuilt == 0 && r.blocks_adopted > 0 {
                "adoption_only"
            } else {
                "repaired"
            },
            r.blocks_rebuilt,
            r.blocks_adopted,
        ),
        Ok(RepairStatus::Unrepairable { adopted, .. }) => ("unrepairable", 0, *adopted),
        Err(e) => (err_kind(e), 0, 0),
    }
}

/// The error's VARIANT, never its message. A `Malformed` string carries
/// set arithmetic, an `Io` one carries a path, and a `VerifyFailed` one
/// carries a file name - none of which these aggregates need. The
/// variant is what separates populations: a set nobody can repair, a
/// box that is too small for the solve, and a disk that would not read
/// are three different reasons for an unread corpus.
fn err_kind(e: &RepairError) -> &'static str {
    match e {
        RepairError::Io(_) => "error_io",
        RepairError::NoMainPacket => "error_no_main_packet",
        RepairError::Malformed(_) => "error_malformed",
        RepairError::RecoveryShort { .. } => "error_recovery_short",
        RepairError::SolveBudget { .. } => "error_solve_budget",
        RepairError::SingularMatrix => "error_singular_matrix",
        RepairError::VerifyFailed(_) => "error_verify_failed",
        // NOT a failure, and the census must not fold it in with one:
        // nothing was wrong with the set, the caller simply stopped it.
        // Its own population for the same reason `Observer::Stop` has
        // one - a retained corpus bought by an attempt somebody called
        // off is not evidence about sets.
        RepairError::Cancelled => "error_cancelled",
        // Same reading as `Cancelled`, one step earlier: the caller's
        // long-repair veto stood the repair down before the fold, so
        // nothing about the set was measured past the survey and this
        // corpus is not evidence about sets either. TODO 332.
        RepairError::Deferred { .. } => "error_deferred",
    }
}

/// Why a corpus went unread, from the attempt's own evidence.
fn discard_reason(outcome: &'static str, observer: Observer) -> &'static str {
    if observer == Observer::Stop {
        return "observer_stop";
    }
    match outcome {
        "no_damage" => "no_damage",
        "repaired" => "consumed_by_syndrome_pass",
        "adoption_only" => "adoption_only",
        "unrepairable" => "shortfall",
        // Every remaining outcome is an `err_kind`, which already names
        // the variant on the attempt record beside this one.
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/// An in-memory census, for the validation cases. Installed under a
/// process-wide lock, because the sink is process-global and so is the
/// retention budget it reports.
#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Holds the census pointed at memory for as long as it lives.
    pub struct Recorder {
        _g: std::sync::MutexGuard<'static, ()>,
    }

    /// Arm the census into memory. Serializes against every other
    /// recorder and against `retain`'s forced-policy seam.
    pub fn record() -> Recorder {
        let g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The env arm is a `Once`: run it now so a later production
        // call cannot replace the memory sink half way through a test.
        ENV_ARM.call_once(|| {});
        install(
            Out::Mem(std::thread::current().id(), Vec::new()),
            "synthetic".into(),
        );
        Recorder { _g: g }
    }

    /// Arm the census at a real FILE, which is the shape production
    /// collection takes. `record()` above shares every line of this
    /// module except the one that writes, so the file arm needs its own
    /// coverage or the only untested code is the one that ships.
    pub fn record_to_file(path: &std::path::Path) -> Recorder {
        let g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        ENV_ARM.call_once(|| {});
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("the test owns this path");
        install(Out::File(f), "synthetic".into());
        Recorder { _g: g }
    }

    impl Recorder {
        /// Every record written so far, parsed.
        pub fn events(&self) -> Vec<Value> {
            let g = sink_cell().lock().unwrap_or_else(|e| e.into_inner());
            match g.as_ref().map(|s| &s.out) {
                Some(Out::Mem(_, v)) => v
                    .iter()
                    .map(|l| serde_json::from_str(l).expect("the census writes valid JSON"))
                    .collect(),
                _ => Vec::new(),
            }
        }

        /// Every record of one kind.
        pub fn of_kind(&self, kind: &str) -> Vec<Value> {
            self.events()
                .into_iter()
                .filter(|e| e["kind"] == kind)
                .collect()
        }
    }

    impl Drop for Recorder {
        fn drop(&mut self) {
            ARMED.store(false, Ordering::Relaxed);
            *sink_cell().lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }
}
