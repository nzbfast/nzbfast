//! Extraction knobs: the NZBFAST_NO_* env gates, the global
//! nested-depth and external-unrar settings, and the per-extractor
//! set_* configuration accessors.
//!
//! Split out of the 19,920-line `extract.rs` under the TODO 43
//! recipe: a verbatim move, not a redesign.

use super::*;
use crate::sync::MutexExt;

/// Default nesting levels an extractor chain will map. A child created at
/// this depth is built with extraction disabled, so every slot at that
/// level goes Plain (the file materializes - never a hard failure). Real
/// usenet nesting is 2-3 levels; the cap is the DoS backstop against a
/// crafted archive that unpacks to a slightly different archive forever.
/// Configurable via the daemon `nested_max_depth` setting
/// ([`set_nested_depth_cap`]) or the `NZBFAST_NESTED_MAX_DEPTH` env
/// override (tests); resolved by [`nested_depth_cap`].
pub(super) const NESTED_MAX_DEPTH_DEFAULT: usize = 5;

/// Process-global nested depth cap set from the daemon `nested_max_depth`
/// setting. 0 = unset (fall back to [`NESTED_MAX_DEPTH_DEFAULT`]). Both
/// the in-stream child chain (via the ctor default) and the disk
/// post-pass (nzbfast `extract_nested`) resolve through
/// [`nested_depth_cap`], so a single setting drives both.
pub(super) static NESTED_MAX_DEPTH_SETTING: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Daemon knob: set the nested-extraction depth cap (0 clears back to the
/// default). Clamped to >= 1 - a cap of 0 would materialize the OUTER
/// archive and extract nothing.
pub fn set_nested_depth_cap(depth: usize) {
    NESTED_MAX_DEPTH_SETTING.store(depth, std::sync::atomic::Ordering::Relaxed);
}

/// Resolve the effective nested depth cap: the `NZBFAST_NESTED_MAX_DEPTH`
/// env override (tests) wins, then the daemon setting, then the default.
/// Always >= 1.
pub fn nested_depth_cap() -> usize {
    if let Some(n) = std::env::var("NZBFAST_NESTED_MAX_DEPTH")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
    {
        return n.max(1);
    }
    match NESTED_MAX_DEPTH_SETTING.load(std::sync::atomic::Ordering::Relaxed) {
        0 => NESTED_MAX_DEPTH_DEFAULT,
        n => n.max(1),
    }
}

/// Rollout escape hatch for nested routing, latched at construction.
pub(super) fn nested_env_off() -> bool {
    nested_env_off_value(std::env::var("NZBFAST_NO_NESTED_ONEPASS").ok().as_deref())
}

/// Pure parse of the escape-hatch value (unit-testable without mutating
/// the process environment under the parallel test runner).
pub(super) fn nested_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Soak isolation switch for the RAR chasing decompressor alone: with it
/// set, nested routing still runs (store-in-store keeps one-pass) but a
/// compressed inner RAR demotes to a materialized file exactly as it did
/// before the chase existed. Latched at construction.
///
/// RAR ONLY, by design: it does NOT gate the 7z chase (or the zip one).
/// Each chase family has its own switch - `NZBFAST_NO_NESTED_7Z`,
/// `NZBFAST_NO_NESTED_ZIP` - so a soak can isolate one decoder without
/// turning off the others; `NZBFAST_NO_NESTED_ONEPASS` is the switch
/// that takes the whole nested path down. Its doc used to say "inner
/// archive", which overstated it (TODO 37 open list, closed 23 Aug 2026).
pub(super) fn chase_env_off() -> bool {
    chase_env_off_value(std::env::var("NZBFAST_NO_NESTED_CHASE").ok().as_deref())
}

/// Pure parse of the chase escape-hatch value (same rationale as
/// [`nested_env_off_value`]).
pub(super) fn chase_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Soak isolation switch for the 7z chase alone (phase 3), mirroring
/// `NZBFAST_NO_NESTED_CHASE`: with it set, an inner .7z demotes to a
/// materialized file exactly as it did before the 7z path existed.
/// Latched at construction.
pub(super) fn sevenz_env_off() -> bool {
    sevenz_env_off_value(std::env::var("NZBFAST_NO_NESTED_7Z").ok().as_deref())
}

/// Pure parse of the 7z escape-hatch value (same rationale as
/// [`nested_env_off_value`]).
pub(super) fn sevenz_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Soak isolation switch for the NESTED zip chase alone, the zip twin
/// of `NZBFAST_NO_NESTED_7Z`: with it set, an inner zip demotes to a
/// materialized file exactly as it did before the depth guard came off.
/// Added with the nested lift so the two gate families stay symmetric -
/// nested 7z and nested compressed RAR both have one, and a user who
/// wants only zip's nested half off should not have to disable nested
/// one-pass routing wholesale. Latched at construction.
pub(super) fn nested_zip_env_off() -> bool {
    nested_zip_env_off_value(std::env::var("NZBFAST_NO_NESTED_ZIP").ok().as_deref())
}

/// Pure parse of the nested-zip escape-hatch value (same rationale as
/// [`nested_env_off_value`]).
pub(super) fn nested_zip_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Soak isolation switch for the TOP-LEVEL 7z chase alone (TODO 37 step
/// 1), one level finer than `NZBFAST_NO_NESTED_7Z`: with it set, an
/// inner .7z still streams but a posted `.7z` materializes and waits for
/// the disk post-pass exactly as it did before the depth guard came off.
/// Latched at construction.
pub(super) fn top_sevenz_env_off() -> bool {
    top_sevenz_env_off_value(std::env::var("NZBFAST_NO_TOP_7Z").ok().as_deref())
}

/// Pure parse of the top-level 7z escape-hatch value (same rationale as
/// [`nested_env_off_value`]).
pub(super) fn top_sevenz_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Soak isolation switch for the TOP-LEVEL RAR chase, one level finer
/// than `NZBFAST_NO_NESTED_CHASE` and the exact analogue of
/// `NZBFAST_NO_TOP_7Z`: with it set, an inner compressed RAR still
/// chases but a POSTED compressed RAR materializes its volumes and
/// waits for the unrar ladder exactly as it did before the depth guard
/// came off. Latched at construction.
pub(super) fn top_chase_env_off() -> bool {
    top_chase_env_off_value(std::env::var("NZBFAST_NO_TOP_RAR_CHASE").ok().as_deref())
}

/// Pure parse of the top-level RAR chase escape-hatch value (same
/// rationale as [`nested_env_off_value`]).
pub(super) fn top_chase_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Process-global "prefer external unrar" - the daemon setting
/// (`prefer_external_unrar`, via [`set_prefer_external_unrar`]) that
/// routes RAR unpacking through the user's own unrar subprocess instead
/// of the native extractor.
pub(super) static PREFER_EXTERNAL_UNRAR: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Daemon knob: prefer the external unrar subprocess over the native
/// (vendored rars) extractor. See [`prefer_external_unrar`].
pub fn set_prefer_external_unrar(on: bool) {
    PREFER_EXTERNAL_UNRAR.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Resolve the effective "prefer external unrar" answer: the
/// `NZBFAST_NO_NATIVE_UNRAR` env override (presence, not value - it
/// predates the `=1` convention of the later switches and is documented
/// bare) forces it on, else the daemon setting decides.
///
/// ONE predicate on purpose, consulted from BOTH places that would
/// otherwise unpack a RAR natively: the disk-path engine choice in the
/// nzbfast binary (`try_unrar`), and the top-level RAR chase latch below
/// - with the chase left on, a posted compressed set streams through the
/// native decoder mid-download and the user's unrar never sees it, which
/// is exactly what the switch promises to prevent. It deliberately does
/// NOT reach the store path (a stored set is placed byte-for-byte and
/// CRC-checked, no decompressor involved; anything that pass cannot
/// finish demotes to disk, where this switch applies) or the obfuscated
/// disk handoff (hash-named volumes follow naming no unrar subprocess
/// can, so the native path is the only one that unpacks them).
pub fn prefer_external_unrar() -> bool {
    std::env::var_os("NZBFAST_NO_NATIVE_UNRAR").is_some()
        || PREFER_EXTERNAL_UNRAR.load(std::sync::atomic::Ordering::Relaxed)
}

/// Escape hatch for drop-behind trimming (TODO 37 step 2): with it set,
/// a 7z chase retains every byte it has taken and an archive over the
/// retention cap demotes, which is exactly the behaviour before trimming
/// existed. Latched at construction.
pub(super) fn sevenz_trim_env_off() -> bool {
    sevenz_trim_env_off_value(std::env::var("NZBFAST_NO_7Z_TRIM").ok().as_deref())
}

/// Pure parse of the trim escape-hatch value (same rationale as
/// [`nested_env_off_value`]).
pub(super) fn sevenz_trim_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Escape hatch for the RAR chase's drop-behind trim: with it set, a
/// chased RAR set retains every byte it has taken and a set over the
/// retention cap demotes to the unrar ladder, which is exactly the
/// behaviour before the incremental split decode existed. The exact
/// analogue of `NZBFAST_NO_7Z_TRIM`. Latched at construction.
pub(super) fn rar_trim_env_off() -> bool {
    rar_trim_env_off_value(std::env::var("NZBFAST_NO_RAR_TRIM").ok().as_deref())
}

/// TODO 211 (b) escape hatch: `NZBFAST_NO_RAR_SPLIT=1` turns off the
/// one-pass mapping of a declared `.rar.NNN` byte split, so the parts
/// materialize and the TODO 211 (a) rescue joins them on disk exactly as
/// before the mapper learned the shape. Latched at construction.
pub(super) fn rar_split_env_off() -> bool {
    rar_split_env_off_value(std::env::var("NZBFAST_NO_RAR_SPLIT").ok().as_deref())
}

/// Pure parse of the RAR split escape-hatch value (same rationale as
/// [`nested_env_off_value`]).
pub(super) fn rar_split_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Pure parse of the RAR trim escape-hatch value.
pub(super) fn rar_trim_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Escape hatch for the RAR trim's drop-not-spill: with it set, every
/// trim spills its consumed prefix into the volume file (the pre-22 Aug
/// 2026 behaviour, a write of consumed input a clean job never reads
/// back), so a demote materializes from disk and RAM alone and no
/// re-fetch is ever needed. Latched at construction.
pub(super) fn rar_drop_env_off() -> bool {
    rar_drop_env_off_value(std::env::var("NZBFAST_NO_RAR_DROP").ok().as_deref())
}

/// Pure parse of the RAR drop escape-hatch value.
pub(super) fn rar_drop_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Kill switch for the TAR chase at every depth (TODO 163 item 6):
/// with it set, a `.tar` - posted or inside another archive -
/// materializes as an ordinary file and the disk pass sees it exactly
/// as it did before the arm existed.
///
/// ONE gate where zip has two (`NZBFAST_NO_NESTED_ZIP` plus
/// `NZBFAST_NO_TOP_ZIP`), because zip's nested lift and its top-level
/// chase shipped as separate phases and each wanted its own soak
/// switch. Tar lands whole, and a declining top-level tar simply lands
/// on disk, so a second gate would say nothing the first does not.
/// Latched at construction.
pub(super) fn tar_env_off() -> bool {
    tar_env_off_value(std::env::var("NZBFAST_NO_TAR").ok().as_deref())
}

/// Pure parse of the tar escape-hatch value (same rationale as
/// [`nested_env_off_value`]).
pub(super) fn tar_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Escape hatch for the TOP-LEVEL zip chase (one-pass zip, phase 2):
/// with it set, a posted `.zip` materializes and waits for the disk
/// post-pass exactly as it did in phase 1. The exact analogue of
/// `NZBFAST_NO_TOP_7Z`. Latched at construction.
pub(super) fn top_zip_env_off() -> bool {
    top_zip_env_off_value(std::env::var("NZBFAST_NO_TOP_ZIP").ok().as_deref())
}

/// Pure parse of the top-level zip escape-hatch value (same rationale as
/// [`nested_env_off_value`]).
pub(super) fn top_zip_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Escape hatch for the final-output CRC gate, mirroring the nested
/// gates: with it set, the level-0 store payload ships unverified
/// exactly as before the gate existed. Latched at construction.
pub(super) fn output_crc_env_off() -> bool {
    output_crc_env_off_value(std::env::var("NZBFAST_NO_OUTPUT_CRC").ok().as_deref())
}

/// Pure parse of the output-CRC escape-hatch value (same rationale as
/// [`nested_env_off_value`]).
pub(super) fn output_crc_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

impl Extractor {
    /// Ceiling on how much space an inner-file writer may RESERVE, shared
    /// by every nesting level (see [`Limits::prealloc_cap`]). Pass the
    /// NZB's posted byte count: a store archive cannot legitimately unpack
    /// to more than what was posted, and preallocation past the ceiling is
    /// only an optimisation the writer does without.
    ///
    /// Safe to set at any time - the Arc is shared with children, and it
    /// is read per writer creation.
    pub fn set_prealloc_ceiling(&self, bytes: u64) {
        self.inner
            .lock_ok()
            .limits
            .prealloc_cap
            .store(bytes, Ordering::Relaxed);
    }

    /// Cap the DISTINCT extracted bytes this chain may write - the
    /// in-stream half of the decompression-bomb guard (the disk and
    /// post-pass sinks carry their own `BombGuardWriter` with the same
    /// budget). Shared across nesting levels and across every inner file,
    /// so a bomb split over many outputs cannot restart the allowance.
    pub fn set_extract_budget(&self, bytes: u64) {
        self.inner.lock_ok().limits.budget.set_limit(bytes);
    }

    /// Extracted bytes charged against [`Self::set_extract_budget`] so far
    /// (whole chain). Test/diagnostic hook.
    pub fn extract_budget_used(&self) -> u64 {
        self.inner.lock_ok().limits.budget.used()
    }

    /// Nested-routing gate (see `NZBFAST_NO_NESTED_ONEPASS`, latched at
    /// construction). Set before any span arrives - routing decisions are
    /// deterministic per inner file and must not flip mid-download.
    pub fn set_nested_one_pass(&self, on: bool) {
        self.inner.lock_ok().nested_on = on;
    }

    /// Override this chain's nested depth cap (see [`nested_depth_cap`]).
    /// Set before any child is created - the value is read when a span
    /// first descends a level. Clamped to >= 1. Used by the daemon to
    /// apply a live `nested_max_depth` change and by tests for a
    /// deterministic cap without touching the process-global setting.
    pub fn set_nested_max_depth(&self, depth: usize) {
        self.inner.lock_ok().nested_max_depth = depth.max(1);
    }

    /// Chasing-decompressor gate (see `NZBFAST_NO_NESTED_CHASE`, latched
    /// at construction). Same set-before-spans discipline as the nested
    /// routing gate.
    pub fn set_nested_chase(&self, on: bool) {
        self.inner.lock_ok().chase_on = on;
    }

    /// 7z-chase gate (see `NZBFAST_NO_NESTED_7Z`, latched at
    /// construction). Same set-before-spans discipline as the other
    /// gates.
    pub fn set_nested_sevenz(&self, on: bool) {
        self.inner.lock_ok().sevenz_on = on;
    }

    /// Nested-zip gate (see `NZBFAST_NO_NESTED_ZIP`, latched at
    /// construction). Same set-before-spans discipline as the other
    /// gates.
    pub fn set_nested_zip(&self, on: bool) {
        self.inner.lock_ok().nested_zip_on = on;
    }

    /// Top-level 7z gate (see `NZBFAST_NO_TOP_7Z`, latched at
    /// construction). Same set-before-spans discipline as the other
    /// gates: a posted `.7z` is classified once, on its offset-0
    /// article.
    pub fn set_top_level_sevenz(&self, on: bool) {
        self.inner.lock_ok().top_sevenz_on = on;
    }

    /// Top-level RAR chase gate (see `NZBFAST_NO_TOP_RAR_CHASE`, latched
    /// at construction). Same set-before-spans discipline as the other
    /// gates: the blocker that attaches a chase fires on the archive's
    /// first parsed entry.
    pub fn set_top_level_chase(&self, on: bool) {
        self.inner.lock_ok().top_chase_on = on;
    }

    /// Tar-chase gate (see `NZBFAST_NO_TAR`, latched at construction).
    /// Same set-before-spans discipline as the other gates: a `.tar` is
    /// classified once, on its offset-0 article.
    pub fn set_tar(&self, on: bool) {
        self.inner.lock_ok().tar_on = on;
    }

    /// Top-level zip gate (see `NZBFAST_NO_TOP_ZIP`, latched at
    /// construction). Same set-before-spans discipline as the other
    /// gates: a posted `.zip` is classified once, on its offset-0
    /// article.
    pub fn set_top_level_zip(&self, on: bool) {
        self.inner.lock_ok().top_zip_on = on;
    }

    /// Declare a byte-split zip set from the NZB's own file list:
    /// `base` is `zip::split_part_name`'s base, `parts` the count, and
    /// the caller must have checked the indices run exactly `1..=n`.
    /// A zip split cannot be sized from its own bytes (no part carries
    /// a container-sizing header, unlike 7z), so this is what tells the
    /// chase when every part's decoded size is in. Same set-before-
    /// spans discipline as the gates: declare before the first write.
    ///
    /// Also the CLOSE of a parent-opened nested set (§94 D): when a
    /// pending set already sits under `base`, the count resolves it
    /// here and its tail promote is raised - see `zip_split.rs`.
    pub fn declare_zip_split(&self, base: &str, parts: u32) {
        if parts == 0 {
            return;
        }
        self.declare_zip_split_closed(&base.to_ascii_lowercase(), parts);
    }

    /// Drop-behind trim gate (see `NZBFAST_NO_7Z_TRIM`, latched at
    /// construction). Unlike the other gates this one is safe to flip
    /// mid-download - it only decides whether a budget breach trims
    /// before it demotes - but tests set it up front like the rest.
    pub fn set_sevenz_trim(&self, on: bool) {
        self.inner.lock_ok().sevenz_trim_on = on;
    }

    /// RAR chase drop-behind trim gate (see `NZBFAST_NO_RAR_TRIM`,
    /// latched at construction). Same discipline as
    /// [`Self::set_sevenz_trim`]: safe to flip mid-download, but tests
    /// set it up front.
    pub fn set_rar_trim(&self, on: bool) {
        self.inner.lock_ok().rar_trim_on = on;
    }

    /// RAR trim drop-not-spill gate (see `NZBFAST_NO_RAR_DROP`, latched
    /// at construction). Safe to flip mid-download like
    /// [`Self::set_rar_trim`]: it only decides what a trim does with the
    /// bytes it releases.
    pub fn set_rar_drop(&self, on: bool) {
        self.inner.lock_ok().rar_drop_on = on;
    }

    /// Final-output CRC gate (see `NZBFAST_NO_OUTPUT_CRC`, latched at
    /// construction; default on). Same set-before-spans discipline as
    /// the other gates - composition happens as spans route, so a
    /// mid-download flip would leave gaps that read as "unverifiable"
    /// and skip the check.
    pub fn set_verify_output_crc(&self, on: bool) {
        self.inner.lock_ok().verify_output_crc = on;
    }

    /// Install the article-promotion hook (nested 7z tail prefetch): the
    /// daemon wires this to its seek/promote ladder, so a child extractor
    /// that classifies an inner .7z can front-load the articles carrying
    /// its end header. Composition runs child -> parent through
    /// [`Self::promote_file`], translating each level's file ranges
    /// through the level above (all-store levels only; a compressed level
    /// in between yields no mapping and the promote is skipped - the
    /// chase reaches those bytes sequentially anyway). Install before any
    /// span arrives, like the gates - it also anchors the chain's root
    /// for the upward walk.
    pub fn set_promote_hook(self: &Arc<Self>, hook: PromoteHook) {
        self.anchor();
        self.inner.lock_ok().promote = Some(hook);
    }

    /// Anchor the chain's ROOT: record its own `Arc` weakly, which is
    /// what a chase worker upgrades through on every callback (and what
    /// lets a cancelled job actually drop). A child gets this from
    /// `ensure_child`; the root cannot get it at construction, because
    /// the public constructors hand back an owned value and only the
    /// caller knows whether it becomes an `Arc`.
    ///
    /// A root that is never anchored simply does not chase at depth 0 -
    /// a posted `.7z` materializes for the disk post-pass, which is the
    /// pre-TODO-37 behaviour - so forgetting this degrades rather than
    /// breaks. Call it once, before any span arrives.
    pub fn anchor(self: &Arc<Self>) {
        self.inner.lock_ok().self_weak = Arc::downgrade(self);
    }

    /// Re-extraction mode: slot bytes are fed from real volume files in
    /// `out_dir`, so no fallback may ever materialize a slot writer (it
    /// would truncate the very file being read). Fallback slots discard.
    pub fn set_protect_sources(&self) {
        self.inner.lock_ok().protect_sources = true;
    }

    /// Archive password for encrypted RAR5 store sets. Set before any
    /// span is written - mappers capture it at slot classification.
    pub fn set_password(&self, pw: &str) {
        self.inner.lock_ok().password = Some(std::sync::Arc::from(pw));
    }

    /// Install the candidate-password probe (Increment A). With it set,
    /// a slot hitting a password-shaped blocker holds its spans (same
    /// budget as every other hold) instead of demoting, while the hook
    /// hunts the job's own sidecars/stems for a check-verified password:
    /// a hit re-keys the mapper in place and the set streams one-pass; a
    /// miss demotes at budget pressure or at finish, exactly as before.
    pub fn set_password_probe(&self, hook: PwProbeHook) {
        self.inner.lock_ok().pw_probe = Some(hook);
    }

    /// §94 B: install the verified-block watermark handle. Root level
    /// ONLY, deliberately not inherited by children - nested levels'
    /// bytes are outside the PAR2 set, so a child chase gating on a
    /// level-0 slot index would wait on the wrong slot's verification.
    /// A child chase gates instead through `ChildGate` (row 27), which
    /// translates its routed offsets onto the parent volumes' cells.
    /// Wire before the download starts (buffers created earlier would
    /// miss it).
    pub fn set_verify_gate(&self, gate: Arc<crate::live::VerifyGate>) {
        self.inner.lock_ok().verify_gate = Some(gate);
    }

    /// This slot's verified-block watermark, as [`VerifyGate::engaged_mark`]
    /// answers it: `None` when the verifier never ENGAGED the slot (no
    /// set, unclaimed, gate off), and `u64::MAX` once every block of it
    /// has been vouched in stream.
    ///
    /// The engaged form and not `watermark`, because the two answer
    /// opposite things about an unclaimed slot - `watermark` reads it as
    /// fully vouched, which is the safe reading for a DECODE that must
    /// not park forever and the dangerous one for a caller asking "may I
    /// publish this file". Its only such caller today is the daemon's
    /// early per-file publish (§296), which treats anything but
    /// `Some(u64::MAX)` as "not yet".
    ///
    /// [`VerifyGate::engaged_mark`]: crate::live::VerifyGate::engaged_mark
    pub fn verify_mark(&self, slot: usize) -> Option<u64> {
        let gate = self.inner.lock_ok().verify_gate.clone();
        gate?.engaged_mark(slot)
    }

    /// Whether chase decodes PARK on the verify gate (§94 B proper) or
    /// only consult its watermark (the dropping trim). See
    /// `Inner::verify_gate_waits`. Travels down the chain: a child that
    /// already exists is updated too.
    pub fn set_verify_gate_waits(&self, waits: bool) {
        let child = {
            let mut inner = self.inner.lock_ok();
            inner.verify_gate_waits = waits;
            inner.child.clone()
        };
        if let Some(c) = child {
            c.set_verify_gate_waits(waits);
        }
    }

    /// A mapped repair has PROVED the whole PAR2 set (it re-read every
    /// file of the set through the view it wrote through): every
    /// engaged gate cell goes to "fully vouched". Without this a chase
    /// parked at a block the repair rebuilt waits until finish releases
    /// it, and the whole decode runs in the tail instead of behind the
    /// repair (row 27). No gate installed: nothing to do.
    pub fn release_verify_gate(&self) {
        let gate = self.inner.lock_ok().verify_gate.clone();
        if let Some(g) = gate {
            g.release_all();
        }
    }

    /// Install the materialized-volume notification (see
    /// [`MaterializedHook`]). Root level ONLY, deliberately not
    /// inherited by children - the journal records placements in the
    /// ROOT's slot space, and a nested slot index fired through this
    /// hook would rewrite some unrelated root slot's records.
    pub fn set_materialized_hook(&self, hook: MaterializedHook) {
        self.inner.lock_ok().materialized = Some(hook);
    }
}
