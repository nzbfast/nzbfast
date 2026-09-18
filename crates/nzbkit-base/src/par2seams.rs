//! The algorithm-selection census: every point in the PAR2 stack where
//! the code chooses between two implementations, the arm it takes for a
//! given shape, and the provenance of the constant that decided it.
//!
//! **Why this exists.** The stack has two dozen selection points, each
//! with its own `NZBFAST_*` escape hatch and its own threshold, and
//! nothing enumerated them. Three failure modes followed, all of them
//! live when this was written:
//! a constant goes STALE when both sides of its seam are optimised and
//! nobody re-derives the crossover;
//! a constant SHARED across architectures gets set by the binding one
//! (the additive leaf's own comment prices this at 19% left on the i5);
//! and a constant split only `aarch64`-vs-else is COARSE, collapsing
//! three x86 kernel classes that [`crate::gf16::multi_fold_width`]
//! already tells apart.
//!
//! The Forney gate is the counter-example and the model: it carries
//! three constants, one per class, each measured on the class it gates
//! and each arguing its own safety margin. It is also the reason this
//! module exists - a reader (this one) mis-transcribed which of the
//! three a build takes while looking straight at the file, and published
//! it. A resolved arm, printed, is cheaper than a careful reader.
//!
//! **The rule that keeps this honest: every arm below CALLS the real
//! gate.** Nothing here re-implements a threshold. A census that
//! reasoned about the gates independently would be a second copy of the
//! rule, free to disagree with the code it claims to describe - which is
//! precisely the class of defect it exists to expose. Where a gate is
//! `pub(super)` its owning module carries a three-line `pub(crate)` shim
//! and nothing else.
//!
//! **What it is NOT.** Not a policy engine and not a gate: it changes no
//! selection and fails no build. It answers "what did this run choose,
//! and on what evidence" - which is the precondition for a crossover
//! sweep being able to prove it measured the arm it thinks it did.
//! `tools/seam-sweep.py` is the other half: it re-measures a seam on
//! demand and reports which seams have drifted since their `measured_at`.

use std::fmt::Write as _;

/// The fused-kernel class this part falls in, which is the axis the
/// thresholds below should be keyed on and mostly are not. Derived from
/// [`crate::gf16::multi_fold_width`] - the group width the multi-source
/// fold uses - so it needs no CPU detection of its own and cannot
/// disagree with the kernel actually selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelClass {
    /// AVX-512 + GFNI: 12 matrix pairs in 32 zmm registers.
    Avx512Gfni,
    /// GFNI without AVX-512: the affine2x group, 6 pairs in 16 ymm.
    Gfni256,
    /// NEON: 8 sources per group.
    Neon,
    /// AVX2 or SSSE3 nibble-shuffle tables: 4 sources per group.
    Nibble,
    /// No fused kernel: a `FoldTable` per source (armv7, or a forced
    /// `NZBFAST_GF16_MULTI=0` A/B).
    Scalar,
}

impl KernelClass {
    /// This process's class, from the width the fold kernel reports.
    pub fn current() -> KernelClass {
        match crate::gf16::multi_fold_width() {
            12 => KernelClass::Avx512Gfni,
            6 => KernelClass::Gfni256,
            8 => KernelClass::Neon,
            4 => KernelClass::Nibble,
            _ => KernelClass::Scalar,
        }
    }

    /// The short tag used in sweep output and registry entries.
    pub fn tag(self) -> &'static str {
        match self {
            KernelClass::Avx512Gfni => "avx512-gfni",
            KernelClass::Gfni256 => "gfni256",
            KernelClass::Neon => "neon",
            KernelClass::Nibble => "nibble",
            KernelClass::Scalar => "scalar",
        }
    }
}

/// The shape a selection is made against. Every field is a quantity some
/// seam keys on; a caller that does not know one leaves it `None` and
/// the seams that need it report `n/a` rather than guessing.
#[derive(Debug, Clone, Copy, Default)]
pub struct Shape {
    /// Missing blocks - the repair's dimension.
    pub missing: Option<usize>,
    /// Present input slices in the set.
    pub sources: Option<usize>,
    /// Recovery rows wanted.
    pub rows: Option<usize>,
    /// Block size in bytes.
    pub block_size: Option<usize>,
    /// Sources packed into one transform leaf.
    pub leaf_fill: Option<usize>,
    /// Create-side accumulator batches the layout makes.
    pub batches: Option<usize>,
}

/// Where a seam's threshold came from, so a reader can tell a measured
/// constant from an inherited one without leaving the file.
#[derive(Debug, Clone, Copy)]
pub struct Provenance {
    /// The box the crossover was measured on, or `""` when the seam is a
    /// capability test rather than a threshold.
    pub measured_on: &'static str,
    /// ISO date of that measurement, or `""`.
    pub measured_at: &'static str,
    /// The commit the measurement was taken against. `tools/seam-sweep.py
    /// --stale` compares this against the seam's own implementation files
    /// and names the ones that have moved since.
    pub measured_sha: &'static str,
    /// Which kernel classes that measurement actually covered. A class
    /// absent here is inheriting somebody else's number.
    pub covers: &'static [KernelClass],
}

/// One selection point.
pub struct Seam {
    /// Stable id, also the `tools/seam-sweep.py` argument.
    pub id: &'static str,
    /// The two implementations, as `"a vs b"`.
    pub chooses: &'static str,
    /// The rule in one line, for a reader who will not open the file.
    pub rule: &'static str,
    /// Files whose change can invalidate the threshold.
    pub files: &'static [&'static str],
    /// True when the rule turns on a NUMBER somebody measured, so it can
    /// drift and is worth re-sweeping; false for a capability test ("is
    /// this kernel present"), which cannot. Stated rather than inferred:
    /// a seam with a threshold nobody has measured yet must read as an
    /// unmeasured crossover, not as a capability test that needs nothing.
    pub is_crossover: bool,
    pub provenance: Provenance,
    /// The arm this shape takes, by CALLING the real gate. `None` when
    /// the shape does not carry the field the gate keys on.
    pub arm: fn(&Shape) -> Option<&'static str>,
}

/// Seams whose threshold is a CROSSOVER and can therefore go stale when
/// either side is optimised. The pure environment toggles are
/// deliberately absent: a seam with no measured number cannot drift, and
/// listing it here would dilute the thing this census is for.
pub static SEAMS: &[Seam] = &[
    Seam {
        id: "forney-backsub",
        chooses: "transform back-substitution vs dense m x m product",
        rule: "missing >= backsub_min_missing() - 704 NEON / 1280 nibble / 1280 generic - and a fused kernel exists",
        files: &[
            "crates/nzbkit-base/src/par2repair/forney.rs",
            "crates/nzbkit-base/src/par2repair/linalg.rs",
            "crates/nzbkit-base/src/gf16.rs",
        ],
        is_crossover: true,
        provenance: Provenance {
            measured_on: "six boxes, three classes: M1 Ultra / M3 Ultra / M5 Max (NEON, 704), i5-10600KF (nibble, 1280 - exact), Core Ultra 9 386H + EPYC 9354P (GFNI, ~1300-1400, gated at 1280); research/FORNEY-GATE-CROSSOVER-2026-09-10.md",
            measured_at: "2026-09-10",
            measured_sha: "fd7527d6e4",
            covers: &[
                KernelClass::Neon,
                KernelClass::Nibble,
                KernelClass::Avx512Gfni,
            ],
        },
        arm: |s| {
            s.missing.map(|m| {
                if crate::par2repair::forney::seam_backsub(m) {
                    "forney"
                } else {
                    "dense"
                }
            })
        },
    },
    Seam {
        id: "joint-arm",
        chooses: "joint constructor-and-solver vs the shipped two-stage solve",
        rule: "joint_gate(): --fast or NZBFAST_FORNEY_JOINT wins, else default ON for NEON, AVX-512 GFNI, 256-bit GFNI and Nibble (AVX2/SSSE3), OFF only where no fused kernel exists",
        files: &[
            "crates/nzbkit-base/src/par2repair/forney/joint.rs",
            "crates/nzbkit-base/src/par2repair/forney/whole.rs",
            "crates/nzbkit-base/src/gf16.rs",
        ],
        // Not a number, but it CAN go stale the way a number can: the
        // default rests on a whole-arm A/B taken against one revision of
        // the kernels below, and `seam-sweep.py --stale` is what compares
        // `measured_sha` to those files. A capability test could not go
        // stale and this is not one.
        is_crossover: true,
        provenance: Provenance {
            measured_on: "NEON: two Apple generations, M1 Ultra and M3 Ultra, 14 rungs \
                          from 256 to 16,384, whole-arm A/B with a paired A/A at every \
                          rung; no rung a loss, +4% to +21% from 4,096 up; the crossing \
                          unmoved by a 4x block size; \
                          research/JOINT-CROSSOVER-PER-CLASS-2026-09-11.md. \
                          AVX-512 GFNI: an EPYC 9354P at 48952e0bd2, native kernel, \
                          off vs --fast, \
                          medians of three, SHA-256 restoration gating every leg, BOTH \
                          bands - 2,048 +4.4% / 4,096 +1.6% / 6,144 +3.7% shallow and \
                          8,192 +29.7% / 16,384 +24.9% / 24,576 +29.1% deep, no rung a \
                          loss; m=1,024 is below this class's 1,280 BACKSUB_MIN_MISSING \
                          so the arm is never consulted there, which is why x86 has no \
                          equivalent of NEON's shallow turnover. THAT BOX'S SHALLOW \
                          FIGURES ARE INSIDE ITS OWN NOISE - its A/A floor was later \
                          measured at 13.6-36.9% - so they are kept above only to make \
                          this note readable, and the class rests instead on a \
                          RE-VALIDATION on quotable parts, 12 Sep 2026: two bare-metal \
                          Ryzen 7 9800X3D boxes, 93 legs each, five reps, 2,048 +4.84% / \
                          4,096 +7.85% / 6,144 +10.21% / 12,288 +31.98% on maxpc with \
                          xanderpc within 1.65 points at every rung and 5/5 positive \
                          throughout, every rung clearing its own paired A/A floor. \
                          Supported from m=2,048 UP: m=1,536, the first rung above the \
                          1,280 gate, clears its floor on NEITHER box, so 1,280-2,048 is \
                          unproven either way; \
                          research/JOINT-DEFAULT-ON-X86-GFNI-2026-09-11.md. \
                          256-bit GFNI (Gfni256): a Core Ultra 9 386H, 16 cores, Windows \
                          11, at fa5278f21128, native kernel, off vs --fast with a paired \
                          A/A at every rung, 14 rungs from 256 to 16,384, medians of \
                          three, SHA-256 restoration gating every leg, 129/129 restored; \
                          2,048 +5.4% (3/3, A/A 2.3%) and 16,384 +18.1% (3/3, A/A 2.6%) \
                          carry it, and every rung from 1,536 up clears its own floor with \
                          no losing band; the three rungs below the 1,280 gate are flat; \
                          research/rounds/jcross-intel-fastmode-2026-09-11/jcross-coreultra9.log",
            measured_at: "2026-09-11",
            // THE OLDER OF TWO ROUNDS, DELIBERATELY. This field is
            // single-valued and `seam-sweep.py --stale` names the seam's
            // files that moved since it, so with two measurements behind
            // one seam the EARLIER sha is the conservative choice: a file
            // that moved since it may have invalidated either round,
            // where the later sha would hide the older one's staleness.
            // The NEON round is `8c3da7d70d2d`; the AVX-512 GFNI round
            // ran at `48952e0bd2` and the 256-bit GFNI round at
            // `fa5278f21128`, both named in `measured_on` above, because
            // that is the only place a further sha can live until this
            // field learns to hold a set.
            measured_sha: "8c3da7d70d2d",
            covers: &[
                KernelClass::Neon,
                KernelClass::Avx512Gfni,
                KernelClass::Gfni256,
                // 12 Sep 2026, the GATED arm (JOINT_KERNEL_MIN_M_X86 in
                // force) on the i5-10600KF, off against --fast, three
                // rotated reps, an A/A at every rung: +2.3% (1,536) to
                // +20.2% (16,384), 3/3 at all eleven rungs;
                // research/FAST-MODE-CROSS-CLASS-ROUNDS-2026-09-12.md 5.5.
                // The class that lost at nine rungs a day earlier, on a
                // binary without the stage-1 gate and with the stripe
                // narrowed under stage 2.
                KernelClass::Nibble,
            ],
        },
        arm: |_| {
            Some(if crate::par2repair::forney::seam_joint_arm() {
                "joint"
            } else {
                "shipped"
            })
        },
    },
    Seam {
        id: "joint-factor",
        chooses: "factored stage-2 evaluation vs the shipped per-group sweep",
        rule: "missing >= JOINT_FACTOR_MIN_M (8192) - one constant; NEON-set, measured TOO HIGH on Zen 5",
        files: &[
            "crates/nzbkit-base/src/par2repair/forney/joint.rs",
            "crates/nzbkit-base/src/gf16.rs",
        ],
        is_crossover: true,
        provenance: Provenance {
            measured_on: "two aarch64 generations - M3 Ultra (research/JOINT-STAGE2-\
                          DEPTH-GATE-2026-09-11.md) and M1 Ultra at a different fixture \
                          and block size (research/JOINT-CROSSOVER-PER-CLASS-2026-09-11.md); \
                          both arms hold stage 1 on the additive product and differ only \
                          in NZBFAST_FORNEY_FACTOR; both put the crossover in the SAME \
                          512-block interval, 6,144 to 6,656, gated at 8,192 under a \
                          bias-HIGH rule. x86 Avx512Gfni IS now measured, on Zen 5 only \
                          (research/JOINT-FACTOR-MIN-M-X86-2026-09-11.md), and it does NOT \
                          agree: the factored arm wins from 1,536 - the first rung above \
                          x86's Forney gate - up to 12,288, by 5-17%, with ONE band around \
                          3,840 to 4,096 where it does not pay (sections 15 and 17). So no \
                          crossing exists on this part to place a constant at, and this \
                          constant denies a real gain over most of the range. The value is \
                          unchanged because that round covers ONE microarchitecture of the \
                          class and Zen 4 is in it too.",
            measured_at: "2026-09-11",
            measured_sha: "316f12ffb3",
            // NEON AND NOTHING ELSE, and that is the point of listing it.
            // Two GENERATIONS of it now, which is what justifies one
            // constant for the class rather than one per part - but two
            // generations of NEON is still one class.
            // Every x86 class is inheriting a number measured on Apple
            // silicon: the constant's own docstring argues the SHAPE of the
            // crossover is class-independent (both arms are `fold_rows`
            // calls over a group count that is arithmetic in `m`) but says
            // outright that the per-call cost can shift WHERE it falls.
            //
            // THE x86 ROUND HAS NOW BEEN RUN, ON BORROWED ZEN 5 HARDWARE,
            // AND IT CONTRADICTS THE INHERITED NUMBER. Two ladders, 225
            // timed legs, 9800X3D: the factored arm wins 5-9% over 5,120 to
            // 7,680 and 12-14% over 2,560 to 3,584, where NEON LOST up to
            // 18.75% at the same depths. The classes differ in SIGN across
            // the band this constant governs, not merely in where a crossing
            // sits. So 8,192 is too HIGH for the part measured.
            //
            // `covers` STILL SAYS Neon ONLY, and that is the point of the
            // field rather than an oversight. Avx512Gfni is every part with
            // AVX-512 and GFNI, Zen 4 included - and the round that flipped
            // `joint_default_on()` for this class ran on an EPYC 9354P,
            // which IS Zen 4. The stage-2 round covers two boxes of ONE
            // part, which is not the standard the NEON number met (two
            // generations). Lowering a class-wide constant on one
            // microarchitecture would pay the bias rule's growing
            // below-crossing loss on every Zen 4 part to buy a gain measured
            // only on Zen 5. The measurement lands; the constant waits for a
            // second microarchitecture.
            //
            // THE ZEN 4 HALF WAS ATTEMPTED ON 11 Sep 2026 AND IS VOID, so the
            // wait above is still on. 75 legs on an 8-vCPU EPYC 9354P guest
            // (section 15 of the x86 write-up) moved the control phase 18.18%
            // against a 4.91% A/A spread and voided on the rule pre-registered
            // before the round ran. Independently of that it would not have
            // resolved: 14 of 25 pairs positive, two-sided binomial p = 0.690,
            // with per-rung A/A floors of 13.6-36.9% against a 5-14% effect.
            // A void is NOT a disagreement - it is no evidence either way, so
            // it neither moves this constant nor licenses splitting the class.
            // Do not just add reps: they only buy sqrt(n). The floor's CAUSE
            // is NOT identified, though re-reducing the same legs in CPU
            // SECONDS is no quieter than in wall time (best signal/floor 0.72
            // against 0.69), which is evidence against time spent off-CPU and
            // for contention that leaves the core running and merely slower. It
            // needs a QUIET Zen 4 part for about an hour, and a per-leg steal
            // sample; the ladder and arms are already right
            // (every leg restored 32/32 with zero stage-label disagreements).
            //
            // A power-of-two artefact was suspected at 8,192 and then
            // REFUTED by a dense ladder straddling it (7,680 / 7,936 / 8,192
            // / 8,448 / 8,704). There is no notch: both arms step up together
            // by about 42% between 8,192 and 8,448 (shipped 1.350 -> 1.910s,
            // factored 1.320 -> 1.870s), so the cost structure belongs to the
            // problem size and does not favour either arm. The apparent dip in
            // the coarse ladder was 8,192 being the last rung BEFORE that step.
            // Recorded because the suspicion reached this comment before the
            // probe did, and a refuted claim left standing is worse than one
            // never made.
            covers: &[KernelClass::Neon],
        },
        arm: |s| {
            s.missing.map(|m| {
                if crate::par2repair::forney::seam_joint_factor(m) {
                    "factor"
                } else {
                    "shipped"
                }
            })
        },
    },
    Seam {
        id: "joint-kernel",
        chooses: "additive-FFT stage 1 vs the shipped Hankel product, inside the joint scheduler",
        rule: "missing >= JOINT_KERNEL_MIN_M_X86 (16384) on Nibble and Gfni256; no gate on NEON or AVX-512 GFNI, which are unmeasured for it",
        files: &[
            "crates/nzbkit-base/src/par2repair/forney/joint.rs",
            "crates/nzbkit-base/src/par2repair/forney/whole.rs",
            "crates/nzbkit-base/src/gf16.rs",
        ],
        is_crossover: true,
        provenance: Provenance {
            measured_on: "i5-10600KF (Nibble, jx6) and Core Ultra 9 386H (Gfni256, jx5), \
                          12 Sep 2026, the s1off arm (NZBFAST_FORNEY_STAGE1=owned) against \
                          fast on the standard ladder, three rotated reps, an A/A at every \
                          rung: the held Hankel wins 5-22% of the repair from 5,120 to \
                          12,288 on both classes and loses only at 16,384 (-3.9% i5, -1.6% \
                          Core Ultra 9 inside its floor); \
                          research/FAST-MODE-CROSS-CLASS-ROUNDS-2026-09-12.md sections 5.2 \
                          and 5.3. NEON's own round (jx3, M1 Ultra) decides that class; \
                          AVX-512 GFNI runs the same 256-bit GFNI butterfly as Gfni256 and \
                          is NOT admitted on that likeness.",
            measured_at: "2026-09-12",
            measured_sha: "a62e5e798ff0",
            covers: &[KernelClass::Nibble, KernelClass::Gfni256],
        },
        arm: |s| {
            s.missing.map(|m| {
                if crate::par2repair::forney::seam_joint_kernel(m) {
                    "kernel"
                } else {
                    "hankel"
                }
            })
        },
    },
    Seam {
        id: "ntt-additive-leaf",
        chooses: "additive (Cantor) leaf vs paired conjugate leaf",
        rule: "leaf fill >= NZBFAST_NTT_ADDITIVE_MIN (128)",
        files: &[
            "crates/nzbkit-base/src/par2ntt/additive.rs",
            "crates/nzbkit-base/src/par2ntt/conjugate.rs",
        ],
        is_crossover: true,
        provenance: Provenance {
            measured_on: "Apple M3 Ultra + i5-10600KF, leaf_bench, 3 reps each",
            measured_at: "2026-09-09",
            measured_sha: "2f1b90742e",
            covers: &[KernelClass::Neon, KernelClass::Nibble],
        },
        arm: |s| {
            s.leaf_fill.map(|f| {
                if crate::par2ntt::seam_additive(f) {
                    "additive"
                } else {
                    "paired"
                }
            })
        },
    },
    Seam {
        id: "ntt-paired-leaf",
        chooses: "paired conjugate leaf vs dense leaf",
        rule: "on where the nibble kernels are selected (AVX2 without GFNI, NEON)",
        files: &["crates/nzbkit-base/src/par2ntt/conjugate.rs"],
        is_crossover: false,
        // A capability test, not a crossover: it asks which kernel was
        // selected, so there is no threshold to go stale. It is listed
        // because it decides which leaf the additive gate is measured
        // AGAINST, and a reader chasing that gate needs to see it.
        provenance: Provenance {
            measured_on: "",
            measured_at: "",
            measured_sha: "",
            covers: &[],
        },
        arm: |_| {
            Some(if crate::par2ntt::seam_paired() {
                "paired"
            } else {
                "dense"
            })
        },
    },
    Seam {
        id: "create-stripe-first",
        chooses: "stripe-first create (one transform pass) vs per-batch create",
        rule: "batches >= 2, mapped inputs, and the transform admits every row",
        files: &[
            "crates/nzbkit-base/src/par2gen/stripe_first.rs",
            "crates/nzbkit-base/src/par2gen.rs",
        ],
        is_crossover: true,
        provenance: Provenance {
            measured_on: "Apple M1 Ultra, 20 cores",
            measured_at: "2026-09-08",
            measured_sha: "599be1903d",
            covers: &[KernelClass::Neon],
        },
        arm: |s| {
            s.batches.map(|b| {
                if b >= 2 {
                    "stripe-first (if the transform admits)"
                } else {
                    "batch"
                }
            })
        },
    },
    Seam {
        id: "create-duplicate-collapse",
        chooses: "duplicate-source collapse vs the plain fold",
        rule: "sources <= 64 and rows <= 128",
        files: &["crates/nzbkit-base/src/par2gen/duplicates.rs"],
        is_crossover: true,
        provenance: Provenance {
            measured_on: "",
            measured_at: "",
            measured_sha: "",
            covers: &[],
        },
        arm: |s| match (s.block_size, s.rows, s.sources) {
            (Some(bs), Some(r), Some(n)) => Some(if crate::par2gen::seam_duplicates(bs, r, n) {
                "collapse"
            } else {
                "plain"
            }),
            _ => None,
        },
    },
];

/// The census as text: the kernel class, then one line per seam with the
/// arm this shape takes and where its threshold came from. Returned
/// rather than printed so a caller can log it, a test can assert on it
/// and a bench driver can stamp it into a round log.
pub fn report(shape: &Shape) -> String {
    let class = KernelClass::current();
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[seam-census] kernel class {} (multi_fold_width {})",
        class.tag(),
        crate::gf16::multi_fold_width()
    );
    for seam in SEAMS {
        let arm = (seam.arm)(shape).unwrap_or("n/a (shape does not say)");
        let p = &seam.provenance;
        let cover = if p.covers.is_empty() {
            "capability test, no threshold".to_string()
        } else if p.covers.contains(&class) {
            format!("measured on this class {} {}", p.measured_at, p.measured_on)
        } else {
            format!(
                "INHERITED - never measured on {}, value from {}",
                class.tag(),
                if p.measured_on.is_empty() {
                    "an unrecorded round"
                } else {
                    p.measured_on
                }
            )
        };
        let _ = writeln!(
            out,
            "[seam-census] {:<24} -> {:<12} [{}]",
            seam.id, arm, cover
        );
    }
    out
}

/// Print [`report`] when `NZBFAST_SEAM_CENSUS` is set. Silent otherwise,
/// and it allocates nothing when off - a bench driver can call it on
/// every leg without the call itself becoming part of what is measured.
pub fn report_if_asked(shape: &Shape) {
    if std::env::var_os("NZBFAST_SEAM_CENSUS").is_some() {
        eprint!("{}", report(shape));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The census must describe the code, so every seam's `files` must
    /// exist. A renamed module that leaves a dangling entry is exactly
    /// the rot this file exists to prevent, and "failing to find is
    /// failing" - the entry is repointed, never deleted.
    #[test]
    fn every_seam_names_files_that_exist() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root");
        for seam in SEAMS {
            assert!(!seam.files.is_empty(), "{} names no files", seam.id);
            for f in seam.files {
                assert!(root.join(f).exists(), "{}: {f} does not exist", seam.id);
            }
        }
    }

    /// Ids are the `seam-sweep.py` argument, so they must be unique and
    /// shell-safe.
    #[test]
    fn ids_are_unique_and_plain() {
        let mut seen = std::collections::BTreeSet::new();
        for seam in SEAMS {
            assert!(seen.insert(seam.id), "duplicate seam id {}", seam.id);
            assert!(
                seam.id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()),
                "{} is not a plain id",
                seam.id
            );
            assert!(
                seam.chooses.contains(" vs "),
                "{}: `chooses` must read `a vs b`",
                seam.id
            );
        }
    }

    /// The Forney rule string spells the three constants OUT, for a
    /// reader who will not open `forney.rs` - so it can go stale in
    /// silence, and it did: it still read "896 NEON / 1280 nibble / 2048
    /// generic" after the 10 Sep 2026 recalibration moved two of the
    /// three. Nothing was checking the prose against the code it
    /// describes, which is the same blindness the `arm` callbacks exist
    /// to prevent one level down.
    ///
    /// Fixing a hit here means editing the STRING (and the provenance
    /// beside it) to the value the code now carries - never the other
    /// way round, and never by deleting the numbers from the rule: they
    /// are what makes the census readable without opening the file.
    #[test]
    fn the_forney_rule_string_names_the_constants_the_code_carries() {
        use crate::par2repair::forney::{
            BACKSUB_MIN_MISSING, BACKSUB_MIN_MISSING_NEON, BACKSUB_MIN_MISSING_NIBBLE,
        };
        let seam = SEAMS
            .iter()
            .find(|s| s.id == "forney-backsub")
            .expect("seam present");
        for (want, class) in [
            (BACKSUB_MIN_MISSING_NEON, "NEON"),
            (BACKSUB_MIN_MISSING_NIBBLE, "nibble"),
            (BACKSUB_MIN_MISSING, "generic"),
        ] {
            let phrase = format!("{want} {class}");
            assert!(
                seam.rule.contains(&phrase),
                "the rule string must say `{phrase}` - it reads `{}`",
                seam.rule
            );
        }
    }

    /// **The default may only be ON for a kernel class the census says
    /// somebody MEASURED.** This is the guard that matters most on this
    /// pair of seams, and it is a rule about provenance rather than about
    /// a number: `joint_default_on` turning a class on is a claim that
    /// the class has a round behind it, and `covers` is where that claim
    /// is recorded. Widening one without the other is exactly the move
    /// this repo's bias rules exist to prevent - the 2,048 Forney gate
    /// was wrong for a year because it was applied to the one class
    /// nobody had measured it on.
    ///
    /// Fixing a hit means RUNNING THE ROUND for that class and adding it
    /// to `covers` with its own date and sha - never adding the class to
    /// `covers` because the code already turns it on.
    #[test]
    fn the_joint_default_is_only_on_for_classes_the_census_covers() {
        // `joint_gate` reads two environment switches and a process-global
        // arm, any of which would make this assert the environment rather
        // than the default.
        if std::env::var_os("NZBFAST_FORNEY_JOINT").is_some() {
            return;
        }
        let seam = SEAMS
            .iter()
            .find(|s| s.id == "joint-arm")
            .expect("seam present");
        let here = KernelClass::current();
        if crate::par2repair::forney::seam_joint_default_on() {
            assert!(
                seam.provenance.covers.contains(&here),
                "the joint arm is ON by default on the {} class, which the \
                 census does not list as measured: covers = {:?}. Run the round \
                 (research/JOINT-CROSSOVER-PER-CLASS-2026-09-11.md section 7) \
                 and add the class with its own date and sha - never the \
                 other way round.",
                here.tag(),
                seam.provenance.covers,
            );
        }
    }

    /// The same drift guard for the stage-2 gate, and it exists because
    /// the Forney one earned it: that rule string still read "896 NEON /
    /// 1280 nibble / 2048 generic" for a day after the recalibration
    /// moved two of the three, because nothing compared the prose to the
    /// code. `JOINT_FACTOR_MIN_M` is younger than that lesson and starts
    /// with the guard rather than acquiring one after its own stale day.
    ///
    /// Fix a hit by editing the STRING to the value the code now carries,
    /// never the other way round, and never by deleting the number from
    /// the rule - the number is what makes the census readable without
    /// opening the file.
    #[test]
    fn the_joint_factor_rule_string_names_the_constant_the_code_carries() {
        use crate::par2repair::forney::JOINT_FACTOR_MIN_M;
        let seam = SEAMS
            .iter()
            .find(|s| s.id == "joint-factor")
            .expect("seam present");
        let phrase = format!("JOINT_FACTOR_MIN_M ({JOINT_FACTOR_MIN_M})");
        assert!(
            seam.rule.contains(&phrase),
            "the rule string must say `{phrase}` - it reads `{}`",
            seam.rule
        );
    }

    /// And the arm must be the REAL gate, sampled AROUND it rather than
    /// at fixed numbers, so a recalibration cannot move the boundary out
    /// from between the sample points - the trap the Forney arm's own
    /// test records having fallen into on 10 Sep 2026.
    #[test]
    fn joint_factor_arm_is_the_real_gate() {
        // `factor_gate` reads NZBFAST_FORNEY_FACTOR, which forces the
        // answer in either direction and would make this test assert the
        // environment instead of the constant. Skip rather than lie.
        if std::env::var_os("NZBFAST_FORNEY_FACTOR").is_some() {
            return;
        }
        let seam = SEAMS
            .iter()
            .find(|s| s.id == "joint-factor")
            .expect("seam present");
        use crate::par2repair::forney::JOINT_FACTOR_MIN_M;
        let at = |m: usize| {
            (seam.arm)(&Shape {
                missing: Some(m),
                ..Shape::default()
            })
        };
        assert_eq!(at(JOINT_FACTOR_MIN_M), Some("factor"));
        assert_eq!(at(JOINT_FACTOR_MIN_M - 1), Some("shipped"));
        assert_eq!(
            (seam.arm)(&Shape::default()),
            None,
            "a shape with no missing count must report n/a, not guess"
        );
    }

    /// The stage-1 gate's rule string names the constant the code
    /// carries, for the reason the factor gate's does.
    #[test]
    fn the_joint_kernel_rule_string_names_the_constant_the_code_carries() {
        use crate::par2repair::forney::JOINT_KERNEL_MIN_M_X86;
        let seam = SEAMS
            .iter()
            .find(|s| s.id == "joint-kernel")
            .expect("seam present");
        let phrase = format!("JOINT_KERNEL_MIN_M_X86 ({JOINT_KERNEL_MIN_M_X86})");
        assert!(
            seam.rule.contains(&phrase),
            "the rule string must say `{phrase}` - it reads `{}`",
            seam.rule
        );
    }

    /// And its arm is the REAL gate, sampled around the constant - on a
    /// gated class the boundary is there, on an ungated class the kernel
    /// is the answer at every depth, and the seam's `covers` list is
    /// exactly the set of gated classes.
    #[test]
    fn joint_kernel_arm_is_the_real_gate_and_covers_exactly_the_gated_classes() {
        if std::env::var_os("NZBFAST_FORNEY_STAGE1").is_some() {
            return;
        }
        let seam = SEAMS
            .iter()
            .find(|s| s.id == "joint-kernel")
            .expect("seam present");
        use crate::par2repair::forney::JOINT_KERNEL_MIN_M_X86;
        let at = |m: usize| {
            (seam.arm)(&Shape {
                missing: Some(m),
                ..Shape::default()
            })
        };
        let here = KernelClass::current();
        let gated = seam.provenance.covers.contains(&here);
        assert_eq!(at(JOINT_KERNEL_MIN_M_X86), Some("kernel"));
        assert_eq!(
            at(JOINT_KERNEL_MIN_M_X86 - 1),
            Some(if gated { "hankel" } else { "kernel" }),
            "class {}: the gate applies exactly to the classes the census says it was measured on",
            here.tag()
        );
        assert_eq!((seam.arm)(&Shape::default()), None);
    }

    /// A seam that claims a measurement must say enough for a reader to
    /// find it, and one that claims none must claim none consistently.
    /// This is what stops an entry acquiring a date but no sha and
    /// reading as evidence.
    #[test]
    fn provenance_is_all_or_nothing() {
        for seam in SEAMS {
            let p = &seam.provenance;
            if p.covers.is_empty() {
                assert!(
                    p.measured_at.is_empty() && p.measured_sha.is_empty(),
                    "{}: covers nothing but carries a measurement",
                    seam.id
                );
            } else if !p.measured_sha.is_empty() {
                assert!(
                    !p.measured_at.is_empty() && !p.measured_on.is_empty(),
                    "{}: has a sha but no date or box",
                    seam.id
                );
            }
        }
    }

    /// The arms must be the REAL gates. Two checks that would fail if
    /// somebody re-implemented a threshold here: the Forney arm has to
    /// agree with the gate itself at the boundary, and it has to answer
    /// for both sides of it.
    #[test]
    fn forney_arm_is_the_real_gate() {
        let seam = SEAMS
            .iter()
            .find(|s| s.id == "forney-backsub")
            .expect("seam present");
        // Sampled AROUND THE REAL GATE rather than at fixed numbers, so
        // a recalibration cannot quietly move the boundary out from
        // between the sample points: on 10 Sep 2026 the generic
        // constant went 2,048 -> 1,280 and the fixed 2047/2048 pair
        // this used to carry stopped bracketing anything.
        let g = crate::par2repair::forney::backsub_min_missing();
        for m in [0usize, 1, g - 1, g, g + 1, 100_000] {
            let shape = Shape {
                missing: Some(m),
                ..Default::default()
            };
            let want = if crate::par2repair::forney::seam_backsub(m) {
                "forney"
            } else {
                "dense"
            };
            assert_eq!((seam.arm)(&shape), Some(want), "m={m}");
        }
    }

    /// A shape that says nothing must report `n/a` and never a default -
    /// a census that guesses is worse than one that abstains.
    #[test]
    fn an_empty_shape_reports_na_not_a_guess() {
        let text = report(&Shape::default());
        assert!(text.contains("forney-backsub"), "{text}");
        assert!(text.contains("n/a (shape does not say)"), "{text}");
        assert!(
            !text.contains("-> forney"),
            "guessed an arm from nothing: {text}"
        );
    }

    /// The class must come from the fold width and nothing else, so it
    /// cannot disagree with the kernel actually selected.
    #[test]
    fn class_follows_the_fold_width() {
        let w = crate::gf16::multi_fold_width();
        let c = KernelClass::current();
        match w {
            12 => assert_eq!(c, KernelClass::Avx512Gfni),
            8 => assert_eq!(c, KernelClass::Neon),
            6 => assert_eq!(c, KernelClass::Gfni256),
            4 => assert_eq!(c, KernelClass::Nibble),
            _ => assert_eq!(c, KernelClass::Scalar),
        }
        assert!(!c.tag().is_empty());
    }

    /// The report names the class and one line per seam, so a sweep log
    /// carries the whole selection state in a greppable block.
    #[test]
    fn report_covers_every_seam() {
        let shape = Shape {
            missing: Some(4096),
            sources: Some(16384),
            rows: Some(1024),
            block_size: Some(65536),
            leaf_fill: Some(200),
            batches: Some(4),
        };
        let text = report(&shape);
        assert!(text.contains("kernel class"), "{text}");
        for seam in SEAMS {
            assert!(
                text.contains(seam.id),
                "{} missing from the report:\n{text}",
                seam.id
            );
        }
        // A fully specified shape leaves nothing unanswered.
        assert!(
            !text.contains("n/a"),
            "a complete shape still abstained:\n{text}"
        );
    }
}
