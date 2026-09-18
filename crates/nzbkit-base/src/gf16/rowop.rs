//! The additive FFT's two row operations over GF(2^16): [`butterfly`]
//! and the in-place [`scale`], each with its per-architecture kernels,
//! their dispatch and the knobs that arm them.
//!
//! Cut out of `gf16.rs` on 15 Sep 2026, when that file stood at 3,935 of
//! the size gate's 4,000-line file ceiling. This is the seam because it
//! is a LEAF: nothing in the parent names anything here, and everything
//! here reaches down only into the parent's fold machinery
//! ([`FoldCoeff`], [`MulTable`], `clmul_reduce`, the GFNI and nibble
//! availability probes) through `use super::*`, the same way
//! `gf16/tests.rs` does - so nothing in the parent was widened to move
//! it. The public names are re-exported from `gf16`, so every caller
//! still spells them `gf16::butterfly`, `gf16::scale` and so on.

use super::*;

/// The additive FFT's butterfly over whole rows, one pass: forward
/// `(u, v) <- (u + c v, u + c v + v)`, inverse `(u, v) <- (u + c (v + u),
/// v + u)`. Processes whole 32-byte chunks and returns the u16 WORDS
/// processed; the caller runs any remainder itself (the additive leaf's
/// rows are whole chunks by admission). On Apple silicon this is the
/// fused PMULL kernel's single-source multiply with both stores in the
/// same chunk pass, so the pair's rows are read and written once where
/// a multiply pass plus an XOR pass read them twice; elsewhere it is
/// exactly those two passes.
///
/// The coefficient arrives PREPARED, because the x86 nibble arm reads
/// its tables and the additive leaf holds one [`FoldCoeff`] per (stage,
/// block) for the life of the plan: building them per butterfly would
/// pay `nibble_tables`' ~16 shifts and ~60 XORs against a span as short
/// as one 32-byte unit.
pub fn butterfly(u: &mut [u16], v: &mut [u16], c: &FoldCoeff, inverse: bool) -> usize {
    debug_assert_eq!(u.len(), v.len());
    let words = (u.len().min(v.len()) * 2 / 32) * 16;
    #[cfg(target_arch = "x86_64")]
    let coeff = c;
    let c = c.coeff();
    // The additive FFT's block 0 at every stage has twiddle s_i(0) = 0,
    // and its top inverse stage is all zeros: 511 of a 512-point
    // transform's 2,304 butterflies. Both directions collapse to
    // `v ^= u`. A twiddle of 1 is XOR-only too.
    if c == 0 {
        for (d, s) in v[..words].iter_mut().zip(u[..words].iter()) {
            *d ^= *s;
        }
        return words;
    }
    if c == 1 {
        if inverse {
            for (d, s) in v[..words].iter_mut().zip(u[..words].iter()) {
                *d ^= *s;
            }
            for (d, s) in u[..words].iter_mut().zip(v[..words].iter()) {
                *d ^= *s;
            }
        } else {
            for (d, s) in u[..words].iter_mut().zip(v[..words].iter()) {
                *d ^= *s;
            }
            for (d, s) in v[..words].iter_mut().zip(u[..words].iter()) {
                *d ^= *s;
            }
        }
        return words;
    }
    #[cfg(target_arch = "aarch64")]
    {
        // NO FEATURE DETECT, and dropping the one that stood here is a
        // win on every aarch64 part without sha3 (11 Sep 2026).
        //
        // This arm used to read `is_aarch64_feature_detected!("sha3")`,
        // so a part without it fell to `butterfly_two_pass` - a multiply
        // pass plus an XOR pass, reading and writing both rows TWICE
        // where this kernel does it once. No INTRINSIC needs sha3 here:
        // `vmull_p8`, `veorq_u8`, `vld2q_u8`/`vst2q_u8` and reinterprets,
        // and `veor3q` appears exactly once in this file, in the
        // multi-fold, whose own sha3 detect IS load-bearing.
        //
        // BUT THE INTRINSICS WERE ONLY HALF THE QUESTION, and dropping
        // the detect on that half alone shipped a SIGILL - nine tests
        // died ILL on nightly/aarch64-cross's Cortex-A72 model, 12 Sep
        // 2026. `butterfly_neon` still carried `#[target_feature(enable
        // = "neon,sha3")]`, and that attribute licenses LLVM to
        // SYNTHESIZE sha3: it fused the inlined `clmul_reduce`'s XOR
        // chains into NINE `eor3` on `aarch64-unknown-linux-musl` at opt
        // 2. A detect is not the only thing that can promise a feature -
        // the attribute promises it too, and the two have to be dropped
        // TOGETHER. It reads `enable = "neon"` now and emits no sha3.
        // NO BOX ON THIS FLEET COULD SEE IT: sha3 is BASELINE on
        // `aarch64-apple-darwin`, so Apple codegen is byte-for-byte the
        // same either way (9 `eor3` before and after).
        //
        // `scale_neon` runs the SAME `vmull_p8` on every aarch64 with no
        // detect AND no attribute, on the stated grounds that pmull on
        // poly8 is baseline - the right treatment of the pair all along.
        //
        if fused_butterfly_enabled() {
            // SAFETY: NEON incl. pmull on poly8 is baseline on aarch64,
            // so there is no feature precondition; both rows are the
            // same length, the kernel's precondition, debug_asserted
            // above.
            return unsafe { butterfly_neon(u, v, c, inverse) };
        }
    }
    #[cfg(target_arch = "x86_64")]
    if fused_butterfly_enabled() {
        if gfni256_available() && gfni_rowop_armed() {
            // SAFETY: gfni+avx2 verified by `gfni256_available`; both
            // rows are the same length, the kernel's precondition,
            // debug_asserted above.
            return unsafe { butterfly_gfni(u, v, c, inverse) };
        }
        if nibble_kernel_selected()
            && forced_nibble_kernel() != Some("ssse3")
            && is_x86_feature_detected!("avx2")
        {
            // SAFETY: avx2 verified by the detect above; the nibble
            // tables this kernel reads are populated exactly when
            // `nibble_kernel_selected` (see `FoldCoeff::new`); both rows
            // are the same length, debug_asserted above.
            return unsafe { butterfly_avx2(u, v, coeff, inverse) };
        }
    }
    butterfly_two_pass(u, v, c, inverse)
}

/// `NZBFAST_GF16_BUTTERFLY_FUSED=0`: the butterfly falls back to
/// [`butterfly_two_pass`] - a fold-kernel call for `u ^= c v` and then a
/// plain XOR pass for `v ^= u`, which reads and writes both rows twice.
/// It is the A/B arm for the fused kernels, in one binary, and it is
/// read once.
///
/// # On aarch64 as well since 11 Sep 2026, and not for symmetry
///
/// Dropping the sha3 detect above - and, on 12 Sep 2026, the sha3 in the
/// kernel's `#[target_feature]`, which is the half that was NOT vestigial
/// and cost a SIGILL; see the note there - gave every
/// non-sha3 aarch64 part the fused kernel in place of
/// [`butterfly_two_pass`], and NO BOX ON THIS FLEET IS NON-SHA3 - the
/// Apple parts and the Snapdragon all report it - so the change could
/// not be measured on the hardware it is for. This knob is what makes
/// it measurable anyway: the two ARMS are the same two implementations
/// whichever CPU selects them, so A/B-ing them on a box that has sha3
/// measures the change itself. Only the magnitude is the measuring
/// box's; the sign is the memory traffic's, and that is the claim.
fn fused_butterfly_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| !std::env::var_os("NZBFAST_GF16_BUTTERFLY_FUSED").is_some_and(|v| v == "0"))
}

/// `NZBFAST_GF16_ROWOP_GFNI=0` disarms [`butterfly_gfni`]. **ON by
/// default since 11 Sep 2026**, on the evidence below; it was off for
/// four days before that, and the history is kept because the reason it
/// was off is the reason to trust the measurement that turned it on.
///
/// **THE SPELLING INVERTED WHEN THE DEFAULT DID, AND AN A/B HARNESS
/// WRITTEN BEFORE THAT WILL SILENTLY MEASURE ON AGAINST ON.** It was
/// `=1` to arm, so a round's "unarmed" arm was the variable UNSET or set
/// to empty. Both of those now mean ARMED. The off arm is `=0` and
/// nothing else. Check any harness older than 11 Sep 2026 before
/// believing a flat result from it.
///
/// **This gate decides the BUTTERFLY alone.** `scale` stopped waiting on
/// it earlier the same day (see [`scale_kernel`]), and
/// [`inplace_scale_preferred`] stopped on the flip, so `=0` turns off
/// the fused butterfly and nothing else. A reader who remembers this
/// gate deciding three things is remembering a tree older than
/// `9d91798cec`.
///
/// The history, kept because it is why the flip is trustworthy:
/// **it was OFF, and that was not caution for its own sake.** Until 11 Sep 2026 the reason was that neither had ever
/// executed: no box on this fleet was known to have GFNI while the
/// Core Ultra 9 box was down, and a GitHub x86-64 runner has it only
/// by luck of the draw (the fleet mixes Zen 3 without and Ice Lake with,
/// which is how `forney::joint`'s kernel assertions flapped on 10 Sep).
/// Their multiply core is [`xor_mul_multi_gfni_n`] with one source,
/// transcribed, and their XOR ordering is the same as
/// [`butterfly_avx2`] and [`butterfly_neon`], both differential-
/// tested on real hardware - so they were very likely right. "Very
/// likely right" is what this file's own worst defect was: the 512-bit
/// GFNI arm's 64-byte granule (`69cbf2e2`), wrong on exactly the parts
/// no local box selects, and PAR2 parity computed with a wrong butterfly
/// is silent until someone needs to repair with it.
///
/// A GFNI part with this unset takes [`butterfly_two_pass`] - what it
/// took before the fused kernels landed, so nothing regresses.
///
/// **THE KERNELS HAVE NOW EXECUTED, AND THEY ARE NOT WHAT BLOCKS THE
/// FLIP** (11 Sep 2026, `research/GFNI-ROWOP-EVIDENCE-2026-09-11.md`).
/// The leaf differential and this file's butterfly and scale tests are
/// green with this set, on an EPYC 9354P (Zen 4, avx512f+avx512bw+gfni)
/// and a Core Ultra 9 386H (gfni+avx2), each against an unarmed control,
/// and `perf` names [`butterfly_gfni`] and [`scale_gfni`] in the armed
/// profile and neither in the control's.
///
/// **What blocked it was a second consumer, and that is now FIXED.**
/// Setting this USED TO MAKE [`scale_available`] true, which was the
/// only thing refusing `par2repair::forney::joint` on a GFNI part (it no
/// longer decides that - see below) - so arming it
/// opened a path that had never run on one. That path's tail fold asks
/// [`xor_mul_multi_prepared`] for a 32-byte destination (`joint` pads a
/// short last stripe to a multiple of 16 WORDS, because 32 bytes is the
/// unit every OTHER kernel takes), and [`xor_mul_multi_gfni512`]
/// declines exactly that, because it consumes 64 bytes at a time.
/// `forney::tail`'s full-coverage assert fired and the repair panicked
/// from a scoped worker - `69cbf2e2`'s granule class a second time, in a
/// second place, on AVX-512 GFNI parts only, and loud rather than
/// silent: an `assert_eq!`, so it fired in release and wrote no parity.
/// `Plan::finish_row_stripe` now runs the remainder per source the way
/// every other caller of the fused fold already did, and carries a
/// regression test that is PORTABLE by construction - an 8-word stripe
/// is 16 bytes, under every kernel's granule, so it fails on aarch64 and
/// on a part with no GFNI at all, and this class no longer needs the one
/// box in the fleet that can select the 64-byte kernel to be caught.
///
/// **So the recipe this gate used to give was necessary and not
/// sufficient.** Before flipping the default, all three of:
/// 1. those four differentials, armed and with an unarmed control;
/// 2. `cargo test -p nzbkit-base --lib --features test-support` IN ONE
///    PROCESS, armed, green - the step that found the blocker, and one
///    no filter naming the four tests can reach;
/// 3. both on a host where [`avx512_gfni_available`] is TRUE, because
///    the dispatch this flip opens differs between the two GFNI classes
///    and only one of them was broken.
///
/// **All three are green on the EPYC as of 11 Sep 2026, and the default
/// is STILL OFF, because what is missing now is not correctness but a
/// MEASUREMENT.** Nobody has shown arming the BUTTERFLY is faster on an
/// AVX-512 part, and it is not obvious that it is: unarmed, the
/// butterfly there folds through a 64-byte-wide kernel, and armed it is
/// a fused 256-bit one, so arming moves work OFF the wider kernel -
/// `perf` read 79 sample units on [`xor_mul_multi_gfni512`] unarmed
/// against 56 armed.
///
/// **The one whole-repair reading that argued AGAINST the flip should be
/// discounted entirely, not read as weak evidence** (11 Sep 2026). It is
/// one rep on a Core Ultra 9, 10 Sep, 147.7 s armed against 134.6 s
/// unarmed. `OLED Care Screensaver.scr` was running on that box from
/// 2026-09-07T20:02:35Z and had taken 46,746 CPU seconds by 03:24Z on
/// 11 Sep, so the 10 Sep rep is inside that window. It is BURSTY - about
/// fifteen of sixteen cores when it wakes and nothing when it does not -
/// which is why this matters more than a noise figure would: the rep is
/// not a noisy reading of a real quantity, it is a coin flip on whether
/// the screensaver was awake, and the box was not in a known state. Two
/// rounds queued behind it aborted with
/// `BOX-BUSY foreign_cpu=1564.1 ceiling=160 cores=16`. It is stopped and
/// disabled now. This docstring hedged that rep correctly at the time
/// ("inside that box's noise and is not an answer either"); nothing here
/// is a retraction, but the hedge is now the whole of it.
///
/// **The SECOND consumer is gone, and that changes what this gate is
/// for.** Until 11 Sep 2026 this also decided [`scale_kernel`], and
/// through it `scale_available`, and through THAT whether
/// `par2repair::forney::joint` would run stage 1 at all - so a GFNI part
/// with this unset had `parfast --fast` silently do nothing (TODO 340).
/// `scale` has no wider competitor to be moved off, so it no longer
/// waits here: see [`scale_kernel`], and
/// `research/FAST-MODE-X86-GFNI-2026-09-11.md` for the round that
/// settled it. What is left under this gate is the BUTTERFLY alone,
/// which is the only place the trade above is real.
///
/// A GFNI part with this unset therefore takes [`butterfly_two_pass`],
/// which is what it took before the fused kernels landed, so nothing
/// regresses - and it now does so with joint stage 1 running.
///
/// The same EPYC round measured the flip as well, as its `armed` arm
/// against a decoupled `--fast`: 4.70 s against 5.03 at m = 16,384,
/// 6.66 against 6.82 at 24,576, 7.28 against 8.01 at 30,000, medians of
/// three. That is a further 3 to 9% and it points the SAME way at every
/// depth, which is the first evidence in favour this gate has ever had -
/// but it is one shared VM that has been withdrawn from quotation, and
/// a default flip wants a quotable box. Flip it on a measurement, not on
/// a green suite.
///
/// **THE BUTTERFLY TRADE IS NOW MEASURED, ON A QUOTABLE BOX, AND IT
/// FAVOURS ARMING** (11 Sep 2026, claim `rowop-flip-zen5-ab-11sep`,
/// `research/GFNI-ROWOP-EVIDENCE-2026-09-11.md` section 12). The round
/// above is a shared VM withdrawn from quotation; this one is a matched
/// PAIR of idle Ryzen 7 9800X3D desktops (Zen 5, the same AVX-512 GFNI
/// class), so every figure is two independent boxes agreeing rather than
/// one box repeated. `par2ntt::additive`'s own `phase_split` rig
/// isolates the butterfly from everything else, and on both boxes
/// [`butterfly_gfni`] runs the forward transform in 0.038 ms against
/// [`butterfly_two_pass`]'s 0.052-0.053 and the inverse in 0.040
/// against 0.054-0.055. **So the wider fold kernel loses the trade this
/// gate was opened for: about -27% on the butterflies, not a
/// regression.**
///
/// **Read that round's whole-repair figures with care - they PREDATE
/// `scale` leaving this gate** (they were taken on `4c97bd6000`), so
/// their -8.5%/-7.7% on `ntt syndromes` and -2.0%/-2.3% on wall carry
/// the in-place scale AND the butterfly together. Decomposed by the same
/// rig, the butterfly is 0.030 ms of the 0.041 ms total and the scale
/// 0.011, i.e. about 73/27 - so roughly a quarter of that round's win is
/// already banked by the decoupling above and needs no flip, and what
/// this gate still decides is the other three quarters.
///
/// One condition on all of it, and it is not this gate's: `par2ntt`'s
/// additive leaf is only admitted at a leaf fill of 128 sources or more,
/// and below that these kernels are never called at all - so arming can
/// buy nothing there, which the PLANNER says (`leaf_fill` reports
/// `additive 0` before a stripe is transformed) rather than a stopwatch.
/// That round's first attempt spent 40 reps a side discovering it the
/// slow way. **Any A/B of this gate MUST report
/// `par2ntt::FlatPlan::leaf_fill` (`NZBFAST_NTT_FILL=1`) beside its
/// timings**, or it cannot tell "ran and bought nothing" from "never
/// ran" - the trap round BL hit on 7 Sep 2026 and this one nearly
/// repeated.
///
/// **When that gate is cleared is CLOSED FORM, not a survey question.**
/// Base logs are coprime to 65535 = 3*5*17*257, so exactly 2*4*16 = 128
/// of the 255 leaves are live and fill is `present slices in the WINDOW
/// / 128` (+-1). The gate is therefore cleared at **16,384 present
/// slices in one retention window**, and the window is bounded in BYTES
/// (`min(present, budget / block_size)`), so a large block size starves
/// the fill however big the set is. Checked against real PAR2 constant
/// sequences at 2,048 / 8,192 / 16,384 / 16,512 / 29,696 present, giving
/// fills 16 / 64 / 128 / 129 / 232, and it predicts the Zen 5 round's
/// two fixtures exactly (8,192 present -> fill 64, refused; 28,672 ->
/// 224, admitted). So whether this flip is worth anything to a given
/// user is computed, not guessed.
///
/// **FLIPPED ON 11 Sep 2026, on the evidence above.** What
/// changed on a GFNI part: [`butterfly`] takes [`butterfly_gfni`]
/// instead of [`butterfly_two_pass`] (~27% on the forward and inverse
/// transforms), and [`inplace_scale_preferred`] stopped answering no,
/// so `par2ntt`'s additive leaf scales in place instead of folding
/// through a zeroed temporary (~58%). Both of those were measured on the
/// Zen 5 pair and neither was measured slower anywhere. Nothing off a
/// GFNI part changes at all.
///
/// **And since `9856e25f19` a bare `parfast r` is the JOINT arm on an
/// AVX-512 GFNI part, so an A/B of this gate that means "the shipped
/// solve" must set `NZBFAST_FORNEY_JOINT=0` explicitly or it races the
/// on arm against itself.** The doors, checked in both directions
/// (`=0`, `=off` and `=shipped` all take the shipped solve, and `--fast`
/// overrides an explicit env off in that direction only), are
/// `research/JOINT-DEFAULT-FLIP-ALREADY-LANDED-2026-09-11.md` section 3. The Zen 5 round above predates that commit
/// and is not affected (checked both by ancestry and by every one of its
/// 120 legs carrying a `back-substitution (forney)` line, which only the
/// shipped path emits); a repeat on current `main` does not have that
/// luxury.
///
/// Read once.
#[cfg(target_arch = "x86_64")]
fn gfni_rowop_armed() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| !std::env::var_os("NZBFAST_GF16_ROWOP_GFNI").is_some_and(|v| v == "0"))
}

/// The portable butterfly: the fold kernel for the multiply, a plain
/// pass for the XOR.
fn butterfly_two_pass(u: &mut [u16], v: &mut [u16], c: u16, inverse: bool) -> usize {
    let words = (u.len() * 2 / 32) * 16;
    let (u, v) = (&mut u[..words], &mut v[..words]);
    if inverse {
        for (d, s) in v.iter_mut().zip(u.iter()) {
            *d ^= *s;
        }
    }
    // SAFETY: `v[..words]` is a live, initialised u16 slice of exactly
    // `words` elements, so the same memory read as `words * 2` bytes is in
    // bounds and initialised; the fold kernel only reads it, and `u` is a
    // different slice, so no aliasing with the write.
    let vb = unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, words * 2) };
    let done = xor_mul_multi_into(u, &[vb], &[c]);
    // `words` is sized to the 32-BYTE unit that every kernel here consumes
    // except one: the 512-bit GFNI arm takes 64 bytes at a time and returns
    // 0 for anything shorter. A span of 32 to 63 bytes therefore left this
    // function having done no multiply at all while still reporting `words`
    // - and the caller has no remainder path, `par2ntt::additive` asserts
    // this covered the WHOLE span - so on an AVX-512 GFNI part the fold was
    // silently skipped in release and only the debug assertion that used to
    // stand here caught it. That is what took unit-one-process red on
    // 69cbf2e2 (run 34085236302, left 0 right 16); the job's own three
    // shapes did not include this one, because it is not a process
    // question at all - a runner WITH that instruction set fails where a
    // runner without it passes.
    //
    // Finish whatever the multi kernel declined. `MulTable::xor_mul_into`
    // covers any length, tail included, so the span is always complete
    // after this and the returned `words` is true by construction. On every
    // other kernel `done == words` and this is not entered.
    if done < words {
        MulTable::new(c).xor_mul_into(&mut u[done..], &vb[done * 2..]);
    }
    if !inverse {
        for (d, s) in v.iter_mut().zip(u.iter()) {
            *d ^= *s;
        }
    }
    words
}

/// [`butterfly`] on every aarch64 part: the single-source arm of
/// [`xor_mul_multi_fused`] with the pair's second row updated in the
/// same chunk pass.
///
/// **The attribute enables `neon` and NOTHING ELSE: a feature added back
/// to it is a SIGILL on every part without that feature, whatever the
/// intrinsics say** - see the note at the dispatch site in [`butterfly`].
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn butterfly_neon(u: &mut [u16], v: &mut [u16], c: u16, inverse: bool) -> usize {
    use std::arch::aarch64::*;
    let chunks = (u.len().min(v.len()) * 2) / 32;
    if chunks == 0 {
        return 0;
    }
    // SAFETY: NEON incl. pmull on poly8 is baseline on aarch64 and this
    // kernel asks for nothing beyond it, so there is no feature
    // precondition; every access stays within the first chunks * 32 bytes
    // of each row, in bounds by construction of `chunks` from the shorter
    // row.
    unsafe {
        let c_lo = vdupq_n_p8(c as u8);
        let c_hi = vdupq_n_p8((c >> 8) as u8);
        let c_mid = vreinterpretq_p8_u8(veorq_u8(
            vreinterpretq_u8_p8(c_lo),
            vreinterpretq_u8_p8(c_hi),
        ));
        let pml = |d: poly8x16_t, c: poly8x16_t| -> poly16x8_t {
            vmull_p8(vget_low_p8(d), vget_low_p8(c))
        };
        let pmh = |d: poly8x16_t, c: poly8x16_t| -> poly16x8_t { vmull_high_p8(d, c) };
        let ub = u.as_mut_ptr() as *mut u8;
        let vb = v.as_mut_ptr() as *mut u8;
        for ch in 0..chunks {
            let off = ch * 32;
            let mut du = vld2q_u8(ub.add(off));
            let mut dv = vld2q_u8(vb.add(off));
            if inverse {
                // v <- v + u first; the multiply reads the new v.
                dv.0 = veorq_u8(dv.0, du.0);
                dv.1 = veorq_u8(dv.1, du.1);
            }
            let dlo = vreinterpretq_p8_u8(dv.0);
            let dhi = vreinterpretq_p8_u8(dv.1);
            let dmid = vreinterpretq_p8_u8(veorq_u8(dv.0, dv.1));
            let (out_lo, out_hi) = clmul_reduce(
                pml(dlo, c_lo),
                pmh(dlo, c_lo),
                pml(dmid, c_mid),
                pmh(dmid, c_mid),
                pml(dhi, c_hi),
                pmh(dhi, c_hi),
            );
            du.0 = veorq_u8(du.0, out_lo);
            du.1 = veorq_u8(du.1, out_hi);
            if !inverse {
                dv.0 = veorq_u8(dv.0, du.0);
                dv.1 = veorq_u8(dv.1, du.1);
            }
            vst2q_u8(ub.add(off), du);
            vst2q_u8(vb.add(off), dv);
        }
    }
    chunks * 16
}

/// [`butterfly`] on an x86 part WITHOUT GFNI: [`xor_mul_multi_avx2_n`]'s
/// single-source nibble-shuffle body with the pair's second row updated
/// in the same chunk pass. The two-pass form reads and writes `u` twice
/// and `v` twice; this reads each once and writes each once, which is
/// what the i5's 256 KB L2 pays for at the additive leaf's 512-row
/// working set. Whole 32-byte units, u16 WORDS returned.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn butterfly_avx2(u: &mut [u16], v: &mut [u16], c: &FoldCoeff, inverse: bool) -> usize {
    use std::arch::x86_64::*;
    let units = (u.len().min(v.len()) * 2) / 32;
    if units == 0 {
        return 0;
    }
    // Whole 64-byte chunks through the 256-bit body, then - when `units`
    // is odd - one 32-byte unit at half width, exactly as
    // `xor_mul_multi_avx2_n` splits it.
    let chunks = units / 2;
    // SAFETY: avx2 is enabled here per #[target_feature] (runtime-
    // verified at the dispatch site). Every access stays within the
    // first `units * 32` bytes of each row, in bounds by construction of
    // `units` from the shorter row.
    unsafe {
        let bc = |t: &[u8; 16]| {
            _mm256_broadcastsi128_si256(_mm_loadu_si128(t.as_ptr() as *const __m128i))
        };
        let tl: [__m256i; 4] = std::array::from_fn(|j| bc(&c.nl[j]));
        let th: [__m256i; 4] = std::array::from_fn(|j| bc(&c.nh[j]));
        let nib = _mm256_set1_epi8(0x0f);
        let lo8 = _mm256_set1_epi16(0x00ff);
        // c * (d0, d1), the 64-byte product in the source's own byte
        // order: `xor_mul_multi_avx2_n`'s body with one source and the
        // destination XOR left to the caller.
        let prod = |d0: __m256i, d1: __m256i| -> (__m256i, __m256i) {
            let slo = _mm256_packus_epi16(_mm256_and_si256(d0, lo8), _mm256_and_si256(d1, lo8));
            let shi = _mm256_packus_epi16(_mm256_srli_epi16(d0, 8), _mm256_srli_epi16(d1, 8));
            let n0 = _mm256_and_si256(slo, nib);
            let n1 = _mm256_and_si256(_mm256_srli_epi16(slo, 4), nib);
            let n2 = _mm256_and_si256(shi, nib);
            let n3 = _mm256_and_si256(_mm256_srli_epi16(shi, 4), nib);
            let plo = _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_shuffle_epi8(tl[0], n0),
                    _mm256_shuffle_epi8(tl[1], n1),
                ),
                _mm256_xor_si256(
                    _mm256_shuffle_epi8(tl[2], n2),
                    _mm256_shuffle_epi8(tl[3], n3),
                ),
            );
            let phi = _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_shuffle_epi8(th[0], n0),
                    _mm256_shuffle_epi8(th[1], n1),
                ),
                _mm256_xor_si256(
                    _mm256_shuffle_epi8(th[2], n2),
                    _mm256_shuffle_epi8(th[3], n3),
                ),
            );
            (
                _mm256_unpacklo_epi8(plo, phi),
                _mm256_unpackhi_epi8(plo, phi),
            )
        };
        let ub = u.as_mut_ptr() as *mut u8;
        let vb = v.as_mut_ptr() as *mut u8;
        for ch in 0..chunks {
            let off = ch * 64;
            let up = ub.add(off) as *mut __m256i;
            let vp = vb.add(off) as *mut __m256i;
            let mut u0 = _mm256_loadu_si256(up);
            let mut u1 = _mm256_loadu_si256(up.add(1));
            let mut v0 = _mm256_loadu_si256(vp);
            let mut v1 = _mm256_loadu_si256(vp.add(1));
            if inverse {
                // v <- v + u first; the multiply reads the new v.
                v0 = _mm256_xor_si256(v0, u0);
                v1 = _mm256_xor_si256(v1, u1);
            }
            let (p0, p1) = prod(v0, v1);
            u0 = _mm256_xor_si256(u0, p0);
            u1 = _mm256_xor_si256(u1, p1);
            if !inverse {
                v0 = _mm256_xor_si256(v0, u0);
                v1 = _mm256_xor_si256(v1, u1);
            }
            _mm256_storeu_si256(up, u0);
            _mm256_storeu_si256(up.add(1), u1);
            _mm256_storeu_si256(vp, v0);
            _mm256_storeu_si256(vp.add(1), v1);
        }
        if !units.is_multiple_of(2) {
            // The odd 32-byte unit in 128-bit lanes: identical algebra,
            // because `packus`/`unpack` are per-128-bit-lane in the wide
            // body and `bc` built each table by broadcasting its 128-bit
            // form, so the low lane IS the table.
            let off = chunks * 64;
            let nib128 = _mm_set1_epi8(0x0f);
            let lo8_128 = _mm_set1_epi16(0x00ff);
            let lane = _mm256_castsi256_si128;
            let prod128 = |d0: __m128i, d1: __m128i| -> (__m128i, __m128i) {
                let slo = _mm_packus_epi16(_mm_and_si128(d0, lo8_128), _mm_and_si128(d1, lo8_128));
                let shi = _mm_packus_epi16(_mm_srli_epi16(d0, 8), _mm_srli_epi16(d1, 8));
                let n0 = _mm_and_si128(slo, nib128);
                let n1 = _mm_and_si128(_mm_srli_epi16(slo, 4), nib128);
                let n2 = _mm_and_si128(shi, nib128);
                let n3 = _mm_and_si128(_mm_srli_epi16(shi, 4), nib128);
                let plo = _mm_xor_si128(
                    _mm_xor_si128(
                        _mm_shuffle_epi8(lane(tl[0]), n0),
                        _mm_shuffle_epi8(lane(tl[1]), n1),
                    ),
                    _mm_xor_si128(
                        _mm_shuffle_epi8(lane(tl[2]), n2),
                        _mm_shuffle_epi8(lane(tl[3]), n3),
                    ),
                );
                let phi = _mm_xor_si128(
                    _mm_xor_si128(
                        _mm_shuffle_epi8(lane(th[0]), n0),
                        _mm_shuffle_epi8(lane(th[1]), n1),
                    ),
                    _mm_xor_si128(
                        _mm_shuffle_epi8(lane(th[2]), n2),
                        _mm_shuffle_epi8(lane(th[3]), n3),
                    ),
                );
                (_mm_unpacklo_epi8(plo, phi), _mm_unpackhi_epi8(plo, phi))
            };
            let up = ub.add(off) as *mut __m128i;
            let vp = vb.add(off) as *mut __m128i;
            let mut u0 = _mm_loadu_si128(up);
            let mut u1 = _mm_loadu_si128(up.add(1));
            let mut v0 = _mm_loadu_si128(vp);
            let mut v1 = _mm_loadu_si128(vp.add(1));
            if inverse {
                v0 = _mm_xor_si128(v0, u0);
                v1 = _mm_xor_si128(v1, u1);
            }
            let (p0, p1) = prod128(v0, v1);
            u0 = _mm_xor_si128(u0, p0);
            u1 = _mm_xor_si128(u1, p1);
            if !inverse {
                v0 = _mm_xor_si128(v0, u0);
                v1 = _mm_xor_si128(v1, u1);
            }
            _mm_storeu_si128(up, u0);
            _mm_storeu_si128(up.add(1), u1);
            _mm_storeu_si128(vp, v0);
            _mm_storeu_si128(vp.add(1), v1);
        }
    }
    units * 16
}

/// [`butterfly`] on a GFNI part: [`xor_mul_multi_gfni_n`]'s affine2x
/// body with one source and the pair's second row updated in the same
/// 32-byte chunk pass. UNMEASURED on this fleet - no box here has GFNI
/// (the Core Ultra 9 box is down) - so it is written to the same shape
/// as the AVX2 arm above and covered by the same differential, and the
/// leaf's x86 numbers in the handoff are the i5's nibble arm.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx2")]
unsafe fn butterfly_gfni(u: &mut [u16], v: &mut [u16], c: u16, inverse: bool) -> usize {
    use std::arch::x86_64::*;
    let chunks = (u.len().min(v.len()) * 2) / 32;
    if chunks == 0 {
        return 0;
    }
    // SAFETY: gfni+avx2 are enabled here per #[target_feature] (runtime-
    // verified at the dispatch site). Every access stays within the first
    // `chunks * 32` bytes of each row, in bounds by construction of
    // `chunks` from the shorter row.
    unsafe {
        let m = affine_matrices_fast(c);
        let mat_n = _mm256_set_epi64x(m[3] as i64, m[0] as i64, m[3] as i64, m[0] as i64);
        let mat_s = _mm256_set_epi64x(m[1] as i64, m[2] as i64, m[1] as i64, m[2] as i64);
        let deint = _mm256_broadcastsi128_si256(_mm_setr_epi8(
            0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15,
        ));
        let inter = _mm256_broadcastsi128_si256(_mm_setr_epi8(
            0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15,
        ));
        let ub = u.as_mut_ptr() as *mut u8;
        let vb = v.as_mut_ptr() as *mut u8;
        for ch in 0..chunks {
            let off = ch * 32;
            let up = ub.add(off) as *mut __m256i;
            let vp = vb.add(off) as *mut __m256i;
            let mut uu = _mm256_loadu_si256(up);
            let mut vv = _mm256_loadu_si256(vp);
            if inverse {
                vv = _mm256_xor_si256(vv, uu);
            }
            let data = _mm256_shuffle_epi8(vv, deint);
            let acc_n = _mm256_gf2p8affine_epi64_epi8::<0>(data, mat_n);
            let acc_s = _mm256_gf2p8affine_epi64_epi8::<0>(data, mat_s);
            // 0x4E = _MM_SHUFFLE(1,0,3,2): swap the qwords of each lane,
            // bringing the cross-half contributions home.
            let res = _mm256_xor_si256(acc_n, _mm256_shuffle_epi32::<0x4E>(acc_s));
            uu = _mm256_xor_si256(uu, _mm256_shuffle_epi8(res, inter));
            if !inverse {
                vv = _mm256_xor_si256(vv, uu);
            }
            _mm256_storeu_si256(up, uu);
            _mm256_storeu_si256(vp, vv);
        }
    }
    chunks * 16
}

/// `row <- c * row`, in place, over whole 32-byte units; returns the u16
/// WORDS processed, the caller running any remainder itself.
///
/// The fold kernels all compute `dst ^= c * src` against a SEPARATE
/// source, so a caller that wants a row scaled by itself has to zero a
/// temporary, fold into it and copy back - three passes over the row and
/// a second row's worth of cache, for one pass of arithmetic. The
/// additive leaf's pointwise step does exactly that 512 times per leaf,
/// which is why this exists.
pub fn scale(row: &mut [u16], c: &FoldCoeff) -> usize {
    let words = (row.len() * 2 / 32) * 16;
    if c.coeff() == 1 {
        return words;
    }
    if c.coeff() == 0 {
        row[..words].fill(0);
        return words;
    }
    scale_dispatch(row, c)
}

/// Which kernel [`scale`] selects on this build and CPU.
///
/// ONE copy of the rule, for the reason the gate suite states as "one
/// rule, one copy": `scale_dispatch` dispatches on it,
/// [`scale_available`] asks whether it is a vector arm, and a CLI that
/// has to TELL the user why a fast path declined names it. Three
/// transcriptions of the same predicate is how a diagnostic ends up
/// naming the arm the solve did not take.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScaleKernel {
    /// `scale_neon`: the PMULL kernel, baseline on aarch64.
    Neon,
    /// `scale_gfni`: 256-bit GFNI, behind `gfni_rowop_armed`.
    Gfni256,
    /// `scale_avx2`: the AVX2 nibble-shuffle kernel.
    Avx2Nibble,
    /// `scale_ssse3`: the same nibble kernel at 128 bits, for an x86
    /// part with `pshufb` and no AVX2.
    Ssse3Nibble,
    /// `scale_scalar`: a 512-entry [`MulTable`] per call, and NOT a
    /// vector arm - [`scale_available`] answers no here.
    Scalar,
}

impl ScaleKernel {
    /// The short name a diagnostic prints.
    pub fn name(self) -> &'static str {
        match self {
            ScaleKernel::Neon => "neon",
            ScaleKernel::Gfni256 => "gfni256",
            ScaleKernel::Avx2Nibble => "avx2-nibble",
            ScaleKernel::Ssse3Nibble => "ssse3-nibble",
            ScaleKernel::Scalar => "scalar",
        }
    }

    /// What would give this CPU a vector [`scale`], in the user's
    /// terms - `None` once it has one.
    ///
    /// Only [`ScaleKernel::Scalar`] has an answer, and on x86 there are
    /// two quite different ones: a GFNI part HAS the kernel and ships
    /// with it disarmed, while an SSSE3-only part does not have one at
    /// all. Saying "unsupported CPU" to the first would be false.
    pub fn remedy(self) -> Option<&'static str> {
        if self != ScaleKernel::Scalar {
            return None;
        }
        // THREE different answers, and "unsupported CPU" is right for
        // only one of them. Collapsing them is the misdiagnosis TODO 340
        // is about. There were four until `scale` stopped waiting on the
        // row-op gate: a GFNI part cannot reach this function any more,
        // because `scale_kernel` never answers `Scalar` there.
        #[cfg(target_arch = "x86_64")]
        {
            // The research knob, not the silicon. `a4237f96bb` wrote
            // AVX2 and GFNI scale/butterfly kernels and no SSSE3 one,
            // so forcing ssse3 refuses a kernel this CPU HAS - which is
            // a very different sentence from not having one.
            Some("this CPU has no SSSE3, AVX2 or GFNI row kernel")
        }
        #[cfg(target_arch = "aarch64")]
        {
            // Unreachable: `scale_kernel` never answers `Scalar` here.
            // Kept rather than `unreachable!` because a diagnostic must
            // not be the thing that panics a repair.
            None
        }
        // armv7 is the shipped case: the 32-bit ARM tarball has no
        // vector fold AT ALL (`xor_mul_multi_into` returns 0 there), so
        // this is the BUILD's target and not the chip in the machine,
        // and telling a Raspberry Pi owner their CPU is unsupported
        // would be false - the 64-bit build on the same board runs it.
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            Some(
                "this build's target architecture has no vector row kernel; \
                 --fast needs an x86-64 or 64-bit ARM build",
            )
        }
    }
}

/// The kernel [`scale`] would run here. Read by [`scale_dispatch`],
/// [`scale_available`] and by diagnostics; nothing else re-derives it.
pub fn scale_kernel() -> ScaleKernel {
    #[cfg(target_arch = "aarch64")]
    {
        ScaleKernel::Neon
    }
    #[cfg(target_arch = "x86_64")]
    {
        // NOT `gfni_rowop_armed()`, and that asymmetry with `butterfly`
        // is the whole of TODO 340's second half.
        //
        // The gate exists because arming the BUTTERFLY moves work off a
        // wider fold kernel - 64 bytes at a time on an AVX-512 part -
        // onto a fused 256-bit one, which is a trade nobody had
        // measured. `scale` has no such competitor. Unarmed, this
        // dispatch lands on `scale_scalar`, a 512-entry table built per
        // row, so `scale_available` answers no and its two callers take
        // a THIRD path instead: `par2ntt`'s additive leaf folds through
        // a zeroed temporary, and `par2repair::forney::joint` declines
        // stage 1 outright. The second of those is `parfast --fast`
        // silently doing nothing on every GFNI part - Arrow Lake, Zen 4,
        // anything recent - which is the defect TODO 340 opened.
        //
        // Measured 11 Sep 2026 on an EPYC 9354P (Zen 4, the AVX-512
        // GFNI class, where the butterfly trade is at its WORST): the
        // joint stage-1 kernel beat the fallback arithmetic on 12 of 12
        // paired legs, at every depth and every repetition, and the
        // whole-repair gain tracks the solve's share of the repair -
        // nothing at m = 8,192, 10% at 16,384, 12 to 18% at 30,000.
        // `research/FAST-MODE-X86-GFNI-2026-09-11.md` carries the round
        // and its stated limits. The kernels themselves were proved on
        // both GFNI classes on 11 Sep
        // (`research/GFNI-ROWOP-EVIDENCE-2026-09-11.md`); what was
        // missing was never their correctness.
        if gfni256_available() {
            ScaleKernel::Gfni256
        } else if nibble_kernel_selected()
            && forced_nibble_kernel() != Some("ssse3")
            && is_x86_feature_detected!("avx2")
        {
            ScaleKernel::Avx2Nibble
        } else if nibble_kernel_selected() && is_x86_feature_detected!("ssse3") {
            // THE `!= Some("ssse3")` GUARD ABOVE IS NOW THE ONLY THING
            // THAT ARM NEEDS, and this one no longer carries it. Until
            // 11 Sep 2026 that guard appeared on BOTH arms, and on the
            // second it was not a choice between kernels: `a4237f96bb`
            // wrote AVX2 and GFNI scale kernels and no SSSE3 one, so
            // the guard was marking an ABSENCE. `scale_ssse3` fills it,
            // so the absence is gone and the guard with it - a forced
            // ssse3 arm now gets the ssse3 kernel, which is what the
            // knob always claimed to do.
            ScaleKernel::Ssse3Nibble
        } else {
            ScaleKernel::Scalar
        }
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        ScaleKernel::Scalar
    }
}

/// Whether [`scale`] has a VECTOR kernel on this build and CPU. False on
/// any x86 that lands on the SSSE3-less scalar arm, and on nothing else:
/// a GFNI part answers YES since 11 Sep 2026, whatever
/// `gfni_rowop_armed` says - see [`scale_kernel`].
///
/// **This answers EXISTENCE, not preference.** A caller choosing between
/// the in-place form and folding through a zeroed temporary wants
/// [`inplace_scale_preferred`] instead; the two differ on exactly one
/// part, and conflating them is what made this function's answer
/// load-bearing for two questions with different evidence behind them.
pub fn scale_available() -> bool {
    scale_kernel() != ScaleKernel::Scalar
}

/// Whether a caller with a CHOICE should scale in place rather than fold
/// through a zeroed temporary.
///
/// Not the same question as [`scale_available`], and the split is the
/// whole of why this change could land while four publication rounds
/// were in flight.
///
/// `par2repair::forney`'s joint arm has no choice: it scales in place or
/// it declines stage 1 outright, and it is reached only when a user asks
/// for it with `parfast --fast`. `par2ntt`'s additive leaf DOES have a
/// choice - it folded through a temporary before `scale` existed and can
/// still do that - and it is on EVERY create and repair, gated by no
/// switch at all. Same kernel, two callers, and the evidence needed to
/// move them is not the same size.
///
/// It held an x86 arm answering NO on a GFNI part, so that the leaf kept
/// folding through a temporary until its own arm had been measured
/// there - the opt-in path got the kernel, the ungated path kept what it
/// had been running, and nothing in flight changed underneath. That
/// arm's stated precondition was "when a quotable GFNI box has measured
/// the leaf, delete it".
///
/// **A quotable box has, so it is deleted** (11 Sep 2026): on two
/// matched idle Ryzen 7 9800X3D, the leaf's pointwise step reads
/// 0.008 ms in place against 0.019 ms through the temporary, about -58%,
/// median of three runs on each box. The earlier shared-VM reading had
/// the two arms level, which was a reason to expect no harm rather than
/// a reason to ship unmeasured; this is the measurement it was waiting
/// for.
///
/// **So this is now a pass-through and the split it existed for is
/// spent.** It is kept as a name rather than collapsed into
/// [`scale_available`] because the two questions are genuinely
/// different - "is there a kernel" and "should a caller with a choice
/// use it" - and a target that ever wants to answer them differently
/// again should find the seam here rather than re-cut it. Collapsing it
/// is available to a later lane; doing it in the same commit as a
/// default flip is not.
pub fn inplace_scale_preferred() -> bool {
    scale_available()
}

/// [`scale`]'s kernel call, on whichever arm [`scale_kernel`] named.
/// The selection is NOT repeated here - the same enum [`scale_available`]
/// reads and a diagnostic prints is what decides.
fn scale_dispatch(row: &mut [u16], c: &FoldCoeff) -> usize {
    match scale_kernel() {
        // SAFETY: NEON, incl. pmull on poly8, is baseline on aarch64, so
        // there is no feature precondition; the kernel derives its own
        // bounds from `row`.
        #[cfg(target_arch = "aarch64")]
        ScaleKernel::Neon => unsafe { scale_neon(row, c.coeff()) },
        // SAFETY: gfni+avx2 verified by `gfni256_available`, which
        // `scale_kernel` checked to reach this arm; the kernel derives
        // its own bounds from `row`.
        #[cfg(target_arch = "x86_64")]
        ScaleKernel::Gfni256 => unsafe { scale_gfni(row, c.coeff()) },
        // SAFETY: avx2 verified by `scale_kernel`; the nibble tables
        // this kernel reads are populated exactly when
        // `nibble_kernel_selected` (see `FoldCoeff::new`).
        #[cfg(target_arch = "x86_64")]
        ScaleKernel::Avx2Nibble => unsafe { scale_avx2(row, c) },
        // SAFETY: ssse3 verified by `scale_kernel`; the nibble tables
        // this kernel reads are populated exactly when
        // `nibble_kernel_selected` (see `FoldCoeff::new`).
        #[cfg(target_arch = "x86_64")]
        ScaleKernel::Ssse3Nibble => unsafe { scale_ssse3(row, c) },
        #[cfg(not(target_arch = "aarch64"))]
        ScaleKernel::Scalar => scale_scalar(row, c.coeff()),
        // `scale_kernel` never names a kernel off its own architecture,
        // so the variants left over on each build are unreachable rather
        // than unhandled - and `scale_scalar` does not exist on aarch64,
        // which is why this cannot simply be the scalar arm.
        #[allow(unreachable_patterns)]
        k => unreachable!("scale_kernel chose {k:?}, which this build has no kernel for"),
    }
}

/// The portable scale: one [`MulTable`] over the span. Off the SIMD arms
/// only, so the table build is not on any shipped path. It read "(512
/// multiplies)" until 11 Sep 2026, when [`split_tables`] made it a
/// subset walk; the point of the sentence - that this arm is not worth
/// tuning - is unchanged.
#[cfg(not(target_arch = "aarch64"))]
fn scale_scalar(row: &mut [u16], c: u16) -> usize {
    let words = (row.len() * 2 / 32) * 16;
    let t = MulTable::new(c);
    for w in row[..words].iter_mut() {
        *w = t.mul(*w);
    }
    words
}

/// [`scale`]'s aarch64 kernel: [`butterfly_neon`]'s multiply with
/// the product stored over the source. Baseline NEON - the Barrett
/// reduction is value-only and needs no sha3.
#[cfg(target_arch = "aarch64")]
unsafe fn scale_neon(row: &mut [u16], c: u16) -> usize {
    use std::arch::aarch64::*;
    let chunks = (row.len() * 2) / 32;
    if chunks == 0 {
        return 0;
    }
    // SAFETY: NEON incl. pmull on poly8 is baseline on aarch64. Every
    // access stays within the first `chunks * 32` bytes of `row`, in
    // bounds by construction of `chunks`.
    unsafe {
        let c_lo = vdupq_n_p8(c as u8);
        let c_hi = vdupq_n_p8((c >> 8) as u8);
        let c_mid = vreinterpretq_p8_u8(veorq_u8(
            vreinterpretq_u8_p8(c_lo),
            vreinterpretq_u8_p8(c_hi),
        ));
        let pml = |d: poly8x16_t, c: poly8x16_t| -> poly16x8_t {
            vmull_p8(vget_low_p8(d), vget_low_p8(c))
        };
        let pmh = |d: poly8x16_t, c: poly8x16_t| -> poly16x8_t { vmull_high_p8(d, c) };
        let rb = row.as_mut_ptr() as *mut u8;
        for ch in 0..chunks {
            let off = ch * 32;
            let mut d = vld2q_u8(rb.add(off));
            let dlo = vreinterpretq_p8_u8(d.0);
            let dhi = vreinterpretq_p8_u8(d.1);
            let dmid = vreinterpretq_p8_u8(veorq_u8(d.0, d.1));
            let (out_lo, out_hi) = clmul_reduce(
                pml(dlo, c_lo),
                pmh(dlo, c_lo),
                pml(dmid, c_mid),
                pmh(dmid, c_mid),
                pml(dhi, c_hi),
                pmh(dhi, c_hi),
            );
            d.0 = out_lo;
            d.1 = out_hi;
            vst2q_u8(rb.add(off), d);
        }
    }
    chunks * 16
}

/// [`scale`]'s AVX2 nibble kernel: [`butterfly_avx2`]'s product stored
/// over the source.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scale_avx2(row: &mut [u16], c: &FoldCoeff) -> usize {
    use std::arch::x86_64::*;
    let units = (row.len() * 2) / 32;
    if units == 0 {
        return 0;
    }
    let chunks = units / 2;
    // SAFETY: avx2 is enabled here per #[target_feature] (runtime-
    // verified at the dispatch site). Every access stays within the first
    // `units * 32` bytes of `row`.
    unsafe {
        let bc = |t: &[u8; 16]| {
            _mm256_broadcastsi128_si256(_mm_loadu_si128(t.as_ptr() as *const __m128i))
        };
        let tl: [__m256i; 4] = std::array::from_fn(|j| bc(&c.nl[j]));
        let th: [__m256i; 4] = std::array::from_fn(|j| bc(&c.nh[j]));
        let nib = _mm256_set1_epi8(0x0f);
        let lo8 = _mm256_set1_epi16(0x00ff);
        let rb = row.as_mut_ptr() as *mut u8;
        for ch in 0..chunks {
            let off = ch * 64;
            let rp = rb.add(off) as *mut __m256i;
            let d0 = _mm256_loadu_si256(rp);
            let d1 = _mm256_loadu_si256(rp.add(1));
            let slo = _mm256_packus_epi16(_mm256_and_si256(d0, lo8), _mm256_and_si256(d1, lo8));
            let shi = _mm256_packus_epi16(_mm256_srli_epi16(d0, 8), _mm256_srli_epi16(d1, 8));
            let n0 = _mm256_and_si256(slo, nib);
            let n1 = _mm256_and_si256(_mm256_srli_epi16(slo, 4), nib);
            let n2 = _mm256_and_si256(shi, nib);
            let n3 = _mm256_and_si256(_mm256_srli_epi16(shi, 4), nib);
            let plo = _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_shuffle_epi8(tl[0], n0),
                    _mm256_shuffle_epi8(tl[1], n1),
                ),
                _mm256_xor_si256(
                    _mm256_shuffle_epi8(tl[2], n2),
                    _mm256_shuffle_epi8(tl[3], n3),
                ),
            );
            let phi = _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_shuffle_epi8(th[0], n0),
                    _mm256_shuffle_epi8(th[1], n1),
                ),
                _mm256_xor_si256(
                    _mm256_shuffle_epi8(th[2], n2),
                    _mm256_shuffle_epi8(th[3], n3),
                ),
            );
            _mm256_storeu_si256(rp, _mm256_unpacklo_epi8(plo, phi));
            _mm256_storeu_si256(rp.add(1), _mm256_unpackhi_epi8(plo, phi));
        }
        if !units.is_multiple_of(2) {
            // The odd 32-byte unit at half width - see `butterfly_avx2`.
            let off = chunks * 64;
            let nib128 = _mm_set1_epi8(0x0f);
            let lo8_128 = _mm_set1_epi16(0x00ff);
            let lane = _mm256_castsi256_si128;
            let rp = rb.add(off) as *mut __m128i;
            let d0 = _mm_loadu_si128(rp);
            let d1 = _mm_loadu_si128(rp.add(1));
            let slo = _mm_packus_epi16(_mm_and_si128(d0, lo8_128), _mm_and_si128(d1, lo8_128));
            let shi = _mm_packus_epi16(_mm_srli_epi16(d0, 8), _mm_srli_epi16(d1, 8));
            let n0 = _mm_and_si128(slo, nib128);
            let n1 = _mm_and_si128(_mm_srli_epi16(slo, 4), nib128);
            let n2 = _mm_and_si128(shi, nib128);
            let n3 = _mm_and_si128(_mm_srli_epi16(shi, 4), nib128);
            let plo = _mm_xor_si128(
                _mm_xor_si128(
                    _mm_shuffle_epi8(lane(tl[0]), n0),
                    _mm_shuffle_epi8(lane(tl[1]), n1),
                ),
                _mm_xor_si128(
                    _mm_shuffle_epi8(lane(tl[2]), n2),
                    _mm_shuffle_epi8(lane(tl[3]), n3),
                ),
            );
            let phi = _mm_xor_si128(
                _mm_xor_si128(
                    _mm_shuffle_epi8(lane(th[0]), n0),
                    _mm_shuffle_epi8(lane(th[1]), n1),
                ),
                _mm_xor_si128(
                    _mm_shuffle_epi8(lane(th[2]), n2),
                    _mm_shuffle_epi8(lane(th[3]), n3),
                ),
            );
            _mm_storeu_si128(rp, _mm_unpacklo_epi8(plo, phi));
            _mm_storeu_si128(rp.add(1), _mm_unpackhi_epi8(plo, phi));
        }
    }
    units * 16
}

/// [`scale`] on SSSE3: the 128-bit nibble kernel, for an x86 part with
/// `pshufb` and no AVX2.
///
/// **This is [`scale_avx2`]'s own odd-unit tail, promoted to a kernel.**
/// That tail already runs the whole algorithm at 128 bits and is
/// exercised by `scale_matches_the_definition_in_place` at every odd
/// `units`, so the arithmetic arrives differential-tested rather than
/// newly written. Only the loop around it is new, which is the point: a
/// kernel this file has already proved should not be rewritten to reach
/// one more CPU.
///
/// # Why this one function is the whole of SSSE3 support
///
/// [`butterfly`] needs no SSSE3 arm - it falls through
/// [`butterfly_two_pass`], whose multiply is [`xor_mul_multi_into`] and
/// therefore already [`xor_mul_multi_ssse3`]. `scale` was the only
/// operation with no SSSE3 path at all, and [`scale_available`] is what
/// `par2repair::forney::joint` consults. So on an SSSE3-only part -
/// Intel before Haswell, AMD before Excavator - `parfast --fast` was
/// accepted and then declined, for want of exactly this loop.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
unsafe fn scale_ssse3(row: &mut [u16], c: &FoldCoeff) -> usize {
    use std::arch::x86_64::*;
    let units = (row.len() * 2) / 32;
    if units == 0 {
        return 0;
    }
    // SAFETY: ssse3 is enabled here per #[target_feature] (runtime-
    // verified at the dispatch site). Every access stays within the
    // first `units * 32` bytes of `row`.
    unsafe {
        let ld = |t: &[u8; 16]| _mm_loadu_si128(t.as_ptr() as *const __m128i);
        let tl: [__m128i; 4] = std::array::from_fn(|j| ld(&c.nl[j]));
        let th: [__m128i; 4] = std::array::from_fn(|j| ld(&c.nh[j]));
        let nib = _mm_set1_epi8(0x0f);
        let lo8 = _mm_set1_epi16(0x00ff);
        let rb = row.as_mut_ptr() as *mut u8;
        for u in 0..units {
            let rp = rb.add(u * 32) as *mut __m128i;
            let d0 = _mm_loadu_si128(rp);
            let d1 = _mm_loadu_si128(rp.add(1));
            // Deinterleave the u16 lanes into a low-byte half and a
            // high-byte half, so one `pshufb` table serves each nibble.
            let slo = _mm_packus_epi16(_mm_and_si128(d0, lo8), _mm_and_si128(d1, lo8));
            let shi = _mm_packus_epi16(_mm_srli_epi16(d0, 8), _mm_srli_epi16(d1, 8));
            let n0 = _mm_and_si128(slo, nib);
            let n1 = _mm_and_si128(_mm_srli_epi16(slo, 4), nib);
            let n2 = _mm_and_si128(shi, nib);
            let n3 = _mm_and_si128(_mm_srli_epi16(shi, 4), nib);
            let plo = _mm_xor_si128(
                _mm_xor_si128(_mm_shuffle_epi8(tl[0], n0), _mm_shuffle_epi8(tl[1], n1)),
                _mm_xor_si128(_mm_shuffle_epi8(tl[2], n2), _mm_shuffle_epi8(tl[3], n3)),
            );
            let phi = _mm_xor_si128(
                _mm_xor_si128(_mm_shuffle_epi8(th[0], n0), _mm_shuffle_epi8(th[1], n1)),
                _mm_xor_si128(_mm_shuffle_epi8(th[2], n2), _mm_shuffle_epi8(th[3], n3)),
            );
            _mm_storeu_si128(rp, _mm_unpacklo_epi8(plo, phi));
            _mm_storeu_si128(rp.add(1), _mm_unpackhi_epi8(plo, phi));
        }
    }
    units * 16
}

/// [`scale`]'s GFNI kernel: [`butterfly_gfni`]'s product stored over the
/// source. UNMEASURED on this fleet, as that one is.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx2")]
unsafe fn scale_gfni(row: &mut [u16], c: u16) -> usize {
    use std::arch::x86_64::*;
    let chunks = (row.len() * 2) / 32;
    if chunks == 0 {
        return 0;
    }
    // SAFETY: gfni+avx2 are enabled here per #[target_feature] (runtime-
    // verified at the dispatch site). Every access stays within the first
    // `chunks * 32` bytes of `row`.
    unsafe {
        let m = affine_matrices_fast(c);
        let mat_n = _mm256_set_epi64x(m[3] as i64, m[0] as i64, m[3] as i64, m[0] as i64);
        let mat_s = _mm256_set_epi64x(m[1] as i64, m[2] as i64, m[1] as i64, m[2] as i64);
        let deint = _mm256_broadcastsi128_si256(_mm_setr_epi8(
            0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15,
        ));
        let inter = _mm256_broadcastsi128_si256(_mm_setr_epi8(
            0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15,
        ));
        let rb = row.as_mut_ptr() as *mut u8;
        for ch in 0..chunks {
            let off = ch * 32;
            let rp = rb.add(off) as *mut __m256i;
            let data = _mm256_shuffle_epi8(_mm256_loadu_si256(rp), deint);
            let acc_n = _mm256_gf2p8affine_epi64_epi8::<0>(data, mat_n);
            let acc_s = _mm256_gf2p8affine_epi64_epi8::<0>(data, mat_s);
            let res = _mm256_xor_si256(acc_n, _mm256_shuffle_epi32::<0x4E>(acc_s));
            _mm256_storeu_si256(rp, _mm256_shuffle_epi8(res, inter));
        }
    }
    chunks * 16
}
