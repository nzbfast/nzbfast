//! Output-pruned multiplicative NTT over GF(65536) for PAR2 syndrome
//! computation - the Stage 1 flat module of the merged NTT plan
//! (`research/NTT-STAGE1-flat-module-2026-07-30.md`), relocated from the
//! research harness. EXPERIMENTAL: reachable only through par2repair's
//! disabled-by-default dispatch gate, with the streaming fold as the
//! unconditional fallback.
//!
//! Mathematical identity (differential-tested here and in the research
//! stack): PAR2's syndrome `S_e = Σ_i d_i·2^{L_i·e}` over present
//! slices with base logs L_i is exactly output `e` of the 65535-point
//! DFT (root 2) of the slice array scattered to coefficient slots L_i.
//! The multiplicative group order factors as 65535 = 3·5·17·257, so a
//! mixed-radix Cooley-Tukey with direct Rader-257 leaves applies; base
//! logs are coprime to 65535, which structurally zeroes one residue
//! class per small-prime stage (only 128 of 255 leaves run), and both
//! repair paths request the smallest exponents, so combine stages prune
//! to the `needed = max_exponent + 1` prefix.
//!
//! Shape: one immutable [`FlatPlan`] per (present set, needed) - stage
//! descriptors, live branches, Rader permutations, and every combine
//! coefficient precomputed as a raw GF value (no lookup tables at all;
//! ~1 ms at the heavy geometry). Per-worker [`Scratch`] arenas, zero
//! allocation inside a transform. The hot loops are the production
//! fused multi-source kernel ([`gf16::xor_mul_multi_into`]): each
//! Rader leaf output row is a ~n/128-source region fold, each combine
//! row a 2/4/16-source fold. Sources are pointers straight into the
//! caller's resident slices - there is no scatter step.
//!
//! Measured (2026-07-30, retained outputs, bit-verified): M1 Ultra
//! heavy leg (16384/1500/64 KiB) 0.905 s vs the shipped fold's 4.45 s.
//!
//! WHERE THE TIME GOES, AND WHAT HAS ALREADY BEEN TRIED. The LEAVES are
//! 92-95% of this transform on every box measured; the combine stages,
//! pruned to `needed`, are under 5% and have nothing left to give
//! (`research/PAR2-PERF-AUDIT-2026-09-02.md` section 17). So the only
//! algorithmic lever in here is a cheaper length-256 cyclic
//! convolution at the leaf - and the obvious one is already spent: a
//! KARATSUBA split was built, held bit-identical by the differential
//! harness in this module's tests, and raced on NEON and GFNI on
//! 3 Sep 2026. It measured 1.02x, and was dropped. The reason is worth
//! knowing before trying anything else here: an addition-fold costs
//! what a multiply-fold costs (both are one pass of a `w`-word block
//! through `gf16::xor_mul_multi_into`), so any method priced on
//! "fewer multiplications" is priced in the wrong currency, and any
//! method that goes density-blind loses the sparsity the dense leaf
//! already exploits. Audit section 18 has the tables, the cost model,
//! and what an additive FFT would have to beat. Add a candidate as a
//! third arm in `tests::leaf_case`; nothing ships until that is green.
//!
//! AND READ THE FILL BEFORE RACING ONE. Every leaf kernel here is
//! admitted by how FULL the leaf is, so a candidate that the gate
//! refuses measures flat and a candidate that runs and buys nothing
//! measures flat too - round BL (7 Sep 2026) spent a seventh forced-arm
//! leg learning which it had. [`FlatPlan::leaf_fill`] answers that from
//! the plan, before a stripe is transformed; `NZBFAST_NTT_FILL=1` logs
//! it as one `[ntt-fill]` line per plan.

use crate::gf16;
/// The leaf in a quadratic basis with conjugate row pairs: its own file.
#[path = "par2ntt/additive.rs"]
mod additive;
#[path = "par2ntt/conjugate.rs"]
mod conjugate;

/// Census doors onto the leaf gates (see `par2seams`). Each calls the
/// real predicate and adds nothing, so the census cannot disagree with
/// the selection the transform makes.
pub(crate) fn seam_additive(leaf_fill: usize) -> bool {
    additive::enabled() && leaf_fill >= additive::min_sources()
}

/// As [`seam_additive`], for the paired conjugate leaf.
pub(crate) fn seam_paired() -> bool {
    conjugate::enabled()
}

#[path = "par2ntt/planning.rs"]
mod planning;
#[path = "par2ntt/sparse.rs"]
mod sparse;

/// Transform length: the order of GF(65536)'s multiplicative group.
pub const N: usize = 65535;

const RADER_G: u64 = 3;
const LEAF_ROOT_LOG: u64 = 255;

/// Caller's identifier for one present slice (index into its slice
/// table); resolved to stripe data by the `src_of` callback.
pub type SrcId = u32;

/// Mutable storage private to one prefix or range construction.
struct BuildState {
    coefficients: planning::Coefficients,
    sources: [(u16, SrcId); 256],
}

impl Default for BuildState {
    fn default() -> Self {
        Self {
            coefficients: planning::Coefficients::default(),
            sources: [(0, 0); 256],
        }
    }
}

struct LeafPlan {
    buf: usize,
    /// Conv sources sorted by Rader index i (a_i = x[g^{-i}]): (i, source).
    conv_sources: Vec<(u16, SrcId)>,
    /// Occupant of local slot 0, if present (participates in X[0] and
    /// is XORed into every conv output).
    x0: Option<SrcId>,
}

struct CombinePlan {
    buf: usize,
    /// Output rows (min(needed, node size)).
    rows: usize,
    /// Child DFT length (row index into child buffers is k % q).
    q: usize,
    /// Compact child row for each selected output; None keeps prefix indexing.
    selected_child_rows: Option<std::sync::Arc<[usize]>>,
    /// Output rows in an order that puts everyone sharing a child row
    /// back to back (see [`grouped_order`]); None to walk 0..rows.
    order: Option<std::sync::Arc<[u32]>>,
    /// Live children buffer slots at depth+1, in class order.
    children: Vec<usize>,
    /// Raw GF coefficients, rows-major: coeffs[k*children.len() + j]
    /// = 2^{root_log · u_j · k}.
    coeffs: std::sync::Arc<[u16]>,
    child_nodes: Vec<Node>,
}

enum Node {
    Leaf(LeafPlan),
    Combine(CombinePlan),
}

/// Immutable transform plan for one present set and requested output interval.
pub struct FlatPlan {
    root: Node,
    g_pow: [usize; 256],
    /// b[t] = 2^{255·g^t} - the fixed Rader kernel, raw values.
    /// The Rader kernel `b[t] = 2^(255 g^t)` (see [`rader_tables`]),
    /// prepared for the fused fold once per process: the dense
    /// leaf folds one stripe per call against these same 256 values,
    /// tens of thousands of calls per leaf, and on the x86 nibble kernels
    /// each call used to rebuild its coefficients' tables from scratch -
    /// see [`gf16::FoldCoeff`]. `one` is the x0 term's coefficient.
    kernel_prepared: &'static [gf16::FoldCoeff; 256],
    one: &'static gf16::FoldCoeff,
    /// The paired leaf kernel where it runs (see `conjugate`), else the
    /// dense leaf above is the only one.
    paired: Option<&'static conjugate::Kernel>,
    /// The fixed additive-FFT leaf kernel, shared when its gate is on;
    /// a leaf takes it by fill (`Kernel::admits`).
    additive: Option<&'static additive::Kernel>,
    /// Rows the root produces: max selected exponent + 1, or the range's
    /// length for a range plan.
    pub(crate) needed: usize,
}

/// Per-worker scratch arenas: one pool per tree depth, reused across
/// stripes. Allocated once per worker outside any timed/hot region.
pub struct Scratch {
    w: usize,
    /// The paired leaf's packed sources (empty without that kernel).
    paired_scratch: Vec<u8>,
    /// The additive leaf's 512 working rows (empty without that kernel).
    additive_scratch: Vec<u16>,
    leaf: Vec<u16>,   // 17 slots x 257 rows
    depth2: Vec<u16>, // 5 slots x min(needed, 4369) rows
    rows2: usize,
    depth1: Vec<u16>, // 3 slots x min(needed, 21845) rows
    rows1: usize,
}

/// The Rader-257 tables: `g_pow[t] = 3^t mod 257`, the inverse-power
/// index `ip[s]` (so `a_i = x[g^{-i}]` is `conv_sources`' sort key), and
/// the fixed convolution kernel `b[t] = 2^{255·g^t}`. Fixed for the
/// life of the process and cached by production planning. This constructor
/// remains available to tests that drive a leaf with their own kernel.
fn rader_tables() -> ([usize; 256], [u16; 257], [u16; 256]) {
    let mut g_pow = [0usize; 256];
    let mut g_inv_pow = [0usize; 256];
    let mut v = 1u64;
    for i in 0..256 {
        g_pow[i] = v as usize;
        g_inv_pow[(256 - i) % 256] = v as usize;
        v = v * RADER_G % 257;
    }
    let mut ip = [0u16; 257];
    for (i, &s) in g_inv_pow.iter().enumerate() {
        ip[s] = i as u16;
    }
    let mut kernel = [0u16; 256];
    for t in 0..256 {
        kernel[t] = gf16::pow2(LEAF_ROOT_LOG * g_pow[t] as u64 % N as u64);
    }
    (g_pow, ip, kernel)
}

impl FlatPlan {
    /// Build the plan. `present` maps base logs to caller slice ids;
    /// `needed` is max selected exponent + 1. Fails (so the caller can
    /// fall back to the fold) on empty input, out-of-range logs or
    /// exponents, and duplicate logs - a duplicate feed is representable
    /// by the XOR-accumulating fold but not by coefficient slots.
    pub fn build(present: &[(u32, SrcId)], needed: usize) -> Result<FlatPlan, String> {
        if present.is_empty() {
            return Err("empty present set".into());
        }
        if needed == 0 || needed > N {
            return Err(format!("needed {needed} out of range"));
        }
        if present.len() <= sparse::LIMIT {
            return Self::sparse_plan(present, 0, needed);
        }
        let fixed = planning::fixed();
        let g_pow = &fixed.g_pow;
        let mut slots: Vec<Option<SrcId>> = vec![None; N];
        for &(log, src) in present {
            if log as usize >= N {
                return Err(format!("base log {log} out of range"));
            }
            let slot = &mut slots[log as usize];
            if slot.is_some() {
                return Err(format!("duplicate base log {log}"));
            }
            *slot = Some(src);
        }
        let root = build_node(
            planning::Slots::new(&slots),
            1,
            needed,
            0,
            g_pow,
            &mut BuildState::default(),
        )
        .expect("nonempty set built no tree");
        let plan = FlatPlan {
            root,
            g_pow: fixed.g_pow,
            kernel_prepared: &fixed.prepared,
            one: &fixed.one,
            paired: fixed.paired.as_ref(),
            additive: fixed.additive.as_ref(),
            needed,
        };
        plan.report_leaf_fill();
        Ok(plan)
    }

    /// Produce exactly `first..first+count`, compacted into `count` rows.
    /// Intermediate nodes retain only the distinct residues requested by their
    /// parent. Leaves still compute the full 257-point transform. This avoids
    /// materializing a large unused prefix for later recovery volumes.
    pub fn build_range(
        present: &[(u32, SrcId)],
        first: usize,
        count: usize,
    ) -> Result<FlatPlan, String> {
        if first == 0 {
            return Self::build(present, count);
        }
        let end = first
            .checked_add(count)
            .filter(|&e| e <= N)
            .ok_or_else(|| "output range outside transform".to_string())?;
        if count == 0 || present.is_empty() {
            return Err("empty range or present set".into());
        }
        if present.len() <= sparse::LIMIT {
            return Self::sparse_plan(present, first, count);
        }
        let fixed = planning::fixed();
        let g_pow = &fixed.g_pow;
        let mut slots = vec![None; N];
        for &(log, src) in present {
            let slot = slots
                .get_mut(log as usize)
                .ok_or_else(|| format!("base log {log} out of range"))?;
            if slot.is_some() {
                return Err(format!("duplicate base log {log}"));
            }
            *slot = Some(src);
        }
        let selected: Vec<usize> = (first..end).collect();
        let root = build_node_range(
            planning::Slots::new(&slots),
            1,
            &selected,
            0,
            g_pow,
            &mut BuildState::default(),
        )
        .expect("nonempty set built no tree");
        let plan = FlatPlan {
            root,
            g_pow: fixed.g_pow,
            kernel_prepared: &fixed.prepared,
            paired: fixed.paired.as_ref(),
            additive: fixed.additive.as_ref(),
            one: &fixed.one,
            needed: count,
        };
        plan.report_leaf_fill();
        Ok(plan)
    }

    fn sparse_plan(present: &[(u32, SrcId)], first: usize, count: usize) -> Result<Self, String> {
        let fixed = planning::fixed();
        let root = sparse::tree(present, first, count, &fixed.g_pow)?;
        let plan = Self {
            root,
            g_pow: fixed.g_pow,
            kernel_prepared: &fixed.prepared,
            one: &fixed.one,
            paired: fixed.paired.as_ref(),
            additive: fixed.additive.as_ref(),
            needed: count,
        };
        plan.report_leaf_fill();
        Ok(plan)
    }

    pub fn new_scratch(&self, w: usize) -> Scratch {
        let rows2 = self.needed.min(4369);
        let rows1 = self.needed.min(21845);
        Scratch {
            w,
            paired_scratch: if self.paired.is_some() {
                vec![0; conjugate::scratch_cap(w)]
            } else {
                Vec::new()
            },
            additive_scratch: if self.additive.is_some() {
                vec![0u16; additive::scratch_words(w)]
            } else {
                Vec::new()
            },
            leaf: vec![0u16; 17 * 257 * w],
            rows2,
            depth2: vec![0u16; 5 * rows2 * w],
            rows1,
            depth1: vec![0u16; 3 * rows1 * w],
        }
    }

    /// Bytes ONE worker allocates at stripe width `w`: everything
    /// [`Self::new_scratch`] reserves, plus that worker's `needed * w`
    /// output rows.
    ///
    /// An associated function because the repair dispatcher has to price
    /// this BEFORE a plan exists. Keep the pool clamps in step with
    /// `new_scratch` directly above - they are the same numbers, and the
    /// admission gate is only as honest as this estimate.
    pub fn scratch_bytes(needed: usize, w: usize) -> usize {
        (17 * 257 + 5 * needed.min(4369) + 3 * needed.min(21845) + needed)
            .saturating_mul(w)
            .saturating_mul(2)
            .saturating_add(if conjugate::enabled() {
                conjugate::scratch_cap(w)
            } else {
                0
            })
            .saturating_add(if additive::enabled() {
                additive::scratch_words(w) * 2
            } else {
                0
            })
    }

    /// Transform one stripe of `w` words. `src_of` resolves a SrcId to
    /// the stripe's byte pointer (at least `2*w` readable bytes).
    /// Writes the selected syndrome rows in ascending order into `out`
    /// (needed*w words). No allocation inside.
    pub fn transform(
        &self,
        src_of: &dyn Fn(SrcId) -> *const u8,
        w: usize,
        scratch: &mut Scratch,
        out: &mut [u16],
    ) {
        assert!(scratch.w >= w, "scratch narrower than stripe");
        assert!(out.len() >= self.needed * w);
        eval(&self.root, self, src_of, w, 0, scratch as *mut Scratch, out);
    }
}

/// Recursive plan builder mirroring the differential-tested prototype's
/// decimation exactly. Returns None for structurally dead subtrees.
fn build_node<S: planning::Input>(
    slots: S,
    root_log: u64,
    needed: usize,
    buf: usize,
    g_pow: &[usize; 256],
    tables: &mut BuildState,
) -> Option<Node> {
    let n = slots.len();
    if slots.vacant() {
        return None;
    }
    if n == 257 {
        debug_assert_eq!(root_log % N as u64, LEAF_ROOT_LOG);
        return Some(Node::Leaf(slots.leaf(buf, g_pow, &mut tables.sources)));
    }
    let p = [3usize, 5, 17]
        .iter()
        .copied()
        .find(|p| n.is_multiple_of(*p))
        .expect("bad node size");
    let q = n / p;
    let sub_needed = needed.min(q);
    let mut children = Vec::new();
    let mut child_nodes = Vec::new();
    let mut lives = Vec::new();
    for u in 0..p {
        let class = slots.child(u, p);
        debug_assert_eq!(class.len(), q);
        if let Some(node) = build_node(
            class,
            root_log * p as u64,
            sub_needed,
            children.len(),
            g_pow,
            tables,
        ) {
            children.push(child_buf(&node));
            child_nodes.push(node);
            lives.push(u);
        }
    }
    let rows = needed.min(n);
    let coeffs = tables.coefficients.get(root_log, &lives, 0..rows);
    let order = tables
        .coefficients
        .order(root_log, || (0..rows).map(|k| k % q).collect());
    Some(Node::Combine(CombinePlan {
        buf,
        rows,
        q,
        selected_child_rows: None,
        order,
        children,
        coeffs,
        child_nodes,
    }))
}

/// A selected interval may wrap after reduction modulo a child length.
/// Sort and deduplicate those residues, and explicitly map parent rows to
/// compact child positions. Every child pool then needs at most min(count,q)
/// rows, exactly the bounds used by new_scratch and scratch_bytes.
fn build_node_range<S: planning::Input>(
    slots: S,
    root_log: u64,
    selected: &[usize],
    buf: usize,
    g_pow: &[usize; 256],
    tables: &mut BuildState,
) -> Option<Node> {
    if slots.vacant() {
        return None;
    }
    let n = slots.len();
    if n == 257 {
        return build_node(slots, root_log, 257, buf, g_pow, tables);
    }
    let p = [3usize, 5, 17]
        .into_iter()
        .find(|p| n.is_multiple_of(*p))
        .unwrap();
    let q = n / p;
    let selection = tables.coefficients.range(root_log, q, selected);
    let mut children = Vec::new();
    let mut child_nodes = Vec::new();
    let mut lives = Vec::new();
    for u in 0..p {
        let class = slots.child(u, p);
        if let Some(node) = build_node_range(
            class,
            root_log * p as u64,
            &selection.residues,
            children.len(),
            g_pow,
            tables,
        ) {
            children.push(child_buf(&node));
            child_nodes.push(node);
            lives.push(u);
        }
    }
    let coeffs = tables
        .coefficients
        .get(root_log, &lives, selected.iter().copied());
    let order = tables
        .coefficients
        .order(root_log, || selection.child_rows.to_vec());
    Some(Node::Combine(CombinePlan {
        buf,
        rows: selected.len(),
        q,
        selected_child_rows: Some(selection.child_rows.clone()),
        order,
        children,
        coeffs,
        child_nodes,
    }))
}

/// `NZBFAST_NTT_COMBINE_GROUP=0` restores the plain 0..rows walk; on
/// everywhere else. Read once.
fn combine_group_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NZBFAST_NTT_COMBINE_GROUP").as_deref() != Ok("0"))
}

/// The order to walk a combine's output rows in, given the child row
/// each of them reads. `None` means "0..rows is as good as anything":
/// either the grouping is switched off, or no child row is read twice.
///
/// WHY. A combine row is `out[k] = Sum_j coeff(k,j) * child_j[k mod q]`,
/// so the child row is a function of `k mod q` and every output row in
/// the same residue class reads THE SAME child rows. Walking `k`
/// ascending visits residue 0, then 1, ... then q-1 before coming back
/// to residue 0, so a child row's reuse distance is the whole child
/// pool. At the stage above the leaves that pool is 17 slots x 257 rows
/// (4.5 MB at a 1 KiB row), and the i5-10600KF measured that stage at
/// 16-20% of the transform against the M3 Ultra's 7% - child-row
/// traffic on a 40 GB/s part, not table builds (round C of the
/// `parfast-optimisation-search-2` lane priced prepared coefficients
/// there at flat to +3%). Grouping by residue drops the reuse distance
/// to the one class's rows - 16 KiB, L1-resident - so each child row is
/// read once and consumed by all `rows/q` of its outputs. The folds
/// themselves are unchanged and each output row is still written
/// exactly once, so outputs are bit-identical whichever order runs.
///
/// Only stages with `rows > q` have anything to group: for a repair
/// asking `needed` exponents that is the stage above the leaves once
/// `needed > 257`, which is every heavy repair and every create wide
/// enough to want one.
fn grouped_order(child_rows: &[usize]) -> Option<Vec<u32>> {
    if !combine_group_enabled() {
        return None;
    }
    let mut order: Vec<u32> = (0..child_rows.len() as u32).collect();
    order.sort_by_key(|&k| child_rows[k as usize]);
    let repeats = order
        .windows(2)
        .any(|p| child_rows[p[0] as usize] == child_rows[p[1] as usize]);
    repeats.then_some(order)
}

fn child_buf(n: &Node) -> usize {
    match n {
        Node::Leaf(l) => l.buf,
        Node::Combine(c) => c.buf,
    }
}

/// Fused multi-source fold with scalar tail: dst ^= Σ coeff_j·src_j.
/// Groups of 8 hit the kernel's monomorphized path; the group array is
/// on the stack - no allocation. The ONE exception is the six-source
/// GFNI+AVX2 kernel, which takes 12 - exactly two full register batches,
/// where 8 ends every group with an under-filled two-source pass.
///
/// This is deliberately NOT applied to the twelve-source AVX-512 arm,
/// and the asymmetry is measured, not cautious. the review's `0efd0ab97`
/// widened both x86 arms and its author then REJECTED the whole change:
/// isolated leaves retired 3.29% fewer instructions on AVX-512, but a
/// realistic 0.41 GiB / 1,500-missing Reconstructor gate ran native NTT
/// completion 14.8% SLOWER in every pair (hoisting dispatch: 19.9%).
/// On AVX-512 a 12-group is ONE batch, so nothing is filled and the only
/// effect is widening the leaf's memory order over more live sources.
///
/// On native GFNI/AVX2 silicon it is the other way round, which neither
/// audit measured - review only ever ran a FORCED AVX2 arm on an AVX-512
/// box. Measured here on a Core Ultra 9 386H (GFNI+AVX2, no AVX-512),
/// 1 GiB / 64 KiB / 1,500 missing, 12 position-balanced pairs with
/// alternating arm order, every leg SHA-gated 21/21: transform phase
/// median 5.670 s against 6.165 s (-8.0%), faster in 11 of 12 pairs,
/// faster at BOTH positions, and sd 0.165 against 0.285. Numbers and
/// the two discarded rounds that preceded them:
/// research/PAR2-TWO-LANES-COMPARED-2026-09-03.md.
fn fold_into(dst: &mut [u16], srcs: &[*const u8], coeffs: &[u16], w: usize) {
    debug_assert_eq!(srcs.len(), coeffs.len());
    // Two full batches on the 6-wide GFNI+AVX2 kernel; 8 everywhere else,
    // AVX-512 included (see the doc comment - widening it there is a
    // measured regression, not an untried option).
    //
    // `NZBFAST_GF16_MULTI=0` documents itself as forcing the single-source
    // path, and `linalg::fold_chunk_tiled` honours it - but this call site
    // did not: it always handed sources to `xor_mul_multi_into`, whose own
    // dispatch chain reads CPU features and knows nothing of the knob. So
    // on a fused-kernel box the knob took the SCHEDULER off the fused path
    // while the TRANSFORM kept using it, and an A/B taken with it measured
    // two different things at once. Honour it here too, and the width below
    // is then an honest scheduler question with a knob-sensitive answer.
    let width = gf16::multi_fold_width();
    if width == 0 {
        for (&p, &c) in srcs.iter().zip(coeffs) {
            // SAFETY: as below - every src carries w*2 readable bytes
            // per `FlatPlan::transform`'s contract and `eval`'s pool
            // rows.
            let src = unsafe { std::slice::from_raw_parts(p, w * 2) };
            gf16::xor_mul_single_into(&mut dst[..w], src, c);
        }
        return;
    }
    // Two full batches on the 6-wide GFNI+AVX2 kernel; 8 everywhere else,
    // AVX-512 included (see the doc comment - widening it there is a
    // measured regression, not an untried option).
    let group_width = if width == 6 { 12 } else { 8 };
    let mut g = 0;
    while g < srcs.len() {
        let cnt = (srcs.len() - g).min(group_width);
        let mut group: [&[u8]; 12] = [&[]; 12];
        for (t, &p) in srcs[g..g + cnt].iter().enumerate() {
            // SAFETY: every src must be readable for w*2 bytes. Both
            // callers uphold this: src_of pointers carry at least 2*w
            // readable bytes per FlatPlan::transform's documented
            // contract, and eval's pool pointers each address a full
            // w-word row of a child slot.
            group[t] = unsafe { std::slice::from_raw_parts(p, w * 2) };
        }
        let done = gf16::xor_mul_multi_into(&mut dst[..w], &group[..cnt], &coeffs[g..g + cnt]);
        if done < w {
            // The tail past the fused kernel's granule - and the WHOLE
            // fold on a build with no fused kernel (x86 without GFNI:
            // AVX2 and SSSE3 parts, which is most desktops before Ice
            // Lake and every Zen before 4). That used to be a scalar
            // `gf16::mul` per word, which made the transform slower
            // than the fold it replaces by an order of magnitude:
            // measured 2 Sep 2026 on an i5-10600KF, the heavy leg took
            // 73 s against turbo 1.5.0's 12 s, every one of them in
            // this loop. The single-source SIMD fold (SSSE3/AVX2 split
            // tables, 128 B per coefficient) is what the streaming fold
            // runs on those parts, and it is what runs here now.
            for (src, &c) in group[..cnt].iter().zip(&coeffs[g..g + cnt]) {
                gf16::xor_mul_single_into(&mut dst[done..w], &src[done * 2..w * 2], c);
            }
        }
        g += cnt;
    }
}

/// The Rader kernel, prepared for the fused fold - see
/// `FlatPlan::kernel_prepared`.
fn prepare_kernel(kernel: &[u16; 256]) -> Box<[gf16::FoldCoeff; 256]> {
    Box::new(std::array::from_fn(|t| gf16::FoldCoeff::new(kernel[t])))
}

/// [`fold_into`] over prepared coefficients: the leaf's whole inner loop,
/// where the coefficients are the plan's 256 kernel values and the
/// stripe is narrow. Same grouping and the same tail rule.
fn fold_into_prepared(dst: &mut [u16], srcs: &[*const u8], coeffs: &[&gf16::FoldCoeff], w: usize) {
    debug_assert_eq!(srcs.len(), coeffs.len());
    let width = gf16::multi_fold_width();
    if width == 0 {
        for (&p, c) in srcs.iter().zip(coeffs) {
            // SAFETY: as in `fold_into` - every src carries w*2
            // readable bytes per `FlatPlan::transform`'s contract.
            let src = unsafe { std::slice::from_raw_parts(p, w * 2) };
            gf16::xor_mul_single_into(&mut dst[..w], src, c.coeff());
        }
        return;
    }
    let group_width = if width == 6 { 12 } else { 8 };
    let mut g = 0;
    while g < srcs.len() {
        let cnt = (srcs.len() - g).min(group_width);
        let mut group: [&[u8]; 12] = [&[]; 12];
        for (t, &p) in srcs[g..g + cnt].iter().enumerate() {
            // SAFETY: as in `fold_into`.
            group[t] = unsafe { std::slice::from_raw_parts(p, w * 2) };
        }
        let done = gf16::xor_mul_multi_prepared(&mut dst[..w], &group[..cnt], &coeffs[g..g + cnt]);
        if done < w {
            for (src, c) in group[..cnt].iter().zip(&coeffs[g..g + cnt]) {
                gf16::xor_mul_single_into(&mut dst[done..w], &src[done * 2..w * 2], c.coeff());
            }
        }
        g += cnt;
    }
}

/// The dense leaf: X[g^m] = x0 + Σ_i a_i·b[(m-i) mod 256] evaluated as
/// 256 fused folds over the leaf's ~n/128 conv sources, i.e. a dense
/// 256 x n_leaf block multiply. Costs 256·n block-multiplies over the
/// whole transform against the streaming fold's m·n, which is why the
/// NTT crosses over near m ~ 300 on every box measured
/// (`research/PAR2-PERF-AUDIT-2026-09-02.md` section 7).
fn leaf_dense(
    leaf: &LeafPlan,
    kernel: &[gf16::FoldCoeff; 256],
    one: &gf16::FoldCoeff,
    g_pow: &[usize; 256],
    src_of: &dyn Fn(SrcId) -> *const u8,
    w: usize,
    out: &mut [u16],
) {
    debug_assert!(out.len() >= 257 * w);
    // At most 256 convolution sources plus x0. Resolve each source once
    // and reuse these bounded lists for every output row of this stripe.
    let count = leaf.conv_sources.len() + usize::from(leaf.x0.is_some());
    let mut cptrs = [std::ptr::null(); 257];
    for (p, &(_, src)) in cptrs.iter_mut().zip(&leaf.conv_sources) {
        *p = src_of(src);
    }
    if let Some(x0) = leaf.x0 {
        cptrs[leaf.conv_sources.len()] = src_of(x0);
    }
    let cptrs = &cptrs[..count];
    let mut cco = [one; 257];
    out[..257 * w].fill(0);
    // X[0] = x[0] + every conv source, coefficient 1.
    fold_into(&mut out[..w], cptrs, &[1; 257][..count], w);
    // X[g^m] = x[0] + Σ_i a_i · b[(m-i) mod 256].
    // Private experiment: reuse the source layout across all 256 output
    // rows. Bound extra live storage independently of the NTT arena estimate.
    // ON wherever the planar fold is (the nibble kernels); `NZBFAST_NTT_
    // PLANAR=0` is the A/B arm. Measured on the i5-10600KF, 1,500-block
    // heavy leg, two mirrored rounds: transform 2.81-3.26 s -> 2.14-2.60
    // (-20-25%), wall 4.21-4.64 -> 3.51-4.00 against turbo's 12.4
    // (the review's `ntt-layout.patch`, 5 Sep 2026).
    let pack_enabled = gf16::PreparedSources::enabled()
        && std::env::var("NZBFAST_NTT_PLANAR").ok().as_deref() != Some("0")
        && w.is_multiple_of(32)
        && !cptrs.is_empty()
        // A FULL leaf: all 256 convolution sources plus x0 at the 512-word
        // production stripe. 256 KiB was one row short of it, so every
        // leaf carrying x0 fell to the interleaved kernel unnoticed (the
        // paired leaf shipped with the same cap; both fixed 5 Sep 2026).
        && cptrs.len().saturating_mul(w).saturating_mul(2) <= 257 * 512 * 2;
    let mut packed = Vec::new();
    if pack_enabled {
        for group in cptrs.chunks(4) {
            let mut sources = gf16::PreparedSources::default();
            let mut refs: [&[u8]; 4] = [&[]; 4];
            for (dst, &p) in refs.iter_mut().zip(group) {
                // SAFETY: as in fold_into_prepared, every source pointer
                // carries w*2 readable bytes for this transform.
                *dst = unsafe { std::slice::from_raw_parts(p, w * 2) };
            }
            if !sources.prepare(&refs[..group.len()]) {
                packed.clear();
                break;
            }
            packed.push(sources);
        }
    }
    for m in 0..256usize {
        for (c, &(i, _)) in cco.iter_mut().zip(&leaf.conv_sources) {
            *c = &kernel[(m + 256 - i as usize) & 255];
        }
        let cco = &cco[..count];
        let row = g_pow[m];
        let dst = &mut out[row * w..row * w + w];
        if packed.is_empty() {
            fold_into_prepared(dst, cptrs, cco, w);
        } else {
            for (group, sources) in packed.iter().enumerate() {
                let start = group * 4;
                let end = (start + 4).min(cco.len());
                if cco[start..end].iter().all(|c| c.coeff() == 1) {
                    fold_into_prepared(dst, &cptrs[start..end], &cco[start..end], w);
                } else {
                    let done = sources.fold(dst, &cco[start..end]);
                    assert_eq!(done, w);
                }
            }
        }
    }
}

/// `NZBFAST_NTT_PROFILE=1`: nanoseconds spent per tree depth (0-2 =
/// combine stages, 3 = leaves), summed over every worker's stripes,
/// and the number of leaf and combine evaluations. Read once at the
/// end of a transform by [`FlatPlan::profile_report`]; a research
/// knob, nothing ships it.
static PROFILE_NS: [std::sync::atomic::AtomicU64; 4] = [
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
];
fn profiling() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NZBFAST_NTT_PROFILE").is_some())
}

impl FlatPlan {
    /// The per-depth split accumulated so far, in seconds, when
    /// profiling is on (see [`PROFILE_NS`]); zeros otherwise.
    pub fn profile_report() -> [f64; 4] {
        let mut r = [0f64; 4];
        for (i, slot) in PROFILE_NS.iter().enumerate() {
            r[i] = slot.swap(0, std::sync::atomic::Ordering::Relaxed) as f64 / 1e9;
        }
        r
    }
}

/// Which leaf kernel a leaf is admitted to, as [`eval`]'s dispatch
/// decides it: the additive FFT first (by fill), then the paired
/// conjugate kernel, then the dense Rader fold.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LeafKernel {
    Dense,
    Paired,
    Additive,
}

/// What [`FlatPlan::leaf_fill`] reports: how full this plan's leaves
/// are, and which leaf kernel each one is admitted to.
///
/// This exists because a leaf-kernel A/B is UNREADABLE without it. Round
/// BL (7 Sep 2026) raced the additive leaf on a heavy repair shape and
/// measured -0.1% wall over six legs; a flat result like that cannot
/// distinguish "the kernel ran and bought nothing" from "the fill gate
/// refused it and it never ran at all", and it took a seventh leg forcing
/// `NZBFAST_NTT_ADDITIVE_MIN=0` (+11.8% wall) to establish it was the
/// second. The planner knows the answer before a single stripe is
/// transformed; this reports it.
pub struct LeafFill {
    /// Live leaves in the plan (a structurally dead subtree has none).
    pub leaves: usize,
    /// Sources across all leaves, counting each leaf's `x0` occupant.
    /// Larger than the present set: one source reaches several leaves.
    pub sources: usize,
    /// Sources in the emptiest leaf, the upper median leaf (element
    /// `leaves / 2` of the ascending list), and the fullest.
    pub min: usize,
    pub median: usize,
    pub max: usize,
    /// Leaves admitted to each kernel, summing to `leaves`.
    pub dense: usize,
    pub paired: usize,
    pub additive: usize,
    /// The additive kernel's fill gate in force (`MIN_SOURCES`, or
    /// `NZBFAST_NTT_ADDITIVE_MIN`), so a reader can see the threshold
    /// the `max` above did or did not clear. `None` when the additive
    /// kernel is off or unbuildable, which is itself the answer.
    pub additive_gate: Option<usize>,
}

impl std::fmt::Display for LeafFill {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "leaves {} sources {} fill min {} median {} max {} kernels dense {} paired {} additive {} gate ",
            self.leaves,
            self.sources,
            self.min,
            self.median,
            self.max,
            self.dense,
            self.paired,
            self.additive,
        )?;
        match self.additive_gate {
            Some(g) => write!(f, "{g}"),
            None => f.write_str("off"),
        }
    }
}

impl FlatPlan {
    /// This plan's leaf fill distribution and kernel admission, walked
    /// once over the built tree. Off every hot path: the transform never
    /// calls it, and it is O(leaves) against a build that is already
    /// O(65535).
    ///
    /// STATED LIMIT on the `paired` count: [`conjugate::leaf`] ALSO
    /// refuses at run time on the stripe width (`w % 32 != 0`) and on a
    /// scratch pool too small for `count` sources, neither of which the
    /// plan knows. A leaf counted `paired` here therefore means "the
    /// additive kernel did not take it and the paired kernel exists on
    /// this CPU", and at an unaccepted width it runs dense. The
    /// `additive` count has no such caveat - `Kernel::admits` is the
    /// whole gate, and it is a pure function of the fill.
    pub fn leaf_fill(&self) -> LeafFill {
        let mut counts: Vec<usize> = Vec::new();
        collect_leaf_counts(&self.root, &mut counts);
        counts.sort_unstable();
        let leaves = counts.len();
        let mut fill = LeafFill {
            leaves,
            sources: counts.iter().sum(),
            min: counts.first().copied().unwrap_or(0),
            median: counts.get(leaves / 2).copied().unwrap_or(0),
            max: counts.last().copied().unwrap_or(0),
            dense: 0,
            paired: 0,
            additive: 0,
            additive_gate: self.additive.as_ref().map(|_| additive::min_sources()),
        };
        for count in counts {
            // The same order `eval` dispatches in, and the same
            // predicates - a second copy of the rule would be exactly
            // the way this report goes quietly wrong.
            match self.leaf_kernel(count) {
                LeafKernel::Additive => fill.additive += 1,
                LeafKernel::Paired => fill.paired += 1,
                LeafKernel::Dense => fill.dense += 1,
            }
        }
        fill
    }

    /// The kernel [`eval`] admits a leaf of `count` sources to, modulo
    /// the width-dependent paired refusals documented on
    /// [`Self::leaf_fill`].
    fn leaf_kernel(&self, count: usize) -> LeafKernel {
        if self.additive.as_ref().is_some_and(|k| k.admits(count)) {
            LeafKernel::Additive
        } else if self.paired.is_some() && count > 0 {
            LeafKernel::Paired
        } else {
            LeafKernel::Dense
        }
    }

    /// Report the fill once, at plan build. `debug` normally; `info`
    /// under `NZBFAST_NTT_FILL=1`, which is what a bench round sets so
    /// the line reaches an ordinary release run's log with no rebuild
    /// and no log-level change. The `[ntt-fill]` tag is the anchor a
    /// harness greps for.
    fn report_leaf_fill(&self) {
        let fill = self.leaf_fill();
        if fill_loud() {
            tracing::info!(target: "repair-timing", "[ntt-fill] needed {} {fill}", self.needed);
        } else {
            tracing::debug!(target: "repair-timing", "[ntt-fill] needed {} {fill}", self.needed);
        }
    }
}

fn fill_loud() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NZBFAST_NTT_FILL").is_some())
}

/// Sources per live leaf, in tree order (`leaf_fill` sorts).
fn collect_leaf_counts(node: &Node, out: &mut Vec<usize>) {
    match node {
        Node::Leaf(leaf) => out.push(leaf.conv_sources.len() + usize::from(leaf.x0.is_some())),
        Node::Combine(c) => {
            for child in &c.child_nodes {
                collect_leaf_counts(child, out);
            }
        }
    }
}

/// Post-order evaluation. Children write into the next depth's pool;
/// sibling slots are disjoint by construction and cousins reuse them
/// only after the parent has consumed its children (depth-first order),
/// so the raw pool pointer never aliases a live borrow.
fn eval(
    node: &Node,
    plan: &FlatPlan,
    src_of: &dyn Fn(SrcId) -> *const u8,
    w: usize,
    depth: usize,
    scratch: *mut Scratch,
    out: &mut [u16],
) {
    let t_node = profiling().then(std::time::Instant::now);
    match node {
        Node::Leaf(leaf) => {
            // SAFETY: `scratch` is the exclusive &mut Scratch that transform
            // cast to a raw pointer, valid for the whole recursion; the
            // paired scratch is a byte pool of its own, disjoint from the
            // u16 pools the leaf's rows live in.
            let count = leaf.conv_sources.len() + usize::from(leaf.x0.is_some());
            let handled = plan.additive.as_ref().is_some_and(|k| {
                if !k.admits(count) {
                    return false;
                }
                // SAFETY: `scratch` is the exclusive &mut Scratch that
                // transform cast to a raw pointer, valid for the whole
                // recursion; the additive rows are a u16 pool of their
                // own, disjoint from the pools the leaf's rows live in.
                unsafe {
                    additive::leaf(
                        k,
                        leaf,
                        &plan.g_pow,
                        src_of,
                        w,
                        out,
                        &mut (*scratch).additive_scratch,
                    )
                }
            });
            // SAFETY: as above; the paired scratch is a byte pool of its
            // own, disjoint from the u16 pools the leaf's rows live in.
            let handled = handled
                || plan.paired.as_ref().is_some_and(|k| unsafe {
                    conjugate::leaf(
                        k,
                        leaf,
                        &plan.g_pow,
                        src_of,
                        w,
                        out,
                        &mut (*scratch).paired_scratch,
                    )
                });
            if !handled {
                leaf_dense(
                    leaf,
                    plan.kernel_prepared,
                    plan.one,
                    &plan.g_pow,
                    src_of,
                    w,
                    out,
                );
            }
        }
        Node::Combine(c) => {
            // SAFETY: scratch is the exclusive &mut Scratch that
            // transform cast to a raw pointer; it stays valid for the
            // whole recursion and only row pointers are derived from
            // it here (no long-lived reference), per the aliasing
            // argument in this function's doc comment.
            let (child_pool, child_rows): (*mut u16, usize) = unsafe {
                match depth {
                    0 => ((*scratch).depth1.as_mut_ptr(), (*scratch).rows1),
                    1 => ((*scratch).depth2.as_mut_ptr(), (*scratch).rows2),
                    2 => ((*scratch).leaf.as_mut_ptr(), 257),
                    _ => unreachable!(),
                }
            };
            for child in &c.child_nodes {
                let b = child_buf(child);
                // SAFETY: slot b spans child_rows*w words inside the
                // depth pool; sibling slots are disjoint by
                // construction and cousins reuse a slot only after the
                // parent has consumed its children (see the fn doc),
                // so this exclusive slice aliases no other live
                // borrow.
                let cbuf = unsafe {
                    std::slice::from_raw_parts_mut(
                        child_pool.add(b * child_rows * w),
                        child_rows * w,
                    )
                };
                eval(child, plan, src_of, w, depth + 1, scratch, cbuf);
            }
            // out[k] = Σ_j coeff(k,j) · child_j[k mod q].
            let nc = c.children.len();
            // The small-prime radices are 3, 5 and 17. This pointer list is
            // rebuilt per node per stripe, so keep it off the allocator.
            let mut srcs = [std::ptr::null(); 17];
            out[..c.rows * w].fill(0);
            for i in 0..c.rows {
                // Output rows sharing a child row run back to back, so
                // that row is read once and stays in L1 across all of
                // them - see `grouped_order`. Every row is still
                // written exactly once, by the same fold.
                let k = c.order.as_ref().map_or(i, |o| o[i] as usize);
                let s = c
                    .selected_child_rows
                    .as_ref()
                    .map_or_else(|| k % c.q, |rows| rows[k]);
                for (j, &b) in c.children.iter().enumerate() {
                    // SAFETY: points at row s of child slot b inside
                    // the depth pool, in bounds per the slot layout
                    // invariant in this function's doc comment; the
                    // cbuf borrows from the loop above have ended, so
                    // these raw reads alias no live &mut.
                    srcs[j] = unsafe { child_pool.add(b * child_rows * w + s * w) as *const u8 };
                }
                let co = &c.coeffs[k * nc..(k + 1) * nc];
                fold_into(&mut out[k * w..k * w + w], &srcs[..nc], co, w);
            }
        }
    }
    if let Some(t) = t_node {
        // A combine's own time is its total less its children's, which
        // the children have already booked at their depths; leaves book
        // everything at slot 3. Recorded as inclusive per depth, with
        // the children's inclusive time subtracted by the caller's
        // arithmetic in the report.
        let slot = match node {
            Node::Leaf(_) => 3,
            Node::Combine(_) => depth.min(2),
        };
        PROFILE_NS[slot].fetch_add(
            t.elapsed().as_nanos() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545F4914F6CDD1D)
        }
        fn word(&mut self) -> u16 {
            (self.next() >> 32) as u16
        }
    }

    /// The n smallest naturals coprime to 65535 (the product's
    /// input_base_logs, replicated to keep this module self-contained).
    fn logs(n: usize) -> Vec<u32> {
        let mut out = Vec::with_capacity(n);
        let mut k = 0u32;
        while out.len() < n {
            k += 1;
            if !k.is_multiple_of(3)
                && !k.is_multiple_of(5)
                && !k.is_multiple_of(17)
                && !k.is_multiple_of(257)
            {
                out.push(k);
            }
        }
        out
    }

    /// Reference syndrome, accumulated exactly the way the shipped fold
    /// does (same tables, same xor path).
    fn syndrome_ref(present: &[(u32, Vec<u16>)], e: u32, w: usize) -> Vec<u16> {
        let mut s = vec![0u16; w];
        for (log, data) in present {
            let t = gf16::MulTable::new(gf16::pow2(*log as u64 * e as u64 % N as u64));
            t.xor_mul_words(&mut s, data);
        }
        s
    }

    fn run_case(n_slices: usize, holes: usize, w: usize, needed: usize, seed: u64) {
        let all = logs(n_slices);
        let mut rng = Rng(seed);
        let mut present: Vec<(u32, Vec<u16>)> = Vec::new();
        for (i, &log) in all.iter().enumerate() {
            if i % holes == 0 {
                continue;
            }
            present.push((log, (0..w).map(|_| rng.word()).collect()));
        }
        let ids: Vec<(u32, SrcId)> = present
            .iter()
            .enumerate()
            .map(|(i, (l, _))| (*l, i as SrcId))
            .collect();
        let plan = FlatPlan::build(&ids, needed).unwrap();
        let mut scratch = plan.new_scratch(w);
        let mut out = vec![0u16; needed * w];
        let src_of = |s: SrcId| present[s as usize].1.as_ptr() as *const u8;
        plan.transform(&src_of, w, &mut scratch, &mut out);
        for e in 0..needed {
            let want = syndrome_ref(&present, e as u32, w);
            assert_eq!(&out[e * w..(e + 1) * w], &want[..], "e={e} w={w}");
        }
    }

    #[test]
    fn matches_fold_reference_scalar_width() {
        // w=8 is below the fused kernel's granule: full scalar path.
        run_case(500, 7, 8, 80, 0xA5);
    }

    #[test]
    fn grouped_order_is_a_permutation_that_groups_child_rows() {
        // Every output row exactly once, in an order where a child row
        // is contiguous. Losing either half loses a row of the
        // transform, which `matches_fold_reference_kernel_width` sees
        // only at the one shape it runs.
        let rows: Vec<usize> = (0..900).map(|k| k % 257).collect();
        let order = grouped_order(&rows).expect("900 rows over 257 residues repeat");
        let mut seen = vec![false; rows.len()];
        for &k in &order {
            assert!(!seen[k as usize], "row {k} twice");
            seen[k as usize] = true;
        }
        assert!(seen.into_iter().all(|s| s), "a row went missing");
        let mut runs: Vec<usize> = order.iter().map(|&k| rows[k as usize]).collect();
        let contiguous = runs.clone();
        runs.dedup();
        assert_eq!(runs.len(), 257, "a residue class was split");
        assert!(contiguous.windows(2).all(|p| p[0] <= p[1]));
        // Nothing to group when every output row has its own child row.
        assert!(grouped_order(&(0..200).map(|k| k % 257).collect::<Vec<_>>()).is_none());
    }

    #[test]
    fn the_stage_above_the_leaves_groups_at_a_heavy_repair_shape() {
        // The claim `grouped_order` is made on is that the grouping
        // reaches the stage above the leaves whenever `needed > 257`,
        // and nothing below it. A plan whose depth-2 combine came back
        // ungrouped would leave the whole lever inert with every test
        // above still green.
        fn depth2_orders(node: &Node, depth: usize, out: &mut Vec<bool>) {
            if let Node::Combine(c) = node {
                if depth == 2 {
                    out.push(c.order.is_some());
                }
                for child in &c.child_nodes {
                    depth2_orders(child, depth + 1, out);
                }
            }
        }
        let present: Vec<(u32, SrcId)> = (0..2000u32).map(|i| (i * 7 + 1, i)).collect();
        for (needed, want) in [(900usize, true), (1500, true), (256, false)] {
            let plan = FlatPlan::build(&present, needed).unwrap();
            let mut got = Vec::new();
            depth2_orders(&plan.root, 0, &mut got);
            assert!(
                !got.is_empty(),
                "needed {needed}: no depth-2 combine reached"
            );
            assert!(
                got.iter().all(|&g| g == want),
                "needed {needed}: wanted grouping {want}, got {got:?}"
            );
        }
    }

    #[test]
    fn the_plan_reports_its_leaf_fill_and_kernel_admission() {
        // The report exists so a leaf-kernel A/B is READABLE: round BL
        // (7 Sep 2026) measured the additive leaf flat on a heavy repair
        // and needed a seventh forced-arm leg to learn the kernel had
        // never run. A report that silently went inert - all zeros, or a
        // fill that stopped tracking the decimation - would put that leg
        // back, with every other test here still green. So pin the
        // geometry, and pin the gate crossing on both sides.
        //
        // The geometry is fixed by the decimation and the PAR2 constant
        // sequence, not by a measurement: base logs are coprime to
        // 65535 = 3*5*17*257, so exactly 2*4*16 = 128 of the 255 leaves
        // are live and the first `n` constants spread over them within
        // one source of n/128.
        for (n, leaves, min, median, max) in [
            (2_048usize, 128usize, 15usize, 16usize, 17usize),
            (8_192, 128, 63, 64, 65),
            // The gate's own boundary: 128*128 sources is the first
            // fill at which any leaf reaches MIN_SOURCES.
            (16_384, 128, 127, 128, 129),
            (16_512, 128, 128, 129, 130),
            // Round BL's own present count, had it arrived in ONE
            // retention window rather than the budget-sized windows the
            // fold worker actually feeds.
            (29_696, 128, 231, 232, 233),
        ] {
            let logs = crate::par2repair::input_base_logs(n).unwrap();
            let present: Vec<(u32, SrcId)> = logs
                .iter()
                .enumerate()
                .map(|(i, &l)| (l, i as SrcId))
                .collect();
            let plan = FlatPlan::build(&present, 1500).unwrap();
            let fill = plan.leaf_fill();
            assert_eq!(
                (fill.leaves, fill.sources, fill.min, fill.median, fill.max),
                (leaves, n, min, median, max),
                "n={n}: {fill}"
            );
            assert_eq!(
                fill.dense + fill.paired + fill.additive,
                fill.leaves,
                "n={n}: every leaf takes exactly one kernel: {fill}"
            );
            // The admission half, held against the gate the plan
            // actually carries rather than against MIN_SOURCES - the
            // env knob moves it, and this line must not go green by
            // agreeing with a second copy of the rule.
            if let Some(gate) = fill.additive_gate {
                let want = if max < gate {
                    0
                } else if min >= gate {
                    leaves
                } else {
                    // Straddling the gate: the exact split needs the
                    // histogram, but that it is a SPLIT is the property
                    // the report exists to show.
                    assert!(
                        fill.additive > 0 && fill.additive < leaves,
                        "n={n}: fill straddles gate {gate} but admission does not: {fill}"
                    );
                    fill.additive
                };
                assert_eq!(fill.additive, want, "n={n} gate {gate}: {fill}");
            } else {
                assert_eq!(fill.additive, 0, "n={n}: kernel off but leaves admitted");
            }
        }
    }

    #[test]
    fn a_range_plan_reports_the_same_leaf_fill_as_a_prefix_plan() {
        // `build_range` reaches the leaves through `build_node_range`,
        // which hands 257-slot nodes back to `build_node` - so the fill
        // is a property of the present set alone and the two builders
        // must agree. The repair side is the one that builds ranges, and
        // it is the side the report was asked for.
        let logs = crate::par2repair::input_base_logs(8_192).unwrap();
        let present: Vec<(u32, SrcId)> = logs
            .iter()
            .enumerate()
            .map(|(i, &l)| (l, i as SrcId))
            .collect();
        let prefix = FlatPlan::build(&present, 900).unwrap().leaf_fill();
        let range = FlatPlan::build_range(&present, 8_192, 900)
            .unwrap()
            .leaf_fill();
        assert_eq!(
            (prefix.leaves, prefix.min, prefix.median, prefix.max),
            (range.leaves, range.min, range.median, range.max),
            "prefix {prefix} vs range {range}"
        );
        assert_eq!(prefix.additive, range.additive);
    }

    #[test]
    fn matches_fold_reference_kernel_width() {
        // w=64 exercises the fused kernel; needed past 257 exercises the
        // leaf-row wraparound in the combine stages.
        run_case(2500, 11, 64, 300, 0x51);
    }

    // ---- The leaf differential harness ----------------------------
    //
    // ONE leaf, evaluated against a scalar reference straight from the
    // Rader identity, over random blocks, random source sets from
    // n_leaf 1 to 256 with the x0 slot present and absent, both the
    // real kernel and random ones, and stripe widths on both sides of
    // the fused kernel's granule. Bit-identity, not tolerance: this is
    // exact arithmetic in GF(2^16), so any correct method agrees word
    // for word.
    //
    // It exists to hold a SECOND leaf method to the shipped one. The
    // leaves are 92-95% of the transform (audit section 17), so the
    // only algorithmic lever left inside it is a cheaper length-256
    // cyclic convolution; add the new method as a third arm in
    // `leaf_case` and nothing about it ships until this is green. A
    // Karatsuba split was built and measured that way on 2 Sep 2026 -
    // bit-identical here on its first run on two ISAs, and 1.02-1.08x
    // on the leg the keep rule named, so it was not kept. The shape a
    // third arm takes is in that commit; the numbers and the cost model
    // that predicts them are in audit section 18.

    /// The leaf, straight from the definition: X[0] = Σ x, and
    /// X[g^m] = x0 + Σ_i a_i·b[(m-i) mod 256].
    fn leaf_reference(
        conv: &[(u16, Vec<u16>)],
        x0: Option<&Vec<u16>>,
        kernel: &[u16; 256],
        g_pow: &[usize; 256],
        w: usize,
    ) -> Vec<u16> {
        let mut out = vec![0u16; 257 * w];
        for (_, d) in conv {
            for t in 0..w {
                out[t] ^= d[t];
            }
        }
        if let Some(d) = x0 {
            for t in 0..w {
                out[t] ^= d[t];
            }
        }
        // One table per kernel value, not per (row, source): the table
        // build is ~1.2 KB of setup and this reference would otherwise
        // do 65,536 of them at full width.
        let tables: Vec<gf16::MulTable> = kernel.iter().map(|&c| gf16::MulTable::new(c)).collect();
        for m in 0..256usize {
            let row = g_pow[m];
            for (i, d) in conv {
                let t = (m + 256 - *i as usize) & 255;
                if kernel[t] == 0 {
                    continue;
                }
                // The same primitive `syndrome_ref` above holds the
                // whole transform to - independent of every line the
                // leaf evaluators share.
                tables[t].xor_mul_words(&mut out[row * w..row * w + w], d);
            }
            if let Some(d) = x0 {
                for t in 0..w {
                    out[row * w + t] ^= d[t];
                }
            }
        }
        out
    }

    /// One differential case: `n_leaf` sources at random Rader indices,
    /// `x0` present or not, this `kernel`, this stripe width.
    fn leaf_case(n_leaf: usize, with_x0: bool, w: usize, kernel: &[u16; 256], seed: u64) {
        let (g_pow, ip, _) = rader_tables();
        let mut rng = Rng(seed);
        // Random subset of the 256 Rader indices, in the sorted order
        // build_node produces.
        let mut idx: Vec<u16> = (0..256u16).collect();
        for k in (1..idx.len()).rev() {
            idx.swap(k, (rng.next() % (k as u64 + 1)) as usize);
        }
        idx.truncate(n_leaf);
        idx.sort_unstable();
        let blocks: Vec<Vec<u16>> = (0..n_leaf + 1)
            .map(|_| (0..w).map(|_| rng.word()).collect())
            .collect();
        let conv: Vec<(u16, Vec<u16>)> = idx
            .iter()
            .enumerate()
            .map(|(k, &i)| (i, blocks[k].clone()))
            .collect();
        let x0 = with_x0.then(|| &blocks[n_leaf]);

        // The plan's slot layout: conv_sources carries (rader index,
        // src id) and x0 the occupant of local slot 0. Source ids index
        // `blocks`; `ip` is unused here beyond asserting the tables the
        // production builder feeds the same struct.
        assert_eq!(ip[g_pow[0]], 0, "rader tables self-consistent");
        let leaf = LeafPlan {
            buf: 0,
            conv_sources: idx
                .iter()
                .enumerate()
                .map(|(k, &i)| (i, k as SrcId))
                .collect(),
            x0: with_x0.then_some(n_leaf as SrcId),
        };
        // Input byte stripes need not be word-aligned. Exercise that
        // contract, including the additive leaf's saved x0 source.
        let input_bytes: Vec<Vec<u8>> = blocks
            .iter()
            .map(|b| {
                std::iter::once(0x9b)
                    .chain(b.iter().flat_map(|w| w.to_le_bytes()))
                    .collect()
            })
            .collect();
        let src_of = |id: SrcId| input_bytes[id as usize].as_ptr().wrapping_add(1);

        let want = leaf_reference(&conv, x0, kernel, &g_pow, w);

        let mut dense = vec![0u16; 257 * w];
        let prepared = prepare_kernel(kernel);
        leaf_dense(
            &leaf,
            &prepared,
            &gf16::FoldCoeff::new(1),
            &g_pow,
            &src_of,
            w,
            &mut dense,
        );
        assert_eq!(dense, want, "dense: n_leaf={n_leaf} x0={with_x0} w={w}");

        // The paired leaf, wherever this CPU can run it, against the same
        // reference: a stripe width the kernel takes (it refuses others),
        // and the REAL Rader kernel - the pairing needs entry j + 128 to be
        // entry j's conjugate, so `Kernel::build` refuses the random and
        // zero-laden kernels this rig also feeds, and they exercise the
        // dense leaf alone.
        if let Some(paired) = conjugate::Kernel::new_forced(kernel) {
            let mut out = vec![0u16; 257 * w];
            let mut scratch = vec![0u8; conjugate::scratch_cap(w)];
            let handled =
                conjugate::leaf(&paired, &leaf, &g_pow, &src_of, w, &mut out, &mut scratch);
            if w.is_multiple_of(32) {
                assert!(handled, "paired leaf refused w={w} n_leaf={n_leaf}");
                assert_eq!(out, want, "paired: n_leaf={n_leaf} x0={with_x0} w={w}");
            }
        }
        // The additive-FFT leaf works for ANY kernel (it is a general
        // cyclic convolution), so both kernels drive it; it takes every
        // stripe that is whole 16-word chunks.
        let additive = additive::Kernel::new(kernel).expect("the field's Cantor basis holds");
        // Both buffers may contain a previous leaf. In particular, the
        // pointwise fallback borrows an output row before final assembly.
        let mut out = vec![0xa53cu16; 257 * w];
        let mut scratch = vec![0x39c7u16; additive::scratch_words(w)];
        let handled = additive::leaf(&additive, &leaf, &g_pow, &src_of, w, &mut out, &mut scratch);
        assert_eq!(
            handled,
            w.is_multiple_of(16),
            "additive leaf admission w={w}"
        );
        if handled {
            assert_eq!(out, want, "additive: n_leaf={n_leaf} x0={with_x0} w={w}");
        }
    }

    #[test]
    fn leaf_methods_agree_bit_for_bit() {
        let (_, _, real_kernel) = rader_tables();
        let mut rng = Rng(0xC0FFEE);
        let mut random_kernel = [0u16; 256];
        for c in random_kernel.iter_mut() {
            *c = rng.word();
        }
        // Widths: 16 is under the fused kernel's 32-byte granule (pure
        // scalar tail), 512 is the production stripe, 173 is odd and
        // straddles both. The full n sweep runs at w=16, which is where
        // a wrong index shows up just as loudly and costs a hundredth
        // of the wall; the wider widths re-run the boundary counts to
        // cover the kernel and tail split.
        for &n in &[1usize, 2, 3, 7, 8, 9, 16, 31, 64, 127, 128, 129, 255, 256] {
            for &x0 in &[false, true] {
                leaf_case(n, x0, 16, &real_kernel, 0x51EED ^ (n as u64) << 8);
                leaf_case(n, x0, 16, &random_kernel, 0xBEEF ^ (n as u64) << 8);
            }
        }
        for &(w, ns) in &[
            (173usize, &[1usize, 9, 64, 129, 256][..]),
            (512, &[1usize, 127, 256][..]),
            // 1,024 is the x86 production stripe at blocks of 1 MiB and
            // up (`default_stripe_words`); a FULL leaf there (256 + x0)
            // must be taken by the paired kernel - `assert!(handled)`
            // below is what a scratch sized for 512 words fails.
            (1024, &[129usize, 256][..]),
        ] {
            for &n in ns {
                for &x0 in &[false, true] {
                    let seed = 0x51EED ^ (n as u64) << 8 ^ w as u64;
                    leaf_case(n, x0, w, &real_kernel, seed);
                    leaf_case(n, x0, w, &random_kernel, seed ^ 0xBEEF);
                }
            }
        }
    }

    /// A zero coefficient anywhere in the kernel is legal input to the
    /// fused fold and must not change the answer - the split's
    /// `a0+a1` aliasing is the arm that could get this wrong.
    #[test]
    fn leaf_methods_agree_with_zero_coefficients() {
        let mut rng = Rng(0x2E20);
        let mut kernel = [0u16; 256];
        for c in kernel.iter_mut() {
            *c = if rng.next().is_multiple_of(3) {
                0
            } else {
                rng.word()
            };
        }
        for &n in &[5usize, 64, 200, 256] {
            leaf_case(n, true, 64, &kernel, 0x9A ^ n as u64);
            leaf_case(n, false, 64, &kernel, 0x9B ^ n as u64);
        }
    }

    /// Research rig, not a gate: one leaf timed across the densities
    /// real PAR2 sets produce, which is the curve any replacement leaf
    /// method has to beat. A leaf holds 256 usable slots and 128 leaves
    /// run, so `n_leaf` = input blocks / 128 - a 1 GiB set at 64 KiB
    /// (16,384 blocks) is 128, the PAR2 maximum of 32,768 blocks is 256.
    ///
    /// It is single-threaded with the whole leaf in L2, so it
    /// OVERSTATES any method that trades arithmetic for memory: the
    /// real transform runs one worker per core, each carrying ~15 MB of
    /// scratch. Price a candidate on a real leg before believing this
    /// (audit section 18).
    ///
    ///     cargo test --release -p nzbkit --lib par2ntt::tests::leaf_bench \
    ///       -- --ignored --nocapture
    #[test]
    #[ignore = "research rig: prints timings, asserts nothing"]
    fn leaf_bench() {
        let (g_pow, _, kernel) = rader_tables();
        let w: usize = std::env::var("NZBFAST_NTT_W")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(512);
        let reps: usize = std::env::var("LEAF_BENCH_REPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(40);
        let mut rng = Rng(0x1EAF);
        println!("leaf bench: w={w} reps={reps} (ms per leaf, best of 3)");
        println!(
            "{:>7} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
            "n_leaf", "dense", "paired", "additive", "", "", "", ""
        );
        // 104/112/120 are here because the additive leaf's crossover
        // landed INSIDE the old 96 -> 128 step on both boxes once its
        // second cut went in (7 Sep 2026): at 128 the additive leaf was
        // ahead by 2% on the M3 and 19% on the i5, at 96 behind by 24%
        // and 14%. A gate cannot be moved off a bracket that wide.
        for &n_leaf in &[32usize, 64, 96, 104, 112, 120, 128, 160, 192, 224, 256] {
            let mut idx: Vec<u16> = (0..256u16).collect();
            for k in (1..idx.len()).rev() {
                idx.swap(k, (rng.next() % (k as u64 + 1)) as usize);
            }
            idx.truncate(n_leaf);
            idx.sort_unstable();
            let blocks: Vec<Vec<u16>> = (0..n_leaf + 1)
                .map(|_| (0..w).map(|_| rng.word()).collect())
                .collect();
            let leaf = LeafPlan {
                buf: 0,
                conv_sources: idx
                    .iter()
                    .enumerate()
                    .map(|(k, &i)| (i, k as SrcId))
                    .collect(),
                x0: Some(n_leaf as SrcId),
            };
            let src_of = |id: SrcId| blocks[id as usize].as_ptr() as *const u8;
            let mut out = vec![0u16; 257 * w];
            let prepared = prepare_kernel(&kernel);
            let one = gf16::FoldCoeff::new(1);
            let ms = |t: std::time::Duration| t.as_secs_f64() * 1e3 / reps as f64;
            let mut best = f64::MAX;
            for _ in 0..3 {
                let t = std::time::Instant::now();
                for _ in 0..reps {
                    leaf_dense(&leaf, &prepared, &one, &g_pow, &src_of, w, &mut out);
                }
                best = best.min(ms(t.elapsed()));
            }
            // The paired leaf, forced (its admission is a separate
            // question), in the same scratch the transform gives it.
            let mut paired = f64::MAX;
            if let Some(k) = conjugate::Kernel::new_forced(&kernel) {
                let mut scratch = vec![0u8; conjugate::scratch_cap(w)];
                for _ in 0..3 {
                    let t = std::time::Instant::now();
                    for _ in 0..reps {
                        assert!(conjugate::leaf(
                            &k,
                            &leaf,
                            &g_pow,
                            &src_of,
                            w,
                            &mut out,
                            &mut scratch
                        ));
                    }
                    paired = paired.min(ms(t.elapsed()));
                }
            }
            // The additive-FFT leaf: a fixed cost per leaf, whatever the
            // fill, so its column is flat and the others cross it.
            let mut additive_ms = f64::MAX;
            if let Some(k) = additive::Kernel::new(&kernel) {
                let mut scratch = vec![0u16; additive::scratch_words(w)];
                for _ in 0..3 {
                    let t = std::time::Instant::now();
                    for _ in 0..reps {
                        assert!(additive::leaf(
                            &k,
                            &leaf,
                            &g_pow,
                            &src_of,
                            w,
                            &mut out,
                            &mut scratch
                        ));
                    }
                    additive_ms = additive_ms.min(ms(t.elapsed()));
                }
            }
            println!("{n_leaf:>7} {best:>9.3} {paired:>9.3} {additive_ms:>9.3}");
        }
    }

    /// How much of the dense leaf is the GF MULTIPLY, and how much is
    /// just touching the rows?
    ///
    /// The question decides whether the leaf's 256-point cyclic
    /// convolution is worth attacking algorithmically at all. Karatsuba
    /// (the only structural lever left - there is no length-256 NTT in
    /// GF(2^16)* and the ring is local in characteristic two, see the
    /// lane handoff) cuts the multiplies 65,536 -> 3^8 but pays for them
    /// with intermediate rows through memory. That trade is only worth
    /// making if the multiply is what the leaf is spending its time on.
    ///
    /// The control is the SAME access pattern with the multiply removed:
    /// 256 outputs, each accumulating `n_leaf` source rows, XOR only. It
    /// is not a candidate implementation - it computes nonsense - it is
    /// the floor that the real kernel's traffic cannot go below. So
    /// `dense / xor_floor` is the arithmetic headroom: at 1.1 the leaf
    /// is traffic-bound and Karatsuba is dead on arrival; at 4 there is
    /// something to win.
    ///
    /// Inherits `leaf_bench`'s bias and then some: single-threaded with
    /// the whole leaf in L2, so it UNDERSTATES the traffic side against
    /// a real transform running a worker per core over ~15 MB of
    /// scratch each. Read a low ratio as conclusive and a high one as
    /// permission to measure properly, never the other way round.
    ///
    ///     cargo test --release -p nzbkit-base --lib \
    ///       par2ntt::tests::leaf_cost_split -- --ignored --nocapture
    #[test]
    #[ignore = "research rig: prints timings, asserts nothing"]
    fn leaf_cost_split() {
        let (g_pow, _, kernel) = rader_tables();
        let w: usize = std::env::var("NZBFAST_NTT_W")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(512);
        let reps: usize = std::env::var("LEAF_BENCH_REPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(40);
        let mut rng = Rng(0x1EAF);
        println!("leaf cost split: w={w} reps={reps} (ms per leaf, best of 3)");
        println!(
            "{:>7} {:>10} {:>10} {:>8}",
            "n_leaf", "dense", "xor_floor", "ratio"
        );
        for &n_leaf in &[64usize, 128, 192, 256] {
            let mut idx: Vec<u16> = (0..256u16).collect();
            for k in (1..idx.len()).rev() {
                idx.swap(k, (rng.next() % (k as u64 + 1)) as usize);
            }
            idx.truncate(n_leaf);
            idx.sort_unstable();
            let blocks: Vec<Vec<u16>> = (0..n_leaf + 1)
                .map(|_| (0..w).map(|_| rng.word()).collect())
                .collect();
            let leaf = LeafPlan {
                buf: 0,
                conv_sources: idx
                    .iter()
                    .enumerate()
                    .map(|(k, &i)| (i, k as SrcId))
                    .collect(),
                x0: Some(n_leaf as SrcId),
            };
            let src_of = |id: SrcId| blocks[id as usize].as_ptr() as *const u8;
            let mut out = vec![0u16; 257 * w];
            let prepared = prepare_kernel(&kernel);
            let one = gf16::FoldCoeff::new(1);
            let ms = |t: std::time::Duration| t.as_secs_f64() * 1e3 / reps as f64;

            let mut dense = f64::MAX;
            for _ in 0..3 {
                let t = std::time::Instant::now();
                for _ in 0..reps {
                    leaf_dense(&leaf, &prepared, &one, &g_pow, &src_of, w, &mut out);
                }
                dense = dense.min(ms(t.elapsed()));
            }

            // The floor: every row the dense leaf reads, read and
            // accumulated the same number of times, with no multiply.
            let mut floor = f64::MAX;
            for _ in 0..3 {
                let t = std::time::Instant::now();
                for _ in 0..reps {
                    for m in 0..256usize {
                        let row = g_pow[m];
                        let dst = &mut out[row * w..row * w + w];
                        for (k, _) in leaf.conv_sources.iter().enumerate() {
                            let src = &blocks[k];
                            for (d, s) in dst.iter_mut().zip(src.iter()) {
                                *d ^= *s;
                            }
                        }
                    }
                }
                floor = floor.min(ms(t.elapsed()));
            }
            println!(
                "{n_leaf:>7} {dense:>10.3} {floor:>10.3} {:>8.2}",
                dense / floor
            );
        }
    }

    #[test]
    fn build_rejects_bad_input() {
        assert!(FlatPlan::build(&[], 10).is_err());
        assert!(FlatPlan::build(&[(1, 0)], 0).is_err());
        assert!(FlatPlan::build(&[(1, 0)], N + 1).is_err());
        assert!(FlatPlan::build(&[(65535, 0)], 10).is_err());
        assert!(
            FlatPlan::build(&[(1, 0), (1, 1)], 10).is_err(),
            "duplicate log"
        );
    }
}
