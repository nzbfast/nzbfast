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

use crate::gf16;

/// Transform length: the order of GF(65536)'s multiplicative group.
pub const N: usize = 65535;

const RADER_G: u64 = 3;
const LEAF_ROOT_LOG: u64 = 255;

/// Caller's identifier for one present slice (index into its slice
/// table); resolved to stripe data by the `src_of` callback.
pub type SrcId = u32;

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
    /// Live children buffer slots at depth+1, in class order.
    children: Vec<usize>,
    /// Raw GF coefficients, rows-major: coeffs[k*children.len() + j]
    /// = 2^{root_log · u_j · k}.
    coeffs: Vec<u16>,
    child_nodes: Vec<Node>,
}

enum Node {
    Leaf(LeafPlan),
    Combine(CombinePlan),
}

/// Immutable transform plan for one (present set, requested prefix).
pub struct FlatPlan {
    root: Node,
    g_pow: [usize; 256],
    /// b[t] = 2^{255·g^t} - the fixed Rader kernel, raw values.
    kernel: [u16; 256],
    /// Rows the root produces: max selected exponent + 1.
    pub(crate) needed: usize,
}

/// Per-worker scratch arenas: one pool per tree depth, reused across
/// stripes. Allocated once per worker outside any timed/hot region.
pub struct Scratch {
    w: usize,
    leaf: Vec<u16>,   // 17 slots x 257 rows
    depth2: Vec<u16>, // 5 slots x min(needed, 4369) rows
    rows2: usize,
    depth1: Vec<u16>, // 3 slots x min(needed, 21845) rows
    rows1: usize,
}

/// The Rader-257 tables: `g_pow[t] = 3^t mod 257`, the inverse-power
/// index `ip[s]` (so `a_i = x[g^{-i}]` is `conv_sources`' sort key), and
/// the fixed convolution kernel `b[t] = 2^{255·g^t}`. Fixed for the
/// life of the process; built per plan (~microseconds) rather than
/// cached, which keeps the tests able to drive a leaf on their own.
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
        let (g_pow, ip, kernel) = rader_tables();
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
        let root = build_node(&slots, 1, needed, 0, &ip).expect("nonempty set built no tree");
        Ok(FlatPlan {
            root,
            g_pow,
            kernel,
            needed,
        })
    }

    pub fn new_scratch(&self, w: usize) -> Scratch {
        let rows2 = self.needed.min(4369);
        let rows1 = self.needed.min(21845);
        Scratch {
            w,
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
    }

    /// Transform one stripe of `w` words. `src_of` resolves a SrcId to
    /// the stripe's byte pointer (at least `2*w` readable bytes).
    /// Writes syndrome rows 0..needed, rows-major, into `out`
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
fn build_node(
    slots: &[Option<SrcId>],
    root_log: u64,
    needed: usize,
    buf: usize,
    ip: &[u16; 257],
) -> Option<Node> {
    let n = slots.len();
    if slots.iter().all(|s| s.is_none()) {
        return None;
    }
    if n == 257 {
        debug_assert_eq!(root_log % N as u64, LEAF_ROOT_LOG);
        let mut conv_sources: Vec<(u16, SrcId)> = Vec::new();
        for (s, slot) in slots.iter().enumerate().skip(1) {
            if let Some(src) = slot {
                conv_sources.push((ip[s], *src));
            }
        }
        conv_sources.sort_unstable();
        return Some(Node::Leaf(LeafPlan {
            buf,
            conv_sources,
            x0: slots[0],
        }));
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
        let class: Vec<Option<SrcId>> = slots.iter().skip(u).step_by(p).copied().collect();
        debug_assert_eq!(class.len(), q);
        if let Some(node) = build_node(&class, root_log * p as u64, sub_needed, children.len(), ip)
        {
            children.push(child_buf(&node));
            child_nodes.push(node);
            lives.push(u);
        }
    }
    let rows = needed.min(n);
    let mut coeffs = vec![0u16; rows * lives.len()];
    for k in 0..rows {
        for (j, &u) in lives.iter().enumerate() {
            coeffs[k * lives.len() + j] = gf16::pow2(root_log * (u as u64) * (k as u64) % N as u64);
        }
    }
    Some(Node::Combine(CombinePlan {
        buf,
        rows,
        q,
        children,
        coeffs,
        child_nodes,
    }))
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
/// and the asymmetry is measured, not cautious. Codex's `0efd0ab97`
/// widened both x86 arms and its author then REJECTED the whole change:
/// isolated leaves retired 3.29% fewer instructions on AVX-512, but a
/// realistic 0.41 GiB / 1,500-missing Reconstructor gate ran native NTT
/// completion 14.8% SLOWER in every pair (hoisting dispatch: 19.9%).
/// On AVX-512 a 12-group is ONE batch, so nothing is filled and the only
/// effect is widening the leaf's memory order over more live sources.
///
/// On native GFNI/AVX2 silicon it is the other way round, which neither
/// audit measured - Codex only ever ran a FORCED AVX2 arm on an AVX-512
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
            if c != 0 {
                // SAFETY: as below - every src carries w*2 readable bytes
                // per `FlatPlan::transform`'s contract and `eval`'s pool
                // rows.
                let src = unsafe { std::slice::from_raw_parts(p, w * 2) };
                gf16::FoldTable::new(c).xor_mul_into(&mut dst[..w], src);
            }
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
                if c != 0 {
                    gf16::FoldTable::new(c).xor_mul_into(&mut dst[done..w], &src[done * 2..w * 2]);
                }
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
    kernel: &[u16; 256],
    g_pow: &[usize; 256],
    src_of: &dyn Fn(SrcId) -> *const u8,
    w: usize,
    out: &mut [u16],
) {
    debug_assert!(out.len() >= 257 * w);
    let mut ptrs: Vec<*const u8> = Vec::with_capacity(leaf.conv_sources.len() + 1);
    let mut ones: Vec<u16> = Vec::with_capacity(leaf.conv_sources.len() + 1);
    if let Some(x0) = leaf.x0 {
        ptrs.push(src_of(x0));
        ones.push(1);
    }
    for &(_, src) in &leaf.conv_sources {
        ptrs.push(src_of(src));
        ones.push(1);
    }
    out[..257 * w].fill(0);
    // X[0] = x[0] + every conv source, coefficient 1.
    fold_into(&mut out[..w], &ptrs, &ones, w);
    // X[g^m] = x[0] + Σ_i a_i · b[(m-i) mod 256].
    let x0_ptr = leaf.x0.map(src_of);
    let mut cptrs: Vec<*const u8> = Vec::with_capacity(leaf.conv_sources.len() + 1);
    let mut cco: Vec<u16> = Vec::with_capacity(leaf.conv_sources.len() + 1);
    for &(_, src) in &leaf.conv_sources {
        cptrs.push(src_of(src));
    }
    if let Some(p0) = x0_ptr {
        cptrs.push(p0);
    }
    for m in 0..256usize {
        cco.clear();
        for &(i, _) in &leaf.conv_sources {
            cco.push(kernel[(m + 256 - i as usize) & 255]);
        }
        if x0_ptr.is_some() {
            cco.push(1);
        }
        let row = g_pow[m];
        fold_into(&mut out[row * w..row * w + w], &cptrs, &cco, w);
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
        Node::Leaf(leaf) => leaf_dense(leaf, &plan.kernel, &plan.g_pow, src_of, w, out),
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
            let mut srcs: Vec<*const u8> = vec![std::ptr::null(); nc];
            out[..c.rows * w].fill(0);
            for k in 0..c.rows {
                let s = k % c.q;
                for (j, &b) in c.children.iter().enumerate() {
                    // SAFETY: points at row s of child slot b inside
                    // the depth pool, in bounds per the slot layout
                    // invariant in this function's doc comment; the
                    // cbuf borrows from the loop above have ended, so
                    // these raw reads alias no live &mut.
                    srcs[j] = unsafe { child_pool.add(b * child_rows * w + s * w) as *const u8 };
                }
                let co = &c.coeffs[k * nc..(k + 1) * nc];
                fold_into(&mut out[k * w..k * w + w], &srcs, co, w);
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
        let src_of = |id: SrcId| blocks[id as usize].as_ptr() as *const u8;

        let want = leaf_reference(&conv, x0, kernel, &g_pow, w);

        let mut dense = vec![0u16; 257 * w];
        leaf_dense(&leaf, kernel, &g_pow, &src_of, w, &mut dense);
        assert_eq!(dense, want, "dense: n_leaf={n_leaf} x0={with_x0} w={w}");
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
            "n_leaf", "dense", "k/256", "k/128", "k/64", "k/32", "k/16", "k/8"
        );
        for &n_leaf in &[32usize, 64, 96, 128, 160, 192, 224, 256] {
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
            let ms = |t: std::time::Duration| t.as_secs_f64() * 1e3 / reps as f64;
            let mut best = f64::MAX;
            for _ in 0..3 {
                let t = std::time::Instant::now();
                for _ in 0..reps {
                    leaf_dense(&leaf, &kernel, &g_pow, &src_of, w, &mut out);
                }
                best = best.min(ms(t.elapsed()));
            }
            println!("{n_leaf:>7} {best:>9.3}");
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
