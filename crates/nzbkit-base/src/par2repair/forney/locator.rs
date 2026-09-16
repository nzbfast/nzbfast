//! The locator polynomial `P(z) = Π_c (z + g_c)`, two ways.
//!
//! Every Forney plan starts here: `P` drives stage 1 (its coefficients
//! ARE the Hankel kernel) and its formal derivative gives stage 2's
//! per-column scales. The polynomial is the same either way; only the
//! cost of building it differs.
//!
//! - [`chain`] is the coefficient chain the plan has always used: one
//!   root at a time, `O(m^2)` field multiplies, no allocation past the
//!   answer itself. It is what runs when [`super::joint_gate`] says no -
//!   a build that asked for the shipped solve
//!   (`NZBFAST_FORNEY_JOINT=0`), or one on a kernel class the default
//!   does not yet cover. Every class this fleet has measured is covered
//!   since 12 Sep 2026, so on those parts this arm is the OPT-OUT
//!   rather than the default.
//! - The product tree in [`build`] splits the roots into [`LEAF`]-sized
//!   chunks, expands each by the same chain, and merges pairwise through
//!   [`super::poly::Context::multiply`] - `O(m log^2 m)` instead, at the
//!   cost of holding one level of partial products at a time.
//!
//! Both produce BYTE-IDENTICAL coefficients: the product is the same
//! product and the field is the same field, so the tree is a
//! re-association and nothing else. `locator_tree_matches_the_chain` in
//! `super::joint::tests` pins that at every shape the solve selects,
//! which is what allows the tree to be switched on without re-proving
//! the solve.
use crate::gf16::{self, MulTable};

/// Roots per leaf of the product tree. Below this the chain is cheaper
/// than a transform pair, and the leaves are what set the tree's own
/// working-set floor.
pub(super) const LEAF: usize = 64;

/// What a [`build`] held, so the constructor can charge it. A BOUND, not
/// a measurement - see [`super::poly::Context::peak_heap_bound`].
#[derive(Clone, Copy, Default)]
pub(super) struct Stats {
    pub(super) peak_heap_bound: usize,
    pub(super) cache_heap: usize,
}

/// `P(z) = Π (z + g)`, degree `bases.len()`, `p[i]` the `z^i`
/// coefficient. One root at a time, exactly as `invert_vandermonde`
/// expands the same product, because it IS the same factorization.
pub(super) fn chain(bases: &[u16]) -> Vec<u16> {
    let mut p = vec![0u16; bases.len() + 1];
    p[0] = 1;
    for (deg, &g) in bases.iter().enumerate() {
        let t = MulTable::new(g);
        p[deg + 1] = p[deg];
        for i in (1..=deg).rev() {
            p[i] = p[i - 1] ^ t.mul(p[i]);
        }
        p[0] = t.mul(p[0]);
    }
    p
}

/// A leaf of the product tree: the same chain without the multiply
/// table, which does not pay for itself over [`LEAF`] roots.
fn small(bases: &[u16]) -> Vec<u16> {
    let mut p = vec![0u16; bases.len() + 1];
    p[0] = 1;
    for (deg, &g) in bases.iter().enumerate() {
        p[deg + 1] = p[deg];
        for i in (1..=deg).rev() {
            p[i] = p[i - 1] ^ gf16::mul(g, p[i]);
        }
        p[0] = gf16::mul(g, p[0]);
    }
    p
}

/// The locator polynomial and what building it held. `tree` selects the
/// product tree; false is [`chain`] and the shipped default.
pub(super) fn build(bases: &[u16], tree: bool) -> (Vec<u16>, Stats) {
    if !tree {
        let p = chain(bases);
        let bytes = p.capacity() * 2;
        return (
            p,
            Stats {
                peak_heap_bound: bytes,
                cache_heap: 0,
            },
        );
    }
    if bases.is_empty() {
        return (
            vec![1],
            Stats {
                peak_heap_bound: 2,
                cache_heap: 0,
            },
        );
    }
    let mut ctx = super::poly::Context::new();
    let mut level: Vec<_> = bases.chunks(LEAF).map(small).collect();
    ctx.peak_heap_bound = level.iter().map(|p| p.capacity() * 2).sum::<usize>()
        + level.capacity() * std::mem::size_of::<Vec<u16>>()
        + ctx.cache_heap();
    while level.len() > 1 {
        let old_bytes = level.iter().map(|p| p.capacity() * 2).sum::<usize>()
            + level.capacity() * std::mem::size_of::<Vec<u16>>();
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut next_bytes = next.capacity() * std::mem::size_of::<Vec<u16>>();
        let mut it = level.into_iter();
        while let Some(a) = it.next() {
            let p = if let Some(b) = it.next() {
                ctx.multiply(&a, &b, old_bytes + next_bytes)
            } else {
                a
            };
            next_bytes += p.capacity() * 2;
            next.push(p);
        }
        level = next;
    }
    let mut p = level.pop().expect("the loop exits with exactly one level");
    ctx.peak_heap_bound = ctx.peak_heap_bound.max(
        ctx.cache_heap()
            + p.capacity() * 2
            + p.len() * 2
            + level.capacity() * std::mem::size_of::<Vec<u16>>(),
    );
    p.shrink_to_fit();
    let stats = Stats {
        peak_heap_bound: ctx.peak_heap_bound,
        cache_heap: ctx.cache_heap(),
    };
    (p, stats)
}
