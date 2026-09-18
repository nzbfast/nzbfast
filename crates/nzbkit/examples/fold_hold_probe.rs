//! How far a budgeted fold slice overruns its budget, and what the
//! indivisible unit under that overrun costs, against a COPY of a real
//! index DB. Never point it at a live index - the folds write.
//!
//!   cargo run --release -p nzbkit --features indexer \
//!     --example fold_hold_probe -- <copy.db> [slices]
//!
//! `FOLD=shatter|session|album` picks which fold; shatter is the
//! default and the one with a standing backlog on a real index.
//!
//! A budget of ZERO is the decomposition: the loop admits exactly one
//! unit and then finds itself past the deadline, so the call's wall IS
//! one unit. Everything above that at a real budget is the loop having
//! started a unit it had no time for - which is what
//! `index::foldpace` exists to stop, and what the A/B in section 11 of
//! research/INDEX-SCAN-CHUNK-SWEEP-2026-09-16.md measured with this.
//!
//! TAKE THE CLONE WITH `cp -c`. It is instant and costs no space, but
//! it is page cache COLD per vnode and copy-on-write, so the FIRST WAL
//! checkpoint against one costs seconds to minutes and is an artifact
//! of the rig rather than a number about any daemon (memory topic
//! `nzbfast-apfs-clone-is-page-cache-cold`). Read the max column with
//! that in mind; the p50 and p90 are the honest ones.

use std::path::Path;
use std::time::{Duration, Instant};

fn pct(v: &mut [u128], p: f64) -> u128 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    let i = (((v.len() - 1) as f64) * p).round() as usize;
    v[i]
}

fn run(ix: &mut nzbkit::index::Index, which: &str, budget: Duration, n: usize) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    let mut ms: Vec<u128> = Vec::new();
    let mut work = 0usize;
    for _ in 0..n {
        let t = Instant::now();
        let r = match which {
            "session" => ix.session_fold(now, budget),
            "album" => ix.album_fold(now, budget),
            _ => ix.shatter_fold(now, budget),
        };
        let took = t.elapsed();
        let (_, folded, done) = r.expect("fold");
        work += folded;
        ms.push(took.as_micros());
        if done {
            break;
        }
    }
    let over = |v: u128| v as f64 / 1000.0 - budget.as_secs_f64() * 1000.0;
    let (p50, p90, max) = (pct(&mut ms, 0.5), pct(&mut ms, 0.9), pct(&mut ms, 1.0));
    println!(
        "{which:<8} budget {:>6.0} ms  n {:>3}  rows {:>6}  \
         p50 {:>8.1} ({:+8.1})  p90 {:>8.1} ({:+8.1})  max {:>8.1} ({:+8.1})",
        budget.as_secs_f64() * 1000.0,
        ms.len(),
        work,
        p50 as f64 / 1000.0,
        over(p50),
        p90 as f64 / 1000.0,
        over(p90),
        max as f64 / 1000.0,
        over(max),
    );
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: fold_hold_probe <index.db copy> [slices]");
    let n: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let which = std::env::var("FOLD").unwrap_or_else(|_| "shatter".into());
    let mut ix = nzbkit::index::Index::open(Path::new(&path)).expect("open");
    for b in [0u64, 250, 1000, 4000] {
        run(&mut ix, &which, Duration::from_millis(b), n);
    }
}
