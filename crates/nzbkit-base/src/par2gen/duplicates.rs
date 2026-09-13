//! Opt-in grouping of identical blocks in an already-digested fused window.
//! Only indices and coefficients survive preparation. No additional payload
//! allocation, hashing, read pass or dependency on future windows is introduced.
use super::row_coeff;

const MAX_SOURCES: usize = 64;
const MAX_ROWS: usize = 128;

fn eligible(bs: usize, rows: usize, sources: usize) -> bool {
    bs >= 1 << 20 && (32..=MAX_ROWS).contains(&rows) && (2..=MAX_SOURCES).contains(&sources)
}

pub(super) fn enabled(bs: usize, rows: usize, sources: usize) -> bool {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) || !eligible(bs, rows, sources) {
        return false;
    }
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        matches!(
            std::env::var("NZBFAST_PAR2GEN_DUPLICATES").as_deref(),
            Ok("1") | Ok("on")
        )
    })
}

/// Fixed-capacity, stack-owned metadata: under 17 KiB, no heap allocation.
/// An unchanged all-unique window needs no plan and takes the original fold.
pub(super) struct Plan {
    representatives: [usize; MAX_SOURCES],
    coefficients: [[u16; MAX_SOURCES]; MAX_ROWS],
    count: usize,
    rows: usize,
    sources: usize,
    bs: usize,
}

pub(super) fn prepare(
    arena: &[u8],
    bs: usize,
    held: &[u32],
    first: usize,
    rows: usize,
    digests: &[([u8; 16], u32)],
) -> Option<Plan> {
    let sources = held.len();
    if bs == 0
        || !bs.is_multiple_of(2)
        || !(2..=MAX_SOURCES).contains(&sources)
        || rows == 0
        || rows > MAX_ROWS
        || digests.len() != sources
        || sources.checked_mul(bs) != Some(arena.len())
    {
        return None;
    }
    let mut representatives = [0; MAX_SOURCES];
    let mut group_of = [0usize; MAX_SOURCES];
    let mut count = 0;
    for i in 0..sources {
        let mut found = None;
        let mut comparisons = 0;
        for (g, &rep) in representatives[..count].iter().enumerate() {
            if digests[rep].0 != digests[i].0 {
                continue;
            }
            // Hash equality only nominates a candidate. Bound pathological
            // collision work; unmerged blocks still retain their coefficients.
            if comparisons == 4 {
                break;
            }
            comparisons += 1;
            if arena[i * bs..(i + 1) * bs] == arena[rep * bs..(rep + 1) * bs] {
                found = Some(g);
                break;
            }
        }
        group_of[i] = found.unwrap_or_else(|| {
            representatives[count] = i;
            count += 1;
            count - 1
        });
    }
    if count == sources {
        return None;
    }
    let mut plan = Plan {
        representatives,
        coefficients: [[0; MAX_SOURCES]; MAX_ROWS],
        count,
        rows,
        sources,
        bs,
    };
    for (j, row) in plan.coefficients[..rows].iter_mut().enumerate() {
        for (i, &log) in held.iter().enumerate() {
            row[group_of[i]] ^= row_coeff(log, first + j);
        }
    }
    Some(plan)
}

impl Plan {
    pub(super) fn fold(&self, acc: &mut [Vec<u16>], arena: &[u8]) {
        assert_eq!(acc.len(), self.rows);
        assert_eq!(arena.len(), self.sources * self.bs);
        let mut sources: [&[u8]; MAX_SOURCES] = [&[]; MAX_SOURCES];
        for (slot, &i) in sources.iter_mut().zip(&self.representatives[..self.count]) {
            *slot = &arena[i * self.bs..(i + 1) * self.bs];
        }
        crate::par2repair::linalg::fold_parallel(
            acc,
            &sources[..self.count],
            &|j, i| self.coefficients[j][i],
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_shape_and_metadata() {
        assert!(std::mem::size_of::<Plan>() < 17 * 1024);
        assert!(eligible(1 << 20, 32, 2));
        assert!(eligible(1 << 20, 128, 64));
        for (bs, rows, n) in [
            (1 << 19, 32, 8),
            (1 << 20, 31, 8),
            (1 << 20, 129, 8),
            (1 << 20, 32, 1),
            (1 << 20, 32, 65),
        ] {
            assert!(!eligible(bs, rows, n));
        }
        assert!(prepare(&[], 0, &[], 0, 4, &[]).is_none());
    }
    #[test]
    fn exact_groups_match_original_fold_and_collision_fallback() {
        for bs in [4, 68, 4096] {
            for n in [2, 8, 17, 64] {
                let held = crate::par2repair::input_base_logs(n).unwrap();
                for unique in [1, n / 2, n] {
                    let mut arena = vec![0; bs * n];
                    for (i, b) in arena.chunks_exact_mut(bs).enumerate() {
                        for (j, v) in b.iter_mut().enumerate() {
                            *v = (j * 37 + i % unique) as u8;
                        }
                    }
                    let keys = super::super::digest_window(&arena, n, bs);
                    for first in [0, 65532] {
                        let mut expected = vec![vec![0u16; bs / 2]; 4];
                        super::super::fold_batch(&mut expected, &arena, bs, &held, first, false);
                        for collision in [false, true] {
                            let forced = vec![([0; 16], 0); n];
                            let mut actual = vec![vec![0u16; bs / 2]; 4];
                            match prepare(
                                &arena,
                                bs,
                                &held,
                                first,
                                4,
                                if collision { &forced } else { &keys },
                            ) {
                                Some(p) => p.fold(&mut actual, &arena),
                                None => super::super::fold_batch(
                                    &mut actual,
                                    &arena,
                                    bs,
                                    &held,
                                    first,
                                    false,
                                ),
                            }
                            assert_eq!(actual, expected);
                        }
                    }
                }
            }
        }
    }
}
