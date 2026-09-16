use rayon::prelude::*;

/// The member decode pools' shared in-flight budget: `(bytes admitted but not
/// yet written, abort)` plus the condvar the feeder parks on.
pub(crate) type PoolBudget = (std::sync::Mutex<(u64, bool)>, std::sync::Condvar);

/// Sets a member pool's abort flag and wakes its feeder on EVERY exit from the
/// coordinator, including an unwind.
///
/// The feeder parks in one of two places and each needs its own wake-up:
///
/// * blocked in `work_tx.send` with the work queue full - only dropping the
///   work receiver frees it, which is what the `drop(work_rx)` in each pool is
///   for; a `notify_all` reaches nothing there.
/// * parked in `cvar.wait` with the byte budget charged - only a notify frees
///   it, and dropping the receiver reaches nothing there.
///
/// A coordinator that RETURNS covers the second case itself. A coordinator that
/// PANICS does not: `write_parallel_entry`, the caller's `open` closure, the
/// `Write` impl it hands back, and the inline (non-pooled) decode a coordinator
/// still does itself can all unwind straight past the abort-and-notify lines.
/// `thread::scope` then joins a feeder that nobody will ever wake, so the panic
/// never finishes propagating and the extraction hangs instead of failing.
/// Holding this guard across the coordinator closes that path, because a `Drop`
/// impl runs on both routes out.
pub(crate) struct PoolAbortGuard<'a>(&'a PoolBudget);

impl<'a> PoolAbortGuard<'a> {
    pub(crate) fn new(budget: &'a PoolBudget) -> Self {
        Self(budget)
    }
}

impl Drop for PoolAbortGuard<'_> {
    fn drop(&mut self) {
        let (lock, cvar) = self.0;
        // A panic taken while the budget lock was held poisons it. Setting the
        // flag still matters more than the poison, so reach through it rather
        // than panicking again inside a drop.
        match lock.lock() {
            Ok(mut state) => state.1 = true,
            Err(poisoned) => poisoned.into_inner().1 = true,
        }
        cvar.notify_all();
    }
}

pub(crate) fn map_collect<T, O, E, F>(items: Vec<T>, map: F) -> Result<Vec<O>, E>
where
    T: Send,
    O: Send,
    E: Send,
    F: Fn(T) -> Result<O, E> + Sync + Send,
{
    items.into_par_iter().map(map).collect()
}

/// [`map_collect`] with at most `width` items mapped at once: the items in
/// order, `width` at a time, each group on the pool. Results keep the
/// items' order, so a caller whose map is independent per item gets the
/// same output at any width. For a caller whose items each hold memory
/// the pool width does not bound (a RAR 5 member's match-finder tree).
/// (nzbfast-local addition, 15 Sep 2026; see VENDORING.md.)
pub(crate) fn map_collect_bounded<T, O, E, F>(
    items: Vec<T>,
    width: usize,
    map: F,
) -> Result<Vec<O>, E>
where
    T: Send,
    O: Send,
    E: Send,
    F: Fn(T) -> Result<O, E> + Sync + Send,
{
    if width >= items.len() {
        return map_collect(items, map);
    }
    let width = width.max(1);
    let mut out = Vec::with_capacity(items.len());
    let mut items = items.into_iter();
    loop {
        let group: Vec<T> = items.by_ref().take(width).collect();
        if group.is_empty() {
            return Ok(out);
        }
        let mapped: Vec<O> = if group.len() == 1 {
            group.into_iter().map(&map).collect::<Result<_, E>>()?
        } else {
            group.into_par_iter().map(&map).collect::<Result<_, E>>()?
        };
        out.extend(mapped);
    }
}

pub(crate) fn map_slice_collect<'a, T, O, E, F>(items: &'a [T], map: F) -> Result<Vec<O>, E>
where
    T: Sync + 'a,
    O: Send,
    E: Send,
    F: Fn(&'a T) -> Result<O, E> + Sync + Send,
{
    items.par_iter().map(map).collect()
}
