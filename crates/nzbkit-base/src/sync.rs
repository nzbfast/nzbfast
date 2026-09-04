//! Poison-free locking.
//!
//! A poisoned lock means some thread panicked while holding it. Inheriting
//! that panic is what the 1 August poison sweep set out to stop: one
//! panicking worker was taking the whole daemon down with it, because every
//! other thread that touched the same mutex panicked in turn. The state
//! behind these locks is guarded by the app's own invariants rather than by
//! the poison flag - a partially-updated counter or queue entry is either
//! consistent already or corrected on the next pass - so recovering the
//! guard is the right call at every one of these call sites.
//!
//! The sweep spelled that out as `.lock().unwrap_or_else(|e| e.into_inner())`,
//! which rustfmt then wrapped across three lines, 800-odd times. These
//! traits say the same thing in one word.

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Poison-recovering [`Mutex`] access.
pub trait MutexExt<T: ?Sized> {
    /// Lock, taking the guard even if a previous holder panicked.
    ///
    /// See the module docs for why poison is never fatal here.
    fn lock_ok(&self) -> MutexGuard<'_, T>;
}

impl<T: ?Sized> MutexExt<T> for Mutex<T> {
    #[inline]
    fn lock_ok(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Poison-recovering [`RwLock`] access.
pub trait RwLockExt<T: ?Sized> {
    /// Take a read guard, even if a previous writer panicked.
    ///
    /// See the module docs for why poison is never fatal here.
    fn read_ok(&self) -> RwLockReadGuard<'_, T>;
    /// Take a write guard, even if a previous writer panicked.
    ///
    /// See the module docs for why poison is never fatal here.
    fn write_ok(&self) -> RwLockWriteGuard<'_, T>;
}

impl<T: ?Sized> RwLockExt<T> for RwLock<T> {
    #[inline]
    fn read_ok(&self) -> RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(|e| e.into_inner())
    }

    #[inline]
    fn write_ok(&self) -> RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// The point of the whole module: a panic under the lock must not take
    /// the next caller down with it, and the value it left behind stands.
    #[test]
    fn lock_ok_recovers_a_poisoned_mutex() {
        let m = Arc::new(Mutex::new(7u32));
        let m2 = Arc::clone(&m);
        let _ = std::thread::spawn(move || {
            let mut g = m2.lock_ok();
            *g = 9;
            panic!("poison it");
        })
        .join();
        assert!(m.lock().is_err(), "the mutex should be poisoned");
        assert_eq!(*m.lock_ok(), 9, "the write before the panic stands");
    }

    #[test]
    fn rwlock_ok_recovers_a_poisoned_lock() {
        let l = Arc::new(RwLock::new(String::from("before")));
        let l2 = Arc::clone(&l);
        let _ = std::thread::spawn(move || {
            let mut g = l2.write_ok();
            g.push_str("+after");
            panic!("poison it");
        })
        .join();
        assert!(l.read().is_err(), "the lock should be poisoned");
        assert_eq!(&*l.read_ok(), "before+after");
        l.write_ok().push('!');
        assert_eq!(&*l.read_ok(), "before+after!");
    }

    /// Deref through an `Arc` is what nearly every call site relies on, and
    /// a handful hold unsized contents.
    #[test]
    fn works_through_arc_and_on_unsized_contents() {
        let m: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(vec![1, 2]));
        m.lock_ok().push(3);
        assert_eq!(*m.lock_ok(), vec![1, 2, 3]);
        let boxed: Mutex<Box<dyn Fn() -> u8 + Send>> = Mutex::new(Box::new(|| 5));
        assert_eq!((boxed.lock_ok())(), 5);
    }
}
