//! The daemon's "what am I doing right now" gauge - one refcounted
//! token per background subsystem, feeding the dashboard's status chip
//! strip (stats.busy in mode=dashboard).
//!
//! Tokens are short language-neutral identifiers the page maps to
//! `chip.*` i18n phrases - the daemon never composes English (same rule
//! as the queue activity sub-line). Refcounted rather than boolean
//! because independent workers legitimately overlap under one token
//! (two mover lanes, three enrichment threads), and the chip must stay
//! lit until the LAST of them finishes.
//!
//! Always set through the RAII [`BusyGuard`]: a worker that panics or
//! early-returns must never leave its chip lit, and a guard makes that
//! structural instead of a discipline. Queue-side states (downloading,
//! repairing, unpacking...) are deliberately NOT here - the queue slots
//! already carry them per job, and the page derives its queue chip from
//! those; this map is only for the work that was previously invisible.

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
pub struct BusyMap {
    inner: Mutex<HashMap<&'static str, u32>>,
}

impl BusyMap {
    /// Mark `token` active until the returned guard drops.
    pub fn hold(&self, token: &'static str) -> BusyGuard<'_> {
        *self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(token)
            .or_insert(0) += 1;
        BusyGuard { map: self, token }
    }

    /// The active tokens, sorted - a stable order so the chip strip
    /// never reshuffles between polls.
    pub fn active(&self) -> Vec<&'static str> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<&'static str> = g.iter().filter(|(_, n)| **n > 0).map(|(t, _)| *t).collect();
        v.sort_unstable();
        v
    }
}

pub struct BusyGuard<'a> {
    map: &'a BusyMap,
    token: &'static str,
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        let mut g = self.map.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = g.get_mut(self.token) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.remove(self.token);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_holds_keep_the_token_until_the_last_drops() {
        let m = BusyMap::default();
        let a = m.hold("moving");
        let b = m.hold("moving");
        let c = m.hold("indexing");
        assert_eq!(m.active(), vec!["indexing", "moving"]);
        drop(a);
        assert_eq!(
            m.active(),
            vec!["indexing", "moving"],
            "one lane still moving"
        );
        drop(b);
        assert_eq!(m.active(), vec!["indexing"]);
        drop(c);
        assert!(m.active().is_empty());
    }

    #[test]
    fn a_panicking_holder_still_clears_its_token() {
        let m = std::sync::Arc::new(BusyMap::default());
        let m2 = m.clone();
        let _ = std::thread::spawn(move || {
            let _g = m2.hold("enriching");
            panic!("worker died");
        })
        .join();
        assert!(m.active().is_empty(), "guard drop must survive a panic");
    }
}
