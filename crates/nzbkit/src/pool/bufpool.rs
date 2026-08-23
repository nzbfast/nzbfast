//! Reusable article-body buffers (split from pool.rs for the size gate).

use crate::sync::MutexExt;
use std::sync::Arc;

/// Reusable article-body buffers. Kills the per-article 800 KB
/// alloc/free churn (mmap + page-zero + TLB shootdowns) on the hot path.
/// Consumers hand buffers back with `give()` once decoded/written.
pub struct BufPool {
    bufs: std::sync::Mutex<Vec<Vec<u8>>>,
    max_held: usize,
    /// Memory-floor gauges (memgauge): free-list bytes and outstanding
    /// bytes. None for pools nobody is attributing (nettools, repair).
    gauges: Option<(crate::memgauge::Sub, crate::memgauge::Sub)>,
}

impl BufPool {
    pub fn new(max_held: usize) -> Arc<BufPool> {
        Arc::new(BufPool {
            bufs: std::sync::Mutex::new(Vec::new()),
            max_held,
            gauges: None,
        })
    }

    /// A pool whose free-list and outstanding bytes feed the memory-floor
    /// gauges (instrument-first; the get pipeline's two pools use this).
    pub fn new_gauged(
        max_held: usize,
        free: crate::memgauge::Sub,
        out: crate::memgauge::Sub,
    ) -> Arc<BufPool> {
        Arc::new(BufPool {
            bufs: std::sync::Mutex::new(Vec::new()),
            max_held,
            gauges: Some((free, out)),
        })
    }

    pub fn take(&self) -> Vec<u8> {
        let popped = self.bufs.lock_ok().pop();
        let was_pooled = popped.is_some();
        let buf = popped.unwrap_or_else(|| Vec::with_capacity(body_buf_bytes()));
        if let Some((free, out)) = self.gauges {
            crate::memgauge::add(out, buf.capacity() as u64);
            // A fresh buffer was never on the free list; only a popped
            // one leaves it.
            if was_pooled {
                crate::memgauge::sub(free, buf.capacity() as u64);
            }
        }
        buf
    }

    pub fn give(&self, mut buf: Vec<u8>) {
        buf.clear();
        // The outstanding release comes FIRST - the oversized early
        // return below would otherwise leak the gauge upward forever.
        // Capacity may have GROWN while outstanding, so the gauge's sub
        // saturates (documented there).
        if let Some((_, out)) = self.gauges {
            crate::memgauge::sub(out, buf.capacity() as u64);
        }
        // Drop a buffer that a single oversized read grew far past the
        // normal article size - clear() keeps capacity, so retaining it
        // would pin that allocation in the pool for the rest of the run.
        // Anything up to 4 MB is a plausible large article; beyond that,
        // let it free and hand back a right-sized buffer next take().
        const KEEP_CAP: usize = 4 * 1024 * 1024;
        if buf.capacity() > KEEP_CAP {
            return;
        }
        let mut bufs = self.bufs.lock_ok();
        if bufs.len() < self.max_held {
            if let Some((free, _)) = self.gauges {
                crate::memgauge::add(free, buf.capacity() as u64);
            }
            bufs.push(buf);
        }
    }
}

/// Fresh body-buffer capacity. Bench override `NZBFAST_BODY_BUF_KB`
/// (memfloor levers, 22 Aug 2026); 800 KB shipped.
pub fn body_buf_bytes() -> usize {
    static OVERRIDE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *OVERRIDE.get_or_init(|| {
        std::env::var("NZBFAST_BODY_BUF_KB")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map_or(800 * 1024, |kb| kb.clamp(16, 16384) * 1024)
    })
}

impl Drop for BufPool {
    fn drop(&mut self) {
        // A job's pool dies with its free list; without this the gauge
        // would carry the dead pool's bytes into the next job forever.
        if let Some((free, _)) = self.gauges {
            let held: u64 = self
                .bufs
                .get_mut()
                .map(|b| b.iter().map(|v| v.capacity() as u64).sum())
                .unwrap_or(0);
            crate::memgauge::sub(free, held);
        }
    }
}
