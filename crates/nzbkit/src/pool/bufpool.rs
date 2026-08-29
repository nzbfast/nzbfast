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

    /// A pooled buffer that returns itself. The guard is the contract:
    /// a consumer that early-returns, `?`s or panics between take and
    /// give cannot leak the outstanding gauge upward, which is the one
    /// failure of the bare `take`/`give` pair that never surfaces (a
    /// lost recycle costs one allocation; a lost `give` on a gauged
    /// pool climbs the memory floor for the rest of the run).
    ///
    /// Borrow-based on purpose: no `Arc` clone and no allocation per
    /// article, so this is free on the hot path. A buffer that has to
    /// OUTLIVE the borrow - the one handed down the outcome channel -
    /// disarms with [`PooledBuf::into_vec`] and is re-guarded at the
    /// far end with [`BufPool::adopt`].
    pub fn take(&self) -> PooledBuf<'_> {
        PooledBuf {
            pool: Some(self),
            buf: self.take_vec(),
        }
    }

    /// Re-guard a buffer that came back across a channel. The bytes are
    /// ALREADY charged to the outstanding gauge (by the `take` that
    /// minted them), so this charges nothing and the guard's drop is
    /// the matching release.
    pub fn adopt(&self, buf: Vec<u8>) -> PooledBuf<'_> {
        PooledBuf {
            pool: Some(self),
            buf,
        }
    }

    fn take_vec(&self) -> Vec<u8> {
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

    /// Return a buffer by hand. Prefer [`BufPool::take`] /
    /// [`BufPool::adopt`], whose guards cannot be forgotten; this stays
    /// public for the pool users whose buffers arrive as a bare `Vec`
    /// out of a `FetchOutcome` and are consumed on the spot.
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

/// A buffer on loan from a [`BufPool`], returned on drop.
///
/// Deref-transparent, so it is a `Vec<u8>` everywhere one was expected.
/// Two ways out, and both are exact:
/// - drop it, anywhere, on any path - the buffer goes back;
/// - [`into_vec`](Self::into_vec) to hand the bytes somewhere the
///   borrow cannot follow (the outcome channel), which disarms the
///   guard and makes the far end responsible again.
pub struct PooledBuf<'a> {
    /// `None` for a pool-less caller: the buffer is a plain allocation
    /// and its drop is an ordinary free.
    pool: Option<&'a BufPool>,
    buf: Vec<u8>,
}

impl<'a> PooledBuf<'a> {
    /// Take from `pool` if there is one, else allocate a right-sized
    /// buffer that simply frees on drop. This is the shape every pool
    /// consumer wants, because `PoolConfig::buf_pool` is optional.
    pub fn from_pool(pool: Option<&'a BufPool>) -> PooledBuf<'a> {
        match pool {
            Some(p) => p.take(),
            None => PooledBuf {
                pool: None,
                buf: Vec::with_capacity(body_buf_bytes()),
            },
        }
    }

    /// Bytes that belong to no pool: an ordinary allocation wearing the
    /// guard's shape, so a caller holding a plain `Vec` (a test fixture,
    /// a pool-less path) can still feed an API that speaks `PooledBuf`.
    /// Drops as a plain free.
    pub fn unpooled(buf: Vec<u8>) -> PooledBuf<'static> {
        PooledBuf { pool: None, buf }
    }

    /// Hand the bytes on to an owner the borrow cannot reach, and stop
    /// guarding them. The outstanding gauge charge travels WITH the
    /// buffer, and the far end owes it a `give` (directly, or through
    /// [`BufPool::adopt`]'s drop) - a bare `Vec` drop releases NOTHING,
    /// and `BufPool::Drop` reconciles only the free list, so bytes
    /// dropped disarmed stay on the gauge for the rest of the run.
    pub fn into_vec(mut self) -> Vec<u8> {
        self.pool = None;
        std::mem::take(&mut self.buf)
    }
}

impl std::ops::Deref for PooledBuf<'_> {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.buf
    }
}

impl std::ops::DerefMut for PooledBuf<'_> {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }
}

impl Drop for PooledBuf<'_> {
    fn drop(&mut self) {
        if let Some(p) = self.pool {
            p.give(std::mem::take(&mut self.buf));
        }
    }
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
