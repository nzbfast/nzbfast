//! A create FED its one member's bytes as they are produced, rather than
//! reading a file that already exists: the PAR2 half of a one-pass
//! posting set, where a RAR writer's output is hashed and folded as it
//! goes to disk instead of being read back afterwards.
//!
//! # Why ONE member, and why that is not a limitation of this module
//!
//! The recovery data is `R_e = Σ_i g_i^e · D_i` over the GLOBAL input
//! slice index `i`, and that index runs over the members in the order of
//! their file ids, which the Main packet sorts (module doc of
//! `par2gen.rs`, and `scan::id_order`). A file id is
//! `MD5(md5_16k | length | name)`. So before slice `D_i` can be folded,
//! the writer has to know where its member sorts among ALL the members,
//! which needs every member's first 16 KiB and LENGTH - and for a set of
//! RAR volumes produced one after another, the last volume's length is
//! known only when the write ends. No slice of any volume can be folded
//! before then, and the fold is the whole cost of a create over volumes,
//! so a volume set is created from the finished files (the ordinary
//! [`create_into_exact_controlled`]).
//!
//! With ONE member the index is the slice's position in the stream and
//! there is nothing to sort, so every slice is folded the moment it is
//! complete. That is what this is: a create of exactly one member whose
//! bytes arrive in order, in pieces of any size.
//!
//! # What it writes
//!
//! Byte for byte what [`create_into_exact_controlled`] writes over the
//! same bytes, block size, recovery count and plan - the critical
//! packets, the volume layout, the interleave and the seals all come from
//! the same functions. `a_streamed_set_is_byte_identical_to_a_read_one`
//! is that claim. What it cannot share with the file create is the
//! choice of the block size and the recovery count, because both are
//! normally derived from a length nobody knows yet: the caller decides
//! them from an ESTIMATE before the first byte ([`StreamCreate::new`]),
//! and the recovery count can be lowered at the end
//! ([`StreamCreate::finish`]), never raised.
//!
//! # The pipeline, and where the time goes
//!
//! The caller's thread copies bytes into fixed windows of whole slices
//! and hands each full window to two threads:
//!
//! - the CHAIN thread runs the whole-file MD5, which is one serial chain
//!   over every byte and the pole of any single-member create (memory
//!   topic `nzbfast-digest-cache-hit-route`: ~11 s of a ~12 s create of
//!   8.86 GB);
//! - the FOLD thread hashes each slice (MD5 + CRC32, zero-padded, per
//!   spec) and folds the window into every recovery row through
//!   `par2repair::linalg::fold_parallel`, the engine's one fold.
//!
//! A window is recycled when both are done with it, and at most
//! `WINDOWS_IN_FLIGHT` exist, so a caller that produces faster than the
//! chain can hash is held back rather than buffered without bound. The
//! wall of a streamed create is therefore about the chain's, and what it
//! saves over writing the member and then creating from it is the write
//! itself, which runs under the chain instead of before it.
//!
//! # What it refuses
//!
//! A recovery count whose accumulators do not fit this create's share of
//! the memory budget in ONE batch ([`StreamCreate::fits`]): the file
//! create answers that with several passes over the payload, and a
//! stream cannot be passed over twice. A caller asks first and creates
//! from the file when the answer is no.

use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use super::*;

/// Windows that exist at once: one being filled, and the rest queued for
/// or held by the chain and the fold. Bounds what a stream holds to this
/// many windows of `WINDOW_BYTES` (32 MiB, rounded to whole slices).
pub const WINDOWS_IN_FLIGHT: usize = 4;

/// The size a window aims for: whole slices, at least one, as many as fit
/// this. Big enough that a fold call amortises its per-call setup over
/// many sources, small enough that four of them are a modest footprint.
const WINDOW_BYTES: usize = 32 << 20;

/// One window of whole slices, shared by the chain and the fold. Its
/// buffer goes back to the pool when the last of them lets go.
struct Window {
    buf: Option<Vec<u8>>,
    /// Global index of this window's first slice.
    first_slice: usize,
    /// Whole slices in it; the last may be zero-padded.
    slices: usize,
    /// Member bytes in it, which the chain hashes; the padding is not.
    real: usize,
    pool: Arc<Pool>,
}

impl Window {
    fn bytes(&self) -> &[u8] {
        self.buf.as_deref().unwrap_or(&[])
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            let mut st = self.pool.state.lock().unwrap_or_else(|p| p.into_inner());
            st.free.push(buf);
            self.pool.cv.notify_all();
        }
    }
}

struct PoolState {
    free: Vec<Vec<u8>>,
    made: usize,
}

struct Pool {
    state: Mutex<PoolState>,
    cv: Condvar,
}

/// What the fold thread hands back: the recovery rows and the per-slice
/// checksums, in slice order.
struct Folded {
    acc: Vec<Vec<u16>>,
    blocks: Vec<([u8; 16], u32)>,
}

/// A one-member create fed in order. See the module doc.
pub struct StreamCreate {
    dir: PathBuf,
    base: String,
    name: String,
    bs: usize,
    rows: usize,
    first_exponent: usize,
    control: CreateControl,
    per_window: usize,
    filling: Option<Vec<u8>>,
    fill: usize,
    next_slice: usize,
    length: u64,
    head: Vec<u8>,
    pool: Arc<Pool>,
    chain_tx: Option<SyncSender<Arc<Window>>>,
    fold_tx: Option<SyncSender<Arc<Window>>>,
    chain: Option<JoinHandle<Md5>>,
    fold: Option<JoinHandle<Result<Folded, Par2GenError>>>,
    /// This create's claim on the process's create budget, held until it
    /// is finished or dropped, exactly as a file create holds one.
    _admission: CreateAdmission,
}

impl StreamCreate {
    /// Whether `rows` recovery slices of `block_size` bytes can be built
    /// in one pass under the memory budget as it stands, which is the
    /// only way a stream can build them. Ask before [`StreamCreate::new`]
    /// and create from the finished file when this says no.
    pub fn fits(block_size: u64, rows: usize) -> bool {
        held_bytes(block_size, rows, WINDOW_BYTES) <= accum_budget()
    }

    /// Start a streamed create of one member, `name` (the name its
    /// FileDesc carries), writing `<base>.par2` and its volumes into
    /// `dir` when [`finish`](Self::finish)ed.
    ///
    /// `block_size` is fixed here and `max_recovery` is the most recovery
    /// slices `finish` may ask for, both chosen by the caller before the
    /// length is known - see the module doc. `expected_len` sizes the
    /// progress phase and nothing else. `first_exponent` must be the plan's.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        dir: &Path,
        base: &str,
        name: &str,
        block_size: u64,
        max_recovery: usize,
        first_exponent: usize,
        expected_len: u64,
        control: CreateControl,
    ) -> Result<StreamCreate, Par2GenError> {
        StreamCreate::start(
            dir,
            base,
            name,
            block_size,
            max_recovery,
            first_exponent,
            expected_len,
            control,
            WINDOW_BYTES,
        )
    }

    /// [`new`](Self::new) at a given window size, which the tests shrink
    /// to a few slices so a small payload crosses many window boundaries
    /// and waits on the pool.
    #[expect(clippy::too_many_arguments)]
    fn start(
        dir: &Path,
        base: &str,
        name: &str,
        block_size: u64,
        max_recovery: usize,
        first_exponent: usize,
        expected_len: u64,
        control: CreateControl,
        window_bytes: usize,
    ) -> Result<StreamCreate, Par2GenError> {
        if block_size == 0 || !block_size.is_multiple_of(4) || block_size > MAX_BLOCK_SIZE {
            return Err(Par2GenError::Other(format!(
                "PAR2 block size {block_size} must be a positive multiple of 4 no larger \
                 than {MAX_BLOCK_SIZE}"
            )));
        }
        let member = Member {
            name: name.to_string(),
            path: dir.join(name),
        };
        check_create_inputs(
            std::slice::from_ref(&member),
            base,
            spec_exponent_end(first_exponent, Some(max_recovery)),
        )?;
        let admission = CreateAdmission::acquire();
        if held_bytes(block_size, max_recovery, window_bytes) > admission.accum {
            return Err(Par2GenError::Other(format!(
                "{max_recovery} recovery slices of {block_size} bytes do not fit one pass \
                 under the memory budget; create the set from the finished file instead"
            )));
        }
        let bs = block_size as usize;
        let per_window = (window_bytes / bs).max(1);
        let pool = Arc::new(Pool {
            state: Mutex::new(PoolState {
                free: Vec::new(),
                made: 0,
            }),
            cv: Condvar::new(),
        });
        let control = control.or_env_arm();
        control.begin(CreatePhase::Fold, expected_len);

        let (chain_tx, chain_rx) = sync_channel::<Arc<Window>>(WINDOWS_IN_FLIGHT);
        let chain = std::thread::Builder::new()
            .name("par2-stream-chain".into())
            .spawn(move || chain_loop(chain_rx))
            .map_err(io(dir))?;
        let (fold_tx, fold_rx) = sync_channel::<Arc<Window>>(WINDOWS_IN_FLIGHT);
        let fold_control = control.clone();
        let fold = std::thread::Builder::new()
            .name("par2-stream-fold".into())
            .spawn(move || fold_loop(fold_rx, bs, max_recovery, first_exponent, fold_control))
            .map_err(io(dir))?;
        Ok(StreamCreate {
            dir: dir.to_path_buf(),
            base: base.to_string(),
            name: name.to_string(),
            bs,
            rows: max_recovery,
            first_exponent,
            control,
            per_window,
            filling: None,
            fill: 0,
            next_slice: 0,
            length: 0,
            head: Vec::with_capacity(scan_head_len(u64::MAX)),
            pool,
            chain_tx: Some(chain_tx),
            fold_tx: Some(fold_tx),
            chain: Some(chain),
            fold: Some(fold),
            _admission: admission,
        })
    }

    /// Member bytes fed so far.
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Whether nothing has been fed yet.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// The next `bytes` of the member, in order.
    pub fn write(&mut self, mut bytes: &[u8]) -> Result<(), Par2GenError> {
        let cap = (MAX_INPUT_SLICES as u64).saturating_mul(self.bs as u64);
        if self.length.saturating_add(bytes.len() as u64) > cap {
            return Err(Par2GenError::Other(format!(
                "the member passed {cap} bytes, the PAR2 limit of {MAX_INPUT_SLICES} slices \
                 at a {}-byte block",
                self.bs
            )));
        }
        let head_room = scan_head_len(u64::MAX) - self.head.len();
        if head_room > 0 {
            self.head
                .extend_from_slice(&bytes[..head_room.min(bytes.len())]);
        }
        self.length += bytes.len() as u64;
        let window_bytes = self.per_window * self.bs;
        while !bytes.is_empty() {
            if self.filling.is_none() {
                self.filling = Some(self.take_buffer()?);
            }
            let buf = self.filling.as_mut().expect("a window is being filled");
            let take = (window_bytes - self.fill).min(bytes.len());
            buf[self.fill..self.fill + take].copy_from_slice(&bytes[..take]);
            self.fill += take;
            bytes = &bytes[take..];
            if self.fill == window_bytes {
                self.dispatch(self.per_window)?;
            }
        }
        Ok(())
    }

    /// Finish the member and write the set: `recovery_blocks` slices (at
    /// most the `max_recovery` given to [`new`](Self::new)) laid out by
    /// `plan`, whose `first_exponent` must be the one given there.
    /// Returns the names written, the index first, as the file create
    /// does. A cancel leaves nothing, as the file create's does.
    pub fn finish(
        mut self,
        recovery_blocks: usize,
        plan: CreatePlan,
        comment: Option<&str>,
    ) -> Result<Vec<String>, Par2GenError> {
        let trail = CreateTrail::new(plan.no_clobber);
        let r = self.finish_body(recovery_blocks, plan, comment, &trail);
        if matches!(r, Err(Par2GenError::Cancelled)) {
            trail.unlink_all(&self.dir);
        }
        r
    }

    fn finish_body(
        &mut self,
        recovery_blocks: usize,
        plan: CreatePlan,
        comment: Option<&str>,
        trail: &CreateTrail,
    ) -> Result<Vec<String>, Par2GenError> {
        if plan.first_exponent != self.first_exponent || recovery_blocks > self.rows {
            return Err(Par2GenError::Other(format!(
                "a streamed create sized for exponents {}..{} was asked to finish {} from {}",
                self.first_exponent,
                self.first_exponent + self.rows,
                recovery_blocks,
                plan.first_exponent
            )));
        }
        let comment = comment.filter(|c| !c.is_empty());
        if let Some(c) = comment {
            check_comment(c)?;
        }
        if self.fill > 0 {
            let slices = self.fill.div_ceil(self.bs);
            let buf = self.filling.as_mut().expect("a window is being filled");
            buf[self.fill..slices * self.bs].fill(0);
            self.dispatch(slices)?;
        }
        let (md5_whole, folded) = self.join_workers()?;
        // The late poll the file create takes before its index: a cancel
        // raised while the last window was folding is not answered with a
        // finished set.
        self.control.check()?;
        if self.length == 0 {
            return Err(Par2GenError::Other(
                "a streamed PAR2 member cannot be empty".into(),
            ));
        }
        let Folded { mut acc, blocks } = folded;
        acc.truncate(recovery_blocks);
        let member = Member {
            name: self.name.clone(),
            path: self.dir.join(&self.name),
        };
        let md5_16k: [u8; 16] = Md5::digest(&self.head).into();
        let scanned = [finish_scan(
            &member,
            self.length,
            md5_whole,
            md5_16k,
            blocks,
            None,
        )];
        let (set_id, critical) = critical_packets(&scanned, self.bs as u64, comment);
        let index = format!("{}.par2", self.base);
        write_member(trail, &self.dir, &index, &critical)?;
        let mut names = vec![index];
        if recovery_blocks == 0 {
            return Ok(names);
        }
        // The file create's own layout rule over its own volume cap, so
        // the two write the same volumes: `fits` admitted every row in
        // one batch, which is the case where the cap is the budget's.
        let per_batch = (self._admission.accum / self.bs as u64).max(1) as usize;
        let per_vol = plan
            .max_blocks_per_volume
            .map_or(per_batch, |l| per_batch.min(l.max(1)));
        let layout = volume_layout(recovery_blocks, per_vol, plan.volumes, plan.first_exponent);
        let cidx =
            matches!(plan.critical, CriticalLayout::Interleaved).then(|| critical_index(&critical));
        self.control
            .begin(CreatePhase::Write, recovery_blocks as u64 * self.bs as u64);
        let written = volwrite::write_batch(volwrite::BatchVolumes {
            control: &self.control,
            trail,
            dir: &self.dir,
            base: &self.base,
            layout: &layout,
            set_id: &set_id,
            first: plan.first_exponent,
            slices: &acc,
            ready_critical: Some(&critical),
            critical_shape: &critical,
            cidx: cidx.as_ref(),
        })?;
        self.control.finish(CreatePhase::Write);
        names.extend(written.into_iter().map(|(name, _)| name));
        Ok(names)
    }

    /// A buffer for the next window: a recycled one, a new one while
    /// fewer than `WINDOWS_IN_FLIGHT` exist, or a wait for one to come
    /// back - which is where a caller faster than the chain is held.
    fn take_buffer(&mut self) -> Result<Vec<u8>, Par2GenError> {
        let mut st = self.pool.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(b) = st.free.pop() {
                return Ok(b);
            }
            if st.made < WINDOWS_IN_FLIGHT {
                st.made += 1;
                return Ok(vec![0u8; self.per_window * self.bs]);
            }
            // A fold that stopped (a cancel, or an error) holds no window
            // and will hand none back: surface its answer rather than
            // waiting for a buffer that is not coming.
            if self.fold.as_ref().is_some_and(|h| h.is_finished()) || self.control.cancelled() {
                drop(st);
                return Err(self.worker_error());
            }
            st = self
                .pool
                .cv
                .wait_timeout(st, std::time::Duration::from_millis(50))
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }

    /// Hand the window being filled, `slices` whole slices of it, to the
    /// chain and the fold.
    fn dispatch(&mut self, slices: usize) -> Result<(), Par2GenError> {
        let buf = self.filling.take().expect("a window is being filled");
        let w = Arc::new(Window {
            buf: Some(buf),
            first_slice: self.next_slice,
            slices,
            real: self.fill,
            pool: self.pool.clone(),
        });
        self.next_slice += slices;
        self.fill = 0;
        let sent = self
            .chain_tx
            .as_ref()
            .is_some_and(|t| t.send(w.clone()).is_ok())
            && self.fold_tx.as_ref().is_some_and(|t| t.send(w).is_ok());
        if sent {
            Ok(())
        } else {
            Err(self.worker_error())
        }
    }

    /// Close both channels and collect what the two threads made.
    fn join_workers(&mut self) -> Result<([u8; 16], Folded), Par2GenError> {
        self.chain_tx = None;
        self.fold_tx = None;
        let chain = self.chain.take().map(|h| h.join());
        let fold = self.fold.take().map(|h| h.join());
        let folded = match fold {
            Some(Ok(r)) => r?,
            _ => return Err(Par2GenError::Other("the stream's fold thread died".into())),
        };
        let md5 = match chain {
            Some(Ok(m)) => m,
            _ => return Err(Par2GenError::Other("the stream's chain thread died".into())),
        };
        Ok((md5.finalize().into(), folded))
    }

    /// Why the pipeline stopped: the fold's own error, or a cancel.
    fn worker_error(&mut self) -> Par2GenError {
        self.chain_tx = None;
        self.fold_tx = None;
        if let Some(h) = self.fold.take()
            && let Ok(Err(e)) = h.join()
        {
            return e;
        }
        if self.control.cancelled() {
            Par2GenError::Cancelled
        } else {
            Par2GenError::Other("the stream's fold stopped early".into())
        }
    }
}

impl Drop for StreamCreate {
    /// A stream dropped unfinished - the producer failed, or was called
    /// off - stops both threads and waits for them, so nothing outlives
    /// it. It has written nothing: the set is written only by `finish`.
    fn drop(&mut self) {
        self.chain_tx = None;
        self.fold_tx = None;
        self.filling = None;
        if let Some(h) = self.fold.take() {
            let _ = h.join();
        }
        if let Some(h) = self.chain.take() {
            let _ = h.join();
        }
    }
}

/// What a stream holds at its peak: every recovery row, and every window
/// that may be in flight (whole slices, at least one each). Both are
/// charged against the create's accumulator share - the windows are what
/// the file create's read arena is, and with a large block they are not
/// small.
fn held_bytes(block_size: u64, rows: usize, window_bytes: usize) -> u64 {
    let window = (window_bytes as u64 / block_size.max(1)).max(1) * block_size;
    (rows as u64)
        .saturating_mul(block_size)
        .saturating_add((WINDOWS_IN_FLIGHT as u64).saturating_mul(window))
}

/// The whole-file MD5, over the member bytes of each window in order.
fn chain_loop(rx: Receiver<Arc<Window>>) -> Md5 {
    let mut md5 = Md5::new();
    for w in rx {
        md5.update(&w.bytes()[..w.real]);
    }
    md5
}

/// Per-slice checksums and the fold, window by window. Returns as soon
/// as a cancel is seen; dropping the receiver then refuses the producer's
/// next window, which is how it learns.
fn fold_loop(
    rx: Receiver<Arc<Window>>,
    bs: usize,
    rows: usize,
    first_exponent: usize,
    control: CreateControl,
) -> Result<Folded, Par2GenError> {
    let logs = crate::par2repair::input_base_logs(MAX_INPUT_SLICES)
        .map_err(|e| Par2GenError::Other(e.to_string()))?;
    let mut acc: Vec<Vec<u16>> = (0..rows).map(|_| vec![0u16; bs / 2]).collect();
    let mut blocks: Vec<([u8; 16], u32)> = Vec::new();
    for w in rx {
        // Between two windows with nothing held but the window itself: a
        // park site and the cancel's grain, as the file create's fold
        // windows are.
        control.gate()?;
        let bytes = w.bytes();
        let srcs: Vec<&[u8]> = (0..w.slices)
            .map(|k| &bytes[k * bs..(k + 1) * bs])
            .collect();
        let digests = std::thread::scope(|sc| {
            let hashing = sc.spawn(|| slice_digests(&srcs));
            if rows > 0 {
                let held = &logs[w.first_slice..w.first_slice + w.slices];
                let c = |j: usize, i: usize| row_coeff(held[i], first_exponent + j);
                crate::par2repair::linalg::fold_parallel(&mut acc, &srcs, &c, None);
            }
            hashing.join()
        })
        .map_err(|_| Par2GenError::Other("a slice-hashing thread died".into()))?;
        blocks.extend(digests);
        control.step(CreatePhase::Fold, w.real as u64);
    }
    Ok(Folded { acc, blocks })
}

/// MD5 and CRC32 of each whole (zero-padded) slice, eight to a vector
/// pass and the passes spread over a few threads beside the fold.
fn slice_digests(srcs: &[&[u8]]) -> Vec<([u8; 16], u32)> {
    const LANES: usize = 8;
    let groups: Vec<&[&[u8]]> = srcs.chunks(LANES).collect();
    let threads = groups.len().clamp(1, 4);
    let per = groups.len().div_ceil(threads);
    std::thread::scope(|sc| {
        let handles: Vec<_> = groups
            .chunks(per.max(1))
            .map(|mine| {
                sc.spawn(move || {
                    let mut out = Vec::with_capacity(mine.len() * LANES);
                    for g in mine {
                        let md5s = crate::md5fast::multi::md5_many(g);
                        for (d, s) in md5s.into_iter().zip(g.iter()) {
                            out.push((d, crc32fast::hash(s)));
                        }
                    }
                    out
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("a slice-hashing worker panicked"))
            .collect()
    })
}

#[cfg(test)]
mod tests;
