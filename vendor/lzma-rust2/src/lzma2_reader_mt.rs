use std::{
    collections::BTreeMap,
    io,
    io::{Cursor, Read},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
    time::Duration,
};

/// Interval for checking worker errors while waiting for results.
const ERROR_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// nzbfast: ceiling on what a worker will RESERVE up front for one work
/// unit's decoded output.
///
/// The declared size is what the preallocation exists for and it is also
/// attacker-controlled (see the worker's own comment), so the two are
/// separated here: a legitimate unit is a 7-Zip block, ~256 MiB at
/// `-mx9` and smaller everywhere else, and 64 MiB of it is reserved in
/// one go while the rest grows by doubling - two or three copies on a
/// unit whose decode already costs far more than that. A declaration
/// past the cap buys the archive nothing.
const PREALLOC_CAP: usize = 64 << 20;

/// nzbfast: total DICTIONARY memory this reader will commit across its
/// workers.
///
/// Every worker builds its own `Lzma2Reader`, so every worker allocates
/// and zero-fills its own window of `dict_size`: the cost is
/// `workers x dict`, while a caller's admission gate charges the declared
/// dictionary ONCE (nzbkit's 7z content gate does, and so does
/// sevenz-rust2's own `max_mem_limit_kb`). A crafted archive declaring a
/// 64 MiB dictionary - free under that gate - whose stream is thirty tiny
/// INDEPENDENT blocks therefore committed 20 x 64 MiB of zeroed pages on
/// a 20-core box for a few KB of input, and the props byte allows a
/// declaration up to 4 GiB.
///
/// So the worker count follows the dictionary. Parallelism is what gives
/// way, never correctness: a single worker decodes exactly what twenty
/// do, and a dictionary that large already makes each unit's decode
/// dominate its dispatch.
const WORKER_DICT_BUDGET: u64 = 512 << 20;

/// nzbfast: the worker count that fits `dict_size` inside
/// [`WORKER_DICT_BUDGET`], never below one and never above what was
/// asked for. A function so the rule is testable directly - the shape it
/// guards against is a memory figure, which no decode assertion carries.
fn workers_for_dict(asked: u32, dict_size: u32) -> u32 {
    let asked = asked.clamp(1, 256);
    if dict_size == 0 {
        return asked;
    }
    let affordable = (WORKER_DICT_BUDGET / u64::from(dict_size)).max(1);
    asked.min(u32::try_from(affordable).unwrap_or(u32::MAX))
}

/// nzbfast: how much a worker reserves up front for a unit that DECLARES
/// `decoded_len` bytes of output.
///
/// A function rather than an inline `.min()` so the rule is testable on
/// every platform. The end-to-end shape cannot carry it: a reservation
/// too large to meet aborts the process on Linux but is granted lazily on
/// macOS, so a test that decodes a hostile stream passes on this fleet's
/// own boxes with the cap removed.
const fn prealloc_for(decoded_len: usize) -> usize {
    if decoded_len < PREALLOC_CAP {
        decoded_len
    } else {
        PREALLOC_CAP
    }
}

use crate::{
    Lzma2Reader, set_error,
    work_queue::{WorkStealingQueue, WorkerHandle},
};

/// A work unit for a worker thread.
/// Contains the sequence number, the raw compressed bytes for a series of
/// chunks, and the exact decoded length those chunks declare.
///
/// nzbfast: the decoded length is ours. Every LZMA2 chunk header carries its
/// own uncompressed size, so the dispatcher already knows what a unit decodes
/// to and the worker can size its output buffer once instead of letting
/// `read_to_end` double a 64 MiB `Vec` out of a 1 MiB seed.
type WorkUnit = (u64, Vec<u8>, usize);

/// A result unit from a worker thread.
/// Contains the sequence number and the decompressed data.
type ResultUnit = (u64, Vec<u8>);

enum State {
    /// Actively reading from the inner reader and sending work to threads.
    Reading,
    /// The inner reader has reached EOF. We are now waiting for the remaining
    /// work to be completed by the worker threads.
    Draining,
    /// All data has been decompressed and returned. The stream is exhausted.
    Finished,
    /// A fatal error occurred in either the reader or a worker thread.
    Error,
}

/// A multi-threaded LZMA2 decompressor.
pub struct Lzma2ReaderMt<R: Read> {
    inner: R,
    result_rx: Receiver<ResultUnit>,
    result_tx: SyncSender<ResultUnit>,
    current_work_unit: Vec<u8>,
    /// nzbfast: decoded length declared by the chunks in `current_work_unit`.
    current_work_unit_decoded: usize,
    next_sequence_to_dispatch: u64,
    next_sequence_to_return: u64,
    /// nzbfast: how many results have come back off the channel, in any
    /// order. `next_sequence_to_dispatch - results_received` is the number of
    /// units in flight, which is what the read-ahead is budgeted against.
    results_received: u64,
    last_sequence_id: Option<u64>,
    out_of_order_chunks: BTreeMap<u64, Vec<u8>>,
    current_chunk: Cursor<Vec<u8>>,
    shutdown_flag: Arc<AtomicBool>,
    error_store: Arc<Mutex<Option<io::Error>>>,
    state: State,
    work_queue: WorkStealingQueue<WorkUnit>,
    max_workers: u32,
    /// nzbfast: read-ahead budget, in work units dispatched but not yet
    /// received. `max_workers + 1` so that a worker finishing has a unit
    /// already queued rather than waiting for the dispatcher to read one.
    dispatch_target: u64,
    dict_size: u32,
    preset_dict: Option<Arc<Vec<u8>>>,
    worker_handles: Vec<thread::JoinHandle<()>>,
}

impl<R: Read> Lzma2ReaderMt<R> {
    /// Creates a new multi-threaded LZMA2 reader.
    ///
    /// - `inner`: The reader to read compressed data from.
    /// - `dict_size`: The dictionary size in bytes, as specified in the stream properties.
    /// - `preset_dict`: An optional preset dictionary.
    /// - `num_workers`: The maximum number of worker threads for decompression. Currently capped at 256 Threads.
    pub fn new(inner: R, dict_size: u32, preset_dict: Option<&[u8]>, num_workers: u32) -> Self {
        // nzbfast: the dictionary is per WORKER, so the worker count is
        // bounded by it - see `workers_for_dict`.
        let max_workers = workers_for_dict(num_workers, dict_size);

        let work_queue = WorkStealingQueue::new();
        // nzbfast: bound the result channel by the worker count, not by 1.
        // At 1, a worker that finished while the caller was consuming an
        // earlier unit parked in `send` instead of taking the next unit, so
        // the pipeline drained to one decode per consumer read. The memory is
        // the same either way - a blocked sender holds its output buffer just
        // as a queued one does - and the read-ahead budget below is what
        // actually bounds how many outputs can be live at once.
        let (result_tx, result_rx) = mpsc::sync_channel::<ResultUnit>(max_workers.max(1) as usize);
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let error_store = Arc::new(Mutex::new(None));
        let preset_dict = preset_dict.map(|s| s.to_vec()).map(Arc::new);

        let mut reader = Self {
            inner,
            result_rx,
            result_tx,
            current_work_unit: Vec::with_capacity(1024 * 1024),
            current_work_unit_decoded: 0,
            next_sequence_to_dispatch: 0,
            next_sequence_to_return: 0,
            results_received: 0,
            last_sequence_id: None,
            out_of_order_chunks: BTreeMap::new(),
            current_chunk: Cursor::new(Vec::new()),
            shutdown_flag,
            error_store,
            state: State::Reading,
            work_queue,
            max_workers,
            dispatch_target: max_workers.max(1) as u64 + 1,
            dict_size,
            preset_dict,
            worker_handles: Vec::new(),
        };

        reader.spawn_worker_thread();

        reader
    }

    fn spawn_worker_thread(&mut self) {
        let worker_handle = self.work_queue.worker();
        let result_tx = self.result_tx.clone();
        let shutdown_flag = Arc::clone(&self.shutdown_flag);
        let error_store = Arc::clone(&self.error_store);
        let preset_dict = self.preset_dict.clone();
        let dict_size = self.dict_size;

        let handle = thread::spawn(move || {
            worker_thread_logic(
                worker_handle,
                result_tx,
                dict_size,
                preset_dict,
                shutdown_flag,
                error_store,
            );
        });

        self.worker_handles.push(handle);
    }

    /// The count of independent chunks found inside the compressed file.
    /// This is effectively tha maximum parallelization possible.
    pub fn chunk_count(&self) -> u64 {
        self.next_sequence_to_return
    }

    /// Reads one LZMA2 chunk from the inner reader and appends it to the current work unit.
    /// If the chunk is an independent block, it dispatches the current work unit.
    ///
    /// Returns `Ok(false)` on clean EOF, `Ok(true)` on success, and `Err` on I/O error.
    fn read_and_dispatch_chunk(&mut self) -> io::Result<bool> {
        let mut control_buf = [0u8; 1];
        match self.inner.read_exact(&mut control_buf) {
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                // Clean end of stream.
                return Ok(false);
            }
            Err(error) => return Err(error),
        }

        let control = control_buf[0];

        if control == 0x00 {
            // End of stream marker.
            self.current_work_unit.push(0x00);
            self.send_work_unit();
            return Ok(false);
        }

        let is_independent_chunk = control >= 0xE0 || control == 0x01;

        // Split work units before independent chunks (but not for the very first chunk).
        if is_independent_chunk && !self.current_work_unit.is_empty() {
            self.current_work_unit.push(0x00);
            self.send_work_unit();
        }

        self.current_work_unit.push(control);

        let chunk_data_size = if control >= 0x80 {
            // Compressed chunk. Read header to find size.
            let header_len = if control >= 0xC0 { 5 } else { 4 };
            let mut header_buf = [0; 5];
            self.inner.read_exact(&mut header_buf[..header_len])?;
            self.current_work_unit
                .extend_from_slice(&header_buf[..header_len]);
            // nzbfast: the chunk's own declared decoded size. Control bits
            // 0..4 are bits 16..20 of `unpackSize - 1`; the first two header
            // bytes are its low half, big-endian.
            self.current_work_unit_decoded += (((control & 0x1F) as usize) << 16)
                + u16::from_be_bytes([header_buf[0], header_buf[1]]) as usize
                + 1;
            u16::from_be_bytes([header_buf[2], header_buf[3]]) as usize + 1
        } else if control == 0x01 || control == 0x02 {
            // Uncompressed chunk.
            let mut size_buf = [0u8; 2];
            self.inner.read_exact(&mut size_buf)?;
            self.current_work_unit.extend_from_slice(&size_buf);
            let size = u16::from_be_bytes(size_buf) as usize + 1;
            self.current_work_unit_decoded += size;
            size
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid LZMA2 control byte: {control:X}"),
            ));
        };

        // Read the chunk data itself.
        if chunk_data_size > 0 {
            let start_len = self.current_work_unit.len();
            self.current_work_unit
                .resize(start_len + chunk_data_size, 0);
            self.inner
                .read_exact(&mut self.current_work_unit[start_len..])?;
        }

        Ok(true)
    }

    /// Sends the current work unit to the workers.
    fn send_work_unit(&mut self) {
        if self.current_work_unit.is_empty() {
            return;
        }

        let work_unit =
            core::mem::replace(&mut self.current_work_unit, Vec::with_capacity(1024 * 1024));
        let decoded_len = core::mem::take(&mut self.current_work_unit_decoded);

        if !self
            .work_queue
            .push((self.next_sequence_to_dispatch, work_unit, decoded_len))
        {
            // Queue is closed, this indicates shutdown.
            self.state = State::Error;
            set_error(
                io::Error::new(io::ErrorKind::BrokenPipe, "worker threads have shut down"),
                &self.error_store,
                &self.shutdown_flag,
            );
        }

        self.next_sequence_to_dispatch += 1;

        // nzbfast: one worker per unit in flight, up to the cap. Upstream
        // asked the QUEUE how much work was waiting, and round 11 asked
        // whether every spawned worker was already ACTIVE; both read a state
        // that a worker empties microseconds after the push, so whether a
        // worker was spawned came down to a race with the condvar wake.
        // In-flight (dispatched but not yet returned) is the quantity that
        // does not evaporate under us.
        let spawned_workers = self.worker_handles.len() as u64;
        if spawned_workers < self.max_workers as u64 && spawned_workers < self.in_flight() {
            self.spawn_worker_thread();
        }
    }

    /// nzbfast: work units dispatched but not yet received back, in any
    /// order. This is the read-ahead budget's unit of account and the bound
    /// on how many decoded buffers can be alive at once.
    fn in_flight(&self) -> u64 {
        self.next_sequence_to_dispatch
            .saturating_sub(self.results_received)
    }

    fn get_next_uncompressed_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            // Always check for already-received chunks first.
            if let Some(result) = self
                .out_of_order_chunks
                .remove(&self.next_sequence_to_return)
            {
                self.next_sequence_to_return += 1;
                return Ok(Some(result));
            }

            // Check for a globally stored error.
            if let Some(err) = self.error_store.lock().unwrap().take() {
                self.state = State::Error;
                return Err(err);
            }

            match self.state {
                State::Reading => {
                    // First, always try to receive a result without blocking.
                    // This keeps the pipeline moving and avoids unnecessary blocking on I/O.
                    match self.result_rx.try_recv() {
                        Ok((seq, result)) => {
                            self.results_received += 1;
                            if seq == self.next_sequence_to_return {
                                self.next_sequence_to_return += 1;
                                return Ok(Some(result));
                            } else {
                                self.out_of_order_chunks.insert(seq, result);
                                continue; // Loop again to check the out_of_order_chunks
                            }
                        }
                        Err(mpsc::TryRecvError::Disconnected) => {
                            // All workers are done.
                            self.state = State::Draining;
                            continue;
                        }
                        Err(mpsc::TryRecvError::Empty) => {
                            // No results are ready. Now, we can consider reading more input.
                        }
                    }

                    // nzbfast: read ahead until `dispatch_target` units are in
                    // flight. Upstream's condition here was
                    // `self.work_queue.is_empty()`, which is the whole reason
                    // this reader did not scale: it dispatched ONE unit, found
                    // the queue non-empty on the very next turn of this loop,
                    // and dropped into the blocking wait below - which never
                    // re-checked the queue, because its `Timeout` arm loops on
                    // `recv_timeout` rather than breaking out. So the
                    // dispatcher read the next unit only after a result came
                    // back, and at most one worker could ever be decoding.
                    // Whether it was one or two came down to whether a worker
                    // had already stolen the unit by the time `is_empty()`
                    // ran, which is why the same binary on the same box
                    // measured 2.6 s and 8.2 s for the same GiB.
                    if self.in_flight() < self.dispatch_target {
                        match self.read_and_dispatch_chunk() {
                            Ok(true) => {
                                // Successfully read and dispatched a chunk, loop to continue.
                                continue;
                            }
                            Ok(false) => {
                                // Clean EOF from inner reader.
                                // Send any remaining data as the final work unit.
                                self.send_work_unit();
                                // nzbfast: an EMPTY pack stream dispatches
                                // nothing at all - a 7z folder may declare
                                // pack_size 0, so the very first control byte
                                // is already EOF and `send_work_unit` is a
                                // no-op on an empty unit. `saturating_sub(1)`
                                // then made the last sequence id 0, a unit
                                // that was never sent; `Draining` compared
                                // `next_sequence_to_return` (0) against it,
                                // found 0 > 0 false, and waited on a result
                                // channel whose sender THIS reader owns, so
                                // it never disconnects, with the one
                                // pre-spawned worker parked in `steal()`.
                                // The read wedged permanently - on the 7z
                                // chase thread, which has no catch_unwind and
                                // would not have been helped by one.
                                //
                                // Nothing dispatched means nothing to drain.
                                // (The single-threaded `Lzma2Reader` answers
                                // UnexpectedEof on the same input; a wedge is
                                // strictly worse than either that or an empty
                                // read.)
                                if self.next_sequence_to_dispatch == 0 {
                                    self.state = State::Finished;
                                    continue;
                                }
                                self.last_sequence_id =
                                    Some(self.next_sequence_to_dispatch - 1);
                                self.state = State::Draining;
                                continue;
                            }
                            Err(error) => {
                                set_error(error, &self.error_store, &self.shutdown_flag);
                                self.state = State::Error;
                                continue;
                            }
                        }
                    }

                    // The read-ahead budget is full, so we MUST wait for a
                    // result to make progress.
                    //
                    // nzbfast: every arm here returns to the OUTER loop, where
                    // upstream had an inner `loop` that only left on a result.
                    // That is what pinned the dispatcher: its `Timeout` arm
                    // went straight back into `recv_timeout` without ever
                    // re-reading the queue, so once the reader had dispatched
                    // one unit it stayed here until that unit came back, and
                    // no second unit could be read in the meantime. Coming
                    // back out costs one turn of the outer loop per 100 ms.
                    match self.result_rx.recv_timeout(ERROR_CHECK_INTERVAL) {
                        Ok((seq, result)) => {
                            self.results_received += 1;
                            if seq == self.next_sequence_to_return {
                                self.next_sequence_to_return += 1;
                                return Ok(Some(result));
                            }
                            self.out_of_order_chunks.insert(seq, result);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if let Some(err) = self.error_store.lock().unwrap().take() {
                                self.state = State::Error;
                                return Err(err);
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            // All workers are done.
                            self.state = State::Draining;
                        }
                    }
                }
                State::Draining => {
                    if let Some(last_seq) = self.last_sequence_id {
                        if self.next_sequence_to_return > last_seq {
                            self.state = State::Finished;
                            continue;
                        }
                    }

                    // In Draining state, we only wait for results.
                    loop {
                        match self.result_rx.recv_timeout(ERROR_CHECK_INTERVAL) {
                            Ok((seq, result)) => {
                                self.results_received += 1;
                                if seq == self.next_sequence_to_return {
                                    self.next_sequence_to_return += 1;
                                    return Ok(Some(result));
                                } else {
                                    self.out_of_order_chunks.insert(seq, result);
                                    break;
                                }
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                if let Some(err) = self.error_store.lock().unwrap().take() {
                                    self.state = State::Error;
                                    return Err(err);
                                }
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => {
                                // All workers finished, and channel is empty. We are done.
                                self.state = State::Finished;
                                break;
                            }
                        }
                    }
                }
                State::Finished => {
                    return Ok(None);
                }
                State::Error => {
                    // The error was already logged, now we just propagate it.
                    return Err(self.error_store.lock().unwrap().take().unwrap_or_else(|| {
                        io::Error::other("decompression failed with an unknown error")
                    }));
                }
            }
        }
    }
}

/// The logic for a single worker thread.
fn worker_thread_logic(
    worker_handle: WorkerHandle<WorkUnit>,
    result_tx: SyncSender<ResultUnit>,
    dict_size: u32,
    preset_dict: Option<Arc<Vec<u8>>>,
    shutdown_flag: Arc<AtomicBool>,
    error_store: Arc<Mutex<Option<io::Error>>>,
) {
    // nzbfast: the `active_workers` counter upstream maintained here is
    // gone. Nothing reads it any more - the dispatcher budgets on units in
    // flight instead, which is the quantity a worker cannot empty out from
    // under it - and a count that only becomes true after a worker pops is
    // what round 11 already had to work around.
    while !shutdown_flag.load(Ordering::Acquire) {
        let Some((seq, work_unit_data, decoded_len)) = worker_handle.steal() else {
            // No more work available and queue is closed
            break;
        };

        let mut reader = Lzma2Reader::new(
            work_unit_data.as_slice(),
            dict_size,
            preset_dict.as_deref().map(|v| v.as_slice()),
        );

        // nzbfast: the exact size the chunk headers declared, so a 64 MiB
        // unit is one allocation rather than six doublings and five copies.
        //
        // CAPPED by `prealloc_for`, because `decoded_len` is summed from
        // chunk headers INSIDE the packed payload and no header-level
        // gate can see it: `nameprobe`'s 7z content gate charges the
        // declared dictionary and PPMd window only, and sevenz-rust2's
        // own admission is a dictionary-size check. A compressed chunk
        // costs six input bytes and may declare 2 MiB, so ~6 KiB of
        // crafted payload declares 2 GB and ~1 MiB declares ~350 GB.
        // That reached `Vec::with_capacity` raw, and a reservation that
        // cannot be met calls `handle_alloc_error`, which ABORTS the
        // process rather than returning an error a caller could refuse
        // the archive on. Past the cap the Vec grows the ordinary way,
        // which costs a handful of copies on a unit already big enough
        // for the decode itself to dominate.
        //
        // The comment here used to say "a wrong declaration only costs a
        // `Vec` growth". That is true of an UNDER-declaration and false
        // of the hostile direction.
        let mut decompressed_data = Vec::with_capacity(prealloc_for(decoded_len));
        // And the decode is held TO that declaration. LZMA2 states each
        // chunk's decoded size exactly (control bits 0..4 plus the first
        // two header bytes for a compressed chunk, the length word for an
        // uncompressed one), so the sum is the unit's output for any
        // well-formed stream. `read_to_end` alone took no bound at all,
        // and the whole unit is materialized here before the consumer
        // sees one byte of it, so a write-side bomb guard is not what can
        // stop it.
        let result = match Read::take(&mut reader, decoded_len as u64 + 1)
            .read_to_end(&mut decompressed_data)
        {
            Ok(_) if decompressed_data.len() > decoded_len => {
                set_error(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "LZMA2 work unit decoded past the size its chunk headers declared",
                    ),
                    &error_store,
                    &shutdown_flag,
                );
                return;
            }
            Ok(_) => decompressed_data,
            Err(error) => {
                set_error(error, &error_store, &shutdown_flag);
                return;
            }
        };

        if result_tx.send((seq, result)).is_err() {
            return;
        }
    }
}

impl<R: Read> Read for Lzma2ReaderMt<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let bytes_read = self.current_chunk.read(buf)?;

        if bytes_read > 0 {
            return Ok(bytes_read);
        }

        let chunk_data = self.get_next_uncompressed_chunk()?;

        let Some(chunk_data) = chunk_data else {
            // This is the clean end of the stream.
            return Ok(0);
        };

        self.current_chunk = Cursor::new(chunk_data);

        // Recursive call to read the new chunk data.
        self.read(buf)
    }
}

impl<R: Read> Drop for Lzma2ReaderMt<R> {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::Release);
        self.work_queue.close();
        // Worker threads will exit when the work queue is closed.
        // JoinHandles will be dropped, which is fine since we set the shutdown flag,
    }
}

// ---------------------------------------------------------------------------
// nzbfast: the multi-threaded arm of `decoder::differential`. That module
// proves the symbol loop; this one proves the READER around it - that the
// dispatcher's read-ahead, the out-of-order reassembly and the worker cap
// deliver exactly the bytes the single-threaded reader does, on the same
// 7-Zip fixtures and on streams with more independent blocks than there are
// workers (and fewer).
//
// A scheduling change is only ever as good as the thing that would catch it
// reordering output, so every assert here is a byte comparison against
// `Lzma2Reader` over the identical stream, never against a stored digest.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// The same fixtures `decoder::differential` uses: raw LZMA2 pack streams
    /// lifted out of one-folder `.7z` archives built by 7-Zip. Each is a
    /// single independent block, which is the shape a 7-Zip archive written
    /// without multi-threading has, and the case where the MT reader must
    /// still be exactly right with nothing to parallelise.
    const FIXTURES: &[(&str, &[u8])] = &[
        ("mx1_text", include_bytes!("../testdata/mx1_text.lzma2")),
        ("mx5_text", include_bytes!("../testdata/mx5_text.lzma2")),
        ("mx9_text", include_bytes!("../testdata/mx9_text.lzma2")),
        ("mx1_code", include_bytes!("../testdata/mx1_code.lzma2")),
        ("mx9_code", include_bytes!("../testdata/mx9_code.lzma2")),
        (
            "mx9_code_bcj",
            include_bytes!("../testdata/mx9_code_bcj.lzma2"),
        ),
    ];

    /// Every fixture plaintext is under 2 MiB, so a 2 MiB window is always at
    /// least the window the encoder used.
    const DICT: u32 = 1 << 21;

    fn decode_st(stream: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        Lzma2Reader::new(stream, DICT, None).read_to_end(&mut out)?;
        Ok(out)
    }

    fn decode_mt(stream: &[u8], workers: u32) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        Lzma2ReaderMt::new(stream, DICT, None, workers).read_to_end(&mut out)?;
        Ok(out)
    }

    /// Drains through a fixed, deliberately awkward buffer size. The read-ahead
    /// budget is spent and refilled from inside `read()`, so how fast the
    /// caller pulls is part of the scheduling under test: a one-byte consumer
    /// and a 4 MiB one walk different paths through the dispatcher.
    fn decode_mt_in_reads(stream: &[u8], workers: u32, read_size: usize) -> io::Result<Vec<u8>> {
        let mut reader = Lzma2ReaderMt::new(stream, DICT, None, workers);
        let mut out = Vec::new();
        let mut buf = vec![0u8; read_size];
        loop {
            match reader.read(&mut buf)? {
                0 => return Ok(out),
                n => out.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// Builds an LZMA2 stream of `blocks` independent blocks by encoding each
    /// slice on its own and concatenating, which is structurally what 7-Zip
    /// emits when it compresses multi-threaded: every block opens with a
    /// dict-reset control (>= 0xE0) and so starts a new work unit.
    #[cfg(feature = "encoder")]
    fn many_block_stream(blocks: usize, block_len: usize) -> (Vec<u8>, Vec<u8>) {
        use crate::{Lzma2Options, Lzma2Writer, Write};

        let mut plain = Vec::with_capacity(blocks * block_len);
        let mut x: u32 = 0x1234_5678;
        while plain.len() < blocks * block_len {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            match x >> 29 {
                0..=2 => plain.extend_from_slice(b"the quick brown fox jumps over"),
                3..=4 => plain.extend(core::iter::repeat_n(b'=', (x >> 8) as usize % 200)),
                5 => {
                    let from = plain.len().saturating_sub(4096);
                    let take = ((x >> 4) as usize % 300).min(plain.len() - from);
                    let slice = plain[from..from + take].to_vec();
                    plain.extend_from_slice(&slice);
                }
                _ => plain.extend_from_slice(&x.to_le_bytes()),
            }
        }
        plain.truncate(blocks * block_len);

        let mut stream = Vec::new();
        for block in plain.chunks(block_len) {
            let mut options = Lzma2Options::with_preset(6);
            options.lzma_options.dict_size = DICT;
            let mut packed = Vec::new();
            let mut writer = Lzma2Writer::new(&mut packed, options);
            writer.write_all(block).unwrap();
            writer.finish().unwrap();
            // Drop this block's end-of-stream marker; one terminates the whole
            // concatenation below.
            assert_eq!(packed.pop(), Some(0x00), "expected an LZMA2 end marker");
            assert!(
                packed[0] >= 0xE0,
                "block does not open with a dict reset: {:#04x}",
                packed[0]
            );
            stream.extend_from_slice(&packed);
        }
        stream.push(0x00);
        (stream, plain)
    }

    #[test]
    fn mt_matches_single_threaded_on_the_7zip_fixtures() {
        for (name, stream) in FIXTURES {
            let want = decode_st(stream).expect("single-threaded decode failed");
            for workers in [1u32, 2, 3, 4, 8, 16] {
                let got = decode_mt(stream, workers).unwrap_or_else(|error| {
                    panic!("{name} at {workers} workers: {error}");
                });
                assert!(
                    got == want,
                    "{name} at {workers} workers: {} bytes, expected {}",
                    got.len(),
                    want.len()
                );
            }
        }
    }

    /// The case the reader exists for, and the one a scheduling bug shows up
    /// in: many independent blocks, decoded out of order and reassembled.
    /// Worker counts deliberately straddle the block count in both
    /// directions - 64 workers over 5 blocks is the shape where a reader that
    /// budgets its read-ahead wrongly either spawns threads for work that
    /// does not exist or waits for a result that will never come.
    #[test]
    #[cfg(feature = "encoder")]
    fn mt_matches_single_threaded_on_many_block_streams() {
        for blocks in [1usize, 2, 5, 17] {
            let (stream, plain) = many_block_stream(blocks, 40_000);
            let want = decode_st(&stream).expect("single-threaded decode failed");
            assert!(
                want == plain,
                "{blocks} blocks: the fixture does not decode"
            );
            for workers in [1u32, 2, 3, 8, 64] {
                let got = decode_mt(&stream, workers).unwrap_or_else(|error| {
                    panic!("{blocks} blocks at {workers} workers: {error}");
                });
                assert!(
                    got == plain,
                    "{blocks} blocks at {workers} workers: {} bytes, expected {}",
                    got.len(),
                    plain.len()
                );
            }
        }
    }

    /// The consumer's pull rate is an input to the dispatcher, so vary it.
    #[test]
    #[cfg(feature = "encoder")]
    fn mt_matches_single_threaded_at_every_consumer_read_size() {
        let (stream, plain) = many_block_stream(9, 40_000);
        for read_size in [1usize, 7, 4096, 1 << 20] {
            for workers in [1u32, 4, 8] {
                let got = decode_mt_in_reads(&stream, workers, read_size).unwrap_or_else(|error| {
                    panic!("{read_size}-byte reads at {workers} workers: {error}");
                });
                assert!(
                    got == plain,
                    "{read_size}-byte reads at {workers} workers: {} bytes, expected {}",
                    got.len(),
                    plain.len()
                );
            }
        }
    }

    /// A corrupt block must reach the caller as an error, from whichever
    /// worker met it, rather than as short or wrong output - and must not
    /// wedge the dispatcher, which is the failure mode a bounded read-ahead
    /// plus a bounded result channel could introduce. Both readers are asked
    /// the same question and must give the same answer.
    #[test]
    #[cfg(feature = "encoder")]
    fn mt_and_single_threaded_agree_on_corrupt_streams() {
        let (stream, _) = many_block_stream(9, 40_000);
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..24 {
            let mut bad = stream.clone();
            for _ in 0..1 + (next() % 8) {
                let at = (next() as usize) % bad.len();
                bad[at] ^= 1u8 << (next() % 8);
            }
            let want = decode_st(&bad);
            for workers in [2u32, 8] {
                let got = decode_mt(&bad, workers);
                assert_eq!(
                    got.is_ok(),
                    want.is_ok(),
                    "round {round} at {workers} workers: outcome differs \
                     (mt {got:?} vs st {want:?})"
                );
                if let (Ok(got), Ok(want)) = (&got, &want) {
                    assert!(
                        got == want,
                        "round {round} at {workers} workers: output differs"
                    );
                }
            }
        }
    }

    /// A truncated stream is the other half of the same question: the
    /// dispatcher reaches EOF with units still in flight.
    #[test]
    #[cfg(feature = "encoder")]
    fn mt_and_single_threaded_agree_on_truncated_streams() {
        let (stream, _) = many_block_stream(9, 40_000);
        for cut in [1usize, 2, 3, 5, 8, 13] {
            let short = &stream[..stream.len() * cut / 16];
            let want = decode_st(short);
            for workers in [2u32, 8] {
                let got = decode_mt(short, workers);
                assert_eq!(
                    got.is_ok(),
                    want.is_ok(),
                    "cut {cut}/16 at {workers} workers: outcome differs"
                );
                if let (Ok(got), Ok(want)) = (&got, &want) {
                    assert!(
                        got == want,
                        "cut {cut}/16 at {workers} workers: output differs"
                    );
                }
            }
        }
    }
    /// nzbfast: a work unit's DECLARED decoded size is attacker-controlled
    /// and no header-level gate can see it, so the worker's preallocation
    /// is capped rather than trusting the declaration.
    ///
    /// The stream below is ONE work unit: a leading dict-reset chunk
    /// followed by dependent chunks (control 0x80..0xDF, so nothing after
    /// the first splits the unit), each six or seven bytes on the wire and
    /// each declaring the format's maximum 2 MiB of output. 200,000 of
    /// them is ~1.2 MB of input declaring ~400 GB.
    ///
    /// What the DECODE asserts is the reachable half: the archive is
    /// refused (one data byte cannot feed an LZMA range decoder) rather
    /// than costing memory proportional to what its headers claimed. The
    /// reservation itself is asserted through `prealloc_for`, because an
    /// end-to-end decode CANNOT carry it - see that function's note on why
    /// removing the cap does not fail this test on a Mac.
    #[test]
    fn an_over_declared_work_unit_is_refused_without_reserving_what_it_declared() {
        // control 0xFF: dict reset + new props (5-byte header), unpack
        // bits 0x1F and unpack low half 0xFFFF -> declares 2 MiB; packed
        // 0x0000 -> one data byte; then the props byte.
        let mut stream: Vec<u8> = vec![0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
        // control 0x9F: compressed, no reset (4-byte header), the same
        // 2 MiB declaration, one data byte. Dependent, so the unit never
        // splits.
        for _ in 0..200_000 {
            stream.extend_from_slice(&[0x9F, 0xFF, 0xFF, 0x00, 0x00, 0x00]);
        }
        stream.push(0x00);

        let declared: usize = 200_001 * (1 << 21);
        assert!(
            declared > 16 * PREALLOC_CAP,
            "the fixture must declare far more than the cap, not {declared}"
        );
        assert_eq!(
            prealloc_for(declared),
            PREALLOC_CAP,
            "the worker must reserve the cap, not the ~400 GB the headers claim"
        );
        for workers in [2u32, 4] {
            assert!(
                decode_mt(&stream, workers).is_err(),
                "{workers} workers: a unit with one data byte per 2 MiB claim must be refused"
            );
        }
    }

    /// The reservation rule on its own, which is the half no end-to-end
    /// decode can assert: an ordinary unit is reserved exactly, and any
    /// declaration at or past the cap is reserved at the cap.
    ///
    /// NEGATIVE CONTROL, run: making `prealloc_for` the identity fails the
    /// last two cases by name.
    #[test]
    fn the_reservation_follows_the_declaration_only_up_to_the_cap() {
        assert_eq!(prealloc_for(0), 0);
        assert_eq!(prealloc_for(1 << 20), 1 << 20, "a 1 MiB unit is exact");
        assert_eq!(
            prealloc_for(PREALLOC_CAP - 1),
            PREALLOC_CAP - 1,
            "just under the cap is still exact"
        );
        assert_eq!(prealloc_for(PREALLOC_CAP), PREALLOC_CAP);
        assert_eq!(
            prealloc_for(usize::MAX),
            PREALLOC_CAP,
            "the largest declaration expressible must still reserve the cap"
        );
    }
    /// nzbfast: an EMPTY LZMA2 pack stream. A 7z folder may declare
    /// `pack_size` 0, so the very first control byte read is already EOF
    /// and no work unit is ever dispatched.
    ///
    /// That used to WEDGE: `last_sequence_id` became `Some(0)` through a
    /// `saturating_sub(1)` on a dispatch counter still at zero, naming a
    /// unit nobody sent, and `Draining` then waited on a channel whose
    /// sender the reader itself owns (so never `Disconnected`) with its
    /// one pre-spawned worker parked in `steal()`. Permanently, on a
    /// chase thread with no `catch_unwind` - which would not have helped
    /// anyway, since nothing panicked.
    ///
    /// NEGATIVE CONTROL, run: restore the `saturating_sub(1)` arm and
    /// this test hangs instead of failing. It is written with a watchdog
    /// thread for exactly that reason - a wedge does not fail a test, it
    /// stops the suite, and nextest reports a retried timeout as "flaky".
    #[test]
    fn an_empty_pack_stream_ends_instead_of_wedging() {
        for workers in [1u32, 2, 8] {
            let (tx, rx) = mpsc::channel::<io::Result<Vec<u8>>>();
            let handle = thread::spawn(move || {
                let mut out = Vec::new();
                let r = Lzma2ReaderMt::new(&[][..], DICT, None, workers).read_to_end(&mut out);
                let _ = tx.send(r.map(|_| out));
            });
            match rx.recv_timeout(Duration::from_secs(20)) {
                Ok(Ok(out)) => assert!(
                    out.is_empty(),
                    "{workers} workers: an empty stream cannot decode to bytes"
                ),
                // An error is a perfectly good answer too - the
                // single-threaded reader gives UnexpectedEof here. What
                // must not happen is neither.
                Ok(Err(_)) => {}
                Err(_) => panic!(
                    "{workers} workers: the reader never returned on an empty pack stream"
                ),
            }
            handle.join().expect("the reader thread must not panic");
        }
    }

    /// The same shape one layer in: a stream that is nothing but the
    /// end-of-stream marker, which `read_and_dispatch_chunk` takes
    /// through its `control == 0x00` arm rather than through EOF. That
    /// one DOES dispatch (the marker byte makes the unit non-empty), so
    /// it is the control arm for the fix above.
    #[test]
    fn a_marker_only_stream_still_decodes_to_nothing() {
        let mut out = Vec::new();
        Lzma2ReaderMt::new(&[0x00u8][..], DICT, None, 2)
            .read_to_end(&mut out)
            .expect("a bare end marker is a valid empty stream");
        assert!(out.is_empty());
    }
    /// nzbfast: every worker builds its own `Lzma2Reader` and so its own
    /// dictionary, while the admission gates above this reader charge the
    /// declared dictionary once. A crafted archive declaring 64 MiB - free
    /// under nzbkit's 7z content gate - committed `workers x 64 MiB` of
    /// zeroed pages for a few KB of input, and the props byte allows a
    /// declaration up to 4 GiB.
    ///
    /// NEGATIVE CONTROL, run: restore `num_workers.clamp(1, 256)` and the
    /// last three cases fail by name.
    #[test]
    fn the_worker_count_follows_the_dictionary_size() {
        // An ordinary dictionary costs the caller nothing: it gets every
        // worker it asked for.
        assert_eq!(workers_for_dict(20, 1 << 20), 20, "1 MiB x 20 is affordable");
        assert_eq!(workers_for_dict(8, 64 << 20), 8, "64 MiB x 8 is the budget");
        assert_eq!(workers_for_dict(1, u32::MAX), 1, "never below one");
        // ...and the shapes that do not fit give up PARALLELISM, not
        // correctness.
        assert_eq!(
            workers_for_dict(20, 64 << 20),
            8,
            "64 MiB x 20 is 1.3 GB of zeroed pages; the budget affords eight"
        );
        assert_eq!(
            workers_for_dict(256, 1 << 30),
            1,
            "a 1 GiB dictionary affords exactly one worker"
        );
        assert_eq!(
            workers_for_dict(256, u32::MAX),
            1,
            "the largest dictionary the props byte allows affords one"
        );
        // The asked-for count is still a ceiling, and the hard cap holds.
        assert_eq!(workers_for_dict(0, 1 << 20), 1);
        assert_eq!(workers_for_dict(u32::MAX, 4096), 256);
    }
}
