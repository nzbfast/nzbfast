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
        let max_workers = num_workers.clamp(1, 256);

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
                                self.last_sequence_id =
                                    Some(self.next_sequence_to_dispatch.saturating_sub(1));
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
        // A wrong declaration only costs a `Vec` growth: `read_to_end` is
        // still what decides how many bytes come out.
        let mut decompressed_data = Vec::with_capacity(decoded_len);
        let result = match reader.read_to_end(&mut decompressed_data) {
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
}
