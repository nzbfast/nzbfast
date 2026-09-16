//! The streamed recovery record's CRC64 and GF(2^16) fold on worker
//! threads, for [`super::InlineRecoveryFolder`].
//!
//! Serial, the fold is two passes over every byte of the archive: a CRC64
//! per (group, shard) slice and every parity row's multiply. On 512 MiB at
//! `-rr5` that was 0.30 s and 0.28 s of a 0.76 s create, on one core.
//! Two parallel shapes lost before this one, both a rayon dispatch per
//! 1 MiB write: the fold's 64 KiB pieces on the pool, and each write's
//! whole slices' CRCs on the pool (research/RARFAST-BENCH-2026-09-14.md
//! 6.4 and 7.5; 11x the CPU for a slower wall).
//!
//! This shape copies the writes into a large batch and hands each batch
//! to persistent threads, one job per thread, so a batch costs a handful
//! of channel messages rather than hundreds of pool tasks. A batch splits
//! two ways at once, and no two jobs touch the same memory:
//!
//! - its CRC64 into contiguous pieces cut at slice STARTS, so every piece
//!   but the first begins a slice from a zero state and needs nothing from
//!   the piece before it; the first continues the state the last batch
//!   ended inside;
//! - its fold by parity ROW: a row job walks the whole batch into its own
//!   row, which it owns while the job is out. Two data shards write the
//!   same columns of a row, so the batch cannot be split by shard, but
//!   rows are disjoint.
//!
//! The writer does not wait for a batch: it fills the next one while the
//! workers fold the last, and waits only when handing the next one out.
//! So at most two batches are live, and the working set is the record's
//! rows plus two batches. Batches are a whole number of symbols (even), so
//! only the prefix's own last byte can be half a symbol, and a row job
//! folds that one against its zero padding as the serial `finish` does.

use std::ops::Range;
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

use super::{crc64_update, Error, Gf16MulTable, Result, SliceLayout};

/// Below this the serial fold is a few tens of milliseconds and the team
/// is not started.
pub(super) const MIN_PREFIX: u64 = 32 << 20;
/// The most worker threads one folder starts. Swept at 4, 8, 12 and 16
/// against batches of 4, 8 and 16 MiB over 512 MiB at `-rr5` on the
/// 32-core dev Mac (15 Sep 2026, load average 61 to 73): every arm ran
/// 0.23 to 0.31 s at best against the serial fold's 1.06 and rar's 0.62,
/// and no wider arm was measurably faster than 8, whose work is about a
/// second of CPU in all.
pub(super) const MAX_WORKERS: usize = 8;
/// Bytes handed to the workers at a time. Two batches are live at once, so
/// this is the team's memory: 8 MiB put peak RSS at 101 MiB (rar 101, the
/// serial fold 84, 16 MiB batches 117) for no measurable wall against 16.
pub(super) const BATCH_BYTES: usize = 8 << 20;

/// One worker's share of one batch.
struct Job {
    batch: Arc<Vec<u8>>,
    /// The prefix position of the batch's first byte.
    start: u64,
    crc: Option<CrcPiece>,
    /// The parity rows this job folds the whole batch into, by row index.
    rows: Vec<(usize, Vec<u8>)>,
}

/// A contiguous run of a batch whose slice CRCs one job computes.
struct CrcPiece {
    range: Range<usize>,
    /// The state the piece's first slice continues from: the last batch's
    /// trailing state for the first piece, zero for one cut at a slice start.
    initial: u64,
    /// The piece holds the batch's last byte, so its trailing state is the
    /// next batch's `initial`.
    last: bool,
}

struct Done {
    rows: Vec<(usize, Vec<u8>)>,
    /// Final `(group, shard, state)` of every slice the job completed.
    states: Vec<(usize, usize, u64)>,
    trailing: Option<u64>,
}

type Reply = std::thread::Result<Result<Done>>;

pub(super) struct FoldTeam {
    layout: SliceLayout,
    jobs: Vec<Sender<Job>>,
    replies: Receiver<Reply>,
    workers: Vec<JoinHandle<()>>,
    batch: Vec<u8>,
    batch_cap: usize,
    /// The prefix position of `batch`'s first byte.
    batch_start: u64,
    /// The parity rows; a row is `None` while a job holds it.
    rows: Vec<Option<Vec<u8>>>,
    states_by_group: Vec<Vec<u64>>,
    /// The running state of the slice the handed-out bytes end inside.
    slice_crc: u64,
    in_flight: usize,
    /// The batch last handed out, reused once every job has let go of it.
    spent: Option<Arc<Vec<u8>>>,
}

impl FoldTeam {
    /// Starts `workers` threads over `parity` and `states_by_group`, which
    /// the team owns until [`FoldTeam::finish`]. Hands both back when fewer
    /// than two threads could be spawned.
    #[allow(clippy::type_complexity)]
    pub(super) fn start(
        layout: SliceLayout,
        matrix: &[Vec<u16>],
        parity: Vec<Vec<u8>>,
        states_by_group: Vec<Vec<u64>>,
        workers: usize,
        batch: usize,
    ) -> std::result::Result<Self, (Vec<Vec<u8>>, Vec<Vec<u64>>)> {
        let matrix = Arc::new(matrix.to_vec());
        let (reply_to, replies) = mpsc::channel();
        let mut jobs = Vec::with_capacity(workers);
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (send, receive) = mpsc::channel();
            let reply_to = reply_to.clone();
            let matrix = Arc::clone(&matrix);
            let spawned = std::thread::Builder::new()
                .name("rars-rr-fold".into())
                .spawn(move || work(&receive, &reply_to, &matrix, layout));
            match spawned {
                Ok(handle) => {
                    jobs.push(send);
                    handles.push(handle);
                }
                Err(_) => break,
            }
        }
        // Only the workers may hold a reply sender, so a receive fails
        // rather than blocks if every one of them is gone.
        drop(reply_to);
        let batch_cap = (batch & !1).max(2);
        let mut team = Self {
            layout,
            jobs,
            replies,
            workers: handles,
            batch: Vec::with_capacity(batch_cap.min(usize::try_from(layout.prefix_len).unwrap_or(batch_cap))),
            batch_cap,
            batch_start: 0,
            rows: parity.into_iter().map(Some).collect(),
            states_by_group,
            slice_crc: 0,
            in_flight: 0,
            spent: None,
        };
        if team.workers.len() < 2 {
            let parity = team.rows.iter_mut().filter_map(Option::take).collect();
            return Err((parity, std::mem::take(&mut team.states_by_group)));
        }
        Ok(team)
    }

    pub(super) fn push(&mut self, mut bytes: &[u8]) -> Result<()> {
        let end = (self.batch.len() as u64)
            .checked_add(bytes.len() as u64)
            .and_then(|pending| pending.checked_add(self.batch_start))
            .ok_or(Error::PlanOverflow)?;
        if end > self.layout.prefix_len {
            return Err(Error::PrefixExceedsPlan);
        }
        while !bytes.is_empty() {
            let take = (self.batch_cap - self.batch.len()).min(bytes.len());
            let (head, rest) = bytes.split_at(take);
            self.batch.extend_from_slice(head);
            bytes = rest;
            if self.batch.len() == self.batch_cap {
                self.hand_out()?;
            }
        }
        Ok(())
    }

    /// The parity rows and the slice CRC states over the whole prefix.
    #[allow(clippy::type_complexity)]
    pub(super) fn finish(mut self) -> Result<(Vec<Vec<u8>>, Vec<Vec<u64>>)> {
        if self.batch_start + self.batch.len() as u64 != self.layout.prefix_len {
            return Err(Error::PrefixExceedsPlan);
        }
        self.hand_out()?;
        self.collect()?;
        let mut parity = Vec::with_capacity(self.rows.len());
        for row in &mut self.rows {
            parity.push(row.take().ok_or(Error::PlanOverflow)?);
        }
        Ok((parity, std::mem::take(&mut self.states_by_group)))
    }

    /// Waits for the last batch's jobs, then hands the pending one out.
    fn hand_out(&mut self) -> Result<()> {
        self.collect()?;
        let len = self.batch.len();
        if len == 0 {
            return Ok(());
        }
        let next = match self.spent.take().map(Arc::try_unwrap) {
            Some(Ok(mut reused)) => {
                reused.clear();
                reused
            }
            _ => Vec::with_capacity(self.batch_cap),
        };
        let batch = Arc::new(std::mem::replace(&mut self.batch, next));
        let start = self.batch_start;
        self.batch_start += len as u64;

        let workers = self.jobs.len();
        let mut cuts = vec![0usize];
        for share in 1..workers {
            let target = start + (len / workers * share) as u64;
            let cut = usize::try_from(self.layout.slice_start(target).saturating_sub(start))
                .map_err(|_| Error::PlanOverflow)?;
            if cut > *cuts.last().unwrap_or(&0) {
                cuts.push(cut);
            }
        }
        cuts.push(len);
        let mut jobs: Vec<Job> = (0..workers)
            .map(|_| Job {
                batch: Arc::clone(&batch),
                start,
                crc: None,
                rows: Vec::new(),
            })
            .collect();
        for (index, piece) in cuts.windows(2).enumerate() {
            jobs[index].crc = Some(CrcPiece {
                range: piece[0]..piece[1],
                initial: if index == 0 { self.slice_crc } else { 0 },
                last: piece[1] == len,
            });
        }
        for (index, row) in self.rows.iter_mut().enumerate() {
            let row = row.take().ok_or(Error::PlanOverflow)?;
            jobs[index % workers].rows.push((index, row));
        }
        self.spent = Some(batch);
        for (sender, job) in self.jobs.iter().zip(jobs) {
            if job.crc.is_none() && job.rows.is_empty() {
                continue;
            }
            // A worker only stops receiving when the team drops its sender.
            if sender.send(job).is_err() {
                panic!("a recovery fold worker exited while its team was live");
            }
            self.in_flight += 1;
        }
        Ok(())
    }

    /// Waits for every job out, putting its rows and states back.
    fn collect(&mut self) -> Result<()> {
        while self.in_flight > 0 {
            let Ok(reply) = self.replies.recv() else {
                panic!("every recovery fold worker exited with jobs outstanding");
            };
            self.in_flight -= 1;
            let done = match reply {
                Ok(done) => done?,
                Err(payload) => panic::resume_unwind(payload),
            };
            for (index, row) in done.rows {
                self.rows[index] = Some(row);
            }
            for (group, shard, state) in done.states {
                self.states_by_group[group][shard] = state;
            }
            if let Some(trailing) = done.trailing {
                self.slice_crc = trailing;
            }
        }
        Ok(())
    }
}

impl Drop for FoldTeam {
    fn drop(&mut self) {
        // Closing the job channels ends each worker's loop once its current
        // job is done.
        self.jobs.clear();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn work(jobs: &Receiver<Job>, replies: &Sender<Reply>, matrix: &[Vec<u16>], layout: SliceLayout) {
    for job in jobs {
        let reply = panic::catch_unwind(AssertUnwindSafe(|| run(job, matrix, layout)));
        if replies.send(reply).is_err() {
            return;
        }
    }
}

fn run(job: Job, matrix: &[Vec<u16>], layout: SliceLayout) -> Result<Done> {
    let Job {
        batch,
        start,
        crc,
        mut rows,
    } = job;
    let mut states = Vec::new();
    let mut trailing = None;
    if let Some(piece) = crc {
        let mut state = piece.initial;
        let piece_start = start + piece.range.start as u64;
        layout.walk(piece_start, &batch[piece.range], |step| {
            state = crc64_update(step.chunk, state);
            if step.ends_slice {
                states.push((step.group, step.shard, state));
                state = 0;
            }
            Ok(())
        })?;
        if piece.last {
            trailing = Some(state);
        }
    }
    for (index, row) in &mut rows {
        let coefficients = &matrix[*index];
        let mut table: Option<(usize, Option<Gf16MulTable>)> = None;
        layout.walk(start, &batch, |step| {
            if table.as_ref().map(|(shard, _)| *shard) != Some(step.shard) {
                let coefficient = coefficients[step.shard];
                table = Some((
                    step.shard,
                    (coefficient != 0).then(|| Gf16MulTable::new(coefficient)),
                ));
            }
            let Some((_, Some(table))) = &table else {
                return Ok(());
            };
            let whole = step.chunk.len() & !1;
            let at = step.offset;
            table.fold_into(&mut row[at..at + whole], &step.chunk[..whole]);
            if let Some(&low) = step.chunk.get(whole) {
                // Only the prefix's last byte can be half a symbol; its high
                // byte is the last shard's zero padding.
                table.fold_into(&mut row[at + whole..at + whole + 2], &[low, 0]);
            }
            Ok(())
        })?;
    }
    // Let go of the batch before replying, so the team can reuse it.
    drop(batch);
    Ok(Done {
        rows,
        states,
        trailing,
    })
}
