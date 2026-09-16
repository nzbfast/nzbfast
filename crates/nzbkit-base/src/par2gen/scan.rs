//! The creator's ONE read pass over the members, and the process-wide
//! admission that bounds it: the per-member scan plans (mapped,
//! positional-parallel, streamed), the fused scan that hashes the same
//! bytes the fold is reading, the head-only prepass that fixes file-id
//! order before any body hash exists, and the [`CreateAdmission`] gauge
//! every create charges its accumulator and scan pool against.
//!
//! Split out of `par2gen.rs` on 9 Sep 2026 when that file reached the
//! size gate's 4,000-line ceiling with zero headroom (claim
//! `par2gen-size-split-9sep`). Bodies moved verbatim; only the
//! visibility words are new, because a child module's items have to be
//! spelled `pub(super)` to stay reachable from the parent they were
//! written in.

use super::*;

/// Everything measured about one member in the single read pass.
pub(super) struct Scanned {
    pub(super) name_padded: Vec<u8>,
    pub(super) file_id: [u8; 16],
    pub(super) md5_whole: [u8; 16],
    pub(super) md5_16k: [u8; 16],
    pub(super) length: u64,
    /// Per-block (MD5, CRC32) over the block ZERO-PADDED to `block_size`,
    /// per spec. Empty for a 0-byte file - a real creator emits no IFSC
    /// packet for one, and neither do we.
    pub(super) blocks: Vec<([u8; 16], u32)>,
    /// The store change this member's digest-cache pass owes
    /// (`crate::digest_cache::Pending`), committed only once the whole set
    /// is written - never for a create that fails or is cancelled.
    pub(super) digest: Option<crate::digest_cache::Pending>,
}

/// Ordered checksum state for the sole member of a fused pass: the whole-file
/// and 16 KiB chains plus the per-block products, all advanced from the SAME
/// arena the parity fold is already reading, so the create makes one pass over
/// the payload instead of two.
pub(super) struct FusedScan {
    /// One pinned read handle per member, in slot order: the fold's
    /// reader reads THROUGH these, so the bytes it feeds are the bytes
    /// the checksums cover.
    pub(super) files: Vec<std::fs::File>,
    /// The chains and digests per member, in slot order.
    pub(super) state: Vec<FusedMemberState>,
    /// Eight whole-file chains in lockstep (`md5fast::multi::Md5Lanes`)
    /// when the plan is lane-interleaved (slice size a multiple of 64);
    /// otherwise the members' scalar chains run one at a time.
    pub(super) lanes: Option<crate::md5fast::multi::Md5Lanes>,
}

/// One member's products as the fused pass accumulates them.
pub(super) struct FusedMemberState {
    /// Index into the caller's `members`.
    pub(super) member: usize,
    /// The pinned source's identity and change stamps, the digest cache's
    /// own `Identity`: one read of them per platform, so the Windows arm
    /// carries the volume, file index and change time and not the length
    /// alone (it did until 15 Sep 2026, and a same-length in-place write
    /// during the fold passed `finish_all`).
    pub(super) stamp: crate::disk::Identity,
    pub(super) expected_head: [u8; 16],
    pub(super) whole: Md5,
    /// The whole-file digest once a lane finalised it (lane path); the
    /// scalar `whole` above stands in otherwise (and for an empty member,
    /// which never takes a lane).
    pub(super) whole_digest: Option<[u8; 16]>,
    pub(super) head: Md5,
    pub(super) head_left: usize,
    pub(super) blocks: Vec<([u8; 16], u32)>,
    /// This member's digest-cache pass: a record being validated, or the
    /// member being enrolled, beside the chain (`crate::digest_cache`).
    pub(super) digest: crate::digest_cache::MemberDigest,
    /// The scalar chain stopped because a record validated. Only ever set
    /// off the lanes: eight chains in lockstep are left to finish.
    pub(super) chain_skipped: bool,
}

impl FusedScan {
    /// Pin every member of the set (heads in slot order: `(member index,
    /// length, head MD5, file id)`). None when any member is not a regular
    /// file - pipes and devices have no stable positional snapshot
    /// contract, and the ordinary scanner is the fallback for them.
    ///
    /// Each member's digest-cache pass starts here, against the store the
    /// calling thread's entry point made active.
    pub(super) fn open_all(
        heads: &[(usize, u64, [u8; 16], [u8; 16])],
        members: &[Member],
        block_size: u64,
    ) -> Result<Option<FusedScan>, Par2GenError> {
        let mut files = Vec::with_capacity(heads.len());
        let mut state = Vec::with_capacity(heads.len());
        let digest_cache = crate::digest_cache::active();
        for &(mi, length, expected_head, _) in heads {
            let member = &members[mi];
            let file = std::fs::File::open(&member.path).map_err(io(&member.path))?;
            let metadata = file.metadata().map_err(io(&member.path))?;
            if !metadata.is_file() {
                return Ok(None);
            }
            // No identity to pin (a platform with neither arm) means no
            // snapshot contract either: the ordinary scanner.
            let Ok(stamp) = crate::disk::Identity::of(&file) else {
                return Ok(None);
            };
            if stamp.length() != length {
                return Err(Par2GenError::Other(format!(
                    "{} changed length while the PAR2 set was being built",
                    member.path.display()
                )));
            }
            let digest = crate::digest_cache::MemberDigest::begin(
                digest_cache.as_ref(),
                &file,
                &member.path,
                length,
                crate::digest_cache::FLAG_CREATE,
            );
            files.push(file);
            state.push(FusedMemberState {
                member: mi,
                stamp,
                expected_head,
                whole: Md5::new(),
                whole_digest: None,
                head: Md5::new(),
                head_left: scan_head_len(length),
                blocks: Vec::with_capacity(length.div_ceil(block_size) as usize),
                digest,
                chain_skipped: false,
            });
        }
        // Lanes pay off with members to fill them: a lone member would run
        // one lane and idle seven every step, slower than its scalar chain
        // (measured on an M3 and on the i5, a single 1 GiB member).
        let members_with_bytes = heads.iter().filter(|h| h.1 > 0).count();
        let lanes = (block_size.is_multiple_of(64) && members_with_bytes >= 2)
            .then(crate::md5fast::multi::Md5Lanes::new);
        Ok(Some(FusedScan {
            files,
            state,
            lanes,
        }))
    }

    /// The fused pass reads through descriptors pinned before the fold, so
    /// the "member changed under us" case the placeholder-and-backfill design
    /// refuses has to be caught here instead: both the pinned handle and the
    /// path must still carry the identity the head scan saw. Products come
    /// back in slot order.
    pub(super) fn finish_all(self, members: &[Member]) -> Result<Vec<Scanned>, Par2GenError> {
        let mut out = Vec::with_capacity(self.state.len());
        for (file, st) in self.files.iter().zip(self.state) {
            let member = &members[st.member];
            if !st.stamp.still_holds(file, &member.path) {
                return Err(Par2GenError::Other(format!(
                    "{} changed while the PAR2 set was being built",
                    member.path.display()
                )));
            }
            // A record that validated stopped the scalar chain; the digest
            // pass hands back its MD5, or takes the chain's own.
            let chain = (!st.chain_skipped).then(|| {
                st.whole_digest
                    .unwrap_or_else(|| st.whole.finalize().into())
            });
            let (whole, pending) = st.digest.resolve(chain).map_err(Par2GenError::Other)?;
            let actual = finish_scan(
                member,
                st.stamp.length(),
                whole,
                st.head.finalize().into(),
                st.blocks,
                pending,
            );
            if actual.md5_16k != st.expected_head {
                return Err(Par2GenError::Other(format!(
                    "{} changed identity while the PAR2 set was being built",
                    member.path.display()
                )));
            }
            out.push(actual);
        }
        Ok(out)
    }
}

/// Read exactly `want` bytes, or say which file ran out. A member that
/// shrinks mid-build would otherwise silently produce a set describing
/// bytes that are not there.
pub(super) fn read_exact_or_short(
    r: &mut impl std::io::Read,
    buf: &mut [u8],
    path: &Path,
) -> Result<(), Par2GenError> {
    let mut got = 0usize;
    while got < buf.len() {
        let n = r.read(&mut buf[got..]).map_err(io(path))?;
        if n == 0 {
            return Err(Par2GenError::Other(format!(
                "{} shrank while the recovery set was being built",
                path.display()
            )));
        }
        got += n;
    }
    Ok(())
}

/// Read one member once: whole-file MD5, first-16 KiB MD5, and the
/// per-block checksums. Streamed at `block_size` so a member never has
/// to fit in memory.
/// Scan every member across threads. Files are independent, so the
/// scan used to be the creator's one serial pass - every byte through
/// the whole-file MD5 and again through its block MD5 on ONE core,
/// which on a 1 GiB set is ~3 s of the 4.3 s a create took while 31
/// cores idled (measured 2 Sep 2026, M3 Ultra; ParPar did the same set
/// in 0.74 s). Largest file first off a shared queue, so no fixed-chunk
/// straggler, and each file-level worker hands its file a fair share of
/// the remaining cores for block-parallel hashing - the split
/// `par2repair::verify_all_targets` uses, for the same reason: one big
/// file on a wide box gets every lane instead of one.
///
/// `lane_cap` is [`apriori_scan_lane_width`]'s answer, decided by the
/// caller before anything here spawns and `None` where the caller has no
/// fold running beside this scan to hand cores back to.
pub(super) fn scan_all(
    members: &[Member],
    sizes: &[u64],
    block_size: u64,
    scan_pool: u64,
    lane_cap: Option<usize>,
    control: &CreateControl,
) -> Result<Vec<Scanned>, Par2GenError> {
    debug_assert_eq!(members.len(), sizes.len());
    let mut order: Vec<usize> = (0..members.len()).collect();
    order.sort_by_key(|&i| sizes[i]); // pop() takes the largest
    let queue = std::sync::Mutex::new(order);
    let machine = crate::mem::cpu_workers().max(1);
    let (outer, inner) = scan_pool_geometry(sizes, block_size, machine, scan_pool);
    // The cap lands HERE and not inside the geometry, and it binds only
    // `inner`: the OUTER fan-out is what makes a many-member set's
    // chains run beside each other, which is the quantity both a-priori
    // widths are derived against (`super::chain_pass_bytes`), so moving
    // it would move the ground under them. Narrowing after the search
    // only ever spends LESS than the budget the search admitted.
    let inner = lane_cap.map_or(inner, |cap| inner.min(cap.max(1)));
    // Resolved on the entry point's thread (`CreateControl`), because this
    // may itself be running on a thread the create spawned.
    let digest_cache = control.digest_cache();
    let mut per_thread: Vec<Result<Vec<(usize, Scanned)>, Par2GenError>> = Vec::new();
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..outer)
            .map(|_| {
                s.spawn(|| {
                    let mut out = Vec::new();
                    loop {
                        let next = queue.lock().unwrap_or_else(|e| e.into_inner()).pop();
                        let Some(i) = next else { return Ok(out) };
                        // Between two MEMBERS: a file-level worker's
                        // queue pop is its own and it holds nothing, so
                        // this is a park site as well as a cancel one.
                        control.gate()?;
                        out.push((
                            i,
                            scan_at_length(
                                &members[i],
                                sizes[i],
                                block_size,
                                inner,
                                control,
                                digest_cache,
                            )?,
                        ));
                    }
                })
            })
            .collect();
        per_thread = handles
            .into_iter()
            .map(|h| h.join().expect("par2gen scan worker panicked"))
            .collect();
    });
    let mut slots: Vec<Option<Scanned>> = (0..members.len()).map(|_| None).collect();
    for r in per_thread {
        for (i, sc) in r? {
            slots[i] = Some(sc);
        }
    }
    Ok(slots
        .into_iter()
        .map(|s| s.expect("every member scanned"))
        .collect())
}

/// Below this many bytes a file is hashed on its worker alone: the
/// block fan-out is not worth its thread setup (the same threshold
/// `par2repair`'s verify pool uses).
pub(super) const SCAN_PAR_MIN_BYTES: u64 = 8 << 20;
/// Ceiling on the owned reader/hasher buffer pool of ONE file. This still
/// matters for a single large member, but it is not an aggregate bound:
/// with 32 independent files the dispatcher could allocate it 32 times.
pub(super) const SCAN_FILE_POOL_BYTES: u64 = 64 << 20;
/// Aggregate ceiling on every member scan's owned payload buffers. A quarter
/// of the process budget keeps a small configured box honest; 64 MiB is enough
/// for all 32 ordinary two-buffer lanes, and 256 MiB keeps the same full
/// fan-out through 128 workers on large machines. The 320 MiB upper edge also
/// retains all 32 lanes at the 4.1 MiB default block of an 8 GiB post, leaving
/// that common path byte-for-byte and scheduler-for-scheduler unchanged. One
/// checksum vector per input slice is separate and globally bounded by
/// `MAX_INPUT_SLICES` (under 1 MiB).
pub(super) const SCAN_POOL_MIN_BYTES: u64 = 64 << 20;
pub(super) const SCAN_POOL_MAX_BYTES: u64 = 320 << 20;
/// Hash several small PAR2 blocks per hand-off. A channel trip per 4 KiB
/// slice is measurable on a warm, finely sliced set; a roughly MiB chunk
/// amortizes scheduling while every checksum still observes one exact
/// zero-padded PAR2 block.
pub(super) const SCAN_HASH_CHUNK_BYTES: u64 = 1 << 20;
/// Piece size for the one-worker large-block pipeline. Four MiB amortizes the
/// channel and incremental-digest calls while 32 files still fit exactly in
/// the 256 MiB aggregate ceiling (two pieces per file).
pub(super) const SCAN_STREAM_PIECE_BYTES: u64 = 4 << 20;
/// Below eight MiB, retaining two whole blocks is at most 16 MiB per file and
/// saves splitting the creator's common ~4 MiB default block across messages.
pub(super) const SCAN_STREAM_MIN_BLOCK_BYTES: u64 = 8 << 20;
/// One GiB / one-MiB and larger single-member folds show a repeatable benefit
/// from reading the payload once. Smaller inputs stay on the established
/// overlapping scan/recovery path; `NZBFAST_PAR2GEN_FUSE=1` lowers only these
/// measured floors, and `=0` refuses the route outright.
pub(super) const FUSED_SOURCE_MIN_BYTES: u64 = 1 << 30;
pub(super) const FUSED_SOURCE_MIN_BLOCK_BYTES: u64 = 1 << 20;

pub(super) fn source_fusion_shape_admitted(
    member_count: usize,
    n_recovery: usize,
    per_batch: usize,
    block_size: u64,
) -> bool {
    // Windows: two or more members with a slice size the eight-lane
    // chains take (a multiple of 64) - the fused pass then hashes eight
    // members' whole-file chains per step beside the fold and reads the
    // payload once (the fused-multi and lane-chains handoffs, 5 Sep
    // 2026). A single member's chain is serial and in situ ran at
    // ~0.56 GB/s beside the fold: fused 2.04-2.10 s against the
    // overlapped scan's 1.61-1.63 on the i5-10600KF for one 1 GiB member,
    // so that shape kept the two-pass scan UNTIL 13 Sep 2026. "Beside
    // the fold" was the cause, not the chain: twelve fold workers on six
    // cores shared the chain's core round-robin, which is the starvation
    // `fold_windows` now paces away (`paced_width`), and the chain's own
    // kernel moved to AWS-LC the same day. Re-measured on that day, 8.86 GB
    // one member at 5%, fused against the two-pass scan on Windows:
    // Core Ultra 9 386H 11.34 -> 9.02 s (-20.5%, three of three pairs), i5-10600KF 12.14 -> 10.07 s (-17%, three of three) (research/
    // PARFAST-SINGLE-FILE-MD5-HEADROOM-2026-09-13.md). The single-member
    // shape is admitted on Windows from that measurement. The
    // multiple-of-64 slice rule is the LANE chains' (eight members' chains
    // advanced in lockstep need every block to end on an MD5 block
    // boundary) and a single member has one scalar chain and no lanes, so
    // it is exempt - and it has to be: parfast's default slice for this
    // 8.86 GB file is 4,429,188 bytes, four past a multiple of 64, which
    // is what kept the first cut of this change on the two-pass scan
    // (`fused=false` in its route marker) while the research override
    // that bypassed the gate measured the gain. Unix keeps its
    // single-member gate (measured on an M1 by lane B for large members;
    // at 1 GiB the M3 reads 1.59-1.82 fused against 1.39-1.51, which is a
    // threshold that lane did not set and this one leaves alone).
    let windows_ok = cfg!(windows)
        && (member_count == 1 || (member_count >= 2 && block_size.is_multiple_of(64)));
    let unix_ok = cfg!(unix) && member_count == 1;
    (windows_ok || unix_ok) && n_recovery > 0 && n_recovery <= per_batch
}

/// A fine-sliced, low-redundancy set can have 8,192 or more inputs while
/// sitting far below the NTT's 320-row crossover, so an input count alone is
/// the wrong gate: 8 GiB at 1 MiB slices and 1% recovery is 8,193 inputs and
/// only 82 rows, and its only arithmetic route is the fold either way.
pub(super) fn source_fusion_rows_admitted(
    block_size: usize,
    n_slices: usize,
    n_recovery: usize,
) -> bool {
    !ntt_range::rows_and_present_admitted(block_size, n_slices, n_recovery)
}

pub(super) fn scan_pool_budget(process_budget: u64) -> u64 {
    (process_budget / 4).clamp(SCAN_POOL_MIN_BYTES, SCAN_POOL_MAX_BYTES)
}

/// Payload-buffer bytes claimed by every `create_into` call LIVE in this
/// process right now.
///
/// Every create budget above is a share of the process budget computed
/// independently by each invocation, so before this gauge existed two
/// simultaneous creates each took a full share and the process held twice
/// the intended footprint - measured 3 Sep 2026 on an M3 Ultra, exactly
/// linear in the lane count: peak RSS 619 MB / 1,119 MB / 2,233 MB at one,
/// two and four concurrent `create_into` calls over the same 2 GiB set, and
/// 2.247 GB / 4.273 GB under a published 512 MiB budget. The same shape as
/// [`crate::mem::LZMA_DICT_OUTSTANDING`], and for the same reason: a
/// per-call ceiling is not a process ceiling.
pub(super) static CREATE_ADMITTED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Test-only exclusivity between the admission gauge's own tests and every
/// other create running in the same process. Nothing here reaches a shipped
/// build.
///
/// [`CREATE_ADMITTED`] is process-global by design, and `cargo test` puts a
/// crate's whole lib in ONE process with its tests on parallel threads - so
/// "the FIRST create in an idle process", which is exactly what the two
/// admission tests assert on, is not a fact a test may simply assume. It was
/// not one: on 3 Sep 2026 the one-process line
/// (`cargo test -p nzbkit-base --lib --features test-support`, and CI's
/// `unit-one-process` job) failed deterministically because
/// `a_block_size_past_the_parsers_own_ceiling_is_refused_at_create_time` - a
/// `create_into` at `MAX_BLOCK_SIZE`, slow enough to still be running, and
/// adjacent in the alphabetical order the runner starts tests in - held one
/// whole share while the concurrent-admission test read the gauge. Its
/// "solo" create therefore divided a ceiling that was already spoken for:
/// 4,093,640,704 accumulator bytes against the 8,589,934,592 the formula
/// gives at an idle 16 GiB ceiling, the arithmetic of exactly one
/// outstanding share. Nextest cannot see this class at all - it gives every
/// test its own process - so every CI shard was green throughout.
///
/// Every acquire takes the READ side, so creates still run together exactly
/// as they do in production and no shipped path is serialised; the admission
/// tests take the WRITE side and so measure a gauge that really is idle.
#[cfg(test)]
pub(super) static ADMISSION_QUIESCE: std::sync::RwLock<()> = std::sync::RwLock::new(());

#[cfg(test)]
thread_local! {
    /// Set on the one thread holding [`ADMISSION_QUIESCE`] exclusively.
    ///
    /// The exclusive holder is itself a test that RUNS creates - measuring
    /// what a first and a second create are handed is the whole point of it
    /// - and a `std::sync::RwLock` is not reentrant, so without this the
    /// guard would deadlock against its owner's very next `acquire`. Its own
    /// creates pass straight through; every other thread still waits.
    static ADMISSION_OWNED_HERE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// [`CREATE_ADMITTED`] to the calling test alone, for as long as this is
/// held. It subsumes plain mutual exclusion between the admission tests, so
/// it is the only lock they need.
#[cfg(test)]
pub(crate) fn admission_quiesced_for_tests() -> AdmissionQuiesced {
    let held = ADMISSION_QUIESCE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    ADMISSION_OWNED_HERE.with(|owned| owned.set(true));
    AdmissionQuiesced(held)
}

/// The guard [`admission_quiesced_for_tests`] returns.
#[cfg(test)]
pub(crate) struct AdmissionQuiesced(#[allow(dead_code)] std::sync::RwLockWriteGuard<'static, ()>);

#[cfg(test)]
impl Drop for AdmissionQuiesced {
    fn drop(&mut self) {
        ADMISSION_OWNED_HERE.with(|owned| owned.set(false));
    }
}

/// One live create's share of the process's create budget, released when the
/// call returns - by ANY path, which is why this is a guard and not a pair of
/// statements around the body.
///
/// The FIRST create in an idle process finds nothing outstanding, so it
/// derives exactly the figures the per-invocation formulas gave before this
/// existed: no shipping single-create path changes by a byte. A create that
/// starts while another is running divides what is LEFT, and the floors in
/// both formulas ([`SCAN_POOL_MIN_BYTES`], [`ACCUM_MIN_BYTES`]) mean it
/// always gets a workable plan rather than blocking - so a late create pays
/// extra passes over its own payload instead of the process paying another
/// whole footprint, and nothing can deadlock waiting for a share.
pub(super) struct CreateAdmission {
    pub(super) scan_pool: u64,
    pub(super) accum: u64,
    pub(super) claimed: u64,
    /// Held for this create's whole life so a test asserting on an idle
    /// gauge can wait it out - `None` only on the exclusive holder's own
    /// thread, which already has it. See [`ADMISSION_QUIESCE`].
    #[cfg(test)]
    pub(super) _quiesce: Option<std::sync::RwLockReadGuard<'static, ()>>,
}

/// The share one create takes when `avail` bytes of the process budget are
/// still unclaimed: `(scan_pool, accum, claimed)`.
///
/// Factored out of [`CreateAdmission::acquire`] so the two-lane bound can be
/// checked at ceilings this box does not have - which is the whole reason the
/// bound went wrong unseen. Every term's FLOOR is part of it, and
/// [`read_arena_claim`] DOUBLES the read window while overlap is on: a test
/// that re-derived the floor plan by adding the three constants instead read
/// it 64 MiB short and took nightly's armv7-cross red on 6 Sep 2026, on a
/// machine whose budget happened to sit in the band where the floors bind.
/// Derive a floor plan as `admission_plan(0)`, never as a sum of constants.
pub(super) fn admission_plan(avail: u64) -> (u64, u64, u64) {
    let scan_pool = scan_pool_budget(avail);
    let accum = accum_budget_from(avail);
    let claimed = scan_pool
        .saturating_add(accum)
        .saturating_add(read_arena_claim(accum));
    (scan_pool, accum, claimed)
}

impl CreateAdmission {
    pub(super) fn acquire() -> Self {
        // Taken before the ceiling is read, so a test holding the write side
        // sees this create wholly outside its window or wholly inside it,
        // never half-charged against the gauge it is measuring.
        #[cfg(test)]
        let _quiesce = (!ADMISSION_OWNED_HERE.with(|owned| owned.get())).then(|| {
            ADMISSION_QUIESCE
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        });
        let ceiling = crate::mem::process_budget().total;
        let mut plan = (0u64, 0u64, 0u64);
        // A CAS loop rather than a load-then-add: two creates entering
        // together must not both read the pre-claim total and both take a
        // full share, which is precisely the overshoot this exists to bound.
        let _ = CREATE_ADMITTED.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |outstanding| {
                plan = admission_plan(ceiling.saturating_sub(outstanding));
                Some(outstanding.saturating_add(plan.2))
            },
        );
        Self {
            scan_pool: plan.0,
            accum: plan.1,
            claimed: plan.2,
            #[cfg(test)]
            _quiesce,
        }
    }
}

impl Drop for CreateAdmission {
    fn drop(&mut self) {
        CREATE_ADMITTED.fetch_sub(self.claimed, std::sync::atomic::Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScanPlan {
    /// The whole-file MD5 chain streams on the caller's thread inside a
    /// 1 MiB reader while `workers` independent positional readers hash
    /// contiguous block ranges. The payload is read twice, and that is
    /// DELIBERATE: a one-read pipeline that hands the MD5 lane's own buffers
    /// to the block hashers was measured on a quiet 20-core M1 at 16 GiB /
    /// 8 MiB slices and cost 5.0% of wall (31.97 -> 33.56 s median of three,
    /// byte-identical output) while retired instructions FELL 0.14% - the
    /// MD5 lane's working set goes from a 1 MiB buffer to a whole block, and
    /// every hash worker then waits on that one lane through a shared receive
    /// lock. See the drop record in
    /// research/PAR2-TWO-LANES-COMPARED-2026-09-03.md.
    Positional { workers: usize },
    /// One sequential reader and one sequential block hasher exchange small
    /// PIECES. This is the same two CPU lanes as a one-worker `Positional`
    /// plan, without retaining a whole 32-256 MiB slice or reading the file
    /// twice - so at a huge block it is strictly better on both counts and
    /// there is no fan-out to throttle.
    Streamed { piece_bytes: usize },
    /// Tiny files and explicitly single-threaded tests hash both products on
    /// one lane, with scratch capped independently of the PAR2 slice size.
    Serial { scratch_bytes: usize },
}

impl ScanPlan {
    pub(super) fn buffer_bytes(self) -> u64 {
        match self {
            // Sized by `scan_plan_bytes`, which knows the slice size.
            ScanPlan::Positional { .. } => 0,
            ScanPlan::Streamed { piece_bytes } => piece_bytes.saturating_mul(2) as u64,
            // `BufReader` retains its default 8 KiB beside the scratch.
            ScanPlan::Serial { scratch_bytes } => scratch_bytes.saturating_add(8 << 10) as u64,
        }
    }
}

pub(super) fn scan_plan(length: u64, block_size: u64, threads: usize) -> ScanPlan {
    let n_blocks = length.div_ceil(block_size) as usize;
    if length >= SCAN_PAR_MIN_BYTES && n_blocks >= 2 && threads > 0 {
        let workers = threads
            .min(n_blocks)
            .min((SCAN_FILE_POOL_BYTES / block_size.max(1)).max(1) as usize)
            .max(1);
        // At one hash worker, retaining a whole multi-MiB block buys no block
        // parallelism and costs a second full read. Stream pieces to that same
        // worker instead: one lane either way, a fixed small pool, one read.
        // Research knob (`NZBFAST_PAR2GEN_SCAN=streamed`): one read pass
        // for every parallel-eligible member, the whole-file chain and
        // the block digests off the same pieces. The positional plan
        // reads the payload twice, and on a box whose page-cache copy is
        // kernel-serialised (Windows, 5 Sep 2026 measurements) each read
        // pass is ~2 CPU-seconds per GiB.
        let scan_knob = std::env::var("NZBFAST_PAR2GEN_SCAN").ok();
        let force_streamed = scan_knob.as_deref() == Some("streamed");
        let force_positional = scan_knob.as_deref() == Some("positional");
        // A single-worker member reads ONCE on Windows whatever the slice
        // size: measured 5 Sep 2026 on the i5-10600KF (multi-buffer MD5
        // handoff, round I), 1 GiB / 21 members / 1 MiB, the positional
        // plan's second read pass is ~0.5 s of kernel time per create
        // (3.0-3.3 s against 2.4-3.0 streamed) and the wall follows,
        // 1.49-1.59 -> 1.41-1.49. Elsewhere the page-cache copy is cheap
        // and the positional plan's per-file fan-out keeps its slice-size
        // gate.
        let single_reads_once = workers == 1
            && (block_size >= SCAN_STREAM_MIN_BLOCK_BYTES || (cfg!(windows) && !force_positional));
        if single_reads_once || force_streamed {
            return ScanPlan::Streamed {
                piece_bytes: SCAN_STREAM_PIECE_BYTES.min(block_size) as usize,
            };
        }
        return ScanPlan::Positional { workers };
    }
    ScanPlan::Serial {
        scratch_bytes: SCAN_HASH_CHUNK_BYTES.min(block_size) as usize,
    }
}

/// Payload buffers one member's scan holds at once, for the aggregate bound.
/// `Positional` is sized here rather than in [`ScanPlan::buffer_bytes`]
/// because its cost depends on the slice size the plan does not carry.
pub(super) fn scan_plan_bytes(plan: ScanPlan, block_size: u64) -> u64 {
    match plan {
        ScanPlan::Positional { workers } => (workers as u64)
            .saturating_mul(block_size.saturating_mul(scan_lane_blocks(block_size) as u64))
            .saturating_add(1 << 20),
        other => other.buffer_bytes(),
    }
}

/// Choose the widest file-level fan-out whose worst possible simultaneous
/// payload-buffer set fits one aggregate budget. The plan is recomputed at
/// each candidate width because the remaining CPU lanes per file affect its
/// owned chunk pool. Descending search keeps every normal lane: on a 32-core
/// host, ordinary slices cost 32 x 2 MiB and retain all 32 outer workers.
pub(super) fn scan_pool_geometry(
    sizes: &[u64],
    block_size: u64,
    machine: usize,
    budget: u64,
) -> (usize, usize) {
    let natural = machine.max(1).min(sizes.len()).max(1);
    for outer in (1..=natural).rev() {
        let inner = (machine / outer).max(1);
        let mut needs: Vec<u64> = sizes
            .iter()
            .map(|&length| scan_plan_bytes(scan_plan(length, block_size, inner), block_size))
            .collect();
        needs.sort_unstable_by(|a, b| b.cmp(a));
        let worst = needs
            .iter()
            .take(outer)
            .fold(0u64, |sum, &n| sum.saturating_add(n));
        if worst <= budget || outer == 1 {
            return (outer, inner);
        }
    }
    unreachable!("one scan worker is always admitted")
}

/// The block-digest lanes' a-priori width rule, ON by default since
/// 16 Sep 2026; `NZBFAST_CREATE_SCAN_LANE_PACING=0` is the A/B arm, and
/// `NZBFAST_CREATE_SCAN_LANES=<n>` pins the width for a research sweep
/// (it is how the shape of the rule below was chosen, and it overrides
/// the rule rather than the geometry's own ceiling).
///
/// Separate from the fold's two knobs for the same reason they are
/// separate from each other: the three were measured apart and reach
/// their widths by different means.
fn create_scan_lane_pacing_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NZBFAST_CREATE_SCAN_LANE_PACING").is_none_or(|v| v != "0"))
}

/// A research pin for the block-digest lane width, or `None`.
fn forced_scan_lane_width() -> Option<usize> {
    static N: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("NZBFAST_CREATE_SCAN_LANES")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
    })
}

/// Payload passes ONE block-digest lane completes while the whole-file
/// MD5 chain makes ONE pass over the same bytes, in PER MILLE - the one
/// machine input the lane width needs, and `None` on a box where the
/// quantity that could move it is not known to be present.
///
/// # Why this is a bound and not a measurement
///
/// A member's block digests and its whole-file chain are the SAME MD5
/// over the SAME bytes (`scan_mapped` and `scan_parallel_positional`
/// both run the chain on the file-level worker while the lanes hash that
/// worker's own member), so the payload and the member length both
/// cancel out of the ratio exactly as the payload cancels out of
/// [`super::fold_rows_per_worker_per_chain_pass`]. What is left is one
/// lane's cost against one chain's, and a lane does the chain's MD5 plus
/// a CRC32 over the same bytes - so the ratio is at MOST 1000 on any
/// box, structurally, and the only way it falls much below is a CRC32
/// running out of a table rather than off the hardware instruction.
/// That is what this is keyed on, and it is a far wider gate than the
/// fold rule's, deliberately: the fold's constant compares two DIFFERENT
/// kernels whose rates diverge by several times, this one compares MD5
/// with itself.
///
/// 950 is that bound with a CRC32 charged the ~5% it costs beside MD5,
/// and the width it produces is insensitive to it: every value from 625
/// to 1000 gives the same [`scan_lane_keep_up_width`] of 2.
///
/// # What is deliberately NOT priced in
///
/// A lane hashes up to [`scan_lane_blocks`] blocks per `md5_many` pass,
/// and at eight of them the vector kernel is several times the scalar
/// chain - so a finely sliced set's lane is worth several lanes of this.
/// Taking that would ask for ONE lane, and the speedup is both
/// architecture- and lane-count-dependent (four NEON lanes measure 1.58x
/// the scalar chain, eight AVX2 lanes far more), which is the kind of
/// constant the fold pacers got wrong in the dangerous direction. Every
/// lane is therefore priced at the SCALAR rate: a set whose digests
/// vectorise simply finishes them early, and under-narrowing costs the
/// gain and never the wall. The block size is why this rule has no block
/// size term.
fn block_digest_lane_per_mille_of_chain() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    if is_x86_feature_detected!("sse4.2") && is_x86_feature_detected!("pclmulqdq") {
        return Some(950);
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("crc") {
        return Some(950);
    }
    None
}

/// The fewest block-digest lanes whose work still lands INSIDE the
/// chain's wall, at the same 80% target `super::paced_width` aims at:
/// `lanes >= (1 / 0.8) / (per-mille / 1000)`, which is `1250 / per_mille`.
fn scan_lane_keep_up_width(per_mille: u64) -> usize {
    (1250u64.div_ceil(per_mille.max(1))).max(1) as usize
}

/// The block-digest lane width a create decides BEFORE [`scan_all`]
/// spawns anything, from the fold width decided in the same breath.
///
/// `None` means "do not narrow" - an unmeasured box, or the knob off.
/// See [`apriori_scan_lane_width_for`] for the rule and
/// [`block_digest_lane_per_mille_of_chain`] for the one constant in it.
pub(super) fn apriori_scan_lane_width(
    fold_width: usize,
    scan_outer: usize,
    max: usize,
) -> Option<usize> {
    if let Some(pinned) = forced_scan_lane_width() {
        return Some(pinned);
    }
    if !create_scan_lane_pacing_enabled() {
        return None;
    }
    let keep_up = scan_lane_keep_up_width(block_digest_lane_per_mille_of_chain()?);
    Some(apriori_scan_lane_width_for(
        fold_width, scan_outer, keep_up, max,
    ))
}

/// [`apriori_scan_lane_width`]'s arithmetic with the machine constant
/// already reduced to `keep_up` - split out so the RULE can be pinned by
/// a test on every box in the fleet, exactly as
/// [`super::apriori_fold_width_for`] is.
///
/// # The rule, and why it is ONE decision with the fold's and not two
///
/// The block digests are a fixed amount of MD5 work over the payload
/// that must finish before the set can be written, and the chain is one
/// sequential MD5 pass over the same bytes. Lanes handed back to the
/// chain pay for themselves exactly while the digests still land inside
/// the chain's wall - which is `keep_up` lanes, a number with no box in
/// it. But a lane narrowed BELOW what the box would otherwise have spent
/// idle buys nothing at all, so the rule sheds only what the box is
/// actually short of: `scan_all` runs `outer` chains and `outer * inner`
/// digest lanes beside the fold's workers, so what is left for the lanes
/// is `max - fold - outer`, and that is the width - never fewer than
/// `keep_up`, never more than the box.
///
/// **This is the whole coupling between the two a-priori widths, and it
/// is why they are decided together.** Two rules that each believed they
/// were the only narrowing could shed together until neither's work fits
/// its own target - which is how the two feedback pacers failed without
/// either of them containing a feedback term over the other. Here the
/// fold width is an INPUT: the lane width is what the box has left after
/// the fold has been paid, so the two can only ever sum to the box, and
/// on a box with cores to spare the lane rule declines to narrow at all
/// (a 32-core host running one member keeps every lane the geometry
/// gave it).
///
/// The floor is `keep_up` and not `super::PACED_WIDTH_FLOOR`: the
/// dangerous direction here is making the DIGESTS the pole, and the
/// number that bounds that is the one derived from the chain, not the
/// fold's floor. It is the binding term on a small box - four cores with
/// a four-wide fold have nothing left, and the lanes still get two.
pub(super) fn apriori_scan_lane_width_for(
    fold_width: usize,
    scan_outer: usize,
    keep_up: usize,
    max: usize,
) -> usize {
    let outer = scan_outer.max(1);
    let max = max.max(1);
    let keep_up = keep_up.clamp(1, max);
    let spare = max.saturating_sub(fold_width).saturating_sub(outer);
    (spare / outer).clamp(keep_up, max)
}

/// Per-block (MD5, CRC32) for `[first, last)` blocks of `f`, each block
/// zero-padded to `block_size` exactly as the serial scan pads it.
#[allow(clippy::too_many_arguments)]
pub(super) fn hash_block_range(
    f: &std::fs::File,
    path: &Path,
    length: u64,
    block_size: u64,
    first: usize,
    last: usize,
    out: &mut [([u8; 16], u32)],
    control: &CreateControl,
) -> Result<(), Par2GenError> {
    // Up to eight blocks per pass: the block digests are independent
    // chains, and `md5_many` runs eight of them in the lanes of one AVX2
    // register (see `md5fast::multi`). The lane count is bounded by the
    // per-worker scratch `scan_lane_blocks` sizes, so a huge slice still
    // hashes one at a time in one slice's worth of buffer.
    let bs = block_size as usize;
    let lanes = scan_lane_blocks(block_size);
    let mut buf = vec![0u8; bs * lanes];
    let mut bi = first;
    while bi < last {
        // THE GRAIN of the hash phase: one relaxed load per pass of up
        // to eight blocks. A park site too - this worker owns a static
        // disjoint range of ONE file's blocks, holds no lock and holds
        // nothing another thread could take, which is exactly the rule
        // `control::PauseGate` states (and the same shape as the
        // repair's feed readers).
        control.gate()?;
        let n = lanes.min(last - bi);
        let mut fed = 0u64;
        for k in 0..n {
            let off = (bi + k) as u64 * block_size;
            let want = (length - off).min(block_size) as usize;
            fed += want as u64;
            let slot = &mut buf[k * bs..(k + 1) * bs];
            crate::disk::read_exact_at(f, &mut slot[..want], off).map_err(io(path))?;
            slot[want..].fill(0);
        }
        let blocks: Vec<&[u8]> = (0..n).map(|k| &buf[k * bs..(k + 1) * bs]).collect();
        let digests = crate::md5fast::multi::md5_many(&blocks);
        for k in 0..n {
            out[bi - first + k] = (digests[k], crc32fast::hash(blocks[k]));
        }
        bi += n;
        // DATA bytes, not padded ones: the phase's total is the sum of
        // the members' declared lengths, and every byte of it is
        // counted exactly once by whichever lane read it.
        control.step(CreatePhase::Verify, fed);
    }
    Ok(())
}

/// Blocks one positional hash worker holds at once: up to eight (the
/// vector MD5's lane count) while they fit 4 MiB, fewer for larger
/// slices, one from 4 MiB up - so the worker's scratch never exceeds
/// `max(4 MiB, block_size)`.
pub(super) fn scan_lane_blocks(block_size: u64) -> usize {
    // 4 MiB, not the lane count's 8: at 8 MiB per worker the fresh
    // buffers' page faults cost more kernel time than the digests saved
    // (round I of the multi-buffer handoff: +0.5 s kernel per create).
    const LANE_POOL_BYTES: u64 = 4 << 20;
    ((LANE_POOL_BYTES / block_size.max(1)).clamp(1, 8)) as usize
}

/// Whole-file MD5 and the 16 KiB head stream on the calling thread (MD5 is
/// one sequential chain; nothing splits it) while the per-block MD5+CRC -
/// independent streams - run across `workers` positional readers over
/// contiguous block ranges.
///
/// The BLOCK WORKERS share the caller's handle on every platform, and
/// that is correct on every platform: they read only through
/// `disk::read_exact_at`, which is `pread` on unix and `seek_read` on
/// Windows, and both take the offset per call. `seek_read` also leaves
/// the shared file POINTER somewhere arbitrary, which matters to a
/// reader that goes through the cursor and to nothing else.
///
/// The SEQUENTIAL lane below is that reader, and it is the one that
/// reopens on Windows - see the comment at its `reopen_read_handle`.
/// This doc used to say "other platforms open independent handles",
/// which reads as a claim about the workers, is false of them, and sent
/// a 4 Sep 2026 review hunting a race that 674a5d80f had already fixed
/// in the lane that really had it. An 8-worker test over a shared
/// handle (`par2gen_tests`, agrees-with-one-reader) covers this and has
/// passed on a real Win11 box.
#[allow(clippy::too_many_arguments)]
pub(super) fn scan_parallel_positional(
    f: &std::fs::File,
    path: &Path,
    length: u64,
    block_size: u64,
    n_blocks: usize,
    workers: usize,
    control: &CreateControl,
    digest: &crate::digest_cache::MemberDigest,
) -> Result<(Option<[u8; 16]>, [u8; 16], Vec<([u8; 16], u32)>), Par2GenError> {
    let mut blocks = vec![([0u8; 16], 0); n_blocks];
    let per = n_blocks.div_ceil(workers);
    let whole = std::thread::scope(|s| -> Result<(Option<[u8; 16]>, [u8; 16]), Par2GenError> {
        let handles: Vec<_> = blocks
            .chunks_mut(per)
            .enumerate()
            .map(|(wi, chunk)| {
                s.spawn(move || -> Result<(), Par2GenError> {
                    let first = wi * per;
                    hash_block_range(
                        f,
                        path,
                        length,
                        block_size,
                        first,
                        first + chunk.len(),
                        chunk,
                        control,
                    )
                })
            })
            .collect();

        // THE BLOCK LANES SHARE `f` AND `read_exact_at` MOVES ITS CURSOR ON
        // WINDOWS (see `disk::read_exact_at`), so this sequential lane - the
        // only one here that reads THROUGH the cursor - cannot use the same
        // handle there: it would digest whatever bytes a positional worker
        // last left the pointer on, and write that as the member's FileDesc
        // MD5. Unix `pread` leaves the cursor alone, so it keeps the original
        // descriptor and both digest products stay on ONE inode even if the
        // member is replaced mid-create. `ReOpenFile` resolves from the live
        // handle rather than from a pathname, so the Windows arm keeps that
        // property too. (Fix and the real-Win11 verdict: 674a5d80f.)
        #[cfg(windows)]
        let owned = crate::disk::reopen_read_handle(f).map_err(io(path))?;
        #[cfg(windows)]
        let source = &owned;
        #[cfg(not(windows))]
        let source = f;
        let mut reader = std::io::BufReader::with_capacity(1 << 20, source);
        let mut whole = Md5::new();
        let mut head = Md5::new();
        let mut head_left = 16384usize;
        let mut buf = vec![0u8; 1 << 20];
        let mut left = length;
        let mut skipped = false;
        while left > 0 {
            // Cancel only, and NO `CreatePhase::Verify` step: the block
            // lanes above already count every byte of this member once,
            // and the whole-file chain is a second pass over the same
            // bytes. The CHAIN counter below is a different question
            // (how far along is THIS lane) and is stepped per MiB, as
            // `scan_mapped` explains. Per MiB, on the one lane that is
            // this member's serial cost - without it a cancelled create
            // would still hash the whole file out.
            control.check()?;
            // A digest record validated (`crate::digest_cache`): the chain's
            // answer is known, and once the head is done this lane reads for
            // nothing else.
            if head_left == 0 && digest.chain_abandoned() {
                skipped = true;
                break;
            }
            let want = left.min(buf.len() as u64) as usize;
            read_exact_or_short(&mut reader, &mut buf[..want], path)?;
            whole.update(&buf[..want]);
            control.chain_step(want as u64);
            if head_left > 0 {
                let n = head_left.min(want);
                head.update(&buf[..n]);
                head_left -= n;
            }
            left -= want as u64;
        }
        // The member's remaining chain work, credited as this lane
        // leaves - see `scan_mapped`'s own tail credit.
        control.chain_step(left);
        for h in handles {
            h.join().expect("par2gen block hasher panicked")?;
        }
        Ok((
            (!skipped).then(|| whole.finalize().into()),
            head.finalize().into(),
        ))
    })?;
    Ok((whole.0, whole.1, blocks))
}

pub(super) struct ScanPiece {
    pub(super) block_index: usize,
    pub(super) used: usize,
    pub(super) end_block: bool,
    pub(super) padding: usize,
    pub(super) bytes: Vec<u8>,
    pub(super) hash: Option<([u8; 16], u32)>,
}

pub(super) fn recycle_scan_piece(
    done: &std::sync::mpsc::Receiver<ScanPiece>,
    blocks: &mut [([u8; 16], u32)],
    finished: &mut usize,
    free: &mut Vec<ScanPiece>,
) -> Result<(), Par2GenError> {
    let mut piece = done.recv().map_err(|_| {
        Par2GenError::Other("PAR2 streaming block hasher stopped before the scan completed".into())
    })?;
    if let Some(hash) = piece.hash.take() {
        let Some(slot) = blocks.get_mut(piece.block_index) else {
            return Err(Par2GenError::Other(
                "PAR2 streaming block hasher returned an invalid block index".into(),
            ));
        };
        *slot = hash;
        *finished += 1;
    }
    free.push(piece);
    Ok(())
}

/// Feed `zeros` zero bytes through `md5` using `scratch` as the source, so a
/// tail block's spec-mandated zero padding costs no allocation of its own.
pub(super) fn update_md5_zeros(md5: &mut Md5, mut zeros: usize, scratch: &mut [u8]) {
    if zeros == 0 {
        return;
    }
    scratch.fill(0);
    while zeros > 0 {
        let take = zeros.min(scratch.len());
        md5.update(&scratch[..take]);
        zeros -= take;
    }
}

/// Hash a mapped partial block without allocating or copying a whole block.
/// MD5 consumes its exact zero padding; CRC extends the real-byte checksum
/// algebraically, as the streamed and serial scanners already do.
pub(super) fn mapped_tail_checksums(tail: &[u8], block_size: usize) -> ([u8; 16], u32) {
    assert!(tail.len() <= block_size);
    let padding = block_size - tail.len();
    let mut md5 = Md5::new();
    md5.update(tail);
    if padding != 0 {
        let mut zeros = [0u8; 32 << 10];
        update_md5_zeros(&mut md5, padding, &mut zeros);
    }
    (
        md5.finalize().into(),
        crate::yenc_simd::crc32_zeros(crc32fast::hash(tail), padding as u64),
    )
}

/// Both scan products off one mapping: the whole-file and head chains
/// on the caller, the per-block MD5+CRC on `workers` lanes, eight blocks
/// per `md5_many` pass, every byte read from the page cache in place.
/// The tail is hashed directly too, with a bounded scratch buffer for its
/// spec-mandated zero padding.
pub(super) fn scan_mapped(
    map: &MappedMember,
    bs: usize,
    n_blocks: usize,
    workers: usize,
    control: &CreateControl,
    digest: &crate::digest_cache::MemberDigest,
) -> (Option<[u8; 16]>, [u8; 16], Vec<([u8; 16], u32)>) {
    map.prefetch();
    let data = map.bytes();
    let length = data.len();
    let mut blocks = vec![([0u8; 16], 0u32); n_blocks];
    let per = n_blocks.div_ceil(workers.max(1)).max(1);
    let lanes = scan_lane_blocks(bs as u64);
    let (whole, head) = std::thread::scope(|s| {
        for (wi, chunk) in blocks.chunks_mut(per).enumerate() {
            s.spawn(move || {
                let first = wi * per;
                let last = first + chunk.len();
                let mut bi = first;
                while bi < last {
                    // The grain, as in `hash_block_range`: one relaxed
                    // load per pass of up to `lanes` blocks. Cancel
                    // only here - this arm returns no Result, and a
                    // half-hashed member is thrown away by the caller's
                    // own unwind, which reads the cancel a line later.
                    if control.cancelled() {
                        return;
                    }
                    // Full blocks straight off the mapping, up to `lanes` per
                    // pass; the tail block (short) hashed alone, padded.
                    let full_end = (bi + lanes).min(last).min(length / bs);
                    if full_end > bi {
                        let slices: Vec<&[u8]> = (bi..full_end)
                            .map(|b| &data[b * bs..(b + 1) * bs])
                            .collect();
                        let digests = crate::md5fast::multi::md5_many(&slices);
                        for (k, d) in digests.into_iter().enumerate() {
                            chunk[bi - first + k] = (d, crc32fast::hash(slices[k]));
                        }
                        control.step(CreatePhase::Verify, (full_end - bi) as u64 * bs as u64);
                        bi = full_end;
                        continue;
                    }
                    let off = bi * bs;
                    chunk[bi - first] = mapped_tail_checksums(&data[off..], bs);
                    control.step(CreatePhase::Verify, (length - off) as u64);
                    bi += 1;
                }
            });
        }
        let mut whole = Md5::new();
        let mut head = Md5::new();
        let mut skipped = false;
        // No `CreatePhase::Verify` step - the block lanes above count
        // these bytes once (see `scan_parallel_positional`'s sequential
        // lane) - but the CHAIN counter is this lane's own, and stepping
        // it here is the whole point of it: the block lanes run
        // `workers`-way parallel and finish long before this sequential
        // pass, so a pacer that read their progress as the chain's would
        // see a chain that had already finished. It did, and was a
        // measured no-op for it (`CreateControl::chain_step`).
        let mut chained = 0u64;
        for chunk in data.chunks(1 << 20) {
            if control.cancelled() {
                break;
            }
            // A validated digest record answers for the chain.
            if digest.chain_abandoned() {
                skipped = true;
                break;
            }
            whole.update(chunk);
            chained += chunk.len() as u64;
            control.chain_step(chunk.len() as u64);
        }
        // Whatever this member's chain did NOT hash - abandoned to a
        // digest record, or cut short by a cancel - is work that will
        // never happen, so it is credited as the lane leaves. Without
        // this the counter would stall below its whole on the digest-hit
        // path and a pacer would hold a narrowed fold open for a chain
        // that is not running.
        control.chain_step(length as u64 - chained);
        head.update(&data[..length.min(16384)]);
        (
            (!skipped).then(|| whole.finalize().into()),
            head.finalize().into(),
        )
    });
    (whole, head, blocks)
}

/// One file read, with the whole-file MD5 on the reader lane and block
/// MD5/CRC on one worker lane. PIECES, rather than whole PAR2 blocks, cross
/// the bounded queue, so a 256 MiB slice has the same eight-MiB footprint as
/// an eight-MiB slice. This supersedes the huge-block fallback, which
/// allocated one full block per concurrent file and read every payload byte
/// twice.
#[allow(clippy::too_many_arguments)]
pub(super) fn scan_parallel_streamed(
    f: &mut std::fs::File,
    path: &Path,
    length: u64,
    block_size: usize,
    n_blocks: usize,
    piece_bytes: usize,
    control: &CreateControl,
    digest: &crate::digest_cache::MemberDigest,
) -> Result<(Option<[u8; 16]>, [u8; 16], Vec<([u8; 16], u32)>), Par2GenError> {
    let mut blocks = vec![([0u8; 16], 0); n_blocks];
    let mut free: Vec<ScanPiece> = (0..2)
        .map(|_| ScanPiece {
            block_index: 0,
            used: 0,
            end_block: false,
            padding: 0,
            bytes: vec![0u8; piece_bytes],
            hash: None,
        })
        .collect();
    let (jobs_tx, jobs_rx) = std::sync::mpsc::sync_channel::<ScanPiece>(1);
    let (done_tx, done_rx) = std::sync::mpsc::channel::<ScanPiece>();
    let mut reader_result: Option<Result<(Option<[u8; 16]>, [u8; 16]), Par2GenError>> = None;
    let mut finished = 0usize;

    std::thread::scope(|s| {
        let worker = s.spawn(move || {
            let mut block_md5 = Md5::new();
            let mut block_crc = crc32fast::Hasher::new();
            while let Ok(mut piece) = jobs_rx.recv() {
                block_md5.update(&piece.bytes[..piece.used]);
                block_crc.update(&piece.bytes[..piece.used]);
                if piece.end_block {
                    update_md5_zeros(&mut block_md5, piece.padding, &mut piece.bytes);
                    let md5 = std::mem::replace(&mut block_md5, Md5::new())
                        .finalize()
                        .into();
                    let crc = crate::yenc_simd::crc32_zeros(
                        std::mem::replace(&mut block_crc, crc32fast::Hasher::new()).finalize(),
                        piece.padding as u64,
                    );
                    piece.hash = Some((md5, crc));
                }
                if done_tx.send(piece).is_err() {
                    break;
                }
            }
        });

        reader_result = Some((|| {
            let mut whole = Md5::new();
            let mut skipped = false;
            let mut head = Md5::new();
            let mut head_left = 16384usize;
            let mut file_left = length;
            for bi in 0..n_blocks {
                // Per BLOCK on the reader lane, which is this arm's
                // only loop over the payload: a park site (the reader
                // holds a free piece it owns and nothing else) and the
                // cancel's grain.
                control.gate()?;
                let block_data = file_left.min(block_size as u64) as usize;
                let mut block_left = block_data;
                while block_left > 0 {
                    if free.is_empty() {
                        recycle_scan_piece(&done_rx, &mut blocks, &mut finished, &mut free)?;
                    }
                    let mut piece = free.pop().expect("the scan reader owns a free piece");
                    let take = block_left.min(piece_bytes);
                    read_exact_or_short(f, &mut piece.bytes[..take], path)?;
                    // This reader also feeds the block hasher, so it keeps
                    // reading; only the chain stops, once a digest record
                    // validated.
                    skipped = skipped || digest.chain_abandoned();
                    if !skipped {
                        whole.update(&piece.bytes[..take]);
                    }
                    if head_left > 0 {
                        let n = head_left.min(take);
                        head.update(&piece.bytes[..n]);
                        head_left -= n;
                    }
                    piece.block_index = bi;
                    piece.used = take;
                    piece.end_block = take == block_left;
                    piece.padding = if piece.end_block {
                        block_size - block_data
                    } else {
                        0
                    };
                    jobs_tx.send(piece).map_err(|_| {
                        Par2GenError::Other(
                            "PAR2 streaming block hasher stopped before accepting the scan".into(),
                        )
                    })?;
                    block_left -= take;
                }
                file_left -= block_data as u64;
                control.step(CreatePhase::Verify, block_data as u64);
                // This arm's reader IS its chain lane, so the two
                // counters move together here - unlike the mapped and
                // positional arms, where they are different lanes. Both
                // are stepped anyway: a create whose members take
                // DIFFERENT arms (a huge member mapped, a small one
                // streamed) needs one chain counter that covers all of
                // them, or the pacer's estimate is short by whatever the
                // other arms hashed.
                control.chain_step(block_data as u64);
            }
            while free.len() < 2 {
                recycle_scan_piece(&done_rx, &mut blocks, &mut finished, &mut free)?;
            }
            debug_assert_eq!(file_left, 0);
            if finished != n_blocks {
                return Err(Par2GenError::Other(format!(
                    "PAR2 streaming block hasher returned {finished} of {n_blocks} checksums"
                )));
            }
            Ok((
                (!skipped).then(|| whole.finalize().into()),
                head.finalize().into(),
            ))
        })());
        drop(jobs_tx);
        worker
            .join()
            .expect("par2gen streaming block hasher panicked");
    });

    let (whole, head) = reader_result.expect("the PAR2 streamed reader ran")?;
    Ok((whole, head, blocks))
}

pub(super) fn scan_at_length(
    m: &Member,
    expected_length: u64,
    block_size: u64,
    threads: usize,
    control: &CreateControl,
    digest_cache: Option<&std::sync::Arc<crate::digest_cache::DigestCache>>,
) -> Result<Scanned, Par2GenError> {
    let mut f = std::fs::File::open(&m.path).map_err(io(&m.path))?;
    let length = f.metadata().map_err(io(&m.path))?.len();
    if length != expected_length {
        return Err(Par2GenError::Other(format!(
            "{} changed length while the PAR2 set was being built",
            m.path.display()
        )));
    }
    let n_blocks = length.div_ceil(block_size) as usize;
    let block_size_usize = usize::try_from(block_size)
        .map_err(|_| Par2GenError::Other("PAR2 block size does not fit this platform".into()))?;
    // The digest cache's pass for this member, on the handle every arm
    // below reads (`crate::digest_cache::MemberDigest`).
    let digest = crate::digest_cache::MemberDigest::begin(
        digest_cache,
        &f,
        &m.path,
        length,
        crate::digest_cache::FLAG_CREATE,
    );
    // Both scan products off a mapping of the member - no read pass -
    // for every member the parallel plans would take (see
    // `MappedMember`); the tiny-file serial plan and any member that
    // cannot be mapped keep their reads.
    if map_scan_and_fold_enabled()
        && length >= SCAN_PAR_MIN_BYTES
        && n_blocks >= 2
        && threads > 0
        && let Ok(Some(map)) = MappedMember::open(&m.path, length)
    {
        {
            drop(f);
            let workers = match scan_plan(length, block_size, threads) {
                ScanPlan::Positional { workers } => workers,
                _ => threads.min(n_blocks).max(1),
            };
            let (md5_whole, md5_16k, blocks) =
                scan_mapped(&map, block_size_usize, n_blocks, workers, control, &digest);
            // The mapped arm's lanes return nothing, so the cancel is
            // read here rather than propagated out of them: the
            // half-hashed member is dropped with this error.
            control.check()?;
            return finish_digested(m, length, md5_whole, md5_16k, blocks, digest);
        }
    }
    match scan_plan(length, block_size, threads) {
        ScanPlan::Positional { workers } => {
            let (md5_whole, md5_16k, blocks) = scan_parallel_positional(
                &f, &m.path, length, block_size, n_blocks, workers, control, &digest,
            )?;
            finish_digested(m, length, md5_whole, md5_16k, blocks, digest)
        }
        ScanPlan::Streamed { piece_bytes } => {
            let (md5_whole, md5_16k, blocks) = scan_parallel_streamed(
                &mut f,
                &m.path,
                length,
                block_size_usize,
                n_blocks,
                piece_bytes,
                control,
                &digest,
            )?;
            finish_digested(m, length, md5_whole, md5_16k, blocks, digest)
        }
        ScanPlan::Serial { scratch_bytes } => {
            let mut r = std::io::BufReader::new(f);
            let mut whole = Md5::new();
            let mut skipped = false;
            let mut head = Md5::new();
            let mut head_left = 16384usize;
            let mut blocks = Vec::with_capacity(n_blocks);
            let mut buf = vec![0u8; scratch_bytes];
            let mut left = length;
            while left > 0 {
                // Per BLOCK on the one lane a small member gets: a park
                // site, and the cancel's grain on this arm.
                control.gate()?;
                let block_data = left.min(block_size) as usize;
                let mut block_left = block_data;
                let mut block_md5 = Md5::new();
                let mut block_crc = crc32fast::Hasher::new();
                while block_left > 0 {
                    let take = block_left.min(buf.len());
                    read_exact_or_short(&mut r, &mut buf[..take], &m.path)?;
                    skipped = skipped || digest.chain_abandoned();
                    if !skipped {
                        whole.update(&buf[..take]);
                    }
                    block_md5.update(&buf[..take]);
                    block_crc.update(&buf[..take]);
                    if head_left > 0 {
                        let n = head_left.min(take);
                        head.update(&buf[..n]);
                        head_left -= n;
                    }
                    block_left -= take;
                }
                // The spec hashes the block zero-padded to the full slice, so
                // the tail block's checksum covers `block_size` bytes and not
                // `block_data` of them.
                let padding = block_size_usize - block_data;
                update_md5_zeros(&mut block_md5, padding, &mut buf);
                blocks.push((
                    block_md5.finalize().into(),
                    crate::yenc_simd::crc32_zeros(block_crc.finalize(), padding as u64),
                ));
                left -= block_data as u64;
                control.step(CreatePhase::Verify, block_data as u64);
                // One lane does both products here, so this is the same
                // bytes twice into two counters that ask different
                // questions - see the streamed arm above.
                control.chain_step(block_data as u64);
            }
            let md5_whole: Option<[u8; 16]> = (!skipped).then(|| whole.finalize().into());
            // A file SHORTER than 16 KiB has md5_16k == the whole-file MD5,
            // because the "first 16k" is all of it. For a 0-byte file both are
            // the MD5 of the empty string, which is exactly what a real creator
            // stores and what `e2e_norar`'s empty-FileDesc patch writes.
            let md5_16k: [u8; 16] = head.finalize().into();
            finish_digested(m, length, md5_whole, md5_16k, blocks, digest)
        }
    }
}

#[cfg(test)]
pub(super) fn scan(m: &Member, block_size: u64, threads: usize) -> Result<Scanned, Par2GenError> {
    let length = std::fs::metadata(&m.path).map_err(io(&m.path))?.len();
    scan_at_length(
        m,
        length,
        block_size,
        threads,
        &CreateControl::default(),
        None,
    )
}

/// [`finish_scan`] for an arm whose whole-file chain ran beside a digest
/// pass: the pass turns what the chain produced (`None` where a validated
/// record stopped it) into the member's MD5 and the store change it owes.
pub(super) fn finish_digested(
    m: &Member,
    length: u64,
    md5_whole: Option<[u8; 16]>,
    md5_16k: [u8; 16],
    blocks: Vec<([u8; 16], u32)>,
    digest: crate::digest_cache::MemberDigest,
) -> Result<Scanned, Par2GenError> {
    let (md5_whole, pending) = digest.resolve(md5_whole).map_err(Par2GenError::Other)?;
    Ok(finish_scan(m, length, md5_whole, md5_16k, blocks, pending))
}

/// A lone member with a digest record waiting: the create takes the split
/// scan for it rather than the fused pass (see
/// `crate::digest_cache::has_record` for the measurement). Asked last in
/// the fusion decision, so no other shape ever opens the store here.
pub(super) fn a_digest_record_is_waiting(
    control: &CreateControl,
    members: &[Member],
    lengths: &[u64],
) -> bool {
    members.len() == 1
        && crate::digest_cache::has_record(control.digest_cache(), &members[0].path, lengths[0])
}

/// Commit every store change a create's members owe. Called only once the
/// set is completely written, so a failed or cancelled create changes no
/// record.
pub(super) fn commit_digests(scanned: &mut [Scanned]) {
    for s in scanned {
        if let Some(pending) = s.digest.take() {
            pending.commit();
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Unit tests reach the fused arm on sets far under its size floors
    /// through this, on their own thread, so no other test's create is
    /// forced onto it (the env knob would reach every create in the
    /// process).
    pub(super) static FUSE_FOR_TESTS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `NZBFAST_PAR2GEN_FUSE=1` for the calling thread's create, in a unit test.
pub(super) fn fusion_forced_for_tests() -> bool {
    #[cfg(test)]
    {
        FUSE_FOR_TESTS.with(|f| f.get())
    }
    #[cfg(not(test))]
    {
        false
    }
}

pub(super) fn scan_head_len(length: u64) -> usize {
    length.min(16_384) as usize
}

/// Read the identities needed to order recovery slices across the worker
/// pool. A directory with thousands of small members used to open and hash
/// every 16 KiB head serially before either the full scan or the recovery
/// work could start. The full scan already fans files out, and the head pass
/// has the same independent-per-file shape.
pub(super) fn scan_heads(
    members: &[Member],
    control: &CreateControl,
) -> Result<Vec<(usize, u64, [u8; 16], [u8; 16])>, Par2GenError> {
    map_members_parallel(members, |i, member| {
        // The prepass is 16 KiB per member and reports no progress -
        // there is no phase in it - but a 30,000-member directory is
        // still long enough to want stopping.
        control.check()?;
        let (length, md5_16k, file_id) = scan_head(member)?;
        Ok((i, length, md5_16k, file_id))
    })
}

/// Lengths are the only pre-scan data an index-only set needs. Recovery sets
/// get them as part of [`scan_heads`], but doing the head read at zero
/// redundancy only duplicated the first 16 KiB of every file without buying
/// any overlap or ordering information.
pub(super) fn scan_lengths(members: &[Member]) -> Result<Vec<u64>, Par2GenError> {
    map_members_parallel(members, |_, member| {
        std::fs::metadata(&member.path)
            .map(|v| v.len())
            .map_err(io(&member.path))
    })
}

/// Apply an independent metadata/identity probe to every member, preserving
/// caller order in the result. Both creation prepasses are tiny per file but
/// directory-wide, so one shared fan-out keeps their scheduling identical.
pub(super) fn map_members_parallel<T, F>(members: &[Member], f: F) -> Result<Vec<T>, Par2GenError>
where
    T: Send,
    F: Fn(usize, &Member) -> Result<T, Par2GenError> + Sync,
{
    // These are short positional reads and metadata probes, not the CPU-heavy
    // body hashes below. Thread setup is not repaid by ordinary 20-file sets;
    // at the other end, beyond eight readers the filesystem queue is the
    // bottleneck and extra threads only amplify seek/metadata contention.
    let workers = if members.len() < 64 {
        1
    } else {
        crate::mem::cpu_workers().min(8).min(members.len())
    };
    if workers == 1 {
        return members.iter().enumerate().map(|(i, m)| f(i, m)).collect();
    }
    let per = members.len().div_ceil(workers);
    let mut per_thread: Vec<Result<Vec<T>, Par2GenError>> = Vec::new();
    std::thread::scope(|s| {
        let handles: Vec<_> = members
            .chunks(per)
            .enumerate()
            .map(|(chunk_index, chunk)| {
                let f = &f;
                s.spawn(move || {
                    chunk
                        .iter()
                        .enumerate()
                        .map(|(offset, member)| f(chunk_index * per + offset, member))
                        .collect()
                })
            })
            .collect();
        per_thread = handles
            .into_iter()
            .map(|h| h.join().expect("par2gen member scanner panicked"))
            .collect();
    });
    let mut out = Vec::with_capacity(members.len());
    for result in per_thread {
        out.extend(result?);
    }
    Ok(out)
}

/// The recovery fold starts from the head scan's file-id order while the full
/// scan runs beside it. Compare identities by their ORIGINAL member index
/// rather than comparing only the final sorted Main packet: two same-length
/// members could otherwise exchange contents and leave the set of file ids
/// unchanged while the fold's coefficient order had changed.
pub(super) fn heads_match_scanned(
    heads: &[(usize, u64, [u8; 16], [u8; 16])],
    scanned: &[Scanned],
) -> bool {
    heads.len() == scanned.len()
        && heads.iter().all(|&(i, length, md5_16k, file_id)| {
            scanned.get(i).is_some_and(|actual| {
                actual.length == length && actual.md5_16k == md5_16k && actual.file_id == file_id
            })
        })
}

/// The identity of a member without hashing its body: length, the
/// 16 KiB head digest, and the file id derived from them - all a
/// creator needs to fix the input-slice ORDER (Main lists ids sorted)
/// before the whole-file and block hashes exist. Sixteen KiB per
/// member, so it is cheap enough to run serially ahead of everything.
pub(super) fn scan_head(m: &Member) -> Result<(u64, [u8; 16], [u8; 16]), Par2GenError> {
    let f = std::fs::File::open(&m.path).map_err(io(&m.path))?;
    let length = f.metadata().map_err(io(&m.path))?.len();
    // Clamp in u64 before narrowing. On a 32-bit target, narrowing a
    // 4-GiB-aligned file length first produces zero and hashes an empty
    // identity prefix instead of the required first 16 KiB.
    let mut buf = vec![0u8; scan_head_len(length)];
    crate::disk::read_exact_at(&f, &mut buf, 0).map_err(io(&m.path))?;
    let md5_16k: [u8; 16] = Md5::digest(&buf).into();
    let mut id = Md5::new();
    id.update(md5_16k);
    id.update(length.to_le_bytes());
    // The UNPADDED name - see `finish_scan` for the whole story.
    id.update(m.name.as_bytes());
    Ok((length, md5_16k, id.finalize().into()))
}

/// The sort key a PAR2 file id carries, and the ONE spelling of it.
///
/// # A file id sorts as a 16-byte LITTLE-ENDIAN number
///
/// Not lexicographically. The spec's Main packet lists the recovery-set
/// ids in ascending order, and "ascending" there means the numeric order
/// of the id read little-endian - compare from the LAST byte back - so
/// `df10..28` sorts before `7404..50` because 0x28 < 0x50, where a
/// bytewise sort puts them the other way round.
///
/// That order is not cosmetic: `Par2Set::files` IS the global input
/// slice index space, laid out by walking the Main list, so every
/// recovery constant is keyed to it. Getting it wrong changes the
/// recovery DATA.
///
/// # Why nothing caught it until 3 Sep 2026
///
/// A set built under the wrong order SELF-VERIFIES, and so does every
/// repair from it, because each tool reads the order out of the Main
/// packet it was handed rather than deriving one. Our own reader agreed
/// with our own writer; par2cmdline agreed with both, on our sets and on
/// its own. Only a byte-level diff against the reference over a set with
/// at least two members whose ids straddle the difference shows it - the
/// conformance harness's first such set, and the trap was already
/// written down in `the parfast reference tree HANDOFF.md`, from the standalone
/// build that hit it in August and never had a way to carry the finding
/// back into this engine. That is the copy this crate's `parfast` front
/// exists to end.
pub(super) fn id_order(id: &[u8; 16]) -> [u8; 16] {
    let mut k = *id;
    k.reverse();
    k
}

/// The identity half of a scan, shared by the serial and fan-out paths
/// so the file id is spelled once.
pub(super) fn finish_scan(
    m: &Member,
    length: u64,
    md5_whole: [u8; 16],
    md5_16k: [u8; 16],
    blocks: Vec<([u8; 16], u32)>,
    digest: Option<crate::digest_cache::Pending>,
) -> Scanned {
    let name_padded = pad4(m.name.as_bytes().to_vec());
    // File id = MD5(md5_16k | length | name), over the name WITHOUT its
    // null padding. The stored id is authoritative on the read side
    // (readers key Main/FileDesc/IFSC by it and never recompute), but it
    // has to be RIGHT here or a conforming reader that does recompute
    // rejects the set.
    //
    // IT WAS NOT, until 3 Sep 2026: both hashes here fed `name_padded`,
    // so every member whose name length is not already a multiple of 4
    // got an id derived from trailing NULs the spec does not hash. A
    // name of 4, 8 or 12 characters padded to itself and came out right,
    // which is why nothing caught it - the fixture names in this
    // repository's own par2gen tests are `text.txt`, `data.bin`,
    // `movie.mkv`: eight and eight and nine, and the nine-character one
    // never had its id checked against the reference. The conformance
    // harness found it on the first two-member set with a five-character
    // name in it (`a.bin`), 3 Sep 2026: par2cmdline-turbo's FileDesc
    // packets for the same bytes carried a different id, and the
    // reference's matched `par2::filedesc_id` - this crate's own READER
    // - while ours did not.
    //
    // What it cost: nothing that self-verifies. Every reader takes the
    // id out of the packet, so our sets were internally consistent and
    // par2cmdline verified and repaired them (which is what the interop
    // suite proves and why it stayed green). What it cost was
    // CONFORMANCE - a reader that recomputes would reject the set - and
    // byte-identity with the reference, because the Main packet sorts
    // members by id, so a wrong id also permutes the global slice index
    // space and therefore every recovery constant.
    let mut id = Md5::new();
    id.update(md5_16k);
    id.update(length.to_le_bytes());
    id.update(m.name.as_bytes());

    Scanned {
        name_padded,
        file_id: id.finalize().into(),
        md5_whole,
        md5_16k,
        length,
        blocks,
        digest,
    }
}

/// Every arm's CHAIN lane accounts for its member on the chain counter.
///
/// This is the other half of the 16 Sep fix (the pacer half is
/// `super::batch_fold_pacer_tests`): the pacer can read the right
/// counter and still learn nothing if the lane never steps it, which is
/// precisely what shipped - `scan_mapped`'s and
/// `scan_parallel_positional`'s chain lanes stepped NOTHING, by design,
/// because the block lanes already counted those bytes for the progress
/// bar. Each arm is called directly rather than through `scan_at_length`
/// so no environment knob decides which one runs, and so a new arm added
/// tomorrow without a chain step fails a test that names it.
#[cfg(test)]
mod chain_counter_tests {
    use super::*;

    fn watched() -> CreateControl {
        CreateControl::new(None, Some(crate::par2repair::PauseGate::new()))
    }

    struct Tmp(std::path::PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let p = std::env::temp_dir().join(format!(
                "nzbfast-scan-chain-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Nine MiB, so the parallel arms' own 8 MiB floor is cleared and
    /// the mapped arm has several `1 << 20` chain chunks plus a short
    /// last one to credit.
    const LEN: usize = 9 << 20;
    const BS: usize = 64 << 10;

    /// An inert digest pass, in a spelling that compiles with the
    /// `digest-cache` feature either way: `begin` with no store is the
    /// one constructor both `digest_cache.rs` and `digest_cache_off.rs`
    /// publish (`MemberDigest::off` is the ON build's only).
    fn inert_digest(path: &std::path::Path) -> crate::digest_cache::MemberDigest {
        let f = std::fs::File::open(path).unwrap();
        let len = f.metadata().unwrap().len();
        crate::digest_cache::MemberDigest::begin(
            None,
            &f,
            path,
            len,
            crate::digest_cache::FLAG_CREATE,
        )
    }

    fn fixture(t: &Tmp, name: &str) -> std::path::PathBuf {
        let path = t.0.join(name);
        let data: Vec<u8> = (0..LEN)
            .map(|i| (i as u32).wrapping_mul(2654435761) as u8)
            .collect();
        std::fs::write(&path, &data).unwrap();
        path
    }

    #[test]
    fn the_mapped_arm_steps_the_chain_counter_for_its_whole_member() {
        let t = Tmp::new("mapped");
        let path = fixture(&t, "m.bin");
        let Ok(Some(map)) = crate::par2gen::MappedMember::open(&path, LEN as u64) else {
            // A box that cannot map is the serial arm's business.
            return;
        };
        let control = watched();
        let n_blocks = LEN.div_ceil(BS);
        let (whole, _head, blocks) =
            scan_mapped(&map, BS, n_blocks, 4, &control, &inert_digest(&path));
        assert!(whole.is_some());
        assert_eq!(blocks.len(), n_blocks);
        assert_eq!(
            control.chain_done(),
            LEN as u64,
            "the mapped arm's sequential chain lane accounted for nothing - \
             the pacer over it can only read the block lanes' progress"
        );
    }

    #[test]
    fn the_positional_arm_steps_the_chain_counter_for_its_whole_member() {
        let t = Tmp::new("positional");
        let path = fixture(&t, "p.bin");
        let f = std::fs::File::open(&path).unwrap();
        let control = watched();
        let n_blocks = LEN.div_ceil(BS);
        let (whole, _head, blocks) = scan_parallel_positional(
            &f,
            &path,
            LEN as u64,
            BS as u64,
            n_blocks,
            4,
            &control,
            &inert_digest(&path),
        )
        .expect("positional scan");
        assert!(whole.is_some());
        assert_eq!(blocks.len(), n_blocks);
        assert_eq!(control.chain_done(), LEN as u64);
    }

    #[test]
    fn the_streamed_arm_steps_the_chain_counter_for_its_whole_member() {
        let t = Tmp::new("streamed");
        let path = fixture(&t, "s.bin");
        let mut f = std::fs::File::open(&path).unwrap();
        let control = watched();
        let n_blocks = LEN.div_ceil(BS);
        let (whole, _head, blocks) = scan_parallel_streamed(
            &mut f,
            &path,
            LEN as u64,
            BS,
            n_blocks,
            BS.min(SCAN_STREAM_PIECE_BYTES as usize),
            &control,
            &inert_digest(&path),
        )
        .expect("streamed scan");
        assert!(whole.is_some());
        assert_eq!(blocks.len(), n_blocks);
        assert_eq!(control.chain_done(), LEN as u64);
    }

    /// And the serial arm, reached where it really is reached - through
    /// `scan_at_length` with one thread on a member under the parallel
    /// floor, which is the only arm that plan picks there.
    #[test]
    fn the_serial_arm_steps_the_chain_counter_for_its_whole_member() {
        let t = Tmp::new("serial");
        let path = t.0.join("tiny.bin");
        let small = 3usize << 20;
        std::fs::write(&path, vec![7u8; small]).unwrap();
        let control = watched();
        let m = Member {
            name: "tiny.bin".into(),
            path: path.clone(),
        };
        let scanned =
            scan_at_length(&m, small as u64, BS as u64, 1, &control, None).expect("serial scan");
        assert_eq!(scanned.length, small as u64);
        assert_eq!(control.chain_done(), small as u64);
    }
}

#[cfg(test)]
mod apriori_scan_lane_width_tests {
    use super::{
        apriori_scan_lane_width, apriori_scan_lane_width_for, block_digest_lane_per_mille_of_chain,
        scan_lane_keep_up_width, scan_pool_geometry,
    };

    /// **The constant is a bound, not a calibration, and the width it
    /// produces does not depend on where in that bound the box sits.**
    /// A block-digest lane runs the chain's own MD5 over the chain's own
    /// bytes plus a CRC32, so it can never be FASTER than the chain
    /// (1000 per mille) and a hardware CRC32 cannot make it much slower.
    /// Every ratio across that whole band asks for the same two lanes -
    /// which is why this rule needs no per-box measurement and the fold
    /// rule does.
    #[test]
    fn every_ratio_in_the_bound_asks_for_the_same_two_lanes() {
        for per_mille in 625..=1000 {
            assert_eq!(
                scan_lane_keep_up_width(per_mille),
                2,
                "per mille {per_mille} should still want two lanes"
            );
        }
        // Only a lane FASTER than the chain - which is the vector kernel
        // this rule deliberately declines to price in - reaches one.
        assert_eq!(scan_lane_keep_up_width(1_250), 1);
        assert_eq!(scan_lane_keep_up_width(8_000), 1);
        // And a lane far slower than the chain asks for more of them,
        // rather than letting the digests become the pole.
        assert_eq!(scan_lane_keep_up_width(300), 5);
    }

    /// **The lanes are shed to what the box has LEFT, which is the whole
    /// coupling between this rule and the fold's.** The measured shape:
    /// eight vCPUs, a four-wide fold chosen by `apriori_fold_width`, one
    /// member and so one chain. Three lanes is what remains, and the box
    /// is then exactly spoken for - a rule that sheds a width without
    /// asking what else is running is the failure this one is built to
    /// avoid.
    #[test]
    fn the_lanes_take_what_the_fold_and_the_chains_leave() {
        assert_eq!(apriori_scan_lane_width_for(4, 1, 2, 8), 3);
        assert_eq!(4 + 3 + 1, 8);
        // A wider fold leaves fewer, in step.
        assert_eq!(apriori_scan_lane_width_for(6, 1, 2, 8), 2);
        // A narrower one leaves more.
        assert_eq!(apriori_scan_lane_width_for(2, 1, 2, 8), 5);
    }

    /// **On a wide box the rule takes back the OVERSUBSCRIPTION and
    /// nothing more**, which is the property that stops two independent
    /// narrowings over-shedding together. The same member and the same
    /// four-wide fold on 32 vCPUs: the geometry would hand one member
    /// all 32 lanes, five more threads than the box has once the fold
    /// and the chain are paid, and the rule sheds exactly those five.
    /// What is left is thirteen times the keep-up width - so the lanes
    /// are nowhere near the floor, and the shedding is bounded by the
    /// box rather than by any estimate of the digests' cost.
    #[test]
    fn a_wide_box_sheds_only_what_it_is_short_of() {
        let (outer, inner) = scan_pool_geometry(&[8_858_370_048], 4_429_188, 32, 320 << 20);
        assert_eq!((outer, inner), (1, 32));
        let wide = apriori_scan_lane_width_for(4, outer, 2, 32);
        assert_eq!(wide, 32 - 4 - outer);
        assert_eq!(inner - wide, 5);
        assert!(wide > 2 * 2, "a wide box is nowhere near the keep-up floor");
    }

    /// **The floor is the keep-up width and it is the binding term on a
    /// small box.** Four cores with a four-wide fold have nothing left
    /// at all, and the lanes still get two: the dangerous direction here
    /// is making the DIGESTS the pole, and this is what bounds it. The
    /// width is never zero, on any box.
    #[test]
    fn the_keep_up_floor_holds_when_nothing_is_left() {
        assert_eq!(apriori_scan_lane_width_for(4, 1, 2, 4), 2);
        assert_eq!(apriori_scan_lane_width_for(8, 1, 2, 8), 2);
        assert_eq!(apriori_scan_lane_width_for(1, 1, 2, 1), 1);
        for max in 1..=64 {
            for fold in 1..=max {
                for outer in 1..=4 {
                    let w = apriori_scan_lane_width_for(fold, outer, 2, max);
                    assert!(w >= 1 && w <= max, "max {max} fold {fold} outer {outer}");
                }
            }
        }
    }

    /// **Many members are a schedule, not a sum.** `scan_all` runs
    /// `outer` chains beside each other and gives each of them `inner`
    /// lanes, so what one member may take is what is left DIVIDED by the
    /// chains - and the geometry has usually divided the box already, so
    /// on a many-member set this rule mostly finds nothing to shed.
    #[test]
    fn many_members_divide_what_is_left_between_their_chains() {
        // Eight cores, four chains, a two-wide fold: two spare between
        // four members is nothing each, so the floor answers.
        assert_eq!(apriori_scan_lane_width_for(2, 4, 2, 8), 2);
        // And the geometry that produced those four chains has already
        // handed each member two lanes, so the cap binds nothing.
        let sizes = [4u64 << 30, 4 << 30, 4 << 30, 4 << 30];
        let (outer, inner) = scan_pool_geometry(&sizes, 4_429_188, 8, 320 << 20);
        assert_eq!((outer, inner), (4, 2));
        assert_eq!(inner.min(apriori_scan_lane_width_for(2, outer, 2, 8)), 2);
    }

    /// **A box whose ratio is not known declines to narrow**, the same
    /// refusal `fold_rows_per_worker_per_chain_pass` makes and for the
    /// same reason - except that this gate is far wider, because it asks
    /// only that the CRC32 beside the digests runs on the hardware
    /// instruction rather than out of a table. On a box that answers, the
    /// rule is the arithmetic above with the bound's own keep-up width.
    #[test]
    fn an_unmeasured_box_declines_to_narrow() {
        match block_digest_lane_per_mille_of_chain() {
            Some(per_mille) => {
                assert!(
                    (625..=1000).contains(&per_mille),
                    "{per_mille} is outside the bound"
                );
                assert_eq!(
                    apriori_scan_lane_width(4, 1, 8),
                    Some(apriori_scan_lane_width_for(4, 1, 2, 8))
                );
            }
            None => assert_eq!(apriori_scan_lane_width(4, 1, 8), None),
        }
    }
}
