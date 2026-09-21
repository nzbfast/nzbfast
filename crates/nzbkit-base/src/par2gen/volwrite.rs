//! Writing the recovery volumes of one fold batch, and the backfill
//! that replaces the placeholder critical block once the member hashes
//! are in. Both lifted out of [`super::create_into_inner`] on 9 Sep 2026
//! (claim `par2gen-size-split-9sep`), which was 3 lines under the size
//! gate's 500-line function ceiling.
//!
//! Nothing here decides anything: the batch's exponent range, its
//! slices and whether the real critical block is ready are all settled
//! by the caller. Only the rewrites a call boundary forces are new -
//! `layout[vi..vj]` became the `layout` slice passed in, and the two
//! critical blocks arrive as `&[u8]` rather than `&Vec<u8>`.

use super::*;

/// Everything one batch of volumes is written from. A struct rather
/// than nine positional parameters, for the same reason
/// [`super::FoldWindows`] is one.
pub(super) struct BatchVolumes<'a> {
    pub(super) control: &'a CreateControl,
    /// Every volume this batch creates is opened THROUGH this and
    /// noted the moment the open succeeds, so a cancel taken in this
    /// batch or any later one removes it - and a volume the trail
    /// REFUSED (no-clobber over a file that is already there) is never
    /// noted and so never removed. See `control::CreateTrail`.
    pub(super) trail: &'a CreateTrail,
    pub(super) dir: &'a Path,
    pub(super) base: &'a str,
    /// The `(first exponent, count)` pairs of THIS batch's volumes.
    pub(super) layout: &'a [(usize, usize)],
    pub(super) set_id: &'a [u8; 16],
    /// Exponent of `slices[0]` - a volume's rows are `slices[e - first]`.
    pub(super) first: usize,
    pub(super) slices: &'a [Vec<u16>],
    /// The real critical block once the hashes have landed; `None`
    /// leaves the placeholder in place for the backfill below.
    pub(super) ready_critical: Option<&'a [u8]>,
    pub(super) critical_shape: &'a [u8],
    pub(super) cidx: Option<&'a CriticalIndex>,
}

/// Write this batch's volumes across threads and return them in layout
/// order, each with the patch its file still owes.
pub(super) fn write_batch(
    b: BatchVolumes<'_>,
) -> Result<Vec<(String, CriticalPatch)>, Par2GenError> {
    let BatchVolumes {
        control,
        trail,
        dir,
        base,
        layout,
        set_id,
        first,
        slices,
        ready_critical,
        critical_shape,
        cidx,
    } = b;
    let mut out: Vec<(String, CriticalPatch)> = Vec::with_capacity(layout.len());
    // Volumes of one batch are sealed and written across
    // threads: each is its own packet stream over its own
    // slice range, and serially the 111 MB of a 10% set over
    // 1 GiB cost ~170 ms of a 1.1 s create (measured 2 Sep
    // 2026, M3 Ultra) - the MD5 seal of every recovery packet
    // is the larger half of that.
    let names: Vec<String> = layout
        .iter()
        .map(|&(vfirst, count)| format!("{base}.vol{vfirst:03}+{count:02}.par2"))
        .collect();
    let mut written: Vec<Option<Result<CriticalPatch, Par2GenError>>> =
        (0..names.len()).map(|_| None).collect();
    // One recovery slice's payload: the block size, taken off the
    // accumulator rather than passed in, because that is where it is
    // already known to be right.
    let slice_bytes = slices.first().map_or(0, |s| s.len() as u64 * 2);
    // Before a single byte is written: a cancel here costs the batch
    // that was already folded, and a volume that was never created is
    // one the trail never has to name.
    control.check()?;
    let seals = recovery_seals(set_id, first, slices);
    std::thread::scope(|wsc| {
        for ((&(vfirst, count), name), slot) in layout.iter().zip(&names).zip(written.iter_mut()) {
            let critical = ready_critical.unwrap_or(critical_shape);
            let complete = ready_critical.is_some();
            let seals = &seals;
            wsc.spawn(move || {
                // PER VOLUME, which is this site's grain: one relaxed
                // load before a file worth tens or hundreds of
                // megabytes. Cancel only, never a park - a parked
                // writer would hold the batch's scope open while the
                // others finished, and the batch boundary in
                // `create_body` is where a pause belongs.
                if control.cancelled() {
                    *slot = Some(Err(Par2GenError::Cancelled));
                    return;
                }
                let path = dir.join(name);
                let result = (|| -> std::io::Result<CriticalPatch> {
                    // Opened and noted in one call. A no-clobber trail
                    // answers `AlreadyExists` here rather than
                    // truncating a file this run does not own, and the
                    // error reaches the caller through this closure's
                    // own `io(&path)` mapping like any other.
                    let file: SetMember = trail.create(dir, name)?;
                    // Fine-sliced sets feed many 4 KiB packets, so
                    // coalesce their small writes; a large slice
                    // bypasses the buffer and streams straight out
                    // of the accumulator with no volume-sized copy.
                    let mut writer = std::io::BufWriter::with_capacity(1 << 20, file);
                    let Some(cidx) = cidx else {
                        std::io::Write::write_all(&mut writer, critical)?;
                        for i in 0..count {
                            let e = vfirst + i;
                            let slice = crate::gf16::words_as_bytes(&slices[e - first]);
                            write_recovery_packet(
                                &mut writer,
                                set_id,
                                e as u32,
                                slice,
                                seals.as_ref().map(|d| &d[e - first]),
                            )?;
                        }
                        std::io::Write::flush(&mut writer)?;
                        return Ok(if complete {
                            CriticalPatch::Complete
                        } else {
                            CriticalPatch::Head
                        });
                    };
                    // par2cmdline's shape: a recovery packet, then
                    // however many critical packets the schedule
                    // owes at that point, and the Creator once at
                    // the end. Offsets are recorded as they are
                    // written, so the backfill patches exactly what
                    // this loop laid down.
                    let after = interleave_schedule(count, cidx.cycle.len());
                    let mut offsets = Vec::with_capacity(after.iter().sum::<usize>());
                    let mut pos = 0u64;
                    let mut turn = 0usize;
                    for (i, owed) in after.iter().enumerate() {
                        let e = vfirst + i;
                        let slice = crate::gf16::words_as_bytes(&slices[e - first]);
                        write_recovery_packet(
                            &mut writer,
                            set_id,
                            e as u32,
                            slice,
                            seals.as_ref().map(|d| &d[e - first]),
                        )?;
                        pos += 68 + slice.len() as u64;
                        for _ in 0..*owed {
                            let (o, l) = cidx.cycle[turn % cidx.cycle.len()];
                            std::io::Write::write_all(&mut writer, &critical[o..o + l])?;
                            offsets.push(pos);
                            pos += l as u64;
                            turn += 1;
                        }
                    }
                    let (o, l) = cidx.creator;
                    std::io::Write::write_all(&mut writer, &critical[o..o + l])?;
                    std::io::Write::flush(&mut writer)?;
                    Ok(if complete {
                        CriticalPatch::Complete
                    } else {
                        CriticalPatch::Interleaved(offsets)
                    })
                })();
                if result.is_ok() {
                    // The set's recovery payload, in bytes, as this
                    // volume's share of it. Sized once for the whole
                    // create (`create_body`), so this walks up across
                    // every batch.
                    control.step(CreatePhase::Write, count as u64 * slice_bytes);
                }
                *slot = Some(result.map_err(io(&path)));
            });
        }
    });
    for (name, w) in names.into_iter().zip(written) {
        let patch = w.expect("volume writer filled its slot")?;
        out.push((name, patch));
    }
    Ok(out)
}

/// The real critical block over the placeholder - at the front of the
/// index and of every `Head` volume, and at each recorded packet offset
/// of an interleaved one.
///
/// # The one write path here that is NOT a [`SetMember`]
///
/// This is a REOPEN of a member `write_batch` above already created
/// through the door, and it deliberately holds a raw `std::fs::File`.
/// Its chain carries no `.create`, no `.create_new` and no `.truncate`,
/// so it cannot bring a file into existence: there is nothing for the
/// door to refuse and nothing new to note - noting it a second time
/// would be a duplicate in the cancel's unlink list. Threading a
/// `SetMember` to it would mean giving that type a construction that
/// does not create, which is precisely the hole it exists to close, so
/// the separation is create-versus-reopen and this is the reopen side. The placeholder and the real block hold the
/// same packets at the same lengths (the caller's set-id and length
/// check is what makes that true), so a recorded offset still names the
/// packet it named when it was written.
pub(super) fn backfill_critical(
    dir: &Path,
    out: &[(String, CriticalPatch)],
    critical: &[u8],
    cidx: Option<&CriticalIndex>,
) -> Result<(), Par2GenError> {
    for (name, patch) in out {
        if matches!(patch, CriticalPatch::Complete) {
            continue;
        }
        let path = dir.join(name);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(io(&path))?;
        match patch {
            CriticalPatch::Complete => unreachable!("complete volumes were skipped"),
            CriticalPatch::Head => {
                crate::disk::write_all_at(&f, critical, 0).map_err(io(&path))?;
            }
            CriticalPatch::Interleaved(offsets) => {
                let cidx = cidx.expect("an interleaved file had an index");
                for (k, &at) in offsets.iter().enumerate() {
                    let (o, l) = cidx.cycle[k % cidx.cycle.len()];
                    crate::disk::write_all_at(&f, &critical[o..o + l], at).map_err(io(&path))?;
                }
            }
        }
    }
    Ok(())
}
