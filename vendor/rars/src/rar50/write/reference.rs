//! RAR 5 archives in the byte layout the reference `rar` writes.
//!
//! [`super`] is the fork's own RAR 5 writer, and its layout choices are
//! its own: a BLAKE2sp hash record on every member, no quick-open
//! information, no locator, minimum-width vints throughout. Those are
//! good choices for a writer whose output only has to be READ, and they
//! are what nzbfast's posting layouts are pinned to, so they must not
//! move.
//!
//! This module is the other requirement. `rarfast` is a drop-in for the
//! reference `rar`, and the conformance table compares a sha256 of the
//! archive it wrote (`tools/conformance/run.py rar` in the nzbfast repo,
//! rows `add-stored`, `add-level-m0`, `add-stored-recurse`,
//! `add-hash-blake2` and the whole in-place editing family). The spec's
//! R.2 paragraph says why byte-identity is required for STORED mode and
//! only for stored mode: two RAR encoders do not emit the same bytes for
//! a compressed entry, but a store has nothing for an encoder to choose,
//! so the bytes are a property of the FORMAT and a drop-in owes them.
//!
//! Everything below was measured against rar 7.23 on macOS on 4 Sep 2026
//! by writing archives and reading them back, not by reading the format
//! note - several of these are not what the note would lead you to write:
//!
//! * The main header carries a LOCATOR extra record whose quick-open
//!   offset is a FIXED-WIDTH vint, reserved before the offset is known
//!   and patched afterwards. The width is not the width the value needs;
//!   see [`locator_reserve_width`], which carries the measurement that
//!   pinned it.
//! * `PackSize`, `UnpSize` and `CompressionInfo` in a FILE header are
//!   written with a MINIMUM width of two bytes - `51` is `b3 00`, and a
//!   compression info of zero is `80 00`. A directory member, whose size
//!   is known to be zero before the header is written, uses one byte for
//!   both sizes and still two for the compression info.
//! * A member whose mtime has a fractional second carries an HTIME extra
//!   record (unix seconds plus nanoseconds) and does NOT set the
//!   header's own mtime flag; a whole-second mtime is written the other
//!   way round, in the header field with no extra record.
//! * The default data checksum is CRC32 in the header. `-htb` moves it
//!   to a BLAKE2sp HASH extra record and clears the CRC32 flag - the
//!   two never appear together.
//! * The main and end headers set the "skip if unknown" flag (0x04);
//!   file headers do not.
//! * A quick-open (`QO`) service block is appended when at least one
//!   member's data is LARGER THAN 4096 bytes, caching that member's
//!   whole block image. Small members are not cached even when the
//!   archive is large.
//!
//! The one thing this module deliberately does not do is compress. A
//! caller that wants `-m1`..`-m5` uses [`super::Rar50Writer`]; the bytes
//! cannot match the reference there and the spec makes the ratio a
//! non-goal.

use crate::crc32::crc32;
use crate::error::{Error, Result};
use crate::rar50::blake2sp;

/// Which checksum a member carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReferenceHash {
    /// The reference's default: CRC32, in the file header itself.
    #[default]
    Crc32,
    /// `-htb`: BLAKE2sp, in a HASH extra record, and no CRC32 flag.
    Blake2sp,
}

/// How much quick-open information to write, which `-qo` selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReferenceQuickOpen {
    /// The default: cache the header of every member larger than
    /// [`QUICK_OPEN_MIN_DATA`], and none of the rest.
    #[default]
    Auto,
    /// `-qo+`: cache every member, whatever its size.
    All,
    /// `-qo-`: no quick-open block, AND no locator record in the main
    /// header - measured, because the locator is what points at the
    /// block and the reference drops the pair together.
    None,
}

/// Which of the reference's two header layouts to write.
///
/// They differ in ONE field and the difference is measured: creating an
/// archive puts a whole-second mtime in the header's own 32-bit field,
/// and REWRITING one (`rn`, and every other command that re-emits rather
/// than copies) puts the same time in an HTIME extra record with the
/// header's mtime flag clear. A sub-second time uses the record either
/// way, with the nanosecond flag added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReferenceLayout {
    /// What `rar a` writes into a new archive.
    #[default]
    Create,
    /// What `rar rn` writes when it re-emits an existing member.
    Rewrite,
}

/// One member of a reference-layout archive.
#[derive(Debug, Clone, Copy)]
pub struct ReferenceMember<'a> {
    /// The archived name, `/`-separated, as it appears in a listing.
    pub name: &'a str,
    /// The member's bytes. Empty for a directory.
    pub data: &'a [u8],
    /// Unix mtime as (whole seconds, nanoseconds). `None` writes no
    /// time at all, which the reference does only for a service block.
    pub mtime: Option<(u32, u32)>,
    /// The member's attribute word, host-OS shaped.
    pub attributes: u64,
    /// 0 Windows, 1 Unix.
    pub host_os: u64,
    /// Whether this member is a directory entry, which carries no data
    /// and no checksum.
    pub is_dir: bool,
}

const HEAD_MAIN: u64 = 1;
const HEAD_FILE: u64 = 2;
const HEAD_SERVICE: u64 = 3;
const HEAD_END: u64 = 5;

const HFL_EXTRA: u64 = 0x0001;
const HFL_DATA: u64 = 0x0002;
const HFL_SKIP: u64 = 0x0004;
const HFL_SPLIT_BEFORE: u64 = 0x0008;
const HFL_SPLIT_AFTER: u64 = 0x0010;

const FHFL_DIRECTORY: u64 = 0x0001;
const FHFL_MTIME: u64 = 0x0002;
const FHFL_CRC32: u64 = 0x0004;

const MHEXTRA_LOCATOR: u64 = 0x01;
const MHEXTRA_LOCATOR_QUICK_OPEN: u64 = 0x01;
const MHEXTRA_LOCATOR_RECOVERY: u64 = 0x02;
const FHEXTRA_HASH: u64 = 0x02;
const FHEXTRA_HTIME: u64 = 0x03;
const HTIME_UNIX: u64 = 0x01;
const HTIME_MTIME: u64 = 0x02;
const HTIME_UNIX_NS: u64 = 0x10;

const MHFL_VOLUME: u64 = 0x0001;
const MHFL_VOLUME_NUMBER: u64 = 0x0002;
/// The main header's "this archive carries a recovery record" bit, which
/// `rr` sets and `a -rr` sets for the same reason.
const MHFL_RECOVERY: u64 = 0x0008;
const EHFL_NEXT_VOLUME: u64 = 0x0001;

/// Data larger than this gets its header cached in the quick-open block.
///
/// Measured: a lone 4096-byte member produces no `QO` block at all and a
/// 4097-byte one does, and in a two-member archive only the large member
/// is cached. So the test is per member and on its data size, not on the
/// size of the archive.
const QUICK_OPEN_MIN_DATA: usize = 4096;

/// The signature every RAR 5 archive opens with.
pub const RAR5_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";

fn write_vint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Writes `value` in EXACTLY `width` bytes, padding with continuation
/// bytes that carry no bits.
///
/// This is the shape the reference uses wherever it has to patch a field
/// after the fact, and wherever it writes a size it did not know when the
/// header was laid out. A decoder cannot tell the two apart - a vint is
/// read until a byte without the top bit - so the padding is invisible to
/// everything except a byte comparison, which is exactly what the
/// conformance table does.
fn write_vint_padded(out: &mut Vec<u8>, value: u64, width: usize) {
    let mut left = value;
    for _ in 0..width.saturating_sub(1) {
        out.push(((left & 0x7f) as u8) | 0x80);
        left >>= 7;
    }
    out.push((left & 0x7f) as u8);
}

/// How many bytes a plain vint of `value` needs.
fn vint_width(value: u64) -> usize {
    let mut width = 1;
    let mut left = value >> 7;
    while left != 0 {
        width += 1;
        left >>= 7;
    }
    width
}

/// Width the reference reserves for the locator's quick-open offset.
///
/// **This is a measurement, not a derivation, and the measurement is
/// exact.** The reference lays the main header out before it knows where
/// the quick-open block will land, so the offset is a fixed-width vint it
/// patches at the end - but the width is not the width the eventual value
/// needs. A 209-byte archive reserves three bytes for an offset of zero;
/// a 24,821-byte one reserves four; a 300,154-byte one reserves five.
///
/// Fitting it took two rounds of bisection on the dev Mac, 4 Sep 2026,
/// because the driver is neither the payload nor the archive size: a
/// 463-byte payload under a 5-character name reserves three bytes and the
/// SAME payload under a 37-character name reserves four, in a LARGER
/// archive that a size rule would have to answer the same way. What fits
/// every one of the twenty-odd shapes measured is
///
///     estimate = sum over members of (data length + 33 + 3 * name length)
///     width    = vint_width(estimate << 12)
///
/// and the fit was then CONFIRMED by prediction rather than by curve
/// fitting: it says a single member named `s.bin` crosses from four bytes
/// to five at exactly 65,488 payload bytes (estimate 65,536), and the
/// reference does, 65,487 giving four and 65,488 giving five. The same
/// formula predicts the 37-character name's crossing at 368 bytes, and
/// that is where it is.
///
/// The `3 * name length` is presumably a UTF-8 worst case over a wide
/// character, and the `<< 12` presumably a headroom factor. Neither
/// reading matters here: what matters is that the width is reproduced,
/// and a shape where it is not would show up as a whole-archive sha256
/// mismatch in the conformance table rather than silently.
fn locator_reserve_width(members: &[(u64, usize)]) -> usize {
    let estimate: u64 = members
        .iter()
        .map(|(data_len, name_len)| data_len + 33 + 3 * *name_len as u64)
        .sum();
    vint_width(estimate << 12)
}

/// Assembles one block: CRC32, header size, header, then the data area.
fn block_image(
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    data_size_width: usize,
    specific: &[u8],
    extra: &[u8],
) -> Vec<u8> {
    let mut header = Vec::new();
    write_vint(&mut header, header_type);
    write_vint(&mut header, flags);
    if !extra.is_empty() {
        write_vint(&mut header, extra.len() as u64);
    }
    if let Some(size) = data_size {
        write_vint_padded(&mut header, size, data_size_width);
    }
    header.extend_from_slice(specific);
    header.extend_from_slice(extra);

    let mut sized = Vec::new();
    write_vint(&mut sized, header.len() as u64);
    sized.extend_from_slice(&header);

    let mut out = crc32(&sized).to_le_bytes().to_vec();
    out.extend_from_slice(&sized);
    out
}

/// The HTIME extra record, or nothing when the header's own field will
/// carry the time instead.
fn htime_record(mtime: Option<(u32, u32)>, layout: ReferenceLayout) -> Option<Vec<u8>> {
    let (secs, nanos) = mtime?;
    if nanos == 0 && layout == ReferenceLayout::Create {
        // A whole second goes in the header's own mtime field instead,
        // and the reference writes no record at all. Measured: `touch -t`
        // a file and the extra area disappears. On the REWRITE path it
        // does the opposite - see [`ReferenceLayout`].
        return None;
    }
    let mut body = Vec::new();
    let mut flags = HTIME_UNIX | HTIME_MTIME;
    if nanos != 0 {
        flags |= HTIME_UNIX_NS;
    }
    write_vint(&mut body, flags);
    body.extend_from_slice(&secs.to_le_bytes());
    if nanos != 0 {
        body.extend_from_slice(&nanos.to_le_bytes());
    }
    Some(extra_record(FHEXTRA_HTIME, &body))
}

fn extra_record(record_type: u64, body: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    write_vint(&mut inner, record_type);
    inner.extend_from_slice(body);
    let mut out = Vec::new();
    write_vint(&mut out, inner.len() as u64);
    out.extend_from_slice(&inner);
    out
}

/// One member's header image: CRC32, header size and header bytes, with
/// no data area. [`assemble`] appends the data.
pub fn member_header(
    member: &ReferenceMember<'_>,
    hash: ReferenceHash,
    layout: ReferenceLayout,
) -> Result<Vec<u8>> {
    member_header_split(member, hash, layout, Split::Whole, member.data)
}

fn member_header_split(
    member: &ReferenceMember<'_>,
    hash: ReferenceHash,
    layout: ReferenceLayout,
    split: Split,
    fragment_bytes: &[u8],
) -> Result<Vec<u8>> {
    let fragment = fragment_bytes.len() as u64;
    if member.name.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 file name is empty"));
    }
    let name = member.name.as_bytes();
    let whole_member = split == Split::Whole;
    let mut extra = Vec::new();
    let mut file_flags = 0;
    let mut crc = None;

    if member.is_dir {
        file_flags |= FHFL_DIRECTORY;
    } else {
        // EVERY fragment carries a checksum, and the reference does not
        // put the same one on each: measured on a three-volume set, the
        // first two headers carry the CRC32 of their OWN fragment and
        // the last carries the CRC32 of the whole member. So a reader
        // that has only volume 2 can still check what it has, and a
        // reader that reaches the end can check the join.
        let covered: &[u8] = if whole_member || split == Split::Tail {
            member.data
        } else {
            fragment_bytes
        };
        match hash {
            ReferenceHash::Crc32 => {
                file_flags |= FHFL_CRC32;
                crc = Some(crc32(covered));
            }
            ReferenceHash::Blake2sp => {
                let mut body = vec![0];
                body.extend_from_slice(&blake2sp::hash(covered));
                extra.extend_from_slice(&extra_record(FHEXTRA_HASH, &body));
            }
        }
    }

    let mtime_field = match member.mtime {
        Some((secs, 0)) if layout == ReferenceLayout::Create => {
            file_flags |= FHFL_MTIME;
            Some(secs)
        }
        _ => None,
    };
    if let Some(record) = htime_record(member.mtime, layout) {
        extra.extend_from_slice(&record);
    }

    let unpacked = member.data.len() as u64;
    // Sizes get a two-byte minimum wherever the reference laid the
    // header out before it knew them; a directory's are known to be zero
    // and take one. The compression info is always two.
    let size_width = if member.is_dir {
        1
    } else {
        vint_width(unpacked).max(2)
    };

    let mut specific = Vec::new();
    write_vint(&mut specific, file_flags);
    write_vint_padded(&mut specific, unpacked, size_width);
    write_vint(&mut specific, member.attributes);
    if let Some(secs) = mtime_field {
        specific.extend_from_slice(&secs.to_le_bytes());
    }
    if let Some(crc) = crc {
        specific.extend_from_slice(&crc.to_le_bytes());
    }
    write_vint_padded(&mut specific, 0, 2);
    write_vint(&mut specific, member.host_os);
    write_vint(&mut specific, name.len() as u64);
    specific.extend_from_slice(name);

    let mut flags = HFL_DATA;
    if !extra.is_empty() {
        flags |= HFL_EXTRA;
    }
    if matches!(split, Split::Tail | Split::Middle) {
        flags |= HFL_SPLIT_BEFORE;
    }
    if matches!(split, Split::Head | Split::Middle) {
        flags |= HFL_SPLIT_AFTER;
    }

    Ok(block_image(
        HEAD_FILE,
        flags,
        Some(fragment),
        size_width,
        &specific,
        &extra,
    ))
}

/// Where a member's fragment sits in a split member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Split {
    /// Not split at all.
    Whole,
    /// The first fragment.
    Head,
    /// Neither the first nor the last.
    Middle,
    /// The last fragment.
    Tail,
}

/// The main header, with the locator's offset left at zero.
fn main_header(reserve: usize, archive_flags: u64) -> Vec<u8> {
    let extra = locator_extra(reserve);

    let mut specific = Vec::new();
    write_vint(&mut specific, archive_flags);
    if archive_flags & MHFL_VOLUME_NUMBER != 0 {
        write_vint(&mut specific, 0);
    }
    block_image(
        HEAD_MAIN,
        if extra.is_empty() { HFL_SKIP } else { HFL_EXTRA | HFL_SKIP },
        None,
        1,
        &specific,
        &extra,
    )
}

/// The locator extra record, or nothing when `-qo-` asked for neither it
/// nor the block it points at.
fn locator_extra(reserve: usize) -> Vec<u8> {
    if reserve == 0 {
        return Vec::new();
    }
    let mut record = Vec::new();
    write_vint(&mut record, MHEXTRA_LOCATOR_QUICK_OPEN);
    write_vint_padded(&mut record, 0, reserve);
    extra_record(MHEXTRA_LOCATOR, &record)
}

/// The main header `rr` writes: the recovery bit set, and a locator
/// carrying BOTH offsets.
///
/// Measured against rar 7.23 on 4 Sep 2026. Adding a record to an
/// archive that had none moves three things in the main header at once,
/// and all three are needed before the reference will verify the record:
/// the archive flags gain 0x0008, the locator's flags gain 0x02, and a
/// second fixed-width offset is appended after the quick-open one. It
/// does this even to an archive written with `-qo-`, which had no
/// locator at all: the rebuilt header carries the pair with the
/// quick-open offset left at zero.
fn main_header_recovery(reserve: usize, archive_flags: u64) -> Vec<u8> {
    let mut record = Vec::new();
    write_vint(
        &mut record,
        MHEXTRA_LOCATOR_QUICK_OPEN | MHEXTRA_LOCATOR_RECOVERY,
    );
    write_vint_padded(&mut record, 0, reserve);
    write_vint_padded(&mut record, 0, reserve);
    let extra = extra_record(MHEXTRA_LOCATOR, &record);

    let mut specific = Vec::new();
    write_vint(&mut specific, archive_flags);
    block_image(HEAD_MAIN, HFL_EXTRA | HFL_SKIP, None, 1, &specific, &extra)
}

/// Width the reference reserves for EACH locator offset when `rr` adds a
/// recovery record to an archive that already exists.
///
/// **It is not [`locator_reserve_width`], and the difference is
/// measured.** The create path estimates from the members it is about to
/// write; this path has an archive in front of it and estimates from its
/// SIZE. A single 300-byte member under a 100-character name is the case
/// that separates them: the member estimate says four bytes and the
/// reference reserves four when it creates that archive, while `rr` over
/// the same 459-byte file reserves three.
///
/// What fits every shape measured is
///
///     width = vint_width((archive length + 1) << 12)
///
/// and it was then confirmed by PREDICTION at both crossings rather than
/// by curve fitting. It says three bytes becomes four at exactly 511
/// bytes of archive: 510 gives three and 511 gives four. It says four
/// becomes five at 65,535: 65,534 gives four and 65,535 gives five. Both
/// were checked byte by byte over the sizes either side.
fn locator_reserve_width_rewrite(existing_len: u64) -> usize {
    vint_width(existing_len.saturating_add(1).saturating_mul(1 << 12))
}

/// Byte offset of the locator's quick-open field inside a main header
/// block, so the caller can patch it once the offset is known.
///
/// It is the LAST field of the block - the locator is the last extra
/// record and the offset is its last field - so it is found by counting
/// back from the end rather than forward from the start. Counting
/// forward was wrong for a volume: the volume number sits between the
/// archive flags and the extra area, so a fixed offset patched one byte
/// early and corrupted the record.
fn locator_offset_position(main_len: usize, reserve: usize) -> usize {
    main_len - reserve
}

fn end_header(next_volume: bool) -> Vec<u8> {
    let mut specific = Vec::new();
    write_vint(
        &mut specific,
        if next_volume { EHFL_NEXT_VOLUME } else { 0 },
    );
    block_image(HEAD_END, HFL_SKIP, None, 1, &specific, &[])
}

/// The quick-open service block, or nothing when no member earns one.
///
/// `cached` is (offset of the member's block inside the archive, that
/// block's header image). The record's own offset is the DISTANCE back
/// from the quick-open block to the cached header, and the record's CRC32
/// covers the size vint together with the body it introduces.
/// Whether a member of this size earns a cached header.
fn caches(mode: ReferenceQuickOpen, data_len: usize) -> bool {
    match mode {
        ReferenceQuickOpen::Auto => data_len > QUICK_OPEN_MIN_DATA,
        ReferenceQuickOpen::All => true,
        ReferenceQuickOpen::None => false,
    }
}

fn quick_open_block(quick_open_pos: usize, cached: &[(usize, Vec<u8>)]) -> Option<Vec<u8>> {
    if cached.is_empty() {
        return None;
    }
    let mut data = Vec::new();
    for (pos, header) in cached {
        let mut body = Vec::new();
        write_vint(&mut body, 0);
        write_vint(&mut body, (quick_open_pos - pos) as u64);
        write_vint(&mut body, header.len() as u64);
        body.extend_from_slice(header);

        let mut sized = Vec::new();
        write_vint(&mut sized, body.len() as u64);
        sized.extend_from_slice(&body);

        data.extend_from_slice(&crc32(&sized).to_le_bytes());
        data.extend_from_slice(&sized);
    }

    let mut specific = Vec::new();
    write_vint(&mut specific, 0);
    write_vint_padded(&mut specific, data.len() as u64, 2);
    write_vint(&mut specific, 0);
    write_vint_padded(&mut specific, 0, 2);
    write_vint(&mut specific, 1);
    write_vint(&mut specific, 2);
    specific.extend_from_slice(b"QO");

    let mut out = block_image(
        HEAD_SERVICE,
        HFL_DATA | HFL_SKIP,
        Some(data.len() as u64),
        2,
        &specific,
        &[],
    );
    out.extend_from_slice(&data);
    Some(out)
}

/// The `CMT` service header an archive comment rides in.
///
/// Measured against the reference: it sits between the main header and
/// the first member, carries the comment's bytes STORED with a CRC32 in
/// the header, and - unlike the quick-open block - does NOT set the
/// skip-if-unknown flag. It is also invisible to the locator's size
/// estimate: a 100-byte comment beside a 400-byte member leaves the
/// reserve at three bytes, where counting it would have pushed it to
/// four.
pub fn comment_header(data: &[u8]) -> Vec<u8> {
    let mut specific = Vec::new();
    write_vint(&mut specific, FHFL_CRC32);
    write_vint_padded(&mut specific, data.len() as u64, 2);
    write_vint(&mut specific, 0);
    specific.extend_from_slice(&crc32(data).to_le_bytes());
    write_vint_padded(&mut specific, 0, 2);
    write_vint(&mut specific, if cfg!(windows) { 0 } else { 1 });
    write_vint(&mut specific, 3);
    specific.extend_from_slice(b"CMT");
    block_image(
        HEAD_SERVICE,
        HFL_DATA,
        Some(data.len() as u64),
        2,
        &specific,
        &[],
    )
}

/// One block of an assembled archive: its header image and its data.
pub struct ReferenceBlock<'a> {
    /// CRC32, header size and header bytes, as [`member_header`] returns.
    pub header: Vec<u8>,
    /// The data area that follows the header.
    pub data: &'a [u8],
    /// The member's archived name, or `None` for a service block. A
    /// service block is not a member: it is skipped by the locator's
    /// size estimate and never cached in the quick-open block, both
    /// measured against the reference (a `-z` comment of any size leaves
    /// the reserve where it was).
    pub name: Option<&'a str>,
}

/// Assembles an archive from blocks already in their final form.
///
/// This is the half every WRITING command shares: `a` builds its blocks
/// from files on disk, the in-place editing commands build theirs by
/// copying or re-emitting an existing archive's, and both need the same
/// main header, the same locator reserve, the same quick-open block and
/// the same end header. `archive_flags` carries `k`'s lock bit, which is
/// the only archive flag any of them sets.
pub fn assemble(
    blocks: &[ReferenceBlock<'_>],
    archive_flags: u64,
    quick_open: ReferenceQuickOpen,
) -> Vec<u8> {
    let sizes: Vec<(u64, usize)> = blocks
        .iter()
        .filter_map(|b| b.name.map(|name| (b.data.len() as u64, name.len())))
        .collect();
    let reserve = if quick_open == ReferenceQuickOpen::None {
        0
    } else {
        locator_reserve_width(&sizes)
    };

    let mut body = assemble_body(blocks, archive_flags, quick_open, reserve, false);
    refresh_main_crc(&mut body);
    body.out.extend_from_slice(&end_header(false));
    body.out
}

/// Assembles an archive from blocks and appends a data recovery record
/// over the bytes it just laid down, which is what `rar rr[N]` does to an
/// archive that already exists.
///
/// `existing_len` is the length of THAT archive, and it is the only input
/// the locator reserve is taken from - see
/// [`locator_reserve_width_rewrite`], which measured the difference from
/// the create path.
///
/// The record's geometry is the fork's rather than the reference's, so
/// the archive is not the reference's byte for byte; what it IS, and what
/// the caller owes, is an archive the reference recognises and verifies
/// (`rar t` prints `Testing the recovery record ... OK` over it). Three
/// things have to be right for that and all three are here: the main
/// header's recovery bit, the locator's second offset, and the record
/// sitting after the quick-open block and before the end header.
pub fn assemble_with_recovery(
    blocks: &[ReferenceBlock<'_>],
    archive_flags: u64,
    quick_open: ReferenceQuickOpen,
    recovery_percent: u64,
    existing_len: u64,
) -> Result<Vec<u8>> {
    let reserve = locator_reserve_width_rewrite(existing_len);
    let mut body = assemble_body(blocks, archive_flags, quick_open, reserve, true);

    // The locator's recovery offset is its LAST field, so it is found by
    // counting back from the end of the main header for the same reason
    // the quick-open one is.
    let recovery_pos = body.out.len();
    let at = body.main_start + locator_offset_position(body.main_len, reserve);
    patch_locator_field(
        &mut body.out,
        at,
        (recovery_pos - RAR5_SIGNATURE.len()) as u64,
        reserve,
    );
    refresh_main_crc(&mut body);

    // ORDER IS LOAD-BEARING: the record is built over the archive as it
    // stands at this line, so every byte before it must already be final.
    // Patching the main header afterwards would leave a record describing
    // bytes the archive no longer has, and the reference's `t` would
    // report the record as broken.
    super::write_recovery_service(&mut body.out, recovery_percent, None, 1)?;
    body.out.extend_from_slice(&end_header(false));
    Ok(body.out)
}

/// An archive assembled as far as its quick-open block, with the locator's
/// quick-open offset already patched and its CRC32 not yet refreshed.
struct Assembly {
    out: Vec<u8>,
    main_start: usize,
    main_len: usize,
}

/// The middle every assembly shares: main header, blocks, quick-open
/// block. `recovery` picks the main header with the two-field locator and
/// the recovery bit; the caller adds the record and the end header.
fn assemble_body(
    blocks: &[ReferenceBlock<'_>],
    archive_flags: u64,
    quick_open: ReferenceQuickOpen,
    reserve: usize,
    recovery: bool,
) -> Assembly {
    let mut out = RAR5_SIGNATURE.to_vec();
    let main_start = out.len();
    let main = if recovery {
        main_header_recovery(reserve, archive_flags | MHFL_RECOVERY)
    } else {
        main_header(reserve, archive_flags)
    };
    let main_len = main.len();
    out.extend_from_slice(&main);

    let mut cached: Vec<(usize, Vec<u8>)> = Vec::new();
    for block in blocks {
        let pos = out.len();
        if block.name.is_some() && caches(quick_open, block.data.len()) {
            cached.push((pos, block.header.clone()));
        }
        out.extend_from_slice(&block.header);
        out.extend_from_slice(block.data);
    }

    let quick_open_pos = out.len();
    if let Some(block) = quick_open_block(quick_open_pos, &cached) {
        out.extend_from_slice(&block);
        // On the recovery path the quick-open offset is the FIRST of two
        // fields, so it sits one whole reserve further back.
        let fields = if recovery { 2 } else { 1 };
        let at = main_start + main_len - fields * reserve;
        patch_locator_field(
            &mut out,
            at,
            (quick_open_pos - RAR5_SIGNATURE.len()) as u64,
            reserve,
        );
    }
    Assembly {
        out,
        main_start,
        main_len,
    }
}

/// Writes `value` over the `reserve` placeholder bytes at `at`.
fn patch_locator_field(out: &mut [u8], at: usize, value: u64, reserve: usize) {
    let mut patched = Vec::new();
    write_vint_padded(&mut patched, value, reserve);
    out[at..at + reserve].copy_from_slice(&patched);
}

/// Recomputes the main header's CRC32 over the bytes a patch just moved,
/// so it describes the header rather than the placeholder it was built
/// with. Recomputing when nothing was patched writes the same four bytes
/// back, which is why this is unconditional.
fn refresh_main_crc(body: &mut Assembly) {
    let (start, len) = (body.main_start, body.main_len);
    let crc = crc32(&body.out[start + 4..start + len]).to_le_bytes();
    body.out[start..start + 4].copy_from_slice(&crc);
}

/// Writes a stored archive in the reference's own byte layout.
pub fn write_reference_stored(
    members: &[ReferenceMember<'_>],
    hash: ReferenceHash,
    quick_open: ReferenceQuickOpen,
) -> Result<Vec<u8>> {
    let mut blocks = Vec::with_capacity(members.len());
    for member in members {
        blocks.push(ReferenceBlock {
            header: member_header(member, hash, ReferenceLayout::Create)?,
            data: member.data,
            name: Some(member.name),
        });
    }
    Ok(assemble(&blocks, 0, quick_open))
}

/// Bytes the reference holds back at the end of every volume but the
/// last, for the housekeeping it has not written yet.
///
/// Measured, and it is a CONSTANT rather than a computation: at `-v8k`
/// and `-v12k` a volume ends 9 bytes short of its size and at `-v20k` it
/// ends 8 short, and the difference is exactly the byte the quick-open
/// record's offset vint grows by in the larger volume. Reserve minus the
/// tail actually written is 82 in every case measured, including one
/// with no quick-open block at all (`-v4200b`, where the fragment falls
/// under the caching threshold and the shortfall is 74).
///
/// The unused bytes are then written as zeros, so the volume is exactly
/// the size asked for.
const VOLUME_TAIL_RESERVE: u64 = 82;

/// One member fragment as it landed in one volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceFragment {
    /// Index into the member list the set was written from.
    pub member: usize,
    /// How many of that member's bytes this volume holds.
    pub bytes: u64,
    /// Whether this is the member's first fragment.
    pub first: bool,
    /// Whether this is the member's last.
    pub last: bool,
}

/// A written volume set: the bytes, and where each member landed.
///
/// The layout is returned rather than inferred by reading the volumes
/// back, because the CALLER needs it for the progress lines - the
/// reference opens a member's line on the volume it starts in and closes
/// it on the volume it finishes in, and a front end that had to re-parse
/// its own output to find that out would be one parse away from getting
/// it wrong.
pub struct ReferenceVolumeSet {
    /// One buffer per volume, in order.
    pub volumes: Vec<Vec<u8>>,
    /// One entry per volume, listing the fragments it holds in order.
    pub layout: Vec<Vec<ReferenceFragment>>,
}

/// Writes a stored set split into volumes of `volume_size` bytes.
///
/// Every volume but the last is exactly `volume_size` long, padded with
/// zeros; the last is as long as it needs to be. The main header carries
/// the volume flag, and from the second volume on the volume number as
/// well; the end header of every volume but the last says another
/// follows.
pub fn write_reference_stored_volumes(
    members: &[ReferenceMember<'_>],
    hash: ReferenceHash,
    volume_size: u64,
    quick_open: ReferenceQuickOpen,
) -> Result<ReferenceVolumeSet> {
    if volume_size == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 volume size must be non-zero",
        ));
    }
    // The locator's estimate is over the WHOLE members, not over what
    // lands in this volume: measured on a three-part set, the last
    // volume holds 287 bytes and still reserves the width the whole
    // 24,576-byte member needs.
    let sizes: Vec<(u64, usize)> = members
        .iter()
        .map(|m| (m.data.len() as u64, m.name.len()))
        .collect();
    let reserve = if quick_open == ReferenceQuickOpen::None {
        0
    } else {
        locator_reserve_width(&sizes)
    };

    let mut volumes: Vec<Vec<u8>> = Vec::new();
    let mut layout: Vec<Vec<ReferenceFragment>> = Vec::new();
    let mut index = 0usize;
    let mut member = 0usize;
    let mut offset = 0usize;
    while member < members.len() {
        let archive_flags = if index == 0 {
            MHFL_VOLUME
        } else {
            MHFL_VOLUME | MHFL_VOLUME_NUMBER
        };
        let main = main_header_volume(reserve, archive_flags, index as u64);
        let mut out = RAR5_SIGNATURE.to_vec();
        let main_start = out.len();
        let main_len = main.len();
        out.extend_from_slice(&main);

        let budget = volume_size.saturating_sub(out.len() as u64 + VOLUME_TAIL_RESERVE);
        let mut used = 0u64;
        let mut cached: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut wrote_any = false;
        let mut here: Vec<ReferenceFragment> = Vec::new();
        while member < members.len() {
            let entry = &members[member];
            let left = entry.data.len() - offset;
            let head = offset > 0;
            // A first pass with the "not the last piece" header, because
            // the last piece's header is the longer of the two and a
            // fragment sized against the shorter one could not fit it.
            let probe = member_header_split(
                entry,
                hash,
                ReferenceLayout::Create,
                if head { Split::Middle } else { Split::Head },
                &entry.data[offset..offset + left.min(1)],
            )?;
            let room = budget.saturating_sub(used);
            if room <= probe.len() as u64 {
                break;
            }
            let take = ((room - probe.len() as u64) as usize).min(left);
            let split = match (head, take == left) {
                (false, true) => Split::Whole,
                (false, false) => Split::Head,
                (true, true) => Split::Tail,
                (true, false) => Split::Middle,
            };
            let fragment = &entry.data[offset..offset + take];
            let header =
                member_header_split(entry, hash, ReferenceLayout::Create, split, fragment)?;
            if used + header.len() as u64 + take as u64 > budget && take < left {
                break;
            }
            if caches(quick_open, fragment.len()) {
                cached.push((out.len(), header.clone()));
            }
            out.extend_from_slice(&header);
            out.extend_from_slice(fragment);
            here.push(ReferenceFragment {
                member,
                bytes: take as u64,
                first: !head,
                last: take == left,
            });
            used += header.len() as u64 + take as u64;
            wrote_any = true;
            offset += take;
            if offset == entry.data.len() {
                member += 1;
                offset = 0;
            } else {
                break;
            }
        }
        if !wrote_any {
            return Err(Error::InvalidHeader(
                "RAR 5 volume size leaves no room for a member header",
            ));
        }

        let quick_open_pos = out.len();
        if let Some(block) = quick_open_block(quick_open_pos, &cached) {
            out.extend_from_slice(&block);
            let at = main_start + locator_offset_position(main_len, reserve);
            let mut patched = Vec::new();
            write_vint_padded(
                &mut patched,
                (quick_open_pos - RAR5_SIGNATURE.len()) as u64,
                reserve,
            );
            out[at..at + reserve].copy_from_slice(&patched);
            let crc = crc32(&out[main_start + 4..main_start + main_len]).to_le_bytes();
            out[main_start..main_start + 4].copy_from_slice(&crc);
        }
        let last = member >= members.len();
        out.extend_from_slice(&end_header(!last));
        if !last {
            out.resize(volume_size as usize, 0);
        }
        volumes.push(out);
        layout.push(here);
        index += 1;
    }
    Ok(ReferenceVolumeSet { volumes, layout })
}

/// The main header of one volume: the locator, the volume flag and, from
/// the second volume on, the volume number.
fn main_header_volume(reserve: usize, archive_flags: u64, number: u64) -> Vec<u8> {
    let extra = locator_extra(reserve);

    let mut specific = Vec::new();
    write_vint(&mut specific, archive_flags);
    if archive_flags & MHFL_VOLUME_NUMBER != 0 {
        write_vint(&mut specific, number);
    }
    block_image(
        HEAD_MAIN,
        if extra.is_empty() { HFL_SKIP } else { HFL_EXTRA | HFL_SKIP },
        None,
        1,
        &specific,
        &extra,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member<'a>(name: &'a str, data: &'a [u8]) -> ReferenceMember<'a> {
        ReferenceMember {
            name,
            data,
            mtime: Some((1_000_000_000, 0)),
            attributes: 0o100_644,
            host_os: 1,
            is_dir: false,
        }
    }

    /// The whole archive, byte for byte, as `rar 7.23` writes it.
    ///
    /// Captured from the reference on the dev Mac, 4 Sep 2026:
    ///
    ///     printf 'hello\n' > hello.txt && touch -t 200109082146.40 hello.txt
    ///     rar a -y -m0 -inul arc.rar hello.txt
    ///
    /// It is a golden fixture rather than a property check on purpose:
    /// the point of this module is the bytes, and a test that only says
    /// "it parses" would pass through every layout change that breaks
    /// the conformance table.
    #[test]
    fn one_stored_member_matches_the_reference_byte_for_byte() {
        let out = write_reference_stored(
            &[member("hello.txt", b"hello\n")],
            ReferenceHash::Crc32,
            ReferenceQuickOpen::Auto,
        )
        .expect("writes");
        let expected = concat!(
            // signature
            "526172211a070100",
            // main header: locator with a three-byte quick-open reserve
            "3392b5e50a01050600050101808000",
            // hello.txt: two-byte sizes, whole-second mtime in the
            // header's own field, CRC32, two-byte compression info
            "5b3822231f02028600068600a4830200ca9a3b20303a368000010968656c6c6f2e747874",
            // the member's six bytes
            "68656c6c6f0a",
            // end header, skip-if-unknown set
            "1d77565103050400",
        )
        .to_owned();
        assert_eq!(hex(&out), expected);
    }

    /// The two crossings [`locator_reserve_width_rewrite`] predicted,
    /// checked against the reference on the dev Mac, 4 Sep 2026.
    ///
    /// The archives either side of each crossing were built with
    /// `rar a -m0` over a single `s.bin` and then handed to `rar rr5`,
    /// and the locator's record size was read back out of the rebuilt
    /// main header. A formula that only fitted the shapes it was derived
    /// from would not have survived either boundary.
    #[test]
    fn the_rewrite_reserve_crosses_where_the_reference_crosses_it() {
        assert_eq!(locator_reserve_width_rewrite(510), 3);
        assert_eq!(locator_reserve_width_rewrite(511), 4);
        assert_eq!(locator_reserve_width_rewrite(65_534), 4);
        assert_eq!(locator_reserve_width_rewrite(65_535), 5);
    }

    /// It is NOT the create path's estimate, and this is the shape that
    /// separates them: one 300-byte member under a 100-character name.
    /// The reference reserves four bytes when it CREATES that archive
    /// and three when `rr` rewrites the 459-byte file it produced.
    #[test]
    fn the_rewrite_reserve_is_not_the_create_estimate() {
        assert_eq!(locator_reserve_width(&[(300, 100)]), 4);
        assert_eq!(locator_reserve_width_rewrite(459), 3);
    }

    /// The three things `rr` moves in the main header, in the bytes the
    /// reference wrote: the archive's recovery flag, the locator's
    /// two-field flags, and a record long enough for both offsets.
    #[test]
    fn the_recovery_main_header_carries_both_locator_offsets() {
        let main = main_header_recovery(3, MHFL_RECOVERY);
        // crc32(4) | header size(1) | type(1) flags(1) extra size(1)
        // archive flags(1) | record size(1) type(1) locator flags(1)
        // quick-open(3) recovery(3)
        assert_eq!(main.len(), 4 + 1 + 4 + 1 + 8);
        let header = &main[5..];
        assert_eq!(header[0], HEAD_MAIN as u8);
        assert_eq!(header[1] as u64, HFL_EXTRA | HFL_SKIP);
        assert_eq!(header[3] as u64, MHFL_RECOVERY);
        // The extra area: one record of eight bytes, the locator, whose
        // flags say both offsets are present and are zero for now.
        assert_eq!(header[4], 8);
        assert_eq!(header[5] as u64, MHEXTRA_LOCATOR);
        assert_eq!(
            header[6] as u64,
            MHEXTRA_LOCATOR_QUICK_OPEN | MHEXTRA_LOCATOR_RECOVERY
        );
        assert_eq!(&header[7..13], &[0x80, 0x80, 0x00, 0x80, 0x80, 0x00]);
    }

    #[test]
    fn a_member_over_four_kilobytes_earns_a_quick_open_block() {
        let big = vec![7u8; 4097];
        let small = vec![7u8; 4096];
        let with = write_reference_stored(
            &[member("big.bin", &big)],
            ReferenceHash::Crc32,
            ReferenceQuickOpen::Auto,
        )
        .expect("writes");
        let without = write_reference_stored(
            &[member("small.bin", &small)],
            ReferenceHash::Crc32,
            ReferenceQuickOpen::Auto,
        )
        .expect("writes");
        let forced = write_reference_stored(
            &[member("small.bin", &small)],
            ReferenceHash::Crc32,
            ReferenceQuickOpen::All,
        )
        .expect("writes");
        let refused = write_reference_stored(
            &[member("big.bin", &big)],
            ReferenceHash::Crc32,
            ReferenceQuickOpen::None,
        )
        .expect("writes");
        assert!(find(&forced, b"QO"), "-qo+ caches every member");
        assert!(!find(&refused, b"QO"), "-qo- caches none");
        assert!(find(&with, b"QO"), "4097 bytes must be cached");
        assert!(!find(&without, b"QO"), "4096 bytes must not be");
    }

    /// The reserve is not the width the value needs, so a test that only
    /// round-tripped would not see it move. These three are the measured
    /// crossings named in [`locator_reserve_width`]'s own docs.
    #[test]
    fn the_locator_reserve_crosses_where_the_reference_crosses() {
        assert_eq!(locator_reserve_width(&[(463, 5)]), 3);
        assert_eq!(locator_reserve_width(&[(464, 5)]), 4);
        assert_eq!(locator_reserve_width(&[(367, 37)]), 3);
        assert_eq!(locator_reserve_width(&[(368, 37)]), 4);
        assert_eq!(locator_reserve_width(&[(65_487, 5)]), 4);
        assert_eq!(locator_reserve_width(&[(65_488, 5)]), 5);
    }

    #[test]
    fn a_rewrite_moves_a_whole_second_time_into_an_htime_record() {
        // `rar rn` re-emits every header and puts the time in an HTIME
        // record with flags 3, where `rar a` would have used the
        // header's own field. Measured on the `rename-member` row.
        let created = member_header(&member("a.txt", b"x"), ReferenceHash::Crc32, ReferenceLayout::Create)
            .expect("header");
        let rewritten =
            member_header(&member("a.txt", b"x"), ReferenceHash::Crc32, ReferenceLayout::Rewrite)
                .expect("header");
        assert!(rewritten.len() > created.len());
        assert!(find(&rewritten, &[0x06, 0x03, 0x03]), "HTIME record");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn find(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
