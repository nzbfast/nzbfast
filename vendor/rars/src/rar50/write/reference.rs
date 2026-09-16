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
//! * The packed size, unpacked size and compression information fields of a FILE header are
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

use std::io::{Read, Seek, SeekFrom, Write};

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

const BLOCK_TYPE_MAIN: u64 = 1;
const BLOCK_TYPE_FILE: u64 = 2;
const BLOCK_TYPE_SERVICE: u64 = 3;
const BLOCK_TYPE_END_OF_ARCHIVE: u64 = 5;

const BLOCK_HAS_EXTRA_AREA: u64 = 0x0001;
const BLOCK_HAS_DATA_AREA: u64 = 0x0002;
const BLOCK_SKIP_IF_UNKNOWN: u64 = 0x0004;
const BLOCK_CONTINUED_FROM_PREVIOUS_VOLUME: u64 = 0x0008;
const BLOCK_CONTINUES_IN_NEXT_VOLUME: u64 = 0x0010;

const FILE_IS_DIRECTORY: u64 = 0x0001;
const FILE_HAS_UNIX_MTIME: u64 = 0x0002;
const FILE_HAS_CRC32: u64 = 0x0004;

const MAIN_EXTRA_LOCATOR: u64 = 0x01;
const LOCATOR_HAS_QUICK_OPEN_OFFSET: u64 = 0x01;
const LOCATOR_HAS_RECOVERY_RECORD_OFFSET: u64 = 0x02;
const FILE_EXTRA_HASH: u64 = 0x02;
const FILE_EXTRA_TIME: u64 = 0x03;
const TIME_RECORD_UNIX_FORMAT: u64 = 0x01;
const TIME_RECORD_HAS_MTIME: u64 = 0x02;
const TIME_RECORD_UNIX_NANOSECONDS: u64 = 0x10;

/// The host-OS byte a member written on Windows carries.
const HOST_OS_WINDOWS: u64 = 0;

/// Unix epoch as a Windows FILETIME: 100-nanosecond ticks from
/// 1601-01-01 to 1970-01-01.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

const ARCHIVE_IS_VOLUME: u64 = 0x0001;
const ARCHIVE_HAS_VOLUME_NUMBER: u64 = 0x0002;
/// The main header's "this archive carries a recovery record" bit, which
/// `rr` sets and `a -rr` sets for the same reason.
const ARCHIVE_HAS_RECOVERY_RECORD: u64 = 0x0008;
const END_OF_ARCHIVE_NOT_LAST_VOLUME: u64 = 0x0001;

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
    // AT LEAST `width` bytes, never exactly: a value that needs more takes
    // more, as the reference's does. Until 14 Sep 2026 this wrote exactly
    // `width` and silently dropped the high bits, so a quick-open block
    // whose data ran past 16,383 bytes (about 190 cached headers under
    // `-qo+`, or a few hundred members over 4 KiB under the default) carried
    // a data size of `len & 0x3fff`, and the reference unrar answered
    // "Corrupt header is found" on `t` and `x` while `l` still listed the
    // members. Found by tools/rarbench.py's create-small-m0 leg in nzbfast.
    let width = width.max(vint_width(value));
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
/// ```text
/// estimate = sum over members of (data length + 33 + 3 * name length)
/// width    = vint_width(estimate << 12)
/// ```
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
///
/// `host_os` decides the FORM, and it is the member's own byte rather
/// than the platform this is running on - measured 16 Sep 2026 on an
/// x86-64 Windows 11 box against rar 7.23, which rewrote a Unix-host archive
/// (`rar rn`, `rar d`, and `rar a` of a second member onto it) leaving
/// every copied member at `host=1` with the Unix-format record, and gave
/// only the member it added from the Windows disk the Windows form. So a
/// `cfg!(windows)` here would have written the wrong record for exactly
/// the archives that cross platforms.
fn htime_record(
    mtime: Option<(u32, u32)>,
    layout: ReferenceLayout,
    host_os: u64,
) -> Option<Vec<u8>> {
    let (secs, nanos) = mtime?;
    if host_os == HOST_OS_WINDOWS {
        // A Windows member carries a FILETIME - 100-nanosecond ticks
        // from 1601 - and carries it in the record ALWAYS: the header's
        // own field is Unix seconds by definition and cannot hold one,
        // so the Create/Rewrite split above does not exist on this side.
        // Measured on the box: `rar a -m0` of a whole-second file, of a
        // sub-second one, of a directory, of a `-htb` member, and `rn` /
        // `d` / `ch` / `k` over an archive it wrote, all give the same
        // eleven-byte record with flags 0x0002 and no header field.
        let mut body = Vec::new();
        write_vint(&mut body, TIME_RECORD_HAS_MTIME);
        let ticks = u64::from(secs) * 10_000_000 + u64::from(nanos) / 100;
        body.extend_from_slice(&(ticks + FILETIME_UNIX_EPOCH).to_le_bytes());
        return Some(extra_record(FILE_EXTRA_TIME, &body));
    }
    if nanos == 0 && layout == ReferenceLayout::Create {
        // A whole second goes in the header's own mtime field instead,
        // and the reference writes no record at all. Measured: `touch -t`
        // a file and the extra area disappears. On the REWRITE path it
        // does the opposite - see [`ReferenceLayout`].
        return None;
    }
    let mut body = Vec::new();
    let mut flags = TIME_RECORD_UNIX_FORMAT | TIME_RECORD_HAS_MTIME;
    if nanos != 0 {
        flags |= TIME_RECORD_UNIX_NANOSECONDS;
    }
    write_vint(&mut body, flags);
    body.extend_from_slice(&secs.to_le_bytes());
    if nanos != 0 {
        body.extend_from_slice(&nanos.to_le_bytes());
    }
    Some(extra_record(FILE_EXTRA_TIME, &body))
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
    // EVERY fragment carries a checksum, and the reference does not put
    // the same one on each: measured on a three-volume set, the first two
    // headers carry the CRC32 of their OWN fragment and the last carries
    // the CRC32 of the whole member. So a reader that has only volume 2
    // can still check what it has, and a reader that reaches the end can
    // check the join.
    let digest = (!member.is_dir).then(|| {
        let covered: &[u8] = if split == Split::Whole || split == Split::Tail {
            member.data
        } else {
            fragment_bytes
        };
        Digest::of(hash, covered)
    });
    header_image(
        &MemberFields {
            name: member.name,
            unpacked: member.data.len() as u64,
            mtime: member.mtime,
            attributes: member.attributes,
            host_os: member.host_os,
            is_dir: member.is_dir,
        },
        digest,
        layout,
        split,
        fragment_bytes.len() as u64,
    )
}

/// What a member's header says about it, apart from its bytes: the
/// fields [`ReferenceMember`] and [`ReferenceStreamedMember`] share.
struct MemberFields<'a> {
    name: &'a str,
    unpacked: u64,
    mtime: Option<(u32, u32)>,
    attributes: u64,
    host_os: u64,
    is_dir: bool,
}

/// A member's checksum, computed by whoever holds its bytes: the slice
/// writers from the slice, the streamed writer as the bytes pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Digest {
    Crc32(u32),
    Blake2sp([u8; 32]),
}

impl Digest {
    fn of(hash: ReferenceHash, bytes: &[u8]) -> Self {
        match hash {
            ReferenceHash::Crc32 => Digest::Crc32(crc32(bytes)),
            ReferenceHash::Blake2sp => Digest::Blake2sp(blake2sp::hash(bytes)),
        }
    }

    /// A digest of the right KIND and no value: a header built with it is
    /// exactly as long as the one built with the real digest, which is what
    /// lets the streamed writer lay it down first and patch it in place.
    fn placeholder(hash: ReferenceHash) -> Self {
        match hash {
            ReferenceHash::Crc32 => Digest::Crc32(0),
            ReferenceHash::Blake2sp => Digest::Blake2sp([0; 32]),
        }
    }
}

/// One member's header image from its fields and its checksum, `None`
/// for a directory.
fn header_image(
    member: &MemberFields<'_>,
    digest: Option<Digest>,
    layout: ReferenceLayout,
    split: Split,
    fragment: u64,
) -> Result<Vec<u8>> {
    if member.name.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 file name is empty"));
    }
    let name = member.name.as_bytes();
    let mut extra = Vec::new();
    let mut file_flags = 0;
    let mut crc = None;

    if member.is_dir {
        file_flags |= FILE_IS_DIRECTORY;
    } else {
        match digest {
            Some(Digest::Crc32(value)) => {
                file_flags |= FILE_HAS_CRC32;
                crc = Some(value);
            }
            Some(Digest::Blake2sp(value)) => {
                let mut body = vec![0];
                body.extend_from_slice(&value);
                extra.extend_from_slice(&extra_record(FILE_EXTRA_HASH, &body));
            }
            None => {
                return Err(Error::InvalidHeader(
                    "RAR 5 reference file header needs its checksum",
                ))
            }
        }
    }

    let mtime_field = match member.mtime {
        // The header's own field is Unix seconds, so a Windows member
        // never uses it: its time goes in the record, in FILETIME form.
        Some((secs, 0))
            if layout == ReferenceLayout::Create && member.host_os != HOST_OS_WINDOWS =>
        {
            file_flags |= FILE_HAS_UNIX_MTIME;
            Some(secs)
        }
        _ => None,
    };
    if let Some(record) = htime_record(member.mtime, layout, member.host_os) {
        extra.extend_from_slice(&record);
    }

    let unpacked = member.unpacked;
    // Sizes get a two-byte minimum wherever the reference laid the header
    // out BEFORE it knew them, which is the create path: `rar a` streams a
    // member it is still reading, so it reserves two bytes for a size it
    // cannot know yet and pads. A REWRITE has the member in hand - it is
    // copying one whose header it has already parsed - so it writes the
    // natural width and pads nothing. A directory's sizes are known to be
    // zero either way and take one. The compression info is always two.
    //
    // Measured against rar 7.23 on this Mac, 16 Sep 2026, `rar a -m0` then
    // `rar rn` over the same member at five sizes: the rewrite header is 29
    // bytes at 6 and at 127 (one-byte sizes) and 31 at 128 (two-byte), so
    // the crossover is the vint's own and not a minimum; at 20,000 both
    // paths take three. The create header is 27 bytes at 6, 127 AND 128,
    // which is the padding. Reachable only below 128 bytes, which is why
    // no conformance row sees it: every rewrite row's member clears that.
    let size_width = if member.is_dir {
        1
    } else if layout == ReferenceLayout::Rewrite {
        vint_width(unpacked)
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

    let mut flags = BLOCK_HAS_DATA_AREA;
    if !extra.is_empty() {
        flags |= BLOCK_HAS_EXTRA_AREA;
    }
    if matches!(split, Split::Tail | Split::Middle) {
        flags |= BLOCK_CONTINUED_FROM_PREVIOUS_VOLUME;
    }
    if matches!(split, Split::Head | Split::Middle) {
        flags |= BLOCK_CONTINUES_IN_NEXT_VOLUME;
    }

    Ok(block_image(
        BLOCK_TYPE_FILE,
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
    if archive_flags & ARCHIVE_HAS_VOLUME_NUMBER != 0 {
        write_vint(&mut specific, 0);
    }
    block_image(
        BLOCK_TYPE_MAIN,
        if extra.is_empty() {
            BLOCK_SKIP_IF_UNKNOWN
        } else {
            BLOCK_HAS_EXTRA_AREA | BLOCK_SKIP_IF_UNKNOWN
        },
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
    write_vint(&mut record, LOCATOR_HAS_QUICK_OPEN_OFFSET);
    write_vint_padded(&mut record, 0, reserve);
    extra_record(MAIN_EXTRA_LOCATOR, &record)
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
        LOCATOR_HAS_QUICK_OPEN_OFFSET | LOCATOR_HAS_RECOVERY_RECORD_OFFSET,
    );
    write_vint_padded(&mut record, 0, reserve);
    write_vint_padded(&mut record, 0, reserve);
    let extra = extra_record(MAIN_EXTRA_LOCATOR, &record);

    let mut specific = Vec::new();
    write_vint(&mut specific, archive_flags);
    block_image(
        BLOCK_TYPE_MAIN,
        BLOCK_HAS_EXTRA_AREA | BLOCK_SKIP_IF_UNKNOWN,
        None,
        1,
        &specific,
        &extra,
    )
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
/// ```text
/// width = vint_width((archive length + 1) << 12)
/// ```
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
        if next_volume { END_OF_ARCHIVE_NOT_LAST_VOLUME } else { 0 },
    );
    block_image(BLOCK_TYPE_END_OF_ARCHIVE, BLOCK_SKIP_IF_UNKNOWN, None, 1, &specific, &[])
}

/// The quick-open service block, or nothing when no member earns one.
///
/// `cached` is (offset of the member's block inside the archive, that
/// block's header image). The record's own offset is the DISTANCE back
/// from the quick-open block to the cached header, and the record's CRC32
/// covers the size vint together with the body it introduces.
/// The host-OS byte a SERVICE header carries, and it is the WRITER's
/// platform rather than anything about the archive.
///
/// This is the OPPOSITE of the rule a member's own byte and its HTIME
/// record follow - [`htime_record`] takes the member's, and says why a
/// `cfg!(windows)` there would be wrong for an archive that crosses
/// platforms. A service block is not a member: there is no file behind
/// it to inherit from, so the platform doing the writing is all there
/// is to follow.
///
/// Measured on the x86-64 Windows 11 box, 16 Sep 2026, against rar 7.23.
/// An archive built on macOS carries `host=1` in its quick-open block;
/// the Windows reference rewriting that same archive - `rn`, and `a` of a
/// second member from the Windows disk - regenerates the block with
/// `host=0` while `lt` still reports `text.txt` as `Host OS: Unix`.
///
/// ONE CONSTANT FOR EVERY SERVICE WRITER IN THE CRATE, and that is the
/// point rather than tidiness. [`comment_header`] followed this rule from 4 Sep 2026
/// and [`quick_open_block`] wrote a constant `1` beside it until 16 Sep,
/// which is invisible on a Unix box - `1` IS the Unix answer - and was
/// the whole of nineteen `[files]` divergences on the windows `rar`
/// conformance leg. A macOS test cannot tell a hardcoded `1` from this
/// rule; what it CAN tell is the two writers disagreeing, which is how
/// that bug would arrive again, and the windows leg is the backstop for
/// the rest.
///
/// It is `pub(super)` because the GENERAL writer in [`super`] writes
/// service blocks too - `CMT`, `QO`, an arbitrary service beside a
/// member, `RR`, and the encrypted spellings of those - and wrote a
/// hardcoded `0` in every one of them, the WINDOWS answer, so the same
/// bug with the platforms swapped, until 16 Sep 2026. No conformance row saw it: the `a` rows this
/// module serves never reach that writer, and a Mac cannot tell a
/// hardcoded `0` from anything by observation either.
///
/// THE UNIX HALF IS MEASURED, on the dev Mac the same day against the
/// same rar 7.23, which is what extends the rule past the two blocks
/// the Windows box measured: `rar a -m0 -zc.txt`, `-qo+` and `-rr10`
/// each write `host=1`, in `CMT`, `QO` and `RR` alike. `RR` is a
/// service block on the same footing as the other two and nothing about
/// it is special, so the general writer's recovery blocks follow this
/// constant as well.
pub(super) const SERVICE_HOST_OS: u64 = if cfg!(windows) { 0 } else { 1 };

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
    write_vint(&mut specific, SERVICE_HOST_OS);
    write_vint(&mut specific, 2);
    specific.extend_from_slice(b"QO");

    let mut out = block_image(
        BLOCK_TYPE_SERVICE,
        BLOCK_HAS_DATA_AREA | BLOCK_SKIP_IF_UNKNOWN,
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
    write_vint(&mut specific, FILE_HAS_CRC32);
    write_vint_padded(&mut specific, data.len() as u64, 2);
    write_vint(&mut specific, 0);
    specific.extend_from_slice(&crc32(data).to_le_bytes());
    write_vint_padded(&mut specific, 0, 2);
    write_vint(&mut specific, SERVICE_HOST_OS);
    write_vint(&mut specific, 3);
    specific.extend_from_slice(b"CMT");
    block_image(
        BLOCK_TYPE_SERVICE,
        BLOCK_HAS_DATA_AREA,
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
    super::write_recovery_service(&mut body.out, recovery_percent, None, 1, false)?;
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
        main_header_recovery(reserve, archive_flags | ARCHIVE_HAS_RECOVERY_RECORD)
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

/// One member of a reference-layout archive whose bytes are read from
/// `source` as they are written, rather than held.
pub struct ReferenceStreamedMember<'a, R: Read> {
    /// The archived name, `/`-separated.
    pub name: &'a str,
    /// How many bytes `source` holds. Ignored for a directory.
    pub size: u64,
    /// Unix mtime as (whole seconds, nanoseconds).
    pub mtime: Option<(u32, u32)>,
    /// The member's attribute word, host-OS shaped.
    pub attributes: u64,
    /// 0 Windows, 1 Unix.
    pub host_os: u64,
    /// Whether this member is a directory entry.
    pub is_dir: bool,
    /// Where the member's bytes come from. Read for exactly `size` bytes
    /// and never for a directory.
    pub source: R,
}

/// [`write_reference_stored`] into a sink, reading each member from its
/// source as it goes: the same bytes, without holding the members or the
/// archive.
pub fn write_reference_stored_streamed<R: Read + Send, W: Write + Seek>(
    members: &mut [ReferenceStreamedMember<'_, R>],
    hash: ReferenceHash,
    quick_open: ReferenceQuickOpen,
    sink: &mut W,
) -> Result<u64> {
    assemble_streamed(&[], members, hash, 0, quick_open, sink)
}

/// A member at most this long is read whole into one reused buffer,
/// checksummed and written on the calling thread; a longer one goes
/// through [`copy_member`], this many bytes to a chunk.
const STREAM_CHUNK: usize = 4 << 20;

/// Chunks in circulation between [`copy_member`]'s three stages, which is
/// the whole of what a large member costs in memory.
const STREAM_CHUNKS_IN_FLIGHT: usize = 4;

/// [`assemble`] into a sink: `prefix` blocks as they stand (an archive
/// comment, the members of an archive being added to), then `members`
/// read from their sources. Returns the bytes written.
///
/// **The bytes are [`assemble`]'s, and a test holds them there.** Nothing
/// in the layout needs a member's bytes except its checksum, and a
/// checksum is a fixed-width field, so a large member's header is laid
/// down with a placeholder, the data is copied behind it, and the header
/// is written again in place once the copy has computed the real one.
/// The locator's quick-open offset is patched the same way at the end.
/// What is held is every cached HEADER image (for the quick-open block),
/// one small member at a time, and [`STREAM_CHUNKS_IN_FLIGHT`] chunks of a
/// large one: tens of megabytes where [`write_reference_stored`] held the
/// members and the archive, twice the input.
///
/// Hence `Seek` on the sink. A pipe cannot take a stored reference archive
/// this way, and neither can the reference's own writer, which also
/// patches its locator.
pub fn assemble_streamed<R: Read + Send, W: Write + Seek>(
    prefix: &[ReferenceBlock<'_>],
    members: &mut [ReferenceStreamedMember<'_, R>],
    hash: ReferenceHash,
    archive_flags: u64,
    quick_open: ReferenceQuickOpen,
    sink: &mut W,
) -> Result<u64> {
    let sizes: Vec<(u64, usize)> = prefix
        .iter()
        .filter_map(|b| b.name.map(|name| (b.data.len() as u64, name.len())))
        .chain(
            members
                .iter()
                .map(|m| (if m.is_dir { 0 } else { m.size }, m.name.len())),
        )
        .collect();
    let reserve = if quick_open == ReferenceQuickOpen::None {
        0
    } else {
        locator_reserve_width(&sizes)
    };

    let start = sink.stream_position()?;
    let mut main = main_header(reserve, archive_flags);
    sink.write_all(RAR5_SIGNATURE)?;
    sink.write_all(&main)?;
    let mut pos = (RAR5_SIGNATURE.len() + main.len()) as u64;

    let mut cached: Vec<(usize, Vec<u8>)> = Vec::new();
    for block in prefix {
        if block.name.is_some() && caches(quick_open, block.data.len()) {
            cached.push((offset(pos)?, block.header.clone()));
        }
        sink.write_all(&block.header)?;
        sink.write_all(block.data)?;
        pos += (block.header.len() + block.data.len()) as u64;
    }

    let mut small = Vec::new();
    for member in members.iter_mut() {
        let data_len = if member.is_dir { 0 } else { member.size };
        let fields = MemberFields {
            name: member.name,
            unpacked: data_len,
            mtime: member.mtime,
            attributes: member.attributes,
            host_os: member.host_os,
            is_dir: member.is_dir,
        };
        let whole = |digest| header_image(&fields, digest, ReferenceLayout::Create, Split::Whole, data_len);
        let header = if member.is_dir {
            let header = whole(None)?;
            sink.write_all(&header)?;
            header
        } else if data_len <= STREAM_CHUNK as u64 {
            small.resize(data_len as usize, 0);
            fill(&mut member.source, &mut small)?;
            let header = whole(Some(Digest::of(hash, &small)))?;
            sink.write_all(&header)?;
            sink.write_all(&small)?;
            header
        } else {
            let placeholder = whole(Some(Digest::placeholder(hash)))?;
            sink.write_all(&placeholder)?;
            let digest = copy_member(&mut member.source, data_len, hash, sink)?;
            let header = whole(Some(digest))?;
            if header.len() != placeholder.len() {
                return Err(Error::InvalidHeader(
                    "RAR 5 streamed header changed length when its checksum was filled in",
                ));
            }
            let end = start + pos + header.len() as u64 + data_len;
            sink.seek(SeekFrom::Start(start + pos))?;
            sink.write_all(&header)?;
            sink.seek(SeekFrom::Start(end))?;
            header
        };
        if caches(quick_open, usize::try_from(data_len).unwrap_or(usize::MAX)) {
            cached.push((offset(pos)?, header.clone()));
        }
        pos += header.len() as u64 + data_len;
    }

    let quick_open_pos = offset(pos)?;
    let mut tail = Vec::new();
    let mut patched = false;
    if let Some(block) = quick_open_block(quick_open_pos, &cached) {
        tail.extend_from_slice(&block);
        let at = locator_offset_position(main.len(), reserve);
        let mut field = Vec::new();
        write_vint_padded(
            &mut field,
            (quick_open_pos - RAR5_SIGNATURE.len()) as u64,
            reserve,
        );
        if field.len() != reserve {
            return Err(Error::InvalidHeader(
                "RAR 5 quick-open offset outgrew the locator's reserve",
            ));
        }
        main[at..].copy_from_slice(&field);
        let crc = crc32(&main[4..]).to_le_bytes();
        main[..4].copy_from_slice(&crc);
        patched = true;
    }
    tail.extend_from_slice(&end_header(false));
    sink.write_all(&tail)?;
    let total = pos + tail.len() as u64;
    if patched {
        sink.seek(SeekFrom::Start(start + RAR5_SIGNATURE.len() as u64))?;
        sink.write_all(&main)?;
        sink.seek(SeekFrom::Start(start + total))?;
    }
    sink.flush()?;
    Ok(total)
}

/// An archive offset as the quick-open block's arithmetic takes it.
fn offset(pos: u64) -> Result<usize> {
    usize::try_from(pos)
        .map_err(|_| Error::InvalidHeader("RAR 5 archive exceeds this platform's address space"))
}

/// Fills `out` from `source`, refusing a source that ends first.
fn fill<R: Read + ?Sized>(source: &mut R, out: &mut [u8]) -> Result<()> {
    let mut at = 0;
    while at < out.len() {
        match source.read(&mut out[at..]) {
            Ok(0) => {
                return Err(Error::InvalidHeader(
                    "RAR 5 streamed member ended before its declared size",
                ))
            }
            Ok(read) => at += read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

/// A checksum being computed over bytes as they pass.
enum Running {
    Crc32(crc32fast::Hasher),
    Blake2sp(Box<blake2sp::Hasher>),
}

impl Running {
    fn new(hash: ReferenceHash) -> Self {
        match hash {
            ReferenceHash::Crc32 => Running::Crc32(crc32fast::Hasher::new()),
            ReferenceHash::Blake2sp => Running::Blake2sp(Box::new(blake2sp::Hasher::new())),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Running::Crc32(hasher) => hasher.update(bytes),
            Running::Blake2sp(hasher) => hasher.update(bytes),
        }
    }

    fn finish(self) -> Digest {
        match self {
            Running::Crc32(hasher) => Digest::Crc32(hasher.finalize()),
            Running::Blake2sp(hasher) => Digest::Blake2sp(hasher.finalize()),
        }
    }
}

/// Copies `size` bytes of a large member from `source` to `sink` and
/// returns their checksum.
///
/// Three stages on three threads - read, checksum, write - handing a small
/// ring of chunks along, so the read's copy out of the page cache, the
/// checksum and the write's copy back in run at the same time rather than
/// one after another. Measured against a single loop doing all three on
/// the 14 Sep 2026 rarbench corpus: see RARFAST-BENCH in nzbfast's
/// research/ for the round.
fn copy_member<R: Read + Send, W: Write>(
    source: &mut R,
    size: u64,
    hash: ReferenceHash,
    sink: &mut W,
) -> Result<Digest> {
    use std::sync::mpsc::{channel, sync_channel};
    std::thread::scope(|scope| -> Result<Digest> {
        let (free_tx, free_rx) = channel::<Vec<u8>>();
        let (read_tx, read_rx) = sync_channel::<Result<(Vec<u8>, usize)>>(STREAM_CHUNKS_IN_FLIGHT);
        let (hashed_tx, hashed_rx) = sync_channel::<(Vec<u8>, usize)>(STREAM_CHUNKS_IN_FLIGHT);
        for _ in 0..STREAM_CHUNKS_IN_FLIGHT {
            free_tx
                .send(vec![0u8; STREAM_CHUNK])
                .map_err(|_| Error::InvalidHeader("RAR 5 streamed copy lost its buffers"))?;
        }
        scope.spawn(move || {
            let mut left = size;
            while left > 0 {
                let Ok(mut buffer) = free_rx.recv() else {
                    return;
                };
                let want = STREAM_CHUNK.min(usize::try_from(left).unwrap_or(usize::MAX));
                let piece = fill(source, &mut buffer[..want]).map(|()| (buffer, want));
                let failed = piece.is_err();
                if read_tx.send(piece).is_err() || failed {
                    return;
                }
                left -= want as u64;
            }
        });
        let checksum = scope.spawn(move || -> Result<Digest> {
            let mut running = Running::new(hash);
            for piece in read_rx {
                let (buffer, len) = piece?;
                running.update(&buffer[..len]);
                if hashed_tx.send((buffer, len)).is_err() {
                    break;
                }
            }
            Ok(running.finish())
        });
        let mut written = 0u64;
        let mut failure = None;
        for (buffer, len) in hashed_rx.iter() {
            if let Err(err) = sink.write_all(&buffer[..len]) {
                failure = Some(err);
                break;
            }
            written += len as u64;
            // The reader is gone once it has read the last chunk, so a
            // buffer with nowhere to go is not an error.
            let _ = free_tx.send(buffer);
        }
        // Hang up before joining, so a stage blocked on either channel
        // wakes and ends rather than waiting for a writer that has left.
        drop(hashed_rx);
        drop(free_tx);
        let digest = checksum
            .join()
            .map_err(|_| Error::InvalidHeader("RAR 5 streamed checksum stage panicked"))?;
        if let Some(err) = failure {
            return Err(err.into());
        }
        let digest = digest?;
        if written != size {
            return Err(Error::InvalidHeader(
                "RAR 5 streamed member ended before its declared size",
            ));
        }
        Ok(digest)
    })
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

/// What that reserve grows by when the volume's members are WINDOWS
/// members.
///
/// Measured 16 Sep 2026 against rar 7.23, `rar a -m0 -v12k` over a
/// 24,576-byte `rand.bin`, reading the first volume's own bytes on each
/// side. Windows: signature 8 + main header 16 + file header 43 +
/// payload 12,133 = 12,200 of 12,288, so 88 held back. macOS: 8 + 16 +
/// 37 + 12,145 = 12,206, so 82. So the reference holds back six more on
/// Windows, and the payload moves by twelve - that six twice, once in
/// the member's own header and once in the copy of it the quick-open
/// block carries, which is what the reserve is holding room for.
///
/// WHERE THE SIX COMES FROM, and it is three terms rather than one:
/// +12 for the TIME extra record and the extra-area-size vint a Windows
/// member carries (see [`htime_record`]), -4 for the header's own
/// Unix-seconds field it then does not use, and -2 because this member's
/// Windows attribute word (0x20, one vint byte) is shorter than its Unix
/// mode (0o100644, three). THE LAST TERM IS A PROPERTY OF THE VALUE, not
/// of the platform, so six is not a law: whether the reference computes
/// this per member or simply holds two constants is not settled by this
/// measurement, and only the two numbers above are. What is pinned
/// against drift is the reference's own fragment sizes, in
/// `a_windows_volume_set_reserves_six_more_than_a_unix_one`.
///
/// It rides on the MEMBER's `host_os` rather than [`SERVICE_HOST_OS`]:
/// what is being sized is a copy of a member's header, so the member's
/// own rule applies. The whole set's members are asked rather than this
/// volume's, because the reserve has to cover the largest header the
/// volume might end up holding.
///
/// STATED LIMIT: this is the reserve with quick-open ENABLED, which is
/// the default and every conformance row. `-qo-` is a different number
/// on both platforms - measured in the same sitting, the Windows
/// reference holds back only the eight bytes of the end header there -
/// and [`VOLUME_TAIL_RESERVE`] does not model that case on either
/// platform today. Auto with a fragment too small to cache still
/// reserves the full amount (measured at `-v4200b`: 88 on Windows), so
/// it is the SWITCH that changes it and not whether a block was written.
const VOLUME_TAIL_RESERVE_WINDOWS_MEMBER: u64 = 6;

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
            ARCHIVE_IS_VOLUME
        } else {
            ARCHIVE_IS_VOLUME | ARCHIVE_HAS_VOLUME_NUMBER
        };
        let main = main_header_volume(reserve, archive_flags, index as u64);
        let mut out = RAR5_SIGNATURE.to_vec();
        let main_start = out.len();
        let main_len = main.len();
        out.extend_from_slice(&main);

        let tail_reserve = VOLUME_TAIL_RESERVE
            + if quick_open != ReferenceQuickOpen::None
                && members.iter().any(|m| m.host_os == HOST_OS_WINDOWS)
            {
                VOLUME_TAIL_RESERVE_WINDOWS_MEMBER
            } else {
                0
            };
        let budget = volume_size.saturating_sub(out.len() as u64 + tail_reserve);
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
    if archive_flags & ARCHIVE_HAS_VOLUME_NUMBER != 0 {
        write_vint(&mut specific, number);
    }
    block_image(
        BLOCK_TYPE_MAIN,
        if extra.is_empty() {
            BLOCK_SKIP_IF_UNKNOWN
        } else {
            BLOCK_HAS_EXTRA_AREA | BLOCK_SKIP_IF_UNKNOWN
        },
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

    /// The same archive written on WINDOWS, byte for byte, as `rar 7.23`
    /// writes it there.
    ///
    /// Captured from the reference on an x86-64 Windows 11 box, 16 Sep 2026, over the
    /// same six bytes and the same whole-second mtime as the test above:
    ///
    ///     rar a -y -m0 -mt1 -inul arc.rar hello.txt
    ///
    /// The member is identical to the Unix one in every field but three -
    /// the host-OS byte, the attribute word, and the TIME - and only the
    /// time changes the LAYOUT: a Windows member never uses the header's
    /// own mtime field, because that field is Unix seconds by definition,
    /// and carries a FILETIME in an extra record instead. That is the
    /// whole of the Windows `[files]` class the conformance leg reported
    /// on 16 Sep: 26 rows, every one of them a writing command.
    ///
    /// This test runs on any platform because the writer keys on the
    /// MEMBER's `host_os` rather than on `cfg!(windows)` - which is also
    /// what the reference does, measured the same day (see
    /// [`htime_record`]).
    #[test]
    fn a_windows_member_matches_the_reference_byte_for_byte() {
        let out = write_reference_stored(
            &[ReferenceMember {
                name: "hello.txt",
                data: b"hello\n",
                mtime: Some((1_000_000_000, 0)),
                attributes: 0x20,
                host_os: 0,
                is_dir: false,
            }],
            ReferenceHash::Crc32,
            ReferenceQuickOpen::Auto,
        )
        .expect("writes");
        let expected = concat!(
            "526172211a070100",
            "3392b5e50a01050600050101808000",
            // hello.txt: no header mtime field (file flags 0x04, CRC32
            // only), attributes 0x20, host OS 0, and an eleven-byte
            // extra area holding the TIME record
            "9ca48b9d2502030b86000486002020303a368000000968656c6c6f2e747874",
            // TIME record: size 10, type 3, flags 0x02 (mtime present,
            // unix-format bit CLEAR), then the FILETIME
            "0a03020080ff44d138c101",
            "68656c6c6f0a",
            "1d77565103050400",
        )
        .to_owned();
        assert_eq!(hex(&out), expected);
    }

    /// And the REWRITE layout on Windows, from the same box on the same
    /// day:
    ///
    ///     rar a -m0 -mt1 base.rar a.txt b.txt
    ///     rar rn rn.rar a.txt z.txt
    ///
    /// over a 256-byte member, and this is that member's header image
    /// read straight back out of the reference's `rn.rar`.
    ///
    /// On Unix the two layouts differ in where a whole second goes. On
    /// Windows they do not differ at all - the record is the only place a
    /// FILETIME can go - so this pins that the Create/Rewrite split does
    /// NOT leak into the Windows side.
    #[test]
    fn a_windows_member_is_the_same_time_record_on_the_rewrite_path() {
        // The reference's payload, so the header's CRC32 over the data
        // and the CRC32 over the header itself both land where its did.
        let data: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
        let header = member_header(
            &ReferenceMember {
                name: "z.txt",
                data: &data,
                mtime: Some((1_000_000_000, 0)),
                attributes: 0x20,
                host_os: 0,
                is_dir: false,
            },
            ReferenceHash::Crc32,
            ReferenceLayout::Rewrite,
        )
        .expect("writes");
        assert_eq!(
            hex(&header),
            concat!(
                "8990ddf62102030b800204800220cca30857800000057a2e747874",
                "0a03020080ff44d138c101",
            )
        );
    }

    /// `-htb` on Windows: the BLAKE2sp HASH record comes FIRST and the
    /// TIME record after it, and the CRC32 flag is clear. From the same
    /// capture:
    ///
    ///     rar a -m0 -mt1 -htb blake.rar a.txt
    ///
    /// over the same 256-byte member, read back out of the reference's
    /// own archive. This is the one shape where the extra area has two
    /// records, so it is the only place their ORDER is pinned at all.
    #[test]
    fn a_windows_blake2sp_member_puts_the_hash_record_before_the_time() {
        let data: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
        let header = member_header(
            &ReferenceMember {
                name: "a.txt",
                data: &data,
                mtime: Some((1_000_000_000, 0)),
                attributes: 0x20,
                host_os: 0,
                is_dir: false,
            },
            ReferenceHash::Blake2sp,
            ReferenceLayout::Create,
        )
        .expect("writes");
        assert_eq!(
            hex(&header),
            concat!(
                "daabdd1a4002032e80020080022080000005612e747874",
                // HASH record: size 34, type 2, algorithm 0, 32 bytes
                "220200d1b35d04c0849d6dc758990229c9539784b9e9a8592aa5db63b7cb424ac7105c",
                // then TIME, FILETIME form
                "0a03020080ff44d138c101",
            )
        );
    }

    /// A sub-second time needs no second shape on Windows: a FILETIME is
    /// already 100-nanosecond ticks, so the record keeps its eleven bytes
    /// and only the ticks move. Measured on the box the same day, over a
    /// file whose mtime was set 1,234,567 ticks past the whole second.
    #[test]
    fn a_windows_sub_second_time_is_the_same_eleven_byte_record() {
        let record = htime_record(
            Some((1_000_000_000, 123_456_700)),
            ReferenceLayout::Create,
            0,
        )
        .expect("a windows member always carries the record");
        assert_eq!(record.len(), 11);
        assert_eq!(hex(&record), "0a030287561245d138c101");
    }

    /// The REWRITE path's size fields take the vint's natural width, and
    /// the crossover is the vint's own rather than a two-byte minimum.
    ///
    /// Captured from rar 7.23 on the dev Mac, 16 Sep 2026, three members of
    /// 6, 127 and 128 bytes with the fixture mtime, each `rar a -m0 -mt1`
    /// and then `rar rn` to `z.bin`. These are the reference's own header
    /// images, read back out of its `rn` output: one-byte sizes at 6 and at
    /// 127, two-byte at 128. The CREATE header is 27 bytes at all three,
    /// which is the padding this path does not do.
    ///
    /// It is reachable only below 128 bytes, which is why no conformance
    /// row sees it - every rewrite row's member clears that - and why this
    /// test is the only thing holding the rule.
    #[test]
    fn the_rewrite_path_takes_the_vints_own_width_for_its_sizes() {
        let reference = [
            (
                6usize,
                "dae535251d020307060406a483024acfeb30800001057a2e62696e",
            ),
            (
                127,
                "d7f2e13c1d0203077f047fa48302aa81c4de800001057a2e62696e",
            ),
            (
                128,
                "05c204a21f0203078001048001a48302570d6524800001057a2e62696e",
            ),
        ];
        for (size, want) in reference {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let header = member_header(
                &ReferenceMember {
                    name: "z.bin",
                    data: &data,
                    mtime: Some((1_000_000_000, 0)),
                    attributes: 0o100_644,
                    host_os: 1,
                    is_dir: false,
                },
                ReferenceHash::Crc32,
                ReferenceLayout::Rewrite,
            )
            .expect("writes");
            // The reference's image carries its HTIME record after the
            // name; this compares everything up to it, which is where the
            // widths are.
            assert_eq!(&hex(&header)[..want.len()], want, "member of {size} bytes");
        }
    }

    /// And the CREATE path still pads, at the same three sizes: its header
    /// is the same length whether the member is 6 bytes or 128, because it
    /// reserved two bytes for a size it had not finished reading.
    #[test]
    fn the_create_path_still_pads_its_sizes_to_two_bytes() {
        let widths: Vec<usize> = [6usize, 127, 128]
            .into_iter()
            .map(|size| {
                let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
                member_header(
                    &ReferenceMember {
                        name: "z.bin",
                        data: &data,
                        mtime: Some((1_000_000_000, 0)),
                        attributes: 0o100_644,
                        host_os: 1,
                        is_dir: false,
                    },
                    ReferenceHash::Crc32,
                    ReferenceLayout::Create,
                )
                .expect("writes")
                .len()
            })
            .collect();
        assert_eq!(widths[0], widths[1], "6 and 127 bytes pad the same");
        assert_eq!(widths[1], widths[2], "and so does 128");
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
        let main = main_header_recovery(3, ARCHIVE_HAS_RECOVERY_RECORD);
        // crc32(4) | header size(1) | type(1) flags(1) extra size(1)
        // archive flags(1) | record size(1) type(1) locator flags(1)
        // quick-open(3) recovery(3)
        assert_eq!(main.len(), 4 + 1 + 4 + 1 + 8);
        let header = &main[5..];
        assert_eq!(header[0], BLOCK_TYPE_MAIN as u8);
        assert_eq!(header[1] as u64, BLOCK_HAS_EXTRA_AREA | BLOCK_SKIP_IF_UNKNOWN);
        assert_eq!(header[3] as u64, ARCHIVE_HAS_RECOVERY_RECORD);
        // The extra area: one record of eight bytes, the locator, whose
        // flags say both offsets are present and are zero for now.
        assert_eq!(header[4], 8);
        assert_eq!(header[5] as u64, MAIN_EXTRA_LOCATOR);
        assert_eq!(
            header[6] as u64,
            LOCATOR_HAS_QUICK_OPEN_OFFSET | LOCATOR_HAS_RECOVERY_RECORD_OFFSET
        );
        assert_eq!(&header[7..13], &[0x80, 0x80, 0x00, 0x80, 0x80, 0x00]);
    }

    /// The padded writer pads UP to a width and never truncates DOWN to
    /// it: 16,612 needs three vint bytes whatever the caller reserved.
    #[test]
    fn a_padded_vint_grows_past_its_width_when_the_value_needs_it() {
        let mut two = Vec::new();
        write_vint_padded(&mut two, 5, 2);
        assert_eq!(two, [0x85, 0x00]);
        let mut three = Vec::new();
        write_vint_padded(&mut three, 16_612, 2);
        assert_eq!(three, [0xe4, 0x81, 0x01], "the reference's own bytes for 16,612");
        let mut plain = Vec::new();
        write_vint_padded(&mut plain, 0, 1);
        assert_eq!(plain, [0x00]);
    }

    /// A quick-open block whose data runs past 16,383 bytes carries the
    /// whole length in both size fields. Reproduces what the reference
    /// unrar 7.23 refused as "Corrupt header is found" (14 Sep 2026): the
    /// block header said `len & 0x3fff`, so the reader walked into the
    /// cached headers expecting the end of the archive.
    #[test]
    fn a_quick_open_block_over_sixteen_kilobytes_declares_its_whole_length() {
        let names: Vec<String> = (0..400)
            .map(|i| format!("file-with-a-fairly-long-name-{i}.dat"))
            .collect();
        let members: Vec<ReferenceMember<'_>> = names.iter().map(|n| member(n, b"x")).collect();
        let out = write_reference_stored(&members, ReferenceHash::Crc32, ReferenceQuickOpen::All)
            .expect("writes");
        let marker = out
            .windows(2)
            .position(|w| w == b"QO")
            .expect("a QO block");
        // Walk back to the block's CRC and CHECK IT, rather than taking
        // the first candidate that merely parses.
        //
        // "Decodes as a service header" is not a test: the fields are
        // vints, so a shifted start lands on arbitrary bytes that decode
        // as *something* perfectly often, and which offset does so
        // depends on the surrounding byte VALUES. That is how the
        // Windows leg of `unit-one-process` went red on 16 Sep 2026:
        // `SERVICE_HOST_OS` is 0 there and 1 on unix, and the one byte
        // is inside this scan window, so a false candidate parsed, put
        // `data_start` past the end of the archive, and the arithmetic
        // below panicked with "attempt to subtract with overflow" - on
        // Windows only, on a writer that was correct. Reproducible on
        // any box by forcing that constant to 0.
        //
        // The CRC is the block's own answer to "does this start here":
        // `block_image` writes crc32 over the size vint and the header
        // it precedes, so a candidate that is not the real start fails
        // it. Both host-OS values are then found identically.
        let mut decoded = None;
        for start in marker.saturating_sub(32)..marker {
            let mut at = start + 4;
            let Some((header_size, next)) = read_vint(&out, at) else { continue };
            let sized_end = start + 4 + vint_width(header_size) + header_size as usize;
            if sized_end > out.len() {
                continue;
            }
            let stored = u32::from_le_bytes(out[start..start + 4].try_into().unwrap());
            if crc32(&out[start + 4..sized_end]) != stored {
                continue;
            }
            at = next;
            let Some((3, next)) = read_vint(&out, at) else { continue };
            at = next;
            let Some((flags, next)) = read_vint(&out, at) else { continue };
            at = next;
            if flags & BLOCK_HAS_EXTRA_AREA != 0 {
                let Some((_, next)) = read_vint(&out, at) else { continue };
                at = next;
            }
            let Some((data_size, _)) = read_vint(&out, at) else { continue };
            decoded = Some((start + 4 + vint_width(header_size) + header_size as usize, data_size));
            break;
        }
        let (data_start, data_size) = decoded.expect("the QO block header decodes");
        // The QO data is the last thing before the eight-byte end header.
        let actual = (out.len() - 8 - data_start) as u64;
        assert!(actual > 16_383, "the fixture must push the block past two vint bytes: {actual}");
        assert_eq!(data_size, actual, "the block header's data size names the whole data area");
    }

    fn read_vint(bytes: &[u8], mut at: usize) -> Option<(u64, usize)> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = *bytes.get(at)?;
            at += 1;
            value |= u64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                return Some((value, at));
            }
            if shift > 63 {
                return None;
            }
        }
    }

    /// The `QO` service header's host-OS byte is the WRITER's platform,
    /// and it is not the member's.
    ///
    /// Measured on the x86-64 Windows 11 box, 16 Sep 2026, against rar
    /// 7.23: an archive built on macOS carries `host=1` in its quick-open
    /// block, and the Windows reference rewriting that same archive
    /// (`rn`, and `a` of a second member from the Windows disk) leaves
    /// `text.txt` reported by `lt` as `Host OS: Unix` while regenerating
    /// the `QO` block with `host=0`. So a service block follows neither
    /// the members it caches nor the archive it sits in.
    ///
    /// The member here carries the OPPOSITE byte to this platform's, so
    /// the assertion separates the two rules on Windows and on Unix
    /// alike rather than passing by coincidence on one of them. The
    /// second half ties `CMT` to the same value: the two service writers
    /// disagreed from 4 Sep to 16 Sep 2026 - `comment_header` followed
    /// the platform and `quick_open_block` wrote a constant `1` - and
    /// that one byte was the whole of nineteen `[files]` divergences on
    /// the windows `rar` conformance leg.
    #[test]
    fn a_service_header_carries_the_writers_host_os_not_the_members() {
        let platform_host: u8 = if cfg!(windows) { 0 } else { 1 };
        let opposite = u64::from(1 - platform_host);
        let big = vec![7u8; 4097];
        let mut m = member("big.bin", &big);
        m.host_os = opposite;
        let out = write_reference_stored(&[m], ReferenceHash::Crc32, ReferenceQuickOpen::Auto)
            .expect("writes");
        let qo = out.windows(2).position(|w| w == b"QO").expect("a QO block");
        // name length (1 byte, value 2) then the host-OS vint before it.
        assert_eq!(out[qo - 1], 2, "the byte before the name is its length");
        assert_eq!(
            out[qo - 2],
            platform_host,
            "the QO header follows the writer, not the member's {opposite}",
        );

        let cmt = comment_header(b"a comment");
        let at = cmt.windows(3).position(|w| w == b"CMT").expect("a CMT block");
        assert_eq!(cmt[at - 1], 3, "the byte before the name is its length");
        assert_eq!(
            cmt[at - 2],
            platform_host,
            "CMT and QO are one rule, not two",
        );
    }

    /// The reference's own first-volume fragment, on both platforms, from
    /// one run of `rar a -m0 -v12k` over a 24,576-byte member on each.
    ///
    /// This is the pin under [`VOLUME_TAIL_RESERVE_WINDOWS_MEMBER`], and
    /// it needs no `cfg`: the member's `host_os` is an input here, so
    /// either box checks both answers. A Windows member costs twelve
    /// payload bytes - six for its own longer header and six for the copy
    /// the quick-open block carries, which is the reserve.
    ///
    /// `add-volumes` and `add-recovery-volumes` were the last two
    /// `[files]` rows of the windows `rar` conformance leg once the
    /// service header's host byte was fixed: the budget held 82 back on
    /// both platforms, so rarfast packed six more bytes into every volume
    /// than the Windows reference did.
    #[test]
    fn a_windows_volume_set_reserves_six_more_than_a_unix_one() {
        let data = vec![9u8; 24_576];
        let first = |host_os: u64, attributes: u64| {
            let mut m = member("rand.bin", &data);
            m.host_os = host_os;
            m.attributes = attributes;
            let set = write_reference_stored_volumes(
                &[m],
                ReferenceHash::Crc32,
                12_288,
                ReferenceQuickOpen::Auto,
            )
            .expect("writes");
            set.layout[0][0].bytes
        };
        // The attributes are the reference's own on each side: a Windows
        // member carries FILE_ATTRIBUTE_ARCHIVE, a Unix one its mode.
        assert_eq!(first(1, 0o100_644), 12_145, "the macOS reference's fragment");
        assert_eq!(first(0, 0x20), 12_133, "the Windows reference's fragment");
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

    fn streamed_of<'a>(
        members: &[ReferenceMember<'a>],
    ) -> Vec<ReferenceStreamedMember<'a, std::io::Cursor<&'a [u8]>>> {
        members
            .iter()
            .map(|m| ReferenceStreamedMember {
                name: m.name,
                size: m.data.len() as u64,
                mtime: m.mtime,
                attributes: m.attributes,
                host_os: m.host_os,
                is_dir: m.is_dir,
                source: std::io::Cursor::new(m.data),
            })
            .collect()
    }

    /// A payload that does not repeat inside a chunk, so a chunk copied
    /// to the wrong place changes the checksum.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    /// The streamed writer's bytes ARE the slice writer's, over every
    /// shape it has a separate path for: a directory, small members read
    /// whole, members past [`STREAM_CHUNK`] that take the three-stage copy
    /// and a patched header (one ending mid-chunk, one on a chunk edge),
    /// both checksums, all three quick-open modes, and a prefix block.
    #[test]
    fn the_streamed_reference_writer_matches_the_slice_writer_byte_for_byte() {
        let big = noise(2 * STREAM_CHUNK + 12_345, 3);
        let edge = noise(3 * STREAM_CHUNK, 5);
        let small = noise(40_000, 7);
        let tiny = b"hello\n".to_vec();
        let mut dir = member("sub", b"");
        dir.is_dir = true;
        let mut sub_second = member("sub/tiny.txt", &tiny);
        sub_second.mtime = Some((1_000_000_000, 123_456_789));
        let members = [
            member("big.bin", &big),
            sub_second,
            member("sub/small.bin", &small),
            dir,
            member("edge.bin", &edge),
            member("empty.bin", b""),
        ];
        let comment = b"a comment".to_vec();
        for hash in [ReferenceHash::Crc32, ReferenceHash::Blake2sp] {
            for quick_open in [
                ReferenceQuickOpen::Auto,
                ReferenceQuickOpen::All,
                ReferenceQuickOpen::None,
            ] {
                let expected = write_reference_stored(&members, hash, quick_open).expect("writes");
                let mut sink = std::io::Cursor::new(Vec::new());
                let written = write_reference_stored_streamed(
                    &mut streamed_of(&members),
                    hash,
                    quick_open,
                    &mut sink,
                )
                .expect("streams");
                assert_eq!(written, expected.len() as u64);
                assert!(
                    sink.get_ref() == &expected,
                    "{hash:?} {quick_open:?}: streamed bytes differ from the slice writer's"
                );

                let blocks: Vec<ReferenceBlock<'_>> = std::iter::once(ReferenceBlock {
                    header: comment_header(&comment),
                    data: &comment,
                    name: None,
                })
                .chain(members.iter().take(2).map(|m| ReferenceBlock {
                    header: member_header(m, hash, ReferenceLayout::Create).unwrap(),
                    data: m.data,
                    name: Some(m.name),
                }))
                .collect();
                let mut all = blocks
                    .iter()
                    .map(|b| ReferenceBlock {
                        header: b.header.clone(),
                        data: b.data,
                        name: b.name,
                    })
                    .collect::<Vec<_>>();
                for m in &members[2..] {
                    all.push(ReferenceBlock {
                        header: member_header(m, hash, ReferenceLayout::Create).unwrap(),
                        data: m.data,
                        name: Some(m.name),
                    });
                }
                let expected = assemble(&all, 0x10, quick_open);
                let mut sink = std::io::Cursor::new(Vec::new());
                assemble_streamed(
                    &blocks,
                    &mut streamed_of(&members[2..]),
                    hash,
                    0x10,
                    quick_open,
                    &mut sink,
                )
                .expect("streams");
                assert!(
                    sink.get_ref() == &expected,
                    "{hash:?} {quick_open:?}: a prefixed streamed archive differs from assemble's"
                );
            }
        }
    }

    /// A source shorter than the size it was declared with is refused on
    /// both paths, small and large, rather than written short.
    #[test]
    fn a_streamed_member_that_ends_early_is_refused() {
        for (declared, actual) in [(100u64, 60usize), (STREAM_CHUNK as u64 * 2, STREAM_CHUNK + 7)] {
            let data = noise(actual, 9);
            let mut members = [ReferenceStreamedMember {
                name: "short.bin",
                size: declared,
                mtime: Some((1_000_000_000, 0)),
                attributes: 0o100_644,
                host_os: 1,
                is_dir: false,
                source: std::io::Cursor::new(&data[..]),
            }];
            let mut sink = std::io::Cursor::new(Vec::new());
            let refused = write_reference_stored_streamed(
                &mut members,
                ReferenceHash::Crc32,
                ReferenceQuickOpen::Auto,
                &mut sink,
            );
            assert!(refused.is_err(), "declared {declared}, held {actual}");
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn find(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
