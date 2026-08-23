//! Tar container reading: the header grammar, a strictly forward reader
//! over an arriving byte stream, and the naming rules that decide
//! whether a posted file may be treated as packaging at all.
//!
//! Tar is the one container in this crate with no tail structure. A zip
//! keeps its directory behind the payload and a 7z keeps its map there,
//! so both chases have to front-load a window before they can name a
//! single entry; a tar is a flat sequence of `header block, data,
//! padding, header block, …` running front to back. That makes the
//! reader here a pure `io::Read` consumer - no `Seek`, no random
//! access, no promote - and it is why the extract-side chase
//! (`extract/tar.rs`) can arm its drop-behind trim the moment it starts
//! instead of waiting for a map to parse.
//!
//! What is read:
//! - **ustar** (POSIX.1-1988) and **GNU tar**, which differ only in the
//!   six magic bytes at 257 and how they spell long names.
//! - Long paths both ways: GNU's `L` typeflag entry, whose data IS the
//!   next entry's name, and POSIX pax `x` extended headers, whose
//!   `path=` and `size=` records override the ustar fields behind them.
//! - `prefix` (ustar's own long-path field) joined back onto `name`.
//! - Numeric fields in octal, and in GNU base-256 for sizes past 8 GB.
//!
//! What is deliberately refused, each one demoting the whole container
//! rather than half-extracting it:
//! - **Symlinks, hard links, devices and FIFOs.** The zip chase refuses
//!   symlinks for the same reason: an entry that is a reference rather
//!   than bytes has no honest one-pass output, and following one is how
//!   an archive writes outside its own directory.
//! - **GNU sparse entries** (`S`, and the pax `GNU.sparse.*` keywords).
//!   A sparse member declares a real size unrelated to the bytes that
//!   follow it, which is precisely the shape the in-stream bomb guard
//!   cannot price from the container's own length.
//!
//! NOT handled, and not a gap: `.tar.gz`, `.tar.xz`, `.tar.bz2` and
//! `.tgz`. Those carry a compressor's magic at offset 0, never ustar's
//! at 257, so they classify as ordinary files and land on disk exactly
//! as they do today.

use std::io;

/// Every tar structure is a multiple of this. Headers are one block;
/// entry data is padded up to the next one.
pub const BLOCK: usize = 512;

/// Field offsets inside the 512-byte header block.
const OFF_NAME: usize = 0;
const OFF_SIZE: usize = 124;
const OFF_CHKSUM: usize = 148;
const OFF_TYPEFLAG: usize = 156;
const OFF_MAGIC: usize = 257;
const OFF_PREFIX: usize = 345;

/// Shortest prefix of a header that [`looks_like_tar`] can judge: up
/// through the magic and version fields (257 + 6 + 2).
pub const SNIFF_MIN: usize = 265;

/// POSIX.1-1988 ustar: magic `ustar\0`, version `00`.
const MAGIC_USTAR: &[u8] = b"ustar\x0000";
/// GNU tar: magic `ustar `, version ` \0` - one field of eight bytes in
/// practice, which is why it is matched as one.
const MAGIC_GNU: &[u8] = b"ustar  \x00";

/// May a posted (or inner) file of this name be treated as a tar
/// container? Carries the same rule the zip side states in its module
/// note: a NAMED file that is not a tar is never magic-sniffed, so only
/// `.tar` and extensionless (obfuscated) names are eligible.
///
/// That is also why tar needs no `FINAL_FILE_EXTS` list of its own,
/// where zip and RAR both grew one after a `.cbz`/`.cbr` was unpacked
/// into loose pages: any wrapper extension a tar-shaped payload might
/// acquire fails the `.tar`-or-nothing test here already. A list would
/// be dead code today and is the thing to add if that ever changes.
///
/// Deliberately narrower than the zip predicate in one way: there is no
/// multi-part grammar here. A byte-split tar has no header of its own in
/// parts 2..n and nothing in the format sizes the whole container, so a
/// `name.tar.001` is left to the disk pass exactly as it is today.
pub fn chase_eligible_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".tar") || std::path::Path::new(&lower).extension().is_none()
}

/// Does this prefix of a file's first bytes look like a tar header?
///
/// Two strengths, because the caller is a stream and may not have a
/// whole block yet. With 512 bytes the header checksum is verified,
/// which is what makes the answer strong enough to route on; with only
/// [`SNIFF_MIN`] the magic and version fields are all there is, and the
/// reader re-checks the checksum on its own first read - a header that
/// fails it there demotes the container byte-exactly, so the weaker
/// sniff can cost a demote but never a wrong output.
///
/// The magic is required in both cases. Pre-POSIX V7 tars carry none at
/// all and would have to be identified by the checksum alone, which is
/// 17 bits of evidence spread over a 512-byte window - far too weak to
/// point at an arbitrary posted file and call it packaging.
pub fn looks_like_tar(data: &[u8]) -> bool {
    let Some(magic) = data.get(OFF_MAGIC..OFF_MAGIC + 8) else {
        return false;
    };
    if magic != MAGIC_USTAR && magic != MAGIC_GNU {
        return false;
    }
    match data.get(..BLOCK) {
        Some(block) => checksum_ok(block) && read_size(block).is_some(),
        None => true,
    }
}

/// Sum of the header's bytes with the checksum field read as spaces,
/// compared against the value stored there.
///
/// Both the unsigned and the signed sum are accepted: historical tar
/// implementations on platforms with a signed `char` wrote the signed
/// one, and archives carrying it are still in circulation. Refusing them
/// would demote a container that every other reader opens.
fn checksum_ok(block: &[u8]) -> bool {
    let Some(stored) = read_octal(&block[OFF_CHKSUM..OFF_CHKSUM + 8]) else {
        return false;
    };
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &b) in block.iter().enumerate() {
        let v = if (OFF_CHKSUM..OFF_CHKSUM + 8).contains(&i) {
            b' '
        } else {
            b
        };
        unsigned += v as u64;
        signed += v as i8 as i64;
    }
    stored == unsigned || i64::try_from(stored).is_ok_and(|s| s == signed)
}

/// Octal ASCII, terminated by NUL or space and tolerant of leading
/// spaces - the numeric encoding every tar field uses. `None` for a
/// field that is not octal at all (an empty field reads as 0, which is
/// what a zero-size entry writes).
fn read_octal(field: &[u8]) -> Option<u64> {
    let mut v: u64 = 0;
    let mut seen = false;
    for &b in field {
        match b {
            b' ' if !seen => continue,
            0 | b' ' => break,
            b'0'..=b'7' => {
                v = v.checked_mul(8)?.checked_add((b - b'0') as u64)?;
                seen = true;
            }
            _ => return None,
        }
    }
    Some(v)
}

/// The size field: octal, or GNU base-256 when the top bit of the first
/// byte is set (sizes past the 8 GB an 11-digit octal field can spell).
/// Negative base-256 values - the format allows them, nothing in a size
/// field can mean one - are refused rather than wrapped.
fn read_size(block: &[u8]) -> Option<u64> {
    let f = &block[OFF_SIZE..OFF_SIZE + 12];
    if f[0] & 0x80 == 0 {
        return read_octal(f);
    }
    if f[0] & 0x40 != 0 {
        return None;
    }
    let mut v: u64 = (f[0] & 0x3f) as u64;
    for &b in &f[1..] {
        v = v.checked_mul(256)?.checked_add(b as u64)?;
    }
    Some(v)
}

/// A NUL-terminated text field, as lossy UTF-8. Tar carries no encoding
/// declaration, so a non-UTF-8 name is replaced rather than refused -
/// the name is sanitized on the way to disk regardless.
fn read_str(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// What one member of the archive is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    /// A symlink, hard link, device node or FIFO: a reference, not
    /// bytes. Named as one because the extractor treats them alike -
    /// it refuses the container - and the wording it prints comes from
    /// [`Entry::kind_word`].
    Reference(&'static str),
}

/// One member of the archive, as its header block describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub size: u64,
    pub kind: Kind,
}

impl Entry {
    /// The noun a demote reason uses for a refused member.
    pub fn kind_word(&self) -> &'static str {
        match self.kind {
            Kind::Reference(w) => w,
            Kind::File => "file",
            Kind::Dir => "directory",
        }
    }
}

#[derive(Debug)]
pub enum TarError {
    Io(io::Error),
    /// Structurally not a tar we can read: a header whose checksum
    /// fails, a truncated block, a size that runs past the container.
    Malformed(&'static str),
    /// Readable, but this member uses something deliberately declined.
    /// Carries the user-facing reason.
    Unsupported(String),
}

impl std::fmt::Display for TarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TarError::Io(e) => write!(f, "{e}"),
            TarError::Malformed(w) => write!(f, "malformed tar ({w})"),
            TarError::Unsupported(w) => write!(f, "{w}"),
        }
    }
}

impl std::error::Error for TarError {}

impl From<io::Error> for TarError {
    fn from(e: io::Error) -> TarError {
        TarError::Io(e)
    }
}

/// Most members one container may declare. A tar member costs one
/// 512-byte header and nothing else, so a crafted container spends
/// 512 bytes per entry to make the extractor open a child slot and a
/// file - a ratio no other format here offers. The cap is far above any
/// real post (the largest source tarballs run to tens of thousands of
/// files) and a container over it demotes to disk, so the cost of being
/// wrong is one extra pass, not a failure.
pub const MAX_ENTRIES: usize = 100_000;

/// Longest name a `L` entry or a pax `path=` record may carry. Both are
/// read into memory whole before the entry they name is known, so the
/// bound is on the read, not on the name.
const MAX_NAME_BYTES: u64 = 64 * 1024;

/// A strictly forward reader over a tar container.
///
/// Drives an `io::Read` that may BLOCK - in the extract chase it is a
/// view over bytes still arriving from the wire - and never seeks. Reads
/// ascend monotonically, which is the property the chase's drop-behind
/// trim needs: nothing below the reader's position is ever asked for
/// again.
///
/// Use is a two-step loop: [`Self::next_entry`] to advance to the next
/// member's header, then [`Self::read_data`] until it returns 0 for that
/// member's bytes. Skipping the data is legal - the next `next_entry`
/// consumes whatever is left of it.
pub struct Reader<R> {
    src: R,
    /// Container offset of the next byte to be read.
    pos: u64,
    /// The container's declared length, so an entry that runs past it is
    /// refused at its header rather than by blocking forever on bytes
    /// that will never arrive.
    total: u64,
    /// Unread bytes of the current member, and the padding behind them.
    left: u64,
    pad: u64,
    entries: usize,
    /// Set once the end-of-archive marker (or a clean EOF) is reached,
    /// so a caller that keeps asking gets `None` rather than a fresh
    /// parse of whatever padding follows.
    ended: bool,
    /// Did the walk stop on a real end-of-archive marker, rather than on
    /// the container simply running out? See [`Self::saw_end_marker`].
    end_marker: bool,
}

impl<R: io::Read> Reader<R> {
    pub fn new(src: R, total: u64) -> Reader<R> {
        Reader {
            src,
            pos: 0,
            total,
            left: 0,
            pad: 0,
            entries: 0,
            ended: false,
            end_marker: false,
        }
    }

    /// Did the archive END, or merely STOP? A tar's last structure is a
    /// zero block; a container that runs out without one was cut
    /// between members, and every member before the cut looks perfectly
    /// well-formed - so a caller that does not ask this publishes a
    /// truncated archive as a complete one. (A member cut mid-DATA is
    /// caught without this, by its own declared size.)
    ///
    /// Only meaningful once [`Self::next_entry`] has returned `None`.
    pub fn saw_end_marker(&self) -> bool {
        self.end_marker
    }

    /// Advance to the next member and return its header, or `None` at
    /// the end of the archive.
    pub fn next_entry(&mut self) -> Result<Option<Entry>, TarError> {
        if self.ended {
            return Ok(None);
        }
        self.skip_rest()?;
        // A pax header applies to the entry BEHIND it, so both long-name
        // spellings accumulate here and are consumed by the first
        // ordinary member that follows.
        let mut long_name: Option<String> = None;
        let mut pax_name: Option<String> = None;
        let mut pax_size: Option<u64> = None;
        loop {
            let Some(block) = self.read_block()? else {
                self.ended = true;
                return Ok(None);
            };
            if block.iter().all(|&b| b == 0) {
                // The end-of-archive marker is two zero blocks. One is
                // accepted as the end too: the second is padding, and
                // plenty of writers (and every truncating splitter) omit
                // it. Nothing can follow a zero block that this reader
                // would trust anyway.
                self.ended = true;
                self.end_marker = true;
                return Ok(None);
            }
            if !checksum_ok(&block) {
                return Err(TarError::Malformed("header checksum does not match"));
            }
            let magic = &block[OFF_MAGIC..OFF_MAGIC + 8];
            if magic != MAGIC_USTAR && magic != MAGIC_GNU {
                return Err(TarError::Malformed("header carries no ustar magic"));
            }
            let size =
                read_size(&block).ok_or(TarError::Malformed("size field is not a number"))?;
            let flag = block[OFF_TYPEFLAG];
            match flag {
                // GNU long name / long link name: the DATA is the name,
                // and the real header follows.
                b'L' | b'K' => {
                    let text = self.read_meta(size)?;
                    if flag == b'L' {
                        long_name = Some(text.trim_end_matches('\0').to_string());
                    }
                    continue;
                }
                // pax extended header (per-entry `x`, global `g`). A
                // global one sets defaults for the rest of the archive;
                // we read neither name nor size out of it, because the
                // only keywords acted on here are per-entry by nature.
                b'x' | b'g' => {
                    let text = self.read_meta(size)?;
                    if flag == b'x' {
                        let (n, s) = parse_pax(&text)?;
                        pax_name = n.or(pax_name);
                        pax_size = s.or(pax_size);
                    }
                    continue;
                }
                b'S' => {
                    return Err(TarError::Unsupported(
                        "the tar holds a sparse member, which is not extracted".to_string(),
                    ));
                }
                _ => {}
            }
            let mut name = pax_name
                .or(long_name)
                .unwrap_or_else(|| join_prefix(&block));
            let size = pax_size.unwrap_or(size);
            let kind = match flag {
                b'0' | 0 | b'7' => {
                    // A V7-era writer spells a directory as a
                    // zero-length regular entry whose name ends in `/`.
                    if name.ends_with('/') {
                        Kind::Dir
                    } else {
                        Kind::File
                    }
                }
                b'5' => Kind::Dir,
                b'1' => Kind::Reference("hard link"),
                b'2' => Kind::Reference("symlink"),
                b'3' | b'4' => Kind::Reference("device node"),
                b'6' => Kind::Reference("FIFO"),
                other => {
                    return Err(TarError::Unsupported(format!(
                        "the tar holds a member of unknown type {:?}, which is not extracted",
                        other as char
                    )));
                }
            };
            if matches!(kind, Kind::Dir) {
                name = name.trim_end_matches('/').to_string();
            }
            // A directory or a reference carries no payload, whatever
            // its header claims; only a file's size opens a data range.
            let data = if matches!(kind, Kind::File) { size } else { 0 };
            if self
                .pos
                .checked_add(data)
                .is_none_or(|end| end > self.total)
            {
                return Err(TarError::Malformed(
                    "a member's data runs past the end of the container",
                ));
            }
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                return Err(TarError::Unsupported(format!(
                    "the tar declares more than {MAX_ENTRIES} members"
                )));
            }
            self.left = data;
            self.pad = (BLOCK as u64 - data % BLOCK as u64) % BLOCK as u64;
            return Ok(Some(Entry {
                name,
                size: data,
                kind,
            }));
        }
    }

    /// Read some of the current member's data. Returns 0 once the whole
    /// member has been handed over - never a byte of the next header.
    pub fn read_data(&mut self, buf: &mut [u8]) -> Result<usize, TarError> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let take = (self.left as usize).min(buf.len());
        let n = self.src.read(&mut buf[..take])?;
        if n == 0 {
            return Err(TarError::Malformed(
                "the container ends inside a member's data",
            ));
        }
        self.pos += n as u64;
        self.left -= n as u64;
        Ok(n)
    }

    /// Consume whatever is left of the current member, and its padding.
    fn skip_rest(&mut self) -> Result<(), TarError> {
        let mut sink = [0u8; 8192];
        while self.left > 0 {
            let take = (self.left as usize).min(sink.len());
            let n = self.src.read(&mut sink[..take])?;
            if n == 0 {
                return Err(TarError::Malformed(
                    "the container ends inside a member's data",
                ));
            }
            self.pos += n as u64;
            self.left -= n as u64;
        }
        let mut pad = std::mem::take(&mut self.pad);
        while pad > 0 {
            let take = (pad as usize).min(sink.len());
            let n = self.src.read(&mut sink[..take])?;
            if n == 0 {
                // Padding missing at EOF is how plenty of real archives
                // end; the next read_block sees EOF and ends cleanly.
                self.pad = 0;
                return Ok(());
            }
            self.pos += n as u64;
            pad -= n as u64;
        }
        Ok(())
    }

    /// One header block, or `None` at a clean end of stream. A partial
    /// block is malformed, not an end.
    fn read_block(&mut self) -> Result<Option<[u8; BLOCK]>, TarError> {
        let mut b = [0u8; BLOCK];
        let mut done = 0usize;
        while done < BLOCK {
            let n = self.src.read(&mut b[done..])?;
            if n == 0 {
                if done == 0 {
                    return Ok(None);
                }
                return Err(TarError::Malformed("the container ends inside a header"));
            }
            done += n;
        }
        self.pos += BLOCK as u64;
        Ok(Some(b))
    }

    /// Read a metadata member's whole data (a GNU long name or a pax
    /// record set) plus its padding, as text.
    fn read_meta(&mut self, size: u64) -> Result<String, TarError> {
        if size > MAX_NAME_BYTES {
            return Err(TarError::Unsupported(format!(
                "the tar declares a {size}-byte name record, over the {MAX_NAME_BYTES}-byte ceiling"
            )));
        }
        self.left = size;
        self.pad = (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64;
        let mut out = vec![0u8; size as usize];
        let mut done = 0usize;
        while done < out.len() {
            let n = self.read_data(&mut out[done..])?;
            if n == 0 {
                break;
            }
            done += n;
        }
        out.truncate(done);
        self.skip_rest()?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}

/// ustar's own long-path field: `prefix` holds the leading directories,
/// `name` the tail, joined with `/`. Empty prefix (the common case) is
/// the plain name.
fn join_prefix(block: &[u8]) -> String {
    let name = read_str(&block[OFF_NAME..OFF_NAME + 100]);
    let prefix = read_str(&block[OFF_PREFIX..OFF_PREFIX + 155]);
    if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    }
}

/// pax extended header records: `<len> <key>=<value>\n`, where `<len>`
/// counts the whole record including itself and the newline. Only
/// `path` and `size` are acted on; every other keyword is ordinary
/// metadata this extractor has no output for.
///
/// A `GNU.sparse.*` keyword is refused outright rather than ignored: a
/// pax-spelled sparse member looks like an ordinary file in its ustar
/// header, so ignoring the keyword would write the FILE IMAGE's holes as
/// literal bytes and call the result good.
fn parse_pax(text: &str) -> Result<(Option<String>, Option<u64>), TarError> {
    let mut name = None;
    let mut size = None;
    let mut rest = text;
    while !rest.is_empty() {
        let Some(sp) = rest.find(' ') else { break };
        let Ok(len) = rest[..sp].parse::<usize>() else {
            return Err(TarError::Malformed("pax record has no length"));
        };
        // A pax length is a BYTE count, and the values are arbitrary
        // UTF-8 (`path=` above all), so a hostile or merely truncated
        // record can point it into the middle of a character. `get`
        // rather than a slice: the panic that would be is reachable
        // from container bytes.
        let (Some(body), Some(tail)) = (rest.get(sp + 1..len), rest.get(len..)) else {
            return Err(TarError::Malformed("pax record length is out of range"));
        };
        let body = body.trim_end_matches('\n');
        rest = tail;
        let Some((key, value)) = body.split_once('=') else {
            continue;
        };
        if key.starts_with("GNU.sparse.") {
            return Err(TarError::Unsupported(
                "the tar holds a sparse member, which is not extracted".to_string(),
            ));
        }
        match key {
            "path" => name = Some(value.to_string()),
            "size" => {
                size = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| TarError::Malformed("pax size is not a number"))?,
                )
            }
            _ => {}
        }
    }
    Ok((name, size))
}

/// Hand-rolled tar writer for the tests, the role `zip::fixtures` plays
/// for zip. Deliberately hand-rolled and not a crate: the fixtures have
/// to be able to write the shapes a real writer refuses (a wrong
/// checksum, a sparse member, a size that runs past the container), and
/// no new dependency belongs in the tree for that.
pub mod fixtures {
    use super::{BLOCK, OFF_CHKSUM};

    /// One member to write.
    #[derive(Clone)]
    pub struct Spec<'a> {
        pub name: &'a str,
        pub data: &'a [u8],
        pub typeflag: u8,
        /// Write GNU's `ustar  \0` magic instead of POSIX `ustar\000`.
        pub gnu: bool,
        /// Precede the member with a GNU `L` long-name entry carrying
        /// this name, and truncate the ustar `name` field to 100 bytes.
        pub long_name: Option<&'a str>,
        /// Precede the member with a pax `x` header carrying these
        /// records, each written as `<len> <key>=<value>\n`.
        pub pax: Vec<(String, String)>,
        /// Corrupt the stored header checksum.
        pub bad_checksum: bool,
    }

    impl<'a> Spec<'a> {
        pub fn file(name: &'a str, data: &'a [u8]) -> Spec<'a> {
            Spec {
                name,
                data,
                typeflag: b'0',
                gnu: false,
                long_name: None,
                pax: Vec::new(),
                bad_checksum: false,
            }
        }

        pub fn dir(name: &'a str) -> Spec<'a> {
            Spec {
                typeflag: b'5',
                ..Spec::file(name, b"")
            }
        }

        /// A member of any typeflag with no payload: `2` symlink, `1`
        /// hard link, `S` GNU sparse, `6` FIFO.
        pub fn special(name: &'a str, typeflag: u8) -> Spec<'a> {
            Spec {
                typeflag,
                ..Spec::file(name, b"")
            }
        }
    }

    fn octal(v: u64, width: usize, out: &mut [u8]) {
        let s = format!("{v:0>width$o}", width = width - 1);
        out[..s.len()].copy_from_slice(s.as_bytes());
    }

    /// One 512-byte header, checksummed.
    fn header(name: &str, size: u64, typeflag: u8, gnu: bool, bad: bool) -> Vec<u8> {
        let mut h = vec![0u8; BLOCK];
        let n = name.as_bytes();
        let take = n.len().min(100);
        h[..take].copy_from_slice(&n[..take]);
        octal(0o644, 8, &mut h[100..108]);
        octal(0, 8, &mut h[108..116]);
        octal(0, 8, &mut h[116..124]);
        octal(size, 12, &mut h[124..136]);
        octal(0, 12, &mut h[136..148]);
        h[OFF_CHKSUM..OFF_CHKSUM + 8].fill(b' ');
        h[156] = typeflag;
        if gnu {
            h[257..265].copy_from_slice(b"ustar  \x00");
        } else {
            h[257..265].copy_from_slice(b"ustar\x0000");
        }
        let sum: u64 = h.iter().map(|&b| b as u64).sum();
        let sum = if bad { sum ^ 0o777 } else { sum };
        let s = format!("{sum:06o}\0 ");
        h[OFF_CHKSUM..OFF_CHKSUM + 8].copy_from_slice(s.as_bytes());
        h
    }

    fn push_member(out: &mut Vec<u8>, name: &str, data: &[u8], flag: u8, gnu: bool, bad: bool) {
        out.extend_from_slice(&header(name, data.len() as u64, flag, gnu, bad));
        out.extend_from_slice(data);
        let pad = (BLOCK - data.len() % BLOCK) % BLOCK;
        out.extend(std::iter::repeat_n(0u8, pad));
    }

    /// Encode a whole container, end-of-archive blocks included.
    pub fn tar_of(specs: &[Spec<'_>]) -> Vec<u8> {
        let mut out = Vec::new();
        for s in specs {
            if !s.pax.is_empty() {
                let mut rec = String::new();
                for (k, v) in &s.pax {
                    // The length counts itself, so it is solved for:
                    // start from the record without it and grow until
                    // the printed width stops changing.
                    let body = format!(" {k}={v}\n");
                    let mut len = body.len() + 1;
                    while format!("{len}").len() + body.len() != len {
                        len = format!("{len}").len() + body.len();
                    }
                    rec.push_str(&format!("{len}{body}"));
                }
                push_member(&mut out, "PaxHeader", rec.as_bytes(), b'x', s.gnu, false);
            }
            if let Some(long) = s.long_name {
                let mut n = long.as_bytes().to_vec();
                n.push(0);
                push_member(&mut out, "././@LongLink", &n, b'L', s.gnu, false);
            }
            push_member(&mut out, s.name, s.data, s.typeflag, s.gnu, s.bad_checksum);
        }
        out.extend(std::iter::repeat_n(0u8, BLOCK * 2));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{Spec, tar_of};
    use super::*;

    fn read_all(arch: &[u8]) -> Result<Vec<(String, Kind, Vec<u8>)>, TarError> {
        let mut r = Reader::new(io::Cursor::new(arch.to_vec()), arch.len() as u64);
        let mut out = Vec::new();
        while let Some(e) = r.next_entry()? {
            let mut body = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = r.read_data(&mut buf)?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..n]);
            }
            out.push((e.name, e.kind, body));
        }
        Ok(out)
    }

    /// The ordinary shape: two files and a directory, POSIX ustar,
    /// contents byte-exact and in archive order.
    #[test]
    fn reads_a_plain_ustar_archive() {
        let a = vec![7u8; 1000];
        let b = vec![9u8; 513];
        let arch = tar_of(&[
            Spec::file("a.bin", &a),
            Spec::dir("sub/"),
            Spec::file("sub/b.bin", &b),
        ]);
        let got = read_all(&arch).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], ("a.bin".into(), Kind::File, a));
        assert_eq!(got[1], ("sub".into(), Kind::Dir, Vec::new()));
        assert_eq!(got[2], ("sub/b.bin".into(), Kind::File, b));
    }

    /// An empty member is a real output, not a skip: the header is
    /// there, the data range is zero long, and the next header follows
    /// immediately with no padding between them.
    #[test]
    fn reads_an_empty_member() {
        let arch = tar_of(&[Spec::file("empty", b""), Spec::file("x", b"hello")]);
        let got = read_all(&arch).unwrap();
        assert_eq!(got[0], ("empty".into(), Kind::File, Vec::new()));
        assert_eq!(got[1].2, b"hello".to_vec());
    }

    /// Both long-name spellings resolve to the same name, and GNU's
    /// magic is read as readily as POSIX's.
    #[test]
    fn reads_long_names_both_ways() {
        let long = format!("deep/{}/payload.mkv", "x".repeat(150));
        let data = vec![3u8; 600];
        let gnu = tar_of(&[Spec {
            gnu: true,
            long_name: Some(&long),
            ..Spec::file(&long[..100], &data)
        }]);
        let pax = tar_of(&[Spec {
            pax: vec![("path".to_string(), long.clone())],
            ..Spec::file(&long[..100], &data)
        }]);
        for (tag, arch) in [("gnu", gnu), ("pax", pax)] {
            let got = read_all(&arch).unwrap();
            assert_eq!(got.len(), 1, "{tag}");
            assert_eq!(got[0].0, long, "{tag}");
            assert_eq!(got[0].2, data, "{tag}");
        }
    }

    /// Re-stamp the checksum of the header block a test has edited in
    /// place - every field but the checksum itself is covered by it.
    fn rechecksum(arch: &mut [u8]) {
        arch[OFF_CHKSUM..OFF_CHKSUM + 8].fill(b' ');
        let sum: u64 = arch[..BLOCK].iter().map(|&b| b as u64).sum();
        arch[OFF_CHKSUM..OFF_CHKSUM + 8].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }

    /// ustar's own `prefix` field joins back onto `name` with a `/`.
    #[test]
    fn joins_the_ustar_prefix() {
        let data = vec![1u8; 20];
        let mut arch = tar_of(&[Spec::file("payload.mkv", &data)]);
        arch[OFF_PREFIX..OFF_PREFIX + 7].copy_from_slice(b"Release");
        rechecksum(&mut arch);
        let got = read_all(&arch).unwrap();
        assert_eq!(got[0].0, "Release/payload.mkv");
    }

    /// A reference member is reported as one - the extractor turns that
    /// into a demote, and the word it prints comes from here.
    #[test]
    fn names_reference_members() {
        for (flag, word) in [
            (b'2', "symlink"),
            (b'1', "hard link"),
            (b'3', "device node"),
            (b'6', "FIFO"),
        ] {
            let arch = tar_of(&[Spec::special("link", flag)]);
            let got = read_all(&arch).unwrap();
            assert_eq!(got[0].1, Kind::Reference(word), "{}", flag as char);
        }
    }

    /// Sparse members are refused, in both spellings - the GNU `S`
    /// typeflag and the pax keyword that hides one behind an ordinary
    /// file header.
    #[test]
    fn refuses_sparse_members() {
        let flagged = tar_of(&[Spec::special("sparse.img", b'S')]);
        let err = read_all(&flagged).unwrap_err();
        assert!(format!("{err}").contains("sparse"), "{err}");

        let paxed = tar_of(&[Spec {
            pax: vec![
                ("GNU.sparse.major".to_string(), "1".to_string()),
                ("GNU.sparse.size".to_string(), "1099511627776".to_string()),
            ],
            ..Spec::file("sparse.img", b"\0\0\0\0")
        }]);
        let err = read_all(&paxed).unwrap_err();
        assert!(format!("{err}").contains("sparse"), "{err}");
    }

    /// A damaged header is refused rather than read past: the checksum
    /// is the only integrity the format offers.
    #[test]
    fn refuses_a_bad_checksum() {
        let arch = tar_of(&[Spec {
            bad_checksum: true,
            ..Spec::file("a.bin", b"12345")
        }]);
        let err = read_all(&arch).unwrap_err();
        assert!(format!("{err}").contains("checksum"), "{err}");
    }

    /// A member whose declared size runs past the container is refused
    /// at its header. Without this the reader would block for ever on
    /// bytes the wire will never carry, which on a chase is the
    /// difference between a demote and a wedged job.
    #[test]
    fn refuses_a_size_past_the_end() {
        let mut arch = tar_of(&[Spec::file("a.bin", b"12345")]);
        // 10 GB claimed by a 1.5 KB container.
        arch[OFF_SIZE..OFF_SIZE + 12].copy_from_slice(b"00123145000\0");
        rechecksum(&mut arch);
        let total = arch.len() as u64;
        let mut r = Reader::new(io::Cursor::new(arch), total);
        let err = r.next_entry().unwrap_err();
        assert!(format!("{err}").contains("runs past"), "{err}");
    }

    /// Base-256 sizes (GNU's escape from the 8 GB octal ceiling) parse,
    /// and a negative one is refused rather than wrapped.
    #[test]
    fn reads_base256_sizes() {
        let mut b = [0u8; BLOCK];
        b[OFF_SIZE] = 0x80;
        b[OFF_SIZE + 11] = 5;
        assert_eq!(read_size(&b), Some(5));
        b[OFF_SIZE + 4] = 1;
        assert_eq!(read_size(&b), Some(5 + (1u64 << 56)));
        b[OFF_SIZE] = 0xff;
        assert_eq!(read_size(&b), None);
    }

    /// The end-of-archive marker stops the walk, and trailing bytes
    /// behind it are never parsed.
    #[test]
    fn stops_at_the_end_marker() {
        let mut arch = tar_of(&[Spec::file("a.bin", b"hi")]);
        arch.extend_from_slice(&[0x41u8; BLOCK]);
        let got = read_all(&arch).unwrap();
        assert_eq!(got.len(), 1);
    }

    /// An archive cut between members reports it. Every member before
    /// the cut is well-formed, so nothing else can tell the difference
    /// and a reader that does not ask calls a truncated archive whole.
    #[test]
    fn reports_a_container_cut_between_members() {
        let arch = tar_of(&[Spec::file("a.bin", b"hi"), Spec::file("b.bin", b"there")]);
        let whole = arch.len();
        let mut r = Reader::new(io::Cursor::new(arch.clone()), whole as u64);
        while r.next_entry().unwrap().is_some() {}
        assert!(r.saw_end_marker());

        // Cut after the first member, on a block boundary.
        let cut = BLOCK * 2;
        let mut r = Reader::new(io::Cursor::new(arch[..cut].to_vec()), cut as u64);
        assert_eq!(r.next_entry().unwrap().unwrap().name, "a.bin");
        assert!(r.next_entry().unwrap().is_none());
        assert!(
            !r.saw_end_marker(),
            "a cut container must not read as ended"
        );
    }

    /// The sniff: strong with a whole block (magic AND checksum), weak
    /// but honest with only the magic window, and no on anything that
    /// carries neither. A `.tar.gz` is the case that matters - its
    /// gzip magic sits at offset 0 and there is no ustar at 257.
    #[test]
    fn sniffs_only_real_tar_headers() {
        let arch = tar_of(&[Spec::file("a.bin", b"hi")]);
        assert!(looks_like_tar(&arch));
        assert!(looks_like_tar(&arch[..SNIFF_MIN]));
        assert!(!looks_like_tar(&arch[..SNIFF_MIN - 1]));

        let mut damaged = arch.clone();
        damaged[OFF_CHKSUM] = b'9';
        assert!(!looks_like_tar(&damaged), "checksum must gate a full block");
        assert!(
            looks_like_tar(&damaged[..SNIFF_MIN]),
            "the short sniff has no checksum to check"
        );

        let mut no_magic = arch.clone();
        no_magic[OFF_MAGIC] = b'X';
        assert!(!looks_like_tar(&no_magic));
        assert!(!looks_like_tar(b"\x1f\x8b\x08\x00 gzip, not tar"));
        assert!(!looks_like_tar(&[0u8; BLOCK]));
    }

    /// Names: `.tar` and obfuscated (extensionless) only. Everything
    /// that already announces itself as something else is left alone,
    /// compressed tarballs included - they are not this format.
    #[test]
    fn tar_chase_name_eligibility() {
        for n in ["Movie.TAR", "release.tar", "a3f9c1d2e"] {
            assert!(chase_eligible_name(n), "{n}");
        }
        for n in [
            "movie.tar.gz",
            "movie.tgz",
            "movie.tar.001",
            "movie.zip",
            "movie.rar",
            "comic.cbr",
            "payload.mkv",
        ] {
            assert!(!chase_eligible_name(n), "{n}");
        }
    }

    /// The member ceiling is enforced, so a container that spends 512
    /// bytes per member cannot open an unbounded number of outputs.
    #[test]
    fn refuses_more_members_than_the_ceiling() {
        let specs: Vec<Spec<'_>> = (0..3).map(|_| Spec::file("x", b"")).collect();
        let arch = tar_of(&specs);
        let mut r = Reader::new(io::Cursor::new(arch.clone()), arch.len() as u64);
        r.entries = MAX_ENTRIES - 1;
        assert!(r.next_entry().is_ok());
        let err = r.next_entry().unwrap_err();
        assert!(format!("{err}").contains("members"), "{err}");
    }
}
