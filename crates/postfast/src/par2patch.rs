//! Byte-level PAR2 packet surgery: the shapes no conforming creator
//! will write, patched into a set after it is built.
//!
//! Ported from `crates/nzbfast/tests/e2e_norar/mod.rs` (`packets`,
//! `reseal`, `filedesc_name`, `rename_filedesc`, `empty_filedesc`) and
//! `e2e_norar/encoding.rs` (`rename_filedesc_raw`). Those live inside
//! one test BINARY and no other target can reach them; the catalog
//! needs the same operations as data-driven planes, so they move here
//! and the e2e copies retire with chip 08. The rules below are the
//! ported ones, unchanged - this is a move, not a redesign, and a
//! second spelling of a packet layout is the last thing this repo
//! needs.
//!
//! **The one invariant every operation here preserves: the packet
//! LENGTH.** A replacement name is null-padded into the region the old
//! name occupied, so no offset in the file moves and, crucially, no
//! file id changes. PAR2 derives a file id from
//! `MD5(md5_16k ‖ length ‖ padded name)`, but readers key Main,
//! FileDesc and IFSC packets by the id as STORED and nobody
//! recomputes it (`nzbkit::par2` says so at its own parser), so a
//! patched name and an unpatched id are exactly the shape a hostile or
//! renamed post has in the wild. An operation that resized a packet
//! would have to rewrite every id in the set and would be building a
//! different fixture than the one these rows are about.
//!
//! **Every body edit is followed by [`reseal`]**, which recomputes the
//! packet checksum at offset 16 (MD5 of set-id ‖ type ‖ body). Without
//! it the client's own parser drops the packet as damaged and the row
//! silently tests packet rejection instead of the shape it names.
//!
//! Nothing here validates that a patched name is one a client SHOULD
//! honour: `../evil.bin` and a name that duplicates another member's
//! are both deliberate inputs. Which of those a profile may select,
//! and what end state it may then declare, is [`crate::recovery`]'s
//! decision, not this module's.

use nzbkit::md5fast::{Digest, Md5};

/// PAR2 packet type of a File Description packet.
const TYPE_FILEDESC: &[u8; 16] = b"PAR 2.0\0FileDesc";
/// PAR2 packet type of an Input File Slice Checksum packet.
const TYPE_IFSC: &[u8; 16] = b"PAR 2.0\0IFSC\0\0\0\0";

/// Offset of the packet checksum within a packet: magic (8) ‖ length
/// (8) ‖ MD5 (16) ‖ set id (16) ‖ type (16), then the body.
const OFF_MD5: usize = 16;
/// Where the checksummed region starts: set id onwards.
const OFF_SEALED: usize = 32;
/// Where a packet body starts.
const HEAD: usize = 64;
/// Offset of the file id inside a FileDesc or IFSC body, from the
/// packet start.
const OFF_FILE_ID: usize = HEAD;
/// Offsets inside a FileDesc body, from the packet start: whole-file
/// MD5, first-16 KiB MD5, length, then the null-padded name.
const OFF_MD5_WHOLE: usize = HEAD + 16;
const OFF_MD5_16K: usize = HEAD + 32;
const OFF_LENGTH: usize = HEAD + 48;
const OFF_NAME: usize = HEAD + 56;

/// `(start, total length, type)` of every structurally valid packet in
/// `data`, in file order.
///
/// Scans for the magic rather than walking lengths from zero, because
/// a `.par2` file is a concatenation of packets with no container
/// header and a set built by any creator may hold bytes this walk
/// should skip. A length that does not fit the buffer is not a packet;
/// the scan resumes one byte on, exactly as the ported original does.
pub fn packets(data: &[u8]) -> Vec<(usize, usize, [u8; 16])> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + HEAD <= data.len() {
        let Some(rel) = data[off..].windows(8).position(|w| w == b"PAR2\0PKT") else {
            break;
        };
        let start = off + rel;
        if start + HEAD > data.len() {
            break;
        }
        let len = u64::from_le_bytes(data[start + 8..start + 16].try_into().unwrap()) as usize;
        if len < HEAD || start + len > data.len() {
            off = start + 1;
            continue;
        }
        out.push((
            start,
            len,
            data[start + 48..start + HEAD].try_into().unwrap(),
        ));
        off = start + len;
    }
    out
}

/// Recompute one packet's checksum after a body edit.
///
/// The checksum covers set id ‖ type ‖ body, which is everything from
/// offset 32 to the end of the packet. Call this after EVERY edit
/// below, or the parser drops the packet.
pub fn reseal(data: &mut [u8], start: usize, len: usize) {
    let sum: [u8; 16] = Md5::digest(&data[start + OFF_SEALED..start + len]).into();
    data[start + OFF_MD5..start + OFF_SEALED].copy_from_slice(&sum);
}

/// Whether a packet still agrees with its own checksum.
///
/// The inverse of [`reseal`], over the same region, and the only place
/// the seal is CHECKED. `crate::fault` damages packets deliberately and
/// leaves the checksum alone, which is what turns an edit into damage;
/// a test that asserted the damage by recomputing the MD5 itself would
/// be a second copy of the arithmetic above, free to agree with a wrong
/// answer.
pub fn is_sealed(data: &[u8], start: usize, len: usize) -> bool {
    let want: [u8; 16] = Md5::digest(&data[start + OFF_SEALED..start + len]).into();
    data[start + OFF_MD5..start + OFF_SEALED] == want
}

/// The raw name bytes of a FileDesc packet: the tail of the body with
/// its null padding trimmed. Not necessarily UTF-8 (row M4-86 posts a
/// CP1252 name deliberately), which is why the byte form exists.
pub fn filedesc_name_bytes(data: &[u8], start: usize, len: usize) -> &[u8] {
    let raw = &data[start + OFF_NAME..start + len];
    let end = raw.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &raw[..end]
}

/// [`filedesc_name_bytes`] as a lossy `String`, which is how a name is
/// MATCHED here: a patch says which name to replace, and a name that is
/// not UTF-8 can still be named by its lossy spelling.
pub fn filedesc_name(data: &[u8], start: usize, len: usize) -> String {
    String::from_utf8_lossy(filedesc_name_bytes(data, start, len)).into_owned()
}

/// Why a patch could not be applied. Returned rather than asserted:
/// this is library code reached from a profile, and a profile that asks
/// for the impossible deserves a message naming the profile, not a
/// panic in somebody else's test run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchError {
    /// The replacement name does not fit the region the old one
    /// occupied, and growing the packet would move every offset after
    /// it and invalidate every file id in the set.
    NameTooLong {
        name: String,
        len: usize,
        region: usize,
    },
    /// No FileDesc in the set carries the name the patch names. Failing
    /// to find is failing: a patch that matched nothing would leave the
    /// set unpatched and the row would test the shape it was written to
    /// replace.
    NoSuchMember(String),
}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameTooLong { name, len, region } => write!(
                f,
                "the patched name {name:?} is {len} bytes and the FileDesc name region is \
                 {region}: a patch may not resize a packet, because every file id in the \
                 set is keyed by offset. Give the member a longer name in [source], or a \
                 shorter one here"
            ),
            Self::NoSuchMember(n) => write!(
                f,
                "no FileDesc in this set is named {n:?}, so the patch would have left the \
                 set exactly as the creator wrote it"
            ),
        }
    }
}

impl std::error::Error for PatchError {}

/// Rewrite every FileDesc named `from` to carry `to` instead.
///
/// Returns how many packets moved, which is normally more than one: a
/// set repeats its critical packets in every volume file, and this is
/// called per file, so a caller patching a whole set sums across it.
///
/// `to` is null-padded into the old region; see the module header for
/// why the packet may not grow.
pub fn rename_filedesc(data: &mut [u8], from: &str, to: &str) -> Result<usize, PatchError> {
    rename_filedesc_raw(data, from, to.as_bytes())
}

/// [`rename_filedesc`] over RAW bytes, for a name that is not valid
/// UTF-8 and so cannot be spelled as a `&str` at all.
///
/// Row M4-86 is the shape: a CP1252 `caf\xE9.mkv` where the UTF-8
/// spelling would be `caf\xC3\xA9.mkv`. Kept here rather than in the
/// naming plane because it is the same packet edit, and because the
/// plane that will select it (N7, `[naming] name_bytes = "raw"`) is
/// chip 10's - the operation lands with its siblings so that chip
/// writes a plane and not a patcher.
pub fn rename_filedesc_raw(data: &mut [u8], from: &str, to: &[u8]) -> Result<usize, PatchError> {
    let mut hits = 0;
    for (start, len, ptype) in packets(data) {
        if &ptype != TYPE_FILEDESC || filedesc_name(data, start, len) != from {
            continue;
        }
        let region = len - OFF_NAME;
        if to.len() > region {
            return Err(PatchError::NameTooLong {
                name: String::from_utf8_lossy(to).into_owned(),
                len: to.len(),
                region,
            });
        }
        data[start + OFF_NAME..start + len].fill(0);
        data[start + OFF_NAME..start + OFF_NAME + to.len()].copy_from_slice(to);
        reseal(data, start, len);
        hits += 1;
    }
    if hits == 0 {
        return Err(PatchError::NoSuchMember(from.to_string()));
    }
    Ok(hits)
}

/// Turn the member named `name` into a 0-BYTE file: length 0, both MD5
/// fields the MD5 of the empty string, and its IFSC packets spliced
/// out, which is what a creator emits for an empty file (there are no
/// slices to checksum).
///
/// The file id is left as the creator minted it from the placeholder's
/// bytes, for the reason in the module header: readers use the stored
/// id.
///
/// `nzbkit::par2gen` describes a genuinely empty member correctly and
/// needs none of this - it exists precisely because par2cmdline prints
/// "Skipping 0 byte file" and omits the member outright (matrix
/// finding F3). So this is the operation for a set built by SOMETHING
/// ELSE: the conformance harness's par2cmdline arm, and the e2e rows
/// until chip 08 retires them. `[recovery] zero_byte_member` goes
/// through par2gen and does not call it.
pub fn empty_filedesc(data: &mut Vec<u8>, name: &str) -> Result<usize, PatchError> {
    let empty: [u8; 16] = Md5::digest(b"").into();
    let mut fid: Option<[u8; 16]> = None;
    let mut hits = 0;
    for (start, len, ptype) in packets(data) {
        if &ptype != TYPE_FILEDESC || filedesc_name(data, start, len) != name {
            continue;
        }
        fid = Some(
            data[start + OFF_FILE_ID..start + OFF_FILE_ID + 16]
                .try_into()
                .unwrap(),
        );
        data[start + OFF_MD5_WHOLE..start + OFF_MD5_WHOLE + 16].copy_from_slice(&empty);
        data[start + OFF_MD5_16K..start + OFF_MD5_16K + 16].copy_from_slice(&empty);
        data[start + OFF_LENGTH..start + OFF_LENGTH + 8].copy_from_slice(&0u64.to_le_bytes());
        reseal(data, start, len);
        hits += 1;
    }
    let Some(fid) = fid else {
        return Err(PatchError::NoSuchMember(name.to_string()));
    };
    // Splice the placeholder's IFSC packets out, back to front so every
    // recorded offset stays valid while the drain walks.
    let mut spans: Vec<(usize, usize)> = packets(data)
        .into_iter()
        .filter(|&(s, l, t)| {
            &t == TYPE_IFSC
                && l >= OFF_MD5_WHOLE
                && data[s + OFF_FILE_ID..s + OFF_FILE_ID + 16] == fid
        })
        .map(|(s, l, _)| (s, l))
        .collect();
    spans.reverse();
    for (s, l) in spans {
        data.drain(s..s + l);
    }
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;

    /// A real set over two members, built the way the recovery plane
    /// builds one, so every operation below is exercised against bytes
    /// a creator actually wrote rather than against a hand-rolled
    /// packet. Returns the index file's bytes.
    fn a_set(names: &[(&str, usize)], redundancy: u32) -> Vec<u8> {
        let files: Vec<String> = names
            .iter()
            .map(|(n, b)| format!("{{ name = \"{n}\", bytes = {b} }}"))
            .collect();
        let text = format!(
            "[layout]\nname = \"patch\"\nseed = 3\n\n[source]\nfiles = [{}]\n\n\
             [recovery]\nkind = \"par2\"\nredundancy_pct = {redundancy}\n",
            files.join(", ")
        );
        let p = Profile::parse(&text).expect("test profile parses");
        let mut rng = crate::Rng::for_profile(&p);
        let s = crate::assemble::sources(&p, &mut rng).expect("sources assemble");
        crate::recovery::build(&p, &s)
            .expect("the set builds")
            .files[0]
            .bytes
            .clone()
    }

    fn names_in(data: &[u8]) -> Vec<String> {
        packets(data)
            .into_iter()
            .filter(|(_, _, t)| t == TYPE_FILEDESC)
            .map(|(s, l, _)| filedesc_name(data, s, l))
            .collect()
    }

    /// The walk finds the packets a creator wrote, and finds every
    /// FileDesc: failing to find is failing, and every operation below
    /// is built on this one.
    #[test]
    fn the_walk_finds_every_filedesc_a_creator_wrote() {
        let d = a_set(&[("alpha.bin", 8192), ("beta.bin", 4096)], 0);
        let mut n = names_in(&d);
        n.sort();
        assert_eq!(n, vec!["alpha.bin", "beta.bin"]);
        // Main and Creator are there too, so the walk is not seeing
        // only the type it was asked about.
        let types: Vec<[u8; 16]> = packets(&d).into_iter().map(|(_, _, t)| t).collect();
        assert!(types.contains(b"PAR 2.0\0Main\0\0\0\0"), "{types:?}");
    }

    /// A rename moves the name, keeps the packet length, keeps the
    /// stored file id, and leaves a packet the parser still accepts.
    #[test]
    fn a_rename_keeps_the_length_the_id_and_the_seal() {
        let mut d = a_set(&[("original.bin", 8192)], 0);
        let before: Vec<(usize, usize)> = packets(&d).iter().map(|&(s, l, _)| (s, l)).collect();
        let ids: Vec<Vec<u8>> = packets(&d)
            .iter()
            .map(|&(s, _, _)| d[s + OFF_FILE_ID..s + OFF_FILE_ID + 16].to_vec())
            .collect();
        let hits = rename_filedesc(&mut d, "original.bin", "renamed.bin").expect("patches");
        assert!(hits >= 1);
        assert_eq!(names_in(&d), vec!["renamed.bin"]);
        let after: Vec<(usize, usize)> = packets(&d).iter().map(|&(s, l, _)| (s, l)).collect();
        assert_eq!(before, after, "a patch may not move or resize a packet");
        let ids_after: Vec<Vec<u8>> = packets(&d)
            .iter()
            .map(|&(s, _, _)| d[s + OFF_FILE_ID..s + OFF_FILE_ID + 16].to_vec())
            .collect();
        assert_eq!(ids, ids_after, "the stored file id is what readers key on");
        // The seal: the client's own parser reads the patched set.
        assert!(
            nzbkit::par2::Par2Set::parse(&[&d]).is_ok(),
            "the patched set no longer parses, so the row would be testing packet rejection"
        );
    }

    /// The reseal is what makes that true: without it the parser drops
    /// the packet. Written as a control arm, because a patch that
    /// forgot to reseal would pass every assertion above about lengths
    /// and ids.
    #[test]
    fn a_patch_without_the_reseal_is_a_damaged_packet() {
        let mut d = a_set(&[("original.bin", 8192)], 0);
        let (start, len, _) = packets(&d)
            .into_iter()
            .find(|(_, _, t)| t == TYPE_FILEDESC)
            .expect("a FileDesc exists");
        let sealed = d[start + OFF_MD5..start + OFF_SEALED].to_vec();
        d[start + OFF_NAME..start + len].fill(0);
        d[start + OFF_NAME..start + OFF_NAME + 5].copy_from_slice(b"x.bin");
        assert_eq!(
            d[start + OFF_MD5..start + OFF_SEALED],
            sealed[..],
            "the checksum is stale until reseal runs"
        );
        reseal(&mut d, start, len);
        assert_ne!(
            d[start + OFF_MD5..start + OFF_SEALED],
            sealed[..],
            "reseal must move the checksum"
        );
    }

    /// P6, the DUPLICATE shape: two members patched to one name. The
    /// operation supports it; whether a profile may SELECT it is
    /// `crate::recovery`'s call, and it says no because the end state
    /// is the client's answer rather than a requirement.
    #[test]
    fn two_members_can_be_patched_to_one_name() {
        let mut d = a_set(&[("dupXa.bin", 4096), ("dupXb.bin", 4096)], 0);
        rename_filedesc(&mut d, "dupXa.bin", "dupfil.bin").expect("patches");
        rename_filedesc(&mut d, "dupXb.bin", "dupfil.bin").expect("patches");
        assert_eq!(names_in(&d), vec!["dupfil.bin", "dupfil.bin"]);
        assert!(nzbkit::par2::Par2Set::parse(&[&d]).is_ok());
    }

    /// P6, the TRAVERSAL shape, and the same answer: the operation
    /// writes whatever it is given.
    #[test]
    fn a_traversal_name_patches_like_any_other() {
        let mut d = a_set(&[("harmless-name.bin", 4096)], 0);
        rename_filedesc(&mut d, "harmless-name.bin", "../evil.bin").expect("patches");
        assert_eq!(names_in(&d), vec!["../evil.bin"]);
    }

    /// M4-86: a name that is not UTF-8 at all. One byte where the UTF-8
    /// spelling has two, so the region and every id are untouched.
    #[test]
    fn a_raw_name_survives_as_bytes() {
        let mut d = a_set(&[("caf\u{e9}.mkv", 4096)], 0);
        rename_filedesc_raw(&mut d, "caf\u{e9}.mkv", b"caf\xE9.mkv").expect("patches");
        let (s, l, _) = packets(&d)
            .into_iter()
            .find(|(_, _, t)| t == TYPE_FILEDESC)
            .expect("a FileDesc exists");
        assert_eq!(filedesc_name_bytes(&d, s, l), b"caf\xE9.mkv");
        // ...and the lossy spelling is not the raw one, which is what
        // makes this a different shape from a plain rename.
        assert_ne!(filedesc_name(&d, s, l), "caf\u{e9}.mkv");
    }

    /// A name that does not fit is refused with the two numbers, not
    /// asserted: growing the packet would move every offset after it.
    #[test]
    fn a_name_too_long_for_its_region_is_refused_with_both_numbers() {
        let mut d = a_set(&[("s.bin", 4096)], 0);
        let long = "x".repeat(4096);
        match rename_filedesc(&mut d, "s.bin", &long) {
            Err(PatchError::NameTooLong { len, region, .. }) => {
                assert_eq!(len, 4096);
                assert!(region < 4096, "region {region}");
            }
            other => panic!("expected NameTooLong, got {other:?}"),
        }
    }

    /// Failing to find is failing: a patch that matched nothing would
    /// leave the set exactly as the creator wrote it and the row would
    /// silently test the shape it was written to replace.
    #[test]
    fn a_patch_that_matches_nothing_is_an_error() {
        let mut d = a_set(&[("s.bin", 4096)], 0);
        assert_eq!(
            rename_filedesc(&mut d, "absent.bin", "x.bin"),
            Err(PatchError::NoSuchMember("absent.bin".into()))
        );
        assert_eq!(
            empty_filedesc(&mut d, "absent.bin"),
            Err(PatchError::NoSuchMember("absent.bin".into()))
        );
    }

    /// The 0-byte patch: length and both MD5 fields become the empty
    /// file's, and the member's slice checksums go away, because a real
    /// creator emits none for a file with no slices.
    #[test]
    fn the_zero_byte_patch_empties_the_descriptor_and_drops_its_ifsc() {
        let mut d = a_set(&[("keep.bin", 8192), ("placeholder.bin", 1)], 0);
        let ifsc_before = packets(&d)
            .into_iter()
            .filter(|(_, _, t)| t == TYPE_IFSC)
            .count();
        empty_filedesc(&mut d, "placeholder.bin").expect("patches");
        let (s, l, _) = packets(&d)
            .into_iter()
            .find(|&(s, l, t)| &t == TYPE_FILEDESC && filedesc_name(&d, s, l) == "placeholder.bin")
            .expect("the placeholder is still described");
        assert_eq!(
            u64::from_le_bytes(d[s + OFF_LENGTH..s + OFF_LENGTH + 8].try_into().unwrap()),
            0
        );
        let empty: [u8; 16] = Md5::digest(b"").into();
        assert_eq!(d[s + OFF_MD5_WHOLE..s + OFF_MD5_WHOLE + 16], empty);
        assert_eq!(d[s + OFF_MD5_16K..s + OFF_MD5_16K + 16], empty);
        let _ = l;
        let ifsc_after = packets(&d)
            .into_iter()
            .filter(|(_, _, t)| t == TYPE_IFSC)
            .count();
        assert_eq!(
            ifsc_after,
            ifsc_before - 1,
            "exactly the placeholder's slice checksums go"
        );
        assert!(
            nzbkit::par2::Par2Set::parse(&[&d]).is_ok(),
            "the patched set must still parse"
        );
        // The other member is untouched: a splice that took a byte too
        // many would corrupt whatever followed it.
        assert!(names_in(&d).contains(&"keep.bin".to_string()));
    }
}
