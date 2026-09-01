//! The bound on the two ID-ONLY set reads: [`set_id_at`] and the
//! constant it takes.
//!
//! `set_id_of` is not "read the first packet header" - it TALLIES every
//! complete packet in the buffer and picks by (a unique Main packet,
//! then total bytes, then packet count), so how much of the file is
//! offered is part of the question. That is what these pin: that the
//! head really is a head, that a first packet longer than it does not
//! silently answer `None`, and that the constant still clears the block
//! sizes the measurement was taken against.

use super::*;

/// One structurally valid PAR2 packet: 8 magic, 8 length, 16 MD5,
/// 16 set id, 16 type, body. `packet_spans` never checks the MD5 - it is
/// a framing pass - so zeros there are exactly as visible as a real one,
/// which is why this fixture can be built without hashing anything.
fn pkt(id: [u8; 16], ty: &[u8; 16], body_len: usize) -> Vec<u8> {
    let len = 64 + body_len;
    let mut p = Vec::with_capacity(len);
    p.extend_from_slice(nzbkit::par2::MAGIC);
    p.extend_from_slice(&(len as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(&id);
    p.extend_from_slice(ty);
    p.resize(len, 0);
    p
}

const RECV: &[u8; 16] = b"PAR 2.0\0RecvSlic";
const MAIN: &[u8; 16] = b"PAR 2.0\0Main\0\0\0\0";

/// A scratch directory that removes itself. `tempfile` is not a
/// dependency of this crate's own unit tests (only of the integration
/// targets), so this is the in-crate idiom `get::dupefill_tests` and
/// `resumeout` already use: `std::env::temp_dir()` plus a per-TEST name,
/// unique per test and not merely per process, because these run
/// concurrently in one binary.
struct TmpDir(std::path::PathBuf);

impl TmpDir {
    fn new(name: &str) -> TmpDir {
        let d = std::env::temp_dir().join(format!("nzbfast-setid-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch dir");
        TmpDir(d)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).expect("fixture written");
    p
}

/// THE BOUND IS REAL, and this is the case that proves it rather than
/// assuming it: a file whose head is set A's and whose TAIL carries more
/// of set B than the whole file has of A. An unbounded read tallies B
/// (more bytes) and a bounded one never sees it, so the two answers
/// DISAGREE by construction - which is the only way a test can tell a
/// bounded read from a lucky one. Revert either call site to
/// `std::fs::read` and this fails.
///
/// It is also the stated limit of `set_id_at` written as an assertion: a
/// real par2 file carries one set's packets, so nothing reachable posts
/// this shape, and the head's answer is the one that stands.
#[test]
fn a_bounded_id_read_answers_off_the_head_and_never_the_tail() {
    let dir = TmpDir::new("mixed");
    let a = [0xA1u8; 16];
    let b = [0xB2u8; 16];

    let cap = 4096usize;
    let mut bytes = pkt(a, RECV, 512);
    bytes.resize(cap, 0);
    // Past the head, and heavier than everything in front of it.
    for _ in 0..4 {
        bytes.extend(pkt(b, RECV, 4096));
    }
    let path = write(dir.path(), "mixed.par2", &bytes);

    assert_eq!(
        set_id_at(&path, cap),
        Some(a),
        "the bounded read must answer off the first `cap` bytes"
    );
    assert_eq!(
        nzbkit::par2::Par2Set::set_id_of(&std::fs::read(&path).unwrap()),
        Some(b),
        "the fixture is only worth anything while the whole-file answer \
         differs - if this ever equals `a` the test above proves nothing"
    );
}

/// The measured large-block case, and the reason `set_id_at` has a
/// fallback at all. par2cmdline writes a recovery VOLUME opening with a
/// full recovery slice packet and interleaves the critical packets after
/// it, so the first complete packet is `block_size + 68` bytes. A head
/// that lands inside it finds NO complete packet, and without the
/// fallback `set_id_of` would answer `None` - which `main_par2_for`
/// reads as "not this set's index", silently, on a post whose only sin
/// is a big block size.
///
/// Delete the fallback in `set_id_at` and this fails.
#[test]
fn a_first_packet_longer_than_the_head_still_reads_its_id() {
    let dir = TmpDir::new("bigblock");
    let b = [0xC3u8; 16];
    // One slice packet far longer than the head it will be read under,
    // then the interleaved Main - the real layout in miniature.
    let mut bytes = pkt(b, RECV, 8192);
    bytes.extend(pkt(b, MAIN, 24));
    let path = write(dir.path(), "bigblock.par2", &bytes);

    assert_eq!(
        set_id_at(&path, 1024),
        Some(b),
        "a head inside the first packet must fall back, not answer None"
    );
}

/// A SHORT file returns straight away rather than re-reading itself, and
/// a file with no packet in it is `None` either way. The first is the
/// only thing separating the fallback from "read every file twice".
#[test]
fn a_short_file_and_a_non_par2_file_need_no_second_read() {
    let dir = TmpDir::new("short");
    let junk = write(dir.path(), "notpar2.bin", &[0x5Au8; 512]);
    assert_eq!(set_id_at(&junk, 1 << 20), None);

    let d = [0xD4u8; 16];
    let small = write(dir.path(), "small.par2", &pkt(d, MAIN, 16));
    assert_eq!(set_id_at(&small, 1 << 20), Some(d));
}

/// The CONSTANT, held to the measurement its comment records. par2cmdline
/// 1.2.0 at `-s8388608` puts the first complete packet at 8,388,676
/// bytes; the floor here is the block size and not a packet header, so a
/// head shrunk toward that intuition reads no id on an ordinary volume
/// and takes the whole-file fallback on EVERY par2 file it is handed -
/// which is the slurp this change exists to remove, restored in silence.
#[test]
fn the_id_head_clears_the_block_sizes_it_was_measured_against() {
    assert!(
        SET_ID_HEAD >= (8 << 20) + 68,
        "SET_ID_HEAD must clear one 8 MiB recovery slice packet"
    );
}

/// The CALL SITES, which nothing above reaches. The four tests before
/// this one prove `set_id_at` bounds its read; none of them can see a
/// caller that stopped using it, and "four sites, four spellings, one
/// predicate" is how this item was found in the first place - a fifth
/// spelling is the failure mode, not a hypothetical.
///
/// So this is a source scan, the same shape
/// `tests/integration/settings_catalogue.rs` uses over the settings
/// files, and it pins the two things a behavioural test in this module
/// cannot:
///
/// * `main_par2_for`'s ownership test asks `set_id_at` and never
///   `set_id_of` - it wants a yes/no and returns a `PathBuf`, so it has
///   no reason to hold a volume at all.
/// * `replace_bootstrap_slice_counts` asks the ID BEFORE it reads the
///   file whole. That ordering IS the fix there: `slices_of` genuinely
///   needs every byte, so the read cannot go - what goes is reading it
///   for a set the bytes turn out not to belong to.
///
/// Revert either call site to `std::fs::read` and this fails. It is
/// deliberately narrow: it judges these two functions and says nothing
/// about the two resume sites, which read whole ON PURPOSE because
/// `usable_slices_of` counts slices across the WHOLE volume and a
/// bounded read there UNDERCOUNTS parity - the one error in this area
/// that is invisible, because the planner refetches volumes it has and
/// the repair still succeeds.
#[test]
fn both_id_only_sites_ask_the_bounded_reader() {
    /// The body of `fn`/`let` `name`, by brace balance from its first
    /// `{`. Bodies, not whole files, or the assertions below would pass
    /// on any file that happens to mention the right token somewhere.
    fn body<'a>(src: &'a str, name: &str) -> &'a str {
        let at = src.find(name).unwrap_or_else(|| panic!("{name} not found"));
        let open = src[at..].find('{').expect("a body") + at;
        let mut depth = 0usize;
        for (i, c) in src[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &src[open..open + i];
                    }
                }
                _ => {}
            }
        }
        panic!("{name}'s body does not close");
    }

    let repair = body(
        include_str!("../repair.rs"),
        "let main_par2_for = |set: &nzbkit::par2::Par2Set|",
    );
    assert!(
        repair.contains("set_id_at("),
        "main_par2_for must ask the bounded reader"
    );
    assert!(
        !repair.contains("set_id_of("),
        "main_par2_for wants a yes/no and returns a PathBuf - it has no \
         reason to read a volume whole to compare 16 bytes"
    );

    let boot = body(
        include_str!("../../settle.rs"),
        "fn replace_bootstrap_slice_counts(",
    );
    let id_at = boot.find("set_id_at(").expect("the bounded id read");
    // Spelled `read_volume_for_slices(` and not `fs::read(` since
    // 31 Aug 2026: the whole read is still whole - `slices_of` needs
    // every byte - but it now goes through `settle::volbytes`, which
    // charges it to `Sub::RepairScan` and refuses it past the engine's
    // own packet-file ceiling. This arm is about the ORDER and is
    // unchanged by that.
    let read = boot
        .find("read_volume_for_slices(")
        .expect("the whole read slices_of needs");
    assert!(
        id_at < read,
        "the id must be read BEFORE the file is read whole, or a \
         bootstrap belonging to another set is slurped and discarded"
    );
}
