//! Row M4-65's entry point at the [`super::has_unclaimed`] door: a
//! `.par2`-NAMED volume whose packet chain begins a few bytes in.
//!
//! [`super::has_par2_magic`] is the M4-52 content check on that door's
//! name test - "a NAME may nominate and only CONTENT may finalize" -
//! and until 31 Aug 2026 it read the magic at offset 0 exactly, while
//! every other reader in the product had moved to
//! [`nzbkit::par2::SNIFF_WINDOW`]. These pins are that disagreement
//! measured from both ends: what the other readers say about the very
//! file this door was calling unclaimed payload, and the two edges of
//! the window it now shares with them.
//!
//! WHY THE DOOR MATTERS is `super`'s own module note: before W4-01 it
//! could only ever open more often and never fail a job, and a vouched
//! late set can now take a job's success away. The second test here is
//! the constructed instance - a set that is vouched, published and
//! non-active, reached ONLY because a prefixed volume armed the door -
//! and it is deliberately a pin on the GATES rather than on a whole
//! repair, because what it has to say is that nothing downstream stands
//! between this door and that set.
//!
//! A sibling module rather than an append to `super`'s `tests`: several
//! lanes are appending to latesets.rs and the size gate is the shared
//! cost of that.

use super::{has_unclaimed, published_here, vouched};
use crate::testscratch::ScratchDir;
use md5::{Digest, Md5};
use nzbkit::par2;
use std::collections::HashSet;

/// The house scratch guard, so these fixtures are swept like every
/// other test's rather than being the next entry in the pile
/// `tests/scratch/mod.rs` was written to clear. The tag is per TEST
/// because `cargo test --bin nzbfast` puts them all in one process,
/// where the pid alone does not separate them.
fn scratch(tag: &str) -> ScratchDir {
    ScratchDir::attach(
        &std::env::temp_dir().join(format!("nzbfast-par2window-{tag}-{}", std::process::id())),
    )
}

/// A valid PAR2 packet: magic, header-inclusive length, body MD5, set
/// id, type. The same hand-built shape `get::dupefill_tests` uses, and
/// for the same reason - the packet types are fixed by the PAR2 2.0
/// spec, not by our parser, so spelling them here needs nothing made
/// `pub` in `nzbkit::par2`.
fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(par2::MAGIC);
    p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(&set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let md5: [u8; 16] = Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&md5);
    p
}

const TYPE_MAIN: &[u8; 16] = b"PAR 2.0\0Main\0\0\0\0";
const TYPE_FILEDESC: &[u8; 16] = b"PAR 2.0\0FileDesc";

/// Main + FileDesc for one member: everything that makes these bytes a
/// recovery SET rather than a buffer that merely opens with the magic.
/// No recovery slice, which is all these pins need - the question here
/// is what each reader CALLS the file, never whether a repair off it
/// would succeed.
fn index_of(set_id: [u8; 16], name: &str, data: &[u8]) -> Vec<u8> {
    let fid = [7u8; 16];
    let mut main = Vec::new();
    main.extend_from_slice(&4096u64.to_le_bytes());
    main.extend_from_slice(&1u32.to_le_bytes());
    main.extend_from_slice(&fid);
    let mut out = pkt(set_id, TYPE_MAIN, &main);
    let mut desc = Vec::new();
    desc.extend_from_slice(&fid);
    desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(data)));
    desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(
        &data[..data.len().min(16384)],
    )));
    desc.extend_from_slice(&(data.len() as u64).to_le_bytes());
    let mut nb = name.as_bytes().to_vec();
    while !nb.len().is_multiple_of(4) {
        nb.push(0);
    }
    desc.extend_from_slice(&nb);
    out.extend_from_slice(&pkt(set_id, TYPE_FILEDESC, &desc));
    out
}

/// The UTF-8 BOM, which is M4-65's documented example of how a volume
/// acquires a prefix: a producer that touched the file as text.
const BOM: &[u8] = b"\xef\xbb\xbf";

/// One file, four readers, and until 31 Aug 2026 this door was the
/// only one that disagreed.
///
/// The assertions are the OTHER readers first and this door last, on
/// purpose: the defect was never that the window is the right rule -
/// M4-65 settled that - it was that the pass opened on the premise a
/// file is unclaimed payload and then, on its very next statement,
/// handed the same path to `disk_sets_scoped` as parity. Both halves
/// are asserted here so a lane narrowing either one sees which other
/// reader it has just parted company with.
#[test]
fn a_prefixed_volume_reads_as_parity_to_every_reader_including_this_door() {
    let t = scratch("agree");
    let d: &std::path::Path = &t;
    let payload = vec![9u8; 4096];
    std::fs::write(d.join("movie.bin"), &payload).unwrap();
    let mut vol = BOM.to_vec();
    vol.extend_from_slice(&index_of([3u8; 16], "movie.bin", &payload));
    std::fs::write(d.join("set.par2"), &vol).unwrap();

    // The one predicate every content sniff in the product shares.
    assert!(
        par2::head_is_packet_file(&vol[..par2::SNIFF_WINDOW + 8]),
        "M4-65: the magic begins within the sniff window"
    );
    // The parser: not merely magic-shaped, a set of one file.
    let set = par2::Par2Set::parse(&[&vol[..]]).expect("a prefixed volume still parses");
    assert_eq!(set.files.len(), 1, "the prefix costs the parser nothing");
    // The discovery `apply_nonactivated_disk_sets` runs the statement
    // after this door - it lists the same path under its set id.
    let found =
        nzbkit::par2repair::disk_sets_scoped(d, nzbkit::par2repair::PacketScope::Nested).unwrap();
    assert!(
        found
            .iter()
            .any(|(id, packets)| id == &[3u8; 16] && packets.contains(&d.join("set.par2"))),
        "the pass itself collects this file as parity: {found:?}"
    );
    // And so the door must not call it unclaimed payload.
    let named = HashSet::from(["movie.bin".to_string()]);
    assert!(
        !has_unclaimed(d, &named),
        "a volume behind a BOM is recovery data, not the thing a late set would exist to name"
    );
}

/// What the door being armed by parity actually reaches, and the
/// reason this is a code fix rather than a comment.
///
/// `super`'s module note says there is nothing behind this door on an
/// ordinary job, "because a job with nothing unclaimed has every file
/// named by an ACTIVE set, which is the set that already verified it in
/// stream". That holds - a prefixed volume is not a counterexample to
/// it, it is a file that should never have counted as unclaimed in the
/// first place. This pins what the miscount buys: a non-active set that
/// is both `vouched` and `published_here`, i.e. one whose
/// `Unrepairable` sets `good = false` and fails the job.
///
/// THE FIXTURE IS CONTRIVED IN EXACTLY ONE PLACE and it is worth being
/// honest about which. Arming the door needs no contrivance at all -
/// one prefixed volume does it. Making the set it lets through VOUCHED
/// needs an active set to name one of that set's packet FILES, and a
/// file the active set names is skipped by the door before the content
/// test is ever reached - so the vouching packet has to be a different
/// file, here one `.par2` carrying two set ids. That is a poster's
/// concatenation or a par2-of-par2 index, not the common case. The
/// UNVOUCHED case is not harmless either and is not pinned here: the
/// pass still APPLIES a foreign disk set, which patches and creates
/// files in the user's output directory and sweeps what it reads as
/// spent.
#[test]
fn the_door_armed_by_parity_reaches_a_set_that_can_fail_the_job() {
    let t = scratch("vouch");
    let d: &std::path::Path = &t;
    let payload = vec![9u8; 4096];
    std::fs::write(d.join("movie.bin"), &payload).unwrap();
    // a.par2 is named by an ACTIVE set and carries a second set's
    // packets too, so that second set is vouched for by this job.
    let mut a = index_of([1u8; 16], "movie.bin", &payload);
    a.extend_from_slice(&index_of([2u8; 16], "ghost.bin", &payload));
    std::fs::write(d.join("a.par2"), &a).unwrap();
    // The prefixed volume of that second set: the ONLY unnamed file.
    let mut b = BOM.to_vec();
    b.extend_from_slice(&index_of([2u8; 16], "ghost.bin", &payload));
    std::fs::write(d.join("b.par2"), &b).unwrap();

    let named = HashSet::from(["movie.bin".to_string(), "a.par2".to_string()]);
    let found =
        nzbkit::par2repair::disk_sets_scoped(d, nzbkit::par2repair::PacketScope::Nested).unwrap();
    let (_, packets) = found
        .iter()
        .find(|(id, _)| id == &[2u8; 16])
        .expect("the non-active set is on disk either way");
    assert!(
        vouched(d, &named, packets) && published_here(d, &named, packets),
        "nothing between the door and this set declines it - its verdict binds the job"
    );
    // So the whole of the protection is the door, and the door must not
    // be armed by the parity it is about to hand that set.
    assert!(
        !has_unclaimed(d, &named),
        "b.par2 is the only unnamed file here and it is a recovery volume"
    );
    // The prefix was the whole difference: an unprefixed copy of the
    // same volume was skipped even at offset 0.
    let at_zero = index_of([2u8; 16], "ghost.bin", &payload);
    std::fs::write(d.join("b.par2"), &at_zero).unwrap();
    assert!(
        !has_unclaimed(d, &named),
        "the offset-0 spelling was never in question - only where the read starts"
    );
}

/// Both edges of the window, which is the half a "widen it" change gets
/// wrong silently: this door's window has to BE the sniff's, or the
/// pass admits a file its own collector will not, or refuses one it
/// will. `par2::packet_file_head_offset` is the shared answer and
/// `head_is_packet_file` is defined in terms of it, so the edges here
/// are asserted against `SNIFF_WINDOW` rather than against 64.
///
/// WHAT THIS ACTUALLY GUARDS, measured rather than assumed. Replacing
/// the shared predicate with a hand-rolled `windows(8).any(..)` over
/// the SAME 72-byte buffer does not move a single verdict - for that
/// length the two are the identical function, because
/// `packet_file_head_offset` truncates to `SNIFF_WINDOW + MAGIC.len()`
/// itself. So the window bound holds however much a caller reads, which
/// is the whole reason to call the shared predicate rather than search
/// a buffer. What DOES redden this test is the pair together - reading
/// further and searching it all - which is the shape a tidy-up
/// produces, and it is that pair the upper edge below refuses.
#[test]
fn the_window_is_the_sniffs_own_window_at_both_edges() {
    let t = scratch("edges");
    let d: &std::path::Path = &t;
    let payload = vec![9u8; 4096];
    std::fs::write(d.join("movie.bin"), &payload).unwrap();
    let named = HashSet::from(["movie.bin".to_string()]);
    let body = index_of([5u8; 16], "movie.bin", &payload);
    let with_prefix = |n: usize| {
        let mut v = vec![b'#'; n];
        v.extend_from_slice(&body);
        v
    };

    std::fs::write(d.join("edge.par2"), with_prefix(par2::SNIFF_WINDOW)).unwrap();
    assert!(
        !has_unclaimed(d, &named),
        "the magic beginning AT the window is inside it"
    );
    std::fs::write(d.join("edge.par2"), with_prefix(par2::SNIFF_WINDOW + 1)).unwrap();
    assert!(
        has_unclaimed(d, &named),
        "one byte past the window is past it - this door reaches no further than the sniff"
    );
}

/// The row this door's content test exists for, unmoved.
///
/// M4-52 posts an obfuscated payload whose yEnc `name=` is
/// `<hash>.par2`, so it lands wearing the extension and the name test
/// alone reported nothing unclaimed. Widening the START of the read
/// must not weaken that, and the only way it could is a payload whose
/// first `SNIFF_WINDOW + 8` bytes happen to contain the magic - which
/// is why this asserts the ordinary payload case rather than pretending
/// to rule that coincidence out.
#[test]
fn the_payload_wearing_the_extension_still_opens_the_door() {
    let t = scratch("m4-52");
    let d: &std::path::Path = &t;
    std::fs::write(
        d.join("Bq3fJm77ZsK.par2"),
        vec![0xab; par2::SNIFF_WINDOW * 4],
    )
    .unwrap();
    assert!(
        has_unclaimed(d, &HashSet::new()),
        "no magic anywhere in the window: a name, not recovery data"
    );
}

/// A pure widening skips MORE and never fewer, and the one place that
/// could have gone wrong is a file too short to carry the magic at all.
///
/// The read used to be `read_exact` of eight bytes, which FAILS on a
/// three-byte file and so fell into the unreadable arm - skipped. A
/// bounded read succeeds there and returns three bytes, so the arm has
/// to be kept explicitly. It is kept for the same reason the unreadable
/// arm exists: a file too short to carry the magic can no more be shown
/// NOT to be parity than an unopenable one can, and this door's whole
/// safety argument is that nothing newly opens it.
#[test]
fn a_file_too_short_to_carry_the_magic_keeps_the_historical_answer() {
    let t = scratch("short");
    let d: &std::path::Path = &t;
    std::fs::write(d.join("stub.par2"), b"ab").unwrap();
    assert!(
        !has_unclaimed(d, &HashSet::new()),
        "two bytes say nothing either way, and saying nothing has always meant skip"
    );
    // A file long enough to have carried it, and not carrying it, is
    // the M4-52 answer and not this one.
    std::fs::write(d.join("stub.par2"), b"abcdefghij").unwrap();
    assert!(
        has_unclaimed(d, &HashSet::new()),
        "eight bytes is enough to answer, and the answer is no"
    );
}
