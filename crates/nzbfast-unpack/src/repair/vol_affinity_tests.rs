//! TODO 311's volume-affinity rule: which recovery volumes of a
//! multi-set post [`super::recovery_candidates`] will let the knapsack
//! buy for ONE set.
//!
//! Its own file rather than a block in `repair_tests.rs`, which sat at
//! 2,939 of the size gate's 3,000-line ceiling when this subject came
//! out - the same reason `ladder_tests`, `side_fetch_tests` and
//! `unpackprog_tests` are each out here.
//!
//! Every case is a NAMING question, so nothing here needs a network:
//! the set is built field by field (the same way `repair_tests` builds
//! its own) and the NZB is parsed from a few lines of XML. The INDEX
//! cases below need a disk, because the whole point of the index rule
//! is that it reads bytes that are already there - so they write a
//! synthetic PAR2 index into a temp dir and are the only cases here
//! that touch one.

use super::*;
use nzbkit::par2::{Par2File, Par2Set};

fn pfile(name: &str) -> Par2File {
    Par2File {
        file_id: [1u8; 16],
        name: name.to_string(),
        length: 1 << 20,
        md5: [0u8; 16],
        md5_16k: [0u8; 16],
        blocks: Vec::new(),
    }
}

fn pset(names: &[&str]) -> Par2Set {
    Par2Set {
        recovery_set_id: [0u8; 16],
        block_size: 4096,
        files: names.iter().copied().map(pfile).collect(),
        nonrecovery: Vec::new(),
        recovery_blocks_seen: 0,
    }
}

/// One `<file>` per name, each with one segment - `recovery_candidates`
/// reads `kind()`, `filename_hint()` and `bytes()` and nothing else.
fn nzb(names: &[&str]) -> Nzb {
    let mut x = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, n) in names.iter().enumerate() {
        x.push_str(&format!(
            "<file poster=\"a@b\" date=\"1\" subject=\"&quot;{n}&quot; yEnc (1/1)\">\n\
             <groups><group>alt.bin</group></groups>\n<segments>\n\
             <segment bytes=\"500000\" number=\"1\">seg{i}@h</segment>\n\
             </segments>\n</file>\n"
        ));
    }
    x.push_str("</nzb>\n");
    Nzb::parse(x.as_bytes()).expect("fixture NZB parses")
}

/// The names `recovery_candidates` hands back, resolved to filenames so
/// a failure names the volume rather than a file index.
///
/// The output directory is a path that does NOT exist, which is the
/// no-index-on-disk case and is what every naming case below wants: the
/// index scan finds nothing and the stems arm is the only thing
/// deciding. `picked_in` is the same call over a real directory.
fn picked(set: &Par2Set, names: &[&str], sniffed: &[usize]) -> Vec<String> {
    picked_in(
        &std::env::temp_dir().join("nzbfast-vol-affinity-no-such-dir"),
        set,
        names,
        sniffed,
    )
}

/// [`picked`] against a real output directory, for the index-base cases.
fn picked_in(out_dir: &Path, set: &Par2Set, names: &[&str], sniffed: &[usize]) -> Vec<String> {
    let n = nzb(names);
    recovery_candidates(&n, out_dir, set, &[], sniffed)
        .into_iter()
        .map(|(fi, _, _)| {
            n.files[fi]
                .filename_hint()
                .unwrap_or(&n.files[fi].subject)
                .to_string()
        })
        .collect()
}

/// A scratch output directory, cleared on entry - `repair_tests::tdir`,
/// which is one file over and not visible from here.
fn tdir(tag: &str) -> crate::testscratch::ScratchDir {
    crate::testscratch::ScratchDir::attach(
        &std::env::temp_dir().join(format!("nzbfast-volaff-{tag}-{}", std::process::id())),
    )
}

/// Write a minimal PAR2 INDEX at `dir/name` carrying `set_id`.
///
/// One Main-type packet, which is all the index rule reads: the set id
/// lives at bytes 32..48 of a packet HEADER, and `packet_spans` walks
/// the framing without hashing, so a real recovery set is not needed to
/// pin which set a file announces. Packet length must be at least the
/// 64-byte header and a multiple of four.
fn write_index(dir: &Path, name: &str, set_id: [u8; 16]) {
    let body = [0u8; 32];
    let mut p = Vec::new();
    p.extend_from_slice(b"PAR2\0PKT");
    p.extend_from_slice(&((64 + body.len()) as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]); // packet MD5 - never read by the scan
    p.extend_from_slice(&set_id);
    p.extend_from_slice(b"PAR 2.0\0Main\0\0\0\0");
    p.extend_from_slice(&body);
    std::fs::write(dir.join(name), &p).unwrap();
}

/// THE DEFECT: the affinity test was `starts_with` over the whole
/// volume name, so a stem could not tell one member of a numbered
/// series from another. `track1`, from this set's `track1.bin`, is a
/// prefix of `track18.bin.vol00+01.par2`.
///
/// Once ANY volume is affine the list is FILTERED to the affine ones,
/// so under the old rule this returned track 18's volume and dropped
/// track 1's own - the knapsack then bought a volume whose slices carry
/// another set id, got nothing usable, and declined a repair whose
/// parity was on the server all along.
#[test]
fn a_prefix_collision_with_a_numbered_sibling_is_not_affine() {
    let set = pset(&["track1.bin"]);
    let got = picked(
        &set,
        &[
            "track1.bin",
            "track1.bin.vol00+01.par2",
            "track18.bin.vol00+01.par2",
            "track18.bin",
        ],
        &[],
    );
    assert_eq!(
        got,
        vec!["track1.bin.vol00+01.par2".to_string()],
        "the sibling's volume is still being read as this set's"
    );
}

/// The same collision one digit further along, which is the shape TODO
/// 311's own write-up names: stem `track01` against
/// `track010.bin.vol00+01.par2`. Worth pinning separately - the
/// sibling's base here starts with the WHOLE stem and continues with a
/// digit, so no delimiter rule would have caught it either.
#[test]
fn a_numeric_extension_of_the_stem_is_not_affine() {
    let set = pset(&["track01.bin"]);
    let got = picked(
        &set,
        &["track010.bin.vol00+01.par2", "track01.bin.vol00+01.par2"],
        &[],
    );
    assert_eq!(got, vec!["track01.bin.vol00+01.par2".to_string()]);
}

/// A stem that ends in an extension is followed by a DOT in a
/// sibling's volume name too, which is why base equality is the rule
/// and a delimiter test is not: `track01.cue` belongs to another set
/// and would pass "stem then a delimiter" against stem `track01`.
#[test]
fn a_sibling_sharing_the_stem_before_its_extension_is_not_affine() {
    let set = pset(&["track01.bin"]);
    let got = picked(
        &set,
        &["track01.cue.vol00+01.par2", "track01.bin.vol00+01.par2"],
        &[],
    );
    assert_eq!(got, vec!["track01.bin.vol00+01.par2".to_string()]);
}

/// BOTH par2cmdline spellings of a volume's base are affine, which is
/// why `stems` carries the full name AND the name minus its last
/// extension: the default is `<payload name>.volXX+YY.par2`, and an
/// explicit `-B` base drops the payload's extension.
#[test]
fn both_par2cmdline_base_spellings_are_affine() {
    let set = pset(&["track01.bin"]);
    let got = picked(
        &set,
        &[
            "track01.bin.vol00+01.par2",
            "track01.vol02+02.par2",
            "other.bin.vol00+01.par2",
        ],
        &[],
    );
    assert_eq!(
        got,
        vec![
            "track01.bin.vol00+01.par2".to_string(),
            "track01.vol02+02.par2".to_string()
        ]
    );
}

/// The bare-ordinal `.vol-NN` convention resolves its base the same
/// way, because `par2_vol_suffix` is the one place that rule lives.
#[test]
fn the_bare_ordinal_volume_shape_resolves_its_base_too() {
    let set = pset(&["Some.Release.mkv"]);
    let got = picked(
        &set,
        &["Some.Release.vol-01.par2", "Other.Release.vol-01.par2"],
        &[],
    );
    assert_eq!(got, vec!["Some.Release.vol-01.par2".to_string()]);
}

/// A SNIFFED volume is recovery data identified by packet magic, not by
/// name, so it is affine to every set - a decision about names must
/// never filter it out. Pinned with a base that is emphatically not
/// this set's.
#[test]
fn a_sniffed_volume_stays_affine_to_every_set() {
    let set = pset(&["track01.bin"]);
    // File index 1 is the obfuscated slot the in-stream sniff caught.
    let got = picked(
        &set,
        &["track01.bin.vol00+01.par2", "Zz9kQr4tXm7pLw2"],
        &[1],
    );
    assert_eq!(
        got,
        vec![
            "track01.bin.vol00+01.par2".to_string(),
            "Zz9kQr4tXm7pLw2".to_string()
        ]
    );
}

/// Read-only sweep finding 8 (31 Aug 2026): a sniffed volume is KEPT
/// and does not ARM the filter.
///
/// The pin above pairs its sniffed volume with a stem-MATCHING named
/// one, so the filter arms on the name and the sniffed volume rides
/// along; it cannot see this. Here nothing is affine BY NAME - the
/// release-named multi-set shape, `cd1.vol...` volumes against a
/// FileDesc of `track01.bin`, which is `e2e_multiset`'s own fixture -
/// so the none-affine fallback is the correct behaviour and hands the
/// set every candidate there is. Counting the sniffed volume as affine
/// took the FILTER branch instead and dropped both named volumes, so a
/// repairable set was priced with nothing left to repair from.
#[test]
fn a_sniffed_volume_does_not_arm_the_filter_against_off_stem_named_volumes() {
    let set = pset(&["track01.bin"]);
    // File index 2 is the obfuscated slot the in-stream sniff caught.
    let got = picked(
        &set,
        &["cd1.vol00+01.par2", "cd1.vol01+02.par2", "Zz9kQr4tXm7pLw2"],
        &[2],
    );
    assert_eq!(
        got,
        vec![
            "cd1.vol00+01.par2".to_string(),
            "cd1.vol01+02.par2".to_string(),
            "Zz9kQr4tXm7pLw2".to_string()
        ],
        "a sniffed volume must be ADDED to the list, never used to arm a \
         decision that is about names"
    );
}

/// The none-affine FALLBACK is untouched: where no name identifies
/// anything the whole list comes back, which is what keeps an
/// obfuscated post behaving exactly as it did, escalation included.
///
/// This is also the arm that makes the tightening safe. Base equality
/// is strictly narrower than the old prefix test, so it can only ever
/// EMPTY the affine list - and an empty list re-arms this fallback,
/// which hands back the set's own volumes as well.
#[test]
fn a_post_where_nothing_is_affine_still_gets_the_whole_list() {
    let set = pset(&["track01.bin"]);
    let got = picked(
        &set,
        &["Release.vol00+01.par2", "Release.vol01+02.par2"],
        &[],
    );
    assert_eq!(
        got,
        vec![
            "Release.vol00+01.par2".to_string(),
            "Release.vol01+02.par2".to_string()
        ]
    );
}

/// The prefix-collision fallback, which is the whole reason the
/// tightening is not a regression on the shape the old rule *appeared*
/// to help: this set's own volumes are named off-stem and a numbered
/// sibling's are prefix-colliding. Under `starts_with` the sibling's
/// volume armed the filter and this set's own were dropped; under base
/// equality nothing is affine, the fallback re-arms, and both come
/// back.
#[test]
fn off_stem_own_volumes_survive_a_prefix_colliding_sibling() {
    let set = pset(&["track1.bin"]);
    let got = picked(
        &set,
        &["Release.vol00+01.par2", "track18.bin.vol00+01.par2"],
        &[],
    );
    assert_eq!(
        got,
        vec![
            "Release.vol00+01.par2".to_string(),
            "track18.bin.vol00+01.par2".to_string()
        ],
        "the fallback did not re-arm, so this set lost its own volumes"
    );
}

/// A stem under three characters is dropped from `stems` as too short
/// to distinguish one release from another, and that filter must not
/// leave the base test reaching for an empty stem and matching
/// everything.
#[test]
fn a_stem_too_short_to_identify_a_release_makes_nothing_affine() {
    let set = pset(&["ab"]);
    let got = picked(&set, &["ab.vol00+01.par2", "xy.vol00+01.par2"], &[]);
    assert_eq!(
        got,
        vec![
            "ab.vol00+01.par2".to_string(),
            "xy.vol00+01.par2".to_string()
        ],
        "a too-short stem must fall back, not match every volume"
    );
}

/// THE INDEX-NAME RULE, and the shape it exists for: a per-file-set post
/// whose sets are named after the RELEASE and whose FileDesc names are
/// the PAYLOAD (`par2 create cd1.par2 track01.bin`, the ordinary way to
/// post a multi-disc release).
///
/// Every stem here is `track01.bin`; every volume base is `cd1`, `cd2`
/// or `cd3`. No stem matches any base, so the stems arm makes nothing
/// affine, the none-affine fallback fires by design, and this set is
/// offered all three sets' parity - measured on origin/main 31 Aug
/// 2026 through this very function: six candidates in, all six back.
///
/// `cd1.par2` is on disk and carries this set's id, so `cd1` is affine
/// by PROOF and the other two sets' volumes are not bought. Zero round
/// trips and zero extra bytes: the index was downloaded long before any
/// repair asked this question.
#[test]
fn this_sets_own_index_scopes_a_release_named_multi_set_post() {
    let dir = tdir("relnamed");
    let mut set = pset(&["track01.bin"]);
    set.recovery_set_id = [7u8; 16];
    write_index(&dir, "cd1.par2", [7u8; 16]);
    write_index(&dir, "cd2.par2", [8u8; 16]);
    write_index(&dir, "cd3.par2", [9u8; 16]);
    let got = picked_in(
        &dir,
        &set,
        &[
            "cd1.vol00+01.par2",
            "cd1.vol01+02.par2",
            "cd2.vol00+01.par2",
            "cd2.vol01+02.par2",
            "cd3.vol00+01.par2",
            "cd3.vol01+02.par2",
        ],
        &[],
    );
    assert_eq!(
        got,
        vec![
            "cd1.vol00+01.par2".to_string(),
            "cd1.vol01+02.par2".to_string()
        ],
        "the index rule did not scope the list - this set is still \
         being offered another set's parity"
    );
}

/// The rule is by CONTENT, not by an index being PRESENT: `cd2.par2`
/// is on disk and carries another set's id, so it contributes no base,
/// nothing is affine, and the fallback hands back the whole list.
///
/// `cd1.vol00+01.par2` is in the list and is what makes this bite. Drop
/// the set-id test and `cd2` becomes affine, the filter arms, and this
/// set is left holding the volumes of the one set it is provably not
/// about while its own - unidentifiable here, since its index never
/// reached disk - are dropped. A two-volume list of `cd2`'s alone
/// cannot tell the two behaviours apart: both return both.
#[test]
fn another_sets_index_on_disk_makes_nothing_affine() {
    let dir = tdir("foreign-index");
    let mut set = pset(&["track01.bin"]);
    set.recovery_set_id = [7u8; 16];
    write_index(&dir, "cd2.par2", [8u8; 16]);
    let got = picked_in(&dir, &set, &["cd1.vol00+01.par2", "cd2.vol00+01.par2"], &[]);
    assert_eq!(
        got,
        vec![
            "cd1.vol00+01.par2".to_string(),
            "cd2.vol00+01.par2".to_string()
        ],
        "a foreign index armed the filter, so this set lost the \
         fallback it is entitled to"
    );
}

/// The two arms are a UNION, not a replacement: a post whose index is on
/// disk AND whose volumes carry the payload-stem naming keeps both, so
/// nothing the stems arm reached yesterday becomes unreachable today.
#[test]
fn the_index_base_and_the_payload_stem_are_both_affine() {
    let dir = tdir("union");
    let mut set = pset(&["track01.bin"]);
    set.recovery_set_id = [7u8; 16];
    write_index(&dir, "cd1.par2", [7u8; 16]);
    let got = picked_in(
        &dir,
        &set,
        &[
            "cd1.vol00+01.par2",
            "track01.bin.vol00+01.par2",
            "cd2.vol00+01.par2",
        ],
        &[],
    );
    assert_eq!(
        got,
        vec![
            "cd1.vol00+01.par2".to_string(),
            "track01.bin.vol00+01.par2".to_string()
        ]
    );
}

/// A SNIFFED volume stays affine to every set with the index rule armed
/// too. It is recovery data identified by packet magic and has no name
/// to be judged by, so a decision made about names must never narrow
/// it - and the index rule is a decision about names.
#[test]
fn a_sniffed_volume_survives_an_armed_index_filter() {
    let dir = tdir("sniffed-armed");
    let mut set = pset(&["track01.bin"]);
    set.recovery_set_id = [7u8; 16];
    write_index(&dir, "cd1.par2", [7u8; 16]);
    let got = picked_in(
        &dir,
        &set,
        &["cd1.vol00+01.par2", "cd2.vol00+01.par2", "Zz9kQr4tXm7pLw2"],
        &[2],
    );
    assert_eq!(
        got,
        vec![
            "cd1.vol00+01.par2".to_string(),
            "Zz9kQr4tXm7pLw2".to_string()
        ]
    );
}

/// A file named `.par2` that carries no PAR2 packet at all contributes
/// nothing: the rule is the SET ID in the bytes, so an empty or
/// truncated index costs the none-affine fallback and never a wrong
/// attribution.
#[test]
fn an_index_with_no_readable_packet_contributes_no_base() {
    let dir = tdir("empty-index");
    let mut set = pset(&["track01.bin"]);
    set.recovery_set_id = [7u8; 16];
    std::fs::write(dir.join("cd1.par2"), b"not a par2 file at all").unwrap();
    let got = picked_in(&dir, &set, &["cd1.vol00+01.par2", "cd2.vol00+01.par2"], &[]);
    assert_eq!(
        got,
        vec![
            "cd1.vol00+01.par2".to_string(),
            "cd2.vol00+01.par2".to_string()
        ]
    );
}

/// The index rule resolves a volume's base with `par2_vol_suffix`, the
/// same function the stems arm uses, so the bare-ordinal `.vol-NN`
/// shape and an UPPERCASE index name both land on the same base.
#[test]
fn the_index_rule_matches_case_blind_and_across_volume_shapes() {
    let dir = tdir("case-shape");
    let mut set = pset(&["track01.bin"]);
    set.recovery_set_id = [7u8; 16];
    write_index(&dir, "Some.Release.PAR2", [7u8; 16]);
    let got = picked_in(
        &dir,
        &set,
        &["Some.Release.vol-01.par2", "Other.Release.vol-01.par2"],
        &[],
    );
    assert_eq!(got, vec!["Some.Release.vol-01.par2".to_string()]);
}
