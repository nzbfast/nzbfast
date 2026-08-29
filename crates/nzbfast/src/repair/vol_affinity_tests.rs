//! TODO 311's volume-affinity rule: which recovery volumes of a
//! multi-set post [`super::recovery_candidates`] will let the knapsack
//! buy for ONE set.
//!
//! Its own file rather than a block in `repair_tests.rs`, which sits at
//! 2,939 of the size gate's 3,000-line ceiling - the same reason
//! `ladder_tests`, `side_fetch_tests` and `unpackprog_tests` are each
//! out here.
//!
//! Every case is a NAMING question, so nothing here needs a network, a
//! disk or a real PAR2 index: the set is built field by field (the same
//! way `repair_tests` builds its own) and the NZB is parsed from a few
//! lines of XML.

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
fn picked(set: &Par2Set, names: &[&str], sniffed: &[usize]) -> Vec<String> {
    let n = nzb(names);
    recovery_candidates(&n, set, &[], sniffed)
        .into_iter()
        .map(|(fi, _, _)| {
            n.files[fi]
                .filename_hint()
                .unwrap_or(&n.files[fi].subject)
                .to_string()
        })
        .collect()
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
