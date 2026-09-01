//! The committed `rar_recovery_scan` seed corpus still reaches the code it
//! was committed to reach.
//!
//! `crates/nzbkit/fuzz/seeds/rar_recovery_scan/` exists because that target's
//! interesting arithmetic sits behind a CRC64 chunk gate and a RAR5 REV
//! header that no mutator guesses: cold it reaches ~226 edges, seeded ~1,686.
//! The failure this file guards is the one `yenc_decode` actually suffered -
//! a corpus that LOOKS seeded but reaches nothing, so a run still prints
//! millions of execs and still says zero crashes while never touching the
//! parser. Nothing about a fuzz corpus is self-checking, and a `.rev` that
//! stopped parsing would be invisible until someone read an edge count.
//!
//! So the named fixtures in that directory are asserted here, by an ordinary
//! `cargo test` that needs neither nightly nor cargo-fuzz. The rest of the
//! directory is fuzzer-derived and deliberately not asserted - a derived blob
//! is allowed to go inert, which is exactly why the real WinRAR output is
//! kept beside it.

use rars::recovery::stream::{MemorySource, scan_inline_recovery_chunks};

/// One seed, and the entry point it has to keep reaching.
const SEEDS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/seeds/rar_recovery_scan");

fn seed(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(SEEDS).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("seed {name} is missing: {e}"))
}

/// The REV bomb's own route: a `.rev` header whose slot table is sized by a
/// declared count. Both volumes must still parse AND still verify, because a
/// payload that no longer matches its declared CRC32 is dropped before the
/// planner ever sees it - the seed would be carrying the fuzzer only as far
/// as the checksum.
#[test]
fn the_rev5_seeds_still_parse_and_still_verify() {
    for name in ["multivol_rev.part1.rev", "multivol_rev.part2.rev"] {
        let src = MemorySource(seed(name));
        let volume = rars::rar50::read_rev5_meta(&src)
            .unwrap_or_else(|e| panic!("{name} no longer parses as a RAR5 REV volume: {e}"));
        assert_eq!(
            volume.meta.data_volumes.len(),
            volume.meta.data_count as usize,
            "{name}: slot table and declared count disagree"
        );
        assert!(
            rars::rar50::verify_rev5_payload(&src, &volume).expect("streaming the payload"),
            "{name}: payload no longer matches its declared CRC32"
        );
    }
}

/// The `{RB}` inline scanner is behind a CRC64 over the whole chunk, which is
/// the gate the corpus exists to get past. A seed that stopped yielding a
/// chunk would leave the plan arithmetic unreached.
#[test]
fn the_inline_recovery_seeds_still_yield_a_crc_valid_chunk() {
    for name in ["with_recovery.rar", "with_all_services.rar"] {
        let src = MemorySource(seed(name));
        let scan = scan_inline_recovery_chunks(&src, 1 << 20)
            .unwrap_or_else(|e| panic!("{name} no longer scans for inline recovery: {e}"));
        assert!(
            !scan.chunks.is_empty(),
            "{name}: no `{{RB}}` chunk survives the CRC64 gate any more"
        );
    }
}

/// The legacy RAR 2/3 leg, added with the bounded protect-record repair. Each
/// of these has to still present a record for the target to reach
/// `repair_protect_to_path` at all.
#[test]
fn the_legacy_protect_record_seeds_still_present_a_record() {
    for name in [
        "rar250_protect_head_rr1.rar",
        "with_recovery_rar300.rar",
        "with_compressed_recovery_rar300.rar",
        "with_compressed_recovery_header_synthetic.rar",
    ] {
        let bytes = seed(name);
        let archive = rars::ArchiveReader::read(&bytes)
            .unwrap_or_else(|e| panic!("{name} no longer reads as an archive: {e}"));
        let legacy = archive
            .as_rar15_40()
            .unwrap_or_else(|| panic!("{name} is no longer a RAR 1.5-4.0 archive"));
        let has_record = legacy.protect_records().next().is_some()
            || legacy
                .new_subs()
                .any(|sub| sub.kind == rars::rar15_40::NewSubKind::RecoveryRecord);
        assert!(has_record, "{name}: carries no recovery record any more");
    }
}

/// The whole directory, not just the names above: a seed corpus is only worth
/// its bytes while it stays small enough that nobody is tempted to delete it,
/// and 240 KB was the size this was committed at. The ceiling is generous
/// (2x) so ordinary additions pass and a distillation dumped in whole does
/// not.
#[test]
fn the_seed_corpus_stays_small_enough_to_carry() {
    let mut total = 0u64;
    let mut count = 0usize;
    for entry in std::fs::read_dir(SEEDS).expect("the seed directory exists") {
        let entry = entry.expect("reading the seed directory");
        if entry.file_name() == "README.md" {
            continue;
        }
        total += entry.metadata().expect("seed metadata").len();
        count += 1;
    }
    assert!(
        count > 200,
        "the seed corpus lost most of its inputs: {count}"
    );
    assert!(
        total < 512 * 1024,
        "the seed corpus grew to {total} bytes - distil it with `cargo +nightly fuzz cmin` \
         rather than committing a whole corpus"
    );
}

// ---------------------------------------------------------------------
// `nzb_parse` seeds (addendum row N6-14).
//
// That target had NO committed seeds and the fuzz-smoke seed step never
// touched `corpus/nzb_parse`, so on a cold cache it started from nothing
// but libFuzzer's own mutations - and an NZB is XML, where every
// interesting path sits behind a well-formed element tree that random
// bytes reach about as often as they reach a CRC. The directory next
// door now holds a realistic post, a PAR2-bearing post, a split archive,
// an obfuscated post, and one seed per confirmed adversarial row of the
// 30 Aug 2026 parser/front-door addendum.
//
// What is asserted here splits in two, on purpose:
//
// * SETTLED behaviour - an undefined entity is refused, a truncated
//   document is refused, a file-less document is refused, the HTML
//   latin-1 entity set still resolves, CDATA and comment-split text
//   still re-join - is asserted by OUTCOME. Each of those has its own
//   doc comment in `nzb.rs` explaining why it is the answer.
// * DISPUTED behaviour - what N6-01..N6-08 should do - is NOT asserted
//   by outcome, because the fixes are owned by other lanes and a test
//   pinning today's answer would go red on their fix rather than on a
//   regression. What is asserted instead is that the SEED still carries
//   the shape it was committed to carry, and that parsing it still
//   reaches an ordinary `Result` rather than a panic. That is the same
//   question the rars seeds above ask - "does this input still get past
//   the gate" - and it is the only one a seed file can answer.

const NZB_SEEDS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/seeds/nzb_parse");

fn nzb_seed(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(NZB_SEEDS).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("nzb seed {name} is missing: {e}"))
}

/// The realistic shapes are the corpus's whole point: a mutator that
/// starts from a valid manifest reaches the attribute, group, segment
/// and classification arms on its first edit. A seed that stopped
/// parsing would leave all of that unreached while the run still printed
/// millions of execs.
#[test]
fn the_realistic_nzb_seeds_still_parse_into_a_manifest() {
    use nzbkit::nzb::{FileKind, Nzb};

    let normal = Nzb::parse(&nzb_seed("normal-multifile.nzb")).expect("the ordinary post parses");
    assert_eq!(normal.files.len(), 3, "normal-multifile.nzb lost a file");
    assert!(
        normal.files.iter().all(|f| !f.segments.is_empty()),
        "normal-multifile.nzb has a file with no fetchable segment"
    );
    assert!(
        normal.files.iter().all(|f| !f.groups.is_empty()),
        "normal-multifile.nzb no longer reaches the <group> arm"
    );
    assert!(
        !normal.meta.is_empty(),
        "normal-multifile.nzb lost its meta"
    );

    let par2 = Nzb::parse(&nzb_seed("par2-set.nzb")).expect("the PAR2-bearing post parses");
    let kinds: Vec<FileKind> = par2.files.iter().map(|f| f.kind()).collect();
    assert!(
        kinds.contains(&FileKind::Par2Main) && kinds.contains(&FileKind::Par2Volume),
        "par2-set.nzb no longer reaches both PAR2 classifications: {kinds:?}"
    );
    assert!(
        par2.par2_seed_file().is_some(),
        "par2-set.nzb no longer offers a PAR2 seed file"
    );
    assert_eq!(
        par2.password(),
        Some("let me in"),
        "par2-set.nzb no longer reaches the meta password arm"
    );

    let split = Nzb::parse(&nzb_seed("split-archive-unquoted.nzb")).expect("the split post parses");
    assert_eq!(
        split.files.len(),
        4,
        "split-archive-unquoted.nzb lost a file"
    );
    assert!(
        split.files.iter().all(|f| f.filename_hint().is_none()),
        "split-archive-unquoted.nzb grew a quoted name - it exists to drive \
         the UNQUOTED read (N6-07)"
    );

    let obf = Nzb::parse(&nzb_seed("obfuscated.nzb")).expect("the obfuscated post parses");
    assert_eq!(obf.files.len(), 3, "obfuscated.nzb lost a file");
    assert!(
        obf.files[0].filename_hint().is_none(),
        "obfuscated.nzb grew a quoted name - it exists to drive the \
         no-name path"
    );

    let dense = Nzb::parse(&nzb_seed("dense-small.nzb")).expect("the dense manifest parses");
    assert_eq!(dense.files.len(), 24, "dense-small.nzb lost a file");
}

/// The compatibility answers `nzb.rs` argues for in its own comments.
/// These are settled, so they are asserted by outcome.
#[test]
fn the_settled_nzb_seed_outcomes_are_unchanged() {
    use nzbkit::nzb::{Nzb, NzbError};

    assert!(
        matches!(
            Nzb::parse(&nzb_seed("undefined-entity.nzb")),
            Err(NzbError::UnknownEntity(_))
        ),
        "an undefined entity in TEXT is refused rather than dropped - see \
         the GeneralRef arm in nzb.rs"
    );
    // The attribute path errors through quick-xml's own resolver, which
    // is a different variant and the reason this is a second seed: one
    // file cannot exercise both, because the first refusal ends the
    // parse.
    assert!(
        Nzb::parse(&nzb_seed("undefined-entity-in-attribute.nzb")).is_err(),
        "an undefined entity in an attribute is refused"
    );
    assert!(
        matches!(
            Nzb::parse(&nzb_seed("truncated.nzb")),
            Err(NzbError::Truncated)
        ),
        "a document ending inside an open element is refused"
    );
    assert!(
        matches!(Nzb::parse(&nzb_seed("no-files.nzb")), Err(NzbError::Empty)),
        "a manifest declaring no file is refused"
    );

    let latin1 = Nzb::parse(&nzb_seed("n6-12-latin1-entities.nzb"))
        .expect("the HTML latin-1 entity set still resolves (nzbget issue #699)");
    assert!(
        latin1.files[0].subject.contains('\u{df}') && latin1.files[0].subject.contains('\u{fc}'),
        "the latin-1 seed no longer resolves its ATTRIBUTE entities: {:?}",
        latin1.files[0].subject
    );
    assert!(
        latin1
            .meta
            .iter()
            .any(|(t, v)| t == "title" && v.contains('\u{e4}') && v.contains('&')),
        "the latin-1 seed no longer resolves its TEXT entities: {:?}",
        latin1.meta
    );

    let mixed = Nzb::parse(&nzb_seed("cdata-comments-prefixed-ns.nzb"))
        .expect("CDATA, comments and a prefixed namespace still parse");
    let ids: Vec<&str> = mixed.files[0]
        .segments
        .iter()
        .map(|s| s.message_id.as_str())
        .collect();
    assert!(
        ids.contains(&"a@news.example"),
        "a text node split by a comment no longer re-joins: {ids:?}"
    );
    assert!(
        ids.contains(&"b@news.example"),
        "a CDATA-wrapped message-id is no longer read: {ids:?}"
    );
    assert_eq!(
        mixed.files[0].groups,
        vec!["alt.binaries.test".to_string()],
        "a comment-split group name no longer re-joins"
    );
    assert_eq!(
        mixed.files[0].dropped_segments, 1,
        "the self-closing <segment/> is no longer charged"
    );
    assert_eq!(
        mixed.password(),
        Some("se&cr<et"),
        "a CDATA meta value is no longer read literally"
    );
}

/// The adversarial seeds, checked by SHAPE: the distinguishing bytes are
/// still there, and the parse still ends in a `Result`.
///
/// This was written while N6-01..N6-08 were open, and said so - "while
/// its correct answer is still being decided". Both lanes have since
/// landed (`dd479f9b4` and `97e4dea88`, 30 Aug 2026) and every row is
/// pinned by its own deterministic regression in `nzb_tests.rs`, which
/// is where the original note said those pins belonged. The shape check
/// STAYS, for a better reason than the one it was written for: what
/// this file asks is whether a SEED still carries the shape it was
/// committed for, and a second copy of each row's outcome assertion
/// here would be two places to keep in step for no coverage at all.
#[test]
fn the_adversarial_nzb_seeds_still_carry_their_shape() {
    use nzbkit::nzb::Nzb;

    // (seed, the substring that IS the case)
    const SHAPES: &[(&str, &str)] = &[
        ("n6-01-self-closing-file.nzb", "yEnc (1/1)\"/>"),
        ("n6-02-namespace-collision.nzb", "x:subject="),
        ("n6-03-nested-and-two-roots.nzb", "</nzb>"),
        ("n6-04-quoted-decoy.nzb", "&quot; - &quot;"),
        ("n6-05-par2-whitespace-tail.nzb", ".par2 notes.txt"),
        ("n6-06-unicode-boundaries.nzb", "&#xA0;"),
        ("n6-08-bad-numerics.nzb", "number=\"abc\""),
        ("n6-13-bracketed-msgid.nzb", "&lt;a@news.example&gt;"),
    ];
    for (name, shape) in SHAPES {
        let bytes = nzb_seed(name);
        let text = String::from_utf8(bytes.clone()).expect("the seeds are UTF-8");
        assert!(
            text.contains(shape),
            "{name} no longer carries the shape it was committed for: {shape}"
        );
        // No outcome assertion - only that the parser answers rather
        // than panicking.
        let _ = Nzb::parse(&bytes);
    }
    // N6-03's own two halves, spelled out because "</nzb>" above only
    // says the document closes.
    let multi = String::from_utf8(nzb_seed("n6-03-nested-and-two-roots.nzb")).unwrap();
    assert_eq!(
        multi.matches("<nzb").count(),
        2,
        "the two-roots half of the N6-03 seed is gone"
    );
    assert!(
        multi.contains("<wrapper>"),
        "the core-tag-outside-a-root half of the N6-03 seed is gone"
    );
}

/// Same reasoning as the rars corpus above: a seed set is only worth its
/// bytes while it stays small enough that nobody is tempted to delete it,
/// and small enough not to raise libFuzzer's `max_len` for the whole
/// burst. 33 KB is what this was committed at; the ceiling is generous
/// but well under the 1 MiB the fuzz README documents as the campaign
/// `max_len`.
#[test]
fn the_nzb_seed_corpus_stays_small_enough_to_carry() {
    let mut total = 0u64;
    let mut count = 0usize;
    let mut largest = 0u64;
    for entry in std::fs::read_dir(NZB_SEEDS).expect("the nzb seed directory exists") {
        let entry = entry.expect("reading the nzb seed directory");
        if entry.file_name() == "README.md" {
            continue;
        }
        let len = entry.metadata().expect("seed metadata").len();
        total += len;
        largest = largest.max(len);
        count += 1;
    }
    assert!(
        count >= 15,
        "the nzb seed corpus lost most of its inputs: {count}"
    );
    assert!(
        total < 128 * 1024,
        "the nzb seed corpus grew to {total} bytes - keep it distilled"
    );
    assert!(
        largest < 64 * 1024,
        "an nzb seed grew to {largest} bytes - libFuzzer sets max_len from \
         the largest corpus unit, so one big seed slows the whole burst"
    );
}

/// `nzb_semantic`'s seeds, which are the odd ones out on this page: that
/// target reads its bytes as a stream of CHOICES rather than as a
/// document, so a seed is a choice stream and there is no parser here to
/// hand it to.
///
/// What that leaves checkable is the SELECTOR, mirrored - and the mirror
/// is the point rather than an apology for it. The failure this guards
/// is specific and silent: the arms are chosen by `data[0] % 4`, so
/// reordering them, or adding a fifth, re-points every committed seed at
/// some other arm. Every `break-*` file would then quietly select the
/// legal manifest arm, the eight `Schema` refusals and both N6-09 count
/// ceilings would stop being reached at INITED, and the burst would go
/// on printing a hundred thousand execs and zero crashes. Nothing else
/// in the tree can see that.
///
/// KEEP IN STEP with `fuzz_targets/nzb_semantic.rs`: the arm selector at
/// the foot of that file, and `COUNT_MAGIC`.
#[test]
fn the_nzb_semantic_seeds_still_select_a_hostile_arm() {
    // The target's own arm selector, written out: `data[0] % 4` is 0 or
    // 1 for the legal manifest arm, 2 for a `Schema` break, 3 for a
    // capped field - and a leading `NZBC` takes the count-ceiling path
    // before any of that is read.
    const COUNT_MAGIC: &[u8] = b"NZBC";
    const ARMS: u8 = 4;
    const BREAK_ARM: u8 = 2;
    const LONG_ARM: u8 = 3;

    let dir = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/seeds/nzb_semantic"
    ));
    let mut breaks = 0;
    let mut longs = 0;
    let mut counts = 0;
    for entry in std::fs::read_dir(dir).expect("the nzb_semantic seed directory exists") {
        let entry = entry.expect("reading the nzb_semantic seed directory");
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "README.md" {
            continue;
        }
        let bytes = std::fs::read(entry.path()).expect("reading a seed");
        // The target returns immediately under this, so a seed shorter
        // than it selects nothing at all.
        assert!(
            bytes.len() >= 8,
            "{name} is {} bytes - nzb_semantic ignores anything under 8",
            bytes.len()
        );
        if name.starts_with("nzbc-") {
            assert!(
                bytes.starts_with(COUNT_MAGIC),
                "{name} no longer carries the count-ceiling magic, so the \
                 N6-09 ceilings are not reached at INITED any more"
            );
            counts += 1;
            continue;
        }
        assert!(
            !bytes.starts_with(COUNT_MAGIC),
            "{name} carries the count magic but is not named for it"
        );
        let arm = bytes[0] % ARMS;
        if let Some(rest) = name.strip_prefix("break-") {
            assert_eq!(
                arm, BREAK_ARM,
                "{name} selects arm {arm}, not the schema-break arm - the \
                 seed and the target's selector have drifted apart"
            );
            // `break-N-*`: N is the index into the target's own `BREAKS`.
            let want: u8 = rest
                .split('-')
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("{name} is not named break-<index>-<what>"));
            assert_eq!(
                bytes[1] % 8,
                want,
                "{name} selects break {} rather than the one it is named for",
                bytes[1] % 8
            );
            breaks += 1;
        } else if name.starts_with("long-") {
            assert_eq!(
                arm, LONG_ARM,
                "{name} selects arm {arm}, not the capped-field arm"
            );
            longs += 1;
        } else {
            panic!("{name} is not a shape this test knows how to check");
        }
    }
    // Floors, not equalities: adding a seed is ordinary, losing the last
    // one of a family is what would leave a whole arm unreached while
    // every other check on this page still passed.
    assert_eq!(
        breaks, 8,
        "every `Schema` violation the hostile arm can spell wants a seed"
    );
    assert!(longs >= 6, "one seed per capped field: {longs}");
    assert_eq!(
        counts, 4,
        "both N6-09 count ceilings, in both element spellings"
    );
}

/// Same reasoning as the corpora above, one size down: these seeds are
/// choice streams of a few dozen bytes and must stay that way. A big
/// one here would raise libFuzzer's `max_len` for the whole target,
/// which is the measured trap `seeds/README.md` records for
/// `nzb_parse`.
#[test]
fn the_nzb_semantic_seed_corpus_stays_tiny() {
    let dir = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/seeds/nzb_semantic"
    ));
    let mut total = 0u64;
    for entry in std::fs::read_dir(dir).expect("the nzb_semantic seed directory exists") {
        let entry = entry.expect("reading the nzb_semantic seed directory");
        if entry.file_name() == "README.md" {
            continue;
        }
        total += entry.metadata().expect("seed metadata").len();
    }
    assert!(
        total < 8 * 1024,
        "the nzb_semantic seeds are choice streams, not documents - {total} bytes"
    );
}
