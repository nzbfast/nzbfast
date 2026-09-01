//! Tests for [`crate::nzb`], out here for the size gate (TODO 106):
//! the parent is production code and the two N6 batches (the P0
//! manifest-integrity rows and the P1 parser/front-door rows) put it
//! 169 lines over the 3,000-line file ceiling between them. Named for
//! its file so `tools/size-gate.py`'s CFG_TEST_MOD resolver still reads
//! it as test code; `super` is still `nzb`, so `use super::*` reaches
//! exactly what the inline module reached.

use super::*;
/// Real NZBIndex-generated NZB (nzbget issue #699): subjects carry
/// `&auml;`, an HTML latin-1 entity undefined in XML. nzbget
/// rejected it ("Reference to undefined entity"); SABnzbd accepts.
/// We resolve the latin-1 set so these download.
#[test]
fn html_latin1_entities_in_attributes_resolve() {
    let xml = include_bytes!("../testdata/nzb/gh-nzbget699-undefined-entity.nzb");
    let nzb = Nzb::parse(xml).expect("latin-1 entity NZB parses");
    assert!(!nzb.files.is_empty());
    let with_auml: Vec<_> = nzb
        .files
        .iter()
        .filter(|f| f.subject.contains("geschändeten"))
        .collect();
    assert!(
        !with_auml.is_empty(),
        "&auml; should resolve to ä in subjects: {:?}",
        nzb.files[0].subject
    );
    assert!(
        nzb.files.iter().all(|f| !f.subject.contains("&auml;")),
        "no subject may keep the raw entity"
    );
}

/// A latin-1 byte anywhere in the document is REFUSED, and CDATA is the
/// arm where that is a change rather than a restatement.
///
/// Measured 28 Aug 2026 against quick-xml 0.41 and 0.42 side by side, in
/// the pass that took the bump. A bad byte in a `subject=` or in element
/// text already failed the parse under 0.41 - every content accessor
/// decoded strictly - so those two are unchanged. CDATA was the outlier:
/// this arm read it with `String::from_utf8_lossy`, so the byte arrived
/// as U+FFFD and the parse SUCCEEDED with a corrupted value. That is the
/// worst of the three outcomes for the two things CDATA actually carries
/// here - a meta password that is now silently wrong, and a message-id
/// that was never posted. 0.42 validates when it builds the event, so all
/// three shapes now agree: refuse the document.
///
/// Do NOT "fix" a report of this by reintroducing a lossy read, and do
/// not reach for a lossy pre-transcode of the whole input either - that
/// would also start ACCEPTING the latin-1 subjects this parser has always
/// refused, which is a product decision and not a bump.
#[test]
fn cdata_with_a_latin1_byte_is_refused_not_corrupted() {
    let mut xml = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head><meta type="password"><![CDATA[stra"#
        .to_vec();
    // 0xDF is `ß` in latin-1 and is not a valid UTF-8 sequence.
    xml.push(0xDF);
    xml.extend_from_slice(
        br#"e]]></meta></head>
  <file subject="s" poster="p" date="1700000000">
<groups><group>alt.binaries.test</group></groups>
<segments><segment bytes="1" number="1">a@example.com</segment></segments>
  </file>
</nzb>"#,
    );
    let err = Nzb::parse(&xml).expect_err("a latin-1 byte in CDATA must refuse the document");
    // It arrives as `Xml`, not as a separate encoding variant: see the
    // note on `NzbError::Xml`.
    assert!(
        matches!(err, NzbError::Xml(_)),
        "encoding failures surface as NzbError::Xml since quick-xml 0.42, got {err:?}"
    );

    // The same document with the byte spelled as UTF-8 still parses, so
    // this test cannot pass by refusing CDATA in general.
    let ok = String::from_utf8(
        xml.iter()
            .map(|&b| if b == 0xDF { b'x' } else { b })
            .collect::<Vec<_>>(),
    )
    .expect("ascii-ised fixture is utf-8");
    let nzb = Nzb::parse(ok.as_bytes()).expect("the well-formed twin parses");
    assert_eq!(nzb.password(), Some("straxe"));
}

/// The same entities must resolve in element text (message-ids, meta
/// values), where they arrive as GeneralRef events - and an entity
/// outside the latin-1 table must still fail the parse: tolerance is
/// scoped to the known HTML set, not entities in general.
#[test]
fn html_latin1_entities_in_text_resolve_unknown_still_rejected() {
    let xml = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head><meta type="password">stra&szlig;e</meta></head>
  <file subject="s" poster="p" date="1700000000">
<groups><group>alt.binaries.test</group></groups>
<segments><segment bytes="1" number="1">a@example.com</segment></segments>
  </file>
</nzb>"#;
    let nzb = Nzb::parse(xml).expect("parses");
    assert_eq!(nzb.password(), Some("straße"));

    let unknown = br#"<?xml version="1.0"?>
<nzb><file subject="x&bogus;y" poster="p" date="1">
  <groups><group>a.b</group></groups>
  <segments><segment bytes="1" number="1">a@b.c</segment></segments>
</file></nzb>"#;
    assert!(
        Nzb::parse(unknown).is_err(),
        "entities outside the latin-1 table must still reject"
    );
}

/// A message-id whose declared character content carries interior
/// whitespace (an entity splits the text, so it arrives as separate
/// fragments) is wire-unsafe and owed to `dropped_segments`.
/// Per-fragment trimming used to eat the spaces around the entity
/// and hand back a FABRICATED id that passed `is_wire_safe` - the
/// manifest then counted a fetched-and-missing article instead of an
/// unfetchable declared segment. Ids get the same
/// accumulate-then-trim-once treatment meta values and groups got.
#[test]
fn an_entity_split_id_with_interior_whitespace_drops_instead_of_rewriting() {
    let xml = br#"<?xml version="1.0"?>
<nzb><file subject="s" poster="p" date="1">
  <groups><group>a.b</group></groups>
  <segments>
<segment bytes="1" number="1">abc &amp;def@news.example</segment>
<segment bytes="1" number="2"> ok@news.example </segment>
  </segments>
</file></nzb>"#;
    let nzb = Nzb::parse(xml).expect("parses");
    let f = &nzb.files[0];
    assert_eq!(
        f.dropped_segments, 1,
        "the whitespace-carrying id is declared-but-unfetchable, never rewritten"
    );
    assert_eq!(
        f.segments
            .iter()
            .map(|s| s.message_id.as_str())
            .collect::<Vec<_>>(),
        vec!["ok@news.example"],
        "element-formatting whitespace still trims off a clean id"
    );
}

/// Three ways a well-formed NZB used to be quietly rewritten rather
/// than parsed or refused. All three are silent-data shapes: nothing
/// logged, nothing counted, a green job with the wrong bytes.
#[test]
fn undefined_entities_and_self_closing_segments_do_not_rewrite_the_manifest() {
    // 1. An undefined entity inside a message-id was DROPPED, so the
    // id parsed as a different, non-existent article.
    let in_text = br#"<?xml version="1.0"?>
<nzb><file subject="s" poster="p" date="1">
  <groups><group>a.b</group></groups>
  <segments><segment bytes="1" number="1">abc&bogus;def@news.example</segment></segments>
</file></nzb>"#;
    let err = Nzb::parse(in_text).expect_err("an undefined entity in text must reject");
    assert!(
        matches!(&err, NzbError::UnknownEntity(name) if name == "bogus"),
        "{err:?}"
    );

    // 2. An entity in a group name split it into two invented names.
    let split_group = br#"<?xml version="1.0"?>
<nzb><file subject="s" poster="p" date="1">
  <groups><group>alt.bin&amp;ary</group></groups>
  <segments><segment bytes="1" number="1">a@b.c</segment></segments>
</file></nzb>"#;
    let nzb = Nzb::parse(split_group).expect("parses");
    assert_eq!(
        nzb.files[0].groups,
        vec!["alt.bin&ary".to_string()],
        "one group element is one group name"
    );

    // 3. A self-closing segment vanished without being counted, so
    // the manifest shrank in silence.
    let empty_seg = br#"<?xml version="1.0"?>
<nzb><file subject="s" poster="p" date="1">
  <groups><group>a.b</group></groups>
  <segments>
<segment bytes="700000" number="1">a@b.c</segment>
<segment bytes="700000" number="2"/>
  </segments>
</file></nzb>"#;
    let nzb = Nzb::parse(empty_seg).expect("parses");
    assert_eq!(nzb.files[0].segments.len(), 1);
    assert_eq!(
        nzb.files[0].dropped_segments, 1,
        "a declared segment we cannot fetch must be counted, not lost"
    );

    // 4. And the same file with NO segment element at all. The plan
    // took that as a slot owing nothing - total 0, remaining 0,
    // missing 0 - so the census never called it incomplete and the
    // job finished GREEN with nothing on disk under that name, and
    // no repair, because nothing was missing.
    let no_segs = br#"<?xml version="1.0"?>
<nzb>
  <file subject="declared but empty" poster="p" date="1">
<groups><group>a.b</group></groups>
<segments></segments>
  </file>
  <file subject="the real one" poster="p" date="1">
<groups><group>a.b</group></groups>
<segments><segment bytes="700000" number="1">a@b.c</segment></segments>
  </file>
</nzb>"#;
    let nzb = Nzb::parse(no_segs).expect("parses");
    assert_eq!(nzb.files.len(), 2, "the file is kept, not dropped");
    assert!(nzb.files[0].segments.is_empty());
    assert_eq!(
        nzb.files[0].dropped_segments, 1,
        "a file that declares no segment at all owes ONE unfetchable one"
    );
    assert_eq!(
        nzb.files[1].dropped_segments, 0,
        "and a healthy file beside it is untouched"
    );
}

/// Soak corpus strictness guards: entity tolerance must not loosen
/// the parser elsewhere. An element name starting with a digit
/// (crashed nzbget, their issue #744 shape) and a document truncated
/// mid-element both stay rejected.
#[test]
fn garbled_and_truncated_nzbs_still_rejected() {
    let garbled = include_bytes!("../testdata/nzb/synth-744-garbled-element.nzb");
    assert!(
        Nzb::parse(garbled).is_err(),
        "element name starting with a digit must reject"
    );
    let truncated = include_bytes!("../testdata/nzb/synth-truncated.nzb");
    assert!(
        Nzb::parse(truncated).is_err(),
        "document truncated mid-element must reject"
    );
}

/// A message-id carrying CR/LF would end our `BODY <id>` command and start
/// the attacker's next command on the user's authenticated, paid provider
/// session (POST/IHAVE among them), and desync every pipelined reply after
/// it. Both routes into the id are covered: numeric char refs, which
/// quick-xml resolves to the real control characters, and a CDATA body,
/// which can hold the raw bytes. Such segments are dropped at parse.
#[test]
fn segments_with_crlf_message_ids_are_dropped() {
    let xml = br#"<?xml version="1.0"?>
<nzb>
  <file subject="x" poster="p" date="1700000000">
<groups><group>alt.binaries.test&#13;&#10;POST</group></groups>
<segments>
  <segment bytes="1" number="1">a@b&#13;&#10;POST&#13;&#10;c@d</segment>
  <segment bytes="1" number="2"><![CDATA[e@f
POST]]></segment>
  <segment bytes="1" number="3">clean@example.com</segment>
</segments>
  </file>
</nzb>"#;
    let nzb = Nzb::parse(xml).expect("parses");
    let f = &nzb.files[0];
    assert_eq!(
        f.segments.len(),
        1,
        "only the clean segment may survive: {:?}",
        f.segments
    );
    assert_eq!(f.segments[0].message_id, "clean@example.com");
    for seg in &f.segments {
        assert!(
            is_wire_safe(&seg.message_id),
            "unsafe id survived: {:?}",
            seg.message_id
        );
    }
    // The group name takes the same route into `GROUP {name}`.
    assert!(
        f.groups.iter().all(|g| is_wire_safe(g)),
        "unsafe group survived: {:?}",
        f.groups
    );
    // The drop must not silently shrink the manifest: the caller
    // has to learn two declared segments can never be fetched, or a
    // hostile NZB completes green with a zero-filled file.
    assert_eq!(f.dropped_segments, 2);
}

/// XML entities split a meta value into separate text events, and
/// trimming each fragment ate the spaces AROUND the entity: a
/// password of `secret &amp; more` decoded to `secret&more`, and
/// extraction then used a password that never existed. Only the
/// whole assembled value may be trimmed.
#[test]
fn entities_in_meta_values_keep_their_neighbouring_spaces() {
    let xml = br#"<?xml version="1.0"?>
<nzb>
  <head>
<meta type="password">  secret &amp; more </meta>
<meta type="title">a &lt;b&gt; c</meta>
  </head>
  <file subject="x" poster="p" date="1700000000">
<groups><group>alt.binaries.test</group></groups>
<segments>
  <segment bytes="1" number="1">clean@example.com</segment>
</segments>
  </file>
</nzb>"#;
    let nzb = Nzb::parse(xml).expect("parses");
    assert_eq!(nzb.password(), Some("secret & more"));
    let title = nzb
        .meta
        .iter()
        .find(|(t, _)| t == "title")
        .map(|(_, v)| v.as_str());
    assert_eq!(title, Some("a <b> c"));
}

/// A file whose EVERY segment is refused still parses (the NZB is
/// not empty), but it must carry the refusal count: with zero
/// segments and zero dropped it would enter the downloader with
/// nothing to fetch, nothing missing, and finish green having
/// written no bytes at all.
#[test]
fn a_file_of_only_unsafe_segments_records_the_drops() {
    let xml = br#"<?xml version="1.0"?>
<nzb>
  <file subject="x" poster="p" date="1700000000">
<groups><group>alt.binaries.test</group></groups>
<segments>
  <segment bytes="1" number="1">a@b&#13;&#10;POST&#13;&#10;c@d</segment>
</segments>
  </file>
</nzb>"#;
    let nzb = Nzb::parse(xml).expect("parses");
    let f = &nzb.files[0];
    assert!(f.segments.is_empty());
    assert_eq!(f.dropped_segments, 1);
}

fn sample() -> &'static [u8] {
    br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <file poster="poster@example.com" date="1700000000" subject="Big Release [1/3] - &quot;release.part1.rar&quot; yEnc (1/2)">
<groups>
  <group>alt.binaries.test</group>
  <group>alt.binaries.misc</group>
</groups>
<segments>
  <segment bytes="750000" number="2">seg2@news.example</segment>
  <segment bytes="750000" number="1">seg1@news.example</segment>
</segments>
  </file>
  <file poster="poster@example.com" date="1700000001" subject="Big Release [2/3] - &quot;release.par2&quot; yEnc (1/1)">
<groups><group>alt.binaries.test</group></groups>
<segments>
  <segment bytes="50000" number="1">par2main@news.example</segment>
</segments>
  </file>
  <file poster="poster@example.com" date="1700000002" subject="Big Release [3/3] - &quot;release.vol000+01.par2&quot; yEnc (1/1)">
<groups><group>alt.binaries.test</group></groups>
<segments>
  <segment bytes="100000" number="1">par2vol@news.example</segment>
</segments>
  </file>
</nzb>"#
}

#[test]
fn meta_password_entities_resolved() {
    // No <head> at all → None.
    assert_eq!(Nzb::parse(sample()).unwrap().password(), None);
    // Entities inside the password ("s3cret&amp;pw") arrive as their
    // own GeneralRef events and must be stitched back in.
    let with_head = String::from_utf8_lossy(sample()).replace(
        "<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">",
        "<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <head>\n    <meta type=\"title\">Big Release</meta>\n    <meta type=\"PASSWORD\">s3cret&amp;pw</meta>\n  </head>",
    );
    let nzb = Nzb::parse(with_head.as_bytes()).unwrap();
    assert_eq!(nzb.password(), Some("s3cret&pw"));
    assert_eq!(nzb.files.len(), 3, "head must not disturb file parsing");
}

#[test]
fn parses_files_groups_segments() {
    let nzb = Nzb::parse(sample()).unwrap();
    assert_eq!(nzb.files.len(), 3);

    let f = &nzb.files[0];
    assert_eq!(f.poster, "poster@example.com");
    assert_eq!(f.date, 1700000000);
    assert_eq!(f.groups, vec!["alt.binaries.test", "alt.binaries.misc"]);
    assert_eq!(f.segments.len(), 2);
    // Sorted by part number despite reversed document order.
    assert_eq!(f.segments[0].number, 1);
    assert_eq!(f.segments[0].message_id, "seg1@news.example");
    assert_eq!(f.segments[1].number, 2);
    assert_eq!(f.filename_hint(), Some("release.part1.rar"));
}

#[test]
fn cdata_segment_id_and_group_preserved() {
    // A CDATA-wrapped message-id / group must not be silently dropped
    // (quick-xml emits it as Event::CData, a distinct event).
    let xml = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <file poster="x" date="0" subject="&quot;a.rar&quot; yEnc (1/1)">
<groups><group><![CDATA[alt.binaries.cdata]]></group></groups>
<segments>
  <segment bytes="750000" number="1"><![CDATA[seg-cdata@news.example]]></segment>
</segments>
  </file>
</nzb>"#;
    let nzb = Nzb::parse(xml).unwrap();
    assert_eq!(nzb.files.len(), 1);
    let f = &nzb.files[0];
    assert_eq!(f.segments.len(), 1, "CDATA segment must not be dropped");
    assert_eq!(f.segments[0].message_id, "seg-cdata@news.example");
    assert_eq!(f.groups, vec!["alt.binaries.cdata"]);
}

#[test]
fn classifies_par2_roles() {
    let nzb = Nzb::parse(sample()).unwrap();
    assert_eq!(nzb.files[0].kind(), FileKind::Data);
    assert_eq!(nzb.files[1].kind(), FileKind::Par2Main);
    assert_eq!(nzb.files[2].kind(), FileKind::Par2Volume);
}

#[test]
fn classifies_dash_range_volumes() {
    // Range-style names ("vol000-001" … "vol127-199", end-exclusive)
    // are recovery volumes, not extra copies of the main index - a
    // Par2Main misclassification pulls the whole recovery set (GBs)
    // ahead of the data and buffers it in memory.
    let mut f = NzbFile {
        subject: r#"< Rel > - "Rel.vol127-199.par2" yEnc (01/99)"#.to_string(),
        ..NzbFile::default()
    };
    assert_eq!(f.kind(), FileKind::Par2Volume);
    f.subject = r#"< Rel > - "Rel.vol000-001.par2" yEnc (1/1)"#.to_string();
    assert_eq!(f.kind(), FileKind::Par2Volume);
    // Bare-ordinal volumes: NOTHING before the dash, zero-padded
    // ("Rel.vol-01.par2" … "Rel.vol-09.par2" - playWEB, NORViNE,
    // GRACE posts, measured live 13 Aug 2026). Both spellings of
    // the old rule demanded digits there, so these classified
    // Par2Main and the whole recovery set (7.5 GB on one measured
    // 42 GiB post) was fetched eagerly.
    f.subject = r#"< Rel > - "Fightland.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-playWEB.vol-01.par2" yEnc (1/13)"#.to_string();
    assert_eq!(f.kind(), FileKind::Par2Volume);
    // A dash in the release name alone must not demote the index.
    f.subject = r#"< Rel > - "Some.Film.2026.H.265-GRP.par2" yEnc (1/1)"#.to_string();
    assert_eq!(f.kind(), FileKind::Par2Main);
    f.subject = r#"< Rel > - "Some.Film-GRP.vol.par2" yEnc (1/1)"#.to_string();
    assert_eq!(f.kind(), FileKind::Par2Main);
    f.subject = r#"< Rel > - "Rel.volume-2.par2" yEnc (1/1)"#.to_string();
    assert_eq!(f.kind(), FileKind::Par2Main);
    // A compilation numbered "Vol-3" is a release name, not a
    // recovery ordinal - single digit after the dash stays an index.
    f.subject = r#"< Rel > - "VA.Best.Hits.Vol-3.par2" yEnc (1/1)"#.to_string();
    assert_eq!(f.kind(), FileKind::Par2Main);
}

#[test]
fn filename_hint_skips_decoy_quotes() {
    // A quoted non-filename before the real one ("S01E01" here) made
    // kind() classify a recovery volume as Data - eager-fetching it.
    let f = NzbFile {
        subject: r#""S01E01" - "Show.vol000+50.par2" yEnc (1/60)"#.to_string(),
        ..NzbFile::default()
    };
    assert_eq!(f.filename_hint(), Some("Show.vol000+50.par2"));
    assert_eq!(f.kind(), FileKind::Par2Volume);
    // No dotted quoted run at all → first non-empty run still wins.
    let g = NzbFile {
        subject: r#"post "some label" yEnc (1/2)"#.to_string(),
        ..NzbFile::default()
    };
    assert_eq!(g.filename_hint(), Some("some label"));
}

/// T5: on the N6-04 ambiguity class the NAME pick must not answer a
/// recovery-volume name for a file the classifier already refused to
/// treat as one.
///
/// `"label.vol000+50.par2" - "Movie.mkv"` classifies `Data` (the runs
/// disagree, and `Data` is the only answer that cannot lose a file) and
/// the first-dotted-run pick still handed `label.vol000+50.par2` to the
/// slot's birth name, the per-file API row, the donor/dupefill key and
/// the PAR2 FileDesc length lookup. NOTHING pinned the hint for this
/// class before this test - the N6-04 test above pins only the kind - so
/// the rule change landed with no existing assertion to move.
///
/// Every row asserts the hint and the kind TOGETHER, because the whole
/// rule is that the pick agrees with the classification where it can.
#[test]
fn the_name_pick_agrees_with_the_classification() {
    let cases = [
        // Both orders of the T5 exemplar. The second was already right
        // (the payload is the first dotted run); it is pinned so a
        // future rule cannot fix one order by breaking the other.
        (
            r#"[1/2] - "label.vol000+50.par2" - "Movie.mkv" yEnc (1/2)"#,
            Some("Movie.mkv"),
            FileKind::Data,
        ),
        (
            r#"[1/2] - "Movie.mkv" - "label.vol000+50.par2" yEnc (1/2)"#,
            Some("Movie.mkv"),
            FileKind::Data,
        ),
        // The Par2Main spelling of the same trap: `.par2` with no
        // recovery-volume suffix excludes the file from ordinary payload
        // verification instead of from the fetch plan.
        (
            r#"[1/2] - "label.par2" - "Movie.mkv" yEnc (1/2)"#,
            Some("Movie.mkv"),
            FileKind::Data,
        ),
        // FALLBACK 1 - a disagreement where NO run agrees with the
        // answer: Par2Main against Par2Volume sums to `Data` and neither
        // run is `Data`. The old first-dotted-run rule is the fallback,
        // so the pick is unchanged rather than None.
        (
            r#"[1/2] - "label.par2" - "label.vol000+50.par2" yEnc (1/2)"#,
            Some("label.par2"),
            FileKind::Data,
        ),
        // FALLBACK 2 - no disagreement at all. The first dotted run
        // agrees with the answer by definition, so agreeing-run and
        // first-dotted-run are the same pick. Inert by construction.
        (
            r#""Show.vol000+50.par2" - "Show.vol050+50.par2" yEnc"#,
            Some("Show.vol000+50.par2"),
            FileKind::Par2Volume,
        ),
        (
            r#""Show.mkv" - "Show.nfo" yEnc"#,
            Some("Show.mkv"),
            FileKind::Data,
        ),
        // The mirror shape this rule CANNOT fix, pinned as such: a
        // dotted LABEL first, which agrees with `Data` before the real
        // volume name is reached. Both runs are plausible filenames, so
        // no par2-awareness in a PICK can separate them - the answer is
        // wrong in the other direction and stays exactly as it was.
        (
            r#"[1/2] - "Show.S01E01" - "Show.vol000+50.par2" yEnc (1/2)"#,
            Some("Show.S01E01"),
            FileKind::Data,
        ),
        // ONE dotted candidate decides alone, so the decoy-first posts
        // the quoted read was written for keep BOTH answers they had.
        (
            r#"[1/2] - "S01E01" - "Show.vol000+50.par2" yEnc (1/2)"#,
            Some("Show.vol000+50.par2"),
            FileKind::Par2Volume,
        ),
    ];
    for (subject, want_hint, want_kind) in cases {
        let f = NzbFile {
            subject: subject.to_string(),
            ..NzbFile::default()
        };
        assert_eq!(f.kind(), want_kind, "kind: {subject}");
        assert_eq!(f.filename_hint(), want_hint, "hint: {subject}");
        // The pick moves at `quoted_filename`, not at `filename_hint`:
        // `index::ingest::quoted_name` and `faultplan::vol_first_block`
        // reach it directly, and one rule may not have two spellings.
        assert_eq!(quoted_filename(subject), want_hint, "direct: {subject}");
    }
}

/// Issue #55's exact posting shape: no quotes anywhere, the real
/// filename in the clear with a `(part/total)` counter after it.
/// The quoted read answers None and the slot was named `fileNNN`,
/// the real name discarded - the lenient read is what plan uses.
#[test]
fn unquoted_subject_filenames_are_recovered() {
    for (subject, want) in [
        // The reporter's track and its per-track PAR2 set.
        (
            "10-Track Name-8c63a701.flac (1/0)",
            Some("10-Track Name-8c63a701.flac"),
        ),
        (
            "01-Other One-ea8f7cf8.flac.par2 (1/0)",
            Some("01-Other One-ea8f7cf8.flac.par2"),
        ),
        (
            "01-Other One-ea8f7cf8.flac.vol00+01.par2 (1/0)",
            Some("01-Other One-ea8f7cf8.flac.vol00+01.par2"),
        ),
        // The yEnc marker ends the name; index tags strip.
        ("release.part01.rar yEnc (1/2)", Some("release.part01.rar")),
        ("[01/30] - foo.rar (1/5)", Some("foo.rar")),
        // Prose subjects must NOT read as filenames: no extension,
        // or a trailing year where an extension would be.
        ("Great Album Name yEnc (1/15)", None),
        ("Movie Title 2026 (1/3)", None),
        ("Movie.2026 (1/3)", None),
        ("(1/0)", None),
        ("", None),
    ] {
        assert_eq!(unquoted_filename(subject), want, "subject: {subject:?}");
    }
    // A quoted name still wins over anything unquoted beside it,
    // and the lenient method is quoted-first.
    let f = NzbFile {
        subject: r#"decoy.flac - "real.part1.rar" yEnc (1/2)"#.to_string(),
        ..NzbFile::default()
    };
    assert_eq!(f.filename_hint_lenient(), Some("real.part1.rar"));
    let g = NzbFile {
        subject: "10-Track Name-8c63a701.flac (1/0)".to_string(),
        ..NzbFile::default()
    };
    assert_eq!(g.filename_hint(), None, "the quoted read stays narrow");
    assert_eq!(
        g.filename_hint_lenient(),
        Some("10-Track Name-8c63a701.flac")
    );
    // ...and kind() still classifies the unquoted PAR2 subjects off
    // the raw-subject fallback, exactly as before this existed.
    let p = NzbFile {
        subject: "01-Other One-ea8f7cf8.flac.vol00+01.par2 (1/0)".to_string(),
        ..NzbFile::default()
    };
    assert_eq!(p.kind(), FileKind::Par2Volume);
}

/// A hostile .nzb can name its volumes anything. `u64::MAX` parses,
/// and used to be cast straight to `usize` and added into the
/// pre-flight recovery budget - two such volumes overflowed the sum
/// (panic in a debug build, a wrapped attacker-chosen budget in
/// release, which then chose the REPAIRABLE / IMPOSSIBLE verdict).
/// The file must stay classified as a recovery volume, because a
/// volume never gets a download slot; only the COUNT goes unknown.
#[test]
fn absurd_declared_slice_counts_are_undeclared_not_sizes() {
    assert_eq!(par2_vol_count("Rel.vol0+18446744073709551615.par2"), None);
    assert_eq!(par2_vol_count("Rel.vol0-18446744073709551615.par2"), None);
    // Above u64 entirely: already None via the parse, pinned so the
    // two paths keep agreeing.
    assert_eq!(par2_vol_count("Rel.vol0+184467440737095516150.par2"), None);
    // Truncated to 1 on a 32-bit target before `try_from`.
    assert_eq!(par2_vol_count("Rel.vol0+4294967297.par2"), None);
    // Still a volume: classification is par2_vol_suffix's question.
    assert_eq!(
        par2_vol_suffix("Rel.vol0+18446744073709551615.par2"),
        Some(3)
    );
    // Real shapes, including the largest ones anyone posts, unchanged.
    assert_eq!(par2_vol_count("Rel.vol012+10.par2"), Some(10));
    assert_eq!(par2_vol_count("x.vol10000+12345.par2"), Some(12345));
    assert_eq!(par2_vol_count("x.vol0+32768.par2"), Some(32768));
}

#[test]
fn vol_count_both_conventions() {
    assert_eq!(par2_vol_count("Rel.vol012+10.par2"), Some(10));
    assert_eq!(par2_vol_count("Rel.vol127-199.par2"), Some(72));
    assert_eq!(par2_vol_count("Rel.vol000-001.par2"), Some(1));
    assert_eq!(par2_vol_count("Rel.vol003-007.par2"), Some(4));
    assert_eq!(par2_vol_count("Rel.par2"), None);
    assert_eq!(par2_vol_count("Rel-GRP.par2"), None);
    assert_eq!(par2_vol_count("Rel.volume-2.par2"), None);
    // Bare ordinal: IS a volume (par2_vol_suffix), but its name
    // declares no slice count - callers fall back to estimates,
    // exactly like the nameless obfuscated path.
    assert_eq!(par2_vol_count("Rel.vol-01.par2"), None);
    assert_eq!(par2_vol_suffix("Rel.vol-01.par2"), Some(3));
    assert_eq!(par2_vol_suffix("Rel.vol-09.par2"), Some(3));
    assert_eq!(par2_vol_suffix("Rel.vol012+10.par2"), Some(3));
    assert_eq!(par2_vol_suffix("Rel.vol127-199.par2"), Some(3));
    // Not volumes: non-numeric field before the separator, spelt-out
    // "volume", a bare index, a single-digit compilation number.
    assert_eq!(par2_vol_suffix("Rel.volume-2.par2"), None);
    assert_eq!(par2_vol_suffix("Some.Film-GRP.vol.par2"), None);
    assert_eq!(par2_vol_suffix("Some.Film.2026.H.265-GRP.par2"), None);
    assert_eq!(par2_vol_suffix("VA.Best.Hits.Vol-3.par2"), None);
    // The suffix must sit at the end of the name (or right before
    // .par2) - "Vol-52" mid-name is a title, not a volume.
    assert_eq!(par2_vol_suffix("VA.Hits.Vol-52.2CD-2023-GRP.par2"), None);
    // kind() falls back to the RAW SUBJECT when nothing is quoted,
    // so the rule must see through a " yEnc (n/m)" tail after .par2.
    assert_eq!(par2_vol_suffix("set.vol000+01.par2 yEnc (1/1)"), Some(3));
    assert_eq!(par2_vol_suffix("set.vol-01.par2 yEnc (1/1)"), Some(3));
    assert_eq!(par2_vol_suffix("set.par2 yEnc (1/1)"), None);
    // ...but ONLY whitespace ends the name. A quoted filename that
    // carries on past .par2 is a DATA file: classifying it as a
    // volume costs it its download slot, and the job then completes
    // without the payload it never fetched (14 Aug sweep).
    assert_eq!(par2_vol_suffix("x.vol-10.par2.bak"), None);
    assert_eq!(par2_vol_suffix("extras.vol-10.par2-sample.mkv"), None);
    assert_eq!(par2_vol_suffix("set.vol000+01.par2.txt"), None);
}

/// The same rule where it actually decides a download: `kind()`.
#[test]
fn a_quoted_name_continuing_past_par2_stays_data() {
    let file = |subject: &str| NzbFile {
        subject: subject.to_string(),
        ..Default::default()
    };
    // The genuine shapes still classify as they did.
    assert_eq!(
        file("Rel [2/3] - \"rel.vol-01.par2\" yEnc (1/1)").kind(),
        FileKind::Par2Volume
    );
    assert_eq!(
        file("Rel [1/3] - \"rel.par2\" yEnc (1/1)").kind(),
        FileKind::Par2Main
    );
    // A quoted payload name that merely CONTAINS the pattern is data
    // and must keep its slot.
    assert_eq!(
        file("Rel [3/3] - \"extras.vol-10.par2-sample.mkv\" yEnc (1/1)").kind(),
        FileKind::Data
    );
    assert_eq!(
        file("Rel [3/3] - \"rel.vol-10.par2.bak\" yEnc (1/1)").kind(),
        FileKind::Data
    );
}

/// One answer to "which par2 file do I fetch to get the critical
/// packets", shared by the download path and pre-flight.
///
/// The download path needs it because an obfuscated post ships
/// volumes and no index, and it bootstraps the set from the smallest
/// one. Pre-flight needs it because the Main packet is the only
/// place the block size is written down, and a `.vol-NN.par2` budget
/// cannot be sized without it. The 15 Aug post was both cases at
/// once: seven `.vol-NN` volumes, no index, and the smallest of them
/// a 41,901-byte file that turned out to hold Main + FileDesc + IFSC
/// and not one recovery slice.
#[test]
fn the_par2_seed_is_the_cheapest_file_carrying_the_critical_packets() {
    let file = |subject: &str, bytes: u64| NzbFile {
        subject: subject.to_string(),
        segments: vec![Segment {
            number: 1,
            bytes,
            message_id: format!("{bytes}@x"),
        }],
        ..Default::default()
    };
    let nzb = |files: Vec<NzbFile>| Nzb {
        files,
        meta: Vec::new(),
    };

    // An index beats every volume, however small the volumes are.
    let with_index = nzb(vec![
        file("\"rel.mkv\" yEnc (1/1)", 3_000_000),
        file("\"rel.vol000+02.par2\" yEnc (1/1)", 900),
        file("\"rel.par2\" yEnc (1/1)", 40_000),
    ]);
    assert_eq!(with_index.par2_seed_file(), Some(2));

    // No index: the smallest volume, which is the 15 Aug shape.
    let obfuscated = nzb(vec![
        file("\"rel.mkv\" yEnc (1/1)", 3_332_350_599),
        file("\"rel.vol-05.par2\" yEnc (1/1)", 26_869_479),
        file("\"rel.vol-01.par2\" yEnc (1/1)", 41_901),
        file("\"rel.vol-02.par2\" yEnc (1/1)", 1_708_175),
    ]);
    assert_eq!(obfuscated.par2_seed_file(), Some(2));

    // A par2 file with no segments cannot be fetched, so it is not
    // the seed however small it looks.
    let mut empty_index = file("\"rel.par2\" yEnc (1/1)", 0);
    empty_index.segments.clear();
    let holed = nzb(vec![
        empty_index,
        file("\"rel.vol-01.par2\" yEnc (1/1)", 41_901),
    ]);
    assert_eq!(holed.par2_seed_file(), Some(1));

    // A post with no par2 at all has no seed and no budget to size.
    assert_eq!(
        nzb(vec![file("\"rel.mkv\" yEnc (1/1)", 3_000_000)]).par2_seed_file(),
        None
    );
}

#[test]
fn minimality_accounting() {
    let nzb = Nzb::parse(sample()).unwrap();
    assert_eq!(nzb.total_bytes(), 1_650_000);
    // Eager set skips the recovery volume.
    assert_eq!(nzb.eager_bytes(), 1_550_000);
}

#[test]
fn parses_head_meta_password() {
    let xml = br#"<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
<meta type="title">Big Release</meta>
<meta type="PASSWORD">s3cret pass</meta>
<meta type="category"></meta>
  </head>
  <file poster="p" date="1" subject="s">
<groups><group>alt.binaries.test</group></groups>
<segments><segment bytes="1" number="1">a@b</segment></segments>
  </file>
</nzb>"#;
    let nzb = Nzb::parse(xml).unwrap();
    // Type is lowercased; empty-valued metas are dropped.
    assert_eq!(
        nzb.meta,
        vec![
            ("title".to_string(), "Big Release".to_string()),
            ("password".to_string(), "s3cret pass".to_string()),
        ]
    );
    assert_eq!(nzb.password(), Some("s3cret pass"));

    let plain = Nzb::parse(sample()).unwrap();
    assert_eq!(plain.password(), None);
}

/// The parser applies XML attribute-value normalization, and a
/// comment claimed for months that it did not. Both halves are
/// pinned here so the next reader can see the rule rather than the
/// claim: a LITERAL tab (or CR, or LF) inside an attribute is a
/// space by the time we see it, and a numeric character reference
/// survives untouched - that is the escape hatch a producer who
/// really means a tab has to use. Covers `subject` and `poster`
/// (one `<file>` attribute route) and `<meta type=>` (the other).
#[test]
fn subject_whitespace_is_normalized_per_xml_spec() {
    let xml = b"<?xml version=\"1.0\"?>
<nzb>
  <head><meta type=\"pass\tword\">hunter2</meta></head>
  <file subject=\"a\tb\r\nc\" poster=\"p\tq\" date=\"1700000000\">
<groups><group>alt.binaries.test</group></groups>
<segments><segment bytes=\"1\" number=\"1\">a@b</segment></segments>
  </file>
  <file subject=\"a&#9;b\" poster=\"p\" date=\"1700000000\">
<groups><group>alt.binaries.test</group></groups>
<segments><segment bytes=\"1\" number=\"1\">c@d</segment></segments>
  </file>
</nzb>";
    let nzb = Nzb::parse(xml).expect("parses");
    // Literal tab -> space; CRLF is one space, not two.
    assert_eq!(nzb.files[0].subject, "a b c");
    assert_eq!(nzb.files[0].poster, "p q");
    // A character reference is NOT normalization input, so it lands
    // as the byte the producer asked for.
    assert_eq!(nzb.files[1].subject, "a\tb");
    // The meta `type=` attribute takes the same route (and is
    // lowercased and trimmed after, which does not touch interior
    // whitespace).
    assert_eq!(nzb.meta[0].0, "pass word");
}

#[test]
fn rejects_empty() {
    let err = Nzb::parse(br#"<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb"></nzb>"#);
    assert!(matches!(err, Err(NzbError::Empty)));
}

/// The whole N6 family's completion rule, in one sentence: a
/// difficult NZB may be accepted accurately or refused honestly, but
/// no well-formed input may silently lose or reclassify a declared
/// file while the reduced manifest can still complete green.
///
/// `<groups>`/`<segments>` around a real segment, so a file that
/// survives is a file with something to fetch.
fn one_file(subject: &str, id: &str) -> String {
    format!(
        "<file subject=\"{subject}\" date=\"1700000000\">\
         <groups><group>alt.binaries.test</group></groups>\
         <segments><segment bytes=\"100\" number=\"1\">{id}</segment></segments>\
         </file>"
    )
}

fn doc(body: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">{body}</nzb>"
    )
}

/// N6-01: a self-closing `<file/>` DECLARES a file, so it must
/// arrive in the manifest owing a segment.
///
/// `Event::Empty` reached only the `<segment/>` arm, so
/// `<file subject="missing.rar"/>` beside a healthy file parsed as
/// ONE file. That is the worst shape in this whole sweep: the
/// declared name charged no `dropped_segments`, `build_fetch_plan`
/// built no slot for it, and every later count - total, remaining,
/// missing, the completion census - was self-consistent WITHOUT it,
/// so the payload was named in the manifest, never mentioned again,
/// and the job returned rc=0.
///
/// The fix declares rather than rejects, and the reason is that the
/// answer was already written down twice next door: a `<segment/>`
/// charges one dropped segment, and a `<file></file>` that declares
/// no segment at all charges one too. Both arms say the same thing -
/// there is nothing to FETCH here, only something to DECLARE - and a
/// self-closing `<file/>` is the same statement in a third spelling.
/// Rejecting it would also refuse a manifest whose only sin is
/// whitespace-free XML, where the two sibling shapes are accepted.
/// Either way the rule holds: never rc=0 with the file omitted.
#[test]
fn a_self_closing_file_is_declared_missing_not_dropped() {
    let n = Nzb::parse(
        doc(&format!(
            "<file subject=\"missing.rar\"/>{}",
            one_file("good.rar", "g@t")
        ))
        .as_bytes(),
    )
    .expect("parses");
    assert_eq!(n.files.len(), 2, "the declared file must not disappear");
    assert_eq!(n.files[0].subject, "missing.rar");
    assert!(n.files[0].segments.is_empty());
    assert_eq!(
        n.files[0].dropped_segments, 1,
        "nothing to fetch, so something to declare: the slot owes a segment"
    );
    // Byte-for-byte the same manifest as the expanded spelling.
    let expanded = Nzb::parse(
        doc(&format!(
            "<file subject=\"missing.rar\"></file>{}",
            one_file("good.rar", "g@t")
        ))
        .as_bytes(),
    )
    .expect("parses");
    assert_eq!(n, expanded);
}

/// N6-02: an extension attribute cannot overwrite core vocabulary,
/// in EITHER order.
///
/// Dispatch was on `local_name()` alone, so `x:subject` and
/// `subject` were one field: the last one written won, which made
/// the parsed name and the FileKind a function of attribute ORDER.
/// Both orders are pinned because one order was already "right" by
/// luck and pinning only that one proves nothing.
#[test]
fn a_namespaced_attribute_cannot_overwrite_a_core_one() {
    for body in [
        "<file subject=\"movie.mkv\" x:subject=\"decoy.vol000+50.par2\" \
         x:bytes=\"7\" x:number=\"9\" date=\"1700000000\">\
         <groups><group>alt.binaries.test</group></groups>\
         <segments><segment bytes=\"100\" number=\"1\" x:bytes=\"7\">a@t</segment></segments>\
         </file>",
        "<file x:subject=\"decoy.vol000+50.par2\" subject=\"movie.mkv\" \
         date=\"1700000000\">\
         <groups><group>alt.binaries.test</group></groups>\
         <segments><segment x:bytes=\"7\" bytes=\"100\" number=\"1\">a@t</segment></segments>\
         </file>",
    ] {
        let xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\" \
             xmlns:x=\"urn:example:not-nzb\">{body}</nzb>"
        );
        let n = Nzb::parse(xml.as_bytes()).expect("parses");
        assert_eq!(n.files[0].subject, "movie.mkv");
        assert_eq!(n.files[0].kind(), FileKind::Data);
        assert_eq!(n.files[0].segments[0].bytes, 100);
        assert_eq!(n.files[0].segments[0].number, 1);
    }
}

/// N6-02, the element half: `<x:file>` is not a file.
///
/// It used to parse as one. It is now an extension element, ignored
/// wholesale - and its unprefixed `<segments>` child, which the
/// document's own default namespace puts squarely IN the core
/// vocabulary, is refused rather than ignored. Ignoring is how a
/// declared file disappears; refusing is the honest half of the
/// completion rule.
#[test]
fn a_namespaced_element_is_not_core_vocabulary() {
    let xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\" \
         xmlns:x=\"urn:example:not-nzb\"><x:file subject=\"foreign.mkv\">{}</x:file>{}</nzb>",
        "<groups><group>alt.binaries.test</group></groups>",
        one_file("real.mkv", "r@t")
    );
    assert!(matches!(
        Nzb::parse(xml.as_bytes()),
        Err(NzbError::Schema(_))
    ));
    // An extension element that keeps to its OWN namespace is simply
    // ignored, and the real file beside it parses.
    let xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\" \
         xmlns:x=\"urn:example:not-nzb\"><x:file><x:note>hi</x:note></x:file>{}</nzb>",
        one_file("real.mkv", "r@t")
    );
    let n = Nzb::parse(xml.as_bytes()).expect("parses");
    assert_eq!(n.files.len(), 1);
    assert_eq!(n.files[0].subject, "real.mkv");
}

/// N6-02: core vocabulary is whatever the ROOT is in, so an NZB that
/// declares no `xmlns` (most hand-written ones) keeps parsing and an
/// NZB that declares a variant one does too.
#[test]
fn the_root_namespace_defines_the_core_vocabulary() {
    for root in [
        "<nzb>",
        "<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">",
        "<nzb xmlns=\"urn:example:some-other-nzb-uri\">",
    ] {
        let xml = format!("{root}{}</nzb>", one_file("real.mkv", "r@t"));
        let n =
            Nzb::parse(xml.as_bytes()).unwrap_or_else(|e| panic!("{root} should parse, got {e}"));
        assert_eq!(n.files.len(), 1);
        assert_eq!(n.files[0].segments.len(), 1);
    }
}

/// N6-03: one root, and core tags only where the grammar has a place
/// for them.
///
/// The parser kept ONE `cur_file` and ONE `cur_segment` and checked
/// nothing but depth at EOF, so every row below used to be accepted
/// with a manifest quietly smaller than the document declared. The
/// oracle is the COUNT, not "did parse() return Ok" - a nested
/// `<file>` replaced its parent and a nested `<segment>` replaced
/// its parent with no `dropped_segments` charge, and both of those
/// are successful parses of the wrong manifest.
#[test]
fn a_second_root_or_a_misplaced_core_tag_is_refused() {
    let good = one_file("a.rar", "a@t");
    for (why, xml) in [
        (
            "a file under a non-NZB wrapper",
            format!("<other>{good}</other>"),
        ),
        (
            "two concatenated roots merge into one manifest",
            format!("<nzb>{good}</nzb><nzb>{}</nzb>", one_file("b.rar", "b@t")),
        ),
        (
            "a nested file replaces and loses the outer one",
            doc(&format!(
                "<file subject=\"outer.rar\">{}</file>",
                one_file("inner.rar", "i@t")
            )),
        ),
        (
            "a nested segment replaces the outer one, uncharged",
            doc("<file subject=\"a.rar\"><segments>\
                 <segment bytes=\"1\" number=\"1\">outer@t\
                 <segment bytes=\"2\" number=\"2\">inner@t</segment>\
                 </segment></segments></file>"),
        ),
        ("a file inside <head>", doc(&format!("<head>{good}</head>"))),
        (
            "a segment outside any file",
            doc("<segments><segment bytes=\"1\" number=\"1\">a@t</segment></segments>"),
        ),
    ] {
        let got = Nzb::parse(xml.as_bytes());
        assert!(
            matches!(got, Err(NzbError::Schema(_))),
            "{why}: expected a schema refusal, got {got:?}"
        );
    }
    // The shapes next door that MUST keep parsing: an ordinary
    // document, and a truncated one, which is its own diagnosis.
    assert!(Nzb::parse(doc(&good).as_bytes()).is_ok());
    assert!(matches!(
        Nzb::parse(format!("<nzb>{good}").as_bytes()),
        Err(NzbError::Truncated)
    ));
}

/// T1: the root spellings a FIELD corpus actually carries.
///
/// N6-03 reads the core namespace off the ROOT rather than pinning it
/// to the newzbin URI, and `child_ctx` then refuses a core-namespace
/// reserved name outside its legal parent. Both halves make the root's
/// exact spelling load-bearing, and nothing pinned the spellings real
/// indexers write.
///
/// So they were counted. 270 unique documents on 2026-08-30 - 253 real
/// manifests off the indexers in use plus the 17 fixtures the SABnzbd
/// and NZBGet projects publish - and all 270 parse. Three of the root
/// spellings in that corpus are not the textbook one, and each is a
/// row below: 264 write the newzbin `xmlns`; 3 write a bare `<nzb>`
/// with NO namespace at all, so core vocabulary is the NO-namespace
/// one and an unprefixed `<file>` under it is still core; and 3 declare
/// a second, junk prefix beside the core one (`xmlns:date="224644"`,
/// from one generator family), which must not make the document
/// foreign to itself. A fourth row carries the multi-line DOCTYPE 26 of
/// them write.
///
/// The failure this guards is a LATER tightening, not today's code,
/// and only ROW 2 was verified to bite: pinning core vocabulary to the
/// newzbin URI instead of taking it from the root reads as a hardening,
/// and reddens this test on the bare-`<nzb>` row. What it reddens with
/// is the reason the row is worth a test rather than a comment - not
/// `Schema` but `Empty`, "NZB contains no files", because every
/// unprefixed `<file>` becomes foreign and is ignored wholesale. That
/// is the silent-manifest shape N6-01 and N6-03 exist to refuse,
/// reintroduced by a change that looks like tightening.
///
/// Rows 1, 3 and 4 are corpus-shape CONTROLS and no mutation was found
/// that kills them alone: an unprefixed element under a default xmlns
/// resolves the same whether or not a junk second prefix is declared
/// beside it, so row 3 guards only a parser that refuses the
/// declaration itself. They are here because the corpus writes them,
/// not because a mutation proved them load-bearing.
#[test]
fn the_root_spellings_a_field_corpus_carries_all_parse() {
    let body = one_file("a.rar", "a@t");
    for (why, xml) in [
        (
            "the textbook root, 264 of 270",
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">{body}</nzb>"
            ),
        ),
        (
            "no namespace declared at all, 3 of 270",
            format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb>{body}</nzb>"),
        ),
        (
            "a junk second prefix beside the core one, 3 of 270",
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\" \
                 xmlns:date=\"224644\">{body}</nzb>"
            ),
        ),
        (
            "the multi-line DOCTYPE, 26 of 270",
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <!DOCTYPE nzb\nPUBLIC \"-//newzBin//DTD NZB 1.1//EN\"\n\
                 \x20      \"http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd\">\n\
                 <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">{body}</nzb>"
            ),
        ),
    ] {
        let got = Nzb::parse(xml.as_bytes());
        let n = got.unwrap_or_else(|e| panic!("{why}: expected a parse, got {e:?}"));
        assert_eq!(n.files.len(), 1, "{why}");
        assert_eq!(n.files[0].segments.len(), 1, "{why}");
        assert_eq!(n.files[0].segments[0].message_id, "a@t", "{why}");
        assert_eq!(
            n.files[0].groups,
            vec!["alt.binaries.test".to_string()],
            "{why}"
        );
    }
}

/// N6-02: text inside an extension element nested in a core one
/// cannot append to the core field. `<segment>real@t<x:note>junk\
/// </x:note></segment>` used to fetch `real@tjunk`, an id nobody
/// posted.
#[test]
fn text_inside_an_extension_child_does_not_reach_the_core_field() {
    let xml = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\" \
               xmlns:x=\"urn:example:not-nzb\">\
               <head><meta type=\"password\">secret<x:note>junk</x:note></meta></head>\
               <file subject=\"a.rar\" date=\"1700000000\">\
               <groups><group>alt.binaries.test<x:note>junk</x:note></group></groups>\
               <segments><segment bytes=\"1\" number=\"1\">real@t\
               <x:note>junk</x:note></segment></segments></file></nzb>";
    let n = Nzb::parse(xml.as_bytes()).expect("parses");
    assert_eq!(n.files[0].segments[0].message_id, "real@t");
    assert_eq!(n.files[0].groups, vec!["alt.binaries.test".to_string()]);
    assert_eq!(n.password(), Some("secret"));
}

/// N6-04: a subject that quotes two filename-looking names does not
/// let the FIRST one decide the kind.
///
/// The dangerous direction is the second row: a PAR2-looking label
/// in front of a real payload classified the payload as a recovery
/// volume, and `build_fetch_plan` gives a non-bootstrap volume no
/// slot at all - so the file was never fetched, nothing was ever
/// missing, and the job finished green. The third row does the same
/// through `Par2Main`, which excludes the file from ordinary payload
/// verification instead.
///
/// Disagreement answers `Data` because that is the only answer that
/// cannot lose a file: calling a recovery volume payload costs
/// bandwidth, calling a payload a recovery volume costs the
/// download.
#[test]
fn a_decoy_quote_cannot_capture_the_classification() {
    let cases = [
        // The two orders of the ambiguous PAR2/payload pair.
        (
            "[1/2] - \"label.vol000+50.par2\" - \"Movie.mkv\" yEnc (1/2)",
            FileKind::Data,
        ),
        (
            "[1/2] - \"Movie.mkv\" - \"label.vol000+50.par2\" yEnc (1/2)",
            FileKind::Data,
        ),
        (
            "[1/2] - \"label.par2\" - \"Movie.mkv\" yEnc (1/2)",
            FileKind::Data,
        ),
        (
            "[1/2] - \"Show.S01E01\" - \"Show.vol000+50.par2\" yEnc (1/2)",
            FileKind::Data,
        ),
        // ONE candidate still decides alone: an undotted run is a
        // label, not a filename, so the decoy-first posts the quoted
        // read was written for keep classifying as they always did.
        (
            "[1/2] - \"S01E01\" - \"Show.vol000+50.par2\" yEnc (1/2)",
            FileKind::Par2Volume,
        ),
        (
            "[1/2] - \"S01E01\" - \"Show.par2\" yEnc (1/2)",
            FileKind::Par2Main,
        ),
        (
            "[1/2] - \"S01E01\" - \"Show.part01.rar\" yEnc (1/2)",
            FileKind::Data,
        ),
        // Candidates that AGREE keep their answer.
        (
            "\"Show.vol000+50.par2\" - \"Show.vol050+50.par2\" yEnc",
            FileKind::Par2Volume,
        ),
        ("\"Show.mkv\" - \"Show.nfo\" yEnc", FileKind::Data),
    ];
    for (subject, want) in cases {
        let f = NzbFile {
            subject: subject.to_string(),
            ..Default::default()
        };
        assert_eq!(f.kind(), want, "{subject}");
        // The one classifier, reached the other way: `role_of` was a
        // hand-copied twin of this rule until 30 Aug 2026.
        assert_eq!(
            crate::faultplan::role_of(subject),
            want,
            "role_of {subject}"
        );
    }
}

/// N6-05: `.par2` followed by whitespace ends a name only in a RAW
/// subject, never inside a quoted one.
///
/// The allowance exists because `kind()` falls back to the whole
/// subject when nothing is quoted, and there `.par2` is followed by
/// ` yEnc (1/2)`. Applied to a name the quotes had already isolated,
/// it turned `"ordinary.par2 notes.txt"` into the recovery index and
/// `"extras.vol-10.par2 sample.mkv"` into a recovery volume - and a
/// volume never gets a download slot, so a payload listed in the NZB
/// was silently never fetched.
#[test]
fn a_quoted_name_must_end_at_par2() {
    for (subject, want) in [
        ("\"ordinary.par2 notes.txt\" yEnc (1/2)", FileKind::Data),
        (
            "\"extras.vol-10.par2 sample.mkv\" yEnc (1/2)",
            FileKind::Data,
        ),
        ("\"extras.vol-10.par2.bak\" yEnc (1/2)", FileKind::Data),
        // A quoted name that really does end there is unchanged.
        ("\"real.par2\" yEnc (1/2)", FileKind::Par2Main),
        ("\"real.vol000+10.par2\" yEnc (1/2)", FileKind::Par2Volume),
        // And the raw-subject allowance the rule exists for stays.
        ("real.par2 yEnc (1/2)", FileKind::Par2Main),
        ("real.vol000+10.par2 yEnc (1/2)", FileKind::Par2Volume),
    ] {
        let f = NzbFile {
            subject: subject.to_string(),
            ..Default::default()
        };
        assert_eq!(f.kind(), want, "{subject}");
    }
    // `par2_vol_suffix` keeps the lenient raw-subject rule for the
    // callers that hold a REAL filename - off disk, or out of the index
    // - rather than a subject (`extract::release_stem`, `scan.rs`),
    // where the isolated/raw distinction does not arise. The
    // subject-reading callers took `SubjectClass` on 31 Aug 2026; see
    // `a_subject_class_carries_the_rule_that_produced_the_kind`.
    assert!(par2_vol_suffix("a.vol-10.par2 yEnc (1/2)").is_some());
}

/// T2: a reader must not re-derive the isolated/raw rule after gating
/// on `kind()`, because the public `par2_vol_suffix` is the RAW rule
/// unconditionally and the two answer differently about one string.
///
/// MEASURED on origin/main at ed6857955, which is what this pins:
/// `"a.vol-10.par2 x.par2"` is `Par2Main` (the isolated rule refuses a
/// volume suffix whose tail carries on past `.par2`) while
/// `par2_vol_suffix` on the very same name answers `Some(1)` - so a
/// reader gating on the kind and then asking that function took the
/// stem `a`, which is a DIFFERENT SET's name. The consequence is pinned
/// one crate up in
/// `check_tests::a_quoted_par2_with_a_trailing_par2_is_its_own_set`.
///
/// The divergence is one-directional and that is worth knowing before
/// reading a green line here as more than it is: the isolated rule
/// accepts a strict SUBSET of the raw one, so a site gated on
/// `Par2Volume` (`repair::volume_candidates`, `faultplan`) cannot
/// currently disagree at all. It is still the same rule written twice,
/// which is what put N6-04 and N6-05 live in two places apiece.
#[test]
fn a_subject_class_carries_the_rule_that_produced_the_kind() {
    let divergent = "a.vol-10.par2 x.par2";
    let subject = format!("Rel - \"{divergent}\" yEnc (1/1)");
    let class = classify_subject_detail(&subject);
    assert_eq!(class.kind(), FileKind::Par2Main, "{divergent}");
    assert!(class.isolated(), "the name came from between quotes");
    assert_eq!(class.name(), divergent);
    assert_eq!(
        class.vol_suffix(),
        None,
        "not a volume, so it has no volume suffix"
    );
    assert_eq!(
        par2_vol_suffix(divergent),
        Some(1),
        "the raw rule still answers Some here - that IS the divergence"
    );
    assert_eq!(
        class.par2_stem(),
        Some("a.vol-10.par2 x"),
        "the stem comes off the terminal `.par2`, not off the raw rule's `.vol`"
    );

    // The ordinary shapes, where the two agree and always did.
    for (subject, kind, stem, isolated) in [
        (
            "Rel - \"seta.par2\" yEnc (1/1)",
            FileKind::Par2Main,
            "seta",
            true,
        ),
        (
            "Rel - \"seta.vol000+02.par2\" yEnc (1/1)",
            FileKind::Par2Volume,
            "seta",
            true,
        ),
        // Raw subject: `.par2` may be followed by ` yEnc (1/1)`, and
        // the stem stops at the FIRST such occurrence.
        ("setb.par2 yEnc (1/1)", FileKind::Par2Main, "setb", false),
        (
            "setb.vol000+02.par2 yEnc (1/1)",
            FileKind::Par2Volume,
            "setb",
            false,
        ),
        // An anonymous volume: a stem that is EMPTY, not absent.
        (
            "Rel - \".vol-01.par2\" yEnc (1/1)",
            FileKind::Par2Volume,
            "",
            true,
        ),
    ] {
        let class = classify_subject_detail(subject);
        assert_eq!(class.kind(), kind, "{subject}");
        assert_eq!(class.isolated(), isolated, "{subject}");
        assert_eq!(class.par2_stem(), Some(stem), "{subject}");
    }

    // Data never answers a PAR2 question, however par2-shaped the name
    // it was judged on: a disagreement between two quoted candidates is
    // `Data` (N6-04), and a reader that asked anyway would get a stem
    // for a file the classifier refused to call PAR2.
    let disagree = classify_subject_detail("\"label.vol000+50.par2\" - \"Movie.mkv\"");
    assert_eq!(disagree.kind(), FileKind::Data);
    assert_eq!(disagree.par2_stem(), None);
    assert_eq!(disagree.vol_suffix(), None);
}
// ---------------------------------------------------------------
// N6-06 .. N6-10, the parser/front-door addendum's P1 rows.
// Every one of these was measured RED on origin/main at 8fbe1c3bd
// before the fix beside it; the red value is written into each
// assertion's message so a future reader can see what the old
// behaviour was without going and reproducing it.
// ---------------------------------------------------------------

/// N6-06. A boundary character reference is EXPLICIT data. Rust's
/// `str::trim` removes Unicode whitespace, so `&#xa0;` and
/// `&#x2003;` at a field's edge used to vanish - and all three
/// fields this parser trims carry something that must never be
/// silently rewritten.
///
/// RED on origin/main: password `secret`, group
/// `alt.binaries.test`, message-id `real@news.example`, zero
/// segments dropped. Every one of those is a value the producer did
/// not write, and the message-id is the worst - a fabricated key,
/// passing `is_wire_safe`, fetched as an article nobody posted.
#[test]
fn unicode_whitespace_at_a_field_boundary_is_not_trimmed_away() {
    let xml = doc(
        r#"<head><meta type="password">&#xa0;secret&#x2003;</meta></head>
  <file subject="a.rar" poster="p" date="1700000000">
<groups><group>&#xa0;alt.binaries.test&#xa0;</group></groups>
<segments>
  <segment bytes="1" number="1">&#xa0;real@news.example&#x2003;</segment>
</segments>
  </file>"#,
    );
    let nzb = Nzb::parse(xml.as_bytes()).expect("parses");

    // The password keeps what was declared. Trimming it produced a
    // WRONG password and extraction failed for a reason nothing
    // reported.
    assert_eq!(
        nzb.password(),
        Some("\u{a0}secret\u{2003}"),
        "a boundary character reference must survive (was silently `secret`)"
    );
    // The id keeps its NBSP, so `is_wire_safe` refuses it and the
    // segment is DECLARED as one that can never be fetched -
    // instead of being rewritten into a different id and fetched.
    assert!(
        nzb.files[0].segments.is_empty(),
        "an id with a boundary NBSP is unfetchable, not rewritable"
    );
    assert_eq!(nzb.files[0].dropped_segments, 1, "and it is still owed");
    // Same verdict for the group: unusable on a GROUP command line.
    assert!(nzb.files[0].groups.is_empty());
}

/// N6-06's other half, and the reason the fix is `trim_xml_space`
/// and not "stop trimming": ordinary XML element formatting must
/// still go, or every indented NZB in the world breaks.
#[test]
fn xml_formatting_whitespace_is_still_trimmed() {
    let xml = doc(
        "<head><meta type=\"password\">\n      s3cret pass\r\n   </meta></head>
  <file subject=\"a.rar\" poster=\"p\" date=\"1700000000\">
<groups><group>\n\talt.binaries.test\n  </group></groups>
<segments>
  <segment bytes=\"1\" number=\"1\">\n        a@news.example\n      </segment>
</segments>
  </file>",
    );
    let nzb = Nzb::parse(xml.as_bytes()).expect("parses");
    assert_eq!(nzb.password(), Some("s3cret pass"), "interior space stays");
    assert_eq!(nzb.files[0].groups, vec!["alt.binaries.test".to_string()]);
    assert_eq!(nzb.files[0].segments[0].message_id, "a@news.example");
    assert_eq!(nzb.files[0].dropped_segments, 0);
}

/// N6-07. `unquoted_filename` demanded a LETTER in the last
/// extension, so every numeric split suffix came back `None` and
/// the plan named the parts `fileNNN` - throwing away the one
/// string that says these files belong together, while
/// `splitjoin`, `nzbkit::zip` and the top-level e2e all handle the
/// shapes downstream.
///
/// RED on origin/main: all seven of the accepted rows below
/// returned `None`.
#[test]
fn unquoted_numeric_split_suffixes_keep_their_name() {
    for (subject, want) in [
        // A numeric tail behind a real extension is unambiguous.
        ("release.zip.001 yEnc (1/2)", Some("release.zip.001")),
        ("release.zip.002 yEnc (1/2)", Some("release.zip.002")),
        ("movie.7z.001 yEnc (1/2)", Some("movie.7z.001")),
        ("archive.rar.001 yEnc (1/2)", Some("archive.rar.001")),
        ("Movie.mkv.001 yEnc (1/2)", Some("Movie.mkv.001")),
        ("movie.7z.1000 yEnc (1/2)", Some("movie.7z.1000")),
        // A BARE numeric tail is taken only when zero-padded.
        ("movie.001 yEnc (1/2)", Some("movie.001")),
        ("movie.01 yEnc (1/2)", Some("movie.01")),
        ("movie.010 yEnc (1/2)", Some("movie.010")),
        // The cases the letter rule was really standing in for, and
        // which must STILL be refused: a trailing year, a bitrate,
        // a resolution. Each falls back to the plan's placeholder
        // exactly as it did before this change.
        ("Movie.2026 (1/3)", None),
        ("Album.320 yEnc (1/3)", None),
        ("Show.480 yEnc (1/3)", None),
        // The stated cost of the zero-padding rule: an unpadded
        // bare tail is indistinguishable from those three, so it
        // keeps the placeholder. Nothing regresses - this is what
        // origin/main did too. This is a statement about ONE
        // subject and not about the job: `set_resolved_hints` names
        // it off the SET, and the row below is why it has to.
        ("movie.100 yEnc (1/2)", None),
        // A tail wider than a splitter ever writes is a name that
        // happens to end in digits (`splitjoin::numeric_tail` draws
        // the same line at 4). All three spellings, because the
        // width rule is the only thing refusing the two padded ones
        // - `Movie.2019.12345` is refused by the letter test on
        // `2019` whatever the width rule says, so on its own it
        // leaves the width rule unfalsifiable (measured: a mutation
        // widening it survived exactly one round of this test).
        ("Movie.2019.12345 yEnc (1/2)", None),
        ("Movie.00001 yEnc (1/2)", None),
        ("Movie.mkv.00001 yEnc (1/2)", None),
        // A numeric tail with no stem in front of it is not a name.
        (".001 yEnc (1/2)", None),
    ] {
        assert_eq!(
            unquoted_filename(subject),
            want,
            "unquoted_filename({subject:?})"
        );
    }
    // Prose subjects still read as prose - the whole reason the
    // letter rule existed.
    assert_eq!(unquoted_filename("Great Album Name yEnc (1/15)"), None);
}

/// N6-07 F3: what a single subject cannot settle, the SET can.
///
/// `unquoted_filename` above takes a bare numeric tail only when it is
/// zero-padded, so in a 3-digit set everything past `.099` keeps the
/// plan's placeholder. MEASURED 31 Aug 2026 over a real 101-part post
/// (`e2e_n607::an_unquoted_bare_numeric_split_past_part_ninety_nine_still_joins_whole`),
/// that PARTIAL naming is worse than naming none of it: the disk joiner
/// saw a contiguous `sunset.001`..`.099`, joined ninety-nine parts into
/// a container nothing can open, and deleted them. Before N6-07 named
/// anything the same post was left alone.
///
/// So `set_resolved_hints` admits an unpadded tail that EXTENDS a padded
/// run by one. The rows below are the whole rule.
#[test]
fn a_split_sets_padded_run_names_the_parts_past_ninety_nine() {
    fn subjects(v: &[&str]) -> Vec<NzbFile> {
        v.iter()
            .map(|s| NzbFile {
                subject: format!("{s} yEnc (1/2)"),
                ..Default::default()
            })
            .collect()
    }
    fn hints(v: &[&str]) -> Vec<Option<String>> {
        let files = subjects(v);
        set_resolved_hints(&files)
            .into_iter()
            .map(|h| h.map(str::to_string))
            .collect()
    }
    let named =
        |v: &[&str]| -> Vec<Option<String>> { v.iter().map(|s| Some((*s).to_string())).collect() };

    // The run extends one part at a time, and keeps extending: `.100`
    // off `.099`, then `.101` off the `.100` just admitted.
    assert_eq!(
        hints(&["sunset.098", "sunset.099", "sunset.100", "sunset.101"]),
        named(&["sunset.098", "sunset.099", "sunset.100", "sunset.101"]),
    );
    // Order in the manifest is not order in the set.
    assert_eq!(
        hints(&["sunset.101", "sunset.100", "sunset.099"]),
        named(&["sunset.101", "sunset.100", "sunset.099"]),
    );
    // A padded run that stops short does NOT reach across the gap.
    assert_eq!(
        hints(&["sunset.001", "sunset.002", "sunset.320"]),
        vec![
            Some("sunset.001".to_string()),
            Some("sunset.002".to_string()),
            None,
        ],
    );
    // No padded member anywhere: a bitrate, a resolution and a year are
    // exactly what they were before this function existed.
    assert_eq!(
        hints(&["Album.320", "Show.480", "Movie.2026"]),
        vec![None; 3]
    );
    // The anchor must be the SAME base, and the same tail WIDTH -
    // `splitjoin::collect_sets` refuses a base mixing `.1` with `.01`,
    // so promoting across widths would build a set it then declines.
    assert_eq!(
        hints(&["other.099", "Album.100"]),
        vec![Some("other.099".to_string()), None],
    );
    assert_eq!(
        hints(&["Album.0099", "Album.100"]),
        vec![Some("Album.0099".to_string()), None],
    );
    // A tail BEHIND a real extension never needed the set: it is
    // unambiguous on its own at any index, so `.100` is named with no
    // padded sibling in sight.
    assert_eq!(
        hints(&["movie.zip.100"]),
        vec![Some("movie.zip.100".to_string())],
    );
    // The stated limit: a width-1 set has no padded member to anchor on,
    // so none of it is named - uniformly, which is the pre-N6-07
    // behaviour and the one outcome that cannot mislead the joiner.
    assert_eq!(hints(&["movie.1", "movie.2", "movie.3"]), vec![None; 3]);
    // A quoted name anchors a run exactly as an unquoted one does: the
    // first pass is `filename_hint_lenient`, which takes quotes first.
    let mixed = vec![
        NzbFile {
            subject: "\"sunset.099\" yEnc (1/2)".to_string(),
            ..Default::default()
        },
        NzbFile {
            subject: "sunset.100 yEnc (1/2)".to_string(),
            ..Default::default()
        },
    ];
    assert_eq!(
        set_resolved_hints(&mixed),
        vec![Some("sunset.099"), Some("sunset.100")],
    );
}

/// N6-08. `bytes` and `number` are REQUIRED by the NZB DTD, and
/// both used to be `parse().unwrap_or(0)` - so garbage, a negative,
/// a value past `u64::MAX` and an absent attribute all became an
/// ordinary declared ZERO that nothing downstream can tell from a
/// producer saying the article is empty.
///
/// RED on origin/main: all four segments below were kept as
/// `number=0 bytes=0`, fetchable, with `dropped_segments` at 0 -
/// so the file's byte total read 0 and every offset derived from it
/// was a lie the job could still finish green over.
#[test]
fn malformed_numeric_segment_attributes_are_refused_not_zeroed() {
    let xml = doc(r#"<file subject="a.rar" poster="p" date="1700000000">
<groups><group>alt.binaries.test</group></groups>
<segments>
  <segment bytes="abc" number="xyz">a@b</segment>
  <segment bytes="-5" number="-1">c@d</segment>
  <segment bytes="18446744073709551616" number="4294967296">e@f</segment>
  <segment bytes="1 2" number="1">g@h</segment>
  <segment bytes="10" number="2">valid@news.example</segment>
</segments>
  </file>"#);
    let nzb = Nzb::parse(xml.as_bytes()).expect("parses");
    let f = &nzb.files[0];
    assert_eq!(
        f.segments.len(),
        1,
        "only the well-formed segment survives, got {:?}",
        f.segments
    );
    assert_eq!(f.segments[0].message_id, "valid@news.example");
    assert_eq!(
        f.dropped_segments, 4,
        "the other four are DECLARED and unfetchable, not vanished"
    );
    assert_eq!(f.bytes(), 10);
}

/// N6-08's boundary, and the one place this lane deliberately does
/// NOT do what the addendum's row says. It lists "invalid, missing
/// or overflowing"; MISSING is not refused here.
///
/// An NZB that omits `bytes=` is a shape this repo already supports
/// ON PURPOSE and has a test for:
/// `repair::sidefetch::an_nzb_without_byte_attributes_is_bounded_by_its_geometry`
/// pins "0 posted bytes means unknown, not zero" and prices such a
/// post off `Nzb::geometry_bytes` instead - which is precisely the
/// "explicit unknown-geometry path" the row asks for, already
/// built. Refusing silence would break a real posting convention to
/// close a hole silence does not open.
///
/// A PRESENT value that is nonsense is different in kind: the
/// producer made a claim, and turning a claim into a valid zero is
/// the defect. That is the line, and this test is what holds it.
#[test]
fn an_absent_numeric_attribute_stays_the_honest_unknown() {
    let xml = doc(
        r#"<file subject="set.vol000+01.par2" poster="p" date="1700000000">
<groups><group>alt.binaries.test</group></groups>
<segments>
  <segment number="1">nobytes@news.example</segment>
  <segment bytes="10">nonumber@news.example</segment>
  <segment>neither@news.example</segment>
</segments>
  </file>"#,
    );
    let nzb = Nzb::parse(xml.as_bytes()).expect("parses");
    let f = &nzb.files[0];
    assert_eq!(f.segments.len(), 3, "nothing is refused for silence");
    assert_eq!(f.dropped_segments, 0);
    assert_eq!(f.bytes(), 10);
    // And the ceiling that replaces the missing byte claim is the
    // one the product already uses: three declared articles.
    assert_eq!(nzb.geometry_bytes(), 3 * (16 << 20));
}

/// N6-08's other half, and a decision rather than an oversight: an
/// EXPLICIT zero is honoured.
///
/// `bytes` is documented as approximate (the yEnc header is the
/// authority) and `Nzb::geometry_bytes` exists precisely because
/// byte claims are poster-controlled. `number` 0 is the pool's own
/// spelling of "part unknown" (`ArticleReq::part`), where the
/// part-mismatch gate stands down - an honest unknown, not a silent
/// rewrite. Refusing these would turn a downloadable post into an
/// undownloadable one for no gain in honesty.
#[test]
fn explicitly_declared_zero_geometry_is_honoured() {
    let xml = doc(r#"<file subject="a.rar" poster="p" date="1700000000">
<groups><group>alt.binaries.test</group></groups>
<segments>
  <segment bytes="0" number="0">a@news.example</segment>
  <segment bytes="0" number="0">b@news.example</segment>
</segments>
  </file>"#);
    let nzb = Nzb::parse(xml.as_bytes()).expect("parses");
    assert_eq!(nzb.files[0].segments.len(), 2);
    assert_eq!(nzb.files[0].dropped_segments, 0);
    assert_eq!(nzb.files[0].bytes(), 0);
}

/// N6-09. The daemon's 256 MiB body cap is on request BYTES and
/// says nothing about manifest STRUCTURE.
///
/// Measured on this tree (release profile, `peak_rss`, at 100k /
/// 500k / 1m / 2m segments): the smallest legal segment is the
/// 20-byte `<segment>a</segment>`, so an in-cap body can declare
/// 13,421,772 of them, and the parser alone retains ~48 bytes per
/// segment - ~640 MB of residency from ONE legal request, before
/// the plan adds its slots, request vectors and bracketed ids.
///
/// The ceilings are refused DURING the read, so nothing past them
/// is ever built. Each is justified at its own `const` in
/// [`limits`].
#[test]
fn structural_ceilings_refuse_a_dense_manifest() {
    // Segment count. Counted in BOTH arms and asserted in both,
    // because a `<segment/>` never reaches the `Start` handler at
    // all (`expand_empty_elements` is off) - so a test written with
    // one spelling leaves the other guard unfalsifiable, and a
    // mutation deleting it survives. Measured: deleting the `Start`
    // arm's ceiling alone is invisible to the self-closing case.
    //
    // Refused ones are counted too, or the cheapest legal segment
    // is the one that walks past the gate.
    for spelling in ["<segment/>", "<segment>a@b</segment>"] {
        let mut body = String::from(r#"<file subject="a.rar"><segments>"#);
        for _ in 0..limits::MAX_SEGMENTS + 1 {
            body.push_str(spelling);
        }
        body.push_str("</segments></file>");
        let err = Nzb::parse(doc(&body).as_bytes()).expect_err("refused");
        assert!(
            matches!(err, NzbError::TooLarge("segment count", n) if n == limits::MAX_SEGMENTS),
            "{spelling}: got {err:?}"
        );
    }

    // File count.
    let mut body = String::new();
    for _ in 0..limits::MAX_FILES + 1 {
        // NOT self-closing: `<file/>` is `Event::Empty`, which this
        // parser does not finalize at all (N6-01, the sibling
        // lane's row), so a self-closing spelling would exercise
        // nothing here.
        body.push_str(r#"<file subject="a.rar"></file>"#);
    }
    let err = Nzb::parse(doc(&body).as_bytes()).expect_err("refused");
    assert!(
        matches!(err, NzbError::TooLarge("file count", n) if n == limits::MAX_FILES),
        "got {err:?}"
    );

    // Field length. Refused rather than truncated: a shortened
    // subject is a different filename and every namer downstream
    // would believe it.
    let long = "x".repeat(limits::MAX_FIELD + 1);
    let err = Nzb::parse(doc(&format!(r#"<file subject="{long}"></file>"#)).as_bytes())
        .expect_err("refused");
    assert!(
        matches!(err, NzbError::TooLarge("subject/poster length", _)),
        "got {err:?}"
    );

    // Total retained text. The per-field caps do NOT bound the
    // document on their own - `MAX_FILES` x `MAX_FIELD` is 410 MB -
    // so this is the ceiling that closes the many-medium-fields
    // shape, and it has to be exercised or it is a line nothing
    // falsifies.
    let field = "y".repeat(limits::MAX_FIELD);
    let one = format!(r#"<file subject="{field}" poster="{field}"></file>"#);
    let n = limits::MAX_TEXT_BYTES / (2 * limits::MAX_FIELD) + 2;
    assert!(n < limits::MAX_FILES, "the TEXT budget must bind first");
    let err = Nzb::parse(doc(&one.repeat(n)).as_bytes()).expect_err("refused");
    assert!(
        matches!(err, NzbError::TooLarge("total text", n) if n == limits::MAX_TEXT_BYTES),
        "got {err:?}"
    );
}

/// N6-09's per-token half. An over-length message-id or group name
/// cannot be spelled on the wire at all (RFC 3977 3.1 caps an NNTP
/// command line at 512 octets), so it takes the same route as a
/// wire-unsafe one rather than refusing the whole document - and an
/// over-length meta VALUE is dropped rather than kept truncated,
/// because half a password is a wrong password.
#[test]
fn over_length_wire_tokens_are_refused_at_their_own_field() {
    let big_id = "x".repeat(limits::MAX_WIRE_TOKEN + 1);
    let big_group = "g".repeat(limits::MAX_WIRE_TOKEN + 1);
    // Written as TWO fragments either side of an entity, which is
    // the shape that actually exercises the truncation guard: a
    // single over-length run is refused whole and leaves the value
    // EMPTY, so an empty value is dropped whether the guard exists
    // or not, and a mutation deleting the guard survives (measured
    // - this is exactly how it survived the first round). With a
    // fitting fragment first, the second is what overflows, and
    // without the guard a PREFIX of the password is retained and
    // handed to extraction as if it were the whole thing.
    let big_pass = format!(
        "{}&amp;{}",
        "p".repeat(limits::MAX_FIELD - 100),
        "q".repeat(200)
    );
    let xml = doc(&format!(
        r#"<head><meta type="password">{big_pass}</meta></head>
  <file subject="a.rar" poster="p" date="1700000000">
<groups><group>{big_group}</group><group>alt.binaries.test</group></groups>
<segments>
  <segment bytes="1" number="1">{big_id}</segment>
  <segment bytes="1" number="2">ok@news.example</segment>
</segments>
  </file>"#
    ));
    let nzb = Nzb::parse(xml.as_bytes()).expect("the document itself is fine");
    assert_eq!(
        nzb.password(),
        None,
        "a truncated password is a wrong one - it must be dropped, not kept as a prefix"
    );
    assert_eq!(nzb.files[0].groups, vec!["alt.binaries.test".to_string()]);
    assert_eq!(nzb.files[0].segments.len(), 1);
    assert_eq!(nzb.files[0].segments[0].message_id, "ok@news.example");
    assert_eq!(nzb.files[0].dropped_segments, 1, "still owed");
}

/// N6-09 must not fire on anything real. The largest NZB fixture in
/// this repo is a genuine NZBIndex-generated file: 89 files, 11,060
/// segments, 1.18 MB. Every ceiling clears it by two orders or
/// more, and this test is what says so on every run rather than in
/// a comment.
#[test]
fn the_ceilings_clear_a_real_world_nzb_by_orders_of_magnitude() {
    let xml = include_bytes!("../testdata/nzb/gh-nzbget699-undefined-entity.nzb");
    let nzb = Nzb::parse(xml).expect("a real NZB still parses");
    let files = nzb.files.len();
    let segs: usize = nzb
        .files
        .iter()
        .map(|f| f.segments.len() + f.dropped_segments)
        .sum();
    assert!(files * 100 < limits::MAX_FILES, "{files} files");
    assert!(segs * 50 < limits::MAX_SEGMENTS, "{segs} segments");
    // And nothing in it was dropped by the N6-08 tightening: every
    // segment of every real fixture carries both required numeric
    // attributes.
    assert_eq!(
        nzb.files.iter().map(|f| f.dropped_segments).sum::<usize>(),
        0,
        "a real NZB must lose no segment to the numeric-attribute rule"
    );
}

/// N6-10. `quoted_filename` had no length cap at all, while
/// `unquoted_filename` beside it has capped at 255 bytes since it
/// was written - so a 5,000-byte quoted name parsed, planned and
/// DOWNLOADED, then failed when the output leaf was created: after
/// the network work, at the filesystem, over a name nobody can
/// read.
///
/// RED on origin/main: `quoted_filename` returned the whole
/// 5,004-byte candidate and `sanitize_out_name` handed it straight
/// back at 5,004 bytes, because the flat path does not truncate.
///
/// The cap is [`crate::disk::name_within_limits`] - the length half
/// of the policy `sanitize_relpath_for` already enforces - asked at
/// the front door instead of at materialization. Refusing is
/// collision-safe by construction: the plan's `fileNNN` placeholder
/// is unique per slot.
#[test]
fn an_overlong_quoted_filename_is_refused_at_the_front_door() {
    let long = "x".repeat(5000);
    let subject = format!("[1/1] - \"{long}.mkv\" yEnc (1/1)");
    assert_eq!(
        quoted_filename(&subject),
        None,
        "a 5004-byte candidate must not reach the filesystem"
    );

    // A name at the component limit is still taken - the cap is a
    // boundary, not a discouragement.
    let at_limit = format!("{}.mkv", "y".repeat(255 - 4));
    assert_eq!(at_limit.len(), 255);
    let subject = format!("\"{at_limit}\" yEnc (1/1)");
    assert_eq!(quoted_filename(&subject).map(str::len), Some(255));

    // One byte over the COMPONENT limit, inside the total limit:
    // still refused, because the leaf is what the filesystem
    // creates.
    let over = format!("{}.mkv", "y".repeat(252));
    assert_eq!(over.len(), 256);
    assert_eq!(quoted_filename(&format!("\"{over}\" yEnc (1/1)")), None);

    // A tree-preserving name (the relpath ruling) is judged per
    // component, so a legitimate disc path is unaffected.
    let tree = "VIDEO_TS/VTS_01_1.VOB";
    assert_eq!(
        quoted_filename(&format!("\"{tree}\" yEnc (1/1)")),
        Some(tree)
    );

    // `\` is a component separator alongside `/` - PAR2 sets and
    // RAR4-era archives built on Windows store backslashes, and
    // `sanitize_relpath_for` has always normalized them - so an
    // over-length component behind one is caught the same way.
    // Without this the backslash arm is a line nothing falsifies.
    let win = format!("DISC1\\{}.mkv", "w".repeat(300));
    assert!(
        win.len() <= 511,
        "the TOTAL cap must not be what refuses it"
    );
    assert_eq!(quoted_filename(&format!("\"{win}\" yEnc (1/1)")), None);
    // And the direction that actually falsifies the backslash arm:
    // a name whose TOTAL is past the per-component cap but whose
    // backslash-separated components are each inside it. Judged as
    // one component it would be refused; judged as a path it is a
    // legitimate Windows-authored tree and must be kept. (An
    // over-length component like the one above is refused either
    // way, so on its own it leaves the arm unfalsifiable - measured.)
    let win_ok = format!("{}\\{}.mkv", "a".repeat(200), "b".repeat(200));
    assert!(win_ok.len() > 255 && win_ok.len() <= 511);
    assert_eq!(
        quoted_filename(&format!("\"{win_ok}\" yEnc (1/1)")).map(str::len),
        Some(win_ok.len())
    );

    // Skipped, not fatal: scanning continues past an unusable
    // candidate, so a later quoted run can still name the file.
    let subject = format!("\"{long}.mkv\" - \"real.mkv\" yEnc (1/1)");
    assert_eq!(quoted_filename(&subject), Some("real.mkv"));

    // The TOTAL half of the policy, separately from the component
    // half: a deep tree whose every component is comfortably inside
    // 255 bytes but whose whole name is past the total cap. Without
    // this the component check alone satisfies every other row here,
    // and a mutation deleting the total check survives (measured).
    //
    // The cap it is scored against went 1024 -> 511 on 31 Aug 2026 -
    // 1024 was a budget no name could use, since the measured ceiling
    // is 1023 bytes of ABSOLUTE path. This row is 1190 bytes and so is
    // past either number; the literal below moved anyway, because a
    // stale one reads as a claim about a policy that no longer exists.
    let deep = (0..12)
        .map(|i| format!("{}{i:02}", "d".repeat(98)))
        .collect::<Vec<_>>()
        .join("/")
        + "/x.mkv";
    assert!(deep.len() > 511, "{}", deep.len());
    assert!(deep.split('/').all(|c| c.len() <= 255));
    assert_eq!(quoted_filename(&format!("\"{deep}\" yEnc (1/1)")), None);

    // A UTF-8 name is measured in BYTES, which is what every
    // filesystem counts: 128 4-byte characters is 512 bytes and
    // over the component limit even though it is 128 "characters".
    let wide = format!("{}.mkv", "\u{1f600}".repeat(64));
    assert_eq!(wide.chars().count(), 68);
    assert_eq!(wide.len(), 260);
    assert_eq!(quoted_filename(&format!("\"{wide}\" yEnc (1/1)")), None);
}
