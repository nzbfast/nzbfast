//! `[nzb]`, plane 7.E: the map, against what the wire really says.
//!
//! Neutral means FAITHFUL: the map agrees with the wire in every
//! particular. Every segment that was posted is listed, every `bytes`
//! attribute is the encoded size the mock will actually serve, every
//! `date` is the instant the articles carry, every `subject` is the
//! Subject header the article was posted under, and the `<meta
//! type="name">` names the post the layout really is.
//!
//! **Every other selection is a disagreement, and disagreement is the
//! plane.** An NZB is a map somebody else wrote; nothing in it is
//! evidence about the bytes, and the client has exactly one source of
//! truth for a file's name, size and content, which is the article. So
//! Z1's `lying`, Z3's wrong sizes, Z4's dropped segments, Z5's
//! differing subject and Z6's backdated date are all one question asked
//! five ways: how much authority does the map have over the wire? The
//! catalog's answer, row by row, is "none of these may change the file
//! that lands".
//!
//! **Which is not the same question the daemon answers**, and the
//! difference is worth stating here because it is easy to read one of
//! these rows as pinning the other.
//! `research/POST-SETTLE-NAME-AUTHORITY-2026-08-31.md` measured, and
//! `nzbkit::release::adopt_proved_identity` then landed, a rule about
//! the JOB name: where a PAR2-proved release name and the parse of the
//! .nzb-supplied job name contradict on title or year, the proved one
//! wins, in the daemon's `finalize_names`. The oracle drives
//! `nzbfast get`, which has no filing step and no `finalize_names` at
//! all, so a Z1 row here pins the FILE name against the map and says
//! nothing about the folder a daemon would file the job into. Both are
//! true, they are different layers, and neither is evidence for the
//! other.
//!
//! **Why this is not `nzbkit::post::emit_nzb`.** The shape is that
//! function's, element for element and attribute for attribute, and
//! `nzbkit::nzb::Nzb::parse` is what both are written against. What
//! differs is what the emitter can be asked for: `emit_nzb` takes a
//! `PostedSet` whose fields are crate-private, it writes no `<head>` at
//! all, and it has no way to state a size that is not the real one or
//! to leave a posted segment out. Those are not shortcomings there - a
//! real post's map has no business lying - and they are exactly the
//! plane here. So this is a second emitter of one shape rather than a
//! wrapper, and the pairing that keeps it honest is
//! `the_emitted_shape_round_trips_through_the_real_parser` below:
//! whatever this writes, the client's own parser has to read back.

use crate::encode::{EncodedFile, FRESH_DATE_UNIX, Segment};
use crate::naming::GROUP;
use crate::profile::{MetaName, NzbDate, NzbSubject, Profile, SegmentBytes};

/// Z6 `old`: how far before [`FRESH_DATE_UNIX`] a backdated post is
/// stamped.
///
/// Thirty days, which is the number `retention_routes_old_post_around_
/// short_server` in `crates/nzbfast/tests/e2e.rs` uses against a
/// 10-day server: this is the same backdate those tests apply, so a
/// profile pairing it with a short-retention server exercises the same
/// routing decision they do. A constant offset from the fixed fresh
/// instant rather than a clock read, for the reason [`FRESH_DATE_UNIX`]
/// gives.
pub const OLD_DATE_UNIX: i64 = FRESH_DATE_UNIX - 30 * 86_400;

/// Z1 `lying`: the name the map states for a post that does not contain
/// it.
///
/// A name and not a token, because the row is about AUTHORITY and a
/// token would let a client "ignore" the meta by finding it implausible
/// rather than by declining to give the map authority. Deliberately
/// unlike every generated payload name, so a test asserting it did not
/// reach the output tree cannot pass by coincidence.
pub const LYING_META_NAME: &str = "Nothing.In.This.Post.2026.1080p-DECOY";

/// Z5 `differing`: the stem the map's subject names instead.
const DECOY_SUBJECT_STEM: &str = "Decoy.Not.The.Posted.File";

/// Why an NZB could not be emitted.
///
/// No variants. Every selection of this plane is emitted, and the type
/// stays because [`emit`] is a fallible step in `crate::layout`'s chain
/// and a plane that grows an impossible combination later should refuse
/// here rather than reach for a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NzbError {}

impl std::fmt::Display for NzbError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {}
    }
}

/// Emit the NZB for an encoded layout.
///
/// `post_name` is what `<meta type="name">` states under Z1's faithful
/// arm. It is the post's own name, which under a descriptive layout is
/// a real name and under an opaque one is a token: the meta is faithful
/// either way, because faithful means "agrees with what was posted",
/// not "is descriptive".
///
/// `payload_files` is how many of `files` are payload rather than
/// recovery. Z4 drops segments from the payload's map only: a `.par2`
/// volume with a hole in it is a damaged recovery set, which is the
/// fault plane's F4, and letting Z4 reach it would mean the row that
/// asks "can the set heal a hole in the map" had quietly holed the set.
pub fn emit(
    profile: &Profile,
    files: &[EncodedFile],
    post_name: &str,
    payload_files: usize,
) -> Result<String, NzbError> {
    let z = &profile.nzb;
    let date = match z.date {
        NzbDate::Fresh => Some(FRESH_DATE_UNIX),
        NzbDate::Old => Some(OLD_DATE_UNIX),
        // Z6 `undated`: no `date` attribute at all. A real shape - a
        // hand-written or re-generated NZB often has none - and the one
        // that leaves a retention decision with nothing to decide on.
        NzbDate::Undated => None,
    };
    let mut out = String::with_capacity(1024 + files.len() * 512);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<!DOCTYPE nzb PUBLIC \"-//newzBin//DTD NZB 1.1//EN\" \
         \"http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd\">\n",
    );
    out.push_str("<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n");
    out.push_str("  <head>\n");
    match z.meta_name {
        MetaName::Faithful => out.push_str(&format!(
            "    <meta type=\"name\">{}</meta>\n",
            esc(post_name)
        )),
        // Z1 `absent`: the `<head>` element is still there and holds no
        // name, which is what most real NZBs carry - a map with no head
        // at all is a different shape and a different row.
        MetaName::Absent => {}
        MetaName::Lying => out.push_str(&format!(
            "    <meta type=\"name\">{}</meta>\n",
            esc(LYING_META_NAME)
        )),
    }
    if z.meta_password {
        out.push_str(&format!(
            "    <meta type=\"password\">{}</meta>\n",
            esc(&profile.container.password)
        ));
    }
    out.push_str("  </head>\n");
    for (i, f) in files.iter().enumerate() {
        let subject = match z.subject {
            NzbSubject::Faithful => f.subject.clone(),
            // The same convention `nzbkit::post::subject_for` writes,
            // over a name that was never posted: a map that is wrong in
            // the one shape every downloader in the world parses,
            // rather than one that is merely unparseable. Everything
            // but the NAME is kept - the same file counter, the same
            // part counter - because a map that also disagreed about
            // how many files or parts there are would be several rows
            // at once and the failure would not say which one bit.
            NzbSubject::Differing => nzbkit::post::subject_for(
                None,
                &format!("{DECOY_SUBJECT_STEM}.{}.bin", i + 1),
                i as u32 + 1,
                files.len() as u32,
                1,
                f.parts_total,
            ),
        };
        out.push_str("  <file ");
        out.push_str(&format!("poster=\"{}\" ", esc(&f.poster)));
        if let Some(d) = date {
            out.push_str(&format!("date=\"{d}\" "));
        }
        out.push_str(&format!("subject=\"{}\">\n", esc(&subject)));
        out.push_str("    <groups>\n");
        out.push_str(&format!("      <group>{}</group>\n", esc(GROUP)));
        out.push_str("    </groups>\n");
        out.push_str("    <segments>\n");
        let droppable = i < payload_files;
        // Listed in PART-NUMBER order, which under the neutral naming
        // plane is also the order the chunks were cut in and so changes
        // nothing: `crate::encode::part_numbers` hands back 1..=n in
        // chunk order, and sorting an already-sorted list is identity.
        // Measured 4 Sep 2026 over the whole catalog: every profile but
        // the one N6 row keeps its exact layout fingerprint.
        //
        // It is not cosmetic under N6, which is the row it was added
        // for. A shuffled `part=` makes chunk order and number order
        // two different sequences, and every indexer in the field emits
        // segments sorted by number - so leaving them in chunk order
        // would have let a client that simply APPENDED the map's
        // segments in the order it read them pass the row by accident,
        // with the shuffle proving nothing. Sorted, the map agrees with
        // the shuffled part numbers and disagrees with byte order, so
        // the only thing that can place the bytes correctly is
        // `=ypart begin=` - which is what N6 asks. Measured on the same
        // day: the client passes the row with the map sorted, so it is
        // reading `begin=` rather than the map's own order.
        let mut ordered: Vec<&Segment> = f.segments.iter().collect();
        ordered.sort_by_key(|s| s.number);
        for s in ordered {
            if droppable && dropped(&s.message_id, z.drop_segments_pct, s.number) {
                continue;
            }
            let bytes = match z.segment_bytes {
                SegmentBytes::True => s.bytes,
                // Z3: an order of magnitude out, not a plausible slip.
                // The realistic mistake - stating the DECODED size,
                // which many posting tools do - is about 2 % low, and
                // 2 % cannot distinguish "the client trusted the map"
                // from "the client ignored it" in a byte-exact grade.
                // A row whose instrument cannot separate the two
                // answers is not a row.
                SegmentBytes::Wrong => s.bytes.saturating_mul(10),
            };
            out.push_str(&format!(
                "      <segment bytes=\"{}\" number=\"{}\">{}</segment>\n",
                bytes,
                s.number,
                esc(&s.message_id)
            ));
        }
        out.push_str("    </segments>\n");
        out.push_str("  </file>\n");
    }
    out.push_str("</nzb>\n");
    Ok(out)
}

/// Z4: whether this segment is left out of the map.
///
/// Decided by hashing the message-id rather than by drawing from the
/// seeded generator, and that is deliberate on two counts. The id is
/// itself a product of the seed, so the choice is still reproducible
/// from the profile alone; and taking no draw means adding this plane
/// did not move the generator's stream, so every layout written before
/// it is still byte-for-byte what it was.
///
/// **Part 1 is never dropped.** A file whose every segment went missing
/// from the map is not a file with a hole - it is a file that is not in
/// the post at all, which is a different row and one the oracle would
/// grade as a missing output rather than as a repaired one. Holding
/// part 1 is the cheapest rule that guarantees a survivor and it puts
/// the hole where a client cannot mistake it for a short file.
fn dropped(message_id: &str, pct: f64, number: u32) -> bool {
    if pct <= 0.0 || number == 1 {
        return false;
    }
    // FNV-1a over the id, folded to 0..100. No dependency, stable
    // across machines and releases - which `DefaultHasher` is not.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in message_id.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    ((h % 100) as f64) < pct
}

/// The XML predefined entities. A superset of what
/// `nzbkit::post::emit_nzb` escapes, which leaves the apostrophe alone
/// because its attributes are double-quoted: escaping it too costs
/// nothing and means one rule covers every value here whatever
/// delimiter it lands inside. A name is attacker-shaped data in the
/// general case (a profile may select a hostile one deliberately), so
/// everything that reaches an attribute or a text node goes through
/// here.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::generate;

    fn layout(text: &str) -> crate::layout::Layout {
        generate(&Profile::parse(text).expect("test profile parses")).expect("layout generates")
    }

    const TWO_FILES: &str = "\
[layout]
name = \"t\"
seed = 1

[source]
files = [
    { name = \"movie.mkv\", bytes = 4096 },
    { name = \"sample/s.mkv\", bytes = 2048 },
]

[encoding]
article_bytes = 1024
";

    /// The pairing that keeps a second emitter honest: the client's own
    /// parser reads back what this writes, and every message-id the map
    /// names is an article the mock can serve.
    #[test]
    fn the_emitted_shape_round_trips_through_the_real_parser() {
        let l = layout(TWO_FILES);
        let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes()).expect("the client parses it");
        assert_eq!(parsed.files.len(), 2);
        let mut named = 0;
        for f in &parsed.files {
            assert_eq!(f.groups, vec![GROUP.to_string()]);
            assert_eq!(f.dropped_segments, 0);
            assert_eq!(f.date, FRESH_DATE_UNIX);
            for s in &f.segments {
                assert!(
                    l.articles.contains_key(&format!("<{}>", s.message_id)),
                    "map names {} which no article answers",
                    s.message_id
                );
                named += 1;
            }
        }
        assert_eq!(named, l.articles.len(), "every article is in the map");
    }

    /// A faithful map states the encoded size the mock will really
    /// serve. A `bytes` attribute that is merely plausible would make
    /// Z3 untestable, because the neutral row would already be lying.
    #[test]
    fn segment_bytes_are_the_bytes_the_mock_serves() {
        let l = layout(TWO_FILES);
        let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes()).unwrap();
        for f in &parsed.files {
            for s in &f.segments {
                let body = &l.articles[&format!("<{}>", s.message_id)];
                assert_eq!(s.bytes as usize, body.len());
            }
        }
    }

    /// Z1 faithful: the meta names the post, and the parser sees it.
    #[test]
    fn the_meta_name_reaches_the_parser() {
        let l = layout(TWO_FILES);
        let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes()).unwrap();
        assert_eq!(parsed.meta, vec![("name".to_string(), "movie".to_string())]);
    }

    /// A name carrying XML metacharacters is escaped rather than
    /// emitted raw, and the parser hands the original back.
    #[test]
    fn xml_metacharacters_in_a_name_survive_escaping() {
        let l = layout(
            "[layout]\nname = \"t\"\nseed = 1\n\n[source]\n\
             files = [{ name = \"a&b<c>.bin\", bytes = 32 }]\n",
        );
        assert!(!l.nzb.contains("a&b<c>"));
        let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes()).unwrap();
        assert!(parsed.files[0].subject.contains("a&b<c>.bin"));
    }

    /// Z1 absent: an empty `<head>` and no name meta at all, which is
    /// what most real NZBs carry.
    #[test]
    fn z1_an_absent_meta_name_leaves_the_head_empty() {
        let l = layout(&format!("{TWO_FILES}\n[nzb]\nmeta_name = \"absent\"\n"));
        let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes()).unwrap();
        assert!(parsed.meta.is_empty());
        assert_eq!(parsed.files.len(), 2, "and the map is otherwise unchanged");
    }

    /// Z1 lying: the meta names a file the post does not contain, and
    /// that name appears NOWHERE else - not in a subject, not in a yEnc
    /// header, and not in the end state the oracle grades. This is the
    /// assertion the chip's acceptance asks for, at the level this
    /// generator owns: the map's claim is emitted and is not evidence.
    #[test]
    fn z1_a_lying_meta_name_names_nothing_that_was_posted() {
        let l = layout(&format!("{TWO_FILES}\n[nzb]\nmeta_name = \"lying\"\n"));
        let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes()).unwrap();
        assert_eq!(
            parsed.meta,
            vec![("name".to_string(), LYING_META_NAME.to_string())]
        );
        for f in &parsed.files {
            assert!(!f.subject.contains(LYING_META_NAME));
        }
        for body in l.articles.values() {
            assert!(
                !String::from_utf8_lossy(body).contains(LYING_META_NAME),
                "the wire must never carry the map's invention"
            );
        }
        for (name, _) in &l.expect.files {
            assert_ne!(name, LYING_META_NAME);
        }
    }

    /// Z2: the container's password is carried in the map, which is the
    /// one place a client can get it before it has opened anything.
    #[test]
    fn z2_the_password_meta_carries_the_containers_password() {
        let l = layout(&format!(
            "{TWO_FILES}\n[container]\npassword = \"notasecret\"\n\n\
             [nzb]\nmeta_password = true\n"
        ));
        let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes()).unwrap();
        assert!(
            parsed
                .meta
                .contains(&("password".to_string(), "notasecret".to_string()))
        );
    }

    /// Z3: the map states a size an order of magnitude out, and the
    /// articles the mock serves are unchanged - so any difference the
    /// oracle sees is the client having trusted the map.
    #[test]
    fn z3_a_wrong_segment_bytes_does_not_change_the_article() {
        let faithful = layout(TWO_FILES);
        let l = layout(&format!("{TWO_FILES}\n[nzb]\nsegment_bytes = \"wrong\"\n"));
        assert_eq!(l.articles, faithful.articles, "the wire is untouched");
        let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes()).unwrap();
        for f in &parsed.files {
            for s in &f.segments {
                let real = l.articles[&format!("<{}>", s.message_id)].len() as u64;
                assert_eq!(s.bytes, real * 10);
            }
        }
    }

    /// Z4: segments vanish from the MAP while the articles stay on the
    /// server, part 1 of every file survives, and no `.par2` loses a
    /// segment - a holed recovery set would disarm the very thing that
    /// has to heal the hole.
    #[test]
    fn z4_dropped_segments_leave_the_wire_and_the_recovery_set_whole() {
        let text = "\
[layout]
name = \"t\"
seed = 3

[source]
files = [{ name = \"Feature.mkv\", bytes = 65536 }]

[recovery]
kind = \"par2\"
redundancy_pct = 20

[encoding]
article_bytes = 4096

[nzb]
drop_segments_pct = 50.0
";
        let l = layout(text);
        let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes()).unwrap();
        let payload = &parsed.files[0];
        assert!(
            payload.segments.len() < 16,
            "some payload segments must actually be dropped"
        );
        assert!(
            payload.segments.iter().any(|s| s.number == 1),
            "part 1 is never dropped"
        );
        for f in &parsed.files[1..] {
            for s in &f.segments {
                assert!(l.articles.contains_key(&format!("<{}>", s.message_id)));
            }
            assert!(
                f.subject.contains(".par2"),
                "everything past the payload is the recovery set"
            );
        }
        // The recovery files keep every segment they were posted with:
        // count the map's recovery segments against the articles that
        // are not the payload's.
        let mapped: usize = parsed.files[1..].iter().map(|f| f.segments.len()).sum();
        assert_eq!(
            mapped,
            l.articles.len() - 16,
            "no recovery segment may be dropped"
        );
    }

    /// Z5: the map's subject names a file that was never posted, and
    /// the yEnc `name=` on the wire is untouched. The two disagree by
    /// construction, which is the row.
    #[test]
    fn z5_a_differing_subject_disagrees_with_the_wire() {
        let faithful = layout(TWO_FILES);
        let l = layout(&format!("{TWO_FILES}\n[nzb]\nsubject = \"differing\"\n"));
        assert_eq!(l.articles, faithful.articles, "the wire is untouched");
        let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes()).unwrap();
        for f in &parsed.files {
            assert!(f.subject.contains("Decoy.Not.The.Posted.File"));
            assert!(!f.subject.contains("movie.mkv"));
            assert!(!f.subject.contains("s.mkv"));
        }
        // The real name is still on the wire, in the one place that is
        // evidence about the bytes.
        assert!(
            l.articles
                .values()
                .any(|b| String::from_utf8_lossy(b).contains("name=movie.mkv")),
            "the article still declares the real name"
        );
    }

    /// Z6: the three date arms. `old` is the same 30-day backdate the
    /// retention tests apply, `undated` writes no attribute at all, and
    /// the parser reads each back as the file states it.
    #[test]
    fn z6_the_date_arms_reach_the_parser_as_written() {
        let fresh = layout(TWO_FILES);
        assert!(fresh.nzb.contains(&format!("date=\"{FRESH_DATE_UNIX}\"")));

        let old = layout(&format!("{TWO_FILES}\n[nzb]\ndate = \"old\"\n"));
        let parsed = nzbkit::nzb::Nzb::parse(old.nzb.as_bytes()).unwrap();
        for f in &parsed.files {
            assert_eq!(f.date, OLD_DATE_UNIX);
        }
        assert_eq!(
            FRESH_DATE_UNIX - OLD_DATE_UNIX,
            30 * 86_400,
            "the backdate is the retention tests' own 30 days"
        );

        let undated = layout(&format!("{TWO_FILES}\n[nzb]\ndate = \"undated\"\n"));
        assert!(!undated.nzb.contains("date=\""), "no attribute at all");
        let parsed = nzbkit::nzb::Nzb::parse(undated.nzb.as_bytes()).unwrap();
        assert_eq!(parsed.files.len(), 2, "and the map still parses");
        for f in &parsed.files {
            assert_eq!(f.date, 0);
        }
    }

    /// Every arm of the plane still writes an NZB the client's own
    /// parser reads, with the same file count. A map that lies is still
    /// a map; a map that does not parse is a different defect and would
    /// make every row above vacuous.
    #[test]
    fn every_selection_still_parses_as_an_nzb() {
        for extra in [
            "[nzb]\nmeta_name = \"absent\"\n",
            "[nzb]\nmeta_name = \"lying\"\n",
            "[nzb]\nsegment_bytes = \"wrong\"\n",
            "[nzb]\nsubject = \"differing\"\n",
            "[nzb]\ndate = \"old\"\n",
            "[nzb]\ndate = \"undated\"\n",
            "[nzb]\ndrop_segments_pct = 25.0\n",
        ] {
            let l = layout(&format!("{TWO_FILES}\n{extra}"));
            let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes())
                .unwrap_or_else(|e| panic!("{extra} must still parse: {e}"));
            assert_eq!(parsed.files.len(), 2, "{extra}");
            for f in &parsed.files {
                assert_eq!(f.dropped_segments, 0, "{extra}: nothing malformed");
                assert!(!f.segments.is_empty(), "{extra}: every file keeps a part");
            }
        }
    }

    /// N6: the map lists segments by PART NUMBER, and under a shuffle
    /// that is not the order the chunks were cut in.
    ///
    /// Both halves are the assertion. Ascending numbers are what every
    /// indexer in the field emits; the second half is what makes the
    /// N6 row discriminating, because a map still in chunk order would
    /// be passed by a client that appended segments in the order it
    /// read them and never looked at `=ypart begin=` at all. See the
    /// comment at the sort in `emit`.
    #[test]
    fn n6_lists_segments_by_part_number_and_not_in_chunk_order() {
        let text = "\
[layout]
name = \"t\"
seed = 17

[source]
files = [{ name = \"Shuffled.Parts.bin\", bytes = 98304 }]

[naming]
part_order = \"reordered\"

[encoding]
article_bytes = 16384
";
        let l = layout(text);
        let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes()).unwrap();
        let numbers: Vec<u32> = parsed.files[0].segments.iter().map(|s| s.number).collect();
        assert_eq!(numbers, vec![1, 2, 3, 4, 5, 6], "sorted by part number");
        // The chunk each listed segment carries, read off the wire's own
        // `=ypart begin=`. Chunk order would be 0..6; the shuffle makes
        // it something else, and if it ever stopped being something else
        // the N6 row would have quietly become a natural-order row.
        let chunks: Vec<u64> = parsed.files[0]
            .segments
            .iter()
            .map(|s| {
                let body = &l.articles[&format!("<{}>", s.message_id)];
                let text = String::from_utf8_lossy(&body[..body.len().min(256)]);
                let begin = text
                    .split("=ypart begin=")
                    .nth(1)
                    .and_then(|r| r.split(' ').next())
                    .and_then(|n| n.parse::<u64>().ok())
                    .expect("every part carries a begin");
                (begin - 1) / 16384
            })
            .collect();
        assert_ne!(
            chunks,
            vec![0, 1, 2, 3, 4, 5],
            "the map's order is not byte order, which is the whole point of the row"
        );
        let mut sorted = chunks.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            vec![0, 1, 2, 3, 4, 5],
            "and every chunk is listed once"
        );
    }
}
