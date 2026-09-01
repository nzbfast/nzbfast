//! N6-07 end to end: a poster who QUOTES NOTHING must still get one
//! extracted payload out of a numbered byte split, not a directory of
//! unrelated placeholder files.
//!
//! The parser half of this row landed with
//! `nzb_tests::unquoted_numeric_split_suffixes_keep_their_name`, which
//! pins `unquoted_filename` on the subject alone. Step 3 of the
//! addendum's implementation order asks for the provider-backed half as
//! well, and this is it - the row's own words are "one extracted
//! payload, not unrelated placeholder files", which is a statement about
//! the JOB and not about a string.
//!
//! # Why the subject is the only name source in these fixtures
//!
//! `Fixture::write_nzb` quotes every subject, so nothing in the e2e tree
//! could express this row. `write_nzb_unquoted` below is that file with
//! the quotes taken off; everything else about the post is ordinary.
//!
//! The yEnc names are HASHES, and that is the measurement rather than a
//! flourish. A split part posted with its real name in the yEnc header
//! lands on disk under that name whatever the subject said, so
//! `splitjoin`'s DISK rescue joins the set and the payload arrives - the
//! job is then green with the subject name thrown away, and the row's
//! assertion says nothing. Measured 31 Aug 2026 by reverting the N6-07
//! arm of `unquoted_filename` with real yEnc names in place: green.
//! With hash yEnc names the subject is the one thing that can name the
//! set, which is exactly the shape the row is about, and the same
//! revert leaves three placeholder files and no payload.
//!
//! That pairing - a real name in an unquoted subject, a hash in the yEnc
//! header - is the norm for an obfuscated poster who leaves the subject
//! human-readable, and it is the shape `Fixture::add_file_obfuscated`
//! already exists for.
//!
//! # What each leg proves
//!
//! * `.zip.001` and `.7z.001`: a numeric tail BEHIND a real extension,
//!   the unambiguous reading.
//! * a bare `sunset.001`: the narrow, zero-padded reading, and it is
//!   CONTENT-PROVEN - `zip::numeric_split_part_name` takes the name on
//!   spec alone (RAR numeric volumes share the grammar), so the declared
//!   set only maps once part 1 sniffs `PK\x03\x04`.
//!
//! No PAR2 in any leg, deliberately: a recovery set carries FileDesc
//! names, and those rename the parts on disk before the join is ever
//! asked - which would make every leg green on a tree with no naming at
//! all. These posts are bare, which is a shape the field has plenty of.
//!
//! A grandchild of e2e.rs rather than a sibling. That started as the
//! size gate - when these legs were written `crates/nzbfast/tests/e2e.rs`
//! sat exactly ON its baseline limit and a one-line `mod` declaration
//! reddened it, measured - and the e2e.rs split has since re-baselined
//! that file, so it is now a filing judgement and stands on its own:
//! a numbered byte split of one container is what `e2e_split` is
//! about. The harness is reached through `super::super::*`.

use super::super::*;

/// [`Fixture::write_nzb`] with the quotes taken OFF the subject - the
/// N6-07 shape, and the one thing the shared fixture cannot express.
///
/// The decoration around the name is what a real unquoted post carries:
/// a leading `[i/n]` index tag and a trailing ` yEnc (1/n)` counter,
/// both of which `unquoted_filename` strips before it looks at the
/// extension. Writing the bare name alone would leave that half of the
/// function untested by this row.
fn write_nzb_unquoted(fx: &Fixture) -> PathBuf {
    let n = fx.nzb_files.len();
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, (name, segs)) in fx.nzb_files.iter().enumerate() {
        assert!(
            !name.contains('"'),
            "an unquoted subject cannot carry a quote: {name}"
        );
        xml.push_str(&format!(
            "  <file poster=\"e2e@test\" date=\"{}\" subject=\"[{:02}/{n:02}] - {name} yEnc (1/{})\">\n    <groups><group>mock.group</group></groups>\n    <segments>\n",
            fx.date,
            i + 1,
            segs.len()
        ));
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    let path = fx.dir.join("unquoted.nzb");
    std::fs::write(&path, xml).unwrap();
    path
}

/// Post `arch` as `<base>.001`..`.00n` with UNQUOTED subjects and HASH
/// yEnc names, so the subject is the only thing naming the set. Returns
/// the part names as the subjects spell them.
fn post_unquoted_split(fx: &mut Fixture, base: &str, arch: &[u8], n: usize) -> Vec<String> {
    let names: Vec<String> = (1..=n).map(|i| format!("{base}.{i:03}")).collect();
    let parts: Vec<&[u8]> = arch.chunks(arch.len().div_ceil(n)).collect();
    assert_eq!(parts.len(), n, "fixture must really split into {n}");
    for (i, (name, part)) in names.iter().zip(parts).enumerate() {
        // A hash where the real name would be: see the module note.
        fx.add_file_obfuscated(name, &format!("Zt9{i:02}pQm4xVb"), part, 120_000);
    }
    names
}

/// Start the mock provider over `fx`'s articles and run one `get` off
/// the UNQUOTED manifest.
async fn run_unquoted(fx: &Fixture) -> (String, bool, PathBuf) {
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = write_nzb_unquoted(fx);
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();
    (log, ok, out)
}

/// The row's assertion, off one output directory: the payload arrived
/// byte for byte, no part survived as a file, and NOTHING is named
/// `fileNNN` - which is the whole of "not unrelated placeholder files".
fn assert_one_payload(out: &Path, member: &str, want: &[u8], names: &[String], log: &str) {
    let got = std::fs::read(out.join(member))
        .unwrap_or_else(|e| panic!("the payload the split held is missing: {e}\n{log}"));
    assert!(got == want, "the payload is not byte-exact\n{log}");
    for name in names {
        assert!(
            !out.join(name).exists(),
            "{name} survived as a file - the set was never joined:\n{log}"
        );
    }
    let mut left: Vec<String> = std::fs::read_dir(out)
        .unwrap_or_else(|e| panic!("no output directory: {e}\n{log}"))
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert!(
        !left
            .iter()
            .any(|n| n.contains("file0") || n.contains("Zt9")),
        "the job wrote placeholder or hash-named files: {left:?}\n{log}"
    );
    assert_eq!(
        left,
        vec![member.to_string()],
        "the payload must be the only thing in the output directory\n{log}"
    );
}

/// N6-07, `.zip.001`: a three-part byte split of a stored zip, posted
/// with unquoted subjects. The set is declared off the NZB's file list
/// (`get::vrig`'s `declare_zip_split` reads the SLOT HINT, which is the
/// subject name), so losing the name loses the whole one-pass and the
/// parts land as placeholders.
#[tokio::test(flavor = "multi_thread")]
async fn an_unquoted_zip_split_extracts_one_payload() {
    let mut fx = Fixture::new("n607zipsplit");
    let movie = incompressible(900_000, 71);
    let arch =
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)]);
    let names = post_unquoted_split(&mut fx, "release.zip", &arch, 3);
    let (log, ok, out) = run_unquoted(&fx).await;
    assert!(ok, "the unquoted zip split must exit 0:\n{log}");
    assert_one_payload(&out, "movie.mkv", &movie, &names, &log);
    // Keep `fx` alive past every assertion: its ScratchDir guard removes
    // the tree the moment it drops.
    drop(fx);
}

/// N6-07, `.7z.001`: the same story for a 7z multipart set, which is a
/// raw byte split whose continuation parts carry no signature at all.
#[tokio::test(flavor = "multi_thread")]
async fn an_unquoted_sevenz_split_extracts_one_payload() {
    let mut fx = Fixture::new("n607sevenzsplit");
    let movie = incompressible(900_000, 72);
    let arch = sevenz_store_container(&[("episode.mkv", &movie)]);
    let names = post_unquoted_split(&mut fx, "movie.7z", &arch, 3);
    let (log, ok, out) = run_unquoted(&fx).await;
    assert!(ok, "the unquoted 7z split must exit 0:\n{log}");
    assert_one_payload(&out, "episode.mkv", &movie, &names, &log);
    drop(fx);
}

/// N6-07, the BARE numeric tail - the narrow, zero-padded reading, and
/// the one that has no extension to lean on. `sunset.001` is taken as a
/// split part on spec alone, and the declared set only maps because part
/// 1 sniffs `PK\x03\x04`: content-proven, exactly as the row asks.
#[tokio::test(flavor = "multi_thread")]
async fn an_unquoted_bare_numeric_split_extracts_one_payload() {
    let mut fx = Fixture::new("n607baresplit");
    let movie = incompressible(900_000, 73);
    let arch =
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored("clip.mkv", &movie)]);
    let names = post_unquoted_split(&mut fx, "sunset", &arch, 3);
    let (log, ok, out) = run_unquoted(&fx).await;
    assert!(ok, "the unquoted bare-numeric split must exit 0:\n{log}");
    assert_one_payload(&out, "clip.mkv", &movie, &names, &log);
    drop(fx);
}

/// N6-07 F3, and the reason `nzb::set_resolved_hints` exists: a
/// bare-numeric split with MORE THAN 99 PARTS.
///
/// Past `.099` a 3-digit tail stops being zero-padded, and the
/// per-subject rule takes a bare numeric tail only when it is - so this
/// set used to come out named for parts 1..99 and placeholdered for the
/// rest. MEASURED on the tree before the set rule landed, this exact
/// fixture at 101 parts:
///
/// * `splitjoin::collect_sets` saw `sunset.001`..`.099`, a contiguous
///   run from 1, and joined NINETY-NINE parts into a `sunset` nothing
///   can open ("no end-of-central-directory record"),
/// * then deleted all ninety-nine ("removed 99 volume file(s)"),
/// * leaving that truncated join beside the two hash-named parts.
///
/// Before N6-07 named anything at all the same post left all 101 parts
/// untouched. Both are broken jobs; only one of them also destroys what
/// a person would have salvaged by hand, which is why partial naming is
/// a regression rather than a miss.
///
/// 101 parts is the smallest fixture that can show it - 100 would leave
/// exactly one part unnamed and still join 99.
#[tokio::test(flavor = "multi_thread")]
async fn an_unquoted_bare_numeric_split_past_part_ninety_nine_still_joins_whole() {
    let mut fx = Fixture::new("n607bare101");
    let movie = incompressible(500_000, 74);
    let arch =
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored("clip.mkv", &movie)]);
    let names = post_unquoted_split(&mut fx, "sunset", &arch, 101);
    let (log, ok, out) = run_unquoted(&fx).await;
    assert!(ok, "the 101-part bare-numeric split must exit 0:\n{log}");
    assert!(
        !log.contains("joining 99 split part(s)"),
        "the set was joined 99 parts short - the tail past .099 lost its name:\n{log}"
    );
    assert_one_payload(&out, "clip.mkv", &movie, &names, &log);
    drop(fx);
}
