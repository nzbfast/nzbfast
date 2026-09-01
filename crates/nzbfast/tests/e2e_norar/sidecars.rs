//! The checksum-sidecar naming tier: `.sfv`, `.md5`, and what a sidecar
//! is NOT allowed to do.
//!
//! One subject end to end. A checksum sidecar is the weakest name source
//! this engine has - it is evidence about BYTES and never an instruction
//! - and every row here is a question about that weakness: whether the
//! tier fires at all (an obfuscated `.sfv` with no extension, a `.md5`
//! whose payload and sidecar are both hash-named), whether it refuses
//! when it cannot be sure (one MD5 two payloads share, a well-formed
//! sidecar matching nothing, prose in an `.nfo` that happens to end a
//! line in eight hex digits), and whether it can ever destroy something
//! stronger (a name a landed slot of the same job already holds, before
//! and after `sanitize_out_name` flattens it).
//!
//! Fourteen rows, gathered here from TWO ranges of `mod.rs` - the
//! `an_sfv_sidecar_names_the_post` family that closed case 22 / rows
//! M4-20 and M4-27, and the W4-03 family that came out of the 30 Aug
//! wave-4 read. They were never one block in that file only because they
//! were written a month apart; they are one block here.
//!
//! A CHILD module, for the reason its siblings give: `mod.rs` was at
//! 2,903 of its 3,000 size-gate lines on 31 Aug 2026 with about a dozen
//! wave-4 lanes appending to it, and it had already grown 11 lines
//! DURING one survey of that margin. A child reaches the builders in
//! `mod.rs` through one `use super::*` where a sibling directory of
//! `e2e.rs` would need each of them made `pub(crate)` on lines those
//! lanes are also editing - and `tests/e2e.rs` is itself only 124 lines
//! under its own baseline, so a sibling could not be declared there
//! cheaply either.
//!
//! `sfvmixed.rs` next door is deliberately NOT folded in: its subject is
//! the zero-byte placeholder on the WITH-SET path and the per-entry veto
//! that makes it safe there, which is a question about the PAR2 set's
//! authority rather than about the sidecar tier itself, and its module
//! header carries the mutation argument that separates its two tests.

use super::*;

/// Case 22, finding F6 - CLOSED 30 Aug 2026 (`sfv-naming`): an SFV
/// sidecar as the ONLY name source - the .sfv maps real names to
/// whole-file CRC32s, payload names random, no PAR2 anywhere. The
/// settle-time tier (get/sfvname.rs, no-set path, runs last) checksums
/// the settled unclaimed files and renames on a unique CRC32 match,
/// declining ambiguity on both sides.
#[tokio::test(flavor = "multi_thread")]
async fn an_sfv_sidecar_names_the_post() {
    let mut fx = Fixture::new("norarsfv");
    let one = payload(60_000, 81);
    let two = payload(45_000, 82);
    let sfv = format!(
        "; sfv generated fixture\r\nReal.One.mkv {:08X}\r\nReal.Two.mkv {:08X}\r\n",
        crc32fast::hash(&one),
        crc32fast::hash(&two)
    );
    fx.add_file_obfuscated("Il7cWd36ZqK", "Il7cWd36ZqK", &one, 40_000);
    fx.add_file_obfuscated("Ep2vBn94XhT", "Ep2vBn94XhT", &two, 40_000);
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "sfv-sidecar post failed:\n{log}");
    let got_one = std::fs::read(out.join("Real.One.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its SFV name: {e}\n{log}"));
    let got_two = std::fs::read(out.join("Real.Two.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its SFV name: {e}\n{log}"));
    assert!(
        got_one == one && got_two == two,
        "payload not byte-exact\n{log}"
    );
    assert!(
        !out.join("Il7cWd36ZqK").exists() && !out.join("Ep2vBn94XhT").exists(),
        "a posted hash name survived beside the SFV name:\n{log}"
    );
}

/// Row M4-20 - CLOSED 30 Aug 2026 (`norar-wave4-obfuscated-sfv`): the
/// SFV itself rides under a hash with NO extension, which is what field
/// obfuscation that hashes everything actually produces. The tier now
/// recognizes a sidecar by CONTENT, so the CRC mapping runs and the
/// names land. Cherry-picked from the wave4-verify probe
/// `m4_20_hash_named_sfv_without_extension_still_names_the_post`, which
/// was CONFIRMED red on the 30 Aug baseline (names never landed, rc=0).
#[tokio::test(flavor = "multi_thread")]
async fn a_hash_named_sfv_without_an_extension_still_names_the_post() {
    let mut fx = Fixture::new("norarsfvhash");
    let data = payload(60_000, 65);
    fx.add_file_obfuscated("Kd8wRn42PfX", "Kd8wRn42PfX", &data, 40_000);
    let sfv = format!("Real.Hidden.mkv {:08X}\r\n", crc32fast::hash(&data));
    fx.add_file_obfuscated("Zj3uMc77LqB", "Zj3uMc77LqB", sfv.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "hash-named sfv post failed outright:\n{log}");
    let got = std::fs::read(out.join("Real.Hidden.mkv")).unwrap_or_else(|e| {
        panic!(
            "M4-20: the extensionless SFV was never consulted - the \
             payload kept its hash: {e}\n{log}"
        )
    });
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("Kd8wRn42PfX").exists(),
        "the posted hash survived beside the SFV name:\n{log}"
    );
}

/// Row M4-27 - CLOSED 30 Aug 2026 (`norar-wave4-obfuscated-sfv`): the
/// md5sum / RapidCRC `.md5` sidecar, the OTHER checksum file the field
/// ships, as the only name source. Hash-named payload, hash-named
/// sidecar - so this is the M4-20 sniff and the new `.md5` parser at
/// once, which is the shape a fully obfuscated post really has. The
/// binary-mode `*` marker is deliberately on the wire: md5sum writes it
/// by default and a reader that takes it as part of the name renames
/// the payload to `*Real.Md5.mkv`.
#[tokio::test(flavor = "multi_thread")]
async fn an_md5_sidecar_names_the_post() {
    let mut fx = Fixture::new("norarmd5");
    let one = payload(60_000, 91);
    let two = payload(45_000, 92);
    let sums = format!(
        "; hashes\r\n{:x}  Real.Md5.One.mkv\r\n{:x} *Real.Md5.Two.mkv\r\n",
        md5::Md5::digest(&one),
        md5::Md5::digest(&two)
    );
    fx.add_file_obfuscated("Qw5tZx18MbN", "Qw5tZx18MbN", &one, 40_000);
    fx.add_file_obfuscated("Vr9pLd60CjY", "Vr9pLd60CjY", &two, 40_000);
    fx.add_file_obfuscated("Hn3kSg47TwE", "Hn3kSg47TwE", sums.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "md5-sidecar post failed:\n{log}");
    let got_one = std::fs::read(out.join("Real.Md5.One.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its .md5 name: {e}\n{log}"));
    let got_two = std::fs::read(out.join("Real.Md5.Two.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its .md5 name: {e}\n{log}"));
    assert!(
        got_one == one && got_two == two,
        "payload not byte-exact\n{log}"
    );
    assert!(
        !out.join("Qw5tZx18MbN").exists() && !out.join("Vr9pLd60CjY").exists(),
        "a posted hash name survived beside the .md5 name:\n{log}"
    );
    assert!(
        !out.join("*Real.Md5.Two.mkv").exists(),
        "the md5sum binary-mode marker was read as part of the name:\n{log}"
    );
}

/// Row M4-27, the ambiguity rule on the MD5 side: two payloads in one
/// job with IDENTICAL bytes share one MD5, so the sidecar's single entry
/// for that checksum cannot say WHICH of them the name belongs to. A
/// weaker checksum is not a licence to guess - both keep their posted
/// hashes. The sidecar deliberately names only one of the two, so the
/// FILE-side decline (`files_by_sum` two-files-one-checksum) is the only
/// arm that can refuse this; an entry-side duplicate would be caught by
/// a second arm and pin neither.
#[tokio::test(flavor = "multi_thread")]
async fn one_md5_claimed_by_two_identical_payloads_names_neither() {
    let mut fx = Fixture::new("norarmd5dup");
    let data = payload(50_000, 97);
    let sums = format!("{:x}  Real.Twin.mkv\r\n", md5::Md5::digest(&data));
    fx.add_file_obfuscated("Ib5wCz36NrP", "Ib5wCz36NrP", &data, 40_000);
    fx.add_file_obfuscated("Fo2qDl81XvS", "Fo2qDl81XvS", &data, 40_000);
    fx.add_file_obfuscated("Ju7yTk94BgM", "Ju7yTk94BgM", sums.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "duplicate-payload md5 post failed:\n{log}");
    assert!(
        !out.join("Real.Twin.mkv").exists(),
        "an MD5 two files share was guessed at instead of declined:\n{log}"
    );
    assert!(
        out.join("Ib5wCz36NrP").exists() && out.join("Fo2qDl81XvS").exists(),
        "a payload went missing when the sidecar was declined:\n{log}"
    );
}

/// Row M4-20/M4-27, the false-positive guard: a hash-named TEXT file
/// that is NOT a sidecar must never be parsed into renames. This is the
/// whole cost of sniffing by content, so it is pinned rather than
/// argued: an .nfo that happens to end one line in 8 hex digits is
/// prose, and the strict parse refuses it because its OTHER lines are
/// not well-formed. Nothing is renamed and nothing is deleted.
#[tokio::test(flavor = "multi_thread")]
async fn a_hash_named_nfo_is_not_parsed_as_a_sidecar() {
    let mut fx = Fixture::new("norarnfo");
    let data = payload(60_000, 93);
    // The .nfo names the payload's own CRC32 on a prose line, so a
    // lenient sniff would rename the payload to "Greets to everyone".
    let nfo = format!(
        "Release notes for something\r\n\
         Encoded by nobody in particular\r\n\
         Greets to everyone {:08X}\r\n",
        crc32fast::hash(&data)
    );
    fx.add_file_obfuscated("Bt7mXq53RvA", "Bt7mXq53RvA", &data, 40_000);
    fx.add_file_obfuscated("Uc4jNf82KpD", "Uc4jNf82KpD", nfo.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "hash-named nfo post failed:\n{log}");
    let got = std::fs::read(out.join("Bt7mXq53RvA"))
        .unwrap_or_else(|e| panic!("payload missing under its posted hash: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("Greets to everyone").exists(),
        "prose was parsed as a sidecar and renamed the payload:\n{log}"
    );
    assert!(
        out.join("Uc4jNf82KpD").exists(),
        "the nfo itself went missing:\n{log}"
    );
}

/// Row M4-20/M4-27, the other half of the guard: a WELL-FORMED sidecar
/// whose checksums match nothing in the post names nothing. A sidecar is
/// evidence about bytes, not an instruction - a tier that fell back to
/// order or count here would rename payload onto names the poster never
/// claimed for it.
#[tokio::test(flavor = "multi_thread")]
async fn a_sidecar_that_matches_nothing_names_nothing() {
    let mut fx = Fixture::new("norarsfvmiss");
    let data = payload(60_000, 94);
    // ONE entry, so the checksum comparison is the ONLY thing standing
    // between this sidecar and a wrong rename - two mismatching entries
    // would also be declined as a contradiction (two names, one slot),
    // and a pin two guards wide is a pin neither guard can fail.
    let sfv = format!(
        "; this entry is for bytes that are not in this post\r\nWrong.One.mkv {:08X}\r\n",
        crc32fast::hash(&payload(1_000, 95))
    );
    fx.add_file_obfuscated("Ml6dHt29ZbW", "Ml6dHt29ZbW", &data, 40_000);
    fx.add_file_obfuscated("Ys1nGv74QcF", "Ys1nGv74QcF", sfv.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "mismatched-sidecar post failed:\n{log}");
    assert!(
        !out.join("Wrong.One.mkv").exists(),
        "a sidecar name landed on bytes whose checksum did not match:\n{log}"
    );
    let got = std::fs::read(out.join("Ml6dHt29ZbW"))
        .unwrap_or_else(|e| panic!("payload missing under its posted hash: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
}

/// W4-03 (30 Aug 2026): an SFV entry names a path an already-landed file
/// of the SAME JOB holds, and points it at OTHER bytes. The weakest tier
/// may never destroy a landed slot - the measured defect was `[extract]
/// renamed Uw5rTk88NcV -> final.bin (replaced the previous copy)` at
/// rc=0, one payload short with no error anywhere.
///
/// The oracle is deliberately not "B is declined": disambiguating is an
/// acceptable answer and so is declining. What it pins is that A's bytes
/// are still at A's name and B's bytes are still somewhere in the job.
#[tokio::test(flavor = "multi_thread")]
async fn an_sfv_naming_a_landed_file_never_replaces_it() {
    let mut fx = Fixture::new("norarsfvcollide");
    let a = payload(60_000, 31);
    let b = payload(60_000, 32);
    fx.add_file("final.bin", &a, 40_000);
    fx.add_file_obfuscated("Uw5rTk88NcV", "Uw5rTk88NcV", &b, 40_000);
    let sfv = format!("final.bin {:08X}\r\n", crc32fast::hash(&b));
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "no-par2 sfv-collision post failed outright:\n{log}");
    let got = std::fs::read(out.join("final.bin"))
        .unwrap_or_else(|e| panic!("final.bin missing entirely: {e}\n{log}"));
    assert!(
        got == a,
        "the SFV rename replaced final.bin's landed content with the \
         hash-posted payload\n{log}"
    );
    // Not just "B survived": B survived under the DECLARED name, in the
    // registry's `{slot:03}-` disambiguated form. Two guards stand
    // between this post and the measured defect - the seeded registry,
    // which pushes the claim off a name a live slot holds, and the weak
    // tier's refusal to replace anything already at its target - and
    // either alone keeps A's bytes safe, so an oracle that only asked
    // "did A survive" could not tell a lost seed from a working one. This
    // is the half only the seed produces: declining leaves B under
    // `Uw5rTk88NcV`, which is the strictly worse of the two acceptable
    // answers. (The refusal is pinned directly, at the unit level, by
    // `a_weak_name_never_replaces_a_file_the_registry_never_saw`.)
    let tree = out_tree(&out);
    let landed = tree
        .iter()
        .find(|(_, bytes)| *bytes == b)
        .unwrap_or_else(|| panic!("the hash-posted payload was lost from the job:\n{log}"));
    assert!(
        landed.0.ends_with("final.bin") && landed.0 != "final.bin",
        "expected the SFV name in its disambiguated form, got {:?}\n{log}",
        landed.0
    );
}

/// W4-03's many-to-one variant: nothing collides in the POST, only after
/// `sanitize_out_name` flattens both onto one on-disk name. A registry
/// seeded from the live slot paths is what catches this one - the
/// sanitizer is the collision, so no comparison of the poster's own two
/// names would ever see it.
#[tokio::test(flavor = "multi_thread")]
async fn an_sfv_name_that_sanitizes_onto_a_landed_file_never_replaces_it() {
    let mut fx = Fixture::new("norarsfvsan");
    let a = payload(60_000, 33);
    let b = payload(60_000, 34);
    fx.add_file("sub__movie.mkv", &a, 40_000);
    fx.add_file_obfuscated("Kv8pRt41MzX", "Kv8pRt41MzX", &b, 40_000);
    let sfv = format!("sub//movie.mkv {:08X}\r\n", crc32fast::hash(&b));
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(
        ok,
        "no-par2 sanitizer-collision post failed outright:\n{log}"
    );
    let tree = out_tree(&out);
    assert!(
        tree.iter()
            .any(|(rel, bytes)| rel == "sub__movie.mkv" && *bytes == a),
        "the honestly-named payload was lost to a sanitizer collision:\n{log}"
    );
    let landed = tree
        .iter()
        .find(|(_, bytes)| *bytes == b)
        .unwrap_or_else(|| panic!("the hash-posted payload was lost from the job:\n{log}"));
    assert!(
        landed.0.ends_with("sub__movie.mkv") && landed.0 != "sub__movie.mkv",
        "expected the sanitized SFV name in its disambiguated form, got {:?}\n{log}",
        landed.0
    );
}

/// W4-05 (30 Aug 2026): evidence tiers RANK, they do not exclude. A
/// manifest-only PAR2 covers and names A; B sits outside that set under a
/// hash with an honest SFV naming it. Both must land under their real
/// names - the measured defect was that `land_sfv_names` ran only where
/// no set activated, so one usable set anywhere in the post suppressed
/// the weakest tier for every file in it and B kept its hash at rc=0.
#[tokio::test(flavor = "multi_thread")]
async fn par2_and_an_sfv_compose_on_disjoint_files() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarsfvcompose");
    let a = payload(120_000, 41);
    let b = payload(90_000, 42);
    fx.add_file_renamed_by_par2("A.bin", "Pm4hSx62WbJ", &a, 40_000);
    fx.add_file_obfuscated("Qn7kVz19YtR", "Qn7kVz19YtR", &b, 40_000);
    assert!(add_par2_index_only(&mut fx, &["A.bin"], 40_000));
    // ...and the same sidecar names A's OWN checksum something else. The
    // set claimed A and its FileDesc name has already been applied, so
    // composing must not mean the weaker tier gets to revisit it: rank,
    // never overrule.
    let sfv = format!(
        "B.bin {:08X}\r\nDecoy.bin {:08X}\r\n",
        crc32fast::hash(&b),
        crc32fast::hash(&a)
    );
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "subset-par2 plus sfv post failed:\n{log}");
    let got_a = std::fs::read(out.join("A.bin"))
        .unwrap_or_else(|e| panic!("A.bin missing under its FileDesc name: {e}\n{log}"));
    assert!(got_a == a, "A.bin not byte-exact\n{log}");
    let got_b = std::fs::read(out.join("B.bin")).unwrap_or_else(|e| {
        panic!(
            "B kept its hash - the SFV tier is suppressed whenever any PAR2 \
             set is usable: {e}\n{log}"
        )
    });
    assert!(got_b == b, "B.bin not byte-exact\n{log}");
    assert!(
        !out.join("Decoy.bin").exists(),
        "the SFV tier overruled a PAR2 claim - a 32-bit checksum took a name \
         off a file an MD5 pair had already spoken for\n{log}"
    );
}

/// W4-13 (30 Aug 2026): a UTF-8 BOM before the first SFV entry must be
/// stripped, not become part of the first filename. U+FEFF is not
/// whitespace under Unicode's White_Space property, so `trim` leaves it
/// exactly where it is - and `"\u{FEFF}Real.Bom.mkv"` was a real
/// directory entry, rendering identically to the right name and matching
/// nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_utf8_bom_does_not_ride_into_the_first_sfv_name() {
    let mut fx = Fixture::new("norarsfvbom");
    let data = payload(60_000, 61);
    fx.add_file_obfuscated("Bx2mQf55HdW", "Bx2mQf55HdW", &data, 40_000);
    let sfv = format!("\u{FEFF}Real.Bom.mkv {:08X}\r\n", crc32fast::hash(&data));
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "bom-sfv post failed:\n{log}");
    let got = std::fs::read(out.join("Real.Bom.mkv")).unwrap_or_else(|e| {
        let tree: Vec<String> = out_tree(&out)
            .into_iter()
            .map(|(n, b)| format!("{n:?} ({} bytes)", b.len()))
            .collect();
        panic!("no clean Real.Bom.mkv - the BOM rode into the name: {e}; tree: {tree:?}\n{log}")
    });
    assert!(got == data, "payload not byte-exact\n{log}");
}

/// W4-13's other half: a UTF-16LE sidecar with a BOM and CRLF. It used to
/// be dropped in silence by a `read_to_string` that could not decode it;
/// decoding it is reading two bytes of unambiguous evidence, not guessing
/// at a charset. Pinned so the sidecar reader cannot quietly narrow back
/// to UTF-8-or-nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_utf16le_sidecar_is_read_rather_than_dropped() {
    let mut fx = Fixture::new("norarsfvu16");
    let data = payload(55_000, 62);
    fx.add_file_obfuscated("Tz9wLn23CqV", "Tz9wLn23CqV", &data, 40_000);
    let text = format!("Real.Utf16.mkv {:08X}\r\n", crc32fast::hash(&data));
    let mut sfv = vec![0xFF, 0xFE];
    for u in text.encode_utf16() {
        sfv.extend_from_slice(&u.to_le_bytes());
    }
    fx.add_file("release.sfv", &sfv, 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "utf16 sfv post failed:\n{log}");
    let got = std::fs::read(out.join("Real.Utf16.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its UTF-16 SFV name: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
}
/// Matrix row M4-07 (wave-4 matrix read, and the product ruling of
/// 30 Aug 2026): the SFV is the only name source AND one of its entries is
/// a legitimate 0-byte placeholder - a `VIDEO_TS/VTS_02_0.VOB` whose
/// declared CRC32 is the CRC32 of the empty input, `00000000`. Nothing
/// was posted for it (a zero-length post is only yEnc framing), so no
/// settled file can ever carry that name, and with no PAR2 anywhere the
/// with-set `emptydesc` tier never runs. Before the fix the disc tree
/// simply came out one file short, in silence.
///
/// Correct: the payload lands under its SFV name AND the placeholder is
/// materialized empty at its sanitized tree path.
#[tokio::test(flavor = "multi_thread")]
async fn an_sfv_zero_crc_entry_materializes_its_empty_placeholder() {
    let mut fx = Fixture::new("norarsfvempty");
    let data = payload(60_000, 91);
    fx.add_file_obfuscated("Ld3pQv66JcM", "Ld3pQv66JcM", &data, 40_000);
    let sfv = format!(
        "Real.Feature.mkv {:08X}\r\nVIDEO_TS/VTS_02_0.VOB 00000000\r\n",
        crc32fast::hash(&data)
    );
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "sfv zero-byte post failed outright:\n{log}");
    let got = std::fs::read(out.join("Real.Feature.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its SFV name: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
    let ph = out.join("VIDEO_TS").join("VTS_02_0.VOB");
    let md = std::fs::metadata(&ph).unwrap_or_else(|e| {
        panic!("the 0-byte SFV-declared placeholder was never materialized: {e}\n{log}")
    });
    assert!(md.len() == 0, "the placeholder is not empty\n{log}");
}

/// The first bound on that ruling (the W4-09 shape): a file already
/// sitting at the placeholder's path - a previous run's real copy, or a
/// name another tier published - WINS. A CRC32-of-empty entry proves the
/// poster meant an empty file; it never proves anything about bytes that
/// are already there, so this tier may create and must never truncate.
#[tokio::test(flavor = "multi_thread")]
async fn an_sfv_zero_crc_entry_never_truncates_a_file_already_there() {
    let mut fx = Fixture::new("norarsfvkeep");
    let data = payload(60_000, 92);
    let squatter = payload(4_096, 93);
    fx.add_file_obfuscated("Ld3pQv66JcM", "Ld3pQv66JcM", &data, 40_000);
    let sfv = format!(
        "Real.Feature.mkv {:08X}\r\nVIDEO_TS/VTS_02_0.VOB 00000000\r\n",
        crc32fast::hash(&data)
    );
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    // A previous run's copy in the very folder this job publishes into.
    let out = fx.dir.join("out");
    std::fs::create_dir_all(out.join("VIDEO_TS")).unwrap();
    std::fs::write(out.join("VIDEO_TS").join("VTS_02_0.VOB"), &squatter).unwrap();
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "sfv zero-byte post failed outright:\n{log}");
    let kept = std::fs::read(out.join("VIDEO_TS").join("VTS_02_0.VOB"))
        .unwrap_or_else(|e| panic!("the file already there was deleted: {e}\n{log}"));
    assert!(
        kept == squatter,
        "a CRC32-of-empty entry truncated a file that was already there\n{log}"
    );
}

/// The second bound: a NON-empty CRC with nothing on disk hashing to it
/// creates nothing. Only the empty CRC is self-proving - every other
/// value is a claim about bytes this tier does not have, and inventing a
/// file for it would be a guess.
#[tokio::test(flavor = "multi_thread")]
async fn an_sfv_entry_with_a_nonempty_crc_and_no_match_creates_nothing() {
    let mut fx = Fixture::new("norarsfvnomatch");
    let data = payload(60_000, 94);
    fx.add_file_obfuscated("Ld3pQv66JcM", "Ld3pQv66JcM", &data, 40_000);
    let sfv = format!(
        "Real.Feature.mkv {:08X}\r\nNever.Posted.mkv DEADBEEF\r\n",
        crc32fast::hash(&data)
    );
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "sfv post failed outright:\n{log}");
    let got = std::fs::read(out.join("Real.Feature.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its SFV name: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("Never.Posted.mkv").exists(),
        "an unmatched non-empty CRC invented a file\n{log}"
    );
}
