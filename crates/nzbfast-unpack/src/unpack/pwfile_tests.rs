//! `unpack`'s passwords-file case: the operator's own list reaching the
//! ON-DISK extraction ladder (the advP/advQ root cause, 12 Aug).
//!
//! A child module file rather than an inline `mod tests`: unpack.rs is
//! over its size-gate ceiling (TODO 106) and the numbers only go down.
//! Same pattern as smart/tests.rs.

use super::*;

/// The operator's passwords file must reach the ON-DISK extraction
/// ladder, not just the in-stream RAR probe.
///
/// This is the advP/advQ root cause (the four-way correctness round,
/// 12 Aug): the file was readable only from the RAR check-value probe
/// and the post-completion unlock, so the two shapes that arrive here
/// with no check to probe - a header-encrypted 7z, an encrypted zip -
/// were left packed with the right password already in hand.
#[test]
fn the_operator_passwords_file_reaches_the_disk_ladder() {
    use nzbkit::zip::fixtures::{Encrypt, Spec, zip_of};
    let dir = std::env::temp_dir().join(format!("nzbfast-pwfile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let payload: Vec<u8> = (0..30_000u32).map(|i| (i * 5 + 1) as u8).collect();
    std::fs::write(
        dir.join("locked.zip"),
        zip_of(&[Spec {
            encrypt: Some(Encrypt::Ae {
                password: "fromthefile",
                strength: 3,
                vendor_version: 2,
            }),
            ..Spec::deflated("movie.mkv", &payload)
        }]),
    )
    .unwrap();

    // With no file configured there is no candidate, so the level
    // resolves nothing and the job would arrive packed - today's
    // behaviour for every zip whose password we were never told.
    crate::pwfile::set_operator_password_file(None);
    assert_eq!(resolve_level_password(&dir, None), None);

    // Configured, the winning line is found - a wrong line first, so
    // the sweep (not a lucky single entry) is what is under test.
    let list = dir.join("pw.txt");
    std::fs::write(&list, "wrong-one\nfromthefile\n").unwrap();
    crate::pwfile::set_operator_password_file(Some(list));
    assert_eq!(
        resolve_level_password(&dir, None).as_deref(),
        Some("fromthefile")
    );
    // And the level actually unpacks with it.
    assert!(extract_one_level(&dir, None, 0).unwrap().is_some());
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), payload);

    crate::pwfile::set_operator_password_file(None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex sweep G, 13 Aug 2026: two encrypted containers in one post
/// need not share a password. The resolver ran once for the LEVEL and
/// handed its answer to every job, so the second archive stayed packed
/// while the pass reported success - and the top-level command exited
/// 0 because the first archive's output looked like the payload.
#[test]
fn each_encrypted_container_resolves_its_own_password() {
    use nzbkit::zip::fixtures::{Encrypt, Spec, zip_of};
    let dir = std::env::temp_dir().join(format!("nzbfast-pwjobs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let a: Vec<u8> = (0..20_000u32).map(|i| (i * 7 + 3) as u8).collect();
    let b: Vec<u8> = (0..24_000u32).map(|i| (i * 11 + 5) as u8).collect();
    for (name, member, pw, data) in [
        ("a.zip", "sample.mkv", "alpha", &a),
        ("b.zip", "movie.mkv", "beta", &b),
    ] {
        std::fs::write(
            dir.join(name),
            zip_of(&[Spec {
                encrypt: Some(Encrypt::Ae {
                    password: pw,
                    strength: 3,
                    vendor_version: 2,
                }),
                ..Spec::deflated(member, data)
            }]),
        )
        .unwrap();
    }
    let list = dir.join("pw.txt");
    std::fs::write(&list, "alpha\nbeta\n").unwrap();
    crate::pwfile::set_operator_password_file(Some(list));

    assert!(extract_one_level(&dir, None, 0).unwrap().is_some());
    assert_eq!(std::fs::read(dir.join("sample.mkv")).unwrap(), a);
    assert_eq!(
        std::fs::read(dir.join("movie.mkv")).unwrap(),
        b,
        "the second container must resolve its OWN password"
    );

    crate::pwfile::set_operator_password_file(None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex sweep F, 13 Aug 2026: a ZipCrypto check byte is ONE byte, so
/// it admits a wrong password once in 256 tries - which the docs said
/// all along, while the caller stopped at the first value the check
/// liked and never tried another. The checked-in `zipcrypto.zip` is
/// admitted by `wrong-93` as well as by its real value `SECRET`, so
/// ordering the accident first left the archive packed. The extraction
/// is the authority; the check is only a shortlist.
#[test]
fn a_false_positive_header_check_does_not_end_the_candidate_sweep() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../nzbkit-base/tests/fixtures/zip");
    let dir = std::env::temp_dir().join(format!("nzbfast-pwfalse-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(root.join("zipcrypto.zip"), dir.join("locked.zip")).unwrap();
    let parts = vec![dir.join("locked.zip")];
    // The premise: BOTH values pass the one-byte check.
    assert!(nzbkit::zip::password_opens(&parts, Some("wrong-93")));
    assert!(nzbkit::zip::password_opens(&parts, Some("SECRET")));

    let list = dir.join("pw.txt");
    std::fs::write(&list, "wrong-93\nSECRET\n").unwrap();
    crate::pwfile::set_operator_password_file(Some(list));
    let cands = zip_password_candidates(&dir, &parts, None);
    let vals: Vec<Option<&str>> = cands.iter().map(|(v, _)| v.as_deref()).collect();
    assert!(
        vals.contains(&Some("wrong-93")) && vals.contains(&Some("SECRET")),
        "the shortlist keeps going past the first hit: {vals:?}"
    );

    assert!(extract_one_level(&dir, None, 0).unwrap().is_some());
    let want: Vec<u8> = (0..20000u32).map(|i| ((i * 37 + 11) % 256) as u8).collect();
    assert_eq!(std::fs::read(dir.join("movie.bin")).unwrap(), want);

    crate::pwfile::set_operator_password_file(None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The password probe decodes a content block to judge a key, so it
/// holds the same content-aware declared-size gate as extraction
/// (bug-sweep H1+H2, 14 Aug 2026): a content dictionary bomb and the
/// zeroed-start recovery shape both answer Fails at the gate, before
/// ArchiveReader allocates anything.
#[test]
fn bomb_declaring_containers_fail_the_key_check_at_the_gate() {
    let fixtures = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../nzbkit-base/tests/fixtures/sevenz"
    );
    for name in ["bomb-content-dict.7z", "recovered-zero-start.bin"] {
        let p = std::path::Path::new(fixtures).join(name);
        assert_eq!(
            sevenz_password_check_capped(std::slice::from_ref(&p), Some("any"), 1 << 20),
            SevenzKey::Fails,
            "{name} must fail at the gate"
        );
    }
}

/// Codex sweep M, 13 Aug 2026: what rejects a wrong key on a
/// data-encrypted 7z entry is the entry's CHECKSUM, at its END. The key
/// check reads at most 64 MB, so a first member bigger than that never
/// reached the checksum and the capped read came back "opens" for ANY
/// value - the first candidate tried won and the archive stayed packed.
/// Reaching the cap is now indeterminate, not a pass.
#[test]
fn a_capped_7z_key_check_is_indeterminate_not_a_pass() {
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter, Password, encoder_options::AesEncoderOptions};
    let dir = std::env::temp_dir().join(format!("nzbfast-7zcap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Copy coding plus AES: a wrong key yields garbage bytes and no
    // error at all until the checksum - exactly the shape the cap hides.
    let payload: Vec<u8> = (0..64_000u32).map(|i| (i * 31 + 7) as u8).collect();
    let bytes = {
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.set_encrypt_header(false); // plaintext headers: it OPENS unkeyed
        w.set_content_methods(vec![AesEncoderOptions::new(Password::from("right")).into()]);
        w.push_archive_entry(ArchiveEntry::new_file("payload.bin"), Some(&payload[..]))
            .unwrap();
        w.finish().unwrap().into_inner()
    };
    let z = dir.join("locked.7z");
    std::fs::write(&z, &bytes).unwrap();

    // Unbounded enough to reach the checksum: the answers are settled.
    assert_eq!(
        sevenz_password_check_capped(std::slice::from_ref(&z), Some("right"), 1 << 20),
        SevenzKey::Opens
    );
    assert_eq!(
        sevenz_password_check_capped(std::slice::from_ref(&z), Some("wrong"), 1 << 20),
        SevenzKey::Fails
    );
    // Cut short of it, neither value can be judged - and the wrong one
    // must NOT come back as a pass.
    assert_eq!(
        sevenz_password_check_capped(std::slice::from_ref(&z), Some("wrong"), 1_024),
        SevenzKey::Unknown,
        "a read that stopped before the checksum settles nothing"
    );
    assert_eq!(
        sevenz_password_check_capped(std::slice::from_ref(&z), Some("right"), 1_024),
        SevenzKey::Unknown
    );

    // And the shortlist puts what IS settled first, so the extraction
    // spends itself on the proven value before any indeterminate one.
    let list = dir.join("pw.txt");
    std::fs::write(&list, "wrong\nright\n").unwrap();
    crate::pwfile::set_operator_password_file(Some(list));
    let cands = sevenz_password_candidates(std::slice::from_ref(&z), &dir, None);
    assert_eq!(
        cands.first().and_then(|(v, _)| v.clone()).as_deref(),
        Some("right")
    );

    crate::pwfile::set_operator_password_file(None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex sweep 13 Aug U1+U2: two encrypted NAMED RAR groups need not
/// share a password, and a harvested value must never shadow the one
/// the caller supplied.
///
/// The level resolver probed only the FIRST encrypted RAR (a.rar), and
/// its harvested answer replaced the job password for the whole level -
/// so b.rar, a RAR4 set whose check-less header can only be opened by
/// the password the user actually gave, was tried with a.rar's value,
/// failed as "wrong password", and stayed packed while the run
/// reported success. Per-group resolution keeps the caller's password
/// leading each group's candidate order.
#[test]
fn each_encrypted_rar_group_resolves_its_own_password() {
    let fixtures = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/rars/tests/fixtures");
    let dir = std::env::temp_dir().join(format!("nzbfast-pwrar-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // a.rar: RAR5, password "testpass", carries a check value so the
    // harvest can prove its candidate. b.rar: RAR4, password "junrar",
    // check-less - ONLY the caller's password can open it.
    std::fs::copy(
        fixtures.join("rar50/encrypted_solid.rar"),
        dir.join("a.rar"),
    )
    .unwrap();
    std::fs::copy(
        fixtures.join("rar15_40/encrypted/rar4_junrar_password.rar"),
        dir.join("b.rar"),
    )
    .unwrap();
    let list = dir.join("pw.txt");
    std::fs::write(&list, "testpass\n").unwrap();
    crate::pwfile::set_operator_password_file(Some(list));

    let out = extract_one_level(&dir, Some("junrar"), 0).unwrap();
    assert_eq!(out, Some(NestOutcome::Produced), "both groups must unpack");
    assert_eq!(
        std::fs::read(dir.join("file1.txt")).unwrap(),
        b"file1\n",
        "the RAR4 group must be opened with the CALLER's password, \
         not the harvested one"
    );

    crate::pwfile::set_operator_password_file(None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 162 item 5: five sites printed the auto-unlock notice and they
/// had drifted into three wordings - with the archive name, without it,
/// and "with a harvested password" carrying no source at all - so the
/// same unlock read as two different events depending on which arm
/// answered. `log_auto_unlocked` is the only site now, and this keeps it
/// that way: the string is what a user greps for and what the e2e suite
/// asserts on, and nothing else would notice a second spelling.
#[test]
fn the_auto_unlock_notice_has_exactly_one_spelling() {
    let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits: Vec<String> = Vec::new();
    let mut stack = vec![src];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|x| x.to_str()) != Some("rs") {
                continue;
            }
            // This file quotes the string to look for it.
            if p.file_name() == Some(std::ffi::OsStr::new("pwfile_tests.rs")) {
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap();
            for line in text.lines() {
                // The doc comment above the helper quotes the shape too,
                // and a comment is not a log call.
                if line.contains("auto-unlocked") && !line.trim_start().starts_with("//") {
                    hits.push(format!("{}: {}", p.display(), line.trim()));
                }
            }
        }
    }
    assert_eq!(
        hits.len(),
        1,
        "the notice must be printed from `log_auto_unlocked` alone: {hits:#?}"
    );
    assert!(
        hits[0].contains("passwords.rs"),
        "the one site must be the helper: {hits:#?}"
    );
}

/// Observed 23 Aug 2026: an UNENCRYPTED `.7z` taken down the disk
/// unpack path announced a false auto-unlock and paid for a candidate
/// sweep it never needed.
///
/// 7-Zip ignores a password on an unencrypted container, so
/// `sevenz_password_check` answers `Opens` for ANY value - and the
/// candidate sweep had no early settle for the no-password case (only
/// for a PROVIDED password that opens), so it harvested, "proved" the
/// first stem it found, and handed the extraction a password. The
/// notice is a lie a user may act on ("this release was passworded"),
/// and each probe may decode up to 64 MB of the first entry against
/// [`PW_PROBE_BUDGET`].
#[test]
fn an_unencrypted_7z_is_settled_before_any_password_is_harvested() {
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
    let dir = std::env::temp_dir().join(format!("nzbfast-7zplain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 13 + 9) as u8).collect();
    let bytes = {
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.push_archive_entry(ArchiveEntry::new_file("movie.mkv"), Some(&payload[..]))
            .unwrap();
        w.finish().unwrap().into_inner()
    };
    let z = dir.join("plain_release_name.7z");
    std::fs::write(&z, &bytes).unwrap();
    let parts = std::slice::from_ref(&z);

    // The premise, both halves: the directory DOES harvest a candidate,
    // and the probe calls that candidate proven - because there is
    // nothing to decrypt, not because the value is right.
    let harvested = harvest_password_candidates(&dir, None);
    let stem = harvested
        .iter()
        .find(|c| c.source == "release/sibling stem")
        .map(|c| c.value.clone())
        .expect("the container's own stem is a candidate");
    assert_eq!(
        sevenz_password_check(parts, Some(&stem)),
        SevenzKey::Opens,
        "an unencrypted container opens under any value at all"
    );

    // So the shortlist must settle on NO password, before the harvest -
    // one entry, no value, nothing for `extract_sevenz` to announce.
    let cands = sevenz_password_candidates(parts, &dir, None);
    assert_eq!(
        cands.iter().map(|(v, _)| v.clone()).collect::<Vec<_>>(),
        vec![None],
        "an archive that opens with no password needs no candidates"
    );

    // And it still unpacks.
    assert!(extract_one_level(&dir, None, 0).unwrap().is_some());
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), payload);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The header check that lets an unencrypted 7z skip its decode probe
/// must still read a DATA-encrypted container as encrypted, even when
/// its headers are plaintext.
///
/// That is the shape a naive fix gets wrong. `sevenz_needs_password`
/// keys on `PasswordRequired` / `MaybeBadPassword` from the header
/// parse, so it answers only for `-mhe` archives and comes back FALSE
/// for a container written with `set_encrypt_header(false)` over AES
/// content - which parses cleanly with no password at all. Short-
/// circuiting on that would hand every such archive an empty password
/// and end the job packed. `sevenz_is_encrypted` reads the blocks'
/// coder ids instead, so it sees the AES coder either way.
#[test]
fn a_data_encrypted_7z_with_plaintext_headers_reads_as_encrypted() {
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter, Password, encoder_options::AesEncoderOptions};
    let dir = std::env::temp_dir().join(format!("nzbfast-7zcoder-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i * 17 + 3) as u8).collect();

    let write = |encrypt_header: bool, aes: bool| {
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.set_encrypt_header(encrypt_header);
        if aes {
            w.set_content_methods(vec![AesEncoderOptions::new(Password::from("right")).into()]);
        }
        w.push_archive_entry(ArchiveEntry::new_file("payload.bin"), Some(&payload[..]))
            .unwrap();
        w.finish().unwrap().into_inner()
    };

    // Plaintext headers over AES content: the whole point of the test.
    let data_enc = dir.join("data_enc.7z");
    std::fs::write(&data_enc, write(false, true)).unwrap();
    assert!(
        !nzbkit::nameprobe::sevenz_needs_password(&data_enc),
        "the premise: the header parse alone calls this one unlocked"
    );
    assert!(
        crate::rarfix::sevenz_set_is_encrypted(std::slice::from_ref(&data_enc)),
        "an AES content coder is encryption whatever the headers say"
    );

    // Header-encrypted: the parse cannot even reach the coders, and the
    // fail-closed answer covers it.
    let hdr_enc = dir.join("hdr_enc.7z");
    std::fs::write(&hdr_enc, write(true, true)).unwrap();
    assert!(crate::rarfix::sevenz_set_is_encrypted(
        std::slice::from_ref(&hdr_enc)
    ));

    // And the one answer that is load-bearing: a plain container proves
    // itself clean, which is what skips the 64 MB decode probe.
    let plain = dir.join("plain.7z");
    std::fs::write(&plain, write(false, false)).unwrap();
    assert!(!crate::rarfix::sevenz_set_is_encrypted(
        std::slice::from_ref(&plain)
    ));

    // Not a 7z at all, and a missing file: both fail closed, so the
    // caller's existing probe path runs unchanged.
    let junk = dir.join("junk.7z");
    std::fs::write(&junk, b"not a 7z container at all").unwrap();
    assert!(crate::rarfix::sevenz_set_is_encrypted(
        std::slice::from_ref(&junk)
    ));
    assert!(crate::rarfix::sevenz_set_is_encrypted(
        std::slice::from_ref(&dir.join("absent.7z"))
    ));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex sweep F-10, 23 Aug 2026: a 7z whose FIRST block is plaintext
/// and whose second is AES must not settle its password off the
/// plaintext one.
///
/// `sevenz_set_is_encrypted` reads the container as encrypted (any AES
/// block), so the shortlist falls through to the decode probe - and the
/// probe read the first data entry, which is block 0's plaintext member
/// and decodes to its checksum under `None` and under any wrong value
/// alike. That `Opens` returned the caller's value as the ONLY
/// candidate, so the harvest never ran and the extraction died on the
/// encrypted block with the right password sitting in a sidecar.
#[test]
fn a_mixed_7z_settles_its_password_on_the_encrypted_block() {
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter, Password, encoder_options::AesEncoderOptions};
    let plain: Vec<u8> = (0..9_000u32).map(|i| (i * 7 + 1) as u8).collect();
    let secret: Vec<u8> = (0..11_000u32).map(|i| (i * 11 + 5) as u8).collect();
    // Two blocks: plain.txt written with the default methods, then
    // secret.txt under AES with plaintext headers, so the container
    // opens with no password at all. That is `7z a` twice over.
    let bytes = {
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.set_encrypt_header(false);
        w.push_archive_entry(ArchiveEntry::new_file("plain.txt"), Some(&plain[..]))
            .unwrap();
        w.set_content_methods(vec![
            AesEncoderOptions::new(Password::from("SECRET")).into(),
        ]);
        w.push_archive_entry(ArchiveEntry::new_file("secret.txt"), Some(&secret[..]))
            .unwrap();
        w.finish().unwrap().into_inner()
    };

    let stage = |tag: &str| {
        let dir = std::env::temp_dir().join(format!("nzbfast-7zmix-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let z = dir.join("mixed_release_name.7z");
        std::fs::write(&z, &bytes).unwrap();
        let list = dir.join("pw.txt");
        std::fs::write(&list, "wrong\nSECRET\n").unwrap();
        crate::pwfile::set_operator_password_file(Some(list));
        (dir, z)
    };

    // The premise, and the verdicts the probe must now give.
    let (probe_dir, z) = stage("probe");
    let parts = std::slice::from_ref(&z);
    assert!(
        crate::rarfix::sevenz_set_is_encrypted(parts),
        "one AES block makes the container encrypted"
    );
    assert_eq!(
        sevenz_password_check(parts, None),
        SevenzKey::Fails,
        "no password cannot decode the encrypted block"
    );
    assert_eq!(
        sevenz_password_check(parts, Some("wrong")),
        SevenzKey::Fails
    );
    assert_eq!(
        sevenz_password_check(parts, Some("SECRET")),
        SevenzKey::Opens
    );

    // And both job-password arms reach the harvested value and unpack
    // BOTH members, not just the plaintext one.
    for (tag, provided) in [("none", None), ("wrong", Some("wrong"))] {
        let (dir, z) = stage(tag);
        let cands = sevenz_password_candidates(std::slice::from_ref(&z), &dir, provided);
        assert!(
            cands.iter().any(|(v, _)| v.as_deref() == Some("SECRET")),
            "{tag}: the harvested password must be on the shortlist, got {cands:?}"
        );
        assert!(extract_one_level(&dir, provided, 0).unwrap().is_some());
        assert_eq!(std::fs::read(dir.join("plain.txt")).unwrap(), plain);
        assert_eq!(std::fs::read(dir.join("secret.txt")).unwrap(), secret);
        let _ = std::fs::remove_dir_all(&dir);
    }

    crate::pwfile::set_operator_password_file(None);
    let _ = std::fs::remove_dir_all(&probe_dir);
}
