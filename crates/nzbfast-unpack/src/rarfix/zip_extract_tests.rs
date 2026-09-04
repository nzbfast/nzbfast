//! Zip disk extraction (the 7z path's twin). The reader itself is tested
//! in `nzbkit::zip`; these cover the WIRING - what lands in the output
//! directory, and the refusals that keep a hostile archive out of it.

use nzbkit::zip::fixtures::Spec;
use std::path::PathBuf;

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-zipx-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(23).wrapping_add(seed))
        .collect()
}

/// The headline change: a zip payload used to FAIL the job with
/// "zip extraction is not built in". It now unpacks, and the
/// container is gone from the output because its payload replaced it.
#[test]
fn a_zip_payload_unpacks_into_the_output_directory() {
    let dir = tmp("payload");
    let movie = payload(120_000, 3);
    let nfo = b"release info".to_vec();
    let z = nzbkit::zip::fixtures::zip_of(&[
        Spec::deflated("Some.Movie/movie.mkv", &movie),
        Spec::stored("Some.Movie/info.nfo", &nfo),
    ]);
    std::fs::write(dir.join("payload.zip"), &z).unwrap();

    let found = nzbkit::zip::scan(&dir);
    assert_eq!(found.len(), 1);
    assert!(super::extract_zip(&dir, &found, None), "zip should unpack");
    assert_eq!(
        std::fs::read(dir.join("Some.Movie/movie.mkv")).unwrap(),
        movie
    );
    assert_eq!(std::fs::read(dir.join("Some.Movie/info.nfo")).unwrap(), nfo);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A self-extracting zip - a stub concatenated in front of a
/// container - reaches the disk pass by NAME (`zip::scan` never
/// magic-sniffs a named file), and the reader now follows the
/// archive's own offsets from where the archive actually starts.
/// The whole path has to hold, not just the parser: this is the
/// shape `unzip` reports as "extra bytes at beginning" and 7-Zip as
/// "the archive is open with offset". TODO 159 item 2.
#[test]
fn a_zip_behind_a_prepended_stub_unpacks_from_disk() {
    let dir = tmp("stubzip");
    let data = payload(80_000, 17);
    let mut z = b"MZ stub bytes, not a zip".to_vec();
    z.resize(511, 0);
    z.extend_from_slice(&nzbkit::zip::fixtures::zip_of(&[Spec::deflated(
        "Some.Movie/movie.mkv",
        &data,
    )]));
    std::fs::write(dir.join("selfextract.zip"), &z).unwrap();

    let found = nzbkit::zip::scan(&dir);
    assert_eq!(found.len(), 1, "a named .zip is found whatever its head");
    assert!(super::extract_zip(&dir, &found, None), "zip should unpack");
    assert_eq!(
        std::fs::read(dir.join("Some.Movie/movie.mkv")).unwrap(),
        data
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Two entries that resolve to ONE output path must not be handed to
/// two workers at once.
///
/// `a\b.bin` and `a/b.bin` are different names in the archive and the
/// same path here, because backslashes normalize to '/'. While
/// entries extracted one at a time the last writer simply won; on the
/// pool both called `File::create` on the same inode and wrote
/// concurrently, each checking only its own CRC and length, so both
/// reported success over a file holding a mixture of the two. The
/// surviving bytes must be exactly one entry's - the last, matching
/// the serial outcome - and never a blend.
#[test]
fn colliding_zip_entry_paths_do_not_race_one_output_file() {
    let dir = tmp("collide");
    // Big enough that a genuine race would interleave visibly rather
    // than finishing inside one buffered write.
    let first = payload(400_000, 1);
    let last = payload(400_000, 200);
    let z = nzbkit::zip::fixtures::zip_of(&[
        Spec::stored("dup/a\\b.bin", &first),
        Spec::stored("dup/a/b.bin", &last),
    ]);
    std::fs::write(dir.join("collide.zip"), &z).unwrap();

    let found = nzbkit::zip::scan(&dir);
    assert_eq!(found.len(), 1);
    assert!(super::extract_zip(&dir, &found, None), "zip should unpack");
    let got = std::fs::read(dir.join("dup/a/b.bin")).unwrap();
    assert_eq!(
        got.len(),
        last.len(),
        "the output is not one whole entry - two writers truncated each other"
    );
    assert_eq!(
        got, last,
        "expected the LAST entry, as a serial unpack gives"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Phase 3: an encrypted zip unpacks when the job carries the
/// password, in both schemes; without it (or with the wrong one)
/// the unpack fails and the container stays put for the user.
#[test]
fn an_encrypted_zip_unpacks_with_the_job_password() {
    use nzbkit::zip::fixtures::Encrypt;
    let movie = payload(80_000, 9);
    for (tag, enc) in [
        ("zc", Encrypt::ZipCrypto { password: "pw123" }),
        (
            "ae",
            Encrypt::Ae {
                password: "pw123",
                strength: 3,
                vendor_version: 2,
            },
        ),
    ] {
        let dir = tmp(&format!("enc-{tag}"));
        let z = nzbkit::zip::fixtures::zip_of(&[Spec {
            encrypt: Some(enc),
            ..Spec::deflated("movie.mkv", &movie)
        }]);
        std::fs::write(dir.join("payload.zip"), &z).unwrap();
        let found = nzbkit::zip::scan(&dir);
        assert!(
            !super::extract_zip(&dir, &found, None),
            "{tag}: no password must not unpack"
        );
        assert!(
            !super::extract_zip(&dir, &found, Some("wrong")),
            "{tag}: a wrong password must not unpack"
        );
        assert!(
            !dir.join("movie.mkv").exists(),
            "{tag}: nothing published on failure"
        );
        assert!(
            super::extract_zip(&dir, &found, Some("pw123")),
            "{tag}: the right password must unpack"
        );
        assert_eq!(
            std::fs::read(dir.join("movie.mkv")).unwrap(),
            movie,
            "{tag}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Zip-slip: an entry naming its way out of the output directory must
/// be refused, and nothing may be written outside it.
#[test]
fn an_entry_escaping_the_output_directory_is_refused() {
    let dir = tmp("slip");
    let inner = dir.join("inner");
    std::fs::create_dir_all(&inner).unwrap();
    let z =
        nzbkit::zip::fixtures::zip_of(&[Spec::stored("../../escaped.txt", b"should never land")]);
    std::fs::write(inner.join("evil.zip"), &z).unwrap();

    let found = nzbkit::zip::scan(&inner);
    assert!(
        !super::extract_zip(&inner, &found, None),
        "zip-slip must not succeed"
    );
    assert!(
        !dir.join("escaped.txt").exists(),
        "wrote outside the output dir"
    );
    assert!(!inner.join("escaped.txt").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A symlink entry's payload is a PATH. Materializing one plants a
/// link pointing wherever the archive likes, so it is refused.
#[test]
fn a_symlink_entry_is_refused() {
    let dir = tmp("link");
    let z = nzbkit::zip::fixtures::zip_of(&[Spec {
        external: 0xA1FF_0000,
        ..Spec::stored("link", b"/etc/passwd")
    }]);
    std::fs::write(dir.join("l.zip"), &z).unwrap();
    let found = nzbkit::zip::scan(&dir);
    assert!(
        !super::extract_zip(&dir, &found, None),
        "symlink entry must not extract"
    );
    assert!(!dir.join("link").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Damaged bytes must not be published: a wrong CRC fails the job
/// rather than landing a corrupt file that looks like success.
#[test]
fn a_damaged_entry_fails_instead_of_publishing() {
    let dir = tmp("crc");
    let data = payload(40_000, 7);
    let z = nzbkit::zip::fixtures::zip_of(&[Spec {
        crc_override: Some(0x1234_5678),
        ..Spec::stored("movie.mkv", &data)
    }]);
    std::fs::write(dir.join("d.zip"), &z).unwrap();
    let found = nzbkit::zip::scan(&dir);
    assert!(
        !super::extract_zip(&dir, &found, None),
        "a bad CRC must fail the unpack"
    );
    assert!(
        !dir.join("movie.mkv").exists(),
        "corrupt output was published"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A method we decline still reports honestly rather than opening
/// and producing nothing - and it names the codec.
#[test]
fn a_declined_method_fails_with_the_codec_named() {
    let dir = tmp("zstd");
    // zstd (93): bzip2 and then lzma stood here and are now decoded.
    let z = nzbkit::zip::fixtures::zip_of(&[Spec {
        method: 93,
        ..Spec::stored("movie.mkv", &payload(2_000, 9))
    }]);
    std::fs::write(dir.join("b.zip"), &z).unwrap();
    let found = nzbkit::zip::scan(&dir);
    assert!(!super::extract_zip(&dir, &found, None));
    // The container survives for the user to unpack by hand.
    assert!(dir.join("b.zip").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `.cbz` and friends ARE zip containers but are the deliverable.
/// The collector must never hand one to the extractor.
#[test]
fn a_cbz_payload_is_never_unpacked() {
    let dir = tmp("cbz");
    let z = nzbkit::zip::fixtures::zip_of(&[Spec::stored("page01.jpg", b"jpegbytes")]);
    std::fs::write(dir.join("comic.cbz"), &z).unwrap();
    assert!(
        nzbkit::zip::scan(&dir).is_empty(),
        "a .cbz must not be collected"
    );
    assert!(dir.join("comic.cbz").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The entry pass fans out on a small pool, so a many-entry archive
/// must land every payload byte-exact under its own name - distinct
/// content and sizes per entry so any cross-wiring of readers,
/// writers or CRCs fails loudly. Mixed store and deflate on purpose:
/// both methods ride the same pool.
#[test]
fn a_many_entry_zip_lands_every_payload_byte_exact() {
    let dir = tmp("many");
    let payloads: Vec<(String, Vec<u8>)> = (0..12u8)
        .map(|i| {
            (
                format!("d{}/file{i:02}.bin", i % 3),
                payload(
                    30_000 + 1_733 * i as usize,
                    i.wrapping_mul(37).wrapping_add(11),
                ),
            )
        })
        .collect();
    let specs: Vec<Spec> = payloads
        .iter()
        .enumerate()
        .map(|(i, (n, p))| {
            if i % 2 == 0 {
                Spec::stored(n, p)
            } else {
                Spec::deflated(n, p)
            }
        })
        .collect();
    let z = nzbkit::zip::fixtures::zip_of(&specs);
    std::fs::write(dir.join("payload.zip"), &z).unwrap();
    let found = nzbkit::zip::scan(&dir);
    assert_eq!(found.len(), 1);
    assert!(super::extract_zip(&dir, &found, None), "zip should unpack");
    for (n, p) in &payloads {
        assert_eq!(&std::fs::read(dir.join(n)).unwrap(), p, "{n}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// One damaged entry among many condemns the whole archive: nothing
/// is published, however many siblings decoded cleanly on the pool.
#[test]
fn one_damaged_entry_among_many_publishes_nothing() {
    let dir = tmp("many-crc");
    let payloads: Vec<(String, Vec<u8>)> = (0..10u8)
        .map(|i| {
            (
                format!("file{i:02}.bin"),
                payload(25_000 + 900 * i as usize, i.wrapping_add(51)),
            )
        })
        .collect();
    let specs: Vec<Spec> = payloads
        .iter()
        .enumerate()
        .map(|(i, (n, p))| Spec {
            // Damage one entry in the middle of the set.
            crc_override: (i == 6).then_some(0xDEAD_BEEF),
            ..Spec::stored(n, p)
        })
        .collect();
    let z = nzbkit::zip::fixtures::zip_of(&specs);
    std::fs::write(dir.join("payload.zip"), &z).unwrap();
    let found = nzbkit::zip::scan(&dir);
    assert!(
        !super::extract_zip(&dir, &found, None),
        "a bad CRC anywhere must fail the unpack"
    );
    for (n, _) in &payloads {
        assert!(!dir.join(n).exists(), "{n} was published from a failed set");
    }
    assert!(dir.join("payload.zip").exists(), "container must survive");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Hand-run timing rig for the multi-entry disk extraction, ignored
/// in normal runs (it writes gigabytes to the temp volume). Run
/// around perf changes with:
/// `cargo test -p nzbfast --bin nzbfast zip_multi_entry_bench -- --ignored --nocapture`
#[test]
#[ignore]
fn zip_multi_entry_bench() {
    for (tag, entries, mib, deflate) in
        [("store", 8usize, 192usize, false), ("deflate", 8, 64, true)]
    {
        let dir = tmp(&format!("bench-{tag}"));
        let payloads: Vec<Vec<u8>> = (0..entries)
            .map(|s| payload(mib << 20, (s as u8).wrapping_mul(31).wrapping_add(5)))
            .collect();
        let names: Vec<String> = (0..entries).map(|i| format!("part{i:02}.bin")).collect();
        let specs: Vec<Spec> = payloads
            .iter()
            .zip(&names)
            .map(|(p, n)| {
                if deflate {
                    Spec::deflated(n, p)
                } else {
                    Spec::stored(n, p)
                }
            })
            .collect();
        let z = nzbkit::zip::fixtures::zip_of(&specs);
        std::fs::write(dir.join("payload.zip"), &z).unwrap();
        drop(z);
        let found = nzbkit::zip::scan(&dir);
        let t0 = std::time::Instant::now();
        assert!(super::extract_zip(&dir, &found, None));
        let dt = t0.elapsed();
        println!(
            "zip bench [{tag}]: {entries} x {mib} MiB unpacked in {:.2}s",
            dt.as_secs_f64()
        );
        for (p, n) in payloads.iter().zip(&names) {
            assert_eq!(&std::fs::read(dir.join(n)).unwrap(), p, "{n}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// A byte-split set extracts without a join step - and without ever
/// writing a second copy of the container to disk.
#[test]
fn a_split_zip_set_unpacks_without_a_scratch_copy() {
    let dir = tmp("split");
    let data = payload(90_000, 11);
    let z = nzbkit::zip::fixtures::zip_of(&[Spec::deflated("movie.mkv", &data)]);
    let cut = z.len() / 2;
    std::fs::write(dir.join("m.zip.001"), &z[..cut]).unwrap();
    std::fs::write(dir.join("m.zip.002"), &z[cut..]).unwrap();
    let found = nzbkit::zip::scan(&dir);
    assert_eq!(found.len(), 1);
    assert!(super::extract_zip(&dir, &found, None));
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
    std::fs::remove_dir_all(&dir).unwrap();
}
