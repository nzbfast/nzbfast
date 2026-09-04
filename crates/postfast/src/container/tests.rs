//! The `container` case table.
//!
//! Out of line since 4 Sep 2026, and it is `tools/size-gate.py`'s own rule
//! that makes this the seam: a `#[cfg(test)] mod foo;` TARGET is scored
//! against TEST_FILE_CEILING rather than the flat production ceiling, so a
//! case table that is allowed to be long lives here and leaves the
//! production file its whole ceiling. Four lanes grew `container.rs` from
//! 2,945 to 4,037 lines in one afternoon and crossed it; the BASELINE_FILES
//! entry that stood in for this move was deleted in the same commit.

use super::*;

/// A profile whose `[container]` table is `extra`, over two small
/// files under a directory apiece so the tree is always in play.
fn profile(extra: &str) -> Profile {
    Profile::parse(&format!(
        "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{{ name = \"movie.bin\", bytes = 24000 }}]\n\n\
         [container]\n{extra}"
    ))
    .expect("test profile parses")
}

fn built(extra: &str) -> Contained {
    let p = profile(extra);
    let mut rng = Rng::for_profile(&p);
    let sources = crate::assemble::sources(&p, &mut rng).expect("sources assemble");
    wrap(&p, &sources, &mut rng)
        .unwrap_or_else(|e| panic!("{extra:?}: {e}"))
        .expect("a container was selected")
}

fn refusal(extra: &str) -> String {
    let p = profile(extra);
    let mut rng = Rng::for_profile(&p);
    let sources = crate::assemble::sources(&p, &mut rng).expect("sources assemble");
    match wrap(&p, &sources, &mut rng) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("{extra:?} must be refused"),
    }
}

/// C0 is not a container, and asking for one back is the caller's
/// signal to leave the payload alone.
#[test]
fn no_container_is_none() {
    let p = Profile::parse(
        "[layout]\nname = \"t\"\nseed = 1\n\n[source]\nfiles = [{ name = \"a.bin\", bytes = 16 }]\n",
    )
    .unwrap();
    let mut rng = Rng::for_profile(&p);
    let s = crate::assemble::sources(&p, &mut rng).unwrap();
    assert_eq!(wrap(&p, &s, &mut rng).unwrap(), None);
}

/// C1: one stored RAR5 volume that reads back. The round trip is
/// inside `wrap`, so reaching this assertion at all is most of the
/// test; the name and the payload are what is left.
#[test]
fn c1_stored_single_volume() {
    let c = built("kind = \"rar-stored\"\n");
    assert_eq!(c.volumes.len(), 1);
    assert_eq!(c.volumes[0].rel, "movie.rar");
    assert_eq!(c.payload.len(), 1);
    assert_eq!(c.payload[0].0, "movie.bin");
}

/// C2: three volumes, and the SET is what reads back - no single
/// volume of it holds the payload.
#[test]
fn c2_stored_split_volumes() {
    let c = built("kind = \"rar-stored\"\nvolume_bytes = 8000\n");
    assert!(c.volumes.len() >= 3, "got {} volumes", c.volumes.len());
    assert_eq!(c.volumes[0].rel, "movie.part01.rar");
    assert_eq!(c.volumes[1].rel, "movie.part02.rar");
}

/// C3: genuinely compressed, and the archive is SMALLER than the
/// payload. Without that assertion the row would pass over a writer
/// that silently stored an incompressible entry, which is exactly
/// what the RAR5 writer does - so the fixture's payload has to be
/// compressible and the test has to prove it was compressed.
#[test]
fn c3_compressed_really_compresses() {
    // A HAND-MADE source, and still worth keeping as one: constant
    // bytes are the strongest compressible input there is and no
    // profile can express them (that is `[source] periodic`, refused
    // by name), so this row pins the WRITER against a payload the
    // catalog will never hand it. What a generated payload reaches
    // is `content = "compressible"` (G8), whose own arm is
    // `a_generated_compressible_payload_reaches_c3` below.
    let sources = vec![SourceFile {
        rel: "doc.bin".into(),
        base: "doc.bin".into(),
        bytes: vec![7u8; 60_000],
    }];
    let prof = profile("kind = \"rar-compressed\"\n");
    let mut rng = Rng::for_profile(&prof);
    let c = wrap(&prof, &sources, &mut rng).unwrap().unwrap();
    assert!(
        c.volumes[0].bytes.len() < 60_000 / 2,
        "a compressible payload compressed to {} bytes",
        c.volumes[0].bytes.len()
    );
}

/// C4 and C5: the encrypted WRITER arms build a real archive on
/// both RAR generations, it opens with the password, and it does
/// NOT open without one.
///
/// Driven through [`write_one_archive`] on OS entropy, which is the
/// arm a real archive is written with. The reproducible arm that
/// the catalog uses is [`wrap`]'s, pinned separately below - this
/// one exists to prove the encryption itself is real whichever
/// source feeds it, and it was the only encrypted coverage there
/// was while `wrap` still refused the shape (until 4 Sep 2026).
#[test]
fn c4_and_c5_encrypt_on_both_generations() {
    const PW: &[u8] = b"not-a-real-password";
    let members = vec![("locked.bin".to_string(), vec![9u8; 4096])];
    for version in ["rar5", "rar4"] {
        for enc in ["data", "header"] {
            let p = profile(&format!(
                "kind = \"rar-stored\"\nversion = \"{version}\"\nencryption = \"{enc}\"\n\
                 password = \"not-a-real-password\"\n"
            ));
            let bytes = write_one_archive(&p.container, &members, [0xa1; 32])
                .unwrap_or_else(|e| panic!("{version}/{enc}: {e}"));
            let out = extract_set(std::slice::from_ref(&bytes), Some(PW)).unwrap_or_else(|e| {
                panic!("{version}/{enc}: does not open with the password: {e}")
            });
            assert_eq!(out, members, "{version}/{enc}");
            // The control arm: without this the row would pass over
            // a writer that ignored the selection entirely.
            assert!(
                extract_set(&[bytes], None).is_err(),
                "{version}/{enc}: the archive opened with no password"
            );
        }
    }
}

/// An encrypted profile now goes all the way through `wrap` and
/// comes back byte-identical, which is what the refusal that used
/// to stand here was waiting for.
///
/// Until 4 Sep 2026 `wrap` refused every encrypted shape by name,
/// because both RAR generations drew the key salt (and RAR5 the
/// data IV) from `getrandom::fill` with no alternative, so one
/// profile emitted different bytes on every run and a catalog walk
/// over it failed on noise. `rars::Entropy` (vendored 4 Sep 2026,
/// commit 1f46a2011) is the seeded source that answers it, and
/// [`ENTROPY_STREAM`] is where this crate draws one per level.
#[test]
fn an_encrypted_profile_wraps_and_repeats() {
    for version in ["rar5", "rar4"] {
        for enc in ["data", "header"] {
            let text = format!(
                "kind = \"rar-stored\"\nversion = \"{version}\"\nencryption = \"{enc}\"\n\
                 password = \"not-a-real-password\"\n"
            );
            let a = built(&text);
            let b = built(&text);
            assert_eq!(
                a.volumes[0].bytes, b.volumes[0].bytes,
                "{version}/{enc}: two wraps of one profile differ"
            );
            // ...and it is a real encrypted archive, not a plain one
            // that ignored the selection.
            assert!(
                extract_set(&[a.volumes[0].bytes.clone()], None).is_err(),
                "{version}/{enc}: the archive opened with no password"
            );
        }
    }
}

/// H2 + C4: a chain whose two levels have DIFFERENT passwords, and
/// each level opens with its own rather than with the stack's.
///
/// The round trip inside `wrap` is what proves it: it peels each
/// level with that level's password, so a build that had quietly
/// written both levels under the outer password would fail here
/// rather than at the client.
#[test]
fn a_chain_gives_each_level_its_own_password() {
    let text = "kind = \"rar-stored\"\nencryption = \"data\"\npassword = \"outer-pw\"\n\n\
                [[container.inner]]\nkind = \"rar-stored\"\n\
                encryption = \"data\"\npassword = \"inner-pw\"\n";
    let c = built(text);
    let outer = &c.volumes[0].bytes;

    // The outer level opens with the OUTER password and not with
    // the inner one, which is the half a shared password would hide.
    assert!(extract_set(std::slice::from_ref(outer), Some(b"inner-pw")).is_err());
    let peeled = extract_set(std::slice::from_ref(outer), Some(b"outer-pw"))
        .expect("the outer level opens with the outer password");
    assert_eq!(peeled.len(), 1, "the outer level holds the inner archive");

    // ...and the inner level the other way round.
    let inner = peeled[0].1.clone();
    assert!(extract_set(std::slice::from_ref(&inner), Some(b"outer-pw")).is_err());
    let payload = extract_set(&[inner], Some(b"inner-pw"))
        .expect("the inner level opens with the inner password");
    assert_eq!(payload[0].0, "movie.bin");

    // And the whole chain still repeats.
    assert_eq!(built(text).volumes[0].bytes, *outer);
}

/// An inner level that says nothing about a password uses the
/// stack's, which is what every profile written before the key
/// existed means and what a uniform chain says.
#[test]
fn an_inner_level_with_no_password_of_its_own_uses_the_stacks() {
    let c = built(
        "kind = \"rar-stored\"\nencryption = \"data\"\npassword = \"one-pw\"\n\n\
         [[container.inner]]\nkind = \"rar-stored\"\nencryption = \"data\"\n",
    );
    let peeled = extract_set(&[c.volumes[0].bytes.clone()], Some(b"one-pw")).unwrap();
    let payload = extract_set(&[peeled[0].1.clone()], Some(b"one-pw"))
        .expect("the inner level inherited the stack's password");
    assert_eq!(payload[0].0, "movie.bin");
}

/// C14 + the chain: a sibling's `text` is its content, verbatim
/// plus the terminator the client's line harvest needs.
#[test]
fn a_text_sibling_carries_its_text_and_draws_no_noise() {
    let with_text = built(
        "kind = \"rar-stored\"\n\
         siblings = [{ name = \"password.txt\", text = \"inner-pw\" }]\n",
    );
    let out = extract_set(&[with_text.volumes[0].bytes.clone()], None).unwrap();
    let note = out
        .iter()
        .find(|(n, _)| n == "password.txt")
        .expect("the sibling is carried");
    assert_eq!(note.1, b"inner-pw\n", "a text sibling holds its text");

    // It draws nothing from the sibling stream, so the payload of a
    // row that adds one does not move. (A `bytes` sibling does draw,
    // which is why this is worth pinning.)
    let without = built("kind = \"rar-stored\"\n");
    let payload = |c: &Contained| {
        extract_set(&[c.volumes[0].bytes.clone()], None)
            .unwrap()
            .into_iter()
            .find(|(n, _)| n == "movie.bin")
            .unwrap()
            .1
    };
    assert_eq!(payload(&with_text), payload(&without));
}

/// A 7z profile that asks for encryption BUILDS, at both storage
/// modes and both encryption depths, and what it builds is a real
/// encrypted archive.
///
/// This arm has a history worth reading before touching it. Until
/// 4 Sep 2026 a blanket encryption refusal caught every encrypted
/// profile on its way past without naming the format; narrowing that
/// refusal to the RAR arms - which is what made C4 and C5
/// expressible at all - left the 7z arm SILENTLY building a readable
/// archive for an encrypted profile, so it was refused by name for
/// the rest of that day. The refusal is lifted now that the writer
/// takes a password, the reader takes one back, and the vendored
/// crate's salt stopped coming from the OS.
///
/// The control - that the archive does NOT open unpassworded - is
/// `crate::sevenz::tests::an_encrypted_archive_does_not_open_unpassworded`,
/// and it is the assertion this pair of tests exists for: a "the
/// archive was written" test passed over the readable archive above
/// without complaint.
#[test]
fn a_seven_zip_profile_that_asks_for_encryption_is_built_and_is_really_encrypted() {
    for kind in ["7z-stored", "7z-compressed"] {
        for enc in ["data", "header"] {
            let c = built(&format!(
                "kind = \"{kind}\"\nencryption = \"{enc}\"\npassword = \"pw-fixture\"\n"
            ));
            let set = vec![c.volumes[0].bytes.clone()];
            assert_eq!(
                crate::sevenz::extract_set(&set, Some("pw-fixture"))
                    .unwrap_or_else(|e| panic!("{kind}/{enc}: {e}"))[0]
                    .0,
                "movie.bin"
            );
            assert!(
                crate::sevenz::extract_set(&set, None).is_err(),
                "{kind}/{enc}: the archive opens with no password at all"
            );
        }
    }
}

/// ...and an INNER 7z level encrypts too, which is the half a check
/// written only against `[container]` would miss: a chain can put a
/// 7z anywhere in the stack, and `level_stack` resolves each level's
/// password before any write site sees it.
///
/// The inner level's password DIFFERS from the outer one here, so a
/// stack that had quietly written every level under the outermost
/// password fails at the peel rather than passing.
#[test]
fn an_inner_seven_zip_level_encrypts_under_its_own_password() {
    let c = built(
        "kind = \"rar-stored\"\nencryption = \"data\"\npassword = \"outer-pw\"\n\n\
         [[container.inner]]\nkind = \"7z-stored\"\n\
         encryption = \"data\"\npassword = \"inner-pw\"\n",
    );
    let peeled = extract_set(&[c.volumes[0].bytes.clone()], Some(b"outer-pw")).unwrap();
    assert_eq!(peeled[0].0, "movie.inner1.7z");
    let inner = vec![peeled[0].1.clone()];
    assert!(
        crate::sevenz::extract_set(&inner, Some("outer-pw")).is_err(),
        "the inner 7z level was written under the OUTER password"
    );
    assert_eq!(
        crate::sevenz::extract_set(&inner, Some("inner-pw"))
            .expect("the inner level opens with its own password")[0]
            .0,
        "movie.bin"
    );
}

/// An encrypted multi-member SPLIT set builds STORED as well as
/// compressed, which is the writers' shape and not a rule this
/// crate chose.
///
/// `Rar50VolumeWriter::encrypted_compressed_entries` has always
/// taken a slice; `::encrypted_stored_entry` was singular with no
/// plural beside it, so this pair used to be one build and one
/// refusal. `::encrypted_stored_entries` closed that on 4 Sep 2026.
/// The pair stays because the asymmetry is what the guard above
/// used to encode, and a reader needs to see BOTH halves build now
/// rather than take a comment's word for it.
#[test]
fn an_encrypted_multi_member_split_builds_either_way() {
    let two_files = |kind: &str| {
        format!(
            "[layout]\nname = \"t\"\nseed = 1\n\n\
             [source]\nfiles = [\
             {{ name = \"a.bin\", bytes = 20000, content = \"compressible\" }}, \
             {{ name = \"b.bin\", bytes = 20000, content = \"compressible\" }}]\n\n\
             [container]\nkind = \"{kind}\"\nencryption = \"data\"\n\
             password = \"pw-fixture\"\nvolume_bytes = 700\n"
        )
    };
    let build = |kind: &str| {
        let p = Profile::parse(&two_files(kind)).expect("parses");
        let mut rng = Rng::for_profile(&p);
        let sources = crate::assemble::sources(&p, &mut rng).expect("sources assemble");
        wrap(&p, &sources, &mut rng)
    };

    for kind in ["rar-compressed", "rar-stored"] {
        let c = build(kind)
            .expect("the encrypted volume writers take several members")
            .expect("a container was selected");
        assert!(c.volumes.len() > 1, "{kind}: the set did not split");
        let out = extract_set(
            &c.volumes
                .iter()
                .map(|v| v.bytes.clone())
                .collect::<Vec<_>>(),
            Some(b"pw-fixture"),
        )
        .unwrap_or_else(|e| panic!("{kind}: the posted set reads back: {e}"));
        let names: Vec<_> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["a.bin", "b.bin"], "{kind}");
        // The password is load-bearing: an encrypted set that opens
        // with none is the failure this plane exists to catch.
        assert!(
            extract_set(
                &c.volumes
                    .iter()
                    .map(|v| v.bytes.clone())
                    .collect::<Vec<_>>(),
                None,
            )
            .is_err(),
            "{kind}: the set opened with no password"
        );
    }
}

/// THE CONTROL ARM, and the reason the seeded source is opt-in.
///
/// Both writers default to OS entropy and nothing outside a
/// generated fixture may move off it: a seeded salt hands the key
/// derivation to anyone holding the seed, and the seed travels in a
/// public catalog. This pins that the DEFAULT is still fresh per
/// run, so the day someone makes the seeded path the default by
/// accident, this reddens rather than every archive anyone writes
/// with these libraries quietly shipping predictable salts.
///
/// **Through `rars`' own API and NOT through [`write_one_archive`],
/// since 4 Sep 2026.** That site now takes a raw SEED - one per
/// stack level, spent by whichever format the level selected - so it
/// has no way left to spell "draw from the OS", and a control arm
/// asking it to would be asserting something it cannot express. What
/// the arm is actually about is the LIBRARY default, which is where
/// it is now asked. The 7z half of the same claim is
/// `crate::sevenz::tests::entropy::the_default_still_varies_per_run`,
/// which reaches `sevenz_rust2`'s draw sites the same way.
///
/// Two OS draws of a 16-byte salt colliding has probability 2^-128.
#[test]
fn os_entropy_is_still_drawn_fresh_every_run() {
    assert_eq!(rars::Entropy::default(), rars::Entropy::Os);
    assert_eq!(
        sevenz_rust2::Entropy::default(),
        sevenz_rust2::Entropy::Os,
        "the 7z writer's default moved off the operating system"
    );
    let write = || {
        let mut f = FeatureSet::store_only();
        f.file_encryption = true;
        let opts = rars::rar50::WriterOptions::new(rars::ArchiveVersion::Rar50, f);
        rars::rar50::Rar50Writer::new(opts)
            .encrypted_stored_entries(&[rars::rar50::EncryptedStoredEntry {
                name: b"locked.bin",
                data: &[9u8; 4096],
                mtime: None,
                attributes: 0,
                host_os: 0,
                password: b"not-a-real-password",
            }])
            .finish()
            .expect("the encrypted writer builds an archive")
    };
    assert_ne!(
        write(),
        write(),
        "the OS default has been made deterministic"
    );
}

/// C6: every volume gets its own token and nothing in the names
/// says which is which, which is the whole row.
#[test]
fn c6_opaque_volume_names_carry_no_ordering() {
    let c = built("kind = \"rar-stored\"\nvolume_bytes = 8000\nvolume_names = \"opaque\"\n");
    assert!(c.volumes.len() >= 3);
    let names: Vec<&str> = c.volumes.iter().map(|v| v.rel.as_str()).collect();
    for n in &names {
        assert!(n.ends_with(".bin"), "{n}");
        assert!(!n.contains("part"), "{n} spells its own order");
        assert!(!n.contains("movie"), "{n} carries the release stem");
    }
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "two volumes share a name");
}

/// C7: the payload rides two levels down, and `wrap` peels exactly
/// that many before it believes the round trip.
#[test]
fn c7_nested_two_levels() {
    let c = built("kind = \"rar-stored\"\nnested = 2\n");
    assert_eq!(c.volumes.len(), 1);
    assert_eq!(c.volumes[0].rel, "movie.rar");
    // Three archives deep, so the outer one is not the payload's:
    // its single member is the level below it.
    let out = extract_set(&[c.volumes[0].bytes.clone()], None).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, "movie.inner2.rar");
}

/// C9: the prefix is a program, at the front, and the volume is
/// named something the client's SFX arm will look at.
#[test]
fn c9_leading_bytes_are_a_launcher_stub() {
    let c = built("kind = \"rar-stored\"\nleading_bytes = 4096\n");
    assert_eq!(c.volumes[0].rel, "movie.exe");
    let head = &c.volumes[0].bytes;
    assert!(
        nzbkit::sfx::is_launcher_stub(head),
        "the prefix is not a shape the client reads as a stub"
    );
    assert_eq!(
        nzbkit::sfx::sfx_payload_at(head).map(|(off, _)| off),
        Some(4096),
        "the archive is not where the stub says it is"
    );
}

/// C8: the emitted file is TWO confirmed archives of different
/// formats, and the one the client's scan settles on is the earlier
/// of them - in both orderings.
///
/// The mirror pair is the control arm, and it is the reason this
/// test runs a table rather than one row. A single ordering is green
/// both for a client that takes the EARLIEST candidate and for one
/// that simply prefers the format that ordering happened to put
/// first; running the same two formats the other way round is what
/// tells those apart, because a format preference answers with the
/// same family twice and a positional rule does not.
///
/// The tail assertions are the OTHER thing that would make this
/// green for nothing: a second half that is not really an archive.
/// `sfx_payload_at` CONFIRMS a candidate - a parseable header behind
/// the magic - and steps over one it cannot, so a tail that failed
/// confirmation would leave the client a single candidate and
/// nothing to disambiguate, and the row would pass having measured
/// C9 instead.
#[test]
fn c8_is_two_confirmed_archives_and_the_client_settles_on_the_earlier() {
    use nzbkit::sfx::SfxFamily;
    for (extra, poly, first, second) in [
        (
            "kind = \"rar-stored\"\nleading_bytes = 4096\npolyglot = \"7z\"\n",
            Polyglot::SevenZ,
            SfxFamily::Rar,
            SfxFamily::SevenZ,
        ),
        (
            "kind = \"7z-stored\"\nleading_bytes = 4096\npolyglot = \"rar\"\n",
            Polyglot::Rar,
            SfxFamily::SevenZ,
            SfxFamily::Rar,
        ),
    ] {
        let c = built(extra);
        assert_eq!(c.volumes.len(), 1, "{extra}");
        let file = &c.volumes[0].bytes;
        assert_eq!(c.volumes[0].rel, "movie.exe", "{extra}");
        assert!(
            nzbkit::sfx::is_launcher_stub(file),
            "{extra}: the file does not begin with a program"
        );
        assert_eq!(
            nzbkit::sfx::sfx_payload_at(file),
            Some((4096, first)),
            "{extra}: the client's scan does not settle on the selected archive"
        );

        // The second archive sits at the end, whole, and is
        // confirmed on its own - which is what makes the file a
        // polyglot rather than an archive with an appendix.
        let tail = polyglot_tail(poly).expect("the second archive writes");
        let at = file.len() - tail.len();
        assert!(
            file[at..] == tail[..],
            "{extra}: the second archive is not at the end of the file"
        );
        assert_eq!(
            nzbkit::sfx::sfx_payload_at(&file[at..]),
            Some((0, second)),
            "{extra}: the second archive is not one the client would confirm"
        );
        assert!(
            at > 4096,
            "{extra}: the second archive would be the EARLIER one"
        );

        // ...and it really opens, to a member of its own. Disjoint
        // trees are what let an oracle row graded on its exact tree
        // say which archive the client took.
        let out = match poly {
            Polyglot::SevenZ => crate::sevenz::extract_set(std::slice::from_ref(&tail), None),
            Polyglot::Rar => extract_set(std::slice::from_ref(&tail), None),
            Polyglot::None => unreachable!("no arm selects it"),
        }
        .unwrap_or_else(|e| panic!("{extra}: the second archive does not open: {e}"));
        assert_eq!(
            out,
            vec![(
                POLYGLOT_MEMBER.to_string(),
                vec![POLYGLOT_MEMBER_FILL; POLYGLOT_MEMBER_BYTES]
            )],
            "{extra}"
        );
        assert!(
            !c.payload.iter().any(|(n, _)| n == POLYGLOT_MEMBER),
            "{extra}: the second archive's member is not an end state"
        );
    }
}

/// C8's refusals, both of them shapes the CLIENT would never have to
/// disambiguate - so a row over either would be green without a
/// second candidate ever having been weighed.
///
/// Read with the arm above: these are what stop the plane being
/// selected by a profile that has not built one.
#[test]
fn a_polyglot_the_client_never_has_to_read_is_refused() {
    for (extra, want) in [
        (
            "kind = \"rar-stored\"\npolyglot = \"7z\"\n",
            "with no launcher stub in front of it",
        ),
        (
            "kind = \"rar-stored\"\nleading_bytes = 4096\npolyglot = \"rar\"\n",
            "names ONE format twice",
        ),
        (
            "kind = \"7z-stored\"\nleading_bytes = 4096\npolyglot = \"7z\"\n",
            "names ONE format twice",
        ),
    ] {
        let msg = refusal(extra);
        assert!(msg.contains(want), "{extra:?} was refused as: {msg}");
    }
}

/// C8's second archive is furniture, so selecting it must not move a
/// single byte of the post it was added to.
///
/// The same property the stub has and for the same reason: a
/// polyglot row is almost always a C9 row with one key added, and if
/// the tail drew from a stream the two would differ in every
/// message-id rather than in the one selection.
#[test]
fn c8_moves_no_name_and_no_message_id() {
    let plain = built("kind = \"rar-stored\"\nleading_bytes = 4096\n");
    let poly = built("kind = \"rar-stored\"\nleading_bytes = 4096\npolyglot = \"7z\"\n");
    assert_eq!(plain.post_stem, poly.post_stem);
    assert_eq!(plain.payload, poly.payload);
    assert_eq!(plain.volumes[0].rel, poly.volumes[0].rel);
    let tail = polyglot_tail(Polyglot::SevenZ).unwrap();
    assert_eq!(
        plain.volumes[0].bytes.len() + tail.len(),
        poly.volumes[0].bytes.len(),
        "the polyglot volume is the C9 volume plus the second archive and nothing else"
    );
    assert!(
        poly.volumes[0].bytes.starts_with(&plain.volumes[0].bytes),
        "selecting C8 rewrote the archive in front of it"
    );
}

/// C10: a recovery record makes the archive bigger, and it still
/// reads back - on BOTH generations since 4 Sep 2026.
///
/// "Bigger" alone is not the assertion. A row saying a record is
/// there, over an archive carrying none, is the defect this plane
/// exists to make impossible, so each generation is asked for the
/// record's own marker: RAR5's `RR` service, and RAR4's `Protect+`
/// NEWSUB block with `MHD_PROTECT` set in the main header.
#[test]
fn c10_recovery_record_is_really_there() {
    for version in ["rar5", "rar4"] {
        let base = format!("kind = \"rar-stored\"\nversion = \"{version}\"\n");
        let plain = built(&base);
        let rr = built(&format!("{base}recovery_record_pct = 10\n"));
        assert!(
            rr.volumes[0].bytes.len() > plain.volumes[0].bytes.len(),
            "{version}: a 10% recovery record added {} bytes",
            rr.volumes[0].bytes.len() as i64 - plain.volumes[0].bytes.len() as i64
        );
        assert!(
            !plain.volumes[0].bytes.windows(8).any(|w| w == b"Protect+"),
            "{version}: the control archive already carries a record"
        );
        let archive = rars::ArchiveReader::read(&rr.volumes[0].bytes).expect("it parses");
        match version {
            "rar4" => {
                let raw = archive.as_rar15_40().expect("a RAR4 archive");
                assert!(raw.main.has_recovery_record(), "MHD_PROTECT is not set");
                let record = raw
                    .new_subs()
                    .find(|sub| sub.kind == rars::rar15_40::NewSubKind::RecoveryRecord)
                    .expect("no RR NEWSUB block behind the flag");
                assert!(record.file.pack_size > 0, "the RR block is empty");
            }
            _ => {
                let raw = archive.as_rar50().expect("a RAR5 archive");
                assert!(raw.main.has_recovery_record(), "no recovery flag");
                assert!(
                    raw.services().any(|service| service.name == b"RR"),
                    "no RR service behind the flag"
                );
            }
        }
        // ...and the payload still comes back out of the archive the
        // record is embedded in.
        let out = extract_set(&[rr.volumes[0].bytes.clone()], None).unwrap();
        assert_eq!(out.len(), 1, "{version}");
    }
    let plain = built("kind = \"rar-stored\"\n");
    let rr = built("kind = \"rar-stored\"\nrecovery_record_pct = 10\n");
    assert!(
        rr.volumes[0].bytes.len() > plain.volumes[0].bytes.len(),
        "a 10% recovery record added {} bytes",
        rr.volumes[0].bytes.len() as i64 - plain.volumes[0].bytes.len() as i64
    );
}

/// C11: three spellings of the same ordering, and each one is the
/// spelling a real archiver writes.
#[test]
fn c11_the_three_volume_styles() {
    for (style, want) in [
        ("partNN", ["movie.part01.rar", "movie.part02.rar"]),
        ("r00", ["movie.rar", "movie.r00"]),
        ("numeric", ["movie.001", "movie.002"]),
    ] {
        let c = built(&format!(
            "kind = \"rar-stored\"\nvolume_bytes = 8000\nvolume_style = \"{style}\"\n"
        ));
        assert_eq!(c.volumes[0].rel, want[0], "{style}");
        assert_eq!(c.volumes[1].rel, want[1], "{style}");
    }
}

/// The numbering a RAR4 set DECLARES is the one its file names spell.
///
/// [`rar4_volume_numbering`] mirrors [`volume_names`] rather than
/// reading its output, because the names are drawn AFTER the bytes
/// and under C6 they draw from the seed, so moving that call would
/// move every opaque row. A mirrored rule drifts, so this drives
/// whole selections through `wrap` and reads the bit back off the
/// WIRE bytes - the only arm that survives the plumb being dropped
/// at the writer.
#[test]
fn the_declared_rar4_numbering_matches_the_names_emitted() {
    for extra in [
        "kind = \"rar-stored\"\nversion = \"rar4\"\nvolume_bytes = 8000\n",
        "kind = \"rar-stored\"\nversion = \"rar4\"\nvolume_bytes = 8000\nvolume_style = \"partNN\"\n",
        "kind = \"rar-stored\"\nversion = \"rar4\"\nvolume_bytes = 8000\nvolume_style = \"r00\"\n",
        "kind = \"rar-stored\"\nversion = \"rar4\"\nvolume_bytes = 8000\nvolume_style = \"numeric\"\n",
        "kind = \"rar-stored\"\nversion = \"rar4\"\nvolume_bytes = 8000\nvolume_names = \"opaque\"\n",
        // `rar-compressed` is not on this list: a RAR C3 row is
        // refused outright today, because `[source]` bytes are
        // incompressible by construction and the writer stores what
        // it cannot shrink. See
        // `a_compressed_selection_the_writer_stored_is_refused`.
    ] {
        let c = built(extra);
        assert!(c.volumes.len() > 1, "{extra:?} did not split");
        let partnn = c.volumes[0].rel.contains(".part01.rar");
        for (index, volume) in c.volumes.iter().enumerate() {
            let main = rars::rar15_40::Archive::parse(&volume.bytes)
                .unwrap_or_else(|e| panic!("{extra:?} volume {index}: {e}"))
                .main
                .uses_new_numbering();
            assert_eq!(
                main, partnn,
                "{extra:?} volume {index} named {} declares new numbering = {main}",
                volume.rel
            );
        }
    }
}

/// RAR4 builds C1 and C2 through `wrap` and reads back; its C4 and
/// C5 arms are in `c4_and_c5_encrypt_on_both_generations`, which
/// drives the writer directly for the reason that test states.
#[test]
fn rar4_stored_and_split() {
    for extra in [
        "kind = \"rar-stored\"\nversion = \"rar4\"\n",
        "kind = \"rar-stored\"\nversion = \"rar4\"\nvolume_bytes = 8000\n",
    ] {
        let c = built(extra);
        assert!(!c.volumes.is_empty(), "{extra}");
    }
}

/// A `rar-compressed` selection the writer answered by STORING is
/// refused, and the refusal names the plane that has to change.
///
/// The refusal still stands and still matters: it is what a C3
/// profile over NEUTRAL bytes gets, which is every C3 profile whose
/// author forgot `[source] content = "compressible"` (G8). Until
/// that key landed on 4 Sep 2026 it was C3's whole status - the
/// compressed writer paths were built and unit-tested above over a
/// hand-made payload and no catalog row could reach them - and what
/// changed is that there is now a way to say yes, not that the
/// refusal was loosened.
#[test]
fn a_compressed_selection_the_writer_stored_is_refused() {
    for extra in [
        "kind = \"rar-compressed\"\n",
        "kind = \"rar-compressed\"\nversion = \"rar4\"\n",
        "kind = \"rar-compressed\"\nvolume_bytes = 8000\n",
    ] {
        let msg = refusal(extra);
        assert!(msg.contains("is STORED"), "{msg}");
        assert!(msg.contains("SOURCE plane"), "{msg}");
    }
}

/// G8: a GENERATED compressible payload drives the compressed
/// writer, which is what makes C3 a plane the catalog can select at
/// all. The `NothingToCompress` refusal above is the same selection
/// over neutral bytes, so the two rows together say exactly what
/// the key buys.
#[test]
fn a_generated_compressible_payload_reaches_c3() {
    for extra in [
        "kind = \"rar-compressed\"\n",
        "kind = \"rar-compressed\"\nversion = \"rar4\"\n",
    ] {
        let prof = Profile::parse(&format!(
            "[layout]\nname = \"t\"\nseed = 1\n\n\
             [source]\nfiles = [{{ name = \"movie.bin\", bytes = 60000, \
             content = \"compressible\" }}]\n\n[container]\n{extra}"
        ))
        .expect("parses");
        let mut rng = Rng::for_profile(&prof);
        let sources = crate::assemble::sources(&prof, &mut rng).expect("sources assemble");
        let c = wrap(&prof, &sources, &mut rng)
            .unwrap_or_else(|e| panic!("{extra:?}: {e}"))
            .expect("a container was selected");
        let total: usize = c.volumes.iter().map(|v| v.bytes.len()).sum();
        assert!(
            total * 2 < 60_000,
            "{extra:?}: a compressible payload must at least halve, got {total}"
        );
    }
}

/// A shape no writer builds is refused BY NAME, and the refusal
/// names the entry point that would have to grow. Silently emitting
/// a different shape that happens to build is the rubber stamp this
/// crate exists to make impossible.
#[test]
fn shapes_no_writer_builds_are_refused_by_name() {
    for (extra, want) in [
        // A plain rar4 recovery record BUILDS since 4 Sep 2026; what
        // is left of the old blanket refusal is the two shapes the
        // writer still has no plan for. Both are named, because both
        // used to be caught by the wider arm on their way past.
        (
            "kind = \"rar-stored\"\nversion = \"rar4\"\nrecovery_record_pct = 10\n\
             volume_bytes = 8000\n",
            "split rar4 set",
        ),
        (
            "kind = \"rar-stored\"\nversion = \"rar4\"\nrecovery_record_pct = 10\n\
             encryption = \"header\"\npassword = \"pw\"\n",
            "header-encrypted rar4",
        ),
        (
            "kind = \"rar-stored\"\nleading_bytes = 8\n",
            "is too short to be a launcher stub",
        ),
        (
            "kind = \"rar-stored\"\nleading_bytes = 4096\nvolume_bytes = 8000\n",
            "behind a launcher stub",
        ),
        (
            "kind = \"rar-stored\"\nvolume_bytes = 8000\nvolume_names = \"opaque\"\n\
             volume_style = \"r00\"\n",
            "two answers to one question",
        ),
    ] {
        let msg = refusal(extra);
        assert!(msg.contains(want), "{extra:?} was refused as: {msg}");
    }
}

/// A split STORED set of several files BUILDS on RAR5, and every
/// member comes back out.
///
/// This was a named writer gap until 4 Sep 2026 - H0 of
/// research/POSTFAST-VS-NESTED-CORPUS-2026-09-03.md - because every
/// stored volume entry point took a single entry. The fix is a
/// writer arm, `Rar50VolumeWriter::stored_entries`, made in the fork
/// at ~/Claude/rars and synced into vendor/rars; the refusal below
/// keeps the arm that is still real. The shape matters because it is
/// the corpus's own baseline leg r1 and the commonest layout on the
/// wire: several files in one split store set.
#[test]
fn a_split_stored_set_of_several_files_builds_on_rar5() {
    let p = Profile::parse(
        "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{ name = \"a.bin\", bytes = 9000 }, { name = \"b.bin\", bytes = 9000 }]\n\n\
         [container]\nkind = \"rar-stored\"\nvolume_bytes = 8000\n",
    )
    .unwrap();
    let mut rng = Rng::for_profile(&p);
    let s = crate::assemble::sources(&p, &mut rng).unwrap();
    let c = wrap(&p, &s, &mut rng)
        .expect("a multi-member split stored set is buildable")
        .expect("a container was selected");
    assert!(
        c.volumes.len() > 2,
        "the set is not split: {:?}",
        c.volumes.iter().map(|v| &v.rel).collect::<Vec<_>>()
    );
    let out = extract_set(
        &c.volumes
            .iter()
            .map(|v| v.bytes.clone())
            .collect::<Vec<_>>(),
        None,
    )
    .expect("the posted set reads back");
    let names: Vec<_> = out.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["a.bin", "b.bin"]);
    for ((_, got), src) in out.iter().zip(s.iter()) {
        assert_eq!(got, &src.bytes);
    }
}

/// The SAME shape on RAR4 builds too, since the RAR4 plurals
/// landed beside the RAR5 ones.
///
/// This arm is what H0 did NOT close: `rar15_40::write`'s volume
/// entry points took one entry each. `write_stored_volume_set` and
/// `write_compressed_volume_set` are the plurals, made in the fork
/// at ~/Claude/rars on 4 Sep 2026 and hand-ported into vendor/rars.
/// A RAR4 set needed one thing its RAR5 twin did not: an ENDARC
/// block with the next-volume flag on every volume but the last. A
/// single member is split across EVERY volume, so the split flags
/// alone chain it; a multi-member set has volumes whose last file
/// is complete, and unrar 7.23 stopped at the first of those and
/// wrote one member out of three.
#[test]
fn a_split_rar4_set_of_several_files_builds() {
    // `volume_bytes` differs by kind because the cut is over PACKED
    // bytes: compressible members shrink to a few hundred, and a
    // stored set's cut has to stay well inside one member or
    // nothing straddles a boundary and the set is two small
    // archives in a trench coat.
    for (kind, volume_bytes) in [("rar-stored", 8000), ("rar-compressed", 64)] {
        let p = Profile::parse(&format!(
            "[layout]\nname = \"t\"\nseed = 1\n\n\
             [source]\nfiles = [\
             {{ name = \"a.bin\", bytes = 9000, content = \"compressible\" }}, \
             {{ name = \"b.bin\", bytes = 9000, content = \"compressible\" }}]\n\n\
             [container]\nkind = \"{kind}\"\nversion = \"rar4\"\n\
             volume_bytes = {volume_bytes}\n",
        ))
        .unwrap();
        let mut rng = Rng::for_profile(&p);
        let s = crate::assemble::sources(&p, &mut rng).unwrap();
        let c = wrap(&p, &s, &mut rng)
            .unwrap_or_else(|e| panic!("{kind}: a multi-member RAR4 split builds: {e}"))
            .expect("a container was selected");
        assert!(c.volumes.len() > 2, "{kind}: the set is not split");
        let out = extract_set(
            &c.volumes
                .iter()
                .map(|v| v.bytes.clone())
                .collect::<Vec<_>>(),
            None,
        )
        .unwrap_or_else(|e| panic!("{kind}: the posted set reads back: {e}"));
        let names: Vec<_> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["a.bin", "b.bin"], "{kind}");
        for ((_, got), src) in out.iter().zip(s.iter()) {
            assert_eq!(got, &src.bytes, "{kind}");
        }
    }
}

/// A split HEADER-ENCRYPTED RAR4 set that is not stored.
///
/// Refused by name until 4 Sep 2026 on the reading that
/// `write_header_encrypted_split_volumes` is reached only from
/// `write_stored_volumes`. `write_compressed_volumes_impl` reaches
/// it too and always did - the refusal was wrong rather than
/// conservative, and nothing on either side of the vendor line
/// tested the path, which is how it survived. The archive is
/// checked for what it CLAIMS to be, not merely for having been
/// written: the names must not be readable in the volume bytes and
/// the set must refuse to open without the password.
#[test]
fn a_split_header_encrypted_rar4_set_is_not_stored_only() {
    let p = Profile::parse(
        "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{ name = \"a.bin\", bytes = 20000, content = \"compressible\" }, \
         { name = \"b.bin\", bytes = 20000, content = \"compressible\" }]\n\n\
         [container]\nkind = \"rar-compressed\"\nversion = \"rar4\"\n\
         encryption = \"header\"\npassword = \"hdr-pw\"\nvolume_bytes = 700\n",
    )
    .unwrap();
    let mut rng = Rng::for_profile(&p);
    let s = crate::assemble::sources(&p, &mut rng).unwrap();
    let c = wrap(&p, &s, &mut rng)
        .expect("a header-encrypted RAR4 split set builds")
        .expect("a container was selected");
    assert!(c.volumes.len() > 1, "the set is not split");
    let parts: Vec<Vec<u8>> = c.volumes.iter().map(|v| v.bytes.clone()).collect();
    for part in &parts {
        assert!(
            !part.windows(5).any(|w| w == b"a.bin"),
            "a header-encrypted volume leaked a member name"
        );
    }
    assert!(
        extract_set(&parts, None).is_err(),
        "the set opened with no password"
    );
    let out = extract_set(&parts, Some(b"hdr-pw")).expect("the posted set reads back");
    let names: Vec<_> = out.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["a.bin", "b.bin"]);
    for ((_, got), src) in out.iter().zip(s.iter()) {
        assert_eq!(got, &src.bytes);
    }
}

/// ...and behind a nesting level the split level holds exactly one
/// member, whatever `[source]` names.
///
/// This was the pair to a refusal that no longer exists. While the
/// volume writers took a single entry, nesting was the documented
/// escape - "or nest: an inner archive is one member" - and until
/// 3 Sep 2026 the guard counted `[source]` files rather than the
/// split level's members, so it refused the shape its own message
/// recommended (found porting the nested corpus's r2 leg, a split
/// set over one inner archive holding two payload files). The
/// plural writers landed on 4 Sep 2026 and the guard stopped
/// counting, but the FACT is still load-bearing: `wrap` builds a
/// nested stack one member per level and `read_the_set_back`
/// asserts it level by level, so a change that let two members
/// reach an inner level would break the naming contract, not just
/// a writer choice. Asserted here rather than inferred.
#[test]
fn the_same_several_files_behind_a_nesting_level_are_not() {
    let p = Profile::parse(
        "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{ name = \"a.bin\", bytes = 9000 }, { name = \"b.bin\", bytes = 9000 }]\n\n\
         [container]\nkind = \"rar-stored\"\nvolume_bytes = 8000\nnested = 1\n",
    )
    .unwrap();
    let mut rng = Rng::for_profile(&p);
    let s = crate::assemble::sources(&p, &mut rng).unwrap();
    let c = wrap(&p, &s, &mut rng)
        .expect("a nested split set is buildable")
        .expect("a container was selected");
    assert!(
        c.volumes.len() > 1,
        "the set is not split: {:?}",
        c.volumes.iter().map(|v| &v.rel).collect::<Vec<_>>()
    );
    // And the level under the split one is the inner archive alone,
    // which is why the single-entry volume writers were enough.
    let out = extract_set(
        &c.volumes
            .iter()
            .map(|v| v.bytes.clone())
            .collect::<Vec<_>>(),
        None,
    )
    .expect("the posted set reads back");
    assert_eq!(out.len(), 1, "the split level holds more than one member");
    assert_eq!(out[0].0, "a.inner1.rar");
}

// -----------------------------------------------------------------
// C12: the 7z arm (H1)
// -----------------------------------------------------------------

/// C12 + C1: a single stored 7z volume, named for its format, that
/// reads back through the 7z reader rather than the RAR one.
#[test]
fn c12_stored_7z_single_volume() {
    let c = built("kind = \"7z-stored\"\n");
    assert_eq!(c.volumes.len(), 1);
    assert_eq!(c.volumes[0].rel, "movie.7z");
    assert!(c.volumes[0].bytes.starts_with(b"7z\xbc\xaf\x27\x1c"));
    assert_eq!(c.payload[0].0, "movie.bin");
}

/// C12 + C2: a split 7z set is `.7z.001`, `.7z.002`, ... and the
/// parts are the archive cut up - only part one carries a
/// signature, which is the fact the opaque refusal rests on.
#[test]
fn c12_split_7z_is_named_by_part_index() {
    let c = built("kind = \"7z-stored\"\nvolume_bytes = 8000\n");
    assert!(c.volumes.len() >= 3, "got {} volumes", c.volumes.len());
    assert_eq!(c.volumes[0].rel, "movie.7z.001");
    assert_eq!(c.volumes[1].rel, "movie.7z.002");
    assert!(c.volumes[0].bytes.starts_with(b"7z\xbc\xaf\x27\x1c"));
    assert!(!c.volumes[1].bytes.starts_with(b"7z\xbc\xaf\x27\x1c"));
}

/// C12 + C3: the FIRST compressed selection a catalog profile can
/// make, and the archive really declares LZMA2.
///
/// The RAR arm cannot: `[source]` bytes are incompressible and the
/// RAR writers silently store what they cannot shrink, which
/// `a_compressed_selection_the_writer_stored_is_refused` pins. The
/// 7z writer records one content method for the whole archive, so
/// the client has to run the decoder whatever the bytes are - the
/// archive is BIGGER than its payload here, and asserting that is
/// what stops a reader taking the row for a size win.
#[test]
fn c12_compressed_7z_declares_lzma2_over_incompressible_bytes() {
    let c = built("kind = \"7z-compressed\"\n");
    assert_eq!(c.volumes[0].rel, "movie.7z");
    assert!(
        c.volumes[0].bytes.len() > 24_000,
        "the payload compressed to {} bytes from 24000, so `[source]` is no longer \
         incompressible and this row is measuring something else",
        c.volumes[0].bytes.len()
    );
    assert_ne!(
        crate::sevenz::declared_method(&c.volumes[0].bytes, None)
            .expect("the archive parses")
            .as_deref(),
        Some(crate::sevenz::COPY_ID),
        "the writer stored what it could not shrink"
    );
}

/// A SPLIT compressed 7z builds, which the compressed-arm guard
/// refused until 4 Sep 2026 by parsing part one on its own.
///
/// The regression test for that arm's own header. It needs no
/// encryption and no nesting - `kind = "7z-compressed"` with a
/// `volume_bytes` is the whole shape - and it read
/// `RoundTrip("next header offset out of range")`, which is the
/// generator accusing its own writer of emitting an unopenable
/// archive. The set reads back JOINED, because that is what a split
/// 7z is.
#[test]
fn a_split_compressed_7z_is_not_refused_by_the_compressed_guard() {
    let c = built("kind = \"7z-compressed\"\nvolume_bytes = 8000\n");
    assert!(c.volumes.len() > 1, "the set did not split");
    let parts: Vec<Vec<u8>> = c.volumes.iter().map(|v| v.bytes.clone()).collect();
    let out = crate::sevenz::extract_set(&parts, None).expect("the split set reads back");
    assert_eq!(out[0].0, "movie.bin");
    assert_ne!(
        crate::sevenz::declared_method(&parts.concat(), None)
            .expect("the joined set parses")
            .as_deref(),
        Some(crate::sevenz::COPY_ID)
    );
}

/// ...and the same for a split compressed ZIP, whose central
/// directory is at the tail exactly as the 7z end header is.
///
/// The zip arm of that guard landed on 4 Sep 2026 written against
/// the one-volume signature, so it inherited the defect the test
/// above pins in the same afternoon it was written. Both are here
/// because the two formats are cut the same way and a fix to one is
/// not a fix to the other.
#[test]
fn a_split_compressed_zip_is_not_refused_by_the_compressed_guard() {
    let c = built("kind = \"zip-compressed\"\nvolume_bytes = 8000\n");
    assert!(c.volumes.len() > 1, "the set did not split");
    let parts: Vec<Vec<u8>> = c.volumes.iter().map(|v| v.bytes.clone()).collect();
    assert!(
        !crate::zip::declared_methods(&parts.concat())
            .expect("the joined set parses")
            .contains(&crate::zip::STORED)
    );
}

/// C2 + C4 + C12: a split ENCRYPTED 7z set, which is the shape both
/// halves of the guard above have to survive at once - the parts are
/// cut from an archive whose end header may itself be encrypted, so
/// the check needs the whole set AND the level's password.
#[test]
fn a_split_encrypted_7z_set_round_trips() {
    for (kind, enc) in [
        ("7z-stored", "data"),
        ("7z-stored", "header"),
        ("7z-compressed", "header"),
    ] {
        let c = built(&format!(
            "kind = \"{kind}\"\nencryption = \"{enc}\"\npassword = \"split-fixture-pw\"\n\
             volume_bytes = 8000\n"
        ));
        assert!(c.volumes.len() > 1, "{kind}/{enc}: the set did not split");
        let parts: Vec<Vec<u8>> = c.volumes.iter().map(|v| v.bytes.clone()).collect();
        assert_eq!(
            crate::sevenz::extract_set(&parts, Some("split-fixture-pw"))
                .unwrap_or_else(|e| panic!("{kind}/{enc}: {e}"))[0]
                .0,
            "movie.bin"
        );
        assert!(
            crate::sevenz::extract_set(&parts, None).is_err(),
            "{kind}/{enc}: the split set opens with no password"
        );
    }
}

/// C7 + C12: an inner level goes in under a name that says which
/// FORMAT it is as well as which level, so a failed extraction of a
/// mixed stack reads.
#[test]
fn a_nested_7z_names_its_inner_level_7z() {
    let c = built("kind = \"7z-stored\"\nnested = 2\n");
    let out = crate::sevenz::extract_set(&[c.volumes[0].bytes.clone()], None).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, "movie.inner2.7z");
}

/// The single-entry volume-writer gap is RAR's alone: a split 7z
/// set is the finished archive cut, so how many members it holds is
/// a question the split never asks.
///
/// The pair with `a_split_rar4_set_of_several_files_is_a_named_writer_gap`
/// is the point - one refusal, one build, over the same `[source]`
/// list and the same `volume_bytes`. RAR5 stopped refusing it when
/// H0's `Rar50VolumeWriter::stored_entries` landed on 4 Sep 2026;
/// RAR4 still does, and this arm never did.
#[test]
fn a_split_7z_set_of_several_files_is_not_a_writer_gap() {
    let p = Profile::parse(
        "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{ name = \"a.bin\", bytes = 9000 }, { name = \"b.bin\", bytes = 9000 }]\n\n\
         [container]\nkind = \"7z-stored\"\nvolume_bytes = 8000\n",
    )
    .unwrap();
    let mut rng = Rng::for_profile(&p);
    let s = crate::assemble::sources(&p, &mut rng).unwrap();
    let c = wrap(&p, &s, &mut rng)
        .expect("a split 7z over two members is buildable")
        .expect("a container was selected");
    assert!(c.volumes.len() > 1, "the set is not split");
    let parts: Vec<Vec<u8>> = c.volumes.iter().map(|v| v.bytes.clone()).collect();
    let out = crate::sevenz::extract_set(&parts, None).expect("the set reads back");
    assert_eq!(out.len(), 2, "the split level lost a member");
}

/// A key that means nothing in the 7z format is refused by name,
/// with the reason, rather than dropped.
#[test]
fn sevenz_shapes_that_are_rars_are_refused_by_name() {
    for (extra, want) in [
        (
            "kind = \"7z-stored\"\nversion = \"rar4\"\n",
            "names a RAR GENERATION",
        ),
        (
            "kind = \"7z-stored\"\nrecovery_record_pct = 10\n",
            "the 7z format has no",
        ),
        (
            "kind = \"7z-stored\"\nvolume_bytes = 8000\nvolume_style = \"r00\"\n",
            "C11 is the RAR plane",
        ),
        (
            "kind = \"7z-stored\"\nvolume_bytes = 8000\nvolume_names = \"opaque\"\n",
            "a set nothing can reassemble",
        ),
    ] {
        let msg = refusal(extra);
        assert!(msg.contains(want), "{extra:?} was refused as: {msg}");
    }
}

// -----------------------------------------------------------------
// C12: the zip arm (H1's other half)
// -----------------------------------------------------------------

/// C12 + C1: a single stored zip volume, named for its format, that
/// reads back through the zip reader rather than the RAR or 7z one.
#[test]
fn c12_stored_zip_single_volume() {
    let c = built("kind = \"zip-stored\"\n");
    assert_eq!(c.volumes.len(), 1);
    assert_eq!(c.volumes[0].rel, "movie.zip");
    assert!(c.volumes[0].bytes.starts_with(b"PK\x03\x04"));
    assert_eq!(c.payload[0].0, "movie.bin");
}

/// C12 + C2: a byte-split zip set is `.zip.001`, `.zip.002`, ...
/// and the parts are the archive cut up - only part one carries a
/// local-header signature, which is the fact the opaque refusal
/// rests on.
///
/// The spelling is the client's own:
/// `nzbkit::zip::split_part_name` mirrors the 7z `split_7z_part`
/// grammar with `.zip` as the stem, and `nzbkit::zip::Parts` opens
/// the ordered files as one logical byte space - which is why
/// concatenating them here is the same operation the client does.
#[test]
fn c12_split_zip_is_named_by_part_index() {
    let c = built("kind = \"zip-stored\"\nvolume_bytes = 8000\n");
    assert!(c.volumes.len() >= 3, "got {} volumes", c.volumes.len());
    assert_eq!(c.volumes[0].rel, "movie.zip.001");
    assert_eq!(c.volumes[1].rel, "movie.zip.002");
    assert!(c.volumes[0].bytes.starts_with(b"PK\x03\x04"));
    assert!(!c.volumes[1].bytes.starts_with(b"PK\x03\x04"));
}

/// C12 + C3: the zip arm really deflates, over bytes that do not
/// shrink.
///
/// The same property the 7z arm has and the RAR arm does not: the
/// method is recorded per entry and the writer does not fall back
/// to Stored for an entry it could not shrink, so the client has to
/// run the inflate whatever the bytes are. The archive is BIGGER
/// than its payload here, and asserting that is what stops a reader
/// taking the row for a size win.
#[test]
fn c12_compressed_zip_declares_deflate_over_incompressible_bytes() {
    let c = built("kind = \"zip-compressed\"\n");
    assert_eq!(c.volumes[0].rel, "movie.zip");
    assert!(
        c.volumes[0].bytes.len() > 24_000,
        "the payload compressed to {} bytes from 24000, so `[source]` is no longer \
         incompressible and this row is measuring something else",
        c.volumes[0].bytes.len()
    );
    assert!(
        !crate::zip::declared_methods(&c.volumes[0].bytes)
            .expect("the archive parses")
            .contains(&crate::zip::STORED),
        "the writer stored what it could not shrink"
    );
}

/// C9 + C12: a launcher stub in front of a zip builds and reads
/// back, like the other two formats.
///
/// It does NOT rest on the zip reader coping with a prefix, even
/// though that reader does - it derives the archive offset from the
/// central directory, which is the tolerance a real SFX zip needs
/// and the shape `nzbfast_unpack::sfx.rs` answers with
/// `SfxKind::Zip`. `read_the_set_back` steps over the stub by the
/// length this stage wrote, for every format, so what a reader
/// happens to tolerate is not what any C9 row proves. The comment
/// there says why, and the assertion that the EMITTED file presents
/// a stub is `c9_leading_bytes_are_a_launcher_stub`, against the
/// client's own locator.
#[test]
fn c12_a_stubbed_zip_builds_and_reads_back() {
    let c = built("kind = \"zip-stored\"\nleading_bytes = 4096\n");
    assert_eq!(c.volumes[0].rel, "movie.exe");
    assert!(c.volumes[0].bytes.starts_with(b"MZ"));
    assert!(c.volumes[0].bytes.len() > 4096 + 24_000);
}

/// C7 + C12: an inner zip level goes in under a name that says
/// which FORMAT it is as well as which level.
#[test]
fn a_nested_zip_names_its_inner_level_zip() {
    let c = built("kind = \"zip-stored\"\nnested = 2\n");
    let out = crate::zip::extract_set(&[c.volumes[0].bytes.clone()]).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, "movie.inner2.zip");
}

/// The single-entry volume-writer gap is RAR's alone here too: a
/// byte-split zip is the finished archive cut, so how many members
/// it holds is a question the split never asks.
#[test]
fn a_split_zip_set_of_several_files_is_not_a_writer_gap() {
    let p = Profile::parse(
        "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{ name = \"a.bin\", bytes = 9000 }, { name = \"b.bin\", bytes = 9000 }]\n\n\
         [container]\nkind = \"zip-stored\"\nvolume_bytes = 8000\n",
    )
    .unwrap();
    let mut rng = Rng::for_profile(&p);
    let s = crate::assemble::sources(&p, &mut rng).unwrap();
    let c = wrap(&p, &s, &mut rng)
        .expect("a split zip over two members is buildable")
        .expect("a container was selected");
    assert!(c.volumes.len() > 1, "the set is not split");
    let parts: Vec<Vec<u8>> = c.volumes.iter().map(|v| v.bytes.clone()).collect();
    let out = crate::zip::extract_set(&parts).expect("the set reads back");
    assert_eq!(out.len(), 2, "the split level lost a member");
}

/// A key that means nothing in the zip format, or a zip shape this
/// writer does not build, is refused by name with the reason.
///
/// The encryption arm is the one worth reading: zip encrypts two
/// ways and `nzbkit::zip` reads both, so this is a writer gap
/// rather than a format one - and it is a bigger gap than the 7z
/// twin, because the zip crate's AE writer draws its key salt from
/// `getrandom` with no seeded alternative, which is the
/// reproducibility problem `rars::Entropy` solved for RAR.
#[test]
fn zip_shapes_that_are_rars_are_refused_by_name() {
    for (extra, want) in [
        (
            "kind = \"zip-stored\"\nversion = \"rar4\"\n",
            "names a RAR GENERATION",
        ),
        (
            "kind = \"zip-stored\"\nrecovery_record_pct = 10\n",
            "the zip format has no",
        ),
        (
            "kind = \"zip-stored\"\nvolume_bytes = 8000\nvolume_style = \"r00\"\n",
            "C11 is the RAR plane",
        ),
        (
            "kind = \"zip-stored\"\nvolume_bytes = 8000\nvolume_names = \"opaque\"\n",
            "a set nothing can reassemble",
        ),
        (
            "kind = \"zip-stored\"\nencryption = \"data\"\npassword = \"not-a-real-password\"\n",
            "aes-crypto",
        ),
    ] {
        let msg = refusal(extra);
        assert!(msg.contains(want), "{extra:?} was refused as: {msg}");
    }
}

/// The WinZip-spanned spelling is refused by the same arm that
/// refuses C11, and the message names it.
///
/// There is no key that selects spanning, deliberately - a key
/// nobody can select is worse than none - so this asserts that the
/// shape is at least NAMED where an author would look for it, which
/// is the `volume_style` refusal. `crate::zip`'s header carries the
/// long form.
#[test]
fn the_spanned_zip_spelling_is_named_where_an_author_would_look() {
    let msg = refusal("kind = \"zip-stored\"\nvolume_bytes = 8000\nvolume_style = \"r00\"\n");
    assert!(msg.contains(".z01"), "{msg}");
    assert!(msg.contains("spanning marker"), "{msg}");
}

// -----------------------------------------------------------------
// C13: per-level container tables (H2)
// -----------------------------------------------------------------

/// A profile with `[[container.inner]]` tables, for the H2 tests.
fn mixed(inner: &str, outer: &str) -> Contained {
    let p = Profile::parse(&format!(
        "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{{ name = \"movie.bin\", bytes = 24000 }}]\n\n\
         [container]\n{outer}\n{inner}"
    ))
    .expect("the mixed profile parses");
    let mut rng = Rng::for_profile(&p);
    let sources = crate::assemble::sources(&p, &mut rng).expect("sources assemble");
    wrap(&p, &sources, &mut rng)
        .unwrap_or_else(|e| panic!("{outer:?} + {inner:?}: {e}"))
        .expect("a container was selected")
}

/// C13: a two-level stack whose levels are two different FORMATS,
/// which is the nested corpus's r3 shape.
///
/// The assertion that matters is the middle one: the outer archive
/// is opened with the RAR reader and its single member is a 7z,
/// under a name that says so. A stack built with one table for
/// every level could not put those two formats in that order.
#[test]
fn c13_a_mixed_stack_writes_each_level_in_its_own_format() {
    let c = mixed(
        "[[container.inner]]\nkind = \"7z-compressed\"\n",
        "kind = \"rar-stored\"\n",
    );
    assert_eq!(c.volumes[0].rel, "movie.rar");
    let out = extract_set(std::slice::from_ref(&c.volumes[0].bytes), None)
        .expect("the outer RAR reads back");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, "movie.inner1.7z");
    // ...and the inner level really is a compressed 7z, not a
    // RAR wearing the name.
    assert_ne!(
        crate::sevenz::declared_method(&out[0].1, None)
            .expect("the inner level parses as 7z")
            .as_deref(),
        Some(crate::sevenz::COPY_ID)
    );
}

/// C13 at depth 3, alternating formats: RAR over 7z over RAR over
/// the payload, which is the corpus's `x3` chain.
///
/// Peeled by hand here rather than trusted to `read_the_set_back`,
/// because what this asserts is the ORDER, and the round trip
/// inside `wrap` reads the same stack it wrote.
#[test]
fn c13_three_levels_alternate_formats_in_the_order_written() {
    let c = mixed(
        "[[container.inner]]\nkind = \"7z-stored\"\n\n\
         [[container.inner]]\nkind = \"rar-stored\"\n",
        "kind = \"rar-stored\"\n",
    );
    let l2 = extract_set(std::slice::from_ref(&c.volumes[0].bytes), None)
        .expect("the outer RAR reads back");
    assert_eq!(l2[0].0, "movie.inner2.7z");
    let l1 = crate::sevenz::extract_set(std::slice::from_ref(&l2[0].1), None)
        .expect("level 1 reads back as 7z");
    assert_eq!(l1[0].0, "movie.inner1.rar");
    let l0 = extract_set(std::slice::from_ref(&l1[0].1), None).expect("level 0 reads back as RAR");
    assert_eq!(l0[0].0, "movie.bin");
}

/// C10 at ONE level of a stack and not the others, which is the
/// shape a single table cannot state: the corpus's `a1` puts a
/// recovery record at level 3 alone.
#[test]
fn c13_a_recovery_record_can_sit_at_one_level_only() {
    let plain = mixed(
        "[[container.inner]]\nkind = \"rar-stored\"\n",
        "kind = \"rar-stored\"\n",
    );
    let rr = mixed(
        "[[container.inner]]\nkind = \"rar-stored\"\nrecovery_record_pct = 10\n",
        "kind = \"rar-stored\"\n",
    );
    // The OUTER archive is the same shape in both, so the growth is
    // the inner level's record and nothing else.
    assert!(
        rr.volumes[0].bytes.len() > plain.volumes[0].bytes.len(),
        "a 10% record at the inner level added {} bytes",
        rr.volumes[0].bytes.len() as i64 - plain.volumes[0].bytes.len() as i64
    );
}

/// A uniform `nested = N` stack is unchanged by the per-level
/// machinery: same bytes, same names, byte for byte.
///
/// The control for the whole of H2. Every profile written before
/// the inner tables existed goes through `level_stack` now, and a
/// change in what one of them emits would move message-ids under
/// rows that never asked for it.
#[test]
fn a_uniform_stack_is_the_one_table_repeated() {
    for depth in 0..3u32 {
        let uniform = built(&format!("kind = \"rar-stored\"\nnested = {depth}\n"));
        let spelled_out = if depth == 0 {
            uniform.clone()
        } else {
            let inner = "[[container.inner]]\nkind = \"rar-stored\"\n".repeat(depth as usize);
            mixed(&inner, "kind = \"rar-stored\"\n")
        };
        assert_eq!(uniform, spelled_out, "depth {depth}");
    }
}

/// The two spellings of the depth cannot both be written, an inner
/// level has to BE a level, and a stack needs an outermost.
#[test]
fn a_stack_that_says_its_depth_twice_is_refused() {
    for (extra, want) in [
        (
            "kind = \"rar-stored\"\nnested = 2\n\n[[container.inner]]\nkind = \"rar-stored\"\n",
            "the same number said twice",
        ),
        (
            "kind = \"rar-stored\"\n\n[[container.inner]]\nkind = \"none\"\n",
            "which is not a level",
        ),
        (
            "kind = \"none\"\n\n[[container.inner]]\nkind = \"rar-stored\"\n",
            "there is no posted set",
        ),
    ] {
        let text = format!(
            "[layout]\nname = \"t\"\nseed = 1\n\n\
             [source]\nfiles = [{{ name = \"movie.bin\", bytes = 24000 }}]\n\n\
             [container]\n{extra}"
        );
        let msg = match Profile::parse(&text) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("{extra:?} must be refused"),
        };
        assert!(msg.contains(want), "{extra:?} was refused as: {msg}");
    }
}

/// A key that belongs to the POSTED set is refused by name inside
/// an inner table rather than accepted and applied nowhere.
///
/// `deny_unknown_fields` is what does it, and the assertion is here
/// because the alternative - inheriting `volume_bytes` down the
/// stack - is the plausible-looking design this schema declines: an
/// inner level is unsplit by construction, because it is one member
/// of the level above it.
#[test]
fn an_inner_level_may_not_name_the_posted_set_s_keys() {
    let text = "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{ name = \"movie.bin\", bytes = 24000 }]\n\n\
         [container]\nkind = \"rar-stored\"\n\n\
         [[container.inner]]\nkind = \"rar-stored\"\nvolume_bytes = 700\n";
    let msg = match Profile::parse(text) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("volume_bytes in an inner level must be refused"),
    };
    assert!(msg.contains("volume_bytes"), "{msg}");
}

/// A per-level refusal names the LEVEL's shape rather than the
/// posted set's: a header-encrypted rar4 carries no recovery record
/// at any depth.
///
/// The split half of the same question cannot be asked here - only
/// the outermost level is ever split - which is why the two arms
/// live in different functions.
#[test]
fn an_inner_level_shape_no_writer_builds_is_refused_by_name() {
    let text = "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{ name = \"movie.bin\", bytes = 24000 }]\n\n\
         [container]\nkind = \"rar-stored\"\n\n\
         [[container.inner]]\nkind = \"rar-stored\"\nversion = \"rar4\"\n\
         recovery_record_pct = 10\nencryption = \"header\"\npassword = \"inner-pw\"\n";
    let p = Profile::parse(text).expect("it loads; the refusal is the generator's");
    let mut rng = Rng::for_profile(&p);
    let s = crate::assemble::sources(&p, &mut rng).unwrap();
    let msg = wrap(&p, &s, &mut rng).unwrap_err().to_string();
    assert!(msg.contains("header-encrypted rar4"), "{msg}");
}

/// A rar4 recovery record at an INNER level builds, and the record
/// is in the level that asked for it rather than the one above.
#[test]
fn an_inner_level_rar4_recovery_record_builds() {
    let text = "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{ name = \"movie.bin\", bytes = 24000 }]\n\n\
         [container]\nkind = \"rar-stored\"\n\n\
         [[container.inner]]\nkind = \"rar-stored\"\nversion = \"rar4\"\n\
         recovery_record_pct = 10\n";
    let p = Profile::parse(text).expect("parses");
    let mut rng = Rng::for_profile(&p);
    let s = crate::assemble::sources(&p, &mut rng).unwrap();
    let c = wrap(&p, &s, &mut rng).unwrap().expect("a container");
    let inner = extract_set(&[c.volumes[0].bytes.clone()], None).unwrap();
    assert_eq!(inner.len(), 1);
    let raw_bytes = &inner[0].1;
    let archive = rars::ArchiveReader::read(raw_bytes).expect("the inner level parses");
    assert!(
        archive
            .as_rar15_40()
            .expect("a RAR4 inner level")
            .main
            .has_recovery_record()
    );
}

/// The corpus's `r2c` shape - a COMPRESSED RAR inside a stored one -
/// is now statable, and what refuses it is the SOURCE plane rather
/// than the container plane.
///
/// Worth a test of its own because it is the only place the
/// narrowing is visible. Before the per-level tables that shape had
/// no spelling at all; now the profile loads, `wrap` builds the
/// inner level, and the archive comes back with every member
/// stored - so the refusal is `NothingToCompress`, whose message
/// names `[source]`'s incompressible bytes and the key that would
/// unblock it. There is no catalog row, because a row over a
/// refusal is not a row; this is the record instead.
///
/// Substituting `7z-compressed` for the inner level would BUILD,
/// and would be a different leg wearing r2c's name: the corpus's
/// r2c is RAR inside RAR and the whole question is whether the RAR
/// decompressor runs.
#[test]
fn the_compressed_inner_level_is_statable_and_refused_by_the_source_plane() {
    let p = Profile::parse(
        "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{ name = \"movie.bin\", bytes = 24000 }]\n\n\
         [container]\nkind = \"rar-stored\"\nvolume_bytes = 10000\n\n\
         [[container.inner]]\nkind = \"rar-compressed\"\n",
    )
    .expect("the shape is statable since the per-level tables landed");
    let mut rng = Rng::for_profile(&p);
    let s = crate::assemble::sources(&p, &mut rng).unwrap();
    let msg = wrap(&p, &s, &mut rng)
        .expect_err("the RAR writer stores what it cannot shrink")
        .to_string();
    assert!(msg.contains("is STORED"), "{msg}");
    assert!(msg.contains("SOURCE plane"), "{msg}");
}

// -----------------------------------------------------------------
// C14: sibling files inside a level (H3)
// -----------------------------------------------------------------

/// C14: a sibling at every level of a stack comes back out, and the
/// archive below it is still the level's FIRST member.
///
/// The corpus's x1 and x2 ladders in miniature. The order matters
/// as much as the presence: a client that stopped denesting the
/// moment a level held something besides an archive would pass a
/// sibling-free ladder and fail both legs, and putting the sibling
/// first would make this fixture agree with such a client.
#[test]
fn c14_a_sibling_at_every_level_comes_back_out() {
    let c = mixed(
        "[[container.inner]]\nkind = \"rar-stored\"\n\
         siblings = [{ name = \"level1.txt\", bytes = 90 }]\n",
        "kind = \"rar-stored\"\nsiblings = [{ name = \"level2.txt\", bytes = 80 }]\n",
    );
    let out = extract_set(std::slice::from_ref(&c.volumes[0].bytes), None).unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].0, "movie.inner1.rar");
    assert_eq!(out[1].0, "level2.txt");
    let inner = extract_set(std::slice::from_ref(&out[0].1), None).unwrap();
    assert_eq!(inner.len(), 2);
    assert_eq!(inner[0].0, "movie.bin");
    assert_eq!(inner[1].0, "level1.txt");
    // And the whole end state is the payload FIRST, then every
    // level's siblings - the order `crate::layout` projects the
    // payload names off.
    let names: Vec<&str> = c.payload.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["movie.bin", "level1.txt", "level2.txt"]);
}

/// A sibling's bytes come off a stream of the container plane's own,
/// so adding one moves no payload name and no message-id.
///
/// Measured as an equality between the volumes of a sibling-free
/// stack and the FIRST member of the same stack with a sibling
/// added at the outer level: not reachable directly, since the
/// archive bytes differ by the added member, so the assertion is
/// on the payload that comes out and on the volume NAME, which is
/// the thing a message-id is derived from.
#[test]
fn a_sibling_draws_from_the_container_plane_s_own_stream() {
    let plain = mixed(
        "[[container.inner]]\nkind = \"rar-stored\"\n",
        "kind = \"rar-stored\"\nvolume_bytes = 10000\nvolume_names = \"opaque\"\n",
    );
    let with_sibling = mixed(
        "[[container.inner]]\nkind = \"rar-stored\"\n",
        "kind = \"rar-stored\"\nvolume_bytes = 10000\nvolume_names = \"opaque\"\n\
         siblings = [{ name = \"notes.txt\", bytes = 90 }]\n",
    );
    assert_eq!(
        plain.volumes.iter().map(|v| &v.rel).collect::<Vec<_>>(),
        with_sibling
            .volumes
            .iter()
            .map(|v| &v.rel)
            .collect::<Vec<_>>(),
        "adding a sibling moved the opaque volume tokens"
    );
}

/// Two runs of a stack with siblings produce one container.
#[test]
fn a_stack_with_siblings_is_byte_identical_between_runs() {
    let one = || {
        mixed(
            "[[container.inner]]\nkind = \"rar-stored\"\n\
             siblings = [{ name = \"level1.txt\", bytes = 90 }]\n",
            "kind = \"rar-stored\"\nsiblings = [{ name = \"level2.txt\", bytes = 80 }]\n",
        )
    };
    assert_eq!(one(), one());
}

/// A `nested = N` stack puts its siblings at the OUTERMOST level
/// only, which is the whole reason a ladder needs an inner table
/// per level: one list repeated down a stack would put one NAME at
/// every depth, and every level extracts into one directory.
#[test]
fn a_uniform_stack_carries_its_siblings_at_the_top_only() {
    let c = built(
        "kind = \"rar-stored\"\nnested = 2\nsiblings = [{ name = \"notes.txt\", bytes = 90 }]\n",
    );
    let l2 = extract_set(std::slice::from_ref(&c.volumes[0].bytes), None).unwrap();
    assert_eq!(
        l2.len(),
        2,
        "the outermost level holds the archive and the sibling"
    );
    let l1 = extract_set(std::slice::from_ref(&l2[0].1), None).unwrap();
    assert_eq!(
        l1.len(),
        1,
        "an inner level of a uniform stack carries none"
    );
    assert_eq!(c.payload.len(), 2, "one payload file and one sibling");
}

/// A sibling nothing would carry, one with no bytes, and two files
/// that would land under one name are each refused by name.
#[test]
fn siblings_that_could_not_land_are_refused() {
    for (extra, want) in [
        (
            "kind = \"none\"\nsiblings = [{ name = \"notes.txt\", bytes = 90 }]\n",
            "no container to carry it",
        ),
        (
            "kind = \"rar-stored\"\nsiblings = [{ name = \"notes.txt\", bytes = 0 }]\n",
            "bytes = 0",
        ),
        (
            "kind = \"rar-stored\"\nsiblings = [{ name = \"movie.bin\", bytes = 90 }]\n",
            "would land under",
        ),
        (
            "kind = \"rar-stored\"\nsiblings = [{ name = \"a.txt\", bytes = 90 }]\n\n\
             [[container.inner]]\nkind = \"rar-stored\"\n\
             siblings = [{ name = \"a.txt\", bytes = 90 }]\n",
            "would land under",
        ),
    ] {
        let text = format!(
            "[layout]\nname = \"t\"\nseed = 1\n\n\
             [source]\nfiles = [{{ name = \"movie.bin\", bytes = 24000 }}]\n\n\
             [container]\n{extra}"
        );
        let msg = match Profile::parse(&text) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("{extra:?} must be refused"),
        };
        assert!(msg.contains(want), "{extra:?} was refused as: {msg}");
    }
}

// -----------------------------------------------------------------
// C15 and F8 at a level: an inner set, and damage after it (H4, H5)
// -----------------------------------------------------------------

/// A profile with per-level tables, a `[fault]` table and a payload
/// long enough for a damage span, for the H4/H5 tests.
fn levelled(tables: &str) -> Contained {
    let p = Profile::parse(&format!(
        "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{{ name = \"movie.bin\", bytes = 24000 }}]\n\n{tables}"
    ))
    .expect("the levelled profile parses");
    let mut rng = Rng::for_profile(&p);
    let sources = crate::assemble::sources(&p, &mut rng).expect("sources assemble");
    wrap(&p, &sources, &mut rng)
        .unwrap_or_else(|e| panic!("{tables:?}: {e}"))
        .expect("a container was selected")
}

/// C15: a level's own PAR2 set rides in the level ABOVE it, beside
/// the archive it covers, and nothing in the post announces it.
#[test]
fn c15_a_level_packs_its_own_recovery_set_into_the_level_above() {
    let c = levelled(
        "[container]\nkind = \"rar-stored\"\n\n\
         [[container.inner]]\nkind = \"rar-stored\"\nrecovery_pct = 30\n",
    );
    let out = extract_set(std::slice::from_ref(&c.volumes[0].bytes), None)
        .expect("the outer archive reads back");
    let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names[0], "movie.inner1.rar", "the archive is not first");
    assert!(names.len() > 1, "the level packed no set: {names:?}");
    for n in &names[1..] {
        assert!(
            n.starts_with("movie.inner1.rar") && n.ends_with(".par2"),
            "{n} is not part of the set over the archive beside it"
        );
    }
    // And the set is NOT in the end state: it is recovery data the
    // client spends repairing the archive it covers, exactly as the
    // posted parity volumes are. Measured on the first `nc-r4` run.
    let landed: Vec<&str> = c.payload.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(landed, ["movie.bin"]);
}

/// The furniture on the first volume rides the copy that goes on the
/// WIRE, not only the clean copy the round trip reads.
///
/// The container plane keeps two copies of the set once a nesting
/// level is damaged (H5), and `wrap` posts the damaged one. The C9
/// stub was applied to the clean copy alone until 4 Sep 2026, so a
/// row selecting both would have posted a set with no launcher stub
/// on it while its profile said it had one, and no `[expect]` could
/// have seen the difference: the stub is not in an end state. No
/// catalog row selected both, which is why nothing was red.
///
/// Found while adding C8's second archive to the same three lines.
#[test]
fn the_first_volumes_furniture_rides_the_damaged_copy_too() {
    let c = levelled(
        "[container]\nkind = \"rar-stored\"\nleading_bytes = 4096\npolyglot = \"7z\"\n\n\
         [[container.inner]]\nkind = \"rar-stored\"\n\n\
         [[fault.corrupt_payload]]\ninner_level = 0\nat = 8000\nbytes = 64\n",
    );
    let posted = &c.volumes[0].bytes;
    assert!(
        nzbkit::sfx::is_launcher_stub(posted),
        "the posted volume carries no launcher stub"
    );
    assert_eq!(
        nzbkit::sfx::sfx_payload_at(posted).map(|(off, _)| off),
        Some(4096),
        "the posted volume's archive is not where the stub says it is"
    );
    let tail = polyglot_tail(Polyglot::SevenZ).expect("the second archive writes");
    assert!(
        posted.ends_with(&tail),
        "the posted volume carries no second archive"
    );
    // ...and it really is the damaged copy, which is what makes the
    // assertions above about the posted set rather than a copy of
    // the clean one that happens to be dressed.
    let clean = levelled(
        "[container]\nkind = \"rar-stored\"\nleading_bytes = 4096\npolyglot = \"7z\"\n\n\
         [[container.inner]]\nkind = \"rar-stored\"\n",
    );
    assert_ne!(
        posted, &clean.volumes[0].bytes,
        "the posted volume is the undamaged one"
    );
}

/// F8 at a level: the archive that goes on the WIRE is damaged, and
/// the set packed beside it was cut over the clean bytes.
///
/// The control for `nc-r4`. Without it the row would pass over an
/// undamaged post - the client would unpack twice and land the
/// payload having repaired nothing, and the oracle could not tell
/// the two apart from the output tree alone.
#[test]
fn f8_at_a_level_damages_the_archive_the_wire_carries() {
    let tables = "[container]\nkind = \"rar-stored\"\n\n\
         [[container.inner]]\nkind = \"rar-stored\"\nrecovery_pct = 30\n\n\
         [[fault.corrupt_payload]]\ninner_level = 0\nat = 8000\nbytes = 64\n";
    let damaged = levelled(tables);
    let clean = levelled(
        "[container]\nkind = \"rar-stored\"\n\n\
         [[container.inner]]\nkind = \"rar-stored\"\nrecovery_pct = 30\n",
    );
    let take = |c: &Contained| {
        extract_set(std::slice::from_ref(&c.volumes[0].bytes), None)
            .expect("the outer archive reads back")
    };
    let (d, k) = (take(&damaged), take(&clean));
    assert_ne!(d[0].1, k[0].1, "the inner archive was not damaged");
    assert_eq!(d[0].1.len(), k[0].1.len(), "the damage changed the length");
    // The set beside it is BYTE-IDENTICAL to the clean row's,
    // because it was cut before the damage was written. A set cut
    // afterwards would describe the damage and ask for no repair,
    // which is the ordering this plane exists to get right.
    assert_eq!(
        d[1..].to_vec(),
        k[1..].to_vec(),
        "the packed set differs, so it was cut over the damaged bytes"
    );
    // And the damaged archive does not give the payload back, which
    // is what makes the repair load-bearing.
    let clean_payload = extract_set(std::slice::from_ref(&k[0].1), None)
        .expect("the clean inner archive reads back");
    let damaged_payload = extract_set(std::slice::from_ref(&d[0].1), None);
    assert!(
        damaged_payload.as_ref().is_err()
            || damaged_payload.as_ref().is_ok_and(|p| p != &clean_payload),
        "the damaged archive still yields the payload the clean one does"
    );
}

/// A levelled damage that does not fit the archive is refused by
/// name, with the length the writer actually produced.
///
/// The schema cannot check this half and says so: how long a level's
/// archive is is the WRITER's answer, not the profile's, which is
/// the same reason F3 cannot name a volume.
#[test]
fn a_levelled_damage_off_the_archive_is_refused_with_the_measured_length() {
    let p = Profile::parse(
        "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{ name = \"movie.bin\", bytes = 4096 }]\n\n\
         [container]\nkind = \"rar-stored\"\n\n\
         [[container.inner]]\nkind = \"rar-stored\"\n\n\
         [[fault.corrupt_payload]]\ninner_level = 0\nat = 900000\nbytes = 64\n",
    )
    .expect("the schema cannot check a length only the writer knows");
    let mut rng = Rng::for_profile(&p);
    let s = crate::assemble::sources(&p, &mut rng).unwrap();
    let msg = wrap(&p, &s, &mut rng).unwrap_err().to_string();
    assert!(msg.contains("falls off the end"), "{msg}");
    assert!(msg.contains("[[container.inner]] 0"), "{msg}");
}

/// A damage entry that names both a file and a level, or neither,
/// and one pointing at a level the stack does not have.
#[test]
fn a_damage_entry_that_names_no_one_thing_is_refused() {
    for (tables, want) in [
        (
            "[container]\nkind = \"rar-stored\"\n\n\
             [[container.inner]]\nkind = \"rar-stored\"\n\n\
             [[fault.corrupt_payload]]\nfile = \"movie.bin\"\ninner_level = 0\n\
             at = 10\nbytes = 4\n",
            "or neither",
        ),
        (
            "[container]\nkind = \"rar-stored\"\n\n\
             [[fault.corrupt_payload]]\nat = 10\nbytes = 4\n",
            "or neither",
        ),
        (
            "[container]\nkind = \"rar-stored\"\n\n\
             [[container.inner]]\nkind = \"rar-stored\"\n\n\
             [[fault.corrupt_payload]]\ninner_level = 3\nat = 10\nbytes = 4\n",
            "1 [[container.inner]] table(s)",
        ),
    ] {
        let text = format!(
            "[layout]\nname = \"t\"\nseed = 1\n\n\
             [source]\nfiles = [{{ name = \"movie.bin\", bytes = 24000 }}]\n\n{tables}"
        );
        let msg = match Profile::parse(&text) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("{tables:?} must be refused"),
        };
        assert!(msg.contains(want), "{tables:?} was refused as: {msg}");
    }
}

/// A stack that damages nothing is written ONCE: the clean/wire
/// fork stays closed, so no undamaged row pays a second write of
/// every level.
///
/// Asserted through the only door a test has onto it - two runs of
/// an undamaged levelled profile are byte-identical, and a damaged
/// one differs from the clean one only in the archive bytes, which
/// the F8 test above pins. Written down because the fork is the one
/// place this plane costs anything.
#[test]
fn an_undamaged_stack_is_byte_identical_between_runs() {
    let one = || {
        levelled(
            "[container]\nkind = \"rar-stored\"\nvolume_bytes = 12000\n\n\
             [[container.inner]]\nkind = \"rar-stored\"\nrecovery_pct = 30\n",
        )
    };
    assert_eq!(one(), one());
    let dmg = || {
        levelled(
            "[container]\nkind = \"rar-stored\"\nvolume_bytes = 12000\n\n\
             [[container.inner]]\nkind = \"rar-stored\"\nrecovery_pct = 30\n\n\
             [[fault.corrupt_payload]]\ninner_level = 0\nat = 8000\nbytes = 64\n",
        )
    };
    assert_eq!(dmg(), dmg());
}

/// Damage at a level TWO or more deep survives every level built
/// over it.
///
/// The pin for a defect this lane shipped for one run and the
/// oracle could not see. The clean/wire fork opens at the first
/// damaged level and each level above it has to be written from the
/// WIRE members; the first spelling wrote the level above from a
/// clean copy, so the damage below was silently thrown away and
/// `nc-a1` went green over a post that carried none of it. The
/// payload lands either way - which is exactly what an absent fault
/// looks like from the output tree - so nothing downstream could
/// have caught it.
///
/// Asserted at the archive rather than at the end state, for that
/// reason: peel the posted set one level and compare the archive
/// that comes out against the same profile with no `[fault]` table.
#[test]
fn deeper_damage_survives_the_levels_above_it() {
    let stack = "[container]\nkind = \"rar-stored\"\n\n\
         [[container.inner]]\nkind = \"rar-stored\"\n\n\
         [[container.inner]]\nkind = \"rar-stored\"\n";
    let clean = levelled(stack);
    // inner_level = 1 is the DEEPEST table, two levels under the
    // posted archive, so its damage has to cross one whole level.
    let damaged = levelled(&format!(
        "{stack}\n[[fault.corrupt_payload]]\ninner_level = 1\nat = 9000\nbytes = 64\n"
    ));
    assert_ne!(
        damaged.volumes[0].bytes, clean.volumes[0].bytes,
        "the posted archive is identical, so no damage reached the wire at all"
    );
    let peel = |c: &Contained| {
        extract_set(std::slice::from_ref(&c.volumes[0].bytes), None)
            .expect("the posted archive reads back")
    };
    let (d, k) = (peel(&damaged), peel(&clean));
    assert_eq!(d[0].0, k[0].0, "the peeled level changed name");
    assert_ne!(
        d[0].1, k[0].1,
        "the middle level is identical, so the damage below it was thrown away when this \
         level was written"
    );
    // And the expectation is untouched: the SOURCE bytes are still
    // what has to land, whatever the post carries.
    assert_eq!(damaged.payload, clean.payload);
}

/// Two runs of one profile produce one container, bytes and names
/// alike - including the opaque names, which are the only thing
/// here that draws from the seed.
#[test]
fn wrapping_twice_is_byte_identical() {
    for extra in [
        "kind = \"rar-stored\"\n",
        "kind = \"rar-stored\"\nvolume_bytes = 8000\nvolume_names = \"opaque\"\n",
        // Both 7z arms too: nothing in that writer may reach a
        // clock or the OS entropy either.
        "kind = \"7z-stored\"\n",
        "kind = \"7z-stored\"\nvolume_bytes = 8000\n",
        "kind = \"7z-compressed\"\n",
        // C8 on both orderings: the second archive is written by
        // the same two libraries and must reach no clock either.
        "kind = \"rar-stored\"\nleading_bytes = 4096\npolyglot = \"7z\"\n",
        "kind = \"7z-stored\"\nleading_bytes = 4096\npolyglot = \"rar\"\n",
    ] {
        assert_eq!(built(extra), built(extra), "{extra}");
    }
}

/// The tree rides IN the archive, which is the first plane that
/// carries one at all.
#[test]
fn a_directory_is_carried_by_the_archive() {
    let p = Profile::parse(
        "[layout]\nname = \"t\"\nseed = 1\n\n\
         [source]\nfiles = [{ name = \"sample/s.bin\", bytes = 4096 }]\n\n\
         [container]\nkind = \"rar-stored\"\n",
    )
    .unwrap();
    let mut rng = Rng::for_profile(&p);
    let s = crate::assemble::sources(&p, &mut rng).unwrap();
    let c = wrap(&p, &s, &mut rng).unwrap().unwrap();
    assert_eq!(c.payload[0].0, "sample/s.bin");
    let out = extract_set(&[c.volumes[0].bytes.clone()], None).unwrap();
    assert_eq!(out[0].0, "sample/s.bin");
}

/// The round-trip check is not decorative: an archive whose bytes
/// have been damaged does not read back, and the error says the
/// defect is the writer's rather than the client's.
#[test]
fn a_damaged_archive_fails_the_round_trip_loudly() {
    let c = built("kind = \"rar-stored\"\n");
    let mut damaged = c.volumes[0].bytes.clone();
    let at = damaged.len() / 2;
    damaged[at] ^= 0xff;
    let err = extract_set(&[damaged], None).unwrap_err();
    assert!(!err.is_empty());
    // And the message a profile would actually see names the class.
    let wrapped = ContainerError::RoundTrip(err).to_string();
    assert!(wrapped.contains("WRITER defect"), "{wrapped}");
}
