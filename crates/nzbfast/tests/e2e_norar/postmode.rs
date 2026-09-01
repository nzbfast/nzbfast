//! The PRODUCER half of the no-RAR shape: `nzbfast post --obfuscate
//! --par2` puts it on the wire, and the real `get` path takes it back
//! off byte-exact under the real names.
//!
//! Every other row in this family builds its articles by hand, which
//! proves what the DOWNLOAD side sweeps and nothing about what we would
//! emit. These post for real - through `post::post_files` to a mock
//! NNTP server that stores what it is given - so the assertion is
//! end-to-end over our own two halves: nothing in the fixture writes a
//! yEnc header, an NZB, or a PAR2 packet.
//!
//! Why it matters that this is a round trip and not two unit tests: the
//! obfuscated shape's whole claim is that the real names survive OUT OF
//! BAND while nothing on the wire carries them. A test of the poster
//! alone cannot see a name that fails to survive, and a test of the
//! reader alone is handed names the fixture chose. Only the pair can
//! fail the way the format can.
//!
//! `have_par2()` is deliberately NOT here: the recovery set is built by
//! `nzbkit::par2gen`, in process, with no external binary. That is the
//! same reason a 0-byte member can be described at all (par2cmdline
//! prints "Skipping 0 byte file" and omits it - matrix finding F3).
//! par2cmdline's own reading of what we write is pinned separately, in
//! `crates/nzbkit/tests/integration/par2gen_interop.rs`, where the
//! guard does belong.

use super::*;
use nzbkit::post::{self, Obfuscation, PlanOpts, PostOpts, YencName};

/// Post `dir`'s contents through a fresh mock server and return
/// (mock, emitted NZB path). Obfuscation and PAR2 are the caller's.
async fn post_through_mock(
    fx: &Fixture,
    paths: &[PathBuf],
    plan_opts: &PlanOpts,
    par2: Option<u32>,
) -> (MockServer, PathBuf) {
    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;
    let mut plan = post::plan_with(paths, 20_000, plan_opts).expect("plan");

    if let Some(pct) = par2 {
        let members: Vec<nzbkit::par2gen::Member> = plan
            .iter()
            .map(|f| nzbkit::par2gen::Member {
                name: f.rel.clone(),
                path: f.path.clone(),
            })
            .collect();
        let scratch = fx.dir.join("par2out");
        std::fs::create_dir_all(&scratch).unwrap();
        let names = nzbkit::par2gen::create_into(
            &scratch,
            &members,
            "recovery",
            &nzbkit::par2gen::Par2Spec {
                redundancy_pct: pct,
                block_size: Some(4096),
            },
        )
        .expect("build the recovery set");
        let par2_paths: Vec<PathBuf> = names.iter().map(|n| scratch.join(n)).collect();
        // Announced, not obfuscated: a recovery set nobody can find
        // carries its names to nobody.
        plan.extend(post::plan_with(&par2_paths, 20_000, &PlanOpts::default()).expect("plan par2"));
    }

    let opts = PostOpts {
        group: "mock.group".into(),
        from: "corpus@nzbfast.invalid".into(),
        msgid_domain: "corpus.example".into(),
        article_size: 20_000,
        title: None,
        connections: 2,
        obfuscate: plan_opts.obfuscate,
    };
    let set = post::post_files(&srv.server_config(), &plan, &opts, None)
        .await
        .expect("post to the mock");
    let nzb = fx.dir.join("posted.nzb");
    std::fs::write(&nzb, post::emit_nzb(&set)).unwrap();
    (srv, nzb)
}

/// Run the real `get` binary over an already-written NZB.
async fn get_posted(fx: &Fixture, srv: &MockServer, nzb: &Path) -> (String, bool, PathBuf) {
    let cfg = fx.write_config(&[srv]);
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.to_path_buf(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    (log, ok, out)
}

/// Nothing anywhere on the wire may spell a real name: not a subject,
/// not a yEnc header, not the NZB. Asserted over the ARTICLES the mock
/// actually holds plus the NZB we published, because those two together
/// are the whole of what a scraper without the NZB, and an indexer with
/// it, can each see.
fn assert_names_are_off_the_wire(nzb: &Path, srv: &MockServer, real: &[&str]) {
    let xml = std::fs::read_to_string(nzb).unwrap();
    let bodies = srv.stored_articles();
    for name in real {
        assert!(
            !xml.contains(name),
            "the NZB spells the real name {name:?} - obfuscation buys nothing"
        );
        for (id, body) in &bodies {
            let text = String::from_utf8_lossy(body);
            // The yEnc header is the first line; the payload past it is
            // +42 of the source and may hold anything by coincidence.
            let header = text.lines().next().unwrap_or_default();
            assert!(
                !header.contains(name),
                "article {id} carries the real name {name:?} in its yEnc header: {header}"
            );
        }
    }
}

/// The headline row: post a directory tree plus a 0-byte placeholder,
/// entirely obfuscated, with a real recovery set carrying the names -
/// and get every byte back under the real name, in the real directory.
#[tokio::test(flavor = "multi_thread")]
async fn an_obfuscated_post_with_a_par2_set_round_trips_under_the_real_names() {
    let fx = Fixture::new("postnorar");
    let src = fx.dir.join("src");
    let episode = payload(90_000, 21);
    let vob = payload(45_000, 33);
    std::fs::create_dir_all(src.join("VIDEO_TS")).unwrap();
    std::fs::write(src.join("Show.S01E01.1080p.mkv"), &episode).unwrap();
    std::fs::write(src.join("VIDEO_TS/VTS_01_1.VOB"), &vob).unwrap();
    // The shape par2cmdline cannot describe at all (matrix F3), and the
    // one the Reddit thread names as a client hole.
    std::fs::write(src.join("VIDEO_TS/VIDEO_TS.BUP"), b"").unwrap();

    let (srv, nzb) = post_through_mock(
        &fx,
        std::slice::from_ref(&src),
        &PlanOpts {
            allow_empty: true,
            obfuscate: Some(Obfuscation {
                yenc_name: YencName::Random,
            }),
        },
        Some(20),
    )
    .await;

    assert_names_are_off_the_wire(
        &nzb,
        &srv,
        &["Show.S01E01.1080p.mkv", "VTS_01_1.VOB", "VIDEO_TS.BUP"],
    );

    let (log, ok, out) = get_posted(&fx, &srv, &nzb).await;
    assert!(ok, "the obfuscated post did not download:\n{log}");
    assert_eq!(
        std::fs::read(out.join("src/Show.S01E01.1080p.mkv")).unwrap_or_default(),
        episode,
        "the episode did not land byte-exact under its FileDesc name:\n{log}"
    );
    assert_eq!(
        std::fs::read(out.join("src/VIDEO_TS/VTS_01_1.VOB")).unwrap_or_default(),
        vob,
        "the tree member did not land in its own directory:\n{log}"
    );
    assert!(
        out.join("src/VIDEO_TS/VIDEO_TS.BUP").exists(),
        "the 0-byte placeholder was not materialized:\n{log}"
    );
}

/// The other admitted yEnc shape: `name=` with nothing after it. A
/// client that trusts the yEnc header blindly has nothing to trust, so
/// the recovery set is the only naming evidence there is.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_yenc_name_still_lands_under_the_filedesc_name() {
    let fx = Fixture::new("postnorarempty");
    let src = fx.dir.join("src");
    let data = payload(70_000, 44);
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("Feature.2024.mkv"), &data).unwrap();

    let (srv, nzb) = post_through_mock(
        &fx,
        std::slice::from_ref(&src),
        &PlanOpts {
            allow_empty: false,
            obfuscate: Some(Obfuscation {
                yenc_name: YencName::Empty,
            }),
        },
        Some(0), // manifest-only: names and block checksums, no parity
    )
    .await;

    // The yEnc headers of the PAYLOAD articles must carry an empty
    // name, while the announced recovery set keeps its own.
    let bodies = srv.stored_articles();
    let empties = bodies
        .values()
        .filter(|b| {
            String::from_utf8_lossy(b)
                .lines()
                .next()
                .unwrap_or_default()
                .ends_with("name=")
        })
        .count();
    assert!(
        empties >= 4,
        "expected the payload articles to carry an empty yEnc name, found {empties} of {}",
        bodies.len()
    );
    assert_names_are_off_the_wire(&nzb, &srv, &["Feature.2024.mkv"]);

    let (log, ok, out) = get_posted(&fx, &srv, &nzb).await;
    assert!(ok, "the empty-name post did not download:\n{log}");
    assert_eq!(
        std::fs::read(out.join("src/Feature.2024.mkv")).unwrap_or_default(),
        data,
        "an empty yEnc name lost the FileDesc naming:\n{log}"
    );
}

/// An ordinary post is unchanged by any of this: real names on the
/// wire, no recovery set, exactly what it emitted before the mode
/// existed. The regression the obfuscation work could plausibly cause.
#[tokio::test(flavor = "multi_thread")]
async fn a_plain_post_still_carries_its_real_names() {
    let fx = Fixture::new("postplain");
    let src = fx.dir.join("src");
    let data = payload(50_000, 8);
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("Plain.Name.bin"), &data).unwrap();

    let (srv, nzb) =
        post_through_mock(&fx, std::slice::from_ref(&src), &PlanOpts::default(), None).await;
    let xml = std::fs::read_to_string(&nzb).unwrap();
    assert!(
        xml.contains("Plain.Name.bin"),
        "a plain post must still name its files in the NZB:\n{xml}"
    );

    let (log, ok, out) = get_posted(&fx, &srv, &nzb).await;
    assert!(ok, "the plain post did not download:\n{log}");
    assert_eq!(
        std::fs::read(out.join("Plain.Name.bin")).unwrap_or_default(),
        data,
        "{log}"
    );
}

/// A title spells the release name into every subject, which is the
/// linkage obfuscation removes - taking both would quietly deliver
/// neither, so it is refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_title_and_obfuscation_together_are_refused() {
    let fx = Fixture::new("postnorartitle");
    let src = fx.dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.bin"), payload(2_000, 1)).unwrap();
    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;
    let obf = Some(Obfuscation {
        yenc_name: YencName::Random,
    });
    let plan = post::plan_with(
        std::slice::from_ref(&src),
        20_000,
        &PlanOpts {
            allow_empty: false,
            obfuscate: obf,
        },
    )
    .expect("plan");
    let opts = PostOpts {
        group: "mock.group".into(),
        from: "corpus@nzbfast.invalid".into(),
        msgid_domain: "corpus.example".into(),
        article_size: 20_000,
        title: Some("Some.Release.Name".into()),
        connections: 1,
        obfuscate: obf,
    };
    let err = post::post_files(&srv.server_config(), &plan, &opts, None)
        .await
        .expect_err("a titled obfuscated post must be refused");
    assert!(
        format!("{err}").contains("choose one"),
        "wrong refusal: {err}"
    );
}
