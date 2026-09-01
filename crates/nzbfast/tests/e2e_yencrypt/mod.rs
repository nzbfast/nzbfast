//! yEnc encryption, BOTH Tensai75 yenc-encryption-standards drafts at
//! v0.3, through the REAL get path: our own encoder halves
//! (`nzbkit::mock::make_file_articles_encrypted` for the body standard,
//! `nzbkit::yencrypt::control_encrypt_block` for the control-lines
//! standard - the drafts have no reference implementation anywhere, so
//! there is nothing else to post) serve encrypted articles off the
//! in-process mock NNTP server, and the engine under
//! `NZBFAST_YENC_CRYPT=1` decrypts as each article arrives: control
//! lines restored pre-parse, body segments in place between decode and
//! verify - the decrypt-while-assembling shape the drafts exist for,
//! with no RAR pass and no post-download decrypt step.
//!
//! Conventions the draft leaves open are declared in
//! `nzbkit::yencrypt`'s header and argued in
//! research/YENC-ENCRYPTION-DESIGN-2026-08-31.md; these tests are also
//! the measurements that memo cites (the flag-off case IS the
//! "unaware client" compatibility answer, and the repair case IS the
//! plaintext-PAR2 composition answer).

use super::*;

/// Session-constant test material. The salt would be random per upload
/// in a real poster; fixtures pin it so the derived key is cacheable
/// across helper calls (Argon2id at 64 MiB is ~25 ms per derive).
const PW: &str = "spike-pass-1";
const SALT: [u8; 16] = *b"e2e-session-salt";

fn session_key() -> [u8; 32] {
    nzbkit::yencrypt::derive_key(PW, &SALT)
}

/// Post one encrypted file: plaintext written to the fixture dir (so
/// `add_par2` covers the PLAINTEXT domain - the composition under
/// test), articles encrypted per segment from `seg_base`. Returns the
/// segment count so the caller can keep the session-wide segmentIndex
/// continuous across files, exactly as the draft requires.
fn add_file_encrypted(
    fx: &mut Fixture,
    name: &str,
    data: &[u8],
    art_size: usize,
    key: &[u8; 32],
    seg_base: u32,
) -> u32 {
    std::fs::write(fx.dir.join(name), data).unwrap();
    let tag = format!("{}-{}", name.replace('.', "_"), fx.nzb_files.len());
    let segs = nzbkit::mock::make_file_articles_encrypted(
        name,
        data,
        art_size,
        &tag,
        key,
        &SALT,
        seg_base,
        &mut fx.articles,
    );
    let n = segs.len() as u32;
    fx.nzb_files.push((name.to_string(), segs));
    n
}

/// The draft's NZB shape: every subject carries the `[n/total]` file
/// number its Section 8 REQUIRES (that is what makes the continuous
/// segmentIndex recoverable), and the password rides
/// `<meta type="password">` - the channel `nzbkit::nzb` already parses.
fn write_nzb_numbered(fx: &Fixture, password: Option<&str>) -> std::path::PathBuf {
    let total = fx.nzb_files.len();
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    if let Some(pw) = password {
        xml.push_str(&format!(
            "  <head><meta type=\"password\">{pw}</meta></head>\n"
        ));
    }
    for (i, (name, segs)) in fx.nzb_files.iter().enumerate() {
        xml.push_str(&format!(
            "  <file poster=\"e2e@test\" date=\"0\" subject=\"[{}/{total}] &quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>mock.group</group></groups>\n    <segments>\n",
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
    let path = fx.dir.join("test.nzb");
    std::fs::write(&path, xml).unwrap();
    path
}

/// One run against the mock server, spike flag per `env`.
async fn run_enc(
    fx: &Fixture,
    password: Option<&str>,
    chaos: Chaos,
    env: &'static [(&'static str, &'static str)],
) -> (String, bool, std::path::PathBuf) {
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = write_nzb_numbered(fx, password);
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, env)
    })
    .await
    .unwrap();
    (log, ok, out)
}

const ON: &[(&str, &str)] = &[("NZBFAST_YENC_CRYPT", "1")];

/// The core claim: an encrypted single-file post lands byte-exact
/// through the one-pass pipeline with nothing but the NZB password.
#[tokio::test(flavor = "multi_thread")]
async fn an_encrypted_file_decrypts_while_assembling() {
    let mut fx = Fixture::new("yenc-enc-one");
    let key = session_key();
    let data = payload(30_000, 11);
    add_file_encrypted(&mut fx, "Plain.Film.mkv", &data, 6_000, &key, 1);
    let (log, ok, out) = run_enc(&fx, Some(PW), Chaos::default(), ON).await;
    assert!(ok, "encrypted single-file post failed:\n{log}");
    let got = std::fs::read(out.join("Plain.Film.mkv"))
        .unwrap_or_else(|e| panic!("Plain.Film.mkv missing: {e}\n{log}"));
    assert_eq!(got, data, "decrypted output must be byte-exact\n{log}");
}

/// The draft's segmentIndex is continuous ACROSS files ([n/total]
/// subject order), not per-file. Three files with different segment
/// counts: if either side restarted the index per file, every article
/// past file 1 would fail its Poly1305 tag and the job could not land.
#[tokio::test(flavor = "multi_thread")]
async fn the_segment_index_stays_continuous_across_files() {
    let mut fx = Fixture::new("yenc-enc-multi");
    let key = session_key();
    let a = payload(25_000, 21);
    let b = payload(9_000, 22);
    let c = payload(40_000, 23);
    let mut base = 1u32;
    base += add_file_encrypted(&mut fx, "Disc.A.vob", &a, 6_000, &key, base);
    base += add_file_encrypted(&mut fx, "Disc.B.vob", &b, 6_000, &key, base);
    add_file_encrypted(&mut fx, "Disc.C.vob", &c, 6_000, &key, base);
    let (log, ok, out) = run_enc(&fx, Some(PW), Chaos::default(), ON).await;
    assert!(ok, "multi-file encrypted post failed:\n{log}");
    for (name, want) in [("Disc.A.vob", &a), ("Disc.B.vob", &b), ("Disc.C.vob", &c)] {
        let got =
            std::fs::read(out.join(name)).unwrap_or_else(|e| panic!("{name} missing: {e}\n{log}"));
        assert_eq!(&got, want, "{name} must be byte-exact\n{log}");
    }
}

/// A wrong password derives a wrong key, every tag refuses, and the job
/// fails NAMED - never a green finish over garbage bytes. This is the
/// draft's "Authentication failure MUST result in complete decryption
/// failure" clause, exercised end to end.
#[tokio::test(flavor = "multi_thread")]
async fn the_wrong_password_refuses_rather_than_landing_garbage() {
    let mut fx = Fixture::new("yenc-enc-wrongpw");
    let key = session_key();
    let data = payload(20_000, 31);
    add_file_encrypted(&mut fx, "Locked.bin", &data, 6_000, &key, 1);
    let (log, ok, out) = run_enc(&fx, Some("not-the-password"), Chaos::default(), ON).await;
    assert!(!ok, "a wrong password must fail the job\n{log}");
    assert!(
        log.contains("failed authentication"),
        "the refusal must name authentication, not a generic decode error:\n{log}"
    );
    if let Ok(got) = std::fs::read(out.join("Locked.bin")) {
        assert_ne!(got, data, "garbage plaintext must never equal the payload");
    }
}

/// No password at all: the articles parse, the job cannot decrypt, and
/// the refusal says exactly what is missing.
#[tokio::test(flavor = "multi_thread")]
async fn a_missing_password_refuses_with_the_reason_named() {
    let mut fx = Fixture::new("yenc-enc-nopw");
    let key = session_key();
    add_file_encrypted(&mut fx, "NoKey.bin", &payload(12_000, 41), 6_000, &key, 1);
    let (log, ok, _out) = run_enc(&fx, None, Chaos::default(), ON).await;
    assert!(!ok, "an encrypted post with no password must fail\n{log}");
    assert!(
        log.contains("decryption is unavailable"),
        "the refusal must name the missing password:\n{log}"
    );
}

/// With the spike flag OFF this binary is "a standard yEnc parser" in
/// the draft's Interoperability sense - and the measured answer to its
/// claim that such parsers "process encrypted blocks normally" is NO:
/// the `=yencryption` line decodes as payload and the =yend gates
/// refuse every article. Pre-spike behavior, preserved byte for byte,
/// and one of the memo's spec-feedback items.
#[tokio::test(flavor = "multi_thread")]
async fn the_flag_off_is_an_unaware_client_and_refuses() {
    let mut fx = Fixture::new("yenc-enc-off");
    let key = session_key();
    add_file_encrypted(&mut fx, "Unaware.bin", &payload(12_000, 51), 6_000, &key, 1);
    let (log, ok, _out) = run_enc(&fx, Some(PW), Chaos::default(), &[]).await;
    assert!(
        !ok,
        "an encryption-unaware run must fail on encrypted articles\n{log}"
    );
}

/// Wrap every article of one already-added file with the control-lines
/// layer (FF1, the draft's second standard) at its session
/// segmentIndex. The wrapped articles carry no visible `=ybegin` at
/// all - the total-obfuscation shape that standard exists for.
fn control_wrap(fx: &mut Fixture, file_idx: usize, seg_base: u32) {
    let cc = nzbkit::yencrypt::ControlCrypt::new(&session_key());
    for (id, _, num) in &fx.nzb_files[file_idx].1 {
        let key = format!("<{id}>");
        let art = fx.articles.get_mut(&key).expect("article exists");
        *art = nzbkit::yencrypt::control_encrypt_block(&cc, &SALT, seg_base + num - 1, art)
            .expect("fixture articles are alphabet-clean");
        assert!(
            !art.windows(7).any(|w| w == b"=ybegin"),
            "control wrap left yEnc structure visible"
        );
    }
}

/// Control-lines standard alone: the post shows no yEnc structure, and
/// the engine restores every control line - via the message-id ->
/// segmentIndex map, since there is no `=ypart` to read pre-restore -
/// then decodes as normal. Two files, so the continuous session index
/// is exercised on the control tweaks exactly as the body tests
/// exercise it on nonces.
#[tokio::test(flavor = "multi_thread")]
async fn a_control_encrypted_post_restores_and_lands() {
    let mut fx = Fixture::new("yenc-ctl-multi");
    let a = payload(20_000, 71);
    let b = payload(15_000, 72);
    fx.add_file("Veil.A.bin", &a, 6_000);
    fx.add_file("Veil.B.bin", &b, 6_000);
    let na = fx.nzb_files[0].1.len() as u32;
    control_wrap(&mut fx, 0, 1);
    control_wrap(&mut fx, 1, 1 + na);
    let (log, ok, out) = run_enc(&fx, Some(PW), Chaos::default(), ON).await;
    assert!(ok, "control-encrypted post failed:\n{log}");
    for (name, want) in [("Veil.A.bin", &a), ("Veil.B.bin", &b)] {
        let got =
            std::fs::read(out.join(name)).unwrap_or_else(|e| panic!("{name} missing: {e}\n{log}"));
        assert_eq!(&got, want, "{name} must be byte-exact\n{log}");
    }
}

/// Scenario 3 of the README: both standards on one post, body
/// encryption inside, control lines outside (the declared ordering).
/// The engine control-decrypts first - which restores the
/// `=yencryption` line among the others - then decodes and
/// body-decrypts, all between fetch and verify.
#[tokio::test(flavor = "multi_thread")]
async fn a_combined_post_decrypts_control_then_body() {
    let mut fx = Fixture::new("yenc-both");
    let key = session_key();
    let data = payload(24_000, 81);
    add_file_encrypted(&mut fx, "Sealed.mkv", &data, 6_000, &key, 1);
    control_wrap(&mut fx, 0, 1);
    let (log, ok, out) = run_enc(&fx, Some(PW), Chaos::default(), ON).await;
    assert!(ok, "combined-encryption post failed:\n{log}");
    let got = std::fs::read(out.join("Sealed.mkv"))
        .unwrap_or_else(|e| panic!("Sealed.mkv missing: {e}\n{log}"));
    assert_eq!(got, data, "combined post must land byte-exact\n{log}");
}

/// A wrong password on a control-encrypted post: the line-1 trial
/// decrypt never yields `=y`, the articles fall through to the decoder
/// as-is, and the job fails - garbage never lands green. (Unlike the
/// body standard there is no tag to name, so the refusal is the
/// decoder's own; the draft's detection contract is probabilistic by
/// design and the memo's feedback item 15 asks it to say so.)
#[tokio::test(flavor = "multi_thread")]
async fn the_wrong_password_on_a_control_post_fails_closed() {
    let mut fx = Fixture::new("yenc-ctl-wrongpw");
    let data = payload(12_000, 91);
    fx.add_file("Veiled.bin", &data, 6_000);
    control_wrap(&mut fx, 0, 1);
    let (log, ok, out) = run_enc(&fx, Some("not-the-password"), Chaos::default(), ON).await;
    assert!(!ok, "a wrong password must fail a control post\n{log}");
    if let Ok(got) = std::fs::read(out.join("Veiled.bin")) {
        assert_ne!(got, data, "no plaintext may land off a wrong password");
    }
}

/// Flag off on a control post: there is no `=ybegin` anywhere, so an
/// unaware client refuses every article outright - the FF1 half's
/// compatibility answer (total obfuscation IS the feature, and the
/// memo's feedback item 14 asks the draft to state it as one).
#[tokio::test(flavor = "multi_thread")]
async fn the_flag_off_cannot_see_a_control_post_at_all() {
    let mut fx = Fixture::new("yenc-ctl-off");
    let data = payload(12_000, 92);
    fx.add_file("Hidden.bin", &data, 6_000);
    control_wrap(&mut fx, 0, 1);
    let (log, ok, _out) = run_enc(&fx, Some(PW), Chaos::default(), &[]).await;
    assert!(
        !ok,
        "an unaware run must refuse a control-encrypted post\n{log}"
    );
}

/// The PAR2 composition this prototype implements: recovery data over
/// the PLAINTEXT domain, decrypt sitting between decode and verify. A
/// whole article never arrives; PAR2 repairs the decrypted file. (The
/// memo argues the STANDARD should specify ciphertext-domain PAR2
/// instead - for the fingerprint leak, not for repair mechanics - and
/// cites this test as the measurement that plaintext-domain repair
/// composes with decrypt-at-decode.)
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_article_repairs_through_plaintext_par2() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("yenc-enc-repair");
    let key = session_key();
    let a = payload(30_000, 61);
    let b = payload(18_000, 62);
    let mut base = 1u32;
    base += add_file_encrypted(&mut fx, "Set.One.vob", &a, 6_000, &key, base);
    add_file_encrypted(&mut fx, "Set.Two.vob", &b, 6_000, &key, base);
    assert!(fx.add_par2(30, &["Set.One.vob", "Set.Two.vob"], 40_000));
    // Lose the second article of file 1 outright (430 forever).
    let lost = fx.nzb_files[0].1[1].0.clone();
    let chaos = Chaos {
        missing: std::iter::once(format!("<{lost}>")).collect(),
        ..Chaos::default()
    };
    let (log, ok, out) = run_enc(&fx, Some(PW), chaos, ON).await;
    assert!(ok, "the lost article must repair from PAR2:\n{log}");
    for (name, want) in [("Set.One.vob", &a), ("Set.Two.vob", &b)] {
        let got =
            std::fs::read(out.join(name)).unwrap_or_else(|e| panic!("{name} missing: {e}\n{log}"));
        assert_eq!(&got, want, "{name} must be byte-exact after repair\n{log}");
    }
}
