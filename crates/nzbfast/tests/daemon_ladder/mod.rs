//! Round B (26 Aug 2026): the recovery LADDER scored end to end - which
//! rung rescues a broken post, and which rungs never fire.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//!
//! # Why this exists beside `e2e_faults`
//!
//! TODO 283's fault matrix is the repo's only fault rig and it drives
//! `run_get` - the CLI. Five of the seven landed recovery mechanisms
//! are DAEMON-side and structurally unreachable from there: block
//! adoption (§293) resolves `donor_dirs` from the daemon's history and
//! is documented empty on the CLI, and spare promotion (§282 B), the
//! hunt (§282 C), the parked offer (§284) and retention insurance
//! (§304) have no CLI door at all. So the matrix answers "does the
//! repair engine save this post" and cannot answer "does the product".
//!
//! This module asks the second question at the one seam that decides
//! it: `altcand::parked_replaceable`, which gates BOTH the §284 parked
//! offer and the clicked hunt on `fail_action(...) == "search"`. The
//! shapes below are two of TODO 283's, reproduced against a real daemon
//! so the classification is the shipped one rather than a reading of
//! it. The first test is the two sides of that gate; the second proves
//! the AUTOMATIC rung is not gated the same way, on the identical
//! shape.
//!
//! **These asserted the behaviour that was measured, not the behaviour
//! anybody wanted** - written positively so the day the seam was fixed
//! this file would go red and the round's table would be known to be
//! stale. It went red on 26 Aug 2026: TODO 305 item 1 is CLOSED, the
//! offer reaches the founding shape, and the assertions below now pin
//! the fix. What the round MEASURED is preserved in the comments beside
//! each one, because the measurement is what the argument rests on and a
//! flipped assertion with no history reads as though it was always so.

use super::*;
use crate::payloads;

/// A post under construction: payload files split into articles, PAR2
/// packets appended, damage applied by removing ids from the mock again.
struct Post {
    files: Vec<(String, Vec<(String, u64, u32)>)>,
}

impl Post {
    fn new() -> Post {
        Post { files: Vec::new() }
    }

    /// One file, `art`-byte articles, every id live in the mock.
    fn add(
        &mut self,
        name: &str,
        data: &[u8],
        art: usize,
        tag: &str,
        articles: &mut HashMap<String, Vec<u8>>,
    ) -> Vec<(String, u64, u32)> {
        let segs = make_file_articles(name, data, art, tag, articles);
        self.files.push((name.to_string(), segs.clone()));
        segs
    }

    /// [`Post::add`], then take the named part numbers back out of the
    /// mock - real bytes for the parts that stay, 430 for the rest.
    fn add_holed(
        &mut self,
        name: &str,
        data: &[u8],
        art: usize,
        tag: &str,
        dead: &[u32],
        articles: &mut HashMap<String, Vec<u8>>,
    ) {
        let segs = self.add(name, data, art, tag, articles);
        for (id, _, num) in &segs {
            if dead.contains(num) {
                articles.remove(&format!("<{id}>"));
            }
        }
    }

    /// [`Post::add`], then take EVERY part back out: the file is
    /// declared in the NZB and on no server.
    fn add_dead(
        &mut self,
        name: &str,
        data: &[u8],
        art: usize,
        tag: &str,
        articles: &mut HashMap<String, Vec<u8>>,
    ) {
        let segs = self.add(name, data, art, tag, articles);
        for (id, _, _) in &segs {
            articles.remove(&format!("<{id}>"));
        }
    }

    fn xml(&self, post_unix: i64) -> String {
        let mut x = String::from(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        for (name, segs) in &self.files {
            x.push_str(&format!(
                "  <file poster=\"x\" date=\"{post_unix}\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
                segs.len()
            ));
            for (id, bytes, num) in segs {
                x.push_str(&format!(
                    "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
                ));
            }
            x.push_str("    </segments>\n  </file>\n");
        }
        x.push_str("</nzb>\n");
        x
    }
}

/// `par2 create` with the recovery BLOCK COUNT pinned, returning the
/// packet files it wrote. `-c<n>` rather than `-r<pct>` so a shape can
/// state "damage one block more than the set can fund" without modelling
/// a percentage of a file size.
fn par2_set(
    build: &Path,
    files: &[(&str, &[u8])],
    block: u64,
    blocks: usize,
) -> Vec<(String, Vec<u8>)> {
    std::fs::create_dir_all(build).unwrap();
    for (name, data) in files {
        std::fs::write(build.join(name), data).unwrap();
    }
    let st = Command::new("par2")
        .arg("create")
        .arg(format!("-s{block}"))
        .arg(format!("-c{blocks}"))
        .arg("-q")
        .arg("testset")
        .args(files.iter().map(|(n, _)| n))
        .current_dir(build)
        .status();
    assert!(st.is_ok_and(|s| s.success()), "par2 create failed");
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(build)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            let name = p.file_name()?.to_string_lossy().to_string();
            (p.extension().is_some_and(|x| x == "par2")).then(|| (name, std::fs::read(&p).unwrap()))
        })
        .collect();
    out.sort();
    out
}

fn have_par2() -> bool {
    Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The recovery set's article size, 8 KiB rather than the payload's
/// block size.
///
/// §282 item 4's yield gate refuses to judge a sample under
/// `sidefetch::MIN_RECOVERY_YIELD_SAMPLE` (16 articles), so at one
/// article per 64 KiB block an eight-block set puts the repair-side ask
/// at about five and the "this provider will not serve the parity"
/// verdict cannot fire at all. `e2e_faults` records the same constant
/// and the same argument; this is the side of the floor the live §282
/// incident was on.
const RECOVERY_ART: usize = 8_192;
const BS: usize = 65_536;
const BLOCKS: usize = 40;
const RECOVERY_BLOCKS: usize = 8;

/// The daemon under test, with one automatic retry that spends itself
/// in seconds so a shape reaches its FINAL verdict inside the test.
fn daemon_cmd(dir: &Path, cfg: &Path) -> impl Fn(u16) -> Command + use<> {
    let cfg = cfg.to_path_buf();
    let dir = dir.to_path_buf();
    move |port: u16| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_AUTO_RETRY_SECS", "5")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("4");
        c
    }
}

fn upload(port: u16, xml: &str, fname: &str) {
    let boundary = "----ladderb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; \
             filename=\"{fname}\"\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let r = http(
        port,
        "/api?mode=addfile&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    assert!(r.contains("\"status\":true"), "{r}");
}

/// §303 `mode=nzb_preview` over the same bytes: the §294 completable
/// verdict BEFORE anything is enqueued.
///
/// This is the pre-download road, and it is the honest counterweight
/// to what the parked road does not do - so the round has to ask it
/// rather than reason about it. It shares no gate with
/// `parked_replaceable`.
fn preview(port: u16, xml: &str) -> serde_json::Value {
    let boundary = "----ladderpv";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"nzbfile\"; \
             filename=\"p.nzb\"\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let r = http(
        port,
        "/api?mode=nzb_preview&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    serde_json::from_str(&r).unwrap_or_default()
}

/// Poll history until this row reaches a terminal state AND has no
/// automatic retry still in the future.
///
/// The second half is the whole reason this is not a two-line poll:
/// `parked_replaceable` refuses a row whose `auto_retry_at` is ahead of
/// now, so a table built off the first terminal reading would score
/// every transient-kind shape as "no offer" for a reason that expires.
/// What this module measures is the FINAL answer.
fn settled(port: u16, frag: &str, tries: u32) -> serde_json::Value {
    for _ in 0..tries {
        let h = http(port, "/api?mode=history&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&h).unwrap_or(serde_json::Value::Null);
        if let Some(s) = v["history"]["slots"].as_array().and_then(|a| {
            a.iter().find(|s| {
                s["name"].as_str().unwrap_or_default().contains(frag)
                    && (s["status"] == "Completed" || s["status"] == "Failed")
                    && s["auto_retry_at"].as_i64().is_none()
            })
        }) {
            return s.clone();
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    panic!("{frag} never settled");
}

/// The row's ladder position, printed so the round's table is in the
/// test log rather than a claim in a comment.
fn score(tag: &str, s: &serde_json::Value) -> (String, String, bool) {
    let kind = s["fail_kind"].as_str().unwrap_or_default().to_string();
    let action = s["fail_action"].as_str().unwrap_or_default().to_string();
    let offer = !s["alt_offer"].is_null();
    println!(
        "LADDER {tag}: status={} fail_kind={kind} fail_action={action} parked_offer={offer}",
        s["status"]
    );
    (kind, action, offer)
}

/// §282's founding shape - a healthy payload one block short over a
/// recovery set no server will serve - reaches the parked offer, and so
/// does a wholly gone post.
///
/// **This test was `..._reaches_no_parked_offer_and_a_gone_post_does`
/// and it is the round's headline measurement, kept.** The shapes are
/// the two sides of one seam. Both are terminal, both are past the
/// automatic retry, both have a `.nzb` on disk and neither has been
/// replaced - so `parked_replaceable`'s only contested clause is the
/// remedy one, and the two shapes used to land on opposite sides of it:
///
/// * "post is gone: ..." -> `FailKind::Gone` -> `search`, so the offer
///   and the clicked hunt were both drawn.
/// * "download incomplete: the recovery data is what failed, not the
///   payload - ..." -> `FailKind::MissingArticles` (the OPENING is what
///   `fail_kind` keys on, and TODO 283 item 13 records that the opening
///   is load-bearing for the age gate) -> `retry`, and the gate read
///   `fail_action == "search"`. §284 built the whole parked surface FOR
///   this shape - its own item 2 names "a job that dies DURING the run
///   ... the recovery set that could not be fetched, which is the
///   incident's actual death" - and the gate it was given classified
///   that death as worth asking again for.
///
/// TODO 305 fixed it by giving the gate its own predicate,
/// `failkind::another_copy_can_help`, rather than by widening
/// `fail_action` - and BOTH halves of that are pinned here, because the
/// half that was not done is as load-bearing as the half that was. The
/// row still classifies `missing`, still says `retry`, and SAB's `retry`
/// BOOLEAN is still true, so every *arr, nzb360 and LunaSea client sees
/// exactly what it saw before; what changed is that the drawer now
/// offers the second copy as well.
#[tokio::test(flavor = "multi_thread")]
async fn a_dead_recovery_set_reaches_the_parked_offer_and_so_does_a_gone_post() {
    if !have_par2() {
        eprintln!("par2 not on PATH - skipping the ladder scoring");
        return;
    }
    let base = std::env::temp_dir().join(format!("nzbfast-ladder-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&base);

    let data = payloads::unique_payload(BLOCKS * BS, 0x5eed_0305);
    let set = par2_set(
        &base.join("build"),
        &[("payload.bin", &data)],
        BS as u64,
        RECOVERY_BLOCKS,
    );

    let mut articles = HashMap::new();

    // Shape R: one payload block short, and every recovery volume dead.
    // The main index stays live so the set activates and the repair
    // ladder actually asks for volumes - a set that never activates
    // fails somewhere else entirely and tests nothing here.
    let mut r = Post::new();
    r.add_holed("payload.bin", &data, BS, "rpay", &[7], &mut articles);
    for (i, (name, bytes)) in set.iter().enumerate() {
        if name.contains(".vol") {
            r.add_dead(
                name,
                bytes,
                RECOVERY_ART,
                &format!("rvol{i}"),
                &mut articles,
            );
        } else {
            r.add(
                name,
                bytes,
                RECOVERY_ART,
                &format!("rmain{i}"),
                &mut articles,
            );
        }
    }

    // Shape G: nothing of the post is on any server, and it is old
    // enough that propagation does not explain it.
    let gone = payloads::unique_payload(8 * BS, 0x60_0e);
    let mut g = Post::new();
    g.add_dead("gone.bin", &gone, BS, "gpay", &mut articles);

    let old = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - 30 * 86_400;
    let r_xml = r.xml(old);
    let g_xml = g.xml(old);

    let srv = MockServer::start(articles, Chaos::default()).await;
    let dir = base.join("run");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, daemon_cmd(&dir, &cfg)).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // The PRE-download road first, on the identical bytes: §303
        // preview over §294's completable verdict. Printed rather
        // than asserted to a value - what the sample can see of a
        // recovery set is §294/§282's subject, not this round's, and
        // pinning a verdict here would make this test go red for
        // somebody else's tuning. What the round needs is the NUMBER.
        let pv = preview(port, &r_xml);
        println!(
            "LADDER preview(recovery-set-dead): completable={} payload={} \
             recovery={}",
            pv["completable"], pv["health"]["payload"], pv["health"]["recovery"]
        );

        upload(port, &r_xml, "Ladder.Recovery.S01E01.1080p.nzb");
        let rec = settled(port, "Recovery", 900);
        let (rk, ra, ro) = score("recovery-set-dead", &rec);
        assert_eq!(rec["status"], "Failed", "the shape must fail: {rec}");
        assert!(
            rec["fail_message"]
                .as_str()
                .unwrap_or_default()
                .contains("the recovery data is what failed"),
            "not the shape this test is about: {rec}"
        );
        assert_eq!(rk, "missing", "the opening keys fail_kind: {rec}");
        // TODO 305 ruled that `fail_action` must NOT move for this
        // family, and this is that ruling pinned rather than described.
        // The token drives the dashboard's dimmed Retry and, one line
        // below, SAB's `retry` boolean - so calling this death "search"
        // would tell every *arr client that a row a journal-resume retry
        // can still shorten may not be asked for again.
        assert_eq!(ra, "retry", "and MissingArticles asks again: {rec}");
        assert_eq!(
            rec["retry"], true,
            "the SAB history contract is derived from fail_action and \
             must be untouched by the offer's own widening: {rec}"
        );
        // Every OTHER clause of `parked_replaceable` is satisfied on
        // this row, so `fail_action` is the only thing withholding the
        // offer. Asserted rather than argued: a test that reads
        // "no offer" without pinning why would pass just as well on a
        // row whose spool file had been reaped, and would then be
        // measuring nothing.
        assert!(!rec["tombstone"].as_bool().unwrap_or(false), "{rec}");
        assert_eq!(rec["alt_to_name"], "", "nothing replaced it: {rec}");
        assert!(rec["auto_retry_at"].is_null(), "retry spent: {rec}");
        assert!(
            Path::new(rec["nzb_path"].as_str().unwrap_or_default()).is_file(),
            "the spool .nzb is still on disk, so the age gate and the \
             admission test can both read it: {rec}"
        );
        // MEASURED 26 Aug 2026, round B: this read `!ro` and passed -
        // §284's parked offer did not reach §282's own founding shape,
        // and seven of the round's twelve failures were in that
        // population. TODO 305 item 1 is the fix and this is its pin.
        assert!(
            ro,
            "the payload is 97.5% on disk over a recovery set no server \
             will serve - another release is the only remedy this \
             product has, and the drawer has to say so: {rec}"
        );

        // AND THE DOOR ANSWERS IT. This is the half of §284's clause 1
        // that survived TODO 305's rewrite: the offer and the clicked
        // hunt ask ONE predicate, so a button that is on the page is a
        // button `hunt_parked_request` will answer rather than refuse.
        // Worth a real call rather than an argument, because the
        // widening moved a row into a population three further gates
        // then judge - `hunt_gates` refuses a kind that is not
        // `post_unavailable()`, and its age gate for `MissingArticles`
        // is `diag::missing_articles_proven_stale`, which reads the age
        // clause back out of this very message. An empty candidate list
        // is the right answer on a daemon with no indexers; the refusal
        // sentence would not be.
        let rid = rec["nzo_id"].as_str().unwrap_or_default().to_string();
        let hunt = http(
            port,
            &format!("/api?mode=alt_hunt&output=json&value={rid}"),
            None,
        );
        assert!(
            hunt.contains("\"status\":true"),
            "the offer is drawn on this row, so the search door behind it \
             must not refuse: {hunt}"
        );

        upload(port, &g_xml, "Ladder.Gone.S02E02.1080p.nzb");
        let gn = settled(port, "Gone", 900);
        let (gk, ga, go) = score("post-wholly-gone", &gn);
        assert_eq!(gn["status"], "Failed", "{gn}");
        assert_eq!(gk, "gone", "{gn}");
        assert_eq!(ga, "search", "{gn}");
        assert!(
            go,
            "a wholly gone post IS offered a replacement - this is the \
             control that proves the offer machinery works and the \
             classification is what withholds it: {gn}"
        );
    })
    .await
    .unwrap();
}

/// The AUTOMATIC rung fires on the identical recovery-set-dead shape: a
/// held spare is promoted and completes.
///
/// **This test was `..._on_the_shape_the_offer_refuses`, and the rename
/// is the finding being closed rather than a tidy-up.** `park_gen`
/// reaches `promote_held_alternative` on `failed && !tombstone &&
/// !armed_auto_retry` with a dupe key - it never asks the remedy
/// question at all - so round B found the ON-by-default road rescuing a
/// shape the click road refused: the user who was not looking got a
/// rescue and the user who opened the drawer was told to retry. TODO
/// 305 fixed the click road, so the two now agree ABOUT THIS SHAPE, and
/// the test beside this one pins that half.
///
/// It is kept, and kept measuring the automatic road, because the
/// disagreement is only closed where it was measured: the two roads are
/// still different predicates, and `promote_held_alternative` would
/// still promote a spare on a `Local` failure that
/// `another_copy_can_help` refuses. Whether the automatic rung should
/// ask the same question is a separate change with a real cost - it
/// would stop rescuing shapes it rescues today - and nothing in round B
/// measured that population.
#[tokio::test(flavor = "multi_thread")]
async fn the_automatic_promotion_rung_fires_on_the_recovery_set_dead_shape() {
    if !have_par2() {
        eprintln!("par2 not on PATH - skipping the promotion leg");
        return;
    }
    let base = std::env::temp_dir().join(format!("nzbfast-ladderp-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&base);

    let data = payloads::unique_payload(BLOCKS * BS, 0x5eed_0306);
    let set = par2_set(
        &base.join("build"),
        &[("payload.bin", &data)],
        BS as u64,
        RECOVERY_BLOCKS,
    );
    let mut articles = HashMap::new();

    // The primary: the same recovery-set-dead shape as the leg above.
    let mut p = Post::new();
    p.add_holed("payload.bin", &data, BS, "ppay", &[7], &mut articles);
    for (i, (name, bytes)) in set.iter().enumerate() {
        if name.contains(".vol") {
            p.add_dead(
                name,
                bytes,
                RECOVERY_ART,
                &format!("pvol{i}"),
                &mut articles,
            );
        } else {
            p.add(
                name,
                bytes,
                RECOVERY_ART,
                &format!("pmain{i}"),
                &mut articles,
            );
        }
    }
    // The spare: a genuinely different post of the same release - every
    // article id different, its own recovery set - and wholly healthy.
    let mut s = Post::new();
    s.add("payload.bin", &data, BS, "spay", &mut articles);
    for (i, (name, bytes)) in set.iter().enumerate() {
        s.add(
            name,
            bytes,
            RECOVERY_ART,
            &format!("smain{i}"),
            &mut articles,
        );
    }

    let old = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - 30 * 86_400;
    let p_xml = p.xml(old);
    let s_xml = s.xml(old);

    // The successor's PAYLOAD articles, which is the baseline the §293
    // measurement plan set out to beat ("the successor fetches only the
    // unadopted remainder") and the only denominator that means anything
    // here. NOT the whole declared post: a clean run defers the recovery
    // volumes and never asks for them, so an all-articles count scores
    // ordinary one-pass laziness as a saving adoption did not make.
    // Measured the wrong way round first and corrected - 41 of 109 reads
    // like a 62% saving and is the payload in full plus the PAR2 main.
    let spare_payload: u64 = s
        .files
        .iter()
        .filter(|(n, _)| !n.ends_with(".par2"))
        .map(|(_, sg)| sg.len() as u64)
        .sum();

    let srv = MockServer::start(articles, Chaos::default()).await;
    let served = srv.served.clone();
    let dir = base.join("run");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, daemon_cmd(&dir, &cfg)).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Paused, so the second add lands HELD as the duplicate of the
        // first before either runs - the M14f shape the promotion path
        // is written against.
        http(port, "/api?mode=pause&output=json", None);
        upload(port, &p_xml, "Ladder.Promote.S03E03.720p.nzb");
        upload(port, &s_xml, "Ladder.Promote.S03E03.1080p.nzb");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(any_held_behind_a_copy(&q), "the spare was not held: {q}");
        http(port, "/api?mode=resume&output=json", None);

        let prim = settled(port, "720p", 1200);
        score("promote-primary", &prim);
        assert_eq!(prim["status"], "Failed", "{prim}");
        let after_primary = served.load(std::sync::atomic::Ordering::Relaxed);
        let spare = settled(port, "1080p", 1200);
        let successor_bodies = served.load(std::sync::atomic::Ordering::Relaxed) - after_primary;
        println!("LADDER promote-spare: status={}", spare["status"]);
        // §293's own measurement plan: "Baseline: successor fetches
        // 100% of the post. Treatment: successor fetches only the
        // unadopted remainder." MEASURED 26 Aug 2026, and this leg
        // measured the BASELINE: the successor re-fetched every payload
        // article though the predecessor left 39 of those 40 blocks
        // verified on disk, because `donor_dirs` reached `get::settle` /
        // `get::tail` / `repair` and NOTHING in `get::plan`.
        //
        // TODO 305 item 2 built the plan-side arm, and this shape is
        // deliberately the one it cannot help - which is why the
        // assertion stays and now pins that LIMIT instead of the gap.
        // Adoption before the plan is WHOLE FILES only (`get/donor.rs`
        // argues it: an NZB states encoded segment sizes, so which
        // articles a partial donor covers is not knowable until their
        // bodies arrive), and this post is ONE file with a hole in it,
        // so nothing is donatable and the successor rightly fetches it
        // all. The saving is pinned next door, on §282's own multi-file
        // shape, by
        // `a_promoted_replacement_does_not_refetch_what_the_predecessor_left_whole`.
        //
        // The count is 42 rather than 41 for a stated reason: a job with
        // donors fetches its PAR2 index twice, once for the pre-pass
        // that reads the FileDesc digests and once for the plan. Here
        // that buys nothing, which is the honest worst case of the arm.
        println!(
            "LADDER promote-cost: successor fetched {successor_bodies} \
             body/bodies for a payload of {spare_payload} article(s) - the \
             predecessor had 39 of those 40 blocks verified on disk"
        );
        assert!(
            successor_bodies >= spare_payload,
            "a ONE-FILE post whose donor copy has a hole in it offers \
             plan-side adoption nothing to take. If this is red, article-level \
             adoption landed - update research/RECOVERY-LADDER-YIELD-2026-08-26.md \
             and TODO 305: {successor_bodies} < {spare_payload}"
        );
        assert_eq!(
            spare["status"], "Completed",
            "the held spare must be promoted and complete: {spare}"
        );
        assert!(
            !spare["alt_from_name"]
                .as_str()
                .unwrap_or_default()
                .is_empty(),
            "the completed row must record what it replaced: {spare}"
        );
    })
    .await
    .unwrap();
}

/// **§293's own measurement plan, and TODO 305 item 2's answer to it:**
/// "Baseline: successor fetches 100% of the post. Treatment: successor
/// fetches only the unadopted remainder." Metric: articles served by the
/// mock to the successor, printed both legs.
///
/// The shape is §282's founding incident rather than the single-file one
/// beside it: a MULTI-FILE post whose predecessor died on the recovery
/// set with most of the payload complete. Two members are whole on the
/// predecessor's disk and one carries a hole, so the successor may take
/// the two and must fetch the third - which is exactly what plan-side
/// adoption can and cannot do. It is WHOLE FILES only, and `get/donor.rs`
/// says why at length: skipping an ARTICLE means proving the donor
/// covers the decoded byte range that article would have written, and an
/// NZB states only ENCODED segment sizes, so a partial file's remainder
/// cannot be named before its bodies arrive. The partial member keeps its
/// existing answer one phase later, in the repair's own adoption scan -
/// which is the rescue rung §293 shipped and this does not replace.
///
/// The cost is stated as well as the saving: the successor fetches its
/// PAR2 index TWICE, once for the pre-pass that reads the FileDesc
/// digests and once for the plan, whose activation needs the packets in
/// memory. That is the whole extra cost of the arm and the bound below
/// counts it.
#[tokio::test(flavor = "multi_thread")]
async fn a_promoted_replacement_does_not_refetch_what_the_predecessor_left_whole() {
    if !have_par2() {
        eprintln!("par2 not on PATH - skipping the plan-side adoption leg");
        return;
    }
    let base = std::env::temp_dir().join(format!("nzbfast-ladderd-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&base);

    let whole1 = payloads::unique_payload(12 * BS, 0x5eed_0401);
    let whole2 = payloads::unique_payload(12 * BS, 0x5eed_0402);
    let holed = payloads::unique_payload(16 * BS, 0x5eed_0403);
    let set = par2_set(
        &base.join("build"),
        &[
            ("whole1.bin", &whole1),
            ("whole2.bin", &whole2),
            ("holed.bin", &holed),
        ],
        BS as u64,
        RECOVERY_BLOCKS,
    );
    let mut articles = HashMap::new();

    // The primary: both whole members land in full, the third loses one
    // article, and every recovery volume is dead - so it fails with 24
    // of its 40 payload blocks sitting complete and verified on disk.
    let mut p = Post::new();
    p.add("whole1.bin", &whole1, BS, "pw1", &mut articles);
    p.add("whole2.bin", &whole2, BS, "pw2", &mut articles);
    p.add_holed("holed.bin", &holed, BS, "phl", &[5], &mut articles);
    for (i, (name, bytes)) in set.iter().enumerate() {
        if name.contains(".vol") {
            p.add_dead(
                name,
                bytes,
                RECOVERY_ART,
                &format!("pvol{i}"),
                &mut articles,
            );
        } else {
            p.add(
                name,
                bytes,
                RECOVERY_ART,
                &format!("pmain{i}"),
                &mut articles,
            );
        }
    }
    // The spare: a genuinely different post of the same release - every
    // article id different - and wholly healthy, so nothing it fails to
    // fetch can be blamed on the mock.
    let mut sp = Post::new();
    sp.add("whole1.bin", &whole1, BS, "sw1", &mut articles);
    sp.add("whole2.bin", &whole2, BS, "sw2", &mut articles);
    sp.add("holed.bin", &holed, BS, "shl", &mut articles);
    for (i, (name, bytes)) in set.iter().enumerate() {
        sp.add(
            name,
            bytes,
            RECOVERY_ART,
            &format!("smain{i}"),
            &mut articles,
        );
    }

    // What the successor would have fetched with no donor: its PAYLOAD,
    // and not the whole declared post - a clean run defers the recovery
    // volumes and never asks for them, so an all-articles denominator
    // would score ordinary one-pass laziness as a saving adoption did
    // not make.
    let arts = |name: &str| -> u64 {
        sp.files
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, sg)| sg.len() as u64)
            .expect("member is in the spare post")
    };
    let (w1_arts, w2_arts, holed_arts) =
        (arts("whole1.bin"), arts("whole2.bin"), arts("holed.bin"));
    let spare_payload = w1_arts + w2_arts + holed_arts;
    // The index the plan fetches, and the pre-pass fetches again.
    let index_arts: u64 = sp
        .files
        .iter()
        .filter(|(n, _)| n.ends_with(".par2") && !n.contains(".vol"))
        .map(|(_, sg)| sg.len() as u64)
        .sum();
    assert!(index_arts > 0, "the spare post must carry a par2 index");

    let old = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - 30 * 86_400;
    let p_xml = p.xml(old);
    let s_xml = sp.xml(old);

    let srv = MockServer::start(articles, Chaos::default()).await;
    let served = srv.served.clone();
    let body_log = srv.body_log.clone();
    let dir = base.join("run");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, daemon_cmd(&dir, &cfg)).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        http(port, "/api?mode=pause&output=json", None);
        upload(port, &p_xml, "Ladder.Donor.S04E01.720p.nzb");
        upload(port, &s_xml, "Ladder.Donor.S04E01.1080p.nzb");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(any_held_behind_a_copy(&q), "the spare was not held: {q}");
        http(port, "/api?mode=resume&output=json", None);

        let prim = settled(port, "720p", 1200);
        assert_eq!(prim["status"], "Failed", "{prim}");
        let after_primary = served.load(std::sync::atomic::Ordering::Relaxed);
        let log_at_handover = body_log.lock().unwrap().len();
        let spare = settled(port, "1080p", 1200);
        let successor_bodies = served.load(std::sync::atomic::Ordering::Relaxed) - after_primary;
        let asked: Vec<String> = body_log.lock().unwrap()[log_at_handover..].to_vec();

        println!(
            "LADDER donor-cost: successor fetched {successor_bodies} body/bodies for a \
             payload of {spare_payload} article(s); the predecessor left whole1.bin and \
             whole2.bin complete on disk"
        );
        assert_eq!(
            spare["status"], "Completed",
            "the held spare must be promoted and complete: {spare}"
        );
        // The headline. MEASURED 26 Aug 2026 on the tree before this
        // landed: 41 bodies for a 40-article payload, because the
        // adoption scan ran AFTER the fetch and could never pre-empt one.
        assert!(
            successor_bodies < spare_payload,
            "plan-side adoption must shrink the successor's fetch plan: \
             {successor_bodies} bodies against a {spare_payload}-article payload. \
             Asked for: {asked:?}"
        );
        // ...and the exact remainder, so a saving that quietly shrinks
        // to one article still fails here. The partial member is fetched
        // in full (its donor copy has a hole, and a hole cannot be named
        // before the bodies land) and the index is fetched twice.
        let want = holed_arts + 2 * index_arts;
        assert!(
            successor_bodies <= want,
            "the unadopted remainder is {holed_arts} holed article(s) plus {index_arts} \
             index article(s) fetched twice = {want}; got {successor_bodies}. \
             Asked for: {asked:?}"
        );
        // Named, not just counted: not one article of either donated
        // member may be asked for. A count alone would pass a run that
        // fetched a whole member and skipped the holed one.
        for (tag, name) in [("sw1", "whole1.bin"), ("sw2", "whole2.bin")] {
            let hits: Vec<&String> = asked.iter().filter(|id| id.contains(tag)).collect();
            assert!(
                hits.is_empty(),
                "{name} was taken whole off the predecessor's disk and must not be \
                 fetched: {hits:?}"
            );
        }
        assert!(
            asked.iter().any(|id| id.contains("shl")),
            "the member the predecessor left holed must still be fetched: {asked:?}"
        );
    })
    .await
    .unwrap();
}
