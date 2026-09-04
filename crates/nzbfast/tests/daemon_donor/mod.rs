//! §293 stage 2: a replacement job adopts the failed predecessor's
//! blocks, measured as a fail-vs-success A/B.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//!
//! The shape under test is §282's founding incident turned around: the
//! primary dies with most of its payload intact on disk, the held
//! alternative is promoted, and the alternative's own post is ALSO
//! damaged past what its declared recovery covers. Baseline (leg A):
//! that replacement fails too - two failures, nothing delivered.
//! Treatment (leg B): the promoted job's repair reads the
//! predecessor's output as a donor, adopts the blocks its own wire
//! would not serve, and completes. Same release bytes, two genuinely
//! different posts: different article ids throughout and two par2 sets
//! created at different block sizes, so not one checksum is shared
//! between the sets - the adoption is pure content match.

use super::*;
use crate::payloads;

/// Write the release files, run `par2 create` over them at `block`
/// bytes per slice with ONE recovery block, and return the resulting
/// packet files as (name, bytes). One recovery block is the whole
/// point: the damage each leg injects spans many blocks, so the
/// declared recovery can never cover it and only a donor can.
fn par2_set(
    build: &std::path::Path,
    files: &[(&str, &[u8])],
    block: u64,
) -> Vec<(String, Vec<u8>)> {
    std::fs::create_dir_all(build).unwrap();
    for (name, data) in files {
        std::fs::write(build.join(name), data).unwrap();
    }
    let st = Command::new("par2")
        .arg("create")
        .arg(format!("-s{block}"))
        .arg("-c1")
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

/// `par2_set`, but ONE INDEPENDENT recovery set PER FILE - GH #63's
/// shape, and the one `tests/e2e_multiset` models. Each file gets its
/// own `par2 create` under its own base name, so the post carries N
/// sets with N distinct set ids, and each set's single recovery block
/// speaks only for its own file.
///
/// The packets are collected and REMOVED after each file, because
/// `par2 create` writes into the build directory and a later file's
/// scan would otherwise pick up the earlier one's volumes.
fn par2_set_per_file(
    build: &std::path::Path,
    files: &[(&str, &[u8])],
    block: u64,
) -> Vec<(String, Vec<u8>)> {
    std::fs::create_dir_all(build).unwrap();
    for (name, data) in files {
        std::fs::write(build.join(name), data).unwrap();
    }
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, _) in files {
        let base = name.rsplit_once('.').map_or(*name, |(stem, _)| stem);
        let st = Command::new("par2")
            .arg("create")
            .arg(format!("-s{block}"))
            .arg("-c1")
            .arg("-q")
            .arg(base)
            .arg(name)
            .current_dir(build)
            .status();
        assert!(
            st.is_ok_and(|s| s.success()),
            "par2 create failed for {name}"
        );
        let mut mine: Vec<(String, Vec<u8>)> = std::fs::read_dir(build)
            .unwrap()
            .filter_map(|e| {
                let p = e.unwrap().path();
                let n = p.file_name()?.to_string_lossy().to_string();
                (p.extension().is_some_and(|x| x == "par2")).then(|| {
                    let b = std::fs::read(&p).unwrap();
                    std::fs::remove_file(&p).unwrap();
                    (n, b)
                })
            })
            .collect();
        mine.sort();
        out.extend(mine);
    }
    out
}

/// One post of the release: every payload file split into articles
/// under `tag`, the par2 packet files appended, ghosts where the leg
/// wants damage. Returns the NZB xml.
struct Post {
    files: Vec<(String, Vec<(String, u64, u32)>)>,
}

impl Post {
    fn new() -> Post {
        Post { files: Vec::new() }
    }
    fn add(&mut self, name: &str, data: &[u8], tag: &str, articles: &mut HashMap<String, Vec<u8>>) {
        let segs = make_file_articles(name, data, 40_000, tag, articles);
        self.files.push((name.to_string(), segs));
    }
    /// A file whose articles are declared but never served: the ids are
    /// minted like real ones and simply absent from the mock, so every
    /// request answers 430.
    fn add_ghost(&mut self, name: &str, len: u64, parts: u32, tag: &str) {
        let segs: Vec<(String, u64, u32)> = (1..=parts)
            .map(|n| (format!("{tag}-{n}@mock"), len / u64::from(parts), n))
            .collect();
        self.files.push((name.to_string(), segs));
    }
    /// `add`, then delete the given part numbers from the mock again -
    /// a partially dead file: real bytes for the parts that stay, 430
    /// for the ones removed.
    fn add_holed(
        &mut self,
        name: &str,
        data: &[u8],
        tag: &str,
        dead_parts: &[u32],
        articles: &mut HashMap<String, Vec<u8>>,
    ) {
        let segs = make_file_articles(name, data, 40_000, tag, articles);
        for (id, _, num) in &segs {
            if dead_parts.contains(num) {
                articles.remove(&format!("<{id}>"));
            }
        }
        self.files.push((name.to_string(), segs));
    }
    fn xml(&self) -> String {
        let mut x = String::from(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        for (name, segs) in &self.files {
            x.push_str(&format!(
                "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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

fn have_par2() -> bool {
    Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// A `serve` command for one leg: its own data directory, its own
/// config, the mock's address already in it.
///
/// Module-level rather than a closure inside each test, because both
/// tests here need the identical daemon and a second hand-copy of it is
/// how two fixtures start meaning different things while reading the
/// same - `NZBFAST_AUTO_RETRY_SECS` in particular is load-bearing for
/// BOTH of them: a promotion cannot happen while an automatic retry is
/// still armed, so the window has to be short enough to spend itself
/// inside the poll below.
fn daemon_in(dir: PathBuf, cfg: PathBuf) -> impl Fn(u16) -> Command {
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
            .arg("2");
        c
    }
}

/// Add one NZB by upload, as the dashboard does.
fn upload(port: u16, xml: &str, fname: &str) {
    let boundary = "----donorb";
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

/// Poll history until the job whose name carries `name_frag` reaches a
/// terminal status, and return it.
///
/// Matched on the NAME rather than on the nzo id because these fixtures
/// name their two posts for the quality tag that tells them apart, and
/// the id is minted by the daemon. The slot is read out of the `history`
/// array by `serde_json` and never by `payload.contains(..)` - see the
/// harness's `history_slot` for why a substring search over a SAB
/// payload answers a different question.
fn outcome(port: u16, name_frag: &str, tries: u32) -> Option<String> {
    for _ in 0..tries {
        let h = http(port, "/api?mode=history&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&h).unwrap_or(serde_json::Value::Null);
        if let Some(s) = v["history"]["slots"].as_array().and_then(|a| {
            a.iter().find(|s| {
                s["name"].as_str().unwrap_or_default().contains(name_frag)
                    && (s["status"] == "Completed" || s["status"] == "Failed")
            })
        }) {
            return Some(s["status"].as_str().unwrap_or_default().to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    None
}

/// The A/B. Leg A: the damaged replacement post, alone, fails - its
/// declared recovery (one block) cannot cover a two-article hole.
/// Leg B: the same replacement, promoted after its predecessor failed,
/// completes by adopting the predecessor's copy of the damaged file -
/// itself damaged, in a different place, so that only block-level
/// adoption can bridge the two (see the fixture comment). The only difference between the legs is the predecessor's
/// existence.
#[tokio::test(flavor = "multi_thread")]
async fn a_promoted_replacement_completes_by_adopting_the_predecessors_blocks() {
    if !have_par2() {
        eprintln!("par2 not on PATH - skipping the donor A/B");
        return;
    }
    let base = std::env::temp_dir().join(format!("nzbfast-donor-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&base);

    // The release: two files, identical bytes in both posts.
    let f1 = payloads::unique_payload(80_000, 51);
    let f2 = payloads::unique_payload(160_000, 53);
    // Two independent recovery sets over the same bytes: different
    // block sizes mean different set ids and zero shared checksums,
    // and DIFFERENT MEMBER NAMES, which is the third thing that keeps
    // this A/B about adoption - see the predecessor's comment below.
    let set_a = par2_set(
        &base.join("build-a"),
        &[("f1p.bin", &f1[..]), ("f2p.bin", &f2[..])],
        4_000,
    );
    let set_b = par2_set(
        &base.join("build-b"),
        &[("f1.bin", &f1[..]), ("f2.bin", &f2[..])],
        8_000,
    );

    let mut articles = HashMap::new();
    // The PREDECESSOR: f1 wholly dead, f2 all but its FIRST article,
    // its own set. Its damage (20 blocks of f1) dwarfs its one recovery
    // block, so it fails - leaving that f2 in its output directory.
    //
    // **The hole in the donor's own f2 is load-bearing and is not what
    // this A/B is about.** It is what keeps the A/B about the thing its
    // name says. TODO 305 item 2 added a PLAN-SIDE arm (§293's byte
    // saving, `get/donor.rs`) that takes a member off a donor WHOLE,
    // before the fetch, on the successor's own FileDesc MD5 - and a
    // byte-perfect f2 here is exactly what that arm takes. Leg B would
    // then still read Completed while measuring a different mechanism
    // entirely, with the repair-time block adoption these legs exist
    // for never running at all. One dead article is enough to refuse
    // the whole-file arm (the file's MD5 and its first-16k MD5 both
    // move) and leaves every byte the successor's hole needs -
    // bytes 40,000..120,000, which is parts 2 and 3 - intact for the
    // sliding scan to find.
    //
    // **The predecessor's own recovery volumes are DEAD, and that is
    // what keeps this A/B about DISK.** M31 stage 1 landed a second
    // donor mechanism on this exact shape - `get::dupefill` borrows the
    // predecessor's LIVE ARTICLES during settle, before the repair
    // ladder that adoption belongs to ever runs - and with the
    // predecessor's par2 alive it wins the race every time. Measured on
    // origin/main, 28 Aug 2026: this test passed while its log read
    // "10 block(s) borrowed from a duplicate posting" and then "clean
    // download - no repair", so the adoption it is named for had not run
    // for as long as M31 had been in the tree, with the green tick
    // intact. `dupefill::donor_sets` fetches the donor's Par2Main OFF THE
    // WIRE - an NZB carries no digest, so that index is the only thing
    // that can say the two postings are the same bytes - so ghosting it
    // shuts that path out and leaves this one. The article donor gets
    // its own A/B below.
    //
    // **And the predecessor NAMES ITS MEMBERS DIFFERENTLY, which is what
    // keeps the A/B about disk now that dupefill reads a donor DIRECTORY
    // as well.** That arm proves a block straight out of the
    // predecessor's own file before opening a socket, and it finds that
    // file BY NAME - so with `f2.bin` in both posts it closed all ten
    // holes inside settle and the adoption this test is named for again
    // never ran (measured 28 Aug 2026, log read "10 off the
    // predecessor's own files"). Two posts of one release disagreeing
    // about a filename is the ordinary case, not a contrivance
    // (`nzbkit::dupedonor::match_by_content` pairs them by DIGEST for
    // exactly that reason), and it is precisely the shape whose general
    // answer is the sliding scan under test here.
    let mut p1 = Post::new();
    p1.add_ghost("f1p.bin", 80_000, 2, "p1f1");
    p1.add_holed("f2p.bin", &f2, "p1f2", &[1], &mut articles);
    for (i, (name, bytes)) in set_a.iter().enumerate() {
        p1.add_ghost(name, bytes.len() as u64, 1, &format!("p1par{i}"));
    }
    // The REPLACEMENT: f1 complete, f2 with a two-article hole
    // (80 KB = ten 8 KB blocks), its own one-block set. Alone it is
    // ten blocks short; the predecessor's f2 covers all ten.
    let mut p2 = Post::new();
    p2.add("f1.bin", &f1, "p2f1", &mut articles);
    p2.add_holed("f2.bin", &f2, "p2f2", &[2, 3], &mut articles);
    for (i, (name, bytes)) in set_b.iter().enumerate() {
        let mut p = Post::new();
        p.add(name, bytes, &format!("p2par{i}"), &mut articles);
        p2.files.extend(p.files);
    }
    let p1_xml = p1.xml();
    let p2_xml = p2.xml();
    let srv = MockServer::start(articles, Chaos::default()).await;
    let addr = format!(
        "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
        srv.addr.ip(),
        srv.addr.port()
    );

    // ---- Leg A: the replacement alone, no predecessor to donate. ----
    let dir_a = base.join("leg-a");
    std::fs::create_dir_all(&dir_a).unwrap();
    let cfg_a = dir_a.join("config.json");
    std::fs::write(&cfg_a, &addr).unwrap();
    let da = serve(&dir_a, daemon_in(dir_a.clone(), cfg_a.clone())).await;
    let port_a = da.port;
    {
        let p2_xml = p2_xml.clone();
        tokio::task::spawn_blocking(move || {
            upload(port_a, &p2_xml, "Donor.Show.S05E01.1080p.nzb");
            let got = outcome(port_a, "1080p", 450).expect("leg A never settled");
            println!("§293 A/B leg A (no predecessor): the replacement post {got}");
            assert_eq!(
                got, "Failed",
                "leg A must fail - ten blocks short, one declared"
            );
        })
        .await
        .unwrap();
    }
    drop(da);

    // ---- Leg B: predecessor fails first, replacement is promoted ----
    // and adopts. Same posts, same mock, same damage.
    let dir_b = base.join("leg-b");
    std::fs::create_dir_all(&dir_b).unwrap();
    // ADOPTION IS THIS LEG, not an artefact of it. `adoptguard::
    // refuse_a_solve_that_solved_nothing` reads every daemon log at
    // teardown and refuses a repair that rebuilt zero blocks from parity
    // and adopted some - and this leg completes exactly `0 block(s)
    // rebuilt across 1 file(s), 10 block(s) adopted from
    // f2p.bin.nzbfast-partial`, which is the sentence the test is named
    // for. It cannot be otherwise: the successor declares ONE recovery
    // block against a ten-block hole, which is what leg A above proves
    // by failing on the same post with no predecessor to donate.
    crate::adoptguard::adoption_is_the_premise(
        &dir_b,
        "TODO 293 stage 2 IS the disk adoption scan - ten blocks short \
         against one declared recovery block, so no block of the hole \
         can come from parity and leg A fails on exactly that; the \
         predecessor's copy closing all ten is the assertion",
    );
    let cfg_b = dir_b.join("config.json");
    std::fs::write(&cfg_b, &addr).unwrap();
    let db = serve(&dir_b, daemon_in(dir_b.clone(), cfg_b.clone())).await;
    let port_b = db.port;
    tokio::task::spawn_blocking(move || {
        // Paused, so the second add is HELD as the duplicate of the
        // first (same episode key) before anything runs.
        http(port_b, "/api?mode=pause&output=json", None);
        upload(port_b, &p1_xml, "Donor.Show.S05E01.720p.nzb");
        upload(port_b, &p2_xml, "Donor.Show.S05E01.1080p.nzb");
        let q = http(port_b, "/api?mode=queue&output=json", None);
        assert!(
            any_held_behind_a_copy(&q),
            "the alternative was not held: {q}"
        );
        http(port_b, "/api?mode=resume&output=json", None);

        // The predecessor fails (its retry spends itself inside the
        // 5 s window), the promotion stamps alt_from, and the promoted
        // job's repair sees the predecessor's output as a donor.
        let got1 = outcome(port_b, "720p", 600).expect("the predecessor never settled");
        assert_eq!(got1, "Failed", "the predecessor must fail to donate");
        let got2 = outcome(port_b, "1080p", 600).expect("the replacement never settled");
        println!(
            "§293 A/B leg B (promoted after the predecessor): the replacement \
             post {got2}"
        );
        assert_eq!(
            got2, "Completed",
            "the same ten-block-short post must complete off the donor"
        );
    })
    .await
    .unwrap();
    // WHICH mechanism completed it, which the status alone cannot say.
    // Driven both ways on 28 Aug 2026: with the article donor disabled
    // outright this leg still read "Completed" off adoption, and with
    // the predecessor's par2 alive it read "Completed" off the article
    // donor with adoption never running - so an outcome assertion here
    // is satisfied by either path and pins neither.
    let lg = db.log();
    assert!(
        lg.contains("10 block(s) adopted from"),
        "leg B completed without adopting a block - this A/B is measuring \
         something else again:\n{lg}"
    );
    assert!(
        !lg.contains("borrowed from a duplicate posting"),
        "the article donor ran, so this leg is not the disk A/B it is named \
         for - see the fixture note on the predecessor's dead par2:\n{lg}"
    );
}

/// PLAN M31 stage 1, end to end on a real daemon job: the promoted
/// successor's own holes are filled from the failed predecessor's LIVE
/// ARTICLES, over the wire, before a single recovery block is spent.
///
/// # Why this is a separate test from the §293 A/B above
///
/// That one is about BYTES ON DISK - `par2repair::adopt` sliding over
/// the predecessor's output directory during repair. This one is about
/// ARTICLES, which is the case §293 has no path to at all: the bytes are
/// on nobody's disk, they are alive on the servers in a duplicate
/// posting precisely where ours are dead. Three doors carry that and,
/// until this test, not one of them had a caller outside production -
/// `serve::tasks::worker::predecessor_posting` (which NZBs count as
/// donors), `get::dupefill::wanted_files` (which slots are eligible) and
/// `get::dupefill::fill_from_duplicate_postings` (the door `settle`
/// calls). Each gets an assertion below, named where it is made.
///
/// # The fixture, and the one constraint that shapes all of it
///
/// The predecessor has to fail for a reason that is not "every article
/// is gone", or it has nothing to donate. Here the two posts are damaged
/// in DISJOINT places - which is M31's own motivating shape - so each
/// one's holes are the other's live articles:
///
/// | | f2.bin (160 KB) | f3.bin (120 KB) |
/// |---|---|---|
/// | predecessor, 4 KB blocks, 1 declared | part 1 dead (10 blocks) | part 1 dead (10 blocks) |
/// | successor, 8 KB blocks, 1 declared | parts 2-3 dead (10 blocks) | part 3 dead (5 blocks) |
///
/// # Two sources, one run - and the run proves them apart
///
/// The predecessor posts f3 under its own name, `f3p.bin`, and that one
/// difference is what makes this a test of BOTH halves of the donor
/// ladder rather than of whichever half happens to win.
///
/// `dupefill` reads a donor DIRECTORY before it opens a socket, and it
/// finds a member there by NAME. So f2 - spelled the same in both posts
/// - is served straight off the predecessor's own file, and f3 is not,
/// and the wire has to fetch it. Both halves are asserted, and the
/// second assertion is the sharper one: `<p1f2-2@mock>` and
/// `<p1f2-3@mock>` must NOT appear on the wire log, because those bytes
/// were already on local disk. Before the disk-first arm they were
/// fetched on every run - 82,781 of the successor's 336,335 wire bytes,
/// spent on bytes it already had.
///
/// Two posts of one release disagreeing about a filename is the
/// ordinary case rather than a contrivance:
/// `nzbkit::dupedonor::match_by_content` pairs members by DIGEST for
/// exactly that reason, and §293's repair-time adoption is name-blind
/// for it too.
///
/// Twenty blocks short against one declared block sinks the
/// predecessor; fifteen against one sinks the successor on its own,
/// which is leg A. Every byte the successor is missing is an article the
/// predecessor still has, and vice versa.
///
/// The predecessor's own hole in each file is load-bearing and is not
/// decoration: §305's plan-side arm takes a member off a donor WHOLE,
/// before the fetch, on the successor's own `FileDesc` MD5, and a
/// byte-perfect copy in the donor's output directory is exactly what
/// that arm takes. The successor would then have no hole at all and this
/// pass would correctly no-op while the test read green. One dead
/// article per file moves both that file's MD5 and its first-16k MD5,
/// so the whole-file arm refuses, and leaves every byte the successor's
/// holes need intact.
///
/// # What this test can NOT arrange, said out loud
///
/// It cannot make §293's repair-time adoption unavailable. A promotion
/// fires only on a GENUINE failure - `daemon_park::promote_held_alternative`
/// refuses a tombstone, which is what a user delete sets, and refuses
/// while an automatic retry is armed - so the predecessor must have RUN,
/// and a posting's live articles are on the disk of the job that fetched
/// them. All three sources therefore coexist on this shape.
///
/// What settles it is that they are not simultaneous: dupefill runs
/// inside settle, BEFORE the repair ladder that adoption belongs to, and
/// within dupefill the disk is read before the wire. So the assertions
/// below do not rest on the outcome. They rest on which of the donor's
/// message-ids reach the mock's wire log after the successor's fetch
/// began - f3's must, f2's must not - on the per-file borrow counts, on
/// the summary's split of the fifteen blocks into ten local and five
/// fetched, and on the job reporting `clean download - no repair`, which
/// says repair, and with it adoption, never ran at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_promoted_replacement_borrows_the_predecessors_live_articles_over_the_wire() {
    if !have_par2() {
        eprintln!("par2 not on PATH - skipping the M31 article-donor A/B");
        return;
    }
    let base = std::env::temp_dir().join(format!("nzbfast-dupefill-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&base);

    // Both files are exact multiples of the 40 KB article size and of
    // both block sizes, so a dead article is a whole number of bad
    // blocks and the counts asserted below are arithmetic rather than
    // an observation of one run.
    let f2 = payloads::unique_payload(160_000, 61);
    let f3 = payloads::unique_payload(120_000, 67);
    // The predecessor calls f3 something else, and that single
    // difference is what splits this run across BOTH donor sources -
    // see the "two sources, one run" block in the doc comment.
    let set_a = par2_set(
        &base.join("build-a"),
        &[("f2.bin", &f2[..]), ("f3p.bin", &f3[..])],
        4_000,
    );
    let set_b = par2_set(
        &base.join("build-b"),
        &[("f2.bin", &f2[..]), ("f3.bin", &f3[..])],
        8_000,
    );

    let mut articles = HashMap::new();
    // The PREDECESSOR. Its recovery volumes are ALIVE on purpose: the
    // pass fetches the donor's own recovery index to prove, by digest,
    // that the two postings are of the same bytes, and a donor whose
    // index cannot be read donates nothing.
    let mut p1 = Post::new();
    p1.add_holed("f2.bin", &f2, "p1f2", &[1], &mut articles);
    p1.add_holed("f3p.bin", &f3, "p1f3", &[1], &mut articles);
    for (i, (name, bytes)) in set_a.iter().enumerate() {
        let mut p = Post::new();
        p.add(name, bytes, &format!("p1par{i}"), &mut articles);
        p1.files.extend(p.files);
    }
    // The SUCCESSOR, damaged where the predecessor is whole.
    let mut p2 = Post::new();
    p2.add_holed("f2.bin", &f2, "p2f2", &[2, 3], &mut articles);
    p2.add_holed("f3.bin", &f3, "p2f3", &[3], &mut articles);
    for (i, (name, bytes)) in set_b.iter().enumerate() {
        let mut p = Post::new();
        p.add(name, bytes, &format!("p2par{i}"), &mut articles);
        p2.files.extend(p.files);
    }
    let p1_xml = p1.xml();
    let p2_xml = p2.xml();
    let srv = MockServer::start(articles, Chaos::default()).await;
    let addr = format!(
        "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
        srv.addr.ip(),
        srv.addr.port()
    );

    // ---- Leg A: the successor alone. Nothing to borrow from. ----
    let dir_a = base.join("leg-a");
    std::fs::create_dir_all(&dir_a).unwrap();
    let cfg_a = dir_a.join("config.json");
    std::fs::write(&cfg_a, &addr).unwrap();
    let da = serve(&dir_a, daemon_in(dir_a.clone(), cfg_a.clone())).await;
    let port_a = da.port;
    {
        let p2_xml = p2_xml.clone();
        tokio::task::spawn_blocking(move || {
            upload(port_a, &p2_xml, "Dupe.Show.S06E02.1080p.nzb");
            let got = outcome(port_a, "1080p", 450).expect("leg A never settled");
            println!("M31 A/B leg A (no predecessor): the successor post {got}");
            assert_eq!(
                got, "Failed",
                "leg A must fail - fifteen blocks short, one declared"
            );
        })
        .await
        .unwrap();
    }
    drop(da);
    // Leg A is now over, so everything past this index belongs to leg B.
    let mark = srv.body_log.lock().unwrap().len();

    // ---- Leg B: the predecessor fails first and donates. ----
    let dir_b = base.join("leg-b");
    std::fs::create_dir_all(&dir_b).unwrap();
    let cfg_b = dir_b.join("config.json");
    std::fs::write(&cfg_b, &addr).unwrap();
    let db = serve(&dir_b, daemon_in(dir_b.clone(), cfg_b.clone())).await;
    let port_b = db.port;
    tokio::task::spawn_blocking(move || {
        // Paused, so the second add is HELD as the duplicate of the
        // first (same episode key) before either runs.
        http(port_b, "/api?mode=pause&output=json", None);
        upload(port_b, &p1_xml, "Dupe.Show.S06E02.720p.nzb");
        upload(port_b, &p2_xml, "Dupe.Show.S06E02.1080p.nzb");
        let q = http(port_b, "/api?mode=queue&output=json", None);
        assert!(any_held_behind_a_copy(&q), "the spare was not held: {q}");
        http(port_b, "/api?mode=resume&output=json", None);

        let got1 = outcome(port_b, "720p", 600).expect("the predecessor never settled");
        assert_eq!(got1, "Failed", "the predecessor must fail to donate");
        let got2 = outcome(port_b, "1080p", 600).expect("the successor never settled");
        println!("M31 A/B leg B (promoted after the predecessor): the successor post {got2}");
        assert_eq!(
            got2, "Completed",
            "the same fifteen-block-short post must complete off the donor's articles"
        );
    })
    .await
    .unwrap();

    let lg = db.log();
    // `predecessor_posting`: the daemon offered the replaced post's own
    // NZB as an article donor. Its only other caller is production.
    assert!(
        lg.contains("available as an article donor"),
        "the predecessor's posting was never offered as a donor:\n{lg}"
    );
    // `wanted_files`: BOTH damaged slots resolved their report's
    // `par2_name` inside the set they were handed and found a real file
    // on disk. A slot it refused would not be counted here, so the
    // "2 file(s)" is that resolution and not just the damage.
    assert!(
        lg.contains(
            "🔎 15 bad block(s) across 2 file(s) - looking for them in 1 duplicate posting(s)"
        ),
        "the pass did not see both holed files, or saw no donor:\n{lg}"
    );
    // `fill_wanted`: bytes landed, per file, each block having matched
    // the TARGET set's own MD5 and CRC32 before its positioned write.
    for want in [
        "✔ f2.bin: 10 block(s) borrowed from a duplicate posting",
        "✔ f3.bin: 5 block(s) borrowed from a duplicate posting",
    ] {
        assert!(lg.contains(want), "missing {want:?} in:\n{lg}");
    }
    // ...and the job's own summary, which is where the SPLIT is stated:
    // f2's ten blocks came off the predecessor's own files and f3's
    // five off the wire. `0 article(s) fetched` would mean the wire
    // half never ran, which on this shape is the one thing that must
    // not read as a pass.
    assert!(
        lg.contains(
            "🤝 recovered 15 block(s) from a duplicate posting (10 off the \
             predecessor's own files,"
        ),
        "the job did not report the ten-block local half of the borrow:\n{lg}"
    );
    assert!(
        !lg.contains("0 article(s) fetched"),
        "the borrow claims no donor article was fetched, so the wire half \
         never ran:\n{lg}"
    );
    // Nothing else did the work. Repair is where §293's block adoption
    // lives, and the successor never reached it: the fill closed every
    // hole inside settle, which is also the only way `whole_files_proved`
    // can have fired - without that subtraction a job whose every byte
    // was healed still fails on its article count.
    assert!(
        lg.contains("clean download - no repair"),
        "repair ran, so the completion is not this pass's:\n{lg}"
    );

    // The wire proof, independent of every log string above. The
    // predecessor's runs - its first attempt AND the automatic retry
    // that has to be spent before a promotion can happen at all - are
    // strictly before the successor starts, so a `<p1` id asked for
    // after the successor's first request can only be the donor fetch.
    let asked: Vec<String> = srv.body_log.lock().unwrap().iter().cloned().collect();
    let tail = &asked[mark.min(asked.len())..];
    let first_p2 = tail
        .iter()
        .position(|id| id.starts_with("<p2"))
        .expect("the successor never asked for an article of its own");
    let after: &[String] = &tail[first_p2..];
    // f3 is the file the predecessor spells differently, so its blocks
    // are the ones the disk cannot serve and the wire must.
    assert!(
        after.contains(&"<p1f3-3@mock>".to_string()),
        "<p1f3-3@mock> was never fetched from the donor posting - the fill \
         did not reach the wire. Asked after the successor started: {after:?}"
    );
    // AND THE OTHER HALF, which is the whole of what the disk-first arm
    // is worth: f2's ten blocks were on the predecessor's own disk, so
    // not one of its articles may be asked for. Before that arm these
    // two were fetched on every run of this test - 82,781 bytes of the
    // successor's 336,335, for bytes it already had.
    for id in ["<p1f2-2@mock>", "<p1f2-3@mock>"] {
        assert!(
            !after.contains(&id.to_string()),
            "{id} was fetched over the wire, but the predecessor's own file \
             holds those bytes - the disk-first arm did not run. Asked after \
             the successor started: {after:?}"
        );
    }
}

/// PLAN M31 item 4: a store-RAR release is REACHED by the article fill
/// now, and borrows its blocks with no recovery block spent.
///
/// **This test used to assert the opposite, and that is the point.**
/// TODO 316 wrote it to pin a real defect: the fill was INERT on a
/// store-RAR release and §293's disk adoption completed the job
/// instead, so a status-only reading scored an M31 pass it never
/// earned. The cause chain it measured was TWO independent gates -
/// `Extractor::is_mapped` refuses a `SlotMode::Rar` volume, and with
/// that patched out the fill still found no file, because a mapped
/// slot owns none. It ended by saying that a lane lifting only the
/// first would find the pass still doing nothing, and that this test
/// was the thing to UPDATE rather than delete.
///
/// So it is updated. Both gates fall to the SECOND ENTRY POINT
/// (`get::settle::fill_from_duplicates_off_materialized_volumes`),
/// which runs the same pass again on the volumes the repair has just
/// materialized - by which point the slot is `SlotMode::RarFallback`
/// with a writer behind it, so neither gate is reachable and not one
/// of the pass's own rules had to move. That function's header carries
/// the argument for the placement and for what it gives up.
///
/// Its sibling above,
/// `a_promoted_replacement_borrows_the_predecessors_live_articles_over_the_wire`,
/// is this shape with a PLAIN payload, where the fill runs at the
/// FIRST entry point inside settle. The two together are what say the
/// payload shape is no longer the difference.
///
/// The sharp assertions are the ordering ones. "Completed" on its own
/// means nothing here - that is precisely the reading TODO 316 caught
/// - so the borrow must happen AFTER a materialize (or it is not this
/// entry point at all), and the disk repair must find nothing left to
/// do (or the borrow did not close the holes and something else
/// finished the job).
#[tokio::test(flavor = "multi_thread")]
async fn a_store_rar_release_is_reached_by_the_article_fill_once_its_volume_is_a_file() {
    if !have_par2() {
        eprintln!("par2 not on PATH - skipping the store-RAR donor probe");
        return;
    }
    let base = std::env::temp_dir().join(format!("nzbfast-rarfill-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&base);

    // One store RAR volume carrying the payload, posted as a real
    // release is: the slot the verifier settles is the VOLUME, and the
    // extractor maps it rather than writing it out.
    let movie = payloads::unique_payload(240_000, 71);
    let rar = nzbkit::rar::fixtures::rar5_volume(&[(
        "movie.bin",
        movie.len() as u64,
        &movie[..],
        false,
        false,
    )]);
    let files: &[(&str, &[u8])] = &[("release.rar", &rar)];
    // Two independent sets over the same bytes, one recovery block
    // each - the damage below is ten blocks, so neither post can
    // repair itself and only a donor could bridge it.
    let set_a = par2_set(&base.join("build-a"), files, 4_000);
    let set_b = par2_set(&base.join("build-b"), files, 8_000);

    let mut articles = HashMap::new();
    // Disjoint damage, both holes MID-STREAM: part 1 stays alive in
    // both posts on purpose, so neither volume loses its header and
    // spills to a plain slot for a reason that is not the one under
    // test.
    let mut p1 = Post::new();
    p1.add_holed("release.rar", &rar, "p1r", &[2], &mut articles);
    for (i, (name, bytes)) in set_a.iter().enumerate() {
        let mut p = Post::new();
        p.add(name, bytes, &format!("p1par{i}"), &mut articles);
        p1.files.extend(p.files);
    }
    let mut p2 = Post::new();
    p2.add_holed("release.rar", &rar, "p2r", &[3, 4], &mut articles);
    for (i, (name, bytes)) in set_b.iter().enumerate() {
        let mut p = Post::new();
        p.add(name, bytes, &format!("p2par{i}"), &mut articles);
        p2.files.extend(p.files);
    }
    let p1_xml = p1.xml();
    let p2_xml = p2.xml();
    let srv = MockServer::start(articles, Chaos::default()).await;
    let addr = format!(
        "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
        srv.addr.ip(),
        srv.addr.port()
    );

    let dir = base.join("leg");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, &addr).unwrap();
    let d = serve(&dir, daemon_in(dir.clone(), cfg.clone())).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        http(port, "/api?mode=pause&output=json", None);
        upload(port, &p1_xml, "Rar.Show.S06E02.720p.nzb");
        upload(port, &p2_xml, "Rar.Show.S06E02.1080p.nzb");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(any_held_behind_a_copy(&q), "the spare was not held: {q}");
        http(port, "/api?mode=resume&output=json", None);
        assert_eq!(
            outcome(port, "720p", 600).expect("the predecessor never settled"),
            "Failed",
            "the predecessor must fail to donate"
        );
        assert_eq!(
            outcome(port, "1080p", 600).expect("the successor never settled"),
            "Completed",
            "the successor completes on this shape - off DISK, per the assertions below"
        );
    })
    .await
    .unwrap();

    let lg = d.log();
    // The donor WAS offered, so what follows is about `wanted_files`
    // and not about the donor source having declined to fire.
    assert!(
        lg.contains("available as an article donor"),
        "the predecessor's posting was never offered as a donor:\n{lg}"
    );
    // ...and this time the fill reached it. `fill_wanted` returns
    // before logging anything when `wanted` is empty, so the PRESENCE
    // of this line is the whole signal that `wanted_files` resolved
    // the slot at all - there is no "0 files" line to look for.
    let ask = lg
        .find("bad block(s) across")
        .unwrap_or_else(|| panic!("the article fill never ran:\n{lg}"));
    let borrow = lg
        .find("borrowed from a duplicate posting")
        .unwrap_or_else(|| panic!("the fill ran and borrowed nothing:\n{lg}"));
    // THE ORDERING, which is what says this is the SECOND entry point
    // and not some widening of the first. A mapped volume is only a
    // file after the repair materializes it, so the ask has to come
    // after that line - and if the fill ever learns to feed the
    // extractor directly, this is the assertion to move rather than
    // the one to delete.
    //
    // The SUCCESSOR's materialize, anchored off the line below rather
    // than off `lg.find`. **This log holds BOTH jobs**, and the
    // predecessor is this same shape - a mapped RAR volume, ten blocks
    // of damage, one recovery block - so it materializes too, hundreds
    // of lines earlier. `lg.find` therefore returned the PREDECESSOR's
    // materialize, which is before everything the successor ever logs,
    // and `mat < ask` was very nearly vacuous: it could not have failed
    // however late the successor's own materialize ran. Found 1 Sep
    // 2026 by the assertion below tripping over it (the unexamined line
    // reads AFTER a materialize that belongs to the other job), and
    // fixed here rather than left, because a weak assertion in a test
    // whose whole subject is ORDERING is the kind that reads as cover
    // and is not.
    let unlooked = lg
        .find("damaged block(s) in 1 file(s) unexamined")
        .unwrap_or_else(|| {
            panic!("the first entry point walked past a mapped slot in silence:\n{lg}")
        });
    let mat = lg[unlooked..]
        .find("materializing volumes for repair")
        .map(|i| i + unlooked)
        .unwrap_or_else(|| panic!("the volume was never materialized:\n{lg}"));
    assert!(
        mat < ask && ask < borrow,
        "the borrow did not happen on a materialized volume \
         (materialize {mat}, ask {ask}, borrow {borrow}):\n{lg}"
    );
    // ...and the FIRST entry point said out loud that it was walking
    // past this damage, BEFORE that materialize. That line is the only
    // thing in the tree that can distinguish "the pass looked and found
    // nothing" from "the pass never looked", and this shape - a mapped
    // RAR volume, which is most real releases - is exactly the one
    // where the two used to be indistinguishable. Pinned HERE because
    // this is the one existing fixture that produces a mapped slot with
    // damage; the unit rig next door
    // (`dupefill_scope_tests::the_unexamined_tally_counts_only_the_mapped_skip`)
    // builds its Extractor disabled and can only pin the zero arm.
    //
    // The COUNT is asserted in the string and is not incidental: ten
    // blocks is the successor's whole damage, so this says the first
    // entry point walked past ALL of it - which is what makes the
    // second entry point load-bearing on this shape rather than a
    // belt-and-braces second look.
    assert!(
        unlooked < mat,
        "the unexamined-damage line came after the successor's own \
         materialize, so it is the second entry point reporting a failed \
         materialize rather than the first reporting the mapped skip \
         (unlooked {unlooked}, materialize {mat}):\n{lg}"
    );
    // And no recovery block was spent closing those holes: the fill
    // ran BEFORE the disk repair, which then found the set already
    // whole. Without this, "Completed" would say nothing about which
    // mechanism did it - TODO 316's own lesson, one line up.
    assert!(
        lg.contains("set already verifies on disk"),
        "the disk repair still had work to do, so the borrow did not \
         close the holes:\n{lg}"
    );
    assert!(
        !lg.contains("block(s) adopted from"),
        "§293's adoption ran, so this completion is not the fill's:\n{lg}"
    );
    // And the BYTES, independent of every log string above. The pass
    // writes its healed blocks straight into the materialized volume
    // with a positioned write, while the extractor still owns that
    // file - the same thing it already does to a plain slot's live
    // writer at the first entry point, but worth proving once at the
    // far end of the pipeline rather than reasoning about: the volume
    // is re-extracted after the repair, so this is the borrowed bytes
    // having survived the write, the verify AND the unpack.
    let got = std::fs::read(
        dir.join("complete")
            .join("Rar.Show.S06E02.1080p")
            .join("movie.bin"),
    )
    .expect("extracted payload");
    assert_eq!(got, movie, "the extracted payload is not byte-exact");
}

/// The duplicate-donor pass over a post that ships ONE RECOVERY SET PER
/// FILE, which until 31 Aug 2026 nothing exercised anywhere.
///
/// # Why this fixture had to be built
///
/// `dupefill::FILL_BUDGET` and `MAX_FILL_BYTES` were created INSIDE
/// `fill_wanted`, which `settle::fill_from_duplicates` calls once per
/// recovery set - so both ceilings were per SET where `FILL_BUDGET`'s
/// own doc comment says "the whole pass". On GH #63's eighteen-set post
/// an unreachable donor cost eighteen 90-second waits at each of the
/// two entry points rather than one, and the number of sets is the
/// POSTER's choice, so the cost was bounded by nothing this end
/// controls. `research/DUPEFILL-CALIBRATION-2026-08-31.md` measured
/// that from the code and said so: no multi-set donor fixture existed
/// to run it on. `tests/e2e_multiset` has the multi-set shape and no
/// donor; `daemon_donor`'s two siblings above have the donor and one
/// set. This is the crossing.
///
/// # What it pins, and what it deliberately does not
///
/// It pins that the pass RUNS ON EVERY SET of a multi-set post off ONE
/// shared budget: three `🔎` lines, one per set, and fifteen blocks
/// borrowed across the three, with no truncation line. That is the
/// regression the scope fix could plausibly have caused - a shared
/// budget can starve a later set where a per-set one could not - and it
/// is the half a unit test over `fill_wanted` cannot reach, because the
/// budget is created by the CALLER's loop.
///
/// It does NOT pin the sharing itself. Seeing a later set refused needs
/// a budget that is actually spent, which is 90 seconds or 256 MiB, and
/// neither is reachable on a mock. The sharing is pinned deterministically
/// one level down, in `get::dupefill::dupefill_tests` -
/// `two_sets_of_one_pass_spend_one_budget_between_them` and
/// `a_set_arriving_on_a_spent_budget_asks_for_nothing_and_says_which_ceiling`.
/// The division is the usual one in this repo: the cheap portable check
/// holds the mechanism, the expensive one holds the wiring.
///
/// # The fixture
///
/// Three 120 KB files, three articles each at the harness's 40 KB, and
/// one independent recovery set per file in BOTH posts at different
/// block sizes - so no checksum is shared between a target set and a
/// donor set and every match is by content.
///
/// | | f1/f2/f3, 4 KB blocks, 1 declared | dead |
/// |---|---|---|
/// | predecessor | 30 blocks per file | part 1 (10 blocks) |
/// | successor, 8 KB blocks | 15 blocks per file | part 3 (5 blocks) |
///
/// The holes are DISJOINT, so each post's damage is the other's live
/// articles. Five blocks short against one declared sinks each of the
/// successor's three sets, so the fifteen blocks it borrows are fifteen
/// it could not otherwise have had; there is no separate leg A because
/// that arithmetic is the argument and the sibling above already
/// carries the A/B for the one-set case.
///
/// **The predecessor names every member differently** (`f1p.bin` for
/// `f1.bin`), which is what puts this test on the WIRE. `dupefill`
/// reads a donor DIRECTORY first and finds a member there by NAME, so
/// same-named files would be served off the predecessor's own disk and
/// the budget - a bound on wire work - would never be exercised at all.
/// Two posts of one release disagreeing about a filename is the
/// ordinary case rather than a contrivance:
/// `nzbkit::dupedonor::match_by_content` pairs members by DIGEST for
/// exactly that reason.
///
/// The predecessor's own hole in each file is load-bearing the same way
/// it is in the sibling above: §305's plan-side arm takes a donor
/// member WHOLE on the successor's own `FileDesc` MD5, and a
/// byte-perfect copy is exactly what that arm takes, leaving this pass
/// nothing to do while the test read green.
///
/// # THE DONOR SHIPS ONE SET PER FILE TOO, since 31 Aug 2026
///
/// It shipped ONE set over all three files for its first hours, and had
/// to: `dupefill::donor_sets` adopted the LARGEST donor set only (TODO
/// 311's last box), so a DONOR that ships one set per file donated for
/// exactly one target set and no other. Measured on this very fixture
/// the day it was built - with a per-file donor, `f1` borrowed its five
/// blocks and the other two sets logged "a duplicate posting of a
/// DIFFERENT encode - no byte range in common", then completed off
/// §293's repair-time adoption instead, so the run read GREEN while two
/// thirds of the pass under test had not happened.
///
/// So the assertions below are now over BOTH halves at once, which is
/// GH #63's exact shape: `donor_sets` probes every `Par2Main` in the
/// donor NZB and `dupedonor::match_by_content_multi` pairs across all
/// of them under one claim per target file. Run against the
/// largest-set-only rule this test heals FIVE blocks and not fifteen -
/// the `✔ f2.bin` and `✔ f3.bin` lines are what go missing, and they
/// are asserted individually for that reason.
#[tokio::test(flavor = "multi_thread")]
async fn the_fill_runs_on_every_recovery_set_of_a_multi_set_post_off_one_budget() {
    if !have_par2() {
        eprintln!("par2 not on PATH - skipping the multi-set donor fixture");
        return;
    }
    let base = std::env::temp_dir().join(format!("nzbfast-multiset-donor-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&base);

    // Exact multiples of the 40 KB article size and of both block
    // sizes, so a dead article is a whole number of bad blocks and
    // every count asserted below is arithmetic rather than an
    // observation of one run.
    let f1 = payloads::unique_payload(120_000, 71);
    let f2 = payloads::unique_payload(120_000, 73);
    let f3 = payloads::unique_payload(120_000, 79);
    // ONE INDEPENDENT SET PER FILE on the donor side as well, which is
    // what makes both posts GH #63's shape rather than only the
    // successor. See the doc comment: this was one joined set until the
    // largest-set-only rule was lifted.
    let set_a = par2_set_per_file(
        &base.join("build-a"),
        &[
            ("f1p.bin", &f1[..]),
            ("f2p.bin", &f2[..]),
            ("f3p.bin", &f3[..]),
        ],
        4_000,
    );
    let set_b = par2_set_per_file(
        &base.join("build-b"),
        &[
            ("f1.bin", &f1[..]),
            ("f2.bin", &f2[..]),
            ("f3.bin", &f3[..]),
        ],
        8_000,
    );
    for (which, built) in [("donor", &set_a), ("target", &set_b)] {
        assert!(
            built.len() >= 3,
            "the {which} post needs three independent sets, so at least three \
             index files: {:?}",
            built.iter().map(|(n, _)| n).collect::<Vec<_>>()
        );
    }

    let mut articles = HashMap::new();
    // The PREDECESSOR. Its recovery volumes are ALIVE on purpose: the
    // pass fetches a donor's own recovery index to prove by digest that
    // the two postings are of the same bytes, and a donor whose index
    // cannot be read donates nothing.
    let mut p1 = Post::new();
    for (i, (name, data)) in [("f1p.bin", &f1), ("f2p.bin", &f2), ("f3p.bin", &f3)]
        .iter()
        .enumerate()
    {
        p1.add_holed(name, data, &format!("p1f{i}"), &[1], &mut articles);
    }
    for (i, (name, bytes)) in set_a.iter().enumerate() {
        p1.add(name, bytes, &format!("p1par{i}"), &mut articles);
    }
    // The SUCCESSOR, damaged where the predecessor is whole.
    let mut p2 = Post::new();
    for (i, (name, data)) in [("f1.bin", &f1), ("f2.bin", &f2), ("f3.bin", &f3)]
        .iter()
        .enumerate()
    {
        p2.add_holed(name, data, &format!("p2f{i}"), &[3], &mut articles);
    }
    for (i, (name, bytes)) in set_b.iter().enumerate() {
        p2.add(name, bytes, &format!("p2par{i}"), &mut articles);
    }
    let p1_xml = p1.xml();
    let p2_xml = p2.xml();
    let srv = MockServer::start(articles, Chaos::default()).await;
    let addr = format!(
        "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
        srv.addr.ip(),
        srv.addr.port()
    );

    let dir = base.join("run");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, &addr).unwrap();
    let d = serve(&dir, daemon_in(dir.clone(), cfg.clone())).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        // Paused, so the second add is HELD as the duplicate of the
        // first (same episode key) before either runs.
        http(port, "/api?mode=pause&output=json", None);
        upload(port, &p1_xml, "Multi.Show.S01E01.720p.nzb");
        upload(port, &p2_xml, "Multi.Show.S01E01.1080p.nzb");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(any_held_behind_a_copy(&q), "the spare was not held: {q}");
        http(port, "/api?mode=resume&output=json", None);

        let got1 = outcome(port, "720p", 600).expect("the predecessor never settled");
        assert_eq!(got1, "Failed", "the predecessor must fail to donate");
        let got2 = outcome(port, "1080p", 600).expect("the successor never settled");
        println!("multi-set donor: the successor post {got2}");
        assert_eq!(
            got2, "Completed",
            "fifteen blocks across three sets, one declared block each - only \
             the donor can have closed them"
        );
    })
    .await
    .unwrap();

    let lg = d.log();
    // THE MULTI-SET ASSERTION. `fill_from_duplicates` loops over the
    // job's adopted sets and each set's pass opens with this line, so
    // three of them is the pass having run on all three sets - off the
    // one budget the loop now creates outside itself.
    let passes = lg
        .matches("bad block(s) across 1 file(s) - looking for them in 1 duplicate posting(s)")
        .count();
    assert_eq!(
        passes, 3,
        "the pass ran on {passes} recovery set(s), not on all three:\n{lg}"
    );
    // ...and every one of them borrowed, which a per-set count alone
    // would not say: a set the pass opened and then did nothing for
    // would still print the line above.
    for f in ["f1.bin", "f2.bin", "f3.bin"] {
        assert!(
            lg.contains(&format!(
                "✔ {f}: 5 block(s) borrowed from a duplicate posting"
            )),
            "{f} borrowed nothing, so one of the three sets was not served:\n{lg}"
        );
    }
    // The job's own summary, over the SUM of the three sets' reports.
    // `0 off the predecessor's own files` is the fixture's differing
    // member names doing their job: every block came off the wire, so
    // the budget this test exists for was actually exercised.
    assert!(
        lg.contains(
            "🤝 recovered 15 block(s) from a duplicate posting (0 off the \
             predecessor's own files,"
        ),
        "the summary does not report fifteen wire-borrowed blocks:\n{lg}"
    );
    // The wire cost, reported apart from the accepted bytes since
    // 31 Aug 2026 - it is the quantity `MAX_FILL_BYTES` caps, and
    // nothing returned it before, so no field install could say what
    // either ceiling should be.
    assert!(
        lg.contains(" MB off the wire of which "),
        "the summary does not split the wire cost from the bytes that \
         landed:\n{lg}"
    );
    // A LOWER BOUND and deliberately not an equality. One article covers
    // each file's whole five-block hole, so three is the floor - but the
    // first ask of a plan is BLIND (an NZB states encoded sizes and no
    // offsets), so a hole at an article's edge can pull one extra body
    // before `candidate_segments_anchored` re-cuts the rest against it.
    // Four is what this fixture actually pulls; pinning that number
    // would pin the estimator's slack rather than the wire half's reach.
    let fetched: usize = {
        let at = lg.find(" article(s) fetched").expect("the summary line");
        lg[..at]
            .rsplit(' ')
            .next()
            .and_then(|t| t.parse().ok())
            .expect("article count")
    };
    assert!(
        fetched >= 3,
        "{fetched} article(s) fetched for three sets - the wire half did not \
         run for every one of them:\n{lg}"
    );
    // The two figures are different quantities and must be reported as
    // such; that they can DIFFER is pinned exactly one level down, in
    // `dupefill_tests::the_reported_wire_cost_is_the_quantity_the_byte_ceiling_caps`,
    // because on this fixture the damage is article-aligned so every
    // fetched byte lands and the two differ only by the yEnc overhead.
    let (wire, landed) = {
        let at = lg
            .find(" MB off the wire of which ")
            .expect("the split line");
        let head: f64 = lg[..at]
            .rsplit(' ')
            .next()
            .and_then(|t| t.parse().ok())
            .expect("wire figure");
        let rest = &lg[at + " MB off the wire of which ".len()..];
        let tail: f64 = rest
            .split(' ')
            .next()
            .and_then(|t| t.parse().ok())
            .expect("landed figure");
        (head, tail)
    };
    assert!(
        wire >= landed,
        "the wire cost ({wire}) cannot be below the bytes that landed \
         ({landed}) - every landed byte was pulled over the wire"
    );
    // THE REGRESSION GUARD for the shared budget: three sets served off
    // one 90-second, 256 MiB budget must not truncate. A run that did
    // would say so here, and this line is the one thing that would fire
    // if the shared budget ever became too small for a healthy donor.
    assert!(
        !lg.contains("the duplicate-posting pass stopped on"),
        "one budget was not enough for three sets of a HEALTHY donor - the \
         shared-budget trade needs re-reading:\n{lg}"
    );
    // Nothing else did the work: repair is where §293's block adoption
    // lives and the successor never reached it.
    assert!(
        lg.contains("clean download - no repair"),
        "repair ran, so the completion is not this pass's:\n{lg}"
    );
}
