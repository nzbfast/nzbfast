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
    let f1 = payload(80_000, 51);
    let f2 = payload(160_000, 53);
    let files: &[(&str, &[u8])] = &[("f1.bin", &f1), ("f2.bin", &f2)];
    // Two independent recovery sets over the same bytes: different
    // block sizes mean different set ids and zero shared checksums.
    let set_a = par2_set(&base.join("build-a"), files, 4_000);
    let set_b = par2_set(&base.join("build-b"), files, 8_000);

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
    let mut p1 = Post::new();
    p1.add_ghost("f1.bin", 80_000, 2, "p1f1");
    p1.add_holed("f2.bin", &f2, "p1f2", &[1], &mut articles);
    for (i, (name, bytes)) in set_a.iter().enumerate() {
        let mut p = Post::new();
        p.add(name, bytes, &format!("p1par{i}"), &mut articles);
        p1.files.extend(p.files);
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

    let daemon_in = |dir: &std::path::Path, cfg: &std::path::Path| {
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
                .arg("2");
            c
        }
    };
    let upload = |port: u16, xml: &str, fname: &str| {
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
    };
    let outcome = |port: u16, name_frag: &str, tries: u32| -> Option<String> {
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
    };

    // ---- Leg A: the replacement alone, no predecessor to donate. ----
    let dir_a = base.join("leg-a");
    std::fs::create_dir_all(&dir_a).unwrap();
    let cfg_a = dir_a.join("config.json");
    std::fs::write(&cfg_a, &addr).unwrap();
    let da = serve(&dir_a, daemon_in(&dir_a, &cfg_a)).await;
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
    let cfg_b = dir_b.join("config.json");
    std::fs::write(&cfg_b, &addr).unwrap();
    let db = serve(&dir_b, daemon_in(&dir_b, &cfg_b)).await;
    let port_b = db.port;
    tokio::task::spawn_blocking(move || {
        // Paused, so the second add is HELD as the duplicate of the
        // first (same episode key) before anything runs.
        http(port_b, "/api?mode=pause&output=json", None);
        upload(port_b, &p1_xml, "Donor.Show.S05E01.720p.nzb");
        upload(port_b, &p2_xml, "Donor.Show.S05E01.1080p.nzb");
        let q = http(port_b, "/api?mode=queue&output=json", None);
        assert!(
            q.contains("\"Duplicate\""),
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
    let _ = std::fs::remove_dir_all(&base);
}
