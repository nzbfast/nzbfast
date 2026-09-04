//! The settle manifest, end to end: a real job through a real daemon
//! leaves a `.nzbfast.manifest` that convicts damage after the PAR2
//! files are gone.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//!
//! The PAR2 set is SYNTHESIZED (Main + FileDesc + IFSC packets, no
//! recovery slices) rather than shelled out to `par2 create`, because
//! verification metadata is all the manifest capture needs and the
//! external binary is not on every box - this test runs everywhere the
//! suite does. The packet builder is the same shape as
//! `nzbkit::par2`'s own `pkt` test helper.
//!
//! The A/B this drives, printed: after completion the `.par2` members
//! are gone (the cleanup default), so the PAR2 verify path has nothing
//! to read - and `nzbfast verify` still convicts a flipped byte,
//! through the manifest. The not-hinder arm: with the setting turned
//! OFF, an identical job leaves no manifest and nothing else changes.
//!
//! THE LIVE ARM SETS NOTHING, and that is the point of it since §310
//! flipped `write_manifest` on (2 Sep 2026): the first job runs on the
//! SHIPPED configuration, so this is also the pin that fails if the
//! default is ever quietly reverted. The off arm still stores the flag
//! explicitly, so it stays a genuine control rather than becoming a
//! second copy of the treatment arm - the failure mode a default flip
//! reliably produces (memory topic
//! `nzbfast-default-flip-control-arm-trap`).

use super::*;

const BLOCK: usize = 4096;

fn md5_of(b: &[u8]) -> [u8; 16] {
    use md5::Digest;
    md5::Md5::digest(b).into()
}

/// Wrap a body in a valid packet header (magic, length, body MD5).
fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(b"PAR2\0PKT");
    p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(&set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let md5 = md5_of(&p[32..]);
    p[16..32].copy_from_slice(&md5);
    p
}

/// A minimal, honest verification-only PAR2 index over one file:
/// real whole-file MD5, real md5-16k, real per-block MD5+CRC32 with
/// the last block zero-padded, no recovery slices.
fn par2_index_over(name: &str, data: &[u8]) -> Vec<u8> {
    let set_id = [7u8; 16];
    let fid = [9u8; 16];

    let mut main = Vec::new();
    main.extend_from_slice(&(BLOCK as u64).to_le_bytes());
    main.extend_from_slice(&1u32.to_le_bytes());
    main.extend_from_slice(&fid);

    let mut desc = Vec::new();
    desc.extend_from_slice(&fid);
    desc.extend_from_slice(&md5_of(data));
    desc.extend_from_slice(&md5_of(&data[..data.len().min(16384)]));
    desc.extend_from_slice(&(data.len() as u64).to_le_bytes());
    desc.extend_from_slice(name.as_bytes());
    // Null-padded to a multiple of 4, per spec - the scanner holds every
    // packet length to that, so an unpadded name drops the whole
    // FileDesc and with it the file.
    while !desc.len().is_multiple_of(4) {
        desc.push(0);
    }

    let mut ifsc = Vec::new();
    ifsc.extend_from_slice(&fid);
    for chunk in data.chunks(BLOCK) {
        let mut padded = chunk.to_vec();
        padded.resize(BLOCK, 0);
        ifsc.extend_from_slice(&md5_of(&padded));
        let mut h = crc32fast::Hasher::new();
        h.update(&padded);
        ifsc.extend_from_slice(&h.finalize().to_le_bytes());
    }

    let mut buf = pkt(set_id, b"PAR 2.0\0Main\0\0\0\0", &main);
    buf.extend(pkt(set_id, b"PAR 2.0\0FileDesc", &desc));
    buf.extend(pkt(set_id, b"PAR 2.0\0IFSC\0\0\0\0", &ifsc));
    buf
}

/// One completed job with the setting on leaves a manifest that
/// convicts a flipped byte after the .par2 is gone; the same job with
/// the setting at its default leaves nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_settled_job_leaves_a_manifest_that_convicts_later_damage() {
    let dir = std::env::temp_dir().join(format!("nzbfast-manifest-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(96_000, 23);
    let par2 = par2_index_over("payload.bin", &data);

    let build_articles = |tag: &str| {
        let mut articles = HashMap::new();
        let a = make_file_articles(
            "payload.bin",
            &data,
            32_000,
            &format!("{tag}p"),
            &mut articles,
        );
        let b = make_file_articles(
            "testset.par2",
            &par2,
            32_000,
            &format!("{tag}r"),
            &mut articles,
        );
        (articles, a, b)
    };

    let nzb_for = |a: &Vec<(String, u64, u32)>, b: &Vec<(String, u64, u32)>| {
        let mut x = String::from(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        for (file, segs) in [("payload.bin", a), ("testset.par2", b)] {
            x.push_str(&format!(
                "  <file poster=\"x\" date=\"0\" subject=\"&quot;{file}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
                segs.len()
            ));
            for (id, bytes, num) in segs.iter() {
                x.push_str(&format!(
                    "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
                ));
            }
            x.push_str("    </segments>\n  </file>\n");
        }
        x.push_str("</nzb>\n");
        x
    };

    let (articles, seg_a, seg_b) = build_articles("mf");
    let xml = nzb_for(&seg_a, &seg_b);
    let srv = MockServer::start(articles, Chaos::default()).await;

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
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
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
    })
    .await;
    let port = d.port;

    let complete_root = dir.join("complete");
    tokio::task::spawn_blocking(move || {
        let set = |name: &str, value: &str| {
            let r = http(
                port,
                &format!("/api?mode=config&name={name}&value={value}&output=json"),
                None,
            );
            assert!(r.contains("\"status\":true"), "set {name}: {r}");
        };
        let upload = |fname: &str, xml: &str| -> String {
            let boundary = "----mfb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .map(|s| format!("SABnzbd_nzo_{s}"))
                .expect("addfile returned no nzo_id")
        };
        let completed = |id: &str| -> bool {
            let h = http(port, "/api?mode=history&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&h).unwrap_or(serde_json::Value::Null);
            v["history"]["slots"].as_array().is_some_and(|s| {
                s.iter()
                    .any(|x| x["nzo_id"] == id && x["status"] == "Completed")
            })
        };
        let wait_completed = |id: &str| {
            for _ in 0..300 {
                if completed(id) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("job {id} never completed");
        };
        let job_dir = |stem: &str| -> std::path::PathBuf {
            std::fs::read_dir(&complete_root)
                .expect("complete/ exists")
                .flatten()
                .map(|e| e.path())
                .find(|p| {
                    p.is_dir()
                        && p.file_name()
                            .is_some_and(|n| n.to_string_lossy().contains(stem))
                })
                .unwrap_or_else(|| panic!("no completed dir for {stem}"))
        };
        let verify_exit = |dir: &std::path::Path| -> i32 {
            Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                .arg("verify")
                .arg(dir)
                .status()
                .expect("verify ran")
                .code()
                .unwrap_or(-1)
        };

        // ---- The arm live: the SHIPPED default, set by nobody ----
        let first = upload("Manifested.Job.nzb", &xml);
        wait_completed(&first);
        let jd = job_dir("Manifested");
        let mpath = jd.join(".nzbfast.manifest");
        assert!(
            mpath.is_file(),
            "the shipped default must write a manifest: none in {}",
            jd.display()
        );

        // The post-cleanup state: whatever .par2 members survived the
        // sweeps are removed, exactly what the cleanup default leaves.
        for e in std::fs::read_dir(&jd).unwrap().flatten() {
            if e.path().extension().is_some_and(|x| x == "par2") {
                std::fs::remove_file(e.path()).unwrap();
            }
        }
        assert_eq!(
            verify_exit(&jd),
            0,
            "an undamaged dir verifies clean through the manifest"
        );

        // Flip one byte mid-payload and the manifest convicts it.
        let target = jd.join("payload.bin");
        let mut bytes = std::fs::read(&target).unwrap();
        bytes[50_000] ^= 0x20;
        std::fs::write(&target, &bytes).unwrap();
        assert_eq!(
            verify_exit(&jd),
            1,
            "a flipped byte must fail the manifest verify"
        );
        println!(
            "A/B settle manifest e2e: on the SHIPPED default, with no .par2 on \
             disk, verify convicted a flipped byte through .nzbfast.manifest; \
             the undamaged run exited 0."
        );

        // ---- The off arm: the tick cleared, no manifest, nothing else
        // changes. ----
        set("write_manifest", "0");
        let second = upload("Unmanifested.Job.nzb", &xml);
        wait_completed(&second);
        let jd2 = job_dir("Unmanifested");
        assert!(
            !jd2.join(".nzbfast.manifest").exists(),
            "with the setting off nothing is written"
        );
    })
    .await
    .unwrap();
}

/// ...and a job the PREFETCH finishes outright leaves the same manifest.
///
/// §310 flipped `write_manifest` on, and this was the one completion
/// road that wrote nothing: `sidecar::completion_tail` called the settle
/// step with no verifier, so a folder an idle-server prefetch produced
/// had no `.nzbfast.manifest` in it while the folder beside it - the
/// same release, finished by the runner - did. Nothing told the user
/// which was which; the "Checking downloads later" box simply answered
/// that the folder carried no manifest this daemon could read.
///
/// It is driven end to end rather than by calling the tail directly
/// because the defect was not IN the tail: the tail was handed nothing
/// to write from. The prefetch runs on a hub of its own, and the fix is
/// the spawn site cloning that hub's verifier and extractor before the
/// task drops them - so a test that hands `completion_tail` a verifier
/// by hand would pass against the broken tree.
///
/// The prefetch road is asserted twice over, because "B completed" on
/// its own is also what the ordinary queue does one job later: the
/// daemon log must carry the prefetch's own completion line, and A must
/// still be downloading when B lands. Shaped on `daemon.rs`'s
/// `idle_servers_prefetch_next_job`, which pins the same road without
/// the recovery set.
#[tokio::test(flavor = "multi_thread")]
async fn a_prefetch_finished_job_leaves_a_manifest_too() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pfmanifest-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // A: slow server only, sized so it is still running when B lands
    // (120 articles x 250 ms over 2 connections is ~15 s).
    let mut slow_articles = HashMap::new();
    let a_segs = make_file_articles(
        "slowa.bin",
        &payload(2_400_000, 21),
        20_000,
        "pfa",
        &mut slow_articles,
    );
    // B: fast server only, payload plus a verification-only recovery set
    // - the manifest is built from the PAR2 the run parses.
    let b_data = payload(96_000, 23);
    let b_par2 = par2_index_over("payload.bin", &b_data);
    let mut fast_articles = HashMap::new();
    let b_payload_segs =
        make_file_articles("payload.bin", &b_data, 32_000, "pfbp", &mut fast_articles);
    let b_par2_segs =
        make_file_articles("testset.par2", &b_par2, 32_000, "pfbr", &mut fast_articles);

    let slow_srv = MockServer::start(
        slow_articles,
        Chaos {
            delay_ms: 250,
            ..Chaos::default()
        },
    )
    .await;
    let fast_srv = MockServer::start(
        fast_articles,
        Chaos {
            delay_ms: 100,
            ..Chaos::default()
        },
    )
    .await;

    let nzb_for = |files: &[(&str, &Vec<(String, u64, u32)>)]| {
        let mut xml = String::from(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        for (name, segs) in files {
            xml.push_str(&format!(
                "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
                segs.len()
            ));
            for (id, bytes, num) in segs.iter() {
                xml.push_str(&format!(
                    "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
                ));
            }
            xml.push_str("    </segments>\n  </file>\n");
        }
        xml.push_str("</nzb>\n");
        xml
    };
    let a_xml = nzb_for(&[("slowa.bin", &a_segs)]);
    let b_xml = nzb_for(&[
        ("payload.bin", &b_payload_segs),
        ("testset.par2", &b_par2_segs),
    ]);

    // Distinct HOST STRINGS for the two loopback mocks: host is server
    // identity throughout, and the prefetch's busy-host exclusion must
    // not catch the idle one. Same reason as the sibling in daemon.rs.
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}},{{\"host\":\"localhost\",\"port\":{},\"tls\":false}}]}}",
            slow_srv.addr.port(),
            fast_srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_DEFER_WARMUP_SECS", "2")
            // With the cross-job hand-over on, the idle server's
            // connections go to B as a first-class start and the
            // prefetch window never opens - so this road needs it off.
            .env("NZBFAST_QUEUE_HANDOFF", "0")
            .env("NZBFAST_DEFER_WINDOW_SECS", "3")
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
    })
    .await;
    let port = d.port;

    // NOTHING IS SET: this runs on the shipped `write_manifest` default,
    // the same way the arm above does, so it pins the default too.
    let complete_root = dir.join("complete");
    let b_id = tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----pfmb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .map(|s| format!("SABnzbd_nzo_{s}"))
                .expect("addfile returned no nzo_id")
        };
        let poll = |pred: &dyn Fn(&str, &str) -> bool, what: &str| -> (String, String) {
            for _ in 0..300 {
                let q = http(port, "/api?mode=queue&output=json", None);
                let h = http(port, "/api?mode=history&output=json", None);
                if pred(&q, &h) {
                    return (q, h);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        let a_id = upload(&a_xml, "SlowActive.Job.nzb");
        poll(
            &|q, _| queue_slot(q, &a_id)["status"] == "Downloading",
            "job A start",
        );
        let b_id = upload(&b_xml, "Prefetched.Job.nzb");

        let (q, _) = poll(
            &|_, h| history_slot(h, &b_id)["status"] == "Completed",
            "B completion via the prefetch",
        );
        assert!(
            queue_slot(&q, &a_id)["status"] == "Downloading",
            "B must land while A is still downloading, or it was not prefetched: {q}"
        );

        let jd = std::fs::read_dir(&complete_root)
            .expect("complete/ exists")
            .flatten()
            .map(|e| e.path())
            .find(|p| {
                p.is_dir()
                    && p.file_name()
                        .is_some_and(|n| n.to_string_lossy().contains("Prefetched"))
            })
            .expect("no completed dir for the prefetched job");

        assert!(
            jd.join(".nzbfast.manifest").is_file(),
            "a job the prefetch finished outright left no settle manifest in {}",
            jd.display()
        );

        // The post-cleanup state, the same A/B the arm above drives: no
        // recovery data on disk, and the manifest still convicts.
        for e in std::fs::read_dir(&jd).unwrap().flatten() {
            if e.path().extension().is_some_and(|x| x == "par2") {
                std::fs::remove_file(e.path()).unwrap();
            }
        }
        let verify_exit = |dir: &std::path::Path| -> i32 {
            Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                .arg("verify")
                .arg(dir)
                .status()
                .expect("verify ran")
                .code()
                .unwrap_or(-1)
        };
        assert_eq!(
            verify_exit(&jd),
            0,
            "the prefetched dir must verify clean through its manifest"
        );
        let target = jd.join("payload.bin");
        let mut bytes = std::fs::read(&target).unwrap();
        bytes[50_000] ^= 0x20;
        std::fs::write(&target, &bytes).unwrap();
        assert_eq!(
            verify_exit(&jd),
            1,
            "a flipped byte in a prefetched dir must fail the manifest verify"
        );
        println!(
            "A/B settle manifest, prefetch road: a job finished entirely by the \
             idle-server prefetch left a .nzbfast.manifest that convicted a \
             flipped byte with no .par2 on disk."
        );
        b_id
    })
    .await
    .unwrap();

    // The second proof that this was the prefetch road and not the queue
    // one job later: only `sidecar` prints this line.
    let log = d.log();
    assert!(
        log.contains(&format!(
            "[prefetch] {b_id} completed entirely on idle servers"
        )),
        "B was not finished by the prefetch, so this pinned nothing:\n{log}"
    );
}
