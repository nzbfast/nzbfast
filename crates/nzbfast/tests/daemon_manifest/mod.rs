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
//! through the manifest. The not-hinder arm: with the setting at its
//! default (off), an identical job leaves no manifest and nothing else
//! changes.

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

        // ---- The arm live ----
        set("write_manifest", "1");
        let first = upload("Manifested.Job.nzb", &xml);
        wait_completed(&first);
        let jd = job_dir("Manifested");
        let mpath = jd.join(".nzbfast.manifest");
        assert!(mpath.is_file(), "no manifest in {}", jd.display());

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
            "A/B settle manifest e2e: with no .par2 on disk, verify convicted a \
             flipped byte through .nzbfast.manifest; the undamaged run exited 0."
        );

        // ---- The default arm: no setting, no manifest, nothing else
        // changes. ----
        set("write_manifest", "0");
        let second = upload("Unmanifested.Job.nzb", &xml);
        wait_completed(&second);
        let jd2 = job_dir("Unmanifested");
        assert!(
            !jd2.join(".nzbfast.manifest").exists(),
            "the default must write nothing"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
