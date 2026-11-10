//! TODO 358 item 13 (decision D2), end to end: a completed MEDIA-shaped
//! download holding an executable is filed Failed with the reason, so a
//! SAB client gives up on the post and grabs another; a software post
//! and an emptied `refuse_exts` list complete as before.
//!
//! Each test is one real job through the real daemon against the mock
//! NNTP server, read back from `mode=history` the way an *arr reads it,
//! and from the output tree on disk. A sibling-dir child of daemon.rs
//! (the daemon_mediafast pattern), so the parent stays inside its
//! size-gate baseline; harness via `super::*`.

use super::*;

/// What one finished job left behind.
struct Run {
    /// The job's `mode=history` slot.
    slot: serde_json::Value,
    /// Every file under the download root once it settled.
    files: Vec<PathBuf>,
}

/// Post `files` as one NZB named `nzb_name` in category `cat` (empty =
/// none), let the daemon finish it, and hand back the history slot and
/// the output tree. `refuse_off` saves `refuse_exts: []` into
/// settings.json before launch, which is also the restore path's proof
/// that an EMPTY list comes back as "off" rather than as the default.
async fn run_job(
    tag: &str,
    nzb_name: &str,
    cat: &str,
    files: Vec<(&'static str, Vec<u8>)>,
    refuse_off: bool,
) -> Run {
    let dir = std::env::temp_dir().join(format!("nzbfast-exerefuse-{tag}-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, (name, data)) in files.iter().enumerate() {
        let segs = make_file_articles(name, data, 100_000, &format!("x{i}"), &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
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
    // Permanent deletes, so "the executable is gone" is read off the
    // tree rather than off a Trash this box may or may not have.
    delete_without_the_trash(&cfg);
    if refuse_off {
        let path = cfg.with_file_name("settings.json");
        let mut saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        saved["refuse_exts"] = serde_json::json!([]);
        std::fs::write(&path, saved.to_string()).unwrap();
    }
    let out = dir.join("complete");
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
            .arg(&out)
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log_path();
    let nzb_name = nzb_name.to_string();
    let cat = cat.to_string();

    tokio::task::spawn_blocking(move || {
        // The setting reads back as the list it holds, the default on a
        // fresh install and empty once saved empty.
        let c = http(port, "/api?mode=get_config&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&c).unwrap_or_default();
        let list = &v["config"]["nzbfast"]["refuse_exts"];
        if refuse_off {
            assert_eq!(*list, serde_json::json!([]), "saved empty, restored as: {c}");
        } else {
            assert!(
                list.as_array().is_some_and(|a| a.iter().any(|e| e == "exe")),
                "a fresh install must refuse .exe by default: {c}"
            );
        }

        let boundary = "----exerefuse";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{nzb_name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let q = if cat.is_empty() {
            "/api?mode=addfile&output=json".to_string()
        } else {
            format!("/api?mode=addfile&output=json&cat={cat}")
        };
        let r = http(
            port,
            &q,
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let mut slot = None;
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&output=json", None);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&h)
                && let Some(s) = v["history"]["slots"].get(0)
                && (s["status"] == "Completed" || s["status"] == "Failed")
            {
                slot = Some(s.clone());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let slot = slot.unwrap_or_else(|| {
            let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
            panic!("the job never reached history\n--- log ---\n{log}")
        });
        Run {
            slot,
            files: walk_files(&out),
        }
    })
    .await
    .unwrap()
}

/// A stand-in program: a DOS/PE header and nothing behind it, so no
/// SFX arm mistakes it for an archive.
fn program() -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    b[0..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    b[0x40..0x44].copy_from_slice(b"PE\0\0");
    b
}

fn named(files: &[PathBuf], name: &str) -> bool {
    files
        .iter()
        .any(|p| p.file_name().is_some_and(|n| n == name))
}

/// The defect D2 answers: a film that arrives with a `setup.exe` beside
/// it. Failed, with the reason naming the file, and the program is not
/// left in the folder.
#[tokio::test(flavor = "multi_thread")]
async fn a_media_job_holding_an_executable_fails_with_the_reason() {
    let run = run_job(
        "media",
        "Example.Movie.2024.1080p.WEB-DL.x264-GRP.nzb",
        "",
        vec![
            ("movie.mkv", payload(300_000, 31)),
            ("setup.exe", program()),
        ],
        false,
    )
    .await;
    assert_eq!(run.slot["status"], "Failed", "{}", run.slot);
    let why = run.slot["fail_message"].as_str().unwrap_or_default();
    assert!(
        why.starts_with("refused:") && why.contains("setup.exe"),
        "the reason must say what was refused: {why:?}"
    );
    assert!(
        !named(&run.files, "setup.exe"),
        "the refused executable is still in the output: {:?}",
        run.files
    );
}

/// The category alone is enough: an obfuscated name claims nothing, and
/// the `movies` category is what says this is a film.
#[tokio::test(flavor = "multi_thread")]
async fn an_obfuscated_job_in_a_media_category_fails_too() {
    let run = run_job(
        "cat",
        "a8f3c9d2e1b04f6a9c7e5b1d.nzb",
        "movies",
        vec![
            ("movie.mkv", payload(300_000, 32)),
            ("setup.exe", program()),
        ],
        false,
    )
    .await;
    assert_eq!(run.slot["status"], "Failed", "{}", run.slot);
}

/// The control D2 exists for: a software post ships its installer, and
/// Weaver's blanket rule fails it where this one must not.
#[tokio::test(flavor = "multi_thread")]
async fn a_software_job_holding_an_executable_completes() {
    let run = run_job(
        "software",
        "Some.Tool.v2.1.3.x64.Incl.Keygen-GRP.nzb",
        "",
        vec![("setup.exe", program()), ("readme.txt", b"notes".to_vec())],
        false,
    )
    .await;
    assert_eq!(run.slot["status"], "Completed", "{}", run.slot);
    assert!(
        named(&run.files, "setup.exe"),
        "a software post keeps its installer: {:?}",
        run.files
    );
}

/// An emptied list is the off switch, and it survives a restart: the
/// same media job that fails above completes.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_refuse_list_turns_the_check_off() {
    let run = run_job(
        "off",
        "Example.Movie.2024.1080p.WEB-DL.x264-GRP.nzb",
        "",
        vec![
            ("movie.mkv", payload(300_000, 33)),
            ("setup.exe", program()),
        ],
        true,
    )
    .await;
    assert_eq!(run.slot["status"], "Completed", "{}", run.slot);
    assert_eq!(run.slot["fail_message"], "", "{}", run.slot);
}

/// The executable arrives INSIDE the archive, which is the shape a
/// malware post actually takes: the extraction writes it out, and the
/// refusal still fails the job and keeps it out of the output.
#[tokio::test(flavor = "multi_thread")]
async fn an_executable_inside_an_extracted_archive_fails_and_is_not_published() {
    let mkv = payload(300_000, 34);
    let exe = program();
    let rar = crate::rarfixtures::stored_archive(&[
        crate::rarfixtures::Member::unix(b"movie.mkv", &mkv),
        crate::rarfixtures::Member::unix(b"setup.exe", &exe),
    ]);
    let run = run_job(
        "rar",
        "Example.Movie.2024.1080p.WEB-DL.x264-GRP.nzb",
        "",
        vec![("Example.Movie.2024.1080p.WEB-DL.x264-GRP.rar", rar)],
        false,
    )
    .await;
    assert_eq!(run.slot["status"], "Failed", "{}", run.slot);
    let why = run.slot["fail_message"].as_str().unwrap_or_default();
    assert!(why.contains("setup.exe"), "{why:?}");
    // The extraction did happen - this is the extracted member being
    // refused, not an archive that never opened.
    assert!(
        named(&run.files, "movie.mkv"),
        "the archive was never extracted, so this proves nothing: {:?}",
        run.files
    );
    assert!(
        !named(&run.files, "setup.exe"),
        "the refused executable was published with the film: {:?}",
        run.files
    );
}

/// A self-extractor around `archive`, with a launcher stub longer than
/// four of `run_job`'s 100 KB articles - the daemon_sfx shape, which the
/// offset-0 sniff never sees, so the get tail's disk SFX arm unpacks it.
fn deep_sfx(archive: &[u8]) -> Vec<u8> {
    let mut sfx = vec![0u8; 400_002];
    sfx[0..2].copy_from_slice(b"MZ");
    sfx[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    sfx[0x40..0x44].copy_from_slice(b"PE\0\0");
    sfx.extend_from_slice(archive);
    sfx
}

/// Pre-release sweep, 9 Nov 2026: a media-named SFX post is a supported
/// shape, and the disk SFX arm left its `.exe` wrapper beside the
/// payload it had just unpacked - so the executable refusal then FAILED
/// a correct download over its own container. The spent self-extractor
/// goes the way a spent RAR set's volumes go, and the job completes.
#[tokio::test(flavor = "multi_thread")]
async fn a_media_named_self_extractor_unpacks_and_completes() {
    let mkv = payload(300_000, 35);
    let vol = nzbkit::rar::fixtures::rar5_volume(&[("movie.mkv", 300_000, &mkv, false, false)]);
    let run = run_job(
        "sfxmedia",
        "Example.Movie.2024.1080p.WEB-DL.x264-GRP.nzb",
        "",
        vec![(
            "Example.Movie.2024.1080p.WEB-DL.x264-GRP.exe",
            deep_sfx(&vol),
        )],
        false,
    )
    .await;
    assert_eq!(run.slot["status"], "Completed", "{}", run.slot);
    assert_eq!(run.slot["fail_message"], "", "{}", run.slot);
    // By extension: the namer files it under the release name. Presence
    // only - `run_job`'s scratch tree is gone by the time it returns, so
    // the list of paths is all that survives to be read.
    assert!(
        run.files
            .iter()
            .any(|p| p.extension().is_some_and(|x| x == "mkv")),
        "the SFX payload was not unpacked: {:?}",
        run.files
    );
    assert!(
        !run.files
            .iter()
            .any(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe"))),
        "the spent self-extractor is still in the output: {:?}",
        run.files
    );
}

/// ...and the container's going does not launder what it CONTAINED: an
/// SFX whose payload holds its own executable is still a media release
/// shipping one, and stays refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_self_extractor_whose_payload_holds_an_executable_stays_refused() {
    let mkv = payload(300_000, 36);
    let exe = program();
    let vol = nzbkit::rar::fixtures::rar5_volume(&[
        ("movie.mkv", 300_000, &mkv, false, false),
        ("setup.exe", exe.len() as u64, &exe, false, false),
    ]);
    let run = run_job(
        "sfxbad",
        "Example.Movie.2024.1080p.WEB-DL.x264-GRP.nzb",
        "",
        vec![(
            "Example.Movie.2024.1080p.WEB-DL.x264-GRP.exe",
            deep_sfx(&vol),
        )],
        false,
    )
    .await;
    assert_eq!(run.slot["status"], "Failed", "{}", run.slot);
    let why = run.slot["fail_message"].as_str().unwrap_or_default();
    assert!(
        why.starts_with("refused:") && why.contains("setup.exe"),
        "the payload's own executable must be what is refused: {why:?}"
    );
    assert!(
        !named(&run.files, "setup.exe"),
        "the refused executable is still in the output: {:?}",
        run.files
    );
}
