//! §18: the phone-remote surface, certified against the clients' own
//! request shapes rather than against SAB/NZBGet documentation.
//!
//! LunaSea's contract was extracted from its Dart source (the app is
//! archived but the code is public): its NZBGet module authenticates
//! ONLY with NZBGet's in-URL credential form `/<user>:<pass>/jsonrpc`
//! (never a Basic header), adds by URL through `append` with the URL
//! as the Content param, and drives the queue with editqueue
//! subcommands (GroupMoveOffset, GroupSetName, GroupApplyCategory,
//! GroupSetParameter, GroupSort) plus `scheduleresume` for its
//! pause-for dialog. Its SABnzbd module uses mode=switch, queue
//! rename/sort, and reads four keys out of fullstatus that must be
//! STRINGS (they go through Dart's tryParse, which takes a String).
//! nzb360's SAB reads are pinned by the daemon suite since issue #34;
//! the arms here are the remainder both apps share.

// The shared daemon launcher (free_port / KillOnDrop / DaemonLog /
// serve_blocking / wait_ready) and the scratch-dir guard, both declared
// once in main.rs because this file is a module of the merged binary.
use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use crate::harness::Daemon;

const KEY: &str = "sekrit";

const NZB: &str = r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb"><file poster="x" date="0" subject="&quot;a.bin&quot; yEnc (1/1)"><groups><group>g</group></groups><segments><segment bytes="1000" number="1">one@remote-compat</segment></segments></file></nzb>"#;

struct Reply {
    status: u16,
    body: String,
}

fn send(port: u16, request: &str) -> Reply {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match send_once(port, request) {
            Ok(r) => return r,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * u64::from(attempt) + 50,
                ));
            }
        }
    }
    let line = request.lines().next().unwrap_or("");
    panic!("daemon on :{port} never answered {line:?}: {last}");
}

fn send_once(port: u16, request: &str) -> std::io::Result<Reply> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    let read = s.read_to_end(&mut raw);
    if raw.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok(Reply {
        status,
        body: body.to_string(),
    })
}

fn get(port: u16, path: &str) -> Reply {
    send(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
    )
}

fn api(port: u16, q: &str) -> serde_json::Value {
    let r = get(port, &format!("/api?output=json&apikey={KEY}&{q}"));
    assert_eq!(r.status, 200, "{q}: {}", r.body);
    serde_json::from_str(&r.body).unwrap_or_else(|e| panic!("{q}: {e}: {}", r.body))
}

/// A JSON-RPC POST the way LunaSea sends it: credentials in the URL
/// path, no Authorization header, body `{jsonrpc, method, params, id}`.
fn rpc_at(port: u16, path: &str, method: &str, params: &str) -> Reply {
    let body =
        format!("{{\"jsonrpc\":\"2.0\",\"method\":\"{method}\",\"params\":{params},\"id\":1}}");
    send(
        port,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn rpc(port: u16, method: &str, params: &str) -> serde_json::Value {
    let r = rpc_at(port, &format!("/nzbget:{KEY}/jsonrpc"), method, params);
    assert_eq!(r.status, 200, "{method}: {}", r.body);
    serde_json::from_str(&r.body).unwrap_or_else(|e| panic!("{method}: {e}: {}", r.body))
}

fn b64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// One-shot HTTP file server for the add-by-URL legs.
fn nzb_server() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in l.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let _ = s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-nzb\r\n\
                     Content-Disposition: attachment; filename=\"fetched.nzb\"\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{NZB}",
                    NZB.len()
                )
                .as_bytes(),
            );
        }
    });
    port
}

fn scratch(name: &str) -> scratch::ScratchDir {
    let dir = std::env::temp_dir().join(format!("nzbfast-remote-{}-{name}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    std::fs::write(dir.join("settings.json"), "{}").unwrap();
    dir
}

fn serve(dir: &Path) -> Daemon {
    crate::harness::serve_blocking(dir, |port| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        cmd.env("NZBFAST_NO_ENRICH", "1")
            .env_remove("NZBFAST_OPEN")
            .current_dir(dir)
            .arg("--config")
            .arg(dir.join("config.json"))
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg(KEY)
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(dir.join("index.db"));
        cmd
    })
}

/// The in-URL credential form is a real login, with the same tiers and
/// refusals as the Basic-header one - and the method still resolves
/// from the path when the path carries a credential segment.
#[test]
fn url_credentials_open_the_jsonrpc_facade() {
    let dir = scratch("urlcred");
    let d = serve(&dir);

    // LunaSea's exact shape: POST, credentials in the path, no header.
    let r = rpc_at(d.port, &format!("/nzbget:{KEY}/jsonrpc"), "version", "[]");
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("21.0"), "{}", r.body);
    // Its newer client keeps a trailing slash.
    let r = rpc_at(d.port, &format!("/nzbget:{KEY}/jsonrpc/"), "version", "[]");
    assert_eq!(r.status, 200, "{}", r.body);

    // GET with the method in the path: the method is what FOLLOWS the
    // jsonrpc segment, not a fixed position from the front.
    let r = get(d.port, &format!("/nzbget:{KEY}/jsonrpc/version"));
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("21.0"), "{}", r.body);

    // A wrong password is refused, and the bare route still requires
    // auth - the credential segment must not have opened a side door.
    let r = rpc_at(d.port, "/nzbget:wrong/jsonrpc", "version", "[]");
    assert_eq!(r.status, 401, "{}", r.body);
    let r = rpc_at(d.port, "/jsonrpc", "version", "[]");
    assert_eq!(r.status, 401, "{}", r.body);
}

/// Every editqueue subcommand LunaSea sends answers `true` and does
/// the thing, and its pause-for pair (pausedownload + scheduleresume)
/// arms a resume that actually fires.
#[test]
fn lunasea_editqueue_surface_answers_true() {
    let dir = scratch("editq");
    let d = serve(&dir);
    let p = d.port;

    // Two paused jobs so the offset move has somewhere to go.
    for name in ["first.nzb", "second.nzb"] {
        let v = rpc(
            p,
            "append",
            &format!(
                "[\"{name}\",\"{}\",\"\",0,false,true,\"{name}\",0,\"All\",[]]",
                b64(NZB.as_bytes())
            ),
        );
        assert!(v["result"].as_i64().unwrap_or(0) > 0, "{v}");
    }
    let groups = rpc(p, "listgroups", "[]");
    let ids: Vec<i64> = groups["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["NZBID"].as_i64().unwrap())
        .collect();
    assert_eq!(ids.len(), 2, "{groups}");
    let id = ids[1]; // the later add sits at the back

    let ok = |v: &serde_json::Value| v["result"] == serde_json::Value::Bool(true);
    // Move the back job up one.
    let v = rpc(
        p,
        "editqueue",
        &format!("[\"GroupMoveOffset\",\"-1\",[{id}]]"),
    );
    assert!(ok(&v), "{v}");
    let groups = rpc(p, "listgroups", "[]");
    assert_eq!(
        groups["result"][0]["NZBID"].as_i64(),
        Some(id),
        "the offset move must reorder the queue: {groups}"
    );
    // Rename, recategorize, set the unpack password.
    let v = rpc(
        p,
        "editqueue",
        &format!("[\"GroupSetName\",\"renamed-by-remote\",[{id}]]"),
    );
    assert!(ok(&v), "{v}");
    let v = rpc(
        p,
        "editqueue",
        &format!("[\"GroupApplyCategory\",\"movies\",[{id}]]"),
    );
    assert!(ok(&v), "{v}");
    let g = rpc(p, "listgroups", "[]");
    let row = g["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["NZBID"].as_i64() == Some(id))
        .unwrap()
        .clone();
    assert_eq!(row["NZBName"].as_str(), Some("renamed-by-remote"), "{row}");
    assert_eq!(row["Category"].as_str(), Some("movies"), "{row}");
    let v = rpc(
        p,
        "editqueue",
        &format!("[\"GroupSetParameter\",\"*Unpack:Password=pw18\",[{id}]]"),
    );
    assert!(ok(&v), "{v}");
    // Sort by name, both directions.
    for dir in ["name+", "name-"] {
        let v = rpc(p, "editqueue", &format!("[\"GroupSort\",\"{dir}\",[]]"));
        assert!(ok(&v), "{v}");
    }

    // pause-for: pausedownload, then resume in one second.
    let v = rpc(p, "pausedownload", "[]");
    assert!(ok(&v), "{v}");
    let v = rpc(p, "scheduleresume", "[1]");
    assert!(ok(&v), "{v}");
    let mut resumed = false;
    for _ in 0..100 {
        let st = rpc(p, "status", "[]");
        if st["result"]["DownloadPaused"] == serde_json::Value::Bool(false) {
            resumed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(resumed, "scheduleresume never resumed the queue");
}

/// A rename and a recategorize through NZBGet's editqueue must still be
/// there after the daemon is restarted.
///
/// Both verbs re-derive `out_dir` through `requeue_category`, which may
/// already have MOVED the release's partial download to the new folder -
/// so a record that came back with the old name and the old directory
/// would name a folder the bytes have left, and the job would refetch
/// the whole release into it.
///
/// Neither `rename_by_ids` nor the `GroupApplyCategory` arm writes on
/// its own: what persists them is the single tail `save_queue` in
/// `jr_editqueue`, one write for whichever subcommand ran. That is
/// deliberate (see `requeue_category`) and cheap, but it is also a save
/// at a distance from the two verbs that move files, so it is pinned
/// here rather than left to be re-derived by whoever next restructures
/// that match.
///
/// The daemon is SIGKILLed, not asked to stop: the write has to have
/// landed by the time the call was answered, not at shutdown.
#[test]
fn a_remote_rename_and_recategorize_survive_a_restart() {
    let dir = scratch("renamepersist");
    let d = serve(&dir);
    let p = d.port;

    let v = rpc(
        p,
        "append",
        &format!(
            "[\"before.nzb\",\"{}\",\"\",0,false,true,\"before.nzb\",0,\"All\",[]]",
            b64(NZB.as_bytes())
        ),
    );
    assert!(v["result"].as_i64().unwrap_or(0) > 0, "{v}");
    let id = rpc(p, "listgroups", "[]")["result"][0]["NZBID"]
        .as_i64()
        .expect("the appended job");

    let ok = |v: &serde_json::Value| v["result"] == serde_json::Value::Bool(true);
    let v = rpc(
        p,
        "editqueue",
        &format!("[\"GroupSetName\",\"renamed-across-restart\",[{id}]]"),
    );
    assert!(ok(&v), "{v}");
    let v = rpc(
        p,
        "editqueue",
        &format!("[\"GroupApplyCategory\",\"movies\",[{id}]]"),
    );
    assert!(ok(&v), "{v}");

    // The durable record, read while the daemon that wrote it is still
    // up: `listgroups` answers from memory, so only the file can say
    // whether the write happened when the call was answered. out_dir is
    // the half no wire form exposes for a queued job, and the half a
    // move has already acted on.
    let stored = std::fs::read_to_string(dir.join(".spool").join("queue.json"))
        .expect("queue.json after the two edits");
    let stored: serde_json::Value = serde_json::from_str(&stored).expect("queue.json parses");
    let saved = stored["queue"]
        .as_array()
        .expect("queue array")
        .iter()
        .find(|j| j["name"] == "renamed-across-restart")
        .unwrap_or_else(|| panic!("the rename never reached queue.json: {stored}"));
    assert_eq!(
        saved["category"].as_str(),
        Some("movies"),
        "the category rode with the rename in memory but not to disk: {saved}"
    );
    let dest = saved["out_dir"].as_str().expect("out_dir").to_string();
    assert!(
        dest.ends_with("movies/renamed-across-restart")
            || dest.ends_with("movies\\renamed-across-restart"),
        "the saved record must name the re-derived folder, not the old one: {saved}"
    );

    // Kill it where it stands and start a second daemon on the same
    // spool. `serve` picks a fresh port; the NZBID is independent of it.
    let _log = d.stop();
    let d = serve(&dir);
    let after = rpc(d.port, "listgroups", "[]")["result"]
        .as_array()
        .expect("listgroups array")
        .iter()
        .find(|r| r["NZBID"].as_i64() == Some(id))
        .cloned()
        .unwrap_or_else(|| panic!("job {id} did not come back into the queue"));
    assert_eq!(
        after["NZBName"].as_str(),
        Some("renamed-across-restart"),
        "the rename did not survive the restart: {after}"
    );
    assert_eq!(
        after["Category"].as_str(),
        Some("movies"),
        "the category did not survive the restart: {after}"
    );
}

/// `append` with a URL as the Content param fetches and enqueues -
/// LunaSea's add-by-URL sends exactly that, with an empty NZBFileName,
/// and used to be answered 0 ("failed") without a fetch.
#[test]
fn jsonrpc_append_accepts_a_url() {
    let dir = scratch("appendurl");
    let d = serve(&dir);
    let web = nzb_server();

    let url = format!("http://127.0.0.1:{web}/fetched.nzb");
    let v = rpc(
        d.port,
        "append",
        &format!("[\"\",\"{url}\",\"\",0,false,true,\"{url}\",0,\"All\",[]]"),
    );
    let id = v["result"].as_i64().unwrap_or(0);
    assert!(id > 0, "URL append must answer the new NZBID: {v}");
    let groups = rpc(d.port, "listgroups", "[]");
    let row = groups["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["NZBID"].as_i64() == Some(id))
        .cloned();
    // Named from the fetch's Content-Disposition, not from the URL.
    assert_eq!(
        row.as_ref().and_then(|r| r["NZBName"].as_str()),
        Some("fetched"),
        "{groups}"
    );
}

/// The SAB-side arms LunaSea drives: top-level switch (wrapped as
/// {"result":{"position"}}), rename with the value3 password, sort,
/// change_complete_action, idempotent class clears, and the four
/// fullstatus keys its statistics page requires as strings.
#[test]
fn sab_remote_arms_cover_lunaseas_calls() {
    let dir = scratch("sabarms");
    let d = serve(&dir);
    let p = d.port;
    let web = nzb_server();

    // Two paused jobs through the SAB door this time.
    let mut nzo = Vec::new();
    for _ in 0..2 {
        let v = api(
            p,
            &format!("mode=addurl&priority=-2&name=http%3A%2F%2F127.0.0.1%3A{web}%2Ffetched.nzb"),
        );
        assert_eq!(v["status"], serde_json::Value::Bool(true), "{v}");
        nzo.push(v["nzo_ids"][0].as_str().unwrap().to_string());
    }

    // switch: SAB's own answer shape, position inside "result".
    let v = api(p, &format!("mode=switch&value={}&value2=0", nzo[1]));
    assert_eq!(v["result"]["position"].as_i64(), Some(0), "{v}");

    // rename, then the same-name rename that carries a password.
    let v = api(
        p,
        &format!("mode=queue&name=rename&value={}&value2=renamed-sab", nzo[0]),
    );
    assert_eq!(v["status"], serde_json::Value::Bool(true), "{v}");
    let v = api(
        p,
        &format!(
            "mode=queue&name=rename&value={}&value2=renamed-sab&value3=pw18",
            nzo[0]
        ),
    );
    assert_eq!(v["status"], serde_json::Value::Bool(true), "{v}");
    let q = api(p, "mode=queue&limit=100");
    let names: Vec<&str> = q["queue"]["slots"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["filename"].as_str())
        .collect();
    assert!(names.contains(&"renamed-sab"), "{names:?}");

    // sort: the three keys LunaSea's dialog offers.
    for key in ["avg_age", "name", "size"] {
        let v = api(p, &format!("mode=queue&name=sort&sort={key}&dir=asc"));
        assert_eq!(
            v["status"],
            serde_json::Value::Bool(true),
            "sort {key}: {v}"
        );
    }

    // change_complete_action: "none" is success; a machine action we
    // cannot perform is refused rather than silently swallowed.
    let v = api(p, "mode=queue&name=change_complete_action&value=none");
    assert_eq!(v["status"], serde_json::Value::Bool(true), "{v}");
    let v = api(
        p,
        "mode=queue&name=change_complete_action&value=shutdown_pc",
    );
    assert_eq!(v["status"], serde_json::Value::Bool(false), "{v}");

    // Class clears are idempotent: an empty history is already in the
    // asked-for state. A per-id miss keeps answering false.
    for class in ["completed", "failed", "all"] {
        let v = api(p, &format!("mode=history&name=delete&value={class}"));
        assert_eq!(
            v["status"],
            serde_json::Value::Bool(true),
            "clear {class}: {v}"
        );
    }
    let v = api(p, "mode=history&name=delete&value=SABnzbd_nzo_nosuch");
    assert_eq!(v["status"], serde_json::Value::Bool(false), "{v}");

    // fullstatus: the four keys LunaSea's statistics page reads, all
    // strings (its parser hands them to tryParse, which takes String).
    let v = api(p, "mode=fullstatus&skip_dashboard=1");
    let st = &v["status"];
    for k in ["speedlimit", "diskspace1", "diskspace2"] {
        assert!(st[k].is_string(), "{k} must be a string: {v}");
        assert!(
            st[k].as_str().unwrap().parse::<f64>().is_ok(),
            "{k} must parse as a number: {v}"
        );
    }
    // "" is SAB's "no cap set"; a "0" here would read as a 0 B/s cap.
    assert_eq!(st["speedlimit_abs"].as_str(), Some(""), "{v}");
}
