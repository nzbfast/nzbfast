#![cfg(feature = "indexer")]
//! M29 availability oracle: a seeded ledger drives browse/wall verdicts
//! through the daemon API - green for a fresh post the (mock) backbone
//! reliably serves, red for an ancient one it consistently 430s, and
//! `verdict=ok` filters the browse list.

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;

use crate::harness::serve;
use nzbkit::nntp::OverEntry;

/// (status, body) of a GET against the daemon.
///
/// A connection REFUSED before it produced a single byte is retried. That
/// is not the same as tolerating a bad answer: tiny_http's honest reply
/// when it cannot start a thread for a new connection is to drop the
/// socket unread, and with our request still in its receive buffer the
/// kernel turns that into an RST - which arrives here as ECONNRESET. A
/// full `cargo test` runs these suites in parallel, each test with a whole
/// daemon behind it, so `thread::Builder::spawn` really does hit EAGAIN,
/// and a test then failed on a refusal to serve rather than on anything it
/// asserts. Once a byte has come back it is an answer, and it is returned
/// (or fails) exactly as it arrived - a truncated response must never be
/// retried away.
fn http_get(port: u16, req: &str) -> (u16, String) {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_get_once(port, req) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * u64::from(attempt) + 50,
                ));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

/// One attempt. Returns Err ONLY when the daemon produced nothing at all;
/// a partial or malformed response is data, and is handed back for the
/// caller's assertions to judge.
fn http_get_once(port: u16, req: &str) -> std::io::Result<(u16, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        s,
        "GET {req} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )?;
    let mut out = String::new();
    // Zero bytes back is a refusal to serve, however the peer
    // phrased it: an RST (Err) when our request was never read off
    // the receive buffer, a plain FIN (Ok) when it was read and then
    // dropped unanswered. Neither carries anything to judge, so both
    // are retried. The moment ANY byte arrives it is an answer and is
    // returned exactly as it came - errors included - because a
    // truncated body must never be retried away.
    let read = s.read_to_string(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    let status: u16 = out
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok((
        status,
        out.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
    ))
}

fn over(number: u64, subject: &str, msgid: &str, date: i64) -> OverEntry {
    OverEntry {
        number,
        subject: subject.into(),
        from: "poster@x".into(),
        message_id: msgid.into(),
        bytes: 50 << 20, // fat enough to dodge the tiny-post junk score
        date,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn seeded_ledger_drives_browse_verdicts() {
    let dir = std::env::temp_dir().join(format!("nzbfast-oracle-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Index: one fresh release (2 days old) and one ancient (5+ years).
    let db = dir.join("index.db");
    {
        let ix_now = now - 3600;
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[
                over(
                    1,
                    "\"Fresh.Show.S01E02.1080p.rar\" yEnc (1/1)",
                    "<fresh@x>",
                    now - 2 * 86_400,
                ),
                over(
                    2,
                    "\"Ancient.Show.S01E01.1080p.rar\" yEnc (1/1)",
                    "<ancient@x>",
                    now - 2000 * 86_400,
                ),
            ],
            ix_now,
        )
        .unwrap();
        // A THIRD release: fresh (2d) but in a family whose fresh bucket
        // is confidently gone → a takedown wave (retention can't expire a
        // 2-day-old post), not age-driven loss (M29 3d).
        ix.ingest(
            "alt.binaries.warez",
            &[over(
                3,
                "\"Reaped.App.2026.rar\" yEnc (1/1)",
                "<reaped@x>",
                now - 2 * 86_400,
            )],
            ix_now,
        )
        .unwrap();
        // Ledger, keyed by the (single) configured server's backbone:
        // teevee's fresh bucket overwhelmingly present, its 3y+ bucket
        // confidently gone (retention). warez's fresh bucket confidently
        // gone (takedown). bucket 1 = 1-7d, bucket 6 = 3y+.
        let s = |fam: &str, bucket: u8, hits: u64, misses: u64| nzbkit::oracle::Sample {
            host: "127.0.0.1".into(),
            family: fam.into(),
            bucket,
            hits,
            misses,
        };
        ix.oracle_ingest(
            &[
                s("teevee", 1, 200, 0),
                s("teevee", 6, 2, 98),
                s("warez", 1, 3, 97),
            ],
            now,
        )
        .unwrap();
    }

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    // The availability ledger is a table in the index database, which
    // the daemon refuses to open while the built-in indexer's master
    // switch is off (its default). This test seeds that database and
    // then reads verdicts back through browse, so it is the switched-on
    // case; settings.json lives beside the config file.
    std::fs::write(
        cfg.with_file_name("settings.json"),
        "{\"index_enabled\": true}",
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        // The daemon mints an API key on a genuinely first run (see
        // serve::first_run_apikey). These suites drive it keyless on purpose,
        // so they take the same deliberate opt-out an operator would.
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            // Loopback only. These suites never need LAN reach, and binding
            // 0.0.0.0 makes the macOS firewall raise a prompt for every freshly
            // built test binary, which is a new path on every run.
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Browse: each row carries its ledger verdict.
        let (code, body) = http_get(
            port,
            "/api?mode=index_browse&all=1&output=json&apikey=sekrit",
        );
        assert_eq!(code, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("browse json");
        let rows = v["results"].as_array().expect("results");
        let row_of = |stem: &str| -> serde_json::Value {
            rows.iter()
                .find(|r| r["name"].as_str().unwrap_or("").starts_with(stem))
                .unwrap_or_else(|| panic!("{stem} not in browse:\n{body}"))
                .clone()
        };
        assert_eq!(
            row_of("Fresh.Show")["verdict"],
            serde_json::json!("ok"),
            "{body}"
        );
        assert_eq!(
            row_of("Ancient.Show")["verdict"],
            serde_json::json!("gone"),
            "{body}"
        );

        // M29 3d takedown fingerprint: the fresh-but-gone warez release is
        // flagged "reaped"; the ancient one (age-driven loss) and the
        // healthy fresh one are not.
        assert_eq!(
            row_of("Reaped.App")["reaped"],
            serde_json::json!(true),
            "{body}"
        );
        assert_eq!(
            row_of("Ancient.Show")["reaped"],
            serde_json::json!(false),
            "{body}"
        );
        assert_eq!(
            row_of("Fresh.Show")["reaped"],
            serde_json::json!(false),
            "{body}"
        );

        // verdict=ok keeps only the predicted-complete row, AND `total`
        // reflects the filter (M29 3c: SQL predicate, not a page trim -
        // the old code left total at the unfiltered 2, breaking paging).
        let (_, body) = http_get(
            port,
            "/api?mode=index_browse&all=1&verdict=ok&output=json&apikey=sekrit",
        );
        let v: serde_json::Value = serde_json::from_str(&body).expect("verdict=ok json");
        assert_eq!(v["total"], serde_json::json!(1), "filtered total: {body}");
        assert_eq!(v["results"].as_array().map(|a| a.len()), Some(1), "{body}");
        assert!(body.contains("Fresh.Show"), "{body}");
        assert!(!body.contains("Ancient.Show"), "{body}");

        // The wall's cards carry verdicts too (unmatched cards included).
        let (_, body) = http_get(
            port,
            "/api?mode=wall2&all=1&matched=0&output=json&apikey=sekrit",
        );
        let v: serde_json::Value = serde_json::from_str(&body).expect("wall2 json");
        let cards = v["cards"].as_array().expect("cards");
        let card = cards
            .iter()
            .find(|c| c["stem"].as_str().unwrap_or("").starts_with("Fresh.Show"))
            .unwrap_or_else(|| panic!("Fresh.Show card missing:\n{body}"));
        assert_eq!(card["verdict"], serde_json::json!("ok"), "{body}");

        // M29 3d: the takedown diagnostics endpoint lists warez (reaped)
        // and not teevee (retention loss is not a takedown).
        let (_, body) = http_get(port, "/api?mode=oracle_takedowns&output=json&apikey=sekrit");
        let v: serde_json::Value = serde_json::from_str(&body).expect("takedowns json");
        let fams: Vec<&str> = v["families"]
            .as_array()
            .expect("families")
            .iter()
            .map(|f| f["family"].as_str().unwrap_or(""))
            .collect();
        assert!(fams.contains(&"warez"), "warez reaped: {body}");
        assert!(!fams.contains(&"teevee"), "teevee not reaped: {body}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
