//! The mock's own contract, where nothing else in the suite asserts it.
//!
//! The ARTICLE arm exists for the competitive benchmarks - rustnzb
//! fetches with ARTICLE, not BODY - so no test in this crate ever asks
//! for one, and the arm has always been a copy of the BODY path kept in
//! step by hand. It fell out of step once already: the §111 fault
//! matrix found it missing stall_pre, brownout and jitter, which let an
//! ARTICLE-fetching client sail untouched through three fault profiles
//! and score walls nothing can reach. Both commands go through one body
//! now (`serve_article`); this is what says so.

use super::*;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// Send one command and read its status line plus, for a 22x, the
/// dot-terminated block that follows.
async fn ask(addr: SocketAddr, cmd: &str) -> (String, Vec<u8>) {
    let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (r, mut w) = sock.into_split();
    let mut reader = BufReader::new(r);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    assert!(greeting.starts_with("200 "), "greeting: {greeting:?}");

    w.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
    w.flush().await.unwrap();
    let mut status = String::new();
    reader.read_line(&mut status).await.unwrap();
    let status = status.trim_end().to_string();
    // Only a 22x carries a block. A refusal does not, and the mock keeps
    // the connection open afterwards, so reading for one would hang
    // rather than fail.
    // STAT's 223 is status-only too, so it is excluded here.
    if !status.starts_with("22") || status.starts_with("223") {
        return (status, Vec::new());
    }

    // Read to the lone-dot terminator. Byte-oriented: a yEnc payload is
    // not valid UTF-8.
    let mut block = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if reader.read_exact(&mut byte).await.is_err() {
            break;
        }
        block.push(byte[0]);
        if block.ends_with(b"\r\n.\r\n") {
            break;
        }
    }
    (status, block)
}

/// ARTICLE answers 220 with a header block; BODY answers 222 without
/// one; the payload after the headers is the same bytes either way.
///
/// The payload equality is the load-bearing half: a decoder scanning
/// for `=ybegin` must not be able to tell which command fetched it, so
/// any hook that rewrites, corrupts or truncates a body has to reach
/// both commands or neither.
#[tokio::test]
async fn article_and_body_serve_the_same_payload() {
    let mut articles = HashMap::new();
    let data: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
    let segs = make_file_articles("dup.bin", &data, 2, "dup", &mut articles);
    let id = format!("<{}>", segs[0].0);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let (body_status, body_block) = ask(srv.addr, &format!("BODY {id}")).await;
    let (art_status, art_block) = ask(srv.addr, &format!("ARTICLE {id}")).await;

    assert_eq!(body_status, format!("222 0 {id}"));
    assert_eq!(art_status, format!("220 0 {id}"));

    // The header block is ARTICLE's only addition, and it ends at the
    // first blank line.
    let split = art_block
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("ARTICLE must send a header block then a blank line");
    let (headers, art_payload) = art_block.split_at(split + 4);
    assert!(
        String::from_utf8_lossy(headers).contains(&format!("Message-ID: {id}")),
        "ARTICLE headers must name the article: {:?}",
        String::from_utf8_lossy(headers)
    );
    assert_eq!(
        art_payload, body_block,
        "ARTICLE and BODY disagree about the payload - the two arms have drifted apart again"
    );
    assert!(
        body_block.starts_with(b"=ybegin"),
        "the payload must still be the yEnc body"
    );
}

/// A chaos hook set on the server reaches BOTH commands.
///
/// `missing` is the cheapest one to state and the exact shape that
/// drifted: an ARTICLE arm that had not been given a hook answered
/// normally where BODY refused, so a client fetching with ARTICLE never
/// saw the fault the leg was built around.
#[tokio::test]
async fn a_chaos_hook_reaches_both_commands() {
    let mut articles = HashMap::new();
    let data: Vec<u8> = (0..8_000u32).map(|i| i as u8).collect();
    let segs = make_file_articles("gone.bin", &data, 1, "gone", &mut articles);
    let id = format!("<{}>", segs[0].0);
    let chaos = Chaos {
        missing: [id.clone()].into_iter().collect(),
        ..Chaos::default()
    };
    let srv = MockServer::start(articles, chaos).await;

    for cmd in ["BODY", "ARTICLE"] {
        let (status, _) = ask(srv.addr, &format!("{cmd} {id}")).await;
        assert!(
            status.starts_with("430"),
            "{cmd} must refuse a missing article, got {status:?}"
        );
    }
}

/// A real file on disk round-trips byte-exact through
/// `make_file_articles_from_path` - decoding every article back in
/// order must reproduce the original bytes, and the posted name must
/// be the file's own basename rather than something the caller chose.
#[test]
fn a_real_file_round_trips_byte_exact() {
    let data: Vec<u8> = (0..250_000u32).map(|i| (i % 251) as u8).collect();
    let path = std::env::temp_dir().join(format!(
        "nzbkit-mock-real-file-fixture-{}.bin",
        std::process::id()
    ));
    std::fs::write(&path, &data).unwrap();

    let want_name = path.file_name().unwrap().to_string_lossy().into_owned();

    let mut articles = HashMap::new();
    let segs = make_file_articles_from_path(&path, 90_000, "realfile", &mut articles).unwrap();
    std::fs::remove_file(&path).ok();

    assert!(segs.len() > 1, "fixture must split into multiple articles");

    let mut rebuilt = vec![0u8; data.len()];
    for (id, _bytes, _part) in &segs {
        let article = &articles[&format!("<{id}>")];
        let decoded = crate::yenc::decode(article).unwrap();
        assert_eq!(
            decoded.name, want_name,
            "posted name should be the file's own basename"
        );
        let start = decoded.begin as usize - 1;
        rebuilt[start..start + decoded.data.len()].copy_from_slice(&decoded.data);
    }
    assert_eq!(
        rebuilt, data,
        "decoding every article back in order must reproduce the original file bytes"
    );
}

/// [`Chaos::lazy`] answers exactly what the stored map would have, for
/// BODY and STAT alike, and a `None` from it is a refusal.
///
/// The ladder in `crates/nzbfast/tests/e2e_ladder` serves gigabytes
/// through this and checks only the extracted payload, so a generator
/// path that drifted from the stored one (a missing dot-stuff, a STAT
/// that refused what BODY serves) would read there as a client defect.
/// This pins the server half on its own.
#[tokio::test]
async fn a_lazy_source_serves_what_the_map_would() {
    let mut stored = HashMap::new();
    // 0..=255 repeating: every byte value, so a column-0 '.' and every
    // critical escape is in the body.
    let data: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
    let segs = make_file_articles("lazy.bin", &data, 40_000, "lazy", &mut stored);
    let id = format!("<{}>", segs[0].0);
    let from_map = MockServer::start(stored.clone(), Chaos::default()).await;
    let lazy = MockServer::start(
        HashMap::new(),
        Chaos {
            lazy: Some(LazyArticles::new(move |id| stored.get(id).cloned())),
            ..Chaos::default()
        },
    )
    .await;

    let (map_status, map_block) = ask(from_map.addr, &format!("BODY {id}")).await;
    let (lazy_status, lazy_block) = ask(lazy.addr, &format!("BODY {id}")).await;
    assert_eq!(lazy_status, map_status);
    assert_eq!(lazy_block, map_block, "the generator's body differs");

    let (stat, _) = ask(lazy.addr, &format!("STAT {id}")).await;
    assert!(
        stat.starts_with("223 "),
        "STAT refused a lazy article: {stat}"
    );
    let (gone, _) = ask(lazy.addr, "BODY <nope@mock>").await;
    assert!(gone.starts_with("430"), "an unknown id must refuse: {gone}");
    let (gone_stat, _) = ask(lazy.addr, "STAT <nope@mock>").await;
    assert!(gone_stat.starts_with("430"), "{gone_stat}");
}
