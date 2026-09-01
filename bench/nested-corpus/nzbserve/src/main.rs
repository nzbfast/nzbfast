//! nzbserve - the nested-corpus loopback rig.
//!
//! Two modes over one deterministic article layout, so the NZB written at
//! generation time and the articles served at bench time always agree:
//!
//!   nzbserve build <legdir>              write <legdir>/<leg>.nzb
//!   nzbserve serve <legdir> [--port N]   serve the leg over NNTP (plain
//!            [--line-mbps N]             TCP, no auth) until killed
//!
//! `--line-mbps` paces the whole server to N MB/s, so a loopback rig can
//! reproduce a real line rate instead of this host's. Added 21 Aug for a
//! disk-counter measurement that needed a 1 GbE box's ~110 MB/s rather
//! than the 700-1300 MB/s loopback runs at unthrottled.
//!
//! A leg directory is what generate.sh produces:
//!   <legdir>/post/   files posted AND served (articles answer 222)
//!   <legdir>/ghost/  files posted but NOT served (every article 430) -
//!                    the par-only leg lists its deleted RAR volumes here
//!   <legdir>/manifest.json  written by generate.sh (not read here)
//!   <legdir>/yenclies.txt   optional: per-file LYING yEnc headers
//!                    (`<postname> <size_lie> <total_lie>` per line) -
//!                    the capability corpus's n37 row, matrix finding F5
//!
//! Article layout: files sorted by (post|ghost, name); file i splits into
//! ART_SIZE chunks; message id = "<NN>-<sanitized-name>-<part>@mock".
//! Encoding is nzbkit's own yEnc encoder via mock::make_file_articles, so
//! every article a client fetches is byte-identical to what a real post of
//! these exact files would decode to. Same convention as the installer
//! acceptance rig (crates/nzbkit/examples/mockserv.rs).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use nzbkit::mock::{Chaos, MockServer, make_file_articles};

/// Article payload size; ~700 KB decoded matches typical real posts.
const ART_SIZE: usize = 700_000;

struct LegFile {
    name: String,
    data: Vec<u8>,
    ghost: bool,
    /// `(size_lie, total_lie)` from `yenclies.txt`: every `=ybegin
    /// size=` for this file overstates the true length by `size_lie`
    /// and every `total=` overstates the part count by `total_lie`,
    /// while the `=ypart begin/end` ranges stay TRUE - a real poster's
    /// tooling gets the ranges right or nothing decodes at all. The
    /// shape of matrix finding F5 (capability leg n37-lying-size).
    lie: Option<(u64, u32)>,
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect()
}

fn read_dir_sorted(dir: &Path, ghost: bool) -> Vec<LegFile> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_file() {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue; // .DS_Store and friends
            }
            let data = std::fs::read(&p).expect("read leg file");
            // A 0-byte file is a legitimate corpus member since the
            // capability corpus's posted-placeholder leg: it rides as a
            // single empty yEnc article (make_file_articles emits it).
            out.push(LegFile {
                name,
                data,
                ghost,
                lie: None,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

struct BuiltLeg {
    nzb: String,
    articles: HashMap<String, Vec<u8>>,
    /// Ghost ids (with angle brackets) - served as 430.
    missing: HashSet<String>,
    total_bytes: u64,
    n_files: usize,
}

/// [`make_file_articles`] with LYING yEnc headers: `=ybegin size=`
/// overstates the true length by `size_lie` and `total=` overstates the
/// part count by `total_lie`, while every `=ypart begin/end` range stays
/// TRUE. That is the shape a real mis-posting produces - the ranges have
/// to be right or nothing decodes at all - and it is what capability leg
/// n37-lying-size posts (matrix row 20 / finding F5): the receiving
/// client preallocates the slot at the DECLARED size, so until settle
/// truncates back to the FileDesc length the published file carries a
/// zero-padded tail at rc=0 with verify green.
///
/// Kept beside [`make_file_articles`] rather than in `nzbkit::mock`
/// because it exists to post something WRONG - a rig affordance, not a
/// mock any product code should reach for.
fn make_lying_file_articles(
    name: &str,
    data: &[u8],
    art_size: usize,
    idtag: &str,
    size_lie: u64,
    total_lie: u32,
    out: &mut HashMap<String, Vec<u8>>,
) -> Vec<(String, u64, u32)> {
    let total = data.len().div_ceil(art_size.max(1)).max(1) as u32;
    let lied = data.len() as u64 + size_lie;
    let mut segs = Vec::new();
    // Same 0-byte rule as make_file_articles: an empty file is still one
    // article on the wire, and here it is the sharpest case of all - a
    // slot preallocated at `size_lie` bytes for a file with none.
    if data.is_empty() {
        let article = nzbkit::yenc::encode(name, lied, Some((1, total + total_lie)), 1, &[]);
        let id = format!("{idtag}-1@mock");
        segs.push((id.clone(), article.len() as u64, 1));
        out.insert(format!("<{id}>"), article);
        return segs;
    }
    for (i, chunk) in data.chunks(art_size.max(1)).enumerate() {
        let part = i as u32 + 1;
        let begin = (i * art_size) as u64 + 1;
        let article =
            nzbkit::yenc::encode(name, lied, Some((part, total + total_lie)), begin, chunk);
        let id = format!("{idtag}-{part}@mock");
        segs.push((id.clone(), article.len() as u64, part));
        out.insert(format!("<{id}>"), article);
    }
    segs
}

/// Read the optional `yenclies.txt` sidecar: one `<postname> <size_lie>
/// <total_lie>` per line, `#` comments and blank lines skipped. A name
/// the sidecar mentions that the leg does not post is a hard error -
/// a silently-ignored line is a leg that quietly stops testing the
/// thing it exists for.
fn read_yenc_lies(legdir: &Path, files: &mut [LegFile]) {
    let path = legdir.join("yenclies.txt");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        assert!(
            f.len() == 3,
            "{}:{}: expected `<postname> <size_lie> <total_lie>`, got {line:?}",
            path.display(),
            n + 1
        );
        let size_lie: u64 = f[1].parse().expect("size_lie must be a number");
        let total_lie: u32 = f[2].parse().expect("total_lie must be a number");
        let hit = files.iter_mut().find(|lf| lf.name == f[0]);
        let Some(hit) = hit else {
            panic!(
                "{}:{}: names {:?}, which this leg does not post",
                path.display(),
                n + 1,
                f[0]
            );
        };
        hit.lie = Some((size_lie, total_lie));
    }
}

/// Build articles + NZB for a leg. Deterministic: same files in, same
/// message ids and same NZB out.
fn build_leg(legdir: &Path) -> BuiltLeg {
    let mut files = read_dir_sorted(&legdir.join("post"), false);
    files.extend(read_dir_sorted(&legdir.join("ghost"), true));
    assert!(!files.is_empty(), "no files under {}/post", legdir.display());
    read_yenc_lies(legdir, &mut files);

    let mut articles = HashMap::new();
    let mut missing = HashSet::new();
    let mut total_bytes = 0u64;
    let mut nzb = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    // Optional NZB-level metadata: a legdir carrying `nzbpass.txt` gets
    // the standard <head><meta type="password"> block (the a4 leg - a
    // password that rides ONLY in the NZB, the common indexer shape).
    if let Ok(pw) = std::fs::read_to_string(legdir.join("nzbpass.txt")) {
        let pw = pw.trim();
        if !pw.is_empty() {
            nzb.push_str(&format!(
                "<head><meta type=\"password\">{pw}</meta></head>\n"
            ));
        }
    }
    for (i, f) in files.iter().enumerate() {
        total_bytes += f.data.len() as u64;
        let idtag = format!("{i:02}-{}", sanitize(&f.name));
        let segs = match f.lie {
            Some((size_lie, total_lie)) => make_lying_file_articles(
                &f.name,
                &f.data,
                ART_SIZE,
                &idtag,
                size_lie,
                total_lie,
                &mut articles,
            ),
            None => make_file_articles(&f.name, &f.data, ART_SIZE, &idtag, &mut articles),
        };
        if f.ghost {
            for (id, _, _) in &segs {
                missing.insert(format!("<{id}>"));
            }
        }
        nzb.push_str(&format!(
            "<file poster=\"bench@nzbfast\" date=\"0\" subject=\"&quot;{}&quot; yEnc (1/{})\">\n\
             <groups><group>alt.binaries.bench</group></groups>\n<segments>\n",
            f.name,
            segs.len()
        ));
        for (id, bytes, number) in &segs {
            nzb.push_str(&format!(
                "<segment bytes=\"{bytes}\" number=\"{number}\">{id}</segment>\n"
            ));
        }
        nzb.push_str("</segments>\n</file>\n");
    }
    nzb.push_str("</nzb>\n");
    BuiltLeg { nzb, articles, missing, total_bytes, n_files: files.len() }
}

fn nzb_path(legdir: &Path) -> PathBuf {
    let leg = legdir
        .canonicalize()
        .unwrap_or_else(|_| legdir.to_path_buf())
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "leg".into());
    legdir.join(format!("{leg}.nzb"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: nzbserve build <legdir> | nzbserve serve <legdir> [--port N]";
    let (mode, legdir) = match (args.first().map(String::as_str), args.get(1)) {
        (Some(m @ ("build" | "serve")), Some(d)) => (m, PathBuf::from(d)),
        _ => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };
    let mut port: u16 = 11901;
    let mut line_mbps: u64 = 0;
    let mut it = args.iter().skip(2);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--port" => {
                port = it
                    .next()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or_else(|| panic!("--port needs a number"));
            }
            "--line-mbps" => {
                line_mbps = it
                    .next()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or_else(|| panic!("--line-mbps needs a number"));
            }
            other => panic!("unknown arg {other:?}\n{usage}"),
        }
    }

    let built = build_leg(&legdir);
    let nzb_file = nzb_path(&legdir);
    std::fs::write(&nzb_file, &built.nzb).expect("write nzb");
    println!(
        "[nzbserve] {}: {} files, {:.1} MB decoded, {} articles ({} ghosted), nzb: {}",
        legdir.display(),
        built.n_files,
        built.total_bytes as f64 / 1048576.0,
        built.articles.len(),
        built.missing.len(),
        nzb_file.display()
    );
    if mode == "build" {
        return;
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let chaos = Chaos { missing: built.missing, ..Chaos::default() };
        let srv = MockServer::start_bound(
            &format!("127.0.0.1:{port}"),
            built.articles,
            HashMap::new(),
            Vec::new(),
            chaos,
        )
        .await;
        if line_mbps > 0 {
            srv.set_line_bps(line_mbps * 1_000_000);
        }
        println!(
            "[nzbserve] NNTP ready on {} - point any client at host 127.0.0.1 port {}, TLS off, no auth{}",
            srv.addr,
            srv.addr.port(),
            if line_mbps > 0 {
                format!(", paced to {line_mbps} MB/s")
            } else {
                String::new()
            }
        );
        let mut last = 0u64;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let s = srv.served.load(std::sync::atomic::Ordering::Relaxed);
            if s != last {
                println!("[nzbserve] {s} articles served");
                last = s;
            }
        }
    });
}
