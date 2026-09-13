//! Hermetic throughput probe for `pool::session::session_loop`.
//!
//! Written 10 Sep 2026 to answer ONE question: does moving
//! `session_loop`'s twenty live locals into two state structs
//! (`Ladder`, `SessionState`) cost throughput in the hottest path in the
//! downloader? A provider round cannot answer that - the WAN is three
//! orders of magnitude louder than the effect being looked for - so this
//! runs the whole pool against an IN-PROCESS mock server over loopback,
//! where the only thing between the articles and the collector is the
//! session loop itself.
//!
//!   cargo run --release -p nzbkit --example session_loop_bench -- [rounds] [mb] [conns]
//!
//! Prints one line per round (MB/s) and the median. Run the SAME source
//! against both builds and interleave the rounds; a single A/A pair is
//! the noise floor and anything inside it is not a reading.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use nzbkit::config::ServerConfig;
use nzbkit::mock::{Chaos, MockServer, make_file_articles};
use nzbkit::pool::{ArticleReq, FetchOutcome, PoolConfig, fetch_all_multi};
use tokio::sync::mpsc;

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let mut args = std::env::args().skip(1);
    let rounds: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(9);
    let mb: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(192);
    let conns: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(8);

    let data: Vec<u8> = (0..mb * 1_000_000)
        .map(|i| (i.wrapping_mul(2654435761) >> 16) as u8)
        .collect();
    let total = data.len() as f64;
    let mut articles = HashMap::new();
    make_file_articles("bench.bin", &data, 750_000, "slb", &mut articles);
    let ids: Vec<Arc<str>> = articles.keys().map(|k| Arc::from(k.as_str())).collect();
    drop(data);

    let srv = MockServer::start(articles, Chaos::default()).await;
    let sc: ServerConfig = srv.server_config();
    let cfg = PoolConfig {
        connections: conns,
        window: 8,
        ..Default::default()
    };

    let mut rates = Vec::with_capacity(rounds);
    for r in 0..rounds {
        let servers = vec![(sc.clone(), cfg.clone())];
        let reqs: Vec<ArticleReq> = ids.iter().map(|id| ArticleReq::fresh(id.clone())).collect();
        let (tx, mut rx) = mpsc::channel(256);
        let collect = tokio::spawn(async move {
            let mut n = 0usize;
            while let Some(o) = rx.recv().await {
                if matches!(o, FetchOutcome::Done { .. }) {
                    n += 1;
                }
            }
            n
        });
        let t0 = Instant::now();
        fetch_all_multi(&servers, reqs, tx).await;
        let el = t0.elapsed();
        let done = collect.await.expect("collector");
        assert_eq!(done, ids.len(), "every article must land");
        let rate = total / el.as_secs_f64() / 1e6;
        println!("round {r}: {rate:.2} MB/s  ({:.3} s)", el.as_secs_f64());
        rates.push(rate);
    }
    rates.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    println!("median {:.2} MB/s over {rounds} rounds", rates[rounds / 2]);
}
