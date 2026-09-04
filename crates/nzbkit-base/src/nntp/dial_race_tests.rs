//! What is left of the dial-racing round (TODO §129 3c tail).
//!
//! `NZBFAST_DIAL_RACE` raced the top two resolved candidates at a 50 ms
//! stagger and took whichever TCP connect landed first. §129 3a then
//! gave the default path a candidate walk ([`dial_in_order`]), which
//! wins the two shapes the race was built for - a dead first node and a
//! blackholed first node - at one SYN. The flag was priced against that
//! walk on 8 Aug 2026 and RETIRED; this file keeps the one assertion
//! that outlived it.
//!
//! The residual shape the race could still win - a first candidate that
//! is REACHABLE but slower to hand back its handshake than the second -
//! cannot be built out of real sockets on a loopback rig: a listening
//! socket completes in microseconds, and the full-backlog trick that
//! stalls a connect elsewhere does not bite on macOS (probed 8 Aug, a
//! connect past `listen(1)` still returned in 0 ms). So it was priced
//! against the two dialers directly, with a synthetic dialer whose
//! per-address latency was exact and whose invocation count IS the SYN
//! count. Virtual time, paused clock:
//!
//! ```text
//! shape (cand 1 / cand 2)      in-order      race        verdict
//! healthy-lan   5 ms / 5 ms      5 ms / 1     5 ms / 1   free, wins nothing
//! healthy-wan  90 ms / 95 ms    90 ms / 1    90 ms / 2   DOUBLED SYN, wins nothing
//! slow-first  300 ms / 20 ms   300 ms / 1    70 ms / 2   race wins 230 ms
//! slow-first  2.0 s / 20 ms    2000 ms / 1   70 ms / 2   race wins 1930 ms
//! dead-second  90 ms / refuse   90 ms / 1   141 ms / 3   race LOSES 51 ms
//! ```
//!
//! The stagger does make the race free on a dial faster than 50 ms, but
//! a real provider RTT is not faster than 50 ms, so the doubled SYN is
//! paid on essentially every healthy dial - for nothing, since a
//! healthy first candidate wins the race anyway. Set against one win in
//! a shape nothing has ever observed, the flag also lost two shapes the
//! walk handles: `dead-second` above (the race cancels the healthy dial
//! in flight when the second candidate refuses, then restarts it), and
//! the third-candidate case below.

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn addr(last: u8) -> std::net::SocketAddr {
    std::net::SocketAddr::from(([192, 0, 2, last], 119))
}

/// The third candidate the race could not see, and the walk must.
///
/// `dial_in_order` walks up to `MAX_DIAL_CANDIDATES` (3). The race was
/// a two-way `select!` over `addrs[0]` and `addrs[1]` with no third
/// arm, so a pool answering with two dead nodes and a live one behind
/// them failed the dial outright under the flag while the default path
/// connects - the flag making the very shape it existed for worse.
/// `the_candidate_walk_stops_at_the_cap` pins the negative case (an
/// all-dead list stops at the cap); this is the positive one.
#[tokio::test(start_paused = true)]
async fn the_walk_reaches_a_live_third_candidate() {
    let syns = Arc::new(AtomicUsize::new(0));
    let counted = syns.clone();
    // Candidates 1 and 2 refuse; 3 is live. The dialer's invocation
    // count is the SYN count.
    let one = move |target: std::net::SocketAddr| {
        let syns = syns.clone();
        Box::pin(async move {
            syns.fetch_add(1, Ordering::Relaxed);
            if target == addr(3) {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(target)
            } else {
                tokio::time::sleep(Duration::from_millis(1)).await;
                Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
            }
        })
            as std::pin::Pin<
                Box<dyn std::future::Future<Output = std::io::Result<std::net::SocketAddr>> + Send>,
            >
    };

    let landed = dial_in_order(&[addr(1), addr(2), addr(3)], one)
        .await
        .expect("the walk must reach the live third address");
    assert_eq!(
        landed,
        addr(3),
        "the walk stopped short of the only live candidate"
    );
    assert_eq!(
        counted.load(Ordering::Relaxed),
        3,
        "one SYN per candidate, no more"
    );
}
