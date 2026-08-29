//! §146 tail give-up tests: the census (`verdict_walkers`) and the
//! commit (`give_up_covered`), including the C4 identity contract -
//! the pair exchange `Walker { id, ord }` so an article in the
//! refusal-to-requeue window can still be claimed by its ordinal.
//! Split out of unit_tests.rs under the size gate; the helper trio
//! mirrors its siblings there.

use super::*;
use crate::config::ServerConfig;

fn server(host: &str) -> ServerConfig {
    ServerConfig {
        host: host.into(),
        port: 119,
        tls: false,
        username: None,
        password: None,
        connections: 1,
        pin_connections: false,
        rcvbuf: None,
        level: 0,
        group: None,
        retention_days: 0,
        block_bytes: None,
        block_account: false,
        bind_ip: None,
        socks5: None,
        enabled: true,
        warm_pool: false,
        idle_release_secs: None,
        idle_keep: None,
        max_source_ips: None,
        address_family: Default::default(),
        tls_hostname: None,
    }
}

fn fresh(ids: &[&str]) -> Vec<ArticleReq> {
    ids.iter().map(|id| ArticleReq::fresh(*id)).collect()
}

fn work(id: &str) -> Work {
    Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: id.into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
        recheck_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    }
}

/// §146 tail give-up census: `verdict_walkers` answers Some only in the
/// exact state the give-up is licensed to spend recovery blocks on -
/// every pending article refusal-tainted - and None the moment any
/// article is still plain payload, including the CORRUPT damage class's
/// refetches, whose evidence is `tried_fail` and must never open this
/// gate.
#[test]
fn verdict_walkers_census_opens_only_on_a_pure_refusal_tail() {
    let ctl = QueueControl::default();
    assert_eq!(
        ctl.verdict_walkers(),
        None,
        "before attach there is no pool to ask"
    );
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>", "<c@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    assert_eq!(
        ctl.verdict_walkers(),
        None,
        "a queue of untried payload is a download, not a tail"
    );
    // Two walkers, one article whose only evidence is a transport
    // failure - that is a refetch (the corrupt-body path), not a
    // refusal, and it must keep the census closed.
    {
        let mut q = sh.queue.try_lock().expect("test owns the queue");
        q[0].tried_430 = 0b01;
        q[1].soft_430 = 0b01;
        q[2].tried_fail = 0b01;
    }
    assert_eq!(
        ctl.verdict_walkers(),
        None,
        "tried_fail is corrupt-class evidence, never a walker"
    );
    // The third article joins the ladder: census opens with all three.
    {
        let mut q = sh.queue.try_lock().expect("test owns the queue");
        q[2].tried_430 = 0b01;
    }
    let walkers = ctl.verdict_walkers().expect("a pure refusal tail");
    assert_eq!(walkers.len(), 3);
    // An in-flight article with no refusal yet is payload on the wire.
    {
        let mut q = sh.queue.try_lock().expect("test owns the queue");
        let w = q.pop_front().expect("three queued");
        sh.register_inflight(&w, 0);
    }
    // NOTE: q[0] carried tried_430, so the entry is seeded refused and
    // the census stays open - now split across queue and inflight.
    let walkers = ctl
        .verdict_walkers()
        .expect("walker in flight still counts");
    assert_eq!(walkers.len(), 3);
    // A clean in-flight article closes it.
    sh.pending.fetch_add(1, Ordering::AcqRel);
    sh.register_inflight(&work("<clean@x>"), 0);
    assert_eq!(
        ctl.verdict_walkers(),
        None,
        "a clean article on the wire may still arrive - no trade"
    );
    sh.inflight.lock_ok().remove("<clean@x>");
    // ...and so does an unaccounted article (pending without a home):
    // the books must balance in one snapshot.
    assert_eq!(
        ctl.verdict_walkers(),
        None,
        "an article invisible between two locks vetoes the snapshot"
    );
    sh.pending.fetch_sub(1, Ordering::AcqRel);
    assert!(ctl.verdict_walkers().is_some());
    // A dup-union verdict claims an article terminal while its ORIGINAL
    // is still mid-read - the inflight entry lingers until that answer
    // lands, seconds on a slow refusal. The census must look straight
    // through it: it is not pending, and counting it failed the books
    // for every tick of the loopback gone rig's tail.
    let mut lingering = work("<claimed@x>");
    lingering.ord = 3; // not one of the three constructed articles
    lingering.tried_430 = 0b01;
    sh.register_inflight(&lingering, 0);
    assert!(sh.claim_done("<claimed@x>", lingering.ord));
    let walkers = ctl
        .verdict_walkers()
        .expect("a lingering terminal original must not close the census");
    assert!(
        walkers.iter().all(|w| &*w.id != "<claimed@x>"),
        "a terminal article is never handed back as a walker"
    );
    sh.inflight.lock_ok().remove("<claimed@x>");
    // A drain keeps its queue: no give-up during a graceful pause.
    sh.draining.store(true, Ordering::Release);
    assert_eq!(ctl.verdict_walkers(), None, "a pause must resume intact");
    sh.draining.store(false, Ordering::Release);
}

/// §146 tail give-up commit: queued walkers cancel, in-flight walkers
/// are claimed where they stand, the run seals when the last one goes,
/// and nothing is ever returned twice.
#[test]
fn give_up_covered_claims_queue_and_flight_and_seals_the_run() {
    let ctl = QueueControl::default();
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>", "<c@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    let finished = sh.finished.subscribe();
    // a stays queued; b goes in flight; c already reached a terminal
    // outcome on its own.
    {
        let mut q = sh.queue.try_lock().expect("test owns the queue");
        q[0].tried_430 = 0b01;
        let mut b = q.remove(1).expect("b queued");
        b.tried_430 = 0b01;
        sh.register_inflight(&b, 0);
        q.pop_back(); // c leaves the queue...
    }
    assert!(sh.claim_done("<c@x>", 2)); // ...and completes on its own
    sh.complete_one();
    // The pairs the census would have handed out (constructed here so
    // the commit can be driven against a hand-built state).
    let ids: Vec<Walker> = ["<a@x>", "<b@x>", "<c@x>"]
        .iter()
        .enumerate()
        .map(|(ord, s)| Walker {
            id: Arc::from(*s),
            ord: ord as u32,
        })
        .collect();
    let mut claimed = ctl.give_up_covered(&ids);
    claimed.sort();
    assert_eq!(
        claimed,
        vec![Arc::<str>::from("<a@x>"), Arc::<str>::from("<b@x>")],
        "c's own outcome stands - the give-up never claims it"
    );
    assert_eq!(sh.pending.load(Ordering::Acquire), 0);
    assert!(
        *finished.borrow(),
        "the last claimed walker seals the run and the fleet winds down"
    );
    assert!(
        ctl.give_up_covered(&ids).is_empty(),
        "a second commit finds everything already terminal"
    );
    // The in-flight walker's eventual verdict lands as a no-op.
    assert!(!sh.claim_done("<b@x>", 1));
}

/// C4 census identity: an article REFUSED but not yet REQUEUED is in
/// neither the queue nor the inflight map - for the length of that
/// window no pool record can answer for its ordinal, so the census
/// pair itself (`Walker { id, ord }`) is what the give-up commit must
/// spend. This drives that window by hand: the walker's Work is out of
/// both structures when `give_up_covered` runs, the commit claims it
/// by the carried ordinal, and the requeue-side worker then finds the
/// claim spent and drops the article exactly as a lost dup race does.
#[test]
fn a_walker_in_the_refusal_to_requeue_window_is_claimed_by_its_census_ordinal() {
    let ctl = QueueControl::default();
    let (sh, _) = Shared::new(
        vec![ArticleReq::fresh("<gap@x>"), ArticleReq::fresh("<peer@x>")],
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    // Both articles walk the ladder; the census sees them and captures
    // their ordinals.
    {
        let mut q = sh.queue.try_lock().unwrap();
        q[0].tried_430 = 0b01;
        q[1].tried_430 = 0b01;
    }
    let walkers = ctl.verdict_walkers().expect("a pure refusal tail");
    assert_eq!(walkers.len(), 2);
    let gap = walkers.iter().find(|w| &*w.id == "<gap@x>").unwrap();
    assert_eq!(gap.ord, 0, "the census carries the accepted-request index");
    // A worker now holds <gap@x> mid-hop: popped from the queue, its
    // refusal read, its requeue not yet inserted - the exact window
    // where no pool structure can name the article.
    let held = {
        let mut q = sh.queue.try_lock().unwrap();
        let at = q.iter().position(|w| &*w.id == "<gap@x>").unwrap();
        q.remove(at).unwrap()
    };
    assert_eq!((&*held.id, held.ord), ("<gap@x>", gap.ord));
    // The commit claims BOTH walkers - the queued peer through cancel,
    // the in-transit one straight off the census pair.
    let mut claimed = ctl.give_up_covered(&walkers);
    claimed.sort();
    assert_eq!(
        claimed,
        vec![Arc::<str>::from("<gap@x>"), Arc::<str>::from("<peer@x>")],
        "the in-transit walker is claimed by its carried ordinal"
    );
    assert_eq!(sh.pending.load(Ordering::Acquire), 0);
    // The worker's requeue side then asks the question every sibling
    // asks before reinserting - and stands down.
    assert!(
        sh.done.lock_ok().contains(held.ord),
        "the worker finds the article terminal and never requeues it"
    );
    assert!(
        !sh.claim_done(&held.id, held.ord),
        "its eventual verdict lands as a no-op - one outcome per article"
    );
}
