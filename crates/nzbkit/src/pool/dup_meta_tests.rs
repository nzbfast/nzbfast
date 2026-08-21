//! A2 dup-path metadata tests: `age_days` and `part` ride the Work
//! (and the Inflight entry) instead of the retired pool-wide id-keyed
//! maps. The trap this pins: hedge dups are FRESH Works built from the
//! inflight entry, and `stash_handed` rebuilds the steer copy from
//! whatever Work DELIVERED - so a seeding gap anywhere in that chain
//! silently trains the M29 oracle at age 0 for dup-delivered bodies
//! and disarms the split-brain part gate for exactly those bodies.
//! Split out of unit_tests.rs under the size gate; the `pick_dup`
//! flavour lives with its rig in steer.rs. C4 rides the same seams:
//! the completion ORDINAL threads through Work/Inflight/Handed exactly
//! as age and part do, so the identity tests for it live here too.

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
    }
}

fn work(id: &str) -> Work {
    Work {
        age_days: 0,
        part: 0,
        ord: 0,
        id: id.into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    }
}

/// A2 dup-path trap: hedge dups are FRESH Works built from the
/// inflight entry, not copies of the queued original. The entry must
/// therefore carry the original's age and part - the M29 oracle reads
/// `w.age_days` verbatim on both the hit (222) and miss (430) paths,
/// dups included, so a zeroed dup would train every dup-delivered
/// outcome into the age-0 bucket; and a zeroed part would disarm the
/// split-brain gate for exactly the bodies a dup delivers.
#[test]
fn a_suspect_race_dup_inherits_the_originals_age_and_part() {
    let hedge_cfg = PoolConfig {
        ttfb_hedge: true,
        adaptive_timeout: true,
        ..Default::default()
    };
    let (sh, _) = Shared::new(
        vec![ArticleReq {
            id: "<aged@x>".into(),
            age_days: 30,
            part: 2,
        }],
        &[(server("p"), hedge_cfg.clone()), (server("q"), hedge_cfg)],
    );
    // The request's metadata rides the queued Work...
    let w = sh.queue.try_lock().unwrap().pop_front().unwrap();
    assert_eq!((w.age_days, w.part), (30, 2));
    assert_eq!(w.ord, 0, "the ordinal is the accepted-request index");
    // ...registration seeds the inflight entry from it...
    sh.register_inflight(&w, 0);
    {
        let inf = sh.inflight.lock_ok();
        let e = inf.get("<aged@x>").unwrap();
        assert_eq!((e.age_days, e.part), (30, 2));
        assert_eq!(e.ord, w.ord, "the entry carries the original's bit");
    }
    // ...and the dup constructor carries both onto the raced copy.
    sh.mark_suspect("<aged@x>");
    let dup = sh
        .pick_suspect_dup(0b10, 0b10, 0, 0)
        .expect("an idle primary races the suspect");
    assert!(dup.dup);
    assert_eq!(dup.age_days, 30, "a dup delivery charges the TRUE age");
    assert_eq!(dup.part, 2, "a dup delivery still faces the part gate");
    assert_eq!(dup.ord, w.ord, "a dup claims the SAME completion bit");
    // C4 arbitration: whichever copy lands first spends the one bit;
    // the loser's identical claim must find it spent.
    assert!(sh.claim_done(&dup.id, dup.ord), "first answer wins");
    assert!(
        !sh.claim_done(&w.id, w.ord),
        "the original's own answer then lands as a no-op - one outcome per article"
    );
}

/// A2 dup-path trap, delivery side: the part gate compares against the
/// STASHED Work, which `stash_handed` rebuilds from whatever copy
/// delivered - so a dup carrying the wrong decoded part must still
/// steer, and a matching or undeclared part must still finalize.
#[test]
fn a_dup_delivered_wrong_part_body_still_trips_the_part_gate() {
    let servers = vec![
        (server("p"), PoolConfig::default()),
        (server("q"), PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(
        vec![
            ArticleReq {
                id: "<sb@x>".into(),
                age_days: 0,
                part: 2,
            },
            ArticleReq::fresh("<nopart@x>"),
        ],
        &servers,
    );
    sh.workers_live.store(1, Ordering::Release);
    let ctl = QueueControl::default();
    ctl.attach(&sh);
    let deliver = |id: &str, part: u32, dup: bool| {
        let mut w = work(id);
        w.ord = if id == "<sb@x>" { 0 } else { 1 };
        w.dup = dup;
        w.part = part;
        sh.stash_handed(&w, ctx_for(&servers, 0));
    };
    // A dup-delivered body with a mismatched part steers: the requeue
    // is an original that keeps the gate armed for the refetch.
    deliver("<sb@x>", 2, true);
    let ack = ctl.note_decoded("<sb@x>", DecodeReport::Clean { part: Some(3) });
    assert!(
        matches!(ack, DecodeAck::Steered),
        "a wrong-part dup body must be refetched, never owned"
    );
    {
        let inbox = sh.steer_inbox.lock_ok();
        assert_eq!(inbox.len(), 1);
        assert!(!inbox[0].dup, "a steer requeues an ORIGINAL");
        assert_eq!(inbox[0].part, 2, "the requeue keeps the gate armed");
        assert_eq!(&*inbox[0].id, "<sb@x>");
        // C4: the steer un-claimed the article's own bit, so the
        // refetch (or a dup still racing) re-claims through the same
        // one-outcome arbitration - and the requeued Work still names
        // that bit.
        assert_eq!(inbox[0].ord, 0);
        assert!(
            sh.claim_done("<sb@x>", inbox[0].ord),
            "a steered article's ordinal is claimable again"
        );
        assert!(!sh.claim_done("<sb@x>", inbox[0].ord));
        sh.done.lock_ok().clear(inbox[0].ord); // hand the bit back to the rig
    }
    // The matching part is owned clean.
    deliver("<sb@x>", 2, true);
    assert!(matches!(
        ctl.note_decoded("<sb@x>", DecodeReport::Clean { part: Some(2) }),
        DecodeAck::Owned
    ));
    // An undeclared part (0 on the request) gates nothing, whatever
    // the body declared.
    deliver("<nopart@x>", 0, true);
    assert!(matches!(
        ctl.note_decoded("<nopart@x>", DecodeReport::Clean { part: Some(7) }),
        DecodeAck::Owned
    ));
}

/// The borrowed-id dedup prepass (A2's construction rider) keeps the
/// FIRST occurrence of a repeated id, in request order, with the first
/// occurrence's metadata - exactly what the owned HashSet did, minus
/// one String clone per id.
#[test]
fn duplicate_requests_keep_the_first_occurrence_in_order() {
    let reqs = vec![
        ArticleReq {
            id: "<a@x>".into(),
            age_days: 5,
            part: 1,
        },
        ArticleReq::fresh("<b@x>"),
        ArticleReq {
            id: "<a@x>".into(),
            age_days: 9,
            part: 7,
        },
        ArticleReq::fresh("<c@x>"),
    ];
    let (sh, _) = Shared::new(reqs, &[(server("s"), PoolConfig::default())]);
    assert_eq!(sh.pending.load(Ordering::Relaxed), 3);
    let q = sh.queue.try_lock().unwrap();
    let ids: Vec<&str> = q.iter().map(|w| &*w.id).collect();
    assert_eq!(ids, ["<a@x>", "<b@x>", "<c@x>"]);
    assert_eq!(
        (q[0].age_days, q[0].part),
        (5, 1),
        "the first occurrence's metadata wins"
    );
}
