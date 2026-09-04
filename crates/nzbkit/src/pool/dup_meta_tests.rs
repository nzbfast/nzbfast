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
        address_family: Default::default(),
        tls_hostname: None,
        warm_reserve: None,
    }
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
        recheck_at: 0,
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
            file: u32::MAX,
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
                file: u32::MAX,
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
        sh.stash_handed(&w, ctx_for(&servers, 0), 0);
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

/// Synthesized segment numbering (22 Aug 2026, tv4-rot1): an NZB whose
/// declared segment numbers are not the yEnc parts trips the part gate
/// on EVERY article, and each trip is a full extra BODY that no dup or
/// hedge tally shows - 2x the payload on the wire, identically on five
/// releases. The tell that separates it from a split-brain: a second,
/// independent server agreeing on the "wrong" part. One server lying
/// is steered and its refetch comes back RIGHT (gate stays armed); two
/// servers agreeing stands the gate down for the run.
#[test]
fn two_servers_agreeing_on_an_undeclared_part_stand_the_gate_down() {
    let servers = vec![
        (server("p"), PoolConfig::default()),
        (server("q"), PoolConfig::default()),
    ];
    // File 0 throughout, and NOT `work()`'s unscoped default: the
    // stand-down is keyed by file and an unscoped request may not
    // earn one (`PartLatch::scoped`), so a rig written on the
    // sentinel would be asserting the gate stands down on a shape
    // where it must not.
    let (sh, _) = Shared::new(
        vec![
            ArticleReq {
                id: "<a@x>".into(),
                age_days: 0,
                part: 1,
                file: 0,
            },
            ArticleReq {
                id: "<b@x>".into(),
                age_days: 0,
                part: 2,
                file: 0,
            },
            ArticleReq {
                id: "<c@x>".into(),
                age_days: 0,
                part: 3,
                file: 0,
            },
        ],
        &servers,
    );
    sh.workers_live.store(2, Ordering::Release);
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    sh.alive[1].fetch_add(1, Ordering::AcqRel);
    let ctl = QueueControl::default();
    ctl.attach(&sh);
    let deliver = |id: &str, ord: u32, part: u32, from: usize| {
        let mut w = work(id);
        w.ord = ord;
        w.part = part;
        w.file = 0;
        sh.stash_handed(&w, ctx_for(&servers, from), 0);
    };
    // A split-brain shape first: server p hands a wrong part, the steer
    // fires, and the refetch from q carries the DECLARED part. Owned,
    // and the gate stays armed - this is the case the gate exists for.
    deliver("<a@x>", 0, 1, 0);
    assert!(matches!(
        ctl.note_decoded("<a@x>", DecodeReport::Clean { part: Some(2) }),
        DecodeAck::Steered
    ));
    sh.steer_inbox.lock_ok().clear();
    deliver("<a@x>", 0, 1, 1);
    assert!(matches!(
        ctl.note_decoded("<a@x>", DecodeReport::Clean { part: Some(1) }),
        DecodeAck::Owned
    ));
    assert!(
        !sh.part_latch.any_off(),
        "a refetch that comes back RIGHT is a split-brain, not a numbering tell"
    );
    // Now the rotated-ladder shape: the refetch from the other server
    // repeats the first copy's part. Two backbones agree - the NZB's
    // numbers are the lie. Owned, gate off, and logged as one steer.
    deliver("<b@x>", 1, 2, 0);
    assert!(matches!(
        ctl.note_decoded("<b@x>", DecodeReport::Clean { part: Some(3) }),
        DecodeAck::Steered
    ));
    sh.steer_inbox.lock_ok().clear();
    deliver("<b@x>", 1, 2, 1);
    assert!(matches!(
        ctl.note_decoded("<b@x>", DecodeReport::Clean { part: Some(3) }),
        DecodeAck::Owned
    ));
    assert!(
        sh.part_latch.any_off(),
        "two servers agreeing latch the gate off"
    );
    assert_eq!(sh.part_latch.steers.load(Ordering::Relaxed), 2);
    // Every later mismatch is owned outright: no steer, no extra BODY.
    deliver("<c@x>", 2, 3, 0);
    assert!(matches!(
        ctl.note_decoded("<c@x>", DecodeReport::Clean { part: Some(1) }),
        DecodeAck::Owned
    ));
    assert!(
        sh.steer_inbox.lock_ok().is_empty(),
        "a latched gate issues no refetch"
    );
    assert_eq!(sh.part_latch.steers.load(Ordering::Relaxed), 2);
}

/// F-09: the stand-down is scoped to the FILE whose numbering proved
/// synthesized. A job mixes files from different posters; one file's
/// latch must not switch off the wrong-part check for the next file,
/// whose mismatch may be a genuine split-brain worth a steer.
#[test]
fn a_latched_file_does_not_stand_the_gate_down_for_another_file() {
    let servers = vec![
        (server("p"), PoolConfig::default()),
        (server("q"), PoolConfig::default()),
    ];
    let req = |id: &str, part: u32, file: u32| ArticleReq {
        id: id.into(),
        age_days: 0,
        part,
        file,
    };
    let (sh, _) = Shared::new(
        vec![req("<a@x>", 1, 0), req("<b@x>", 2, 0), req("<c@x>", 1, 1)],
        &servers,
    );
    sh.workers_live.store(2, Ordering::Release);
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    sh.alive[1].fetch_add(1, Ordering::AcqRel);
    let ctl = QueueControl::default();
    ctl.attach(&sh);
    let deliver = |id: &str, ord: u32, part: u32, file: u32, from: usize| {
        let mut w = work(id);
        w.ord = ord;
        w.part = part;
        w.file = file;
        sh.stash_handed(&w, ctx_for(&servers, from), 0);
    };
    // File 0: two backbones agree on the undeclared part - latched.
    deliver("<a@x>", 0, 1, 0, 0);
    assert!(matches!(
        ctl.note_decoded("<a@x>", DecodeReport::Clean { part: Some(5) }),
        DecodeAck::Steered
    ));
    sh.steer_inbox.lock_ok().clear();
    deliver("<a@x>", 0, 1, 0, 1);
    assert!(matches!(
        ctl.note_decoded("<a@x>", DecodeReport::Clean { part: Some(5) }),
        DecodeAck::Owned
    ));
    assert!(sh.part_latch.is_off(0), "file 0 latched");
    assert!(!sh.part_latch.is_off(1), "file 1 must still be gated");
    // File 0's next mismatch is owned outright, no steer.
    deliver("<b@x>", 1, 2, 0, 0);
    assert!(matches!(
        ctl.note_decoded("<b@x>", DecodeReport::Clean { part: Some(9) }),
        DecodeAck::Owned
    ));
    assert!(sh.steer_inbox.lock_ok().is_empty());
    // File 1's wrong part is still steered: the latch was not run-wide.
    deliver("<c@x>", 2, 1, 1, 0);
    assert!(matches!(
        ctl.note_decoded("<c@x>", DecodeReport::Clean { part: Some(3) }),
        DecodeAck::Steered
    ));
    assert!(
        !sh.steer_inbox.lock_ok().is_empty(),
        "file 1's mismatch must still issue a refetch"
    );
    assert_eq!(sh.part_latch.steers.load(Ordering::Relaxed), 2);
}

/// F-09 residue (31 Aug 2026): `u32::MAX` is [`ArticleReq::file`]'s
/// "unscoped" sentinel - a side fetch, a probe - and it is the ABSENCE
/// of a file index, not one. Every unscoped request in a run shares
/// that single value, so a set keyed BY file must not admit it: one
/// request's two-backbone agreement would otherwise stand the gate down
/// for every other unscoped request beside it, which is the run-wide
/// scope F-09 removed, reinstated at a ONE-request bar on whatever set
/// happened to be batched together. `repair::volume_reqs` batches every
/// recovery volume of a fetch into one request vector, so that set is
/// par2 recovery data.
///
/// Latent rather than live when this was written: the only production
/// caller of `note_decoded` is `get::workers`, whose requests all carry
/// a real slot index, and every unscoped producer runs on a pool with
/// `crc_steer` off, so nothing reaches this seam. It is pinned here
/// because that is a property of the CALLERS - and of a strip
/// (`strip_side_pool_seams`) made for an unrelated reason - and not of
/// the latch.
///
/// Both halves are asserted, because they fail differently: EARNING is
/// what poisons the bucket for the requests beside it, and INHERITING
/// is what a later request does with the poison.
#[test]
fn an_unscoped_request_can_neither_earn_nor_inherit_a_stand_down() {
    let servers = vec![
        (server("p"), PoolConfig::default()),
        (server("q"), PoolConfig::default()),
    ];
    let req = |id: &str, part: u32| ArticleReq {
        id: id.into(),
        age_days: 0,
        part,
        file: u32::MAX,
    };
    let (sh, _) = Shared::new(vec![req("<a@x>", 1), req("<b@x>", 2)], &servers);
    sh.workers_live.store(2, Ordering::Release);
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    sh.alive[1].fetch_add(1, Ordering::AcqRel);
    let ctl = QueueControl::default();
    ctl.attach(&sh);
    // `work()` already defaults `file` to the sentinel; spelled out so
    // the subject of the test cannot drift with that helper.
    let deliver = |id: &str, ord: u32, part: u32, from: usize| {
        let mut w = work(id);
        w.ord = ord;
        w.part = part;
        w.file = u32::MAX;
        sh.stash_handed(&w, ctx_for(&servers, from), 0);
    };
    // Two disjoint backbones agree on `<a@x>`'s undeclared part. The
    // per-ID evidence stands, so the body is OWNED - refusing the
    // stand-down must not turn this into a steer that comes back the
    // same way forever - but nothing is recorded.
    deliver("<a@x>", 0, 1, 0);
    assert!(matches!(
        ctl.note_decoded("<a@x>", DecodeReport::Clean { part: Some(7) }),
        DecodeAck::Steered
    ));
    sh.steer_inbox.lock_ok().clear();
    deliver("<a@x>", 0, 1, 1);
    assert!(matches!(
        ctl.note_decoded("<a@x>", DecodeReport::Clean { part: Some(7) }),
        DecodeAck::Owned
    ));
    assert!(
        !sh.part_latch.any_off(),
        "an unscoped request cannot EARN a stand-down: it is not a file"
    );
    assert!(
        !sh.part_latch.is_off(u32::MAX),
        "and the sentinel is never a latched key"
    );
    // The next unscoped request in the same batch - a different
    // recovery volume of the same fetch - is still gated, and steers.
    deliver("<b@x>", 1, 2, 0);
    assert!(
        matches!(
            ctl.note_decoded("<b@x>", DecodeReport::Clean { part: Some(9) }),
            DecodeAck::Steered
        ),
        "an unscoped request cannot INHERIT a neighbour's stand-down"
    );
    assert!(
        !sh.steer_inbox.lock_ok().is_empty(),
        "and its refetch really is issued"
    );
    assert_eq!(sh.part_latch.steers.load(Ordering::Relaxed), 2);
    // The two doors are pinned SEPARATELY from here down, because each
    // guard alone hides a mutation of the other: with the WRITE
    // refused the sentinel can never be in the set, so the read guard
    // is unfalsifiable through `note_decoded` - and a guard no test can
    // kill is a guard no test is checking (the trap CLAUDE.md's
    // cfg-safety gate entry records in its own words).
    //
    // The WRITE door, while `off` is still empty, so `any_off` - the
    // ledger's "gate stood down" line, read by `pool::saturation` -
    // carries the assertion too.
    assert!(
        !sh.part_latch.stand_down(u32::MAX),
        "the sentinel cannot be recorded, and stand_down says so"
    );
    assert!(
        !sh.part_latch.any_off(),
        "so the ledger does not report a stand-down that never happened"
    );
    // A REAL file index in the same run is unaffected.
    assert!(sh.part_latch.stand_down(0), "a real file still latches");
    assert!(sh.part_latch.is_off(0));
    // The READ door on its own. `off` is reachable from any sibling
    // module of `pool` - the call site in `note_decoded` wrote it
    // directly until 31 Aug 2026 - so the read must refuse the sentinel
    // whatever put it there rather than lean on the write guard.
    sh.part_latch.off.lock_ok().insert(u32::MAX);
    assert!(
        !sh.part_latch.is_off(u32::MAX),
        "the sentinel is never a latched key, however it reached the set"
    );
    assert!(sh.part_latch.is_off(0), "and a real file is unaffected");
}

/// Bug sweep 22 Aug 2026: the "two servers agree" tell has to check the
/// second deliverer's backbone, not assume it. A tail fan-out dup on the
/// FIRST server (or a sibling on its backbone) can win the re-claim
/// after the un-claim and repeat the same wrong part - one backbone
/// talking twice. That must steer again, not stand the gate down for the
/// run; a genuinely different backbone repeating it still latches.
#[test]
fn a_same_backbone_repeat_of_the_wrong_part_does_not_latch() {
    let servers = vec![
        (server("p"), PoolConfig::default()),
        (server("q"), PoolConfig::default()),
    ];
    // File 0, not `work()`'s unscoped default: this rig ends on a
    // stand-down, which an unscoped request may not earn.
    let (sh, _) = Shared::new(
        vec![ArticleReq {
            id: "<a@x>".into(),
            age_days: 0,
            part: 1,
            file: 0,
        }],
        &servers,
    );
    sh.workers_live.store(2, Ordering::Release);
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    sh.alive[1].fetch_add(1, Ordering::AcqRel);
    let ctl = QueueControl::default();
    ctl.attach(&sh);
    let deliver = |from: usize, dup: bool| {
        let mut w = work("<a@x>");
        w.ord = 0;
        w.part = 1;
        w.dup = dup;
        w.file = 0;
        sh.stash_handed(&w, ctx_for(&servers, from), 0);
    };
    deliver(0, false);
    assert!(matches!(
        ctl.note_decoded("<a@x>", DecodeReport::Clean { part: Some(3) }),
        DecodeAck::Steered
    ));
    sh.steer_inbox.lock_ok().clear();
    // Server p's own in-flight fan-out dup wins the re-claim and
    // repeats p's wrong part: not agreement. A dup's bad copy skips the
    // once-per-id budget, so it is steered again rather than owned.
    deliver(0, true);
    assert!(matches!(
        ctl.note_decoded("<a@x>", DecodeReport::Clean { part: Some(3) }),
        DecodeAck::Steered
    ));
    assert!(
        !sh.part_latch.any_off(),
        "one backbone repeating itself is not two backbones agreeing"
    );
    sh.steer_inbox.lock_ok().clear();
    // Server q repeating it IS.
    deliver(1, true);
    assert!(matches!(
        ctl.note_decoded("<a@x>", DecodeReport::Clean { part: Some(3) }),
        DecodeAck::Owned
    ));
    assert!(sh.part_latch.any_off());
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
            file: u32::MAX,
        },
        ArticleReq::fresh("<b@x>"),
        ArticleReq {
            id: "<a@x>".into(),
            age_days: 9,
            part: 7,
            file: u32::MAX,
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
