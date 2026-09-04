//! Tests for the "Why is this slow?" attribution core (TODO 207).
//!
//! Split out of `whyslow.rs` verbatim when TODO 312 item 7's `Knee`
//! verdict took that file past the 3,000-line ceiling (TODO 106, the
//! `check_tests.rs` pattern). Behaviour unchanged: this is still
//! `whyslow`'s own child module, so `use super::*` reaches its private
//! items exactly as it did in place.

use super::*;

/// The rigs' wall clock: a real unix millisecond stamp, not a
/// small number. `missing_case` measures the post's age against
/// `at_ms`, so a toy epoch would put every plausible post date in
/// the future and quietly suppress the arm under test.
const T0: u64 = 1_755_000_000_000;

fn srv(host: &str, connected: usize, budget: usize, bytes: u64, blocked: u64) -> ServerTick {
    ServerTick {
        host: host.into(),
        connected,
        budget,
        bytes,
        blocked_ms: blocked,
        reconnects: 0,
        refused: false,
        tried: 100,
        missing: 0,
        art_ms: 0,
        // TODO 318: no provider has stated a connection cap. The
        // default every case but the sole-source ones wants, and it
        // must stay 0: `capped_since` is the gate on the whole
        // `SoleCap` arm, so a non-zero default would let that verdict
        // land in a case that is about something else.
        capped_since: 0,
        granted_hi: 0,
        capped_at: 0,
        cap_said: String::new(),
    }
}

/// Drive `n` seconds of a steady regime; cumulative counters
/// advance by the per-tick deltas given.
struct Rig {
    core: Core,
    t: u64,
    bytes: HashMap<String, u64>,
    blocked: HashMap<String, u64>,
    recon: HashMap<String, u64>,
    /// What slowstore's diagnostic probes are currently saying. A
    /// field rather than another positional argument: `run` is
    /// already at the clippy limit, and every existing case wants
    /// the default (no diagnostic verdict).
    suspect: bool,
    /// Per-server (tried, missing) for the article census, when a
    /// case is about the post rather than the link. Same reasoning
    /// as `suspect`: every other case wants `srv`'s default of 100
    /// tried and none missing.
    miss: Option<(u64, u64)>,
    /// The running post's date, as `StreamHub::post_unix` publishes
    /// it. 0 (the default every other case wants) is UNKNOWN, which
    /// asserts neither propagation nor a takedown.
    post_unix: i64,
    /// TODO 312 item 3: (cap in force, configured total, auto), as
    /// `LiveStats` publishes them. A cap of 0 - the default every
    /// other case wants - is the rule OFF, so nothing here can
    /// produce a `Fleet` vote by accident.
    fleet: (usize, usize, bool),
    /// TODO 275 item 7: the ceiling the in-run governor may walk the
    /// cap to, as `LiveStats::line_cap_ceiling` publishes it. 0 - the
    /// default every case written before the second ceiling wants - is
    /// NO CLAIM, which `fleet_bound` reads as `LINE_CAP_MAX_FLEET`, so
    /// every one of those cases still asks the question it was written
    /// to ask.
    fleet_ceiling: usize,
    /// TODO 275 item 7: has a provider refused this account for
    /// capacity at any point, as `LiveStats::line_cap_refused`
    /// publishes it. `false` - the default every other case wants -
    /// leaves the receipt off and changes no verdict, because it feeds
    /// none.
    fleet_refused: bool,
    /// TODO 312 item 7: the stale knee the fleet was built under, as
    /// `LiveStats::line_cap_knee` publishes it. `None` - the default
    /// every other case wants - is no knee applied, so nothing here
    /// can produce a `Knee` vote by accident.
    knee: Option<nzbkit::pool::linecap::FleetKnee>,
    /// Sockets a draining predecessor is holding behind this run.
    /// 0 - the default every other case wants - is no hand-over in
    /// flight, which is what a rig with no drain slot reports and
    /// what every case written before this field assumed.
    drain_connected: usize,
    /// TODO 318: PER-SERVER (tried, missing), for the cases where the
    /// whole point is that the servers do not agree. `miss` above is
    /// fleet-uniform, which is the right default for every case about
    /// the POST - and useless for a case about one server holding a
    /// post the others have lost, which is the shape this arm exists
    /// for. Consulted first; a host with no entry falls back to `miss`
    /// and then to `srv`'s own 100-tried default, so adding this field
    /// changed no existing case.
    per_miss: HashMap<String, (u64, u64)>,
    /// TODO 318: per-server (capped_since, granted_hi, capped_at,
    /// said) - what a provider has stated about its own connection
    /// ceiling. Empty for every case but the sole-source ones.
    caps: HashMap<String, (u64, usize, usize, &'static str)>,
}

impl Rig {
    fn new() -> Rig {
        Rig {
            core: Core::default(),
            t: T0,
            bytes: HashMap::new(),
            blocked: HashMap::new(),
            recon: HashMap::new(),
            suspect: false,
            miss: None,
            post_unix: 0,
            fleet: (0, 0, false),
            fleet_ceiling: 0,
            fleet_refused: false,
            knee: None,
            drain_connected: 0,
            per_miss: HashMap::new(),
            caps: HashMap::new(),
        }
    }

    /// TODO 318: give one host its own article census.
    fn miss_on(&mut self, host: &str, tried: u64, missing: u64) -> &mut Rig {
        self.per_miss.insert(host.into(), (tried, missing));
        self
    }

    /// TODO 318: state a provider's connection ceiling on one host -
    /// it granted `granted` of the `asked` we wanted, and said so.
    fn cap_on(&mut self, host: &str, granted: usize, asked: usize, said: &'static str) -> &mut Rig {
        self.caps.insert(host.into(), (T0, granted, asked, said));
        self
    }

    #[expect(clippy::too_many_arguments)]
    fn run(
        &mut self,
        n: usize,
        bps: f64,
        throttle: u64,
        anchor: u64,
        cpu: f64,
        storage: bool,
        // (host, connected, budget, d_bytes, d_blocked, d_recon, refused)
        servers: &[(&str, usize, usize, u64, u64, u64, bool)],
    ) {
        for _ in 0..n {
            self.t += 1000;
            let sv = servers
                .iter()
                .map(|&(h, c, b, db, dbl, dr, refused)| {
                    let bytes = self.bytes.entry(h.into()).or_default();
                    *bytes += db;
                    let blocked = self.blocked.entry(h.into()).or_default();
                    *blocked += dbl;
                    let recon = self.recon.entry(h.into()).or_default();
                    *recon += dr;
                    let (tried, missing) = self
                        .per_miss
                        .get(h)
                        .copied()
                        .or(self.miss)
                        .unwrap_or((100, 0));
                    let (since, granted, asked, said) =
                        self.caps.get(h).copied().unwrap_or((0, 0, 0, ""));
                    ServerTick {
                        refused,
                        reconnects: *recon,
                        tried,
                        missing,
                        capped_since: since,
                        granted_hi: granted,
                        capped_at: asked,
                        cap_said: said.into(),
                        ..srv(h, c, b, *bytes, *blocked)
                    }
                })
                .collect();
            self.core.tick(Tick {
                owner: Some("job1".into()),
                at_ms: self.t,
                achieved_bps: bps,
                throttle_bps: throttle,
                anchor_bps: anchor,
                cpu_pct: cpu,
                storage,
                storage_suspect: self.suspect,
                post_unix: self.post_unix,
                fleet_cap: self.fleet.0,
                fleet_configured: self.fleet.1,
                fleet_auto: self.fleet.2,
                fleet_ceiling: self.fleet_ceiling,
                fleet_refused: self.fleet_refused,
                fleet_knee: self.knee.clone(),
                drain_connected: self.drain_connected,
                servers: sv,
            });
        }
    }
}

#[test]
fn unknown_until_the_window_fills() {
    let mut r = Rig::new();
    r.run(
        MAJORITY - 1,
        100e6,
        0,
        1_000_000_000,
        20.0,
        false,
        &[("a", 8, 8, 100_000_000, 0, 0, false)],
    );
    assert_eq!(
        r.core.verdict().0,
        Layer::Unknown,
        "no verdict before a majority"
    );
}

/// §210 (d). The clamp itself, over the four cases that decide it.
#[test]
fn the_local_link_caps_the_typed_line_and_nothing_else() {
    const LINE: u64 = 710 * 125_000;
    // Gary's shape: a 1200 Mbps Wi-Fi link carries ~660, so 660 is
    // the mark the graph draws 100% at - and it names the link
    // rather than calling the LAN a line speed setting.
    let wifi = 82_500_000;
    assert_eq!(
        link_capped((LINE, "line"), Some(wifi)),
        (wifi, "link"),
        "the LAN is lower, so the LAN is the ceiling"
    );
    // A link that covers the line changes nothing.
    assert_eq!(
        link_capped((LINE, "line"), Some(200_000_000)),
        (LINE, "line")
    );
    // A MEASURED anchor is a rate this machine actually sustained -
    // direct evidence about the whole path, including this hop.
    // An estimate of one hop may not argue with it.
    assert_eq!(
        link_capped((LINE, "measured"), Some(wifi)),
        (LINE, "measured")
    );
    // A tunnel, or an interface the OS would not rate, gives no
    // ceiling at all: nothing to clamp with.
    assert_eq!(link_capped((LINE, "line"), None), (LINE, "line"));
    // And no anchor stays no anchor - never invent one from a link.
    assert_eq!(link_capped((0, ""), Some(wifi)), (0, ""));
}

/// ...and what the clamp is FOR. Gary's own numbers only move the
/// 100% mark (660 of 710 still rides the line bar), so this takes
/// the shape that also moves the VERDICT: an 866 Mbps Wi-Fi 5 link
/// carries ~476 Mbit under a gigabit line, and a run at that
/// ceiling was being blamed on the providers.
#[test]
fn riding_the_local_link_is_not_a_provider_shortfall() {
    const LINE: u64 = 1000 * 125_000;
    let capped = link_capped((LINE, "line"), Some(59_537_500));
    assert_eq!(capped, (59_537_500, "link"));
    let mut r = Rig::new();
    r.run(
        WINDOW,
        58e6,
        0,
        capped.0,
        30.0,
        false,
        &[("a", 8, 8, 58_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Line);
    // Against the unclamped line the same run reads as a shortfall
    // the reader can do nothing about, and names a host that is
    // delivering everything the LAN will carry.
    let mut r = Rig::new();
    r.run(
        WINDOW,
        58e6,
        0,
        LINE,
        30.0,
        false,
        &[("a", 8, 8, 58_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Provider);
}

#[test]
fn riding_the_anchor_is_line_speed() {
    let mut r = Rig::new();
    r.run(
        WINDOW,
        950e6,
        0,
        1_000_000_000,
        50.0,
        false,
        &[("a", 8, 8, 950_000_000, 900_000, 0, false)],
    );
    // Note the huge blocked_ms: a healthy download parks workers.
    // That must NOT read as a client problem (the §108 lesson).
    assert_eq!(r.core.verdict().0, Layer::Line);
}

#[test]
fn a_binding_cap_is_the_limit() {
    let mut r = Rig::new();
    r.run(
        WINDOW,
        99e6,
        100_000_000,
        1_000_000_000,
        20.0,
        false,
        &[("a", 8, 8, 99_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Limit);
}

#[test]
fn shortfall_with_idle_sockets_is_the_provider() {
    let mut r = Rig::new();
    // Half the anchor, workers not parked: upstream.
    r.run(
        WINDOW,
        500e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 500_000_000, 100, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Provider);
}

/// Gary's 16 Aug regime: 44% of the articles are not on the
/// servers, so the pool spends its wire time on requests that
/// return nothing and the fleet delivers a fraction of the anchor.
/// Every other instrument reads this as a shaped or capped
/// provider - the sockets ARE idle - and the verdict used to name
/// a host that was behaving perfectly.
#[test]
fn a_post_full_of_holes_is_not_the_provider() {
    let mut r = Rig::new();
    r.miss = Some((2253, 982)); // 4506 tried, 1965 missing across two
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("a", 8, 8, 35_000_000, 100, 0, false),
            ("b", 8, 8, 35_000_000, 100, 0, false),
        ],
    );
    assert_eq!(r.core.verdict().0, Layer::Missing);
}

/// ...and the same shortfall with an intact post still convicts
/// the provider. The layer above must not swallow the case it was
/// inserted in front of.
#[test]
fn a_shortfall_on_an_intact_post_is_still_the_provider() {
    let mut r = Rig::new();
    r.miss = Some((2253, 20)); // under 1%
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("a", 8, 8, 35_000_000, 100, 0, false),
            ("b", 8, 8, 35_000_000, 100, 0, false),
        ],
    );
    assert_eq!(r.core.verdict().0, Layer::Provider);
}

/// The articles may not be available YET, or may have been taken
/// down. A release grabbed the hour it pre'd 430s everywhere while
/// the backbones fill in, and from in here that is pixel-for-pixel
/// a takedown. The calendar is the only thing that separates them,
/// so the young arm says so and nothing else does.
#[test]
fn a_brand_new_post_full_of_holes_is_still_propagating() {
    let mut r = Rig::new();
    r.miss = Some((2253, 982));
    // Two hours old, against the rig's own wall clock.
    r.post_unix = (r.t / 1000) as i64 - 2 * 3600;
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("news.alpha.com", 8, 8, 35_000_000, 100, 0, false),
            ("news.beta.com", 8, 8, 35_000_000, 100, 0, false),
        ],
    );
    assert_eq!(r.core.verdict(), (Layer::Missing, "young"));
}

/// The other side of the same regime: old enough that propagation
/// is finished, and two independent backbones each saying so. Only
/// here may the surface tell a user that waiting will not help.
#[test]
fn an_old_post_two_backbones_agree_is_gone() {
    let mut r = Rig::new();
    r.miss = Some((2253, 982));
    r.post_unix = (r.t / 1000) as i64 - 9 * 86_400;
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("news.alpha.com", 8, 8, 35_000_000, 100, 0, false),
            ("news.beta.com", 8, 8, 35_000_000, 100, 0, false),
        ],
    );
    assert_eq!(r.core.verdict(), (Layer::Missing, "gone"));
}

/// TODO 318, and the regime this whole arm exists for. Measured on a
/// live three-provider install, 29 Aug 2026: giganews 98% missing,
/// usenet.farm 47%, vipernews 0.1%, and vipernews pinned at its own
/// account's ceiling (`502 connection limit (40) reached`) holding a
/// handful of the 40 sockets asked for. The published verdict was `missing`/`gone` -
/// "waiting will not help" - about a post one provider had in full.
#[test]
fn the_only_server_that_has_the_post_being_capped_is_its_own_verdict() {
    let mut r = Rig::new();
    // Old enough that the `gone` arm would otherwise be licensed, and
    // two backbones DO agree about their own spools. Neither fact is
    // about the post.
    r.post_unix = (r.t / 1000) as i64 - 9 * 86_400;
    r.miss_on("news.giganews.com", 4000, 3920)
        .miss_on("news.usenetfarm.eu", 4000, 1880)
        .miss_on("news.vipernews.com", 4000, 4)
        .cap_on(
            "news.vipernews.com",
            7,
            40,
            "502 connection limit (40) reached",
        );
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("news.giganews.com", 8, 8, 5_000_000, 100, 0, false),
            ("news.usenetfarm.eu", 8, 8, 5_000_000, 100, 0, false),
            // Under its budget, which is what a capped host looks like
            // - and what `worst_refusal` would convict it for, one arm
            // further down, in words that send the reader away from the
            // only server that can finish this job.
            ("news.vipernews.com", 2, 40, 60_000_000, 100, 0, false),
        ],
    );
    assert_eq!(
        r.core.verdict(),
        (Layer::SoleCap, "news.vipernews.com"),
        "the operative constraint is the cap on the one server that has it"
    );
    let e = r.core.sole_capped().expect("the receipts travel with it");
    assert_eq!(e.granted_hi, 7);
    assert_eq!(e.capped_at, 40);
    assert_eq!(e.said, "502 connection limit (40) reached");
    assert!((e.missing_pct - 0.1).abs() < 0.001, "{}", e.missing_pct);
    // ...and the fleet-wide rate the old verdict rested on is
    // untouched: both numbers are true, and the panel ships both.
    let fleet = r.core.fleet_missing().expect("sample is large enough");
    assert!((fleet - 0.4837).abs() < 0.001, "{fleet}");
}

/// The same census with NO provider cap stated. Nothing here licenses
/// naming a cap, so the verdict falls back to the post - but NOT to
/// `gone`, because a server holding 99.9% of it refutes "waiting will
/// not help" whatever the other two backbones agree about.
#[test]
fn a_sole_source_with_no_stated_cap_is_the_post_but_never_gone() {
    let mut r = Rig::new();
    r.post_unix = (r.t / 1000) as i64 - 9 * 86_400;
    r.miss_on("news.giganews.com", 4000, 3920)
        .miss_on("news.usenetfarm.eu", 4000, 1880)
        .miss_on("news.vipernews.com", 4000, 4);
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("news.giganews.com", 8, 8, 5_000_000, 100, 0, false),
            ("news.usenetfarm.eu", 8, 8, 5_000_000, 100, 0, false),
            ("news.vipernews.com", 8, 8, 60_000_000, 100, 0, false),
        ],
    );
    assert_eq!(r.core.verdict(), (Layer::Missing, ""));
    assert!(r.core.sole_capped().is_none(), "no cap was ever stated");
}

/// A cap the provider stated and then GRANTED in full binds nothing.
/// `capped_since` alone is a fact about some earlier moment; the pair
/// with `capped_at > granted_hi` is what says sockets were refused.
#[test]
fn a_stated_cap_that_granted_everything_asked_binds_nothing() {
    let mut r = Rig::new();
    r.miss_on("news.giganews.com", 4000, 3920)
        .miss_on("news.usenetfarm.eu", 4000, 1880)
        .miss_on("news.vipernews.com", 4000, 4)
        .cap_on(
            "news.vipernews.com",
            40,
            40,
            "502 connection limit (40) reached",
        );
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("news.giganews.com", 8, 8, 5_000_000, 100, 0, false),
            ("news.usenetfarm.eu", 8, 8, 5_000_000, 100, 0, false),
            ("news.vipernews.com", 40, 40, 60_000_000, 100, 0, false),
        ],
    );
    assert_eq!(r.core.verdict().0, Layer::Missing);
}

/// TWO servers holding the post is not a sole source, and a cap on one
/// of them binds nothing: the other carries what the capped one
/// cannot. The whole claim rests on there being no second source.
#[test]
fn two_servers_holding_the_post_is_not_a_sole_source() {
    let mut r = Rig::new();
    r.miss_on("news.giganews.com", 4000, 3920)
        .miss_on("news.usenetfarm.eu", 4000, 4)
        .miss_on("news.vipernews.com", 4000, 4)
        .cap_on(
            "news.vipernews.com",
            7,
            40,
            "502 connection limit (40) reached",
        );
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("news.giganews.com", 8, 8, 5_000_000, 100, 0, false),
            ("news.usenetfarm.eu", 8, 8, 32_000_000, 100, 0, false),
            ("news.vipernews.com", 2, 40, 33_000_000, 100, 0, false),
        ],
    );
    assert!(r.core.sole_capped().is_none(), "two holders, not one");
    assert_eq!(r.core.verdict().0, Layer::Missing);
}

/// On a ONE-provider install "only this server has it" is true of
/// every post ever downloaded and says nothing. The honest verdict
/// there is the plain provider one, which is what a capped single
/// server already got.
#[test]
fn a_single_provider_install_is_never_sole_sourced() {
    let mut r = Rig::new();
    r.miss_on("news.vipernews.com", 4000, 4).cap_on(
        "news.vipernews.com",
        7,
        40,
        "502 connection limit (40) reached",
    );
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("news.vipernews.com", 2, 40, 70_000_000, 100, 0, false)],
    );
    assert!(r.core.sole_capped().is_none());
    assert_eq!(
        r.core.verdict(),
        (Layer::Provider, "news.vipernews.com"),
        "under its budget: the existing single-host arm, unchanged"
    );
}

/// A server that saw a handful of requests and missed none of them is
/// not evidence that it HOLDS the post - and without
/// `BACKBONE_MIN_TRIED` it would be the best server on every run. Here
/// the two real servers have both lost the post, so `gone` stands.
#[test]
fn a_barely_used_server_cannot_be_the_one_that_has_it() {
    let mut r = Rig::new();
    r.post_unix = (r.t / 1000) as i64 - 9 * 86_400;
    r.miss_on("news.giganews.com", 4000, 3920)
        .miss_on("news.usenetfarm.eu", 4000, 1880)
        .miss_on("news.vipernews.com", 20, 0)
        .cap_on(
            "news.vipernews.com",
            7,
            40,
            "502 connection limit (40) reached",
        );
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("news.giganews.com", 8, 8, 35_000_000, 100, 0, false),
            ("news.usenetfarm.eu", 8, 8, 35_000_000, 100, 0, false),
            ("news.vipernews.com", 2, 40, 0, 100, 0, false),
        ],
    );
    assert!(r.core.sole_capped().is_none());
    assert_eq!(r.core.verdict(), (Layer::Missing, "gone"));
}

/// The YOUNG arm is deliberately left alone by the holder guard: one
/// backbone holding a post the others have not received yet IS
/// propagation, so a holder corroborates that claim rather than
/// refuting it. Uncapped, so the cap arm stays out of the way.
#[test]
fn a_holder_corroborates_propagation_rather_than_refuting_it() {
    let mut r = Rig::new();
    r.post_unix = (r.t / 1000) as i64 - 2 * 3600;
    r.miss_on("news.giganews.com", 4000, 3920)
        .miss_on("news.usenetfarm.eu", 4000, 1880)
        .miss_on("news.vipernews.com", 4000, 4);
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("news.giganews.com", 8, 8, 5_000_000, 100, 0, false),
            ("news.usenetfarm.eu", 8, 8, 5_000_000, 100, 0, false),
            ("news.vipernews.com", 8, 8, 60_000_000, 100, 0, false),
        ],
    );
    assert_eq!(r.core.verdict(), (Layer::Missing, "young"));
}

/// TODO 318 item 1 on its own: the best single server's own miss rate,
/// which is the number that says whether a post is completable at all.
/// Qualified by `BACKBONE_MIN_TRIED`, and stable across ticks - a tie
/// broken by HashMap order would flap a verdict's detail without the
/// evidence moving.
#[test]
fn the_best_single_server_is_the_lowest_qualified_miss_rate() {
    let mut r = Rig::new();
    r.miss_on("news.giganews.com", 4000, 3920)
        .miss_on("news.usenetfarm.eu", 4000, 1880)
        .miss_on("news.vipernews.com", 4000, 4)
        // A fill host with a tiny perfect sample: excluded, or it
        // would be the best server on every run.
        .miss_on("news.zeta.com", 10, 0);
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("news.giganews.com", 8, 8, 5_000_000, 100, 0, false),
            ("news.usenetfarm.eu", 8, 8, 5_000_000, 100, 0, false),
            ("news.vipernews.com", 8, 8, 60_000_000, 100, 0, false),
            ("news.zeta.com", 1, 1, 0, 0, 0, false),
        ],
    );
    let (host, rate) = r.core.best_missing().expect("four servers, three qualify");
    assert_eq!(host, "news.vipernews.com");
    assert!((rate - 0.001).abs() < 1e-9, "{rate}");
    // ...and no server asked enough to have an opinion yields nothing
    // at all, which is what the payload's empty host field carries. A
    // rate of 0.0 with no host would read as "some server has all of
    // it", which is the exact misreading this field exists to stop.
    let mut r = Rig::new();
    r.miss = Some((10, 0));
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("news.alpha.com", 8, 8, 70_000_000, 100, 0, false)],
    );
    assert!(r.core.best_missing().is_none());
}

/// Five resellers of ONE backbone are one opinion. The same old
/// post, the same misses, every server behind the same upstream:
/// the shortfall is asserted, the takedown is NOT.
#[test]
fn one_backbone_however_emphatic_cannot_say_gone() {
    let mut r = Rig::new();
    r.miss = Some((2253, 982));
    r.post_unix = (r.t / 1000) as i64 - 9 * 86_400;
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            // Same brand, two hostnames: `backbone_of` folds them.
            ("news.alpha.com", 8, 8, 35_000_000, 100, 0, false),
            ("reader.alpha.com", 8, 8, 35_000_000, 100, 0, false),
        ],
    );
    assert_eq!(r.core.verdict(), (Layer::Missing, ""));
}

/// An NZB with no usable date reads as post_unix 0, and 0 is
/// UNKNOWN, not "posted this second". Calling it young would
/// promise a wait that may never end.
#[test]
fn an_undated_post_claims_neither_cause() {
    let mut r = Rig::new();
    r.miss = Some((2253, 982));
    r.post_unix = 0;
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("news.alpha.com", 8, 8, 35_000_000, 100, 0, false),
            ("news.beta.com", 8, 8, 35_000_000, 100, 0, false),
        ],
    );
    assert_eq!(r.core.verdict(), (Layer::Missing, ""));
}

/// A post dated in the future - a wrong clock, a mis-stamped NZB -
/// is not evidence of freshness. Neither arm may fire on it.
#[test]
fn a_post_dated_in_the_future_claims_neither_cause() {
    let mut r = Rig::new();
    r.miss = Some((2253, 982));
    r.post_unix = (r.t / 1000) as i64 + 30 * 86_400;
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("news.alpha.com", 8, 8, 35_000_000, 100, 0, false),
            ("news.beta.com", 8, 8, 35_000_000, 100, 0, false),
        ],
    );
    assert_eq!(r.core.verdict(), (Layer::Missing, ""));
}

/// The boundary itself, walked both sides. `GONE_MIN_AGE_DAYS` is
/// where this project already draws the propagation line and this
/// surface must not draw a fourth one of its own.
#[test]
fn the_young_gone_boundary_is_gone_min_age_days() {
    for (age_secs, want) in [
        (YOUNG_MAX_SECS - 60, "young"),
        (YOUNG_MAX_SECS, "gone"),
        (YOUNG_MAX_SECS + 86_400, "gone"),
    ] {
        let mut r = Rig::new();
        r.miss = Some((2253, 982));
        r.post_unix = (r.t / 1000) as i64 - age_secs;
        r.run(
            WINDOW,
            70e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[
                ("news.alpha.com", 8, 8, 35_000_000, 100, 0, false),
                ("news.beta.com", 8, 8, 35_000_000, 100, 0, false),
            ],
        );
        assert_eq!(
            r.core.verdict(),
            (Layer::Missing, want),
            "post {age_secs}s old"
        );
    }
}

/// A backbone that saw a handful of requests is not one of the
/// independent opinions "gone" needs, even at a 100% miss rate on
/// its own tiny sample. Under `BACKBONE_MIN_TRIED` it sits out.
#[test]
fn a_barely_used_backbone_is_not_a_second_opinion() {
    let mut r = Rig::new();
    r.post_unix = (r.t / 1000) as i64 - 9 * 86_400;
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("news.alpha.com", 8, 8, 35_000_000, 100, 0, false)],
    );
    // The rig's `miss` is fleet-uniform, so the small server is
    // built by hand: 4000 tried / 1900 missing on alpha, 10/10 on
    // the fill host. Fleet-wide that clears MISSING_BAR; the fill
    // host's own sample does not clear BACKBONE_MIN_TRIED.
    let mut core = Core::default();
    for i in 0..WINDOW {
        core.tick(Tick {
            owner: Some("job1".into()),
            at_ms: T0 + (i as u64 + 1) * 1000,
            achieved_bps: 70e6,
            throttle_bps: 0,
            anchor_bps: 1_000_000_000,
            cpu_pct: 30.0,
            storage: false,
            storage_suspect: false,
            post_unix: (T0 / 1000) as i64 - 9 * 86_400,
            fleet_cap: 0,
            fleet_configured: 0,
            fleet_auto: false,
            fleet_ceiling: 0,
            fleet_refused: false,
            fleet_knee: None,
            drain_connected: 0,
            servers: vec![
                ServerTick {
                    tried: 4000,
                    missing: 1900,
                    ..srv("news.alpha.com", 8, 8, 35_000_000 * (i as u64 + 1), 100)
                },
                ServerTick {
                    tried: 10,
                    missing: 10,
                    ..srv("news.beta.com", 8, 8, 35_000_000 * (i as u64 + 1), 100)
                },
            ],
        });
    }
    assert_eq!(core.verdict(), (Layer::Missing, ""));
}

/// A handful of misses in the first seconds of a run is not a
/// verdict about the post: under `MISSING_MIN_TRIED` the rate is
/// not read at all, however bad it looks.
#[test]
fn a_tiny_sample_of_misses_convicts_nothing() {
    let mut r = Rig::new();
    r.miss = Some((20, 19)); // 95% missing, 40 articles fleet-wide
    r.run(
        WINDOW,
        70e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("a", 8, 8, 35_000_000, 100, 0, false),
            ("b", 8, 8, 35_000_000, 100, 0, false),
        ],
    );
    assert_ne!(r.core.verdict().0, Layer::Missing);
}

#[test]
fn shortfall_with_parked_workers_and_hot_cpu_is_cpu() {
    let mut r = Rig::new();
    r.run(
        WINDOW,
        300e6,
        0,
        1_000_000_000,
        95.0,
        false,
        // 8 conns * 1000 ms = 8000 worker-ms; 6000 blocked = 75%.
        &[("a", 8, 8, 300_000_000, 6000, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Cpu);
}

#[test]
fn shortfall_with_parked_workers_and_cool_cpu_is_the_client() {
    let mut r = Rig::new();
    r.run(
        WINDOW,
        300e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 300_000_000, 6000, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Client);
}

#[test]
fn a_storage_pause_engaging_is_disk() {
    let mut r = Rig::new();
    r.run(
        WINDOW,
        50e6,
        0,
        1_000_000_000,
        30.0,
        true,
        &[("a", 8, 8, 50_000_000, 7000, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Disk);
}

/// §108 option 2. The volume that is BAD but not bad enough to trip
/// the breaker: parked on the write side, delivering a twentieth of
/// the line, for as long as you care to watch. The breaker needs
/// three quarters of a three-minute window and never fires here, so
/// before the diagnostic this read as Client - honest about the
/// three candidates, but it sends nobody to look at their drive.
#[test]
fn a_slow_volume_is_named_before_the_breaker_trips() {
    let mut r = Rig::new();
    let regime = |r: &mut Rig| {
        r.run(
            WINDOW,
            50e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 50_000_000, 7000, 0, false)],
        )
    };
    // No answer yet: the probes have not run, or have come back
    // fast. We do not guess.
    regime(&mut r);
    assert_eq!(
        r.core.verdict().0,
        Layer::Client,
        "with no disk answer the honest verdict is our own pipeline"
    );
    assert!(
        r.core.disk_question,
        "...and the fork must be ASKING, or no probe ever runs"
    );

    // slowstore's probes come back slow, twice: now it is the disk,
    // with no pause anywhere in sight.
    r.suspect = true;
    regime(&mut r);
    assert_eq!(r.core.verdict().0, Layer::Disk);
    assert!(
        r.core.disk_question,
        "the question stays open on a Disk vote - closing it would \
         stop the probes, stale the answer and flip back to Client"
    );

    // The volume recovers: a fast probe drops the suspicion and the
    // verdict goes back to naming us, not the hardware.
    r.suspect = false;
    regime(&mut r);
    assert_eq!(r.core.verdict().0, Layer::Client);
}

/// The question is only asked where an answer would change the
/// verdict. Everywhere else, probing a volume would be work for its
/// own sake - and this feature's whole licence is that it never
/// touches a healthy daemon's disk.
#[test]
fn the_disk_question_is_asked_only_at_the_fork() {
    // Riding the line: nothing is slow.
    let mut r = Rig::new();
    r.run(
        WINDOW,
        950e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 950_000_000, 900, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Line);
    assert!(!r.core.disk_question, "a healthy line asks nothing");

    // Short of the line, but the sockets could not fill the pipe -
    // upstream, so the volume is not the question.
    let mut r = Rig::new();
    r.run(
        WINDOW,
        50e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 50_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Provider);
    assert!(!r.core.disk_question, "a provider shortfall asks nothing");

    // Downstream, but CPU owns it: a witness already condemned.
    let mut r = Rig::new();
    r.run(
        WINDOW,
        50e6,
        0,
        1_000_000_000,
        97.0,
        false,
        &[("a", 8, 8, 50_000_000, 7000, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Cpu);
    assert!(!r.core.disk_question, "CPU is its own witness");

    // The breaker is in force: it owns the volume from here, and
    // its probes are already running on the paused cadence.
    let mut r = Rig::new();
    r.run(
        WINDOW,
        50e6,
        0,
        1_000_000_000,
        30.0,
        true,
        &[("a", 8, 8, 50_000_000, 7000, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Disk);
    assert!(
        !r.core.disk_question,
        "a real pause closes the question - the breaker owns it"
    );
}

/// TODO 312 item 3, GH #62's own shape: a 1 Gbit line, two accounts
/// at 50 connections each, and the fleet cap holding the run at 50
/// sockets that are each carrying 6 Mbit against a plan of 150. The
/// line is a quarter used, so more sockets would help, and the cap
/// is at its ceiling so the governor cannot grow it. Before this
/// verdict existed the same evidence read as `Provider` - true of
/// nothing the reader could act on.
#[test]
fn our_own_fleet_cap_is_named_when_the_line_has_headroom() {
    const GIGABIT: u64 = 125_000_000;
    let mut r = Rig::new();
    r.fleet = (nzbkit::pool::linecap::LINE_CAP_MAX_FLEET, 100, true);
    r.run(
        WINDOW,
        37.5e6,
        0,
        GIGABIT,
        30.0,
        false,
        &[
            ("a.example", 25, 25, 18_750_000, 0, 0, false),
            ("b.example", 25, 25, 18_750_000, 0, 0, false),
        ],
    );
    assert_eq!(r.core.verdict().0, Layer::Fleet);
    // ...and it travels with its working, per the module rule.
    assert_eq!(r.core.fleet.cap, 50);
    assert_eq!(r.core.fleet.configured, 100);
    assert_eq!(r.core.fleet.carry_bps, 750_000);
    assert!(
        r.core.fleet.implied > 50,
        "the measured carry has to imply a bigger fleet than the cap, \
         or there is nothing to report: {}",
        r.core.fleet.implied
    );
}

/// TODO 275 item 7: an automatic cap sitting at the FIRST ceiling is
/// not at its ceiling any more on an install whose line anchor was
/// MEASURED, so convicting it there would name a rule that is three
/// ticks from raising itself.
///
/// The same evidence as the case above, in the same shape, with one
/// field different: the ceiling this fleet may walk to. That is the
/// whole test. The verdict's "the cap cannot fix itself" condition was
/// spelled `cap < LINE_CAP_MAX_FLEET` until the second ceiling existed,
/// and a constant is exactly the wrong thing to ask now that the bar is
/// per-install - the error being avoided is the one the auto arm was
/// written for in the first place, one ceiling up.
#[test]
fn a_cap_below_the_second_ceiling_is_not_yet_binding() {
    const GIGABIT: u64 = 125_000_000;
    let servers = [
        ("a.example", 25, 25, 18_750_000, 0, 0, false),
        ("b.example", 25, 25, 18_750_000, 0, 0, false),
    ];
    let mut r = Rig::new();
    r.fleet = (nzbkit::pool::linecap::LINE_CAP_MAX_FLEET, 100, true);
    // A measured anchor with a fleet grant of 100: the governor may
    // still walk this cap from 50 to 100.
    r.fleet_ceiling = nzbkit::pool::linecap::LINE_CAP_SUPPLY_MAX_FLEET;
    r.run(WINDOW, 37.5e6, 0, GIGABIT, 30.0, false, &servers);
    assert_ne!(
        r.core.verdict().0,
        Layer::Fleet,
        "a cap with room left above it is not what is holding this second"
    );
    // And at the second ceiling the identical evidence convicts again,
    // which is what says the field and not the arithmetic did it.
    let mut top = Rig::new();
    top.fleet = (nzbkit::pool::linecap::LINE_CAP_SUPPLY_MAX_FLEET, 200, true);
    top.fleet_ceiling = nzbkit::pool::linecap::LINE_CAP_SUPPLY_MAX_FLEET;
    top.run(WINDOW, 37.5e6, 0, GIGABIT, 30.0, false, &servers);
    assert_eq!(top.core.verdict().0, Layer::Fleet);
    assert_eq!(
        top.core.fleet.ceiling,
        nzbkit::pool::linecap::LINE_CAP_SUPPLY_MAX_FLEET,
        "the ceiling travels with the working, like every other receipt"
    );
}

/// TODO 275 item 7, the residue handoff's OWED 4: a cap a provider's
/// capacity refusal has PINNED at the first ceiling is binding, and the
/// panel says which provider fact pinned it.
///
/// This is the case the second ceiling was built for and the one it
/// went silent on. The install measured its line and its accounts grant
/// 100, so the governor was free to walk the cap from 50 to 100 - and
/// `a_cap_below_the_second_ceiling_is_not_yet_binding` above is exactly
/// that fleet, declining to convict for exactly that reason. Then a
/// provider refuses for capacity, the governor's ceiling latches back
/// to `LINE_CAP_MAX_FLEET` for the rest of the run, and the identical
/// evidence has to convict: this cap is never going to fix itself.
///
/// The two tests are each other's control and they differ in ONE field,
/// which is the ceiling the pool publishes. That is the whole of what
/// OWED 4 repaired on this side: the field was seeded at fleet build
/// and never written again, so it read 100 for the life of a run whose
/// governor was pinned at 50.
///
/// `fleet_refused` is asserted as a RECEIPT and never as an input. It
/// feeds no condition - the stood-down ceiling already carries the
/// verdict - and if it ever did, this panel would be asking one
/// question twice and could answer it two ways in one second.
#[test]
fn a_cap_a_refusal_pinned_at_the_first_ceiling_is_binding() {
    use nzbkit::pool::linecap::{LINE_CAP_MAX_FLEET, LINE_CAP_SUPPLY_MAX_FLEET};
    const GIGABIT: u64 = 125_000_000;
    let servers = [
        ("a.example", 25, 25, 18_750_000, 0, 0, false),
        ("b.example", 25, 25, 18_750_000, 0, 0, false),
    ];
    let mut r = Rig::new();
    r.fleet = (LINE_CAP_MAX_FLEET, 100, true);
    // The pool republishes the ceiling every governor tick, and a
    // capacity refusal has stood it back down to the first ceiling for
    // the rest of this run.
    r.fleet_ceiling = LINE_CAP_MAX_FLEET;
    r.fleet_refused = true;
    r.run(WINDOW, 37.5e6, 0, GIGABIT, 30.0, false, &servers);
    assert_eq!(
        r.core.verdict().0,
        Layer::Fleet,
        "a cap that cannot rise is what is holding this second"
    );
    assert_eq!(r.core.fleet.ceiling, LINE_CAP_MAX_FLEET);
    assert!(
        r.core.fleet.refused,
        "the reason the ceiling fell has to travel with the working, or the panel \
         names our own budget and offers to raise it into an account that said no"
    );
    // The control is the SAME fleet with the ceiling the gauge used to
    // be frozen at, which is what the surface saw before OWED 4: a
    // governor with 50 sockets of room it did not have.
    let mut stale = Rig::new();
    stale.fleet = (LINE_CAP_MAX_FLEET, 100, true);
    stale.fleet_ceiling = LINE_CAP_SUPPLY_MAX_FLEET;
    stale.run(WINDOW, 37.5e6, 0, GIGABIT, 30.0, false, &servers);
    assert_ne!(
        stale.core.verdict().0,
        Layer::Fleet,
        "a stale ceiling has to read as a cap with room left, or this test proves nothing"
    );
}

/// The regime TODO 208 MEASURED, and the one this verdict must stay
/// out of: the fleet is filling the line. 80% of the anchor is short
/// of `LINE_BAR` so it is still a shortfall - but it is over
/// `LINE_CAP_SUPPLY_PCT`, so the line has no headroom the sockets
/// are failing to use and more of them is what §208 measured as
/// costing wall. Same cap, same configured total, same conditions
/// otherwise as the case above.
#[test]
fn a_line_bound_fleet_is_not_our_cap() {
    const GIGABIT: u64 = 125_000_000;
    let mut r = Rig::new();
    r.fleet = (nzbkit::pool::linecap::LINE_CAP_MAX_FLEET, 100, true);
    r.run(
        WINDOW,
        100e6,
        0,
        GIGABIT,
        30.0,
        false,
        &[
            ("a.example", 25, 25, 50_000_000, 0, 0, false),
            ("b.example", 25, 25, 50_000_000, 0, 0, false),
        ],
    );
    assert_eq!(r.core.verdict().0, Layer::Provider);
}

/// TODO 312 item 7, the shape a 5 Gbit bench box measured on
/// 28 Aug 2026: the fleet cap allows more than the account is
/// dialling, because a 19-day-old auto-tune knee sits under it.
/// Rungs of 50, 77 and 100 all ran 32 sockets and landed within
/// 0.4 MB/s of each other, and every instrument read clean.
///
/// Reduced to one 1 Gbit line: a cap of 50 that takes nothing (the
/// account's knee'd ceiling of 32 is already below it), 32 sockets
/// each carrying 6 Mbit against a plan of 150, so the line is a
/// quarter used and more sockets would help. `Fleet` correctly says
/// nothing here - `configured` is UNDER `cap` - and before this
/// verdict existed the same evidence fell through to `Provider`,
/// which is our own measurement blamed on the provider it measured.
#[test]
fn our_own_stale_knee_is_named_when_the_cap_is_not_what_binds() {
    const GIGABIT: u64 = 125_000_000;
    let mut r = Rig::new();
    r.fleet = (nzbkit::pool::linecap::LINE_CAP_MAX_FLEET, 32, true);
    r.knee = Some(nzbkit::pool::linecap::FleetKnee {
        host: "a.example".into(),
        at: 32,
        takes: 18,
        age_secs: 19 * 86_400,
    });
    r.run(
        WINDOW,
        24e6,
        0,
        GIGABIT,
        30.0,
        false,
        &[("a.example", 32, 32, 24_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Knee);
    // The detail is the HOST, as `Provider`'s is, so the page can
    // compose a sentence and land the remedy on that server.
    assert_eq!(r.core.verdict().1, "a.example");
    // ...and it travels with its working, per the module rule.
    assert_eq!(r.core.knee.at, 32);
    assert_eq!(r.core.knee.takes, 18);
    assert_eq!(r.core.knee.age_secs, 19 * 86_400);
    assert_eq!(r.core.knee.carry_bps, 750_000);
    assert!(
        r.core.knee.implied > 32,
        "the measured carry has to imply a bigger fleet than the ceiling \
         the knee leaves, or there is nothing to report: {}",
        r.core.knee.implied
    );
}

/// The same second with NO knee on file: identical numbers, and the
/// verdict must not be `Knee`.
///
/// This is the negative control the assertion above cannot do
/// without. A verdict that fired on "the line has headroom and the
/// sockets are slow" alone would pass that test while saying
/// nothing about a knee at all, and would then convict our own
/// auto-tune on every under-carrying fleet in the world.
#[test]
fn with_no_knee_on_file_the_same_second_is_not_ours() {
    const GIGABIT: u64 = 125_000_000;
    let mut r = Rig::new();
    r.fleet = (nzbkit::pool::linecap::LINE_CAP_MAX_FLEET, 32, true);
    r.run(
        WINDOW,
        24e6,
        0,
        GIGABIT,
        30.0,
        false,
        &[("a.example", 32, 32, 24_000_000, 0, 0, false)],
    );
    assert_ne!(r.core.verdict().0, Layer::Knee);
    assert_eq!(r.core.knee.host, "", "no knee, no server to name");
}

/// The regime §208 MEASURED, asked of this arm too: the fleet is
/// filling the line, so more sockets is what that round priced as
/// costing wall. Same knee, same fleet, 80% of the anchor - over
/// `LINE_CAP_SUPPLY_PCT` and so no headroom the sockets are failing
/// to use. `supply_room` is the shared gate that has to hold here,
/// and holding it in ONE place is why it was factored out rather
/// than copied.
#[test]
fn a_line_bound_fleet_is_not_our_knee_either() {
    const GIGABIT: u64 = 125_000_000;
    let mut r = Rig::new();
    r.fleet = (nzbkit::pool::linecap::LINE_CAP_MAX_FLEET, 32, true);
    r.knee = Some(nzbkit::pool::linecap::FleetKnee {
        host: "a.example".into(),
        at: 32,
        takes: 18,
        age_secs: 19 * 86_400,
    });
    r.run(
        WINDOW,
        100e6,
        0,
        GIGABIT,
        30.0,
        false,
        &[("a.example", 32, 32, 100_000_000, 0, 0, false)],
    );
    assert_ne!(r.core.verdict().0, Layer::Knee);
}

/// PRECEDENCE, on the one fleet where both arms are true at once:
/// server `a` is under a stale knee, server `b` is under the cap's
/// share, and both statements are correct. The cap wins, because it
/// is the bigger and fleet-wide lever and one number gets one
/// sentence.
///
/// It is not a hypothetical shape: `configured` is the SUM of every
/// server's knee-included ceiling, so a knee'd server and an
/// un-knee'd one on one fleet is exactly how `configured > cap` and
/// `takes > 0` come to hold together.
#[test]
fn the_fleet_cap_outranks_a_stale_knee_when_both_are_binding() {
    const GIGABIT: u64 = 125_000_000;
    let mut r = Rig::new();
    // 15 from a's knee'd ceiling plus 40 from b = 55 configured,
    // over a typed cap of 40: the cap really is taking sockets.
    r.fleet = (nzbkit::pool::linecap::LINE_CAP_MAX_FLEET, 55, false);
    r.knee = Some(nzbkit::pool::linecap::FleetKnee {
        host: "a.example".into(),
        at: 15,
        takes: 5,
        age_secs: 30 * 86_400,
    });
    r.run(
        WINDOW,
        30e6,
        0,
        GIGABIT,
        30.0,
        false,
        &[
            ("a.example", 15, 15, 11_250_000, 0, 0, false),
            ("b.example", 25, 25, 18_750_000, 0, 0, false),
        ],
    );
    assert_eq!(r.core.verdict().0, Layer::Fleet);
    // The knee's own working is still published - the panel ships
    // every arm's receipts whichever one is talking - so the
    // assertion above is about PRECEDENCE and not about the knee
    // evidence having been thrown away.
    assert_eq!(r.core.knee.takes, 5);
}

/// A pool that made NO CLAIM - a rig, a CLI run - publishes a
/// `configured` of 0, which reads as "cannot say" and never as "you
/// configured nothing". `fleet_bound` has that rule and this arm
/// inherits it: with 0 as the comparand every implied fleet is
/// bigger, so the verdict would fire on every such pool that
/// happened to have a knee on file.
#[test]
fn a_pool_that_configured_nothing_is_not_convicted() {
    const GIGABIT: u64 = 125_000_000;
    let mut r = Rig::new();
    r.fleet = (nzbkit::pool::linecap::LINE_CAP_MAX_FLEET, 0, true);
    r.knee = Some(nzbkit::pool::linecap::FleetKnee {
        host: "a.example".into(),
        at: 32,
        takes: 18,
        age_secs: 19 * 86_400,
    });
    r.run(
        WINDOW,
        24e6,
        0,
        GIGABIT,
        30.0,
        false,
        &[("a.example", 32, 32, 24_000_000, 0, 0, false)],
    );
    assert_ne!(r.core.verdict().0, Layer::Knee);
}

/// The cross-job hand-over must not hide a binding cap.
///
/// `achieved_bps` is `Daemon::current_speed_bps`, which ADDS the
/// draining predecessor's bytes so the queue's readout does not dip
/// at a job boundary, while `servers` is the successor's fleet
/// alone. Dividing the one by the other inflated the apparent
/// per-socket carry, shrank the implied fleet, and dropped
/// `implied > cap` - so for the whole hand-over the panel fell
/// through to `Provider` while our own cap was in fact binding.
///
/// Same conditions as
/// `our_own_fleet_cap_is_named_when_the_line_has_headroom` - a 1 Gbit
/// anchor a quarter used, a cap at its own ceiling so the governor
/// cannot grow it - with the 50 sockets on the wire SPLIT across the
/// hand-over: 10 on the successor, 40 still on the drainer.
///
/// The arithmetic is what makes this bite rather than merely differ.
/// 37.5 MB/s over all 50 sockets is 750 kB/s each, which implies 170
/// sockets against a cap of 50, so the cap is named. Over the
/// successor's 10 alone it reads 3.75 MB/s each, which implies 35 -
/// UNDER the cap - so `implied > cap` fails and the tick falls
/// through to `Provider` with our own cap binding the whole time.
/// Both assertions below therefore fail on the pre-fix tree.
#[test]
fn a_hand_over_does_not_hide_a_binding_fleet_cap() {
    const GIGABIT: u64 = 125_000_000;
    let mut r = Rig::new();
    r.fleet = (nzbkit::pool::linecap::LINE_CAP_MAX_FLEET, 100, true);
    r.drain_connected = 40;
    r.run(
        WINDOW,
        37.5e6,
        0,
        GIGABIT,
        30.0,
        false,
        &[("a.example", 10, 10, 37_500_000, 0, 0, false)],
    );
    assert_eq!(
        r.core.verdict().0,
        Layer::Fleet,
        "the drainer's sockets belong in the divisor - the rate \
         already counts its bytes"
    );
    assert_eq!(
        r.core.fleet.carry_bps, 750_000,
        "whole-wire rate over whole-wire sockets"
    );
}

/// A fleet the cap cannot touch makes no claim at all.
///
/// `pin_connections` is the documented escape from the fleet cap -
/// `get/fleet.rs` skips `line_share` for a pinned server, so its
/// number stands whatever the cap says - and `line_cap_uncapped` is
/// therefore stamped 0 for it, which is what
/// `linecap::seed_uncapped` sums into the `configured` that arrives
/// here. An all-pinned fleet reaches this arm as 0 and a
/// half-pinned one as the unpinned rows alone; both must stay
/// silent, and the loop below is that assertion.
///
/// THE THIRD CASE IS THE DEFECT, kept here as the contrast because
/// it is the only thing that makes the first two mean anything: the
/// SAME picture arriving as `configured = 75` - one 25-socket
/// account plus a server pinned to 50, which is what the pre-fix
/// stamp summed - does fire, and told a user whose pin had already
/// lifted the cap that the cap of 25 was holding them back, offering
/// to raise it. So this test says what the input means, and the
/// stamp that produces the input is pinned on the other side by
/// `get/fleet.rs`'s
/// `a_pinned_server_is_not_something_the_cap_can_cut`.
#[test]
fn a_pinned_fleet_is_not_held_back_by_a_cap_it_escapes() {
    const GIGABIT: u64 = 125_000_000;
    // (cap, configured, auto), then the verdict this arm may reach.
    for (fleet, want_fleet) in [
        // Everything pinned: nothing for the cap to cut.
        ((25, 0, false), false),
        // One pinned server beside one 25-socket account, under a
        // 25-socket cap: the cap cuts nothing either.
        ((25, 25, false), false),
        // The pre-fix sum, counting the pinned ceiling in.
        ((25, 75, false), true),
    ] {
        let mut r = Rig::new();
        r.fleet = fleet;
        r.run(
            WINDOW,
            37.5e6,
            0,
            GIGABIT,
            30.0,
            false,
            &[
                ("a.example", 25, 25, 18_750_000, 0, 0, false),
                ("pinned.example", 25, 25, 18_750_000, 0, 0, false),
            ],
        );
        assert_eq!(
            r.core.verdict().0 == Layer::Fleet,
            want_fleet,
            "a cap that cuts nothing binds nothing: fleet {fleet:?}"
        );
    }
}

/// An AUTOMATIC cap under the ceiling is three ticks from raising
/// itself (`linecap::fleet_step`), so naming it is reporting a rule
/// mid-stride. The identical evidence at the identical rate, with
/// only the cap moved off the ceiling, must stay `Provider`.
#[test]
fn an_auto_cap_below_the_ceiling_can_still_fix_itself() {
    const GIGABIT: u64 = 125_000_000;
    let mut r = Rig::new();
    r.fleet = (25, 100, true);
    r.run(
        WINDOW,
        37.5e6,
        0,
        GIGABIT,
        30.0,
        false,
        &[
            ("a.example", 12, 12, 18_750_000, 0, 0, false),
            ("b.example", 13, 13, 18_750_000, 0, 0, false),
        ],
    );
    assert_eq!(r.core.verdict().0, Layer::Provider);
    // ...and the same cap TYPED does bind, because a typed fleet
    // pins the governor (`conntune::line_cap_auto_resolve`): there is no
    // raise coming, so 25 is what this install will run at for ever.
    let mut r = Rig::new();
    r.fleet = (25, 100, false);
    r.run(
        WINDOW,
        37.5e6,
        0,
        GIGABIT,
        30.0,
        false,
        &[
            ("a.example", 12, 12, 18_750_000, 0, 0, false),
            ("b.example", 13, 13, 18_750_000, 0, 0, false),
        ],
    );
    assert_eq!(r.core.verdict().0, Layer::Fleet);
}

/// A cap that is not taking any socket away is not binding
/// anything, whatever the rest of the evidence says. `configured`
/// at 0 is a pool that made no claim - a rig, a CLI `get` - and
/// must read as "cannot say" rather than as "you configured
/// nothing", which would convict the cap on every such run.
#[test]
fn a_cap_above_what_the_accounts_allow_binds_nothing() {
    const GIGABIT: u64 = 125_000_000;
    for fleet in [(50, 50, false), (50, 0, false), (0, 100, false)] {
        let mut r = Rig::new();
        r.fleet = fleet;
        r.run(
            WINDOW,
            37.5e6,
            0,
            GIGABIT,
            30.0,
            false,
            &[
                ("a.example", 25, 25, 18_750_000, 0, 0, false),
                ("b.example", 25, 25, 18_750_000, 0, 0, false),
            ],
        );
        assert_eq!(r.core.verdict().0, Layer::Provider, "fleet {fleet:?}");
    }
}

/// A post full of holes starves the pool, so every socket reads as
/// under-carrying and the line reads as unused - the exact picture
/// this verdict fires on. `Missing` is checked first and must keep
/// winning, or the cap gets convicted for the post's gaps.
#[test]
fn a_post_full_of_holes_is_not_our_cap() {
    const GIGABIT: u64 = 125_000_000;
    let mut r = Rig::new();
    r.fleet = (nzbkit::pool::linecap::LINE_CAP_MAX_FLEET, 100, true);
    r.miss = Some((4000, 1900));
    r.run(
        WINDOW,
        37.5e6,
        0,
        GIGABIT,
        30.0,
        false,
        &[
            ("a.example", 25, 25, 18_750_000, 0, 0, false),
            ("b.example", 25, 25, 18_750_000, 0, 0, false),
        ],
    );
    assert_eq!(r.core.verdict().0, Layer::Missing);
}

/// A provider REFUSING is the provider actively failing, and
/// opening more sockets into a 481 makes it worse. It is checked
/// ahead of the cap and must keep winning even with the cap at its
/// ceiling and the line idle.
#[test]
fn a_refusal_outranks_our_cap() {
    const GIGABIT: u64 = 125_000_000;
    let mut r = Rig::new();
    r.fleet = (nzbkit::pool::linecap::LINE_CAP_MAX_FLEET, 100, true);
    r.run(
        WINDOW,
        37.5e6,
        0,
        GIGABIT,
        30.0,
        false,
        &[
            ("a.example", 50, 50, 37_500_000, 0, 0, false),
            ("refusing.example", 0, 8, 0, 0, 0, true),
        ],
    );
    let (l, d) = r.core.verdict();
    assert_eq!(l, Layer::Provider);
    assert_eq!(d, "refusing.example");
}

#[test]
fn a_refusing_host_is_named() {
    let mut r = Rig::new();
    r.run(
        WINDOW,
        400e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("fast.example", 8, 8, 400_000_000, 0, 0, false),
            ("refusing.example", 0, 8, 0, 0, 0, true),
        ],
    );
    let (l, d) = r.core.verdict();
    assert_eq!(l, Layer::Provider);
    assert_eq!(d, "refusing.example");
}

#[test]
fn a_conn_capped_host_is_named() {
    let mut r = Rig::new();
    // 26 granted of a 32 budget - the Giganews shape.
    r.run(
        WINDOW,
        400e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("capped.example", 20, 32, 40_000_000, 0, 0, false),
            ("fast.example", 8, 8, 360_000_000, 0, 0, false),
        ],
    );
    let (l, d) = r.core.verdict();
    assert_eq!(l, Layer::Provider);
    assert_eq!(d, "capped.example");
}

#[test]
fn a_shaped_host_is_convicted_by_relative_rates() {
    let mut r = Rig::new();
    // Full budget connected on both; one delivers ~2 MB/s/conn,
    // the other ~45 MB/s/conn (the measured 8 Aug shape).
    r.run(
        WINDOW,
        420e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("shaped.example", 26, 26, 52_000_000, 0, 0, false),
            ("fast.example", 8, 8, 360_000_000, 0, 0, false),
        ],
    );
    let (l, d) = r.core.verdict();
    assert_eq!(l, Layer::Provider);
    assert_eq!(d, "shaped.example");
}

#[test]
fn healthy_spread_convicts_nobody() {
    let mut r = Rig::new();
    // Both hosts busy at comparable per-conn rates: provider
    // verdict, but no host named - the fleet is just full.
    r.run(
        WINDOW,
        500e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[
            ("a.example", 10, 10, 300_000_000, 0, 0, false),
            ("b.example", 10, 10, 200_000_000, 0, 0, false),
        ],
    );
    let (l, d) = r.core.verdict();
    assert_eq!(l, Layer::Provider);
    assert_eq!(d, "");
}

#[test]
fn no_anchor_means_unknown_not_a_guess() {
    let mut r = Rig::new();
    r.run(
        WINDOW,
        100e6,
        0,
        0,
        30.0,
        false,
        &[("a", 8, 8, 100_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Unknown);
}

#[test]
fn a_dead_fleet_with_a_budget_is_the_provider() {
    let mut r = Rig::new();
    r.run(
        WINDOW,
        0.0,
        0,
        1_000_000_000,
        5.0,
        false,
        &[("a", 0, 8, 0, 0, 0, false)],
    );
    let (l, d) = r.core.verdict();
    assert_eq!(l, Layer::Provider);
    assert_eq!(d, "a");
}

#[test]
fn a_drained_job_in_its_tail_is_not_blamed_on_the_provider() {
    let mut r = Rig::new();
    // A healthy run at line speed...
    r.run(
        WINDOW,
        950e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 950_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Line);
    // ...then net-drain: the connections hang up, speed reads
    // zero, bytes stop advancing. The dead-fleet rule must not
    // fire - the fleet DELIVERED; it is the tail, not an outage.
    r.run(
        WINDOW,
        0.0,
        0,
        1_000_000_000,
        60.0,
        false,
        &[("a", 0, 8, 0, 0, 0, false)],
    );
    assert_eq!(
        r.core.verdict().0,
        Layer::Unknown,
        "a finished wire is not provider evidence"
    );
}

#[test]
fn yesterdays_reconnects_do_not_convict_a_drained_fleet() {
    let mut r = Rig::new();
    // A healthy run at line speed that weathered a routine redial
    // every tick - churn while the bytes flow convicts nobody.
    r.run(
        WINDOW,
        950e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 950_000_000, 0, 1, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Line);
    // Net-drain tail: the sockets hang up and nothing redials. The
    // job-lifetime redial history must not turn the tail into a
    // Provider verdict - this is the churn counterpart of the
    // drained-tail guard above, and it regressed on the live rig
    // when the sum never aged out.
    r.run(
        WINDOW,
        0.0,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 0, 8, 0, 0, 0, false)],
    );
    assert_eq!(
        r.core.verdict().0,
        Layer::Unknown,
        "a hung-up fleet's redial history is not evidence"
    );
}

/// TODO 207: the verdict a finished job carries into history is the
/// LONGEST-HELD layer of its run, not the last one before it left
/// the wire. A job that was provider-bound for most of an hour and
/// spent its final half-minute on a busy CPU was a provider
/// problem, and "last verdict" - the cheap option - says the
/// opposite of the truth about exactly that job.
#[test]
fn the_captured_verdict_is_the_longest_held_layer_not_the_last() {
    let mut r = Rig::new();
    // Forty seconds shy of the anchor with the pipeline idle: the
    // sockets could not fill the pipe.
    r.run(
        40,
        500e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 500_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Provider);
    // ...then the run ends with the machine's own cores pegged and
    // the workers parked on a full channel, which is a different
    // layer and IS the last thing that was true.
    r.run(
        20,
        500e6,
        0,
        1_000_000_000,
        95.0,
        false,
        &[("a", 8, 8, 500_000_000, 8_000, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Cpu, "the LAST verdict");
    let v = r.core.summary(r.t).expect("a judged run has a verdict");
    assert_eq!(v.layer, "provider", "but the longest-held one is kept");
    assert!(
        v.held_secs > v.total_secs / 2,
        "and it carries its own weight: {v:?}"
    );
    assert!(
        (58..=61).contains(&v.total_secs),
        "the whole observed run, not just the winning span: {v:?}"
    );
}

/// ...and the honest half of the same rule: `Unknown` is the
/// ABSENCE of a verdict, so a run nothing could be said about
/// persists nothing at all. Anything else and every fast little
/// download in history would carry "still gathering evidence".
#[test]
fn a_run_nothing_could_judge_persists_no_verdict() {
    let mut r = Rig::new();
    // No anchor: "slow" is undefined, so every tick votes Unknown.
    r.run(
        30,
        500e6,
        0,
        0,
        30.0,
        false,
        &[("a", 8, 8, 500_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Unknown);
    assert!(r.core.summary(r.t).is_none());
    // A verdict that never held a whole second is not one either -
    // it rounds to "for 0s" on every surface that renders it.
    let mut r = Rig::new();
    r.run(
        WINDOW,
        950e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 950_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Line);
    let v = r
        .core
        .summary(r.t)
        .expect("line is a verdict like any other");
    assert_eq!(v.layer, "line");
    assert!(r.core.summary(r.core.verdict_since_ms + 999).is_none());
}

/// The capture is ownership-checked, for the same reason the live
/// payload is: the core judges whoever owns the wire, so asking it
/// about any other job must yield nothing rather than this job's
/// verdict filed under somebody else's name.
#[test]
fn a_capture_for_another_job_is_never_this_ones_verdict() {
    let w = WhySlow::default();
    for i in 1..=WINDOW as u64 {
        w.tick(Tick {
            owner: Some("job1".into()),
            at_ms: T0 + i * 1000,
            achieved_bps: 500e6,
            throttle_bps: 0,
            anchor_bps: 1_000_000_000,
            cpu_pct: 30.0,
            storage: false,
            storage_suspect: false,
            post_unix: 0,
            fleet_cap: 0,
            fleet_configured: 0,
            fleet_auto: false,
            fleet_ceiling: 0,
            fleet_refused: false,
            fleet_knee: None,
            drain_connected: 0,
            servers: vec![srv("a", 8, 8, 500_000_000 * i, 0)],
        });
    }
    let at = T0 + WINDOW as u64 * 1000;
    assert!(w.capture("job2", at).is_none(), "not job2's verdict");
    assert_eq!(
        w.capture("job1", at).map(|v| v.layer),
        Some("provider".to_string())
    );
}

/// The persisted form, both ways. The reading half is where TODO
/// 207's absence rule lives, so every shape that is not a verdict
/// this build understands has to come back as no verdict.
#[test]
fn the_verdict_wire_form_round_trips_and_refuses_everything_else() {
    let v = WhyVerdict {
        layer: "provider".into(),
        detail: "news.example.invalid".into(),
        held_secs: 640,
        total_secs: 900,
    };
    assert_eq!(verdict_from_json(Some(&verdict_json(&v))), Some(v));
    assert!(verdict_from_json(None).is_none());
    for bad in [
        json!({}),
        json!({"layer": "unknown"}),
        json!({"layer": "line "}),
        json!({"detail": "news.example.invalid"}),
    ] {
        assert!(verdict_from_json(Some(&bad)).is_none(), "{bad}");
    }
    // ...and a verdict missing only its numbers is still a verdict:
    // the layer is the claim, the seconds are its weight.
    assert_eq!(
        verdict_from_json(Some(&json!({"layer": "line"}))).map(|v| v.held_secs),
        Some(0)
    );
}

#[test]
fn owner_change_resets_everything() {
    let mut r = Rig::new();
    r.run(
        WINDOW,
        500e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 500_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Provider);
    // New owner: one tick under the new job must not inherit the
    // old evidence.
    r.core.tick(Tick {
        owner: Some("job2".into()),
        at_ms: r.t + 1000,
        achieved_bps: 500e6,
        throttle_bps: 0,
        anchor_bps: 1_000_000_000,
        cpu_pct: 30.0,
        storage: false,
        storage_suspect: false,
        post_unix: 0,
        fleet_cap: 0,
        fleet_configured: 0,
        fleet_auto: false,
        fleet_ceiling: 0,
        fleet_refused: false,
        fleet_knee: None,
        drain_connected: 0,
        servers: vec![srv("a", 8, 8, 500_000_000, 0)],
    });
    assert_eq!(r.core.verdict().0, Layer::Unknown);
    assert!(r.core.timeline.is_empty());
}

#[test]
fn a_flap_cannot_flip_the_verdict() {
    let mut r = Rig::new();
    r.run(
        WINDOW,
        950e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 950_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Line);
    // Five slow seconds inside a line-speed run: not a majority,
    // verdict holds.
    r.run(
        5,
        300e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 300_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Line);
}

#[test]
fn evidence_that_stays_split_falls_to_unknown() {
    let mut r = Rig::new();
    r.run(
        WINDOW,
        950e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 950_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.verdict().0, Layer::Line);
    // Alternate line-speed and half-speed seconds indefinitely:
    // neither layer can hold a majority, and past the transition
    // allowance the stale verdict must yield to Unknown rather
    // than keep asserting a regime the window no longer shows.
    for _ in 0..WINDOW {
        r.run(
            1,
            950e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 950_000_000, 0, 0, false)],
        );
        r.run(
            1,
            300e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 300_000_000, 0, 0, false)],
        );
    }
    assert_eq!(r.core.verdict().0, Layer::Unknown);
}

#[test]
fn the_timeline_records_each_regime_change_once() {
    let mut r = Rig::new();
    r.run(
        WINDOW,
        950e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 950_000_000, 0, 0, false)],
    );
    r.run(
        WINDOW,
        300e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 300_000_000, 0, 0, false)],
    );
    let layers: Vec<Layer> = r.core.timeline.iter().map(|c| c.layer).collect();
    assert_eq!(layers, vec![Layer::Line, Layer::Provider]);
}

#[test]
fn envelope_tracks_only_uncapped_unblocked_ticks() {
    let mut r = Rig::new();
    // Capped ticks must not set the envelope.
    r.run(
        WINDOW,
        100e6,
        100_000_000,
        1_000_000_000,
        20.0,
        false,
        &[("a", 8, 8, 100_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.envelope_bps, 0);
    // Uncapped: the best delivery becomes the envelope estimate.
    r.run(
        5,
        600e6,
        0,
        1_000_000_000,
        20.0,
        false,
        &[("a", 8, 8, 600_000_000, 0, 0, false)],
    );
    assert_eq!(r.core.envelope_bps, 600_000_000);
}

#[test]
fn counter_restart_is_forgiven() {
    let mut r = Rig::new();
    r.run(
        WINDOW,
        500e6,
        0,
        1_000_000_000,
        30.0,
        false,
        &[("a", 8, 8, 500_000_000, 0, 0, false)],
    );
    // The pool restarted: cumulative bytes fall. One tick with a
    // smaller reading must not underflow or convict anyone.
    r.core.tick(Tick {
        owner: Some("job1".into()),
        at_ms: r.t + 1000,
        achieved_bps: 500e6,
        throttle_bps: 0,
        anchor_bps: 1_000_000_000,
        cpu_pct: 30.0,
        storage: false,
        storage_suspect: false,
        post_unix: 0,
        fleet_cap: 0,
        fleet_configured: 0,
        fleet_auto: false,
        fleet_ceiling: 0,
        fleet_refused: false,
        fleet_knee: None,
        drain_connected: 0,
        servers: vec![srv("a", 8, 8, 1000, 0)],
    });
    assert_eq!(
        r.core.verdict().0,
        Layer::Provider,
        "verdict survives the restart"
    );
}
