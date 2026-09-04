//! Unit tests for the rolling per-provider quality ledger: the window
//! trim, the age bucketing, the cap-hour mask, the two backbone joins,
//! and the report that rolls them up.
//!
//! Every case builds its own `Stored` and drives `record`/`report`
//! directly - there is no daemon, no spool file and no clock read
//! anywhere in this module (`now` is a parameter throughout), which is
//! what lets a case pin a date boundary exactly.

use super::*;

/// 2026-08-28T12:00:00Z, so a case can say "yesterday" without doing
/// calendar arithmetic in its own body.
const NOW: i64 = 1_787_918_400;

fn host(h: &str, tried: u64, missing: u64) -> HostFacts {
    HostFacts {
        host: h.to_string(),
        tried,
        missing,
        bytes: tried * 700_000,
        ..Default::default()
    }
}

pub fn job(hosts: Vec<HostFacts>, outcome: Outcome, post_unix: i64) -> JobFacts {
    JobFacts {
        hosts,
        post_unix,
        outcome,
    }
}

#[test]
fn a_day_key_is_the_utc_calendar_day() {
    assert_eq!(day_key(NOW), "2026-08-28");
    // One second before midnight UTC is still the previous day, and one
    // second after is the next: the boundary is what every "today"
    // column in the report is cut on.
    let midnight = NOW.div_euclid(86_400) * 86_400;
    assert_eq!(day_key(midnight - 1), "2026-08-27");
    assert_eq!(day_key(midnight), "2026-08-28");
}

#[test]
fn the_age_key_is_the_oracles_bucket_and_unknown_is_its_own() {
    // Same boundaries as `nzbkit::oracle::age_bucket`, read through the
    // date rather than the day count.
    assert_eq!(age_key(NOW - 3_600, NOW), "0");
    assert_eq!(age_key(NOW - 5 * 86_400, NOW), "1");
    assert_eq!(age_key(NOW - 200 * 86_400, NOW), "4");
    // Unknown is NOT bucket 0. `Hub::post_unix` is explicit that 0
    // means "we do not know" and must never read as "posted just now";
    // folding it into the newest bucket would put every undated post's
    // misses on the retention line.
    assert_eq!(age_key(0, NOW), "?");
    // A date in the future is a poster's clock, not a measurement.
    assert_eq!(age_key(NOW + 86_400, NOW), "?");
    assert_eq!(age_label("2"), "7-30d");
    assert_eq!(age_label("?"), "?");
}

#[test]
fn recording_a_job_lands_in_the_day_the_host_and_the_bucket() {
    let mut s = Stored::default();
    s.record(
        &job(
            vec![host("a.example", 100, 4)],
            Outcome::Completed,
            NOW - 5 * 86_400,
        ),
        NOW,
    );
    let d = &s.days["2026-08-28"];
    let c = &d.hosts["a.example"].age["1"];
    assert_eq!((c.tried, c.missing, c.jobs), (100, 4, 1));
    assert_eq!(d.jobs.total, 1);
    assert_eq!(d.jobs.completed, 1);
    // A second job of the same shape ADDS to the cell and does not
    // replace it - the cell is a running total, and its `jobs` is the
    // denominator that makes the rate readable.
    s.record(
        &job(
            vec![host("a.example", 50, 1)],
            Outcome::Completed,
            NOW - 5 * 86_400,
        ),
        NOW,
    );
    let c = &s.days["2026-08-28"].hosts["a.example"].age["1"];
    assert_eq!((c.tried, c.missing, c.jobs), (150, 5, 2));
}

#[test]
fn a_provider_that_took_no_part_gets_no_row() {
    // Every configured server is in `pool_live`, so a job that never
    // asked one of them for anything hands us a zero row. Recording it
    // would make an idle account look measured at 0% missing, which
    // then reads as the BEST provider on the list.
    let mut s = Stored::default();
    s.record(
        &job(
            vec![host("busy.example", 40, 0), host("idle.example", 0, 0)],
            Outcome::Completed,
            NOW,
        ),
        NOW,
    );
    let hosts = &s.days["2026-08-28"].hosts;
    assert!(hosts.contains_key("busy.example"));
    assert!(!hosts.contains_key("idle.example"), "{hosts:?}");
}

#[test]
fn an_idle_provider_that_refused_us_is_still_recorded() {
    // The exception to the rule above, and the reason it is written as
    // four conditions rather than `tried == 0`: a provider that refused
    // the account served nothing BECAUSE it refused, and that is the
    // one thing about it worth keeping.
    let mut s = Stored::default();
    let mut dead = host("dead.example", 0, 0);
    dead.bytes = 0;
    dead.refused = true;
    s.record(&job(vec![dead], Outcome::Failed, NOW), NOW);
    assert_eq!(s.days["2026-08-28"].hosts["dead.example"].refused_jobs, 1);
}

#[test]
fn the_window_keeps_thirty_days_and_drops_the_oldest() {
    let mut s = Stored::default();
    for i in 0..40i64 {
        s.record(
            &job(vec![host("a.example", 10, 0)], Outcome::Completed, NOW),
            NOW - (39 - i) * 86_400,
        );
    }
    assert_eq!(s.days.len(), WINDOW_DAYS);
    let first = s.days.keys().next().unwrap().clone();
    let last = s.days.keys().next_back().unwrap().clone();
    assert_eq!(last, day_key(NOW));
    assert_eq!(first, day_key(NOW - (WINDOW_DAYS as i64 - 1) * 86_400));
}

#[test]
fn the_trim_is_by_key_so_a_clock_that_jumps_back_loses_nothing() {
    // Trimming on "older than 30 days before now" would empty the whole
    // ledger the moment a container started before NTP, or a laptop
    // woke in another year - and there is no way to get those days
    // back. Dropping the LOWEST key can only ever cost the oldest day.
    let mut s = Stored::default();
    for i in 0..5i64 {
        s.record(
            &job(vec![host("a.example", 10, 0)], Outcome::Completed, NOW),
            NOW - i * 86_400,
        );
    }
    let before = s.days.len();
    // Now record with a clock that has jumped back four years.
    s.record(
        &job(vec![host("a.example", 10, 0)], Outcome::Completed, NOW),
        NOW - 4 * 365 * 86_400,
    );
    assert_eq!(s.days.len(), before + 1, "{:?}", s.days.keys());
    assert!(s.days.contains_key(&day_key(NOW)));
}

#[test]
fn the_host_cap_bounds_one_days_row_count() {
    let mut s = Stored::default();
    for i in 0..(MAX_HOSTS_PER_DAY + 8) {
        s.record(
            &job(
                vec![host(&format!("h{i}.example"), 10, 0)],
                Outcome::Completed,
                NOW,
            ),
            NOW,
        );
    }
    assert_eq!(s.days["2026-08-28"].hosts.len(), MAX_HOSTS_PER_DAY);
}

#[test]
fn a_cap_marks_the_hours_it_was_in_force_and_not_the_jobs_that_saw_it() {
    // Three jobs inside one hour are ONE capped hour. Counting them
    // per job would make a busy evening read as a whole day of cap.
    let day_start = NOW.div_euclid(86_400) * 86_400;
    let mut s = Stored::default();
    for _ in 0..3 {
        let mut h = host("cap.example", 10, 0);
        // Capped from 11:30 on this day; settle is at 12:00.
        h.capped_since_ms = ((day_start + 11 * 3600 + 1800) * 1000) as u64;
        s.record(&job(vec![h], Outcome::Completed, NOW), NOW);
    }
    let hd = &s.days["2026-08-28"].hosts["cap.example"];
    assert_eq!(hd.cap_jobs, 3, "every job that hit the cap is counted");
    assert_eq!(hd.cap_hours.count_ones(), 2, "hours 11 and 12 only");
}

#[test]
fn a_cap_that_began_yesterday_marks_this_day_from_midnight_only() {
    // Clipped at both ends: a cap running since last week must not mark
    // 168 hours on today's row, and a job that settles at noon must not
    // mark this evening.
    let day_start = NOW.div_euclid(86_400) * 86_400;
    let mut s = Stored::default();
    let mut h = host("cap.example", 10, 0);
    h.capped_since_ms = ((day_start - 3 * 86_400) * 1000) as u64;
    s.record(&job(vec![h], Outcome::Completed, NOW), NOW);
    // Midnight through noon inclusive is thirteen hours.
    assert_eq!(
        s.days["2026-08-28"].hosts["cap.example"]
            .cap_hours
            .count_ones(),
        13
    );
}

#[test]
fn the_second_backbone_join_needs_two_distinct_spools() {
    // One provider that missed nothing cannot pair with itself...
    assert!(!saved_by_second_backbone(&[host("a.example", 10, 0)]));
    // ...nor can two brands of ONE backbone, which is the whole reason
    // the fold happens before the comparison: an article a spool has
    // taken down is gone from every host on it.
    assert!(!saved_by_second_backbone(&[
        host("news.eweka.nl", 10, 4),
        host("reader.eweka.nl", 10, 0),
    ]));
    // Two genuinely different spools, one clean: that is a rescue.
    assert!(saved_by_second_backbone(&[
        host("news.eweka.nl", 10, 4),
        host("news.usenetserver.com", 10, 0),
    ]));
    // ...and a backbone that was asked for nothing is not an opinion.
    assert!(!saved_by_second_backbone(&[
        host("news.eweka.nl", 10, 4),
        host("news.usenetserver.com", 0, 0),
    ]));
}

#[test]
fn backbones_in_play_counts_only_the_ones_that_were_asked() {
    assert_eq!(backbones_in_play(&[]), 0);
    assert_eq!(
        backbones_in_play(&[host("news.eweka.nl", 5, 0), host("reader.eweka.nl", 5, 0)]),
        1
    );
    assert_eq!(
        backbones_in_play(&[
            host("news.eweka.nl", 5, 0),
            host("news.usenetserver.com", 5, 0),
        ]),
        2
    );
}

#[test]
fn a_shortfall_on_one_backbone_is_counted_and_one_on_two_is_not() {
    let mut s = Stored::default();
    // Repaired with only one spool in play: there was no second
    // opinion to be had, which is the actionable half.
    s.record(
        &job(vec![host("news.eweka.nl", 100, 9)], Outcome::Repaired, NOW),
        NOW,
    );
    // Repaired with two: a second opinion existed and did not save it,
    // which says nothing about buying another account.
    s.record(
        &job(
            vec![
                host("news.eweka.nl", 100, 9),
                host("news.usenetserver.com", 40, 9),
            ],
            Outcome::Repaired,
            NOW,
        ),
        NOW,
    );
    // ...and a plain completion on one spool is not a shortfall at all.
    s.record(
        &job(vec![host("news.eweka.nl", 100, 0)], Outcome::Completed, NOW),
        NOW,
    );
    assert_eq!(s.days["2026-08-28"].jobs.short_no_second, 1);
}

#[test]
fn every_outcome_lands_in_its_own_counter() {
    let mut s = Stored::default();
    for o in [
        Outcome::Completed,
        Outcome::Repaired,
        Outcome::Failed,
        Outcome::Rescued,
    ] {
        s.record(&job(vec![host("a.example", 10, 0)], o, NOW), NOW);
    }
    let j = &s.days["2026-08-28"].jobs;
    assert_eq!(
        (j.total, j.completed, j.repaired, j.failed, j.rescued),
        (4, 1, 1, 1, 1)
    );
}

#[test]
fn the_report_sums_the_window_and_orders_by_bytes() {
    let mut s = Stored::default();
    for d in 0..3i64 {
        s.record(
            &job(
                vec![host("small.example", 10, 1), host("big.example", 100, 2)],
                Outcome::Completed,
                NOW - 5 * 86_400,
            ),
            NOW - d * 86_400,
        );
    }
    let r = report(&s, NOW);
    assert_eq!(r.days, WINDOW_DAYS as u32);
    assert_eq!(r.since, day_key(NOW - (WINDOW_DAYS as i64 - 1) * 86_400));
    assert_eq!(r.jobs.total, 3);
    assert_eq!(r.providers.len(), 2);
    assert_eq!(r.providers[0].host, "big.example", "biggest first");
    assert_eq!(r.providers[0].tried, 300);
    assert_eq!(r.providers[0].missing, 6);
    assert_eq!(r.providers[0].jobs, 3);
    assert_eq!(miss_pct(300, 6), Some(2.0));
}

#[test]
fn the_report_ignores_days_outside_the_window() {
    // Trim keeps 30 buckets by KEY, so a clock that jumped FORWARD can
    // leave a real old day on file. The report must not count it as if
    // it were inside the month it says it covers.
    let mut s = Stored::default();
    s.record(
        &job(vec![host("a.example", 10, 0)], Outcome::Completed, NOW),
        NOW - 90 * 86_400,
    );
    s.record(
        &job(vec![host("a.example", 10, 0)], Outcome::Completed, NOW),
        NOW,
    );
    assert_eq!(s.days.len(), 2, "both days are on file");
    assert_eq!(report(&s, NOW).jobs.total, 1, "only one is in the window");
}

#[test]
fn the_age_ladder_reads_youngest_first_with_unknown_last() {
    let mut s = Stored::default();
    for (post, _) in [
        (NOW - 200 * 86_400, "4"),
        (0, "?"),
        (NOW - 3_600, "0"),
        (NOW - 20 * 86_400, "2"),
    ] {
        s.record(
            &job(vec![host("a.example", 10, 0)], Outcome::Completed, post),
            NOW,
        );
    }
    let r = report(&s, NOW);
    let keys: Vec<&str> = r.providers[0].age.iter().map(|a| a.key.as_str()).collect();
    assert_eq!(keys, ["0", "2", "4", "?"]);
    assert_eq!(r.providers[0].age[1].label, "7-30d");
}

#[test]
fn cap_hours_add_across_days_and_not_within_one() {
    let mut s = Stored::default();
    for d in 0..4i64 {
        let at = NOW - d * 86_400;
        let day_start = at.div_euclid(86_400) * 86_400;
        for _ in 0..3 {
            let mut h = host("cap.example", 10, 0);
            h.capped_since_ms = ((day_start + 11 * 3600) * 1000) as u64;
            s.record(&job(vec![h], Outcome::Completed, NOW), at);
        }
    }
    // Two hours (11 and 12) on each of four days.
    assert_eq!(report(&s, NOW).providers[0].cap_hours, 8);
}

/// Enough evidence in one cell to clear [`ADVICE_MIN_TRIED`].
fn bulk(h: &str, tried: u64, missing: u64, post: i64, s: &mut Stored) {
    s.record(
        &job(vec![host(h, tried, missing)], Outcome::Completed, post),
        NOW,
    );
}

#[test]
fn advice_stays_quiet_until_there_is_evidence_for_it() {
    // A provider that missed HALF of what it was asked for, over
    // twenty articles, says nothing at all: a rate over a handful is
    // noise, and advice that fires on noise is advice nobody reads.
    let mut s = Stored::default();
    bulk("a.example", 20, 10, NOW - 5 * 86_400, &mut s);
    assert!(report(&s, NOW).advice.is_empty());
}

#[test]
fn a_high_miss_rate_over_the_window_earns_a_sentence() {
    let mut s = Stored::default();
    bulk("a.example", ADVICE_MIN_TRIED, 200, NOW - 5 * 86_400, &mut s);
    let r = report(&s, NOW);
    let a = r
        .advice
        .iter()
        .find(|a| a.code == "miss_high")
        .expect("advice");
    assert_eq!(a.host, "a.example");
    assert!((a.pct - 10.0).abs() < 1e-9, "{}", a.pct);
    assert_eq!(a.n, 200);
}

#[test]
fn the_retention_gap_compares_the_youngest_measured_bucket_with_the_oldest() {
    let mut s = Stored::default();
    // Flawless on new posts, badly short on year-old ones.
    bulk("a.example", ADVICE_MIN_TRIED, 0, NOW - 3_600, &mut s);
    bulk(
        "a.example",
        ADVICE_MIN_TRIED,
        400,
        NOW - 200 * 86_400,
        &mut s,
    );
    let r = report(&s, NOW);
    let a = r
        .advice
        .iter()
        .find(|a| a.code == "miss_old")
        .expect("advice");
    // The KEY, so the surface can name the bucket in the reader's own
    // language; the English label rides beside it on the wire.
    assert_eq!(a.bucket, "4");
    assert_eq!(age_label(&a.bucket), "90-365d");
    assert!((a.pct - 20.0).abs() < 1e-9, "{}", a.pct);
}

#[test]
fn the_retention_gap_needs_evidence_at_both_ends() {
    // One well-evidenced old bucket and a thin new one is not a
    // comparison: the new bucket's rate is noise, so a "gap" against it
    // is noise too.
    let mut s = Stored::default();
    bulk("a.example", 30, 0, NOW - 3_600, &mut s);
    bulk(
        "a.example",
        ADVICE_MIN_TRIED,
        400,
        NOW - 200 * 86_400,
        &mut s,
    );
    assert!(
        !report(&s, NOW).advice.iter().any(|a| a.code == "miss_old"),
        "{:?}",
        report(&s, NOW).advice
    );
}

#[test]
fn the_retention_gap_is_silent_when_age_makes_no_difference() {
    let mut s = Stored::default();
    bulk("a.example", ADVICE_MIN_TRIED, 20, NOW - 3_600, &mut s);
    bulk(
        "a.example",
        ADVICE_MIN_TRIED,
        24,
        NOW - 200 * 86_400,
        &mut s,
    );
    assert!(!report(&s, NOW).advice.iter().any(|a| a.code == "miss_old"));
}

#[test]
fn the_unknown_age_bucket_never_stands_at_either_end_of_the_ladder() {
    // Undated posts are not a point on the age line, so a pile of them
    // must not become the "old" end of a retention comparison.
    let mut s = Stored::default();
    bulk("a.example", ADVICE_MIN_TRIED, 0, NOW - 3_600, &mut s);
    bulk("a.example", ADVICE_MIN_TRIED, 900, 0, &mut s);
    assert!(!report(&s, NOW).advice.iter().any(|a| a.code == "miss_old"));
}

#[test]
fn a_long_cap_and_a_refusal_each_earn_their_own_sentence() {
    let mut s = Stored::default();
    for d in 0..3i64 {
        let at = NOW - d * 86_400;
        let day_start = at.div_euclid(86_400) * 86_400;
        let mut h = host("cap.example", 10, 0);
        h.capped_since_ms = ((day_start + 9 * 3600) * 1000) as u64;
        s.record(&job(vec![h], Outcome::Completed, NOW), at);
    }
    let mut dead = host("dead.example", 0, 0);
    dead.bytes = 0;
    dead.refused = true;
    s.record(&job(vec![dead], Outcome::Failed, NOW), NOW);
    let r = report(&s, NOW);
    let cap = r
        .advice
        .iter()
        .find(|a| a.code == "capped")
        .expect("cap advice");
    assert_eq!(cap.host, "cap.example");
    // Hours 9 through 12 on each of three days.
    assert_eq!(cap.n, 12);
    let ref_ = r
        .advice
        .iter()
        .find(|a| a.code == "refused")
        .expect("refusal");
    assert_eq!((ref_.host.as_str(), ref_.n), ("dead.example", 1));
}

#[test]
fn the_two_backbone_sentences_read_off_the_job_joins() {
    let mut s = Stored::default();
    s.record(
        &job(vec![host("news.eweka.nl", 100, 9)], Outcome::Failed, NOW),
        NOW,
    );
    s.record(
        &job(
            vec![
                host("news.eweka.nl", 100, 9),
                host("news.usenetserver.com", 40, 0),
            ],
            Outcome::Completed,
            NOW,
        ),
        NOW,
    );
    let r = report(&s, NOW);
    assert_eq!(
        r.advice
            .iter()
            .find(|a| a.code == "one_backbone")
            .map(|a| a.n),
        Some(1)
    );
    assert_eq!(
        r.advice
            .iter()
            .find(|a| a.code == "second_earned")
            .map(|a| a.n),
        Some(1)
    );
}

#[test]
fn the_wire_shape_carries_every_figure_the_page_renders() {
    let mut s = Stored::default();
    s.record(
        &job(
            vec![
                host("news.eweka.nl", 100, 9),
                host("news.usenetserver.com", 40, 0),
            ],
            Outcome::Repaired,
            NOW - 5 * 86_400,
        ),
        NOW,
    );
    let v = json_of(&report(&s, NOW));
    assert_eq!(v["days"], WINDOW_DAYS as u64);
    assert_eq!(v["jobs"]["repaired"], 1);
    assert_eq!(v["jobs"]["saved_by_second"], 1);
    let p = &v["providers"][0];
    assert_eq!(p["host"], "news.eweka.nl");
    assert_eq!(p["backbone"], nzbkit::oracle::backbone_of("news.eweka.nl"));
    assert_eq!(p["tried"], 100);
    assert_eq!(p["missing"], 9);
    assert_eq!(p["age"][0]["label"], "1-7d");
    assert_eq!(p["age"][0]["tried"], 100);
    // A provider asked for nothing has no rate, and the wire says
    // `null` rather than inventing a zero that would read as flawless.
    assert!(v["providers"][0]["miss_pct"].is_f64());
    assert!(miss_pct(0, 0).is_none());
}

#[test]
fn a_stored_ledger_survives_a_round_trip_through_its_own_json() {
    let mut s = Stored {
        v: 1,
        ..Default::default()
    };
    let mut h = host("news.eweka.nl", 100, 9);
    h.capped_since_ms = (NOW * 1000) as u64;
    s.record(&job(vec![h], Outcome::Repaired, NOW - 5 * 86_400), NOW);
    let text = serde_json::to_string(&s).unwrap();
    let back: Stored = serde_json::from_str(&text).unwrap();
    assert_eq!(back, s);
}

#[test]
fn a_ledger_written_by_an_older_build_loads_with_the_fields_it_lacks() {
    // Every counter is `#[serde(default)]`, so a file from a build that
    // had not grown one of them loads rather than being thrown away
    // whole - the alternative is a user silently losing a month of
    // history to a version bump.
    let v = serde_json::json!({
        "v": 1,
        "days": {"2026-08-28": {"hosts": {"a.example": {"age": {"1": {"tried": 10}}}}}}
    });
    let s: Stored = serde_json::from_value(v).expect("loads");
    let c = &s.days["2026-08-28"].hosts["a.example"].age["1"];
    assert_eq!((c.tried, c.missing, c.jobs), (10, 0, 0));
    assert_eq!(s.days["2026-08-28"].jobs.total, 0);
}

#[test]
fn two_rows_on_one_host_are_one_job_however_the_conditions_land() {
    // A prepaid block account beside the main account on the same
    // backbone is a SUPPORTED shape, and the facts arrive per row on
    // purpose. The per-JOB counters must not read N rows as N jobs -
    // and a condition that tripped only on the SECOND row must still be
    // credited (the first-row-only spelling of this dedupe misses it).
    let mut s = Stored {
        v: 1,
        ..Default::default()
    };
    let a = host("news.eweka.nl", 100, 3);
    let mut b = host("news.eweka.nl", 40, 1);
    b.capped_since_ms = (NOW * 1000) as u64;
    b.refused = true;
    s.record(&job(vec![a, b], Outcome::Completed, NOW), NOW);
    let hd = &s.days["2026-08-28"].hosts["news.eweka.nl"];
    let c = &hd.age[&age_key(NOW, NOW)];
    // The sums really are per-row; the job counters are per-host.
    assert_eq!((c.tried, c.missing), (140, 4));
    assert_eq!(c.jobs, 1, "two rows of one host are one job");
    assert_eq!(hd.cap_jobs, 1, "credited off the second row, once");
    assert_eq!(hd.refused_jobs, 1, "credited off the second row, once");
    assert_eq!(s.days["2026-08-28"].jobs.total, 1);
}
