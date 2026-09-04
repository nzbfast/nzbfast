//! The persisted job record's compatibility surface: the schema stamp,
//! the narrowed numeric fields, and what a corrupt or foreign record
//! does. A child module of `job`, beside `job_wire` itself.
//!
//! Split out of `job_tests` rather than appended to its
//! `job_json / job_from_json` section: that section pins the field
//! SEMANTICS a reader needs (the `filed` migration, the `bad_blocks`
//! tri-state, the `whyslow` absence rule), and this one pins the wire
//! CONTRACT - what happens to a record this binary was not the one to
//! write. Two different questions about the same pair of functions.

use super::job_wire::JOB_SCHEMA_VERSION;
use super::*;
use serde_json::json;

/// The five keys `job_from_json` refuses a record for the absence of.
fn minimal() -> Value {
    json!({
        "nzo_id": "n1",
        "name": "A.Release",
        "nzb_path": "/tmp/a.nzb",
        "out_dir": "/out/A.Release",
        "state": "Queued",
    })
}

// ---- the schema stamp ----

#[test]
fn every_written_record_carries_the_schema_stamp() {
    let j = job_from_json(&minimal()).expect("parses");
    assert_eq!(job_json(&j)["schema_version"], json!(JOB_SCHEMA_VERSION));
}

/// The whole compatibility claim in one line: every record on every
/// disk today is version-less, and stamping one changes nothing about
/// how it reads.
#[test]
fn a_versionless_record_loads_exactly_like_a_stamped_one() {
    let bare = maximal_versionless();
    let mut stamped = bare.clone();
    stamped["schema_version"] = json!(JOB_SCHEMA_VERSION);
    let a = job_from_json(&bare).expect("version-less parses");
    let b = job_from_json(&stamped).expect("stamped parses");
    assert_eq!(job_json(&a), job_json(&b));
}

/// A record at OUR generation, and one below it, both load: a newer
/// reader reads an older record, which is the direction a version
/// number is for.
#[test]
fn our_generation_and_anything_below_it_loads() {
    for g in 0..=JOB_SCHEMA_VERSION {
        let mut v = minimal();
        v["schema_version"] = json!(g);
        assert!(job_from_json(&v).is_some(), "generation {g} must load");
    }
}

/// The gate itself. A record from a binary that renamed or re-meant a
/// key is refused rather than misread - see `JOB_SCHEMA_VERSION` for
/// why that is the safer of the two wrong answers here.
#[test]
fn a_future_schema_version_is_refused() {
    for g in [JOB_SCHEMA_VERSION + 1, 2, 99, u64::MAX] {
        let mut v = maximal_versionless();
        v["schema_version"] = json!(g);
        assert!(
            job_from_json(&v).is_none(),
            "generation {g} is above {JOB_SCHEMA_VERSION} and must be refused"
        );
    }
}

/// A stamp that is present but is not a generation number is refused
/// too. Our writer emits `json!(u64)` and nothing else, so anything
/// here is a record this reader cannot place - and reading an
/// unparseable stamp as "absent" would walk the future record the gate
/// exists for straight through it.
#[test]
fn a_schema_version_that_is_not_a_number_is_refused() {
    for bad in [
        json!("1"),
        json!(1.5),
        json!(-1),
        json!(true),
        json!(null),
        json!([1]),
        json!({}),
    ] {
        let mut v = minimal();
        v["schema_version"] = bad.clone();
        assert!(
            job_from_json(&v).is_none(),
            "an unreadable stamp {bad} must be refused, not treated as absent"
        );
    }
}

// ---- the narrowed numeric fields ----

/// Every field `job_from_json` reads back into a type narrower than the
/// JSON number carrying it, with the width it lands in and a value that
/// WRAPS TO ZERO under an `as` cast. Zero is the dangerous answer for
/// most of them: five are ladder counters compared against a small
/// give-up constant, and zero hands the ladder its whole budget back.
const NARROWED: &[(&str, u64)] = &[
    ("retries", 1 << 32),
    ("defer_count", 1 << 32),
    ("move_attempts", 1 << 32),
    ("inner_crc", 1 << 32),
    ("cleaned_files", 1 << 32),
    ("cleaned_par2", 1 << 32),
    ("failure_depth", 1 << 8),
    ("refeed_depth", 1 << 8),
];

/// Read one narrowed field back off a parsed job as a `u64`, by name,
/// so the table above can drive every site from one place.
fn narrowed(j: &Job, key: &str) -> u64 {
    match key {
        "retries" => u64::from(j.retries),
        "defer_count" => u64::from(j.defer_count),
        "move_attempts" => u64::from(j.move_attempts),
        "inner_crc" => u64::from(j.inner_crc),
        "cleaned_files" => u64::from(j.cleaned_files),
        "cleaned_par2" => u64::from(j.cleaned_par2),
        "failure_depth" => u64::from(j.failure_depth),
        "refeed_depth" => u64::from(j.refeed_depth),
        other => panic!("{other} is not in NARROWED - add its reader"),
    }
}

/// The defect this whole change is about: an oversized persisted count
/// used to WRAP. `1<<32 as u32` is 0 and `256 as u8` is 0, so a corrupt
/// `move_attempts` reset the retry ladder rather than ending it.
#[test]
fn an_oversized_count_saturates_and_never_wraps_to_zero() {
    for &(key, wraps_to_zero) in NARROWED {
        for probe in [wraps_to_zero, u64::MAX, wraps_to_zero + 7] {
            let mut v = minimal();
            v[key] = json!(probe);
            let j = job_from_json(&v).unwrap_or_else(|| panic!("{key}={probe} must still load"));
            let got = narrowed(&j, key);
            assert_ne!(got, 0, "{key}={probe} wrapped to zero");
            assert!(
                got >= wraps_to_zero - 1,
                "{key}={probe} read back as {got}, which is not saturation"
            );
        }
    }
}

/// A value that FITS is untouched - saturation must not be a clamp on
/// ordinary data. `1<<32 - 1` is the largest legal `u32` and `255` the
/// largest legal `u8`, so this is the boundary on the good side.
#[test]
fn a_count_that_fits_is_read_back_exactly() {
    for &(key, over) in NARROWED {
        for probe in [0, 1, 7, over - 1] {
            let mut v = minimal();
            v[key] = json!(probe);
            let j = job_from_json(&v).expect("parses");
            assert_eq!(narrowed(&j, key), probe, "{key}={probe}");
        }
    }
}

/// `priority` is the one SIGNED narrowed field, so it saturates at both
/// ends. A wrap is what turns a garbage negative into a job that
/// outranks Force (2).
#[test]
fn an_out_of_range_priority_saturates_at_both_ends() {
    let read = |n: i64| {
        let mut v = minimal();
        v["priority"] = json!(n);
        job_from_json(&v).expect("parses").priority
    };
    assert_eq!(read(1i64 << 32), i32::MAX, "a huge positive must not wrap");
    assert_eq!(read(i64::MAX), i32::MAX);
    assert_eq!(
        read(-(1i64 << 32)),
        i32::MIN,
        "a huge negative must not wrap"
    );
    assert_eq!(read(i64::MIN), i32::MIN);
    // ...and every priority the product actually uses is untouched.
    for p in [2, 1, 0, -1, -2, -100] {
        assert_eq!(read(i64::from(p)), p);
    }
}

/// A field of the wrong JSON TYPE reads as its documented default,
/// unchanged from before the checked conversions existed: `as_u64`
/// already answered `None` for all of these, and every field in
/// `job_from_json` documents what its own absence means. Pinned so it
/// stays a decision rather than an accident.
#[test]
fn a_narrowed_field_of_the_wrong_type_reads_as_its_default() {
    for &(key, _) in NARROWED {
        for bad in [
            json!("7"),
            json!(7.5),
            json!(-7),
            json!(true),
            json!(null),
            json!([7]),
        ] {
            let mut v = minimal();
            v[key] = bad.clone();
            let j = job_from_json(&v).unwrap_or_else(|| panic!("{key}={bad} must still load"));
            assert_eq!(narrowed(&j, key), 0, "{key}={bad}");
        }
    }
    let mut v = minimal();
    v["priority"] = json!("high");
    assert_eq!(job_from_json(&v).expect("parses").priority, 0);
}

// ---- truncated and malformed records ----

/// The five keys with no defensible default. A record missing any of
/// them is refused - that predates this change and is what the two
/// production readers' `continue` was written for.
#[test]
fn a_record_truncated_of_a_required_key_is_refused() {
    for key in ["nzo_id", "name", "nzb_path", "out_dir", "state"] {
        let mut v = minimal();
        v.as_object_mut().expect("object").remove(key);
        assert!(job_from_json(&v).is_none(), "missing {key} must be refused");
        // ...and present-but-wrong-type is the same answer, because the
        // reader asks for a string and a truncated write can leave one
        // of these holding anything.
        let mut w = minimal();
        w[key] = json!(42);
        assert!(
            job_from_json(&w).is_none(),
            "{key} as a number must be refused"
        );
    }
    assert!(job_from_json(&minimal()).is_some(), "the control must load");
}

/// A record truncated of everything OPTIONAL still loads, with every
/// field at the default its own comment in `job_from_json` documents.
/// This is the shape the very first persisted records had.
#[test]
fn a_record_of_nothing_but_the_required_keys_loads_at_its_defaults() {
    let j = job_from_json(&minimal()).expect("parses");
    for &(key, _) in NARROWED {
        assert_eq!(narrowed(&j, key), 0, "{key}");
    }
    assert_eq!(j.priority, 0);
    assert_eq!(j.state, JobState::Queued);
    assert_eq!(j.total_bytes, 0);
    assert!(j.whyslow.is_none());
    assert!(j.health.is_none());
    assert!(j.bad_blocks.is_none());
    assert!(j.early_published.is_empty());
    assert!(j.pp_params.is_empty());
}

/// Not a JSON object at all - what a torn line or a hand-edited spool
/// file can leave in an array `restore_records` walks.
#[test]
fn a_record_that_is_not_an_object_is_refused() {
    for v in [json!(null), json!(7), json!("nzo_id"), json!([]), json!({})] {
        assert!(job_from_json(&v).is_none(), "{v} must be refused");
    }
}

// ---- the golden fixture and the round trip ----

/// A version-less record in the shape the CURRENT serializer writes -
/// every key `job_json` emits except the stamp itself, each carrying a
/// distinctive value. Frozen as a literal rather than derived from
/// `job_json`, because a fixture the serializer generates moves with
/// the serializer and can never catch a rename.
///
/// `health` and `media` are null here on purpose. Both are whole
/// nested payloads with their own readers and their own absence rules
/// (`health_from_json`, and a serde `from_value` that answers None for
/// anything it cannot deserialize), and both are covered where those
/// readers live; what this fixture is for is the flat key surface.
fn maximal_versionless() -> Value {
    json!({
        "nzo_id": "SABnzbd_nzo_fixture",
        "name": "Show.S01E02.1080p.WEB-DL",
        "nzb_path": "/spool/show.nzb",
        "origin": "rss",
        "category": "tv",
        "state": "Completed",
        "total_bytes": 12_345_678_901u64,
        "out_dir": "/out/Show/Season 01",
        "alt_from": "SABnzbd_nzo_older",
        "alt_from_name": "Show.S01E02.720p",
        "alt_why": "the first release was missing 40 articles",
        "alt_to_name": "Show.S01E02.1080p.WEB-DL",
        "heal_dir": "/library/Show/Season 01",
        "fail_message": "boom",
        // TODO 307 item 1. Deliberately a kind the SENTENCE beside it
        // does not classify to ("boom" is `Local`): the fixture's whole
        // job is to notice a key that stopped being read, and a code
        // agreeing with its own message would still round-trip if the
        // reader dropped it on the floor.
        "fail_code": "gone",
        "fail_detail": "a longer explanation",
        "delete_status": "DUPE",
        "priority": 1,
        "paused": true,
        "retries": 3,
        "dupe_key": "show/s1e2",
        "held_for": "a password",
        "library": true,
        "insurance": true,
        "fetched": true,
        "downloaded_bytes": 12_000_000_000u64,
        "elapsed_secs": 91.5,
        "finished_unix": 1_756_000_000i64,
        "postproc_secs": 4.25,
        "whyslow": {"layer": "disk", "detail": "the spool volume", "held_secs": 12.0, "total_secs": 91.5},
        "queued_unix": 1_755_900_000i64,
        "nzb_sha": "deadbeef",
        "finalizing": true,
        "deferred": true,
        "defer_reason": "no servers",
        "defer_at": 1_755_950_000u64,
        "defer_count": 2,
        "password": "hunter2",
        "bad_blocks": 5,
        "verify_blocks": 900,
        "tv_sort": true,
        "smart_rule": "tv",
        "filed": true,
        "filed_suffix": " - 1080p",
        "filed_title": "The Episode Title",
        "filed_base": "Show - S01E02",
        "password_required": true,
        "eat_volumes_ok": true,
        "zip_packed": true,
        "unpack_blocked_by": "a password",
        "move_split": "/other/volume",
        "move_failed": "EACCES",
        "move_attempts": 4,
        "move_pending": true,
        "early_published": [
            {"name": "ep1.mkv", "len": 900u64, "mtime_ns": 1_700u64, "nzf_id": "f1", "dest": "/final/ep1.mkv"},
            {"name": "ep2.mkv", "len": 901u64, "mtime_ns": 1_701u64, "nzf_id": "f2", "dest": null},
        ],
        "move_seq": 77u64,
        "archive_shape": "rar5",
        "inner_crc": 0xdead_beefu64,
        "identity_name": "Show (2020) S01E02",
        "identity_imdb": "tt1234567",
        "identity_src": "tvmaze",
        "auto_retry_at": 1_756_100_000u64,
        "auto_retry_why": "a transient 430",
        "pp_params": [["key", "value"], ["other", "thing"]],
        "sab_pp": 3i64,
        "script_override": "notify.sh",
        "replaces": "/spool/older.nzb",
        "failure_link": "https://indexer.example/api?t=get&id=x",
        "failure_host": "indexer.example",
        "failure_https": true,
        "failure_depth": 2,
        "refeed_depth": 1,
        "identify": "tvmaze",
        "health": null,
        "media": null,
        "cleaned_files": 6,
        "cleaned_par2": 4,
        "cleaned_trash": true,
    })
}

/// Compatibility, stated as the property that matters: every key in a
/// record written by yesterday's binary is still a key this serializer
/// emits. A rename or a removal breaks that and would silently strand
/// the field on every existing spool file - which is exactly the class
/// `JOB_SCHEMA_VERSION` is there to make deliberate.
#[test]
fn every_key_in_the_frozen_fixture_is_still_written_today() {
    let emitted = job_json(&job_from_json(&minimal()).expect("parses"));
    let emitted = emitted.as_object().expect("object");
    for key in maximal_versionless().as_object().expect("object").keys() {
        assert!(
            emitted.contains_key(key),
            "`{key}` is in a record on every existing spool file but `job_json` no \
             longer writes it - a rename or a removal, which needs a \
             JOB_SCHEMA_VERSION bump and a migration, not a silent drop"
        );
    }
}

/// The round trip on a maximally-populated record: parse, write, parse,
/// write, and the two writes must agree. A fixed point is the honest
/// form of the assertion - `job_json` legitimately normalises some
/// fields on the way through (an empty `auto_retry_why` becomes None,
/// `bad_blocks` is a tri-state read from two keys), so the first write
/// is where the record settles and everything after it must not move.
#[test]
fn a_maximally_populated_record_round_trips_to_a_fixed_point() {
    let first = job_json(&job_from_json(&maximal_versionless()).expect("parses"));
    let second = job_json(&job_from_json(&first).expect("re-parses"));
    assert_eq!(first, second, "serialize-then-parse is not identity");
    // ...and the stamp is what the second pass reads its own generation
    // from, so it has to survive its own round trip.
    assert_eq!(second["schema_version"], json!(JOB_SCHEMA_VERSION));
}

/// The values themselves, spot-checked across every kind of field the
/// record carries, so a fixed point that is fixed at the WRONG value
/// cannot pass the test above quietly.
#[test]
fn a_maximally_populated_record_keeps_its_values() {
    let j = job_from_json(&maximal_versionless()).expect("parses");
    assert_eq!(j.nzo_id, "SABnzbd_nzo_fixture");
    assert_eq!(j.state, JobState::Completed);
    assert_eq!(j.total_bytes, 12_345_678_901);
    assert_eq!(j.priority, 1);
    assert_eq!(j.retries, 3);
    assert_eq!(j.defer_count, 2);
    assert_eq!(j.move_attempts, 4);
    assert_eq!(j.inner_crc, 0xdead_beef);
    assert_eq!(j.failure_depth, 2);
    assert_eq!(j.refeed_depth, 1);
    assert_eq!(j.cleaned_files, 6);
    assert_eq!(j.cleaned_par2, 4);
    assert_eq!(j.move_seq, 77);
    assert_eq!(j.bad_blocks, Some(5));
    assert_eq!(j.verify_blocks, 900);
    assert_eq!(j.sab_pp, Some(3));
    assert_eq!(j.dupe_key.as_deref(), Some("show/s1e2"));
    assert_eq!(j.password.as_deref(), Some("hunter2"));
    assert_eq!(j.filed_suffix.as_deref(), Some(" - 1080p"));
    assert_eq!(
        j.replaces.as_deref(),
        Some(std::path::Path::new("/spool/older.nzb"))
    );
    // §310: a path field, so a record that carries one must read back as
    // a PATH and not as the empty default a missing key gives - the one
    // way this could round-trip to a fixed point at the wrong value.
    assert_eq!(j.heal_dir, std::path::Path::new("/library/Show/Season 01"));
    assert_eq!(j.pp_params.len(), 2);
    assert_eq!(j.early_published.len(), 2);
    assert_eq!(
        j.early_published[0].dest.as_deref(),
        Some(std::path::Path::new("/final/ep1.mkv"))
    );
    assert!(j.early_published[1].dest.is_none());
    assert_eq!(j.fail_code, Some(FailKind::Gone));
    // ...and it is what the job ANSWERS with, over a sentence that
    // classifies to something else. A field read back into a struct and
    // then ignored by every reader would pass the line above alone.
    assert_eq!(j.fail_kind(), FailKind::Gone);
    assert_eq!(crate::failkind::fail_kind(&j.fail_message), FailKind::Local);
    assert_eq!(j.whyslow.as_ref().map(|w| w.layer.as_str()), Some("disk"));
    assert!(j.filed && j.tv_sort && j.paused && j.library && j.cleaned_trash);
}

// ---- the failure code (TODO 307 item 1) ----

/// The compatibility claim for the new key, which is the whole reason it
/// did not bump `JOB_SCHEMA_VERSION`: a record written before it existed
/// loads unchanged, and reads as "nobody classified this", which is the
/// truth about such a record.
#[test]
fn a_record_written_before_the_failure_code_reads_as_unclassified() {
    let mut v = maximal_versionless();
    v.as_object_mut().expect("object").remove("fail_code");
    let j = job_from_json(&v).expect("parses");
    assert_eq!(j.fail_code, None);
    // And the answer it gives is EXACTLY the one it gave before the
    // field existed - the string classifier over its own sentence.
    assert_eq!(
        j.fail_kind(),
        crate::failkind::fail_kind(&j.fail_message),
        "a version-less record must not change its classification"
    );
}

/// Every kind survives the wire, in the record rather than in isolation:
/// `failkind::tests::job_carry` pins the token pair, this pins that
/// `job_json` and `job_from_json` are the ones spelling it.
#[test]
fn every_failure_code_round_trips_through_the_record() {
    for kind in [
        FailKind::MissingArticles,
        FailKind::Transport,
        FailKind::Unrepairable,
        FailKind::PreflightImpossible,
        FailKind::Gone,
        FailKind::Local,
    ] {
        let mut j = job_from_json(&minimal()).expect("parses");
        j.fail_code = Some(kind);
        let back = job_from_json(&job_json(&j)).expect("re-parses");
        assert_eq!(back.fail_code, Some(kind), "{kind:?}");
    }
}

/// An unset code is written as `null` and read back as `None` - not as
/// an absent key, and not as some default kind. The key is always
/// present in what this binary writes, so the reader's absence rule is
/// only ever exercised by records from before the field existed.
#[test]
fn an_unset_failure_code_is_written_null_and_reads_back_none() {
    let mut j = job_from_json(&minimal()).expect("parses");
    j.fail_code = None;
    let out = job_json(&j);
    assert_eq!(out["fail_code"], Value::Null);
    assert_eq!(job_from_json(&out).expect("re-parses").fail_code, None);
}

/// A token this build has never heard of - which can only come from a
/// NEWER one - costs the code and nothing else. `JOB_SCHEMA_VERSION`'s
/// rule is that an additive key must never refuse a record, and the
/// alternative here is a downgrade silently deleting a user's history
/// row over a classification it could not spell.
#[test]
fn a_failure_code_this_build_cannot_spell_costs_only_the_code() {
    for tok in [json!("quarantined"), json!(""), json!(7), json!(true)] {
        let mut v = maximal_versionless();
        v["fail_code"] = tok.clone();
        let j = job_from_json(&v).unwrap_or_else(|| panic!("{tok} must not refuse the record"));
        assert_eq!(j.fail_code, None, "{tok}");
        assert_eq!(j.nzo_id, "SABnzbd_nzo_fixture", "{tok}");
    }
}

/// Clearing a failure clears BOTH halves. A code outliving the message
/// it explains would classify the job's NEXT failure by its previous
/// one - silently, on the auto-retry gate and the dead-post report both
/// - and `Job::clear_failure` exists so the pair cannot be half-cleared
/// by a caller that only remembered the sentence.
#[test]
fn clearing_a_failure_clears_the_code_with_the_message() {
    let mut j = job_from_json(&maximal_versionless()).expect("parses");
    assert!(!j.fail_message.is_empty() && j.fail_code.is_some());
    j.clear_failure();
    assert!(j.fail_message.is_empty());
    assert_eq!(j.fail_code, None);
    assert_eq!(job_json(&j)["fail_code"], Value::Null);
}
