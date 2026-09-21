//! The save/load round trip and every way the file can be wrong.
//!
//! These assert EXACT values, which the prevalence tests over the engine
//! counters deliberately never do - the difference is that nothing here
//! touches the process-global counters. `load` and `save` are pure
//! functions of a path, so each test owns its own scratch directory and
//! two of them running at once in the same process cannot see each
//! other. The moment a test in this file reaches for
//! `nested_prevalence()` or installs the sink, that stops being true and
//! it has to assert monotonic lower bounds like its neighbours upstairs.

use super::*;

fn scratch(name: &str) -> (crate::testscratch::ScratchDir, PathBuf) {
    let d = crate::testscratch::ScratchDir::attach(
        &std::env::temp_dir().join(format!("nzbfast-nestedstat-{name}-{}", std::process::id())),
    );
    let cfg = d.join("config.local.json");
    (d, cfg)
}

fn sample() -> NestedPrevalence {
    NestedPrevalence {
        levels: 12,
        in_stream: 7,
        demoted: 3,
        disk: 5,
        rar_store: 6,
        rar_compressed: 2,
        rar_encrypted: 1,
        sevenz: 2,
        other: 1,
    }
}

#[test]
fn a_saved_tally_loads_back_field_for_field() {
    let (_g, cfg) = scratch("roundtrip");
    save(&cfg, &sample());
    assert_eq!(load(&cfg), sample());
}

/// The file sits BESIDE the config, not inside it - the same
/// `with_file_name` shape `conntune.json` uses, so an install whose
/// settings file has been renamed still finds its state.
#[test]
fn the_file_sits_beside_the_config() {
    let (_g, cfg) = scratch("path");
    assert_eq!(path_for(&cfg), cfg.with_file_name("nested-prevalence.json"));
}

/// A second save replaces rather than accumulates. This is what makes
/// `install`'s load-the-baseline / sink-writes-the-total pairing safe:
/// the sink writes the running TOTAL every time, so anything that
/// appended would double the history on the next start.
#[test]
fn a_second_save_replaces_the_first() {
    let (_g, cfg) = scratch("replace");
    save(&cfg, &sample());
    let mut later = sample();
    later.levels = 13;
    later.disk = 6;
    save(&cfg, &later);
    assert_eq!(load(&cfg), later);
}

// ---- degradation: every one of these must read as zero, and none of
// them may panic. This is daemon state on a startup path. ----

#[test]
fn an_absent_file_loads_as_zero() {
    let (_g, cfg) = scratch("absent");
    assert_eq!(load(&cfg), NestedPrevalence::default());
}

#[test]
fn a_truncated_file_loads_as_zero() {
    let (_g, cfg) = scratch("truncated");
    save(&cfg, &sample());
    let p = path_for(&cfg);
    let whole = std::fs::read(&p).unwrap();
    std::fs::write(&p, &whole[..whole.len() / 2]).unwrap();
    assert_eq!(load(&cfg), NestedPrevalence::default());
}

#[test]
fn a_file_of_junk_loads_as_zero() {
    let (_g, cfg) = scratch("junk");
    std::fs::write(path_for(&cfg), b"\x00\x01not json at all").unwrap();
    assert_eq!(load(&cfg), NestedPrevalence::default());
}

/// JSON, and the wrong SHAPE - the case a hand edit or a foreign writer
/// produces, which `from_slice` refuses for a different reason than junk
/// does.
#[test]
fn a_json_value_of_the_wrong_shape_loads_as_zero() {
    let (_g, cfg) = scratch("wrongshape");
    std::fs::write(path_for(&cfg), br#"["levels", 4]"#).unwrap();
    assert_eq!(load(&cfg), NestedPrevalence::default());
}

/// A directory where the file should be: `read` fails with EISDIR rather
/// than ENOENT, and a `.ok()` that only anticipated "missing" would still
/// be fine - this pins that it is, and that `save` over it does not panic
/// either.
#[test]
fn a_directory_in_the_files_place_loads_as_zero_and_survives_a_save() {
    let (_g, cfg) = scratch("isdir");
    std::fs::create_dir_all(path_for(&cfg)).unwrap();
    assert_eq!(load(&cfg), NestedPrevalence::default());
    save(&cfg, &sample());
    assert_eq!(load(&cfg), NestedPrevalence::default());
}

/// A file written by an OLDER build, which has only the four headline
/// fields. `#[serde(default)]` on every field is what makes the five
/// per-kind counts load as zero instead of failing the whole parse and
/// losing the four that ARE there.
#[test]
fn a_file_missing_the_newer_fields_keeps_the_ones_it_has() {
    let (_g, cfg) = scratch("partial");
    std::fs::write(
        path_for(&cfg),
        br#"{"levels":9,"in_stream":4,"demoted":2,"disk":5}"#,
    )
    .unwrap();
    let got = load(&cfg);
    assert_eq!(got.levels, 9);
    assert_eq!(got.in_stream, 4);
    assert_eq!(got.demoted, 2);
    assert_eq!(got.disk, 5);
    assert_eq!(got.sevenz, 0);
    assert_eq!(got.other, 0);
}

/// An empty object is the shape a torn write can leave behind, and it is
/// valid JSON - so it takes the defaults path rather than the parse-fail
/// one. Same answer either way, which is the point.
#[test]
fn an_empty_object_loads_as_zero() {
    let (_g, cfg) = scratch("emptyobj");
    std::fs::write(path_for(&cfg), b"{}").unwrap();
    assert_eq!(load(&cfg), NestedPrevalence::default());
}
