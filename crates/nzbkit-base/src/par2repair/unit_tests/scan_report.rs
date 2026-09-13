//! TODO 334: the surveying entry point's lazy catalog, its provisional
//! verify pass, the contested-name restart, and the scan report an
//! observer is shown - a child module of `unit_tests` for the same two
//! reasons as its neighbours (the parent's size-gate entry, and
//! `use super::*` reaching the real PAR2 fixtures).
//!
//! Every test holds `census::testing::record()`: the census sink is
//! process-global, and the restart's own record is part of what is
//! asserted here.

use super::*;
use crate::par2repair::census::testing;

const SET_B: [u8; 16] = [10u8; 16];

/// An observer that keeps everything it is shown and answers as told.
struct Keep {
    answer: AfterSurvey,
    reports: Vec<ScanReport>,
    surveys: usize,
}

impl SurveyObserver for Keep {
    fn packets_scanned(&mut self, report: &ScanReport) {
        self.reports.push(report.clone());
    }
    fn after_survey(&mut self, _members: &[MemberSurvey]) -> AfterSurvey {
        self.surveys += 1;
        self.answer
    }
}

fn keep(answer: AfterSurvey) -> Keep {
    Keep {
        answer,
        reports: Vec::new(),
        surveys: 0,
    }
}

/// Two sets in one directory, each declaring `Contested.bin` for
/// DIFFERENT content, the member absent - the shape `contested` exists
/// for. Set A is the one repaired.
fn contested_dir(tag: &str) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let dir = tmpdir(tag);
    let a = payload(600, 31);
    let b = payload(900, 32);
    let fa: &[(&str, &[u8])] = &[("Contested.bin", &a)];
    let fb: &[(&str, &[u8])] = &[("Contested.bin", &b)];
    std::fs::write(dir.join("a.par2"), par2_index(SET, BS, fa)).unwrap();
    std::fs::write(
        dir.join("a.vol0+16.par2"),
        par2_volume(SET, BS, fa, &(0..16).collect::<Vec<u32>>()),
    )
    .unwrap();
    std::fs::write(dir.join("b.par2"), par2_index(SET_B, BS, fb)).unwrap();
    std::fs::write(
        dir.join("b.vol0+16.par2"),
        par2_volume(SET_B, BS, fb, &(0..16).collect::<Vec<u32>>()),
    )
    .unwrap();
    (dir, a, b)
}

/// The report is exactly what the parser's own census of each file
/// says: same packets, same order, same recovery flags. This is the
/// property `parfast` prints its `Loaded N new packets` lines on.
fn assert_report_matches_census(dir: &Path, report: &ScanReport) {
    let mut seen_files = 0;
    for f in &report.files {
        assert_eq!(f.path.parent(), Some(dir), "flat scope: {:?}", f.path);
        let bytes = std::fs::read(&f.path).unwrap();
        let census = par2::packet_census(&bytes);
        assert_eq!(
            f.packets.len(),
            census.len(),
            "{:?}: report and census disagree on the packet count",
            f.path
        );
        for (p, c) in f.packets.iter().zip(&census) {
            assert_eq!(p.md5, c.md5, "{:?}: packet order differs", f.path);
            assert_eq!(p.set_id, c.set_id);
            assert_eq!(
                p.recovery.map(|r| r.exponent),
                c.recovery_exponent,
                "{:?}: the recovery rule differs between the two walks",
                f.path
            );
            if let Some(r) = p.recovery {
                assert_eq!(r.slice_len as usize, c.body_len - 4);
            }
        }
        seen_files += 1;
    }
    let on_disk = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "par2"))
        .count();
    assert_eq!(seen_files, on_disk, "every packet file is in the report");
}

/// The whole point: a contested name found AFTER the provisional pass
/// restarts the attempt with the settled context, and the repair lands
/// where the eager entry point would have landed it - the disambiguated
/// path, both payloads intact. The observer sees ONE report and ONE
/// survey, and the census says a provisional pass was discarded.
#[test]
fn a_contested_name_restarts_the_provisional_pass_and_lands_disambiguated() {
    let (dir, a, _b) = contested_dir("scan-report-contested");
    let rec = testing::record();

    let mut o = keep(AfterSurvey::Repair);
    let status = repair_dir_set_surveyed_as(
        &dir,
        &SET,
        &[],
        &mut o,
        RetentionCaller::new(CallerSite::ParfastRepair),
    )
    .expect("the repair runs")
    .expect("the observer said Repair");
    let RepairStatus::Repaired(report) = status else {
        panic!("set A was missing its member and had the parity: {status:?}");
    };
    let path = &report.per_file[0].path;
    let leaf = path.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        leaf.contains(".dup-"),
        "the contested name was not disambiguated: landed at {leaf}"
    );
    assert_eq!(std::fs::read(path).unwrap(), a, "set A's own bytes");
    assert!(
        !dir.join("Contested.bin").exists(),
        "nothing may take the declared name while another set claims it"
    );

    assert_eq!(
        o.reports.len(),
        1,
        "one report per attempt, restart included"
    );
    assert_eq!(o.surveys, 1, "one survey per attempt, restart included");
    assert_report_matches_census(&dir, &o.reports[0]);

    let discarded = rec.of_kind("provisional_discarded");
    assert_eq!(discarded.len(), 1, "{discarded:?}");
    assert_eq!(discarded[0]["contested_names"], 1);
    assert_eq!(
        rec.of_kind("admission").len(),
        2,
        "the rerun admits its own corpus after the provisional one is dropped"
    );
}

/// And the same directory through the EAGER scoped entry point lands
/// at the same path: the restart is that path, not a second spelling
/// of it.
#[test]
fn the_restart_lands_where_the_eager_entry_point_lands() {
    let (dir_lazy, _, _) = contested_dir("scan-report-lazy-arm");
    let (dir_eager, _, _) = contested_dir("scan-report-eager-arm");
    let mut o = keep(AfterSurvey::Repair);
    let lazy = repair_dir_set_surveyed_as(
        &dir_lazy,
        &SET,
        &[],
        &mut o,
        RetentionCaller::new(CallerSite::ParfastRepair),
    )
    .unwrap()
    .unwrap();
    let eager = repair_dir_set_with_donors_as(
        &dir_eager,
        &SET,
        &[],
        RetentionCaller::new(CallerSite::ParfastRepair),
    )
    .unwrap();
    let leaf = |s: &RepairStatus| match s {
        RepairStatus::Repaired(r) => r.per_file[0]
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        other => panic!("{other:?}"),
    };
    assert_eq!(leaf(&lazy), leaf(&eager));
}

/// The ordinary directory - one set, nothing contested - pays no
/// restart: one admission, no discard record, one report, and the
/// report agrees with the census over a volume that carries a corrupt
/// packet (skipped by both walks, so absent from both).
#[test]
fn an_uncontested_set_runs_one_pass_and_reports_what_the_scan_validated() {
    let dir = tmpdir("scan-report-plain");
    let data = payload(700, 41);
    let files: &[(&str, &[u8])] = &[("plain.bin", &data)];
    let mut bad = data.clone();
    bad[BS * 2 + 5] ^= 0x11;
    std::fs::write(dir.join("plain.bin"), &bad).unwrap();
    std::fs::write(dir.join("s.par2"), par2_index(SET, BS, files)).unwrap();
    let mut vol = par2_volume(SET, BS, files, &[0, 1, 2, 3]);
    // Corrupt the SECOND recovery packet's body: the first packet's
    // length field tells where it starts.
    let first_len = u64::from_le_bytes(vol[8..16].try_into().unwrap()) as usize;
    vol[first_len + 64 + 10] ^= 0xff;
    std::fs::write(dir.join("s.vol0+4.par2"), &vol).unwrap();
    let rec = testing::record();

    let mut o = keep(AfterSurvey::Repair);
    let status = repair_dir_set_surveyed_as(
        &dir,
        &SET,
        &[],
        &mut o,
        RetentionCaller::new(CallerSite::ParfastRepair),
    )
    .unwrap()
    .unwrap();
    assert!(matches!(status, RepairStatus::Repaired(_)), "{status:?}");
    assert_eq!(std::fs::read(dir.join("plain.bin")).unwrap(), data);
    assert_eq!(o.reports.len(), 1);
    assert_eq!(o.surveys, 1);
    assert_report_matches_census(&dir, &o.reports[0]);
    let vol_report = o.reports[0]
        .files
        .iter()
        .find(|f| f.path.ends_with("s.vol0+4.par2"))
        .expect("the volume is reported");
    let exps: Vec<u32> = vol_report
        .packets
        .iter()
        .filter_map(|p| p.recovery.map(|r| r.exponent))
        .collect();
    assert_eq!(
        exps,
        vec![0, 2, 3],
        "the corrupt packet is not in the report"
    );
    assert!(rec.of_kind("provisional_discarded").is_empty());
    assert_eq!(rec.of_kind("admission").len(), 1);
}

/// An observer that STOPS was still shown the report first, and
/// nothing was written - the report is not a write and the restart
/// never reaches the observer.
#[test]
fn a_stopping_observer_saw_the_report_and_nothing_was_written() {
    let (dir, _, _) = contested_dir("scan-report-stop");
    let before: Vec<String> = {
        let mut v: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    };
    let mut o = keep(AfterSurvey::Stop);
    let status = repair_dir_set_surveyed_as(
        &dir,
        &SET,
        &[],
        &mut o,
        RetentionCaller::new(CallerSite::ParfastRepair),
    )
    .unwrap();
    assert!(status.is_none(), "a stop is Ok(None)");
    assert_eq!(o.reports.len(), 1);
    assert_eq!(o.surveys, 1);
    let after: Vec<String> = {
        let mut v: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    };
    assert_eq!(before, after, "a stop writes nothing, restart or not");
}
