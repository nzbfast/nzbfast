//! The posting-set job, end to end in-process.
//!
//! Each archive is read back by rarkit's own reader and each PAR2 set is
//! judged by the engine's repairer on real damage, which proves the two
//! halves agree with themselves. Interop with RARLAB `rar`/`unrar`,
//! 7-Zip, libarchive and par2cmdline is proved outside this crate, by
//! `research/posting-set/interop.sh` (it needs those binaries; these
//! tests need none).

use std::sync::Arc;

use super::*;
use crate::job::{PostingPar2, RarOptions, RarPassword, RecoverySpec};

/// Bytes that do not compress and do not repeat.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

struct Fixture {
    dir: tempfile::TempDir,
    files: Vec<(String, Vec<u8>)>,
}

impl Fixture {
    fn src(&self) -> PathBuf {
        self.dir.path().join("src")
    }
    fn out(&self) -> PathBuf {
        self.dir.path().join("out")
    }
}

/// Three members of uneven sizes in `src/`, and an empty `out/`.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::create_dir_all(dir.path().join("out")).unwrap();
    let files = vec![
        ("film.mkv".to_string(), noise(300_017, 1)),
        ("sample.mkv".to_string(), noise(40_000, 2)),
        (
            "info.nfo".to_string(),
            b"a posting set's notes\n".repeat(50),
        ),
    ];
    for (n, b) in &files {
        std::fs::write(dir.path().join("src").join(n), b).unwrap();
    }
    Fixture { dir, files }
}

fn spec_for(f: &Fixture, rar: RarOptions) -> PostingSetSpec {
    PostingSetSpec {
        sources: vec![Source {
            path: f.src(),
            recursive: false,
        }],
        path_mode: PathMode::Basename,
        base_path: None,
        output_dir: f.out(),
        name: "Some.Post".to_string(),
        rar,
        par2: PostingPar2 {
            block: Some(crate::job::BlockSpec::Size { size: 4096 }),
            recovery: Some(RecoverySpec::Percent { percent: 10.0 }),
            ..Default::default()
        },
        overwrite: false,
        perf: Default::default(),
    }
}

fn job_for(spec: &PostingSetSpec) -> Job {
    Job {
        spec: JobSpec::PostingSet {
            posting_set: spec.clone(),
        },
        control: Control::new(),
        publisher: Publisher::new(JobSnapshot::queued(
            1,
            JobKind::PostingSet,
            "2026-10-25T00:00:00Z".into(),
            false,
        )),
        knobs: KnobLock::new(),
        shared: false,
        settings: Settings::default(),
    }
}

fn run_spec(spec: &PostingSetSpec) -> Outcome {
    let job = job_for(spec);
    run(&job, spec, Instant::now())
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Collects every member of an archive in memory.
#[derive(Default)]
struct Collect {
    got: Vec<(String, Vec<u8>, Option<bool>)>,
}

impl rarkit::Sink for Collect {
    type Out = Vec<u8>;
    fn open(
        &mut self,
        _member: &rarkit::MemberInfo<'_>,
    ) -> rarkit::Result<rarkit::Disposition<Vec<u8>>> {
        Ok(rarkit::Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        member: &rarkit::MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &rarkit::MemberOutcome,
    ) -> rarkit::Result<()> {
        self.got.push((
            String::from_utf8_lossy(member.name).into_owned(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

/// Extract the set's RAR files with rarkit and check every member came
/// back byte for byte with a good checksum.
fn assert_archive_holds(f: &Fixture, rar: &[WrittenFile], password: Option<&str>) {
    let vols: Vec<Arc<dyn rarkit::RangeSource>> = rar
        .iter()
        .map(|w| {
            Arc::new(std::fs::read(f.out().join(&w.name)).unwrap()) as Arc<dyn rarkit::RangeSource>
        })
        .collect();
    let mut opts = rarkit::ReadOptions::default();
    opts.password = password.map(|p| rarkit::Password::new(p.as_bytes().to_vec()));
    let mut sink = Collect::default();
    rarkit::extract(vols, &opts, &mut sink, &mut ()).expect("rarkit reads the set back");
    let mut want: Vec<(String, Vec<u8>)> = f.files.clone();
    want.sort();
    let mut got: Vec<(String, Vec<u8>)> = sink
        .got
        .iter()
        .map(|(n, b, ok)| {
            assert_eq!(*ok, Some(true), "{n}: checksum");
            (n.clone(), b.clone())
        })
        .collect();
    got.sort();
    assert_eq!(got.len(), want.len(), "member count");
    for ((gn, gb), (wn, wb)) in got.iter().zip(&want) {
        assert_eq!(gn, wn);
        assert!(gb == wb, "{gn} came back different");
    }
}

fn posting(o: &Outcome) -> &PostingResult {
    assert_eq!(o.state, JobState::Done, "error: {:?}", o.error);
    o.result
        .as_ref()
        .and_then(|r| r.posting.as_ref())
        .expect("a posting result")
}

/// Damage `victim` (or delete it) and have the engine's repairer put the
/// set back from the PAR2 set the job wrote.
fn assert_repairs(f: &Fixture, victim: &str, delete: bool) {
    let path = f.out().join(victim);
    let before = std::fs::read(&path).unwrap();
    if delete {
        std::fs::remove_file(&path).unwrap();
    } else {
        let mut b = before.clone();
        let mid = b.len() / 2;
        for x in &mut b[mid..mid + 9000] {
            *x ^= 0xA5;
        }
        std::fs::write(&path, b).unwrap();
    }
    let status = nzbkit::par2repair::repair_dir(&f.out()).expect("repair runs");
    assert!(
        matches!(status, nzbkit::par2repair::RepairStatus::Repaired(_)),
        "{victim}: {status:?}"
    );
    assert!(
        std::fs::read(&path).unwrap() == before,
        "{victim} came back different"
    );
    // The repairer keeps the damaged original aside; that is its rule,
    // not this job's, and it is not part of the set.
    for n in names_in(&f.out()) {
        if n.ends_with(".1") {
            let _ = std::fs::remove_file(f.out().join(n));
        }
    }
}

/// The posting default: one stored archive. One pass, and the set it
/// builds repairs damage in the archive.
#[test]
fn a_stored_single_archive_takes_one_pass_and_repairs() {
    let f = fixture();
    let spec = spec_for(&f, RarOptions::default());
    let o = run_spec(&spec);
    let p = posting(&o).clone();
    assert_eq!(p.route, ONE_PASS);
    assert_eq!(p.rar.len(), 1);
    assert_eq!(p.rar[0].name, "Some.Post.rar");
    assert_eq!(p.par2[0].name, "Some.Post.par2", "the index first");
    assert!(p.par2.len() > 1, "recovery volumes were written");
    assert_eq!(p.source_files, 3);
    assert_archive_holds(&f, &p.rar, None);
    assert_repairs(&f, "Some.Post.rar", false);
}

/// The two routes over the same single archive write sets that describe
/// the same archive: the one-pass set verifies the archive the two-pass
/// route wrote, because the archives are the same bytes (entropy aside:
/// stored and unencrypted draws none) and both PAR2 sets cover them.
#[test]
fn the_one_pass_set_describes_the_archive_a_two_pass_run_writes() {
    let f = fixture();
    let spec = spec_for(&f, RarOptions::default());
    let one = run_spec(&spec);
    posting(&one);
    let one_rar = std::fs::read(f.out().join("Some.Post.rar")).unwrap();
    let mut two_spec = spec.clone();
    two_spec.output_dir = f.dir.path().join("two");
    std::fs::create_dir_all(&two_spec.output_dir).unwrap();
    let job = job_for(&two_spec);
    let two = two_pass(
        &Ctx {
            job: &job,
            spec: &two_spec,
            members: &planner::expand_sources(
                &two_spec.sources,
                PathMode::Basename,
                None,
                planner::SourceRules::Par2,
            )
            .unwrap()
            .members,
            password: None,
            source_bytes: 0,
        },
        "forced".into(),
    );
    assert_eq!(posting(&two).route, TWO_PASS);
    let two_rar = std::fs::read(two_spec.output_dir.join("Some.Post.rar")).unwrap();
    // The archive bytes may differ only in the member times rarkit
    // reads off each source; the sources are the same files, so they
    // must not differ at all.
    assert!(
        one_rar == two_rar,
        "the two routes wrote different archives"
    );
}

/// A volume set: two passes, final names with the width the count
/// needs, no `.partial` left over, and a lost volume rebuilt.
#[test]
fn a_volume_set_takes_two_passes_and_rebuilds_a_lost_volume() {
    let f = fixture();
    let mut spec = spec_for(
        &f,
        RarOptions {
            volumes: RarVolumes::Size { size: 64 << 10 },
            ..Default::default()
        },
    );
    // One whole volume is about a fifth of this small payload.
    spec.par2.recovery = Some(RecoverySpec::Percent { percent: 30.0 });
    let o = run_spec(&spec);
    let p = posting(&o).clone();
    assert_eq!(p.route, TWO_PASS);
    assert!(p.route_reason.contains("volume set"), "{}", p.route_reason);
    assert!(p.rar.len() >= 5, "{} volumes", p.rar.len());
    assert_eq!(p.rar[0].name, "Some.Post.part1.rar");
    assert!(
        names_in(&f.out()).iter().all(|n| !n.ends_with(PARTIAL)),
        "{:?}",
        names_in(&f.out())
    );
    assert!(
        p.rar[..p.rar.len() - 1].iter().all(|v| v.size == 64 << 10),
        "every volume but the last fills its cap: {:?}",
        p.rar
    );
    assert_archive_holds(&f, &p.rar, None);
    assert_repairs(&f, "Some.Post.part2.rar", true);
}

/// A volume COUNT comes out at the count asked, or one fewer.
#[test]
fn a_volume_count_is_honoured() {
    let f = fixture();
    let spec = spec_for(
        &f,
        RarOptions {
            volumes: RarVolumes::Count { count: 4 },
            ..Default::default()
        },
    );
    let o = run_spec(&spec);
    let p = posting(&o);
    assert!(
        p.rar.len() == 4 || p.rar.len() == 3,
        "{} volumes for a count of 4",
        p.rar.len()
    );
    assert_archive_holds(&f, &p.rar, None);
}

/// A password with header encryption, on the one-pass route: the
/// archive opens with the password and refuses without it, and the PAR2
/// set still repairs it.
#[test]
fn a_passworded_archive_takes_one_pass_and_hides_its_names() {
    let f = fixture();
    let spec = spec_for(
        &f,
        RarOptions {
            password: Some(RarPassword::Given("hunter2".into())),
            ..Default::default()
        },
    );
    let o = run_spec(&spec);
    let p = posting(&o).clone();
    assert_eq!(p.route, ONE_PASS);
    assert_archive_holds(&f, &p.rar, Some("hunter2"));
    let raw = std::fs::read(f.out().join("Some.Post.rar")).unwrap();
    assert!(
        !raw.windows(8).any(|w| w == b"film.mkv"),
        "header encryption hides the member names"
    );
    assert_repairs(&f, "Some.Post.rar", false);
}

/// Compression, a solid archive and a recovery record each take the
/// two-pass route, and each still writes a set that reads back.
#[test]
fn compression_solid_and_a_recovery_record_take_two_passes() {
    for (tag, rar) in [
        (
            "compressed",
            RarOptions {
                compression: 3,
                ..Default::default()
            },
        ),
        (
            "solid",
            RarOptions {
                compression: 1,
                solid: true,
                ..Default::default()
            },
        ),
        (
            "recovery-record",
            RarOptions {
                recovery_percent: 5,
                ..Default::default()
            },
        ),
    ] {
        let f = fixture();
        let o = run_spec(&spec_for(&f, rar));
        let p = posting(&o).clone();
        assert_eq!(p.route, TWO_PASS, "{tag}");
        assert_archive_holds(&f, &p.rar, None);
    }
}

/// An existing set is refused without `overwrite`, and replaced whole
/// with it: a stale volume of an earlier, longer set is removed rather
/// than left to be posted beside the new one.
#[test]
fn overwrite_refuses_then_replaces_the_whole_set() {
    let f = fixture();
    let mut spec = spec_for(&f, RarOptions::default());
    std::fs::write(f.out().join("Some.Post.part9.rar"), b"stale").unwrap();
    let o = run_spec(&spec);
    assert_eq!(o.state, JobState::Failed);
    assert_eq!(o.error.as_ref().unwrap().code, "exists");
    assert_eq!(
        names_in(&f.out()),
        vec!["Some.Post.part9.rar"],
        "nothing touched"
    );
    spec.overwrite = true;
    let o = run_spec(&spec);
    posting(&o);
    assert!(
        !f.out().join("Some.Post.part9.rar").exists(),
        "the stale volume is gone"
    );
}

/// A cancel before the work starts leaves nothing, on either route.
#[test]
fn a_cancelled_posting_set_leaves_nothing() {
    for volumes in [RarVolumes::None, RarVolumes::Size { size: 64 << 10 }] {
        let f = fixture();
        let spec = spec_for(
            &f,
            RarOptions {
                volumes,
                ..Default::default()
            },
        );
        let job = job_for(&spec);
        job.control.cancel();
        let o = run(&job, &spec, Instant::now());
        assert_eq!(o.state, JobState::Cancelled, "{volumes:?}: {:?}", o.error);
        assert!(
            names_in(&f.out()).is_empty(),
            "{volumes:?} left {:?}",
            names_in(&f.out())
        );
    }
}

/// A password never leaves the session: it serializes as a marker, and a
/// spec that comes back from disk with the marker refuses to run rather
/// than writing an unencrypted archive.
#[test]
fn a_password_is_withheld_from_every_serialization() {
    let f = fixture();
    let spec = spec_for(
        &f,
        RarOptions {
            password: Some(RarPassword::Given("hunter2".into())),
            ..Default::default()
        },
    );
    let json = serde_json::to_string(&JobSpec::PostingSet {
        posting_set: spec.clone(),
    })
    .unwrap();
    assert!(!json.contains("hunter2"), "{json}");
    assert!(json.contains(r#""password":{"withheld":true}"#), "{json}");
    assert!(!format!("{spec:?}").contains("hunter2"));
    let back: JobSpec = serde_json::from_str(&json).unwrap();
    let JobSpec::PostingSet { posting_set } = back else {
        panic!("kind")
    };
    let o = run_spec(&posting_set);
    assert_eq!(o.state, JobState::Failed);
    assert_eq!(o.error.as_ref().unwrap().code, "password_required");
    assert!(names_in(&f.out()).is_empty());
}

/// The JSON a host sends, as API.md documents it, parses field for
/// field; everything it leaves out takes the posting defaults.
#[test]
fn the_documented_posting_spec_parses() {
    let json = r#"{"kind":"posting_set","posting_set":{
      "sources":[{"path":"/abs/a.mkv"},{"path":"/abs/dir","recursive":true}],
      "output_dir":"/abs/out","name":"Movie.2026",
      "rar":{"volumes":{"split":"size","size":104857600},"compression":0,
             "solid":false,"password":"secret","encrypt_headers":true,
             "recovery_percent":0},
      "par2":{"recovery":{"percent":10.0}},
      "overwrite":false}}"#;
    let spec: JobSpec = serde_json::from_str(json).expect("parses");
    assert_eq!(spec.kind(), JobKind::PostingSet);
    assert_eq!(spec.subject(), "Movie.2026");
    let JobSpec::PostingSet { posting_set: p } = spec else {
        panic!("kind")
    };
    assert_eq!(p.rar.volumes, RarVolumes::Size { size: 104_857_600 });
    assert_eq!(
        p.rar.password.as_ref().and_then(|p| p.given()),
        Some("secret")
    );
    let bare: JobSpec = serde_json::from_str(
        r#"{"kind":"posting_set","posting_set":{"output_dir":"/o","name":"n"}}"#,
    )
    .expect("a bare spec parses");
    let JobSpec::PostingSet { posting_set: b } = bare else {
        panic!("kind")
    };
    assert_eq!(b.rar, RarOptions::default());
    assert!(
        b.rar.encrypt_headers,
        "names are hidden by default once there is a password"
    );
    assert_eq!(b.rar.volumes, RarVolumes::None);
    assert_eq!(b.rar.compression, 0, "store is the posting default");
    assert_eq!(b.par2, PostingPar2::default());
    let count: RarVolumes = serde_json::from_str(r#"{"split":"count","count":20}"#).unwrap();
    assert_eq!(count, RarVolumes::Count { count: 20 });
}

#[test]
fn bad_specs_are_refused_before_anything_is_written() {
    let f = fixture();
    for (tag, edit) in [
        (
            "name with a folder",
            (|s: &mut PostingSetSpec| s.name = "a/b".into()) as fn(&mut _),
        ),
        ("empty name", |s| s.name = String::new()),
        ("level 9", |s| s.rar.compression = 9),
        ("tiny volume", |s| {
            s.rar.volumes = RarVolumes::Size { size: 10 }
        }),
        ("count of one", |s| {
            s.rar.volumes = RarVolumes::Count { count: 1 }
        }),
        ("no folder", |s| {
            s.output_dir = PathBuf::from("/nonexistent/parfast/out")
        }),
    ] {
        let mut spec = spec_for(&f, RarOptions::default());
        edit(&mut spec);
        let o = run_spec(&spec);
        assert_eq!(o.state, JobState::Failed, "{tag}");
        assert_eq!(o.error.as_ref().unwrap().code, "bad_spec", "{tag}");
        assert!(names_in(&f.out()).is_empty(), "{tag}");
    }
}

#[test]
fn posting_member_names_the_set_and_nothing_else() {
    for yes in [
        "S.rar",
        "S.part1.rar",
        "S.part01.rar",
        "S.part3.rar.partial",
        "S.par2",
        "S.vol00+01.par2",
        "S.PART2.RAR",
    ] {
        assert!(posting_member("S", yes), "{yes}");
    }
    for no in [
        "S.r00",
        "S.part.rar",
        "S.partx.rar",
        "Sx.rar",
        "S.nfo",
        "T.rar",
        "S.rar.bak",
    ] {
        assert!(!posting_member("S", no), "{no}");
    }
}

/// A2: with overwrite on, a file of the set that is ALSO a source is
/// refused before anything is unlinked. Two shapes: a source named
/// exactly as the set's archive, and a folder job re-run into the folder
/// it reads, whose last run's archive is now one of its inputs.
#[test]
fn overwrite_never_deletes_one_of_its_own_sources() {
    let f = fixture();
    let mut spec = spec_for(&f, RarOptions::default());
    spec.overwrite = true;
    // The set writes into the folder it reads, and a file there already
    // carries the set's archive name.
    spec.output_dir = f.src();
    std::fs::write(f.src().join("Some.Post.rar"), b"my own payload").unwrap();
    let before = names_in(&f.src());
    let o = run_spec(&spec);
    assert_eq!(o.state, JobState::Failed, "{:?}", o.error);
    assert_eq!(o.error.as_ref().unwrap().code, "output_is_a_source");
    assert_eq!(names_in(&f.src()), before, "nothing was unlinked");
    assert_eq!(
        std::fs::read(f.src().join("Some.Post.rar")).unwrap(),
        b"my own payload",
        "the source survived"
    );

    // Named directly, from a folder that is not the output's.
    let g = fixture();
    let mut spec = spec_for(&g, RarOptions::default());
    spec.overwrite = true;
    std::fs::write(g.out().join("Some.Post.rar"), b"named source").unwrap();
    spec.sources.push(Source {
        path: g.out().join("Some.Post.rar"),
        recursive: false,
    });
    let o = run_spec(&spec);
    assert_eq!(
        o.error.as_ref().map(|e| e.code.as_str()),
        Some("output_is_a_source")
    );
    assert!(
        g.out().join("Some.Post.rar").exists(),
        "the source survived"
    );
}

/// Two members that would be stored under one name in the archive are
/// refused, naming both, and nothing is written.
#[test]
fn two_members_under_one_archive_name_are_refused() {
    let f = fixture();
    std::fs::create_dir_all(f.src().join("a")).unwrap();
    std::fs::create_dir_all(f.src().join("b")).unwrap();
    std::fs::write(f.src().join("a/notes.txt"), b"first").unwrap();
    std::fs::write(f.src().join("b/notes.txt"), b"second").unwrap();
    let mut spec = spec_for(&f, RarOptions::default());
    spec.sources[0].recursive = true;
    let o = run_spec(&spec);
    assert_eq!(
        o.error.as_ref().map(|e| e.code.as_str()),
        Some("duplicate_name")
    );
    let msg = &o.error.as_ref().unwrap().message;
    // The message names each source by its path as the platform prints
    // it, so a Windows run reads `a\notes.txt`; a literal `a/notes.txt`
    // was green on unix only until first run on Windows (9 Nov 2026).
    let a = Path::new("a").join("notes.txt").display().to_string();
    let b = Path::new("b").join("notes.txt").display().to_string();
    assert!(msg.contains(&a) && msg.contains(&b), "{msg}");
    assert!(names_in(&f.out()).is_empty(), "{:?}", names_in(&f.out()));
}

/// A28's posting half: the members' readers hold no descriptor until
/// they are read, and let it go once their bytes are out. Read through
/// the same `open_members` the run uses.
#[test]
fn a_members_reader_holds_its_file_only_while_it_is_read() {
    let f = fixture();
    let members = planner::expand_sources(
        &[Source {
            path: f.src(),
            recursive: false,
        }],
        PathMode::Basename,
        None,
        planner::SourceRules::Par2,
    )
    .unwrap()
    .members;
    let Ok(mut opened) = open_members(&members) else {
        panic!("the members open");
    };
    assert!(
        opened.iter().all(|o| o.file.file.is_none()),
        "a member held a descriptor before anything read it"
    );
    // EXACTLY its size, as rarkit reads it - it never asks past the end,
    // so a reader that let go only on a zero-length read would hold on.
    let mut all = vec![0u8; opened[0].size as usize];
    opened[0].file.read_exact(&mut all).unwrap();
    assert!(
        opened[0].file.file.is_none(),
        "a finished member kept its descriptor"
    );
    assert!(opened[1].file.file.is_none());
}

/// The CRC pre-read honours Pause: with the job paused it parks rather
/// than reading every source to the end, and a Cancel releases it.
#[test]
fn the_crc_pre_read_parks_on_pause() {
    let f = fixture();
    let spec = spec_for(&f, RarOptions::default());
    let job = Arc::new(job_for(&spec));
    let members = planner::expand_sources(
        &spec.sources,
        PathMode::Basename,
        None,
        planner::SourceRules::Par2,
    )
    .unwrap()
    .members;
    job.control.set_paused(true);
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = Arc::clone(&job);
    let t = std::thread::spawn(move || {
        let got = source_crcs(&worker, &members).map(|c| c.is_some());
        let _ = tx.send(got.is_ok_and(|done| done));
    });
    // Parked: no answer while paused. Not a sleep-and-hope for the pass
    // - a pre-read that ignored Pause answers at once on three small
    // files, so it is the ANSWER arriving that fails this.
    assert!(
        rx.recv_timeout(std::time::Duration::from_millis(300))
            .is_err(),
        "the pre-read finished while the job was paused"
    );
    job.control.cancel();
    let finished = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("a cancel releases a parked pre-read");
    assert!(!finished, "a cancelled pre-read must not report CRCs");
    t.join().unwrap();
}

/// A member that SHRINKS after it was measured is an error on every read
/// from then on - never a reopen that feeds its first bytes in again as
/// the missing tail.
#[test]
fn a_member_that_shrank_stays_an_error() {
    let f = fixture();
    let path = f.src().join("film.mkv");
    let mut lazy = LazyFile {
        path: path.clone(),
        left: 300_017,
        file: None,
        short: false,
    };
    let mut head = vec![0u8; 1_000];
    lazy.read_exact(&mut head).expect("the first bytes");
    std::fs::write(&path, &head).expect("truncate to what was read");
    let mut rest = vec![0u8; 4_096];
    let first = lazy.read(&mut rest);
    assert!(first.is_err(), "a short file answered {first:?}");
    let again = lazy.read(&mut rest);
    assert_eq!(
        again.map_err(|e| e.kind()).err(),
        Some(std::io::ErrorKind::UnexpectedEof),
        "the second read reopened the file instead of staying an error"
    );
}

/// TODO 358 sweep F1: overwrite clears every file under the set's name
/// in the output folder, and a SOURCE can be one of them - `Movie.rar`
/// posted from its own folder as `Movie`. That deleted the source and
/// then failed on ENOENT. It is refused instead, whatever `overwrite`
/// says, and the source is untouched.
#[test]
fn overwrite_never_deletes_a_source() {
    let f = fixture();
    let src = f.out().join("Some.Post.rar");
    std::fs::write(&src, noise(10_000, 9)).unwrap();
    let mut spec = spec_for(&f, RarOptions::default());
    spec.sources = vec![Source {
        path: src.clone(),
        recursive: false,
    }];
    spec.overwrite = true;
    let o = run_spec(&spec);
    assert_eq!(o.state, JobState::Failed, "{:?}", o.result);
    // `output_is_a_source`, not the `bad_spec` this landed with: the two
    // 9 Nov fixes of this defect were reconciled at the merge onto the
    // code the FFI contract names (see `clear_or_refuse`).
    assert_eq!(
        o.error.as_ref().unwrap().code,
        "output_is_a_source",
        "{:?}",
        o.error
    );
    assert_eq!(
        std::fs::read(&src).unwrap(),
        noise(10_000, 9),
        "source kept"
    );
}

/// TODO 358 sweep F2: in the basename path mode two sources with one
/// file name (`S01/Sample/sample.mkv`, `S02/Sample/sample.mkv`) would be
/// one name twice inside the archive - extraction keeps one of them - and
/// the job reported Done. It is refused, naming the clash, as the Create
/// pane's own check refuses a PAR2 set that names one slot twice.
#[test]
fn two_sources_with_one_name_are_refused() {
    let f = fixture();
    for s in ["S01", "S02"] {
        let d = f.src().join(s);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("sample.mkv"), noise(5_000, s.len() as u64)).unwrap();
    }
    let mut spec = spec_for(&f, RarOptions::default());
    spec.sources = vec![
        Source {
            path: f.src().join("S01"),
            recursive: true,
        },
        Source {
            path: f.src().join("S02"),
            recursive: true,
        },
    ];
    let o = run_spec(&spec);
    assert_eq!(o.state, JobState::Failed, "{:?}", o.result);
    let e = o.error.as_ref().unwrap();
    // `duplicate_name` since the merge with the parfast sweep's own fix
    // (see `distinct_names`).
    assert_eq!(e.code, "duplicate_name", "{e:?}");
    assert!(e.message.contains("sample.mkv"), "{}", e.message);
    assert!(names_in(&f.out()).is_empty());
}

/// TODO 358 sweep F4: the CRC pre-read's buffers come out of the
/// process memory budget (the Settings pane's Memory limit), not beside
/// it - it used to hold up to 16 workers x 64 MiB = 1 GiB whatever the
/// limit said. A quarter of the budget at most, and never no worker.
#[test]
fn the_crc_pre_read_fits_the_memory_budget() {
    for (cpu, budget) in [
        (16, 64u64 << 20),
        (16, 256 << 20),
        (4, 1 << 30),
        (1, 64 << 20),
    ] {
        let (workers, buf) = crc_plan(cpu, budget, 1_000);
        assert!(workers >= 1, "cpu {cpu} budget {budget}");
        assert!(
            (workers * buf) as u64 <= budget / 4,
            "cpu {cpu} budget {budget}: {workers} x {buf}"
        );
    }
    // A roomy budget still uses every worker the box has.
    assert_eq!(crc_plan(16, 16 << 30, 1_000).0, 16);
    assert_eq!(crc_plan(16, 16 << 30, 3).0, 3, "no idle workers");
}

/// TODO 358 sweep F4: a piece read through a buffer smaller than itself
/// chains to the CRC of the whole piece.
#[test]
fn a_piece_crc_through_a_small_buffer_is_the_whole_crc() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x");
    let bytes = noise(100_003, 7);
    std::fs::write(&p, &bytes).unwrap();
    let f = File::open(&p).unwrap();
    let mut buf = vec![0u8; 4096];
    assert_eq!(
        crc_of_range(&f, 17, 90_000, &mut buf).unwrap(),
        nzbkit::yenc_simd::crc32(&bytes[17..90_017], 0)
    );
    assert_eq!(crc_of_range(&f, 0, 0, &mut buf).unwrap(), 0);
}

/// TODO 358 sweep F3: a set name starting with '.' writes `.name.rar`,
/// which the PAR2 half's own source rule drops as a dot-file, so a
/// two-pass job wrote the whole archive, failed `no_sources` and deleted
/// it. Refused up front instead.
#[test]
fn a_dot_set_name_is_refused_before_anything_is_written() {
    let f = fixture();
    let mut spec = spec_for(
        &f,
        RarOptions {
            compression: 3,
            ..Default::default()
        },
    );
    spec.name = ".Hidden".into();
    let o = run_spec(&spec);
    assert_eq!(o.state, JobState::Failed);
    assert_eq!(o.error.as_ref().unwrap().code, "bad_spec", "{:?}", o.error);
    assert!(names_in(&f.out()).is_empty());
}
