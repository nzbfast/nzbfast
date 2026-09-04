//! The one round trip every generated layout test runs: generate the
//! profile, serve it from the mock, download it with the real binary,
//! and grade the output tree against the end state the profile
//! declares.
//!
//! WHAT THIS REPLACES. `e2e_norar/mod.rs` builds its fixtures by hand -
//! `add_file_renamed_by_par2`, `add_par2`, `add_file_obfuscated` and a
//! dozen more - and each one encodes a posting shape in Rust that only
//! that suite can read. Here the shape is a `.toml` profile and
//! the generator is `postfast`, so a row is data. The RUN half is
//! deliberately the same run as `run_norar_chaos`: mock, config, the
//! real `nzbfast get`, `out_tree`. Only the fixture builders are
//! replaced.
//!
//! WHY THE TWO HELPERS BELOW ARE WRITTEN HERE rather than imported
//! from the `e2e` suite. `out_tree` is `pub(crate)` in
//! `e2e_norar/mod.rs` and `write_config` is a method on `e2e.rs`'s
//! `Fixture`; both live in the `e2e` test BINARY, which is a separate
//! executable, and no target can reach another target's items at all.
//! Pulling `e2e_norar/mod.rs` in by `#[path]` would compile its whole
//! matrix into this binary, which is far worse than twenty lines of
//! directory walk. The two that actually matter ARE shared, through
//! the `#[path]` declarations in `integration/main.rs`:
//! `e2e_getrun::get_cmd` is the one `nzbfast get` command spelling and
//! `harness::output_under_test` is the one process launcher, so
//! neither is a second copy of a rule.

use std::path::{Path, PathBuf};

use nzbkit::mock::MockServer;
use postfast::{Layout, Profile};

use crate::e2e_getrun::{GET_CONNS, GET_WINDOW, get_cmd};
use crate::{adoptguard, harness, scratch};

/// Run one catalog profile end to end and grade it.
///
/// `stem` is the profile's file stem, which is also the second half of
/// the generated test's name, so a failure message and a `-E
/// 'test(...)'` filter spell the same thing.
pub async fn run(stem: &str) {
    let path = catalog_dir().join(format!("{stem}.toml"));
    let profile = Profile::load(&path)
        .unwrap_or_else(|e| panic!("{stem}: the catalog profile does not load: {e}"));
    let layout = postfast::generate(&profile)
        .unwrap_or_else(|e| panic!("{stem}: the layout does not generate: {e}"));
    refuse_an_unasserted_claim(stem, &layout);

    let dir = std::env::temp_dir().join(format!("nzbfast-layouts-{stem}-{}", std::process::id()));
    let _guard = scratch::ScratchDir::attach(&dir);
    // The adopt guard refuses a repair that rebuilt nothing from parity
    // and adopted instead, because that is a fixture whose recovery set
    // was never load-bearing. A profile that damages no payload article
    // is not that mistake: there is nothing for parity to rebuild, so a
    // "repair" it reports is the set NAMING an intact file, which is
    // exactly what a P3 or an F7 row is for. Declared here, from the
    // layout, rather than row by row - `Expectation::repairs` is the
    // generator's own answer and cannot drift from the profile.
    if !layout.expect.repairs {
        adoptguard::adoption_is_the_premise(
            &dir,
            "this profile damages no payload article, so nothing needs rebuilding from \
             parity: a repair it reports is the recovery set naming a file that arrived \
             intact under another name, which is the row",
        );
    }

    // The mock takes the article map and the header block map the
    // generator built, and `vec![]` for overview: no profile selects an
    // XOVER-driven shape yet, and a plane nothing selects is served
    // empty rather than invented here.
    let srv = MockServer::start_full(
        layout.articles.clone(),
        layout.headers.clone(),
        vec![],
        layout.chaos.clone(),
    )
    .await;
    // S6: the further servers, each with its own fault plan over the
    // SAME articles. Held for their whole life so they outlive the run
    // - dropping a `MockServer` closes its listener, and a config
    // naming a dead port is a different test than the one the profile
    // asked for.
    let mut second = Vec::with_capacity(layout.second.len());
    for chaos in &layout.second {
        second.push(
            MockServer::start_full(
                layout.articles.clone(),
                layout.headers.clone(),
                vec![],
                chaos.clone(),
            )
            .await,
        );
    }

    let mut servers: Vec<&MockServer> = vec![&srv];
    servers.extend(second.iter());
    let cfg = write_config(&dir, &servers);
    let nzb = dir.join("layout.nzb");
    std::fs::write(&nzb, layout.nzb.as_bytes()).expect("write the layout's nzb");
    let out = dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out)
    })
    .await
    .expect("the get run does not panic");

    // Same door as `run_norar_chaos`: LAYOUTS_DUMP_LOG=1 cargo nextest
    // run ... --no-capture prints the engine log for one row.
    if std::env::var("LAYOUTS_DUMP_LOG").is_ok() {
        eprintln!("==== {stem} run log ====\n{log}\n==== end ====");
    }
    grade(stem, &layout, &out, &log, ok);
}

/// The catalog directory, from this package rather than from the
/// current directory: nextest runs a test binary from the workspace
/// root, and a relative path would be one more thing to be wrong.
fn catalog_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../postfast/catalog")
}

/// Refuse a profile whose `[expect.ladder]` makes a claim this runner
/// cannot yet check.
///
/// The identification rung is asserted from the engine's own log lines,
/// and the vocabulary of rungs is what chip 09's census establishes
/// (spec section 9.1 step 4). Until that lands, a profile that declares
/// `reaches = "par2-set-id"` and gets a green test would be exactly the
/// rubber stamp the generator refuses planes to prevent: a claim that
/// passed because nobody looked. So it is refused BY NAME, with the
/// work that lands it, rather than ignored.
fn refuse_an_unasserted_claim(stem: &str, layout: &Layout) {
    assert!(
        layout.expect.ladder.is_empty(),
        "{stem}: [expect.ladder] reaches = {:?}, and this runner has no rung assertion yet - \
         the rung vocabulary and the log lines it reads come with the identification census \
         (spec section 9.1 step 4). Refused rather than ignored: a claim nothing checks is \
         worse than no claim.",
        layout.expect.ladder
    );
}

/// Grade one finished run against the profile's declared end state.
fn grade(stem: &str, layout: &Layout, out: &Path, log: &str, ok: bool) {
    // A known gap is a row pinning what the engine DOES today rather
    // than what it should do. It says so on stdout, in a shape
    // `tools/layout-coverage.py` can find, so a plane covered only by
    // gap rows is never counted as recognised.
    if !layout.expect.gap.is_empty() {
        println!("GAP: {stem}: {}", layout.expect.gap);
    }
    // The adopt guard, the same one `run_get_win` applies to every
    // `e2e` leg: a repair that completed having rebuilt nothing from
    // parity is a fixture in the `payloads` trap, not a passing row.
    adoptguard::refuse_a_solve_that_solved_nothing(log, out);
    assert_eq!(
        ok,
        layout.expect.exit_zero,
        "{stem}: the run exited {}, and the profile declares {}\n{log}",
        if ok { "zero" } else { "non-zero" },
        if layout.expect.exit_zero {
            "zero"
        } else {
            "non-zero (an [expect] exits gap row)"
        }
    );
    // A run that did not exit zero is graded on what ARRIVED rather
    // than on its exact tree, whether the gap is a file that never
    // came back or a file that came back correctly under a failing
    // exit code. `grade_a_gap_row` says why.
    if !layout.expect.complete || !layout.expect.exit_zero {
        grade_a_gap_row(stem, layout, out, log);
        return;
    }

    let got = out_tree(out);
    // BOTH SIDES SORTED BY NAME, because a directory tree has no order
    // of its own: `Expectation::files` is in the order the profile
    // lists its sources, and which of two files a walk reaches first is
    // a filesystem fact. Comparing the two orders directly would fail
    // `n1-c0-p0-baseline` - whose sources are `baseline.bin` then
    // `sample/baseline-sample.bin`, and whose flat output sorts the
    // other way round - over an agreement that is complete. Nothing is
    // weakened: a name in one list and not the other still fails, and
    // so does a duplicate, because the sorted vectors differ.
    let mut want = layout.expect.files.clone();
    want.sort_by(|a, b| a.0.cmp(&b.0));
    // Names first and separately, because the byte comparison below
    // prints lengths and not content: a wrong NAME is by far the
    // commoner failure and it deserves a message that reads.
    let got_names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
    let want_names: Vec<&str> = want.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        got_names, want_names,
        "{stem}: the output tree does not carry the expected names\n{log}"
    );
    for ((gn, gb), (_, wb)) in got.iter().zip(&want) {
        assert!(
            gb == wb,
            "{stem}: {gn} is not byte-exact against what the profile expects \
             (got {} bytes, expected {})\n{log}",
            gb.len(),
            wb.len()
        );
    }
}

/// Grade a row that pins a known gap: the payload names the profile
/// says arrive are there and byte-exact, and every other payload name
/// is ABSENT.
///
/// WHY THIS IS SUBSET-BASED where a complete row is graded on the exact
/// tree. A run that does not finish leaves the engine's own bookkeeping
/// behind - a `.nzbfast.journal` so a retry resumes, a payload renamed
/// to `*.nzbfast-partial` so nothing imports it - and which recovery
/// volumes a failing run happened to have fetched before it gave up is
/// the client's answer too. None of those is a REQUIREMENT, and writing
/// them into an expectation would pin the engine's current spelling of
/// its own furniture as though a profile had asked for it, which is the
/// one thing `crate::layouts` grades against.
///
/// What is not weakened is the half that makes a gap row worth having:
/// a payload name the profile says does NOT arrive must be absent, so
/// the day the engine repairs this row the test goes red and somebody
/// reads the `gap` text and deletes it. A gap row that stayed green
/// through its own fix would be worse than no row.
fn grade_a_gap_row(stem: &str, layout: &Layout, out: &Path, log: &str) {
    let got = out_tree(out);
    let at = |name: &str| got.iter().find(|(n, _)| n == name);
    for name in &layout.expect.arrives {
        let Some((_, bytes)) = at(name) else {
            panic!(
                "{stem}: [expect] arrives names {name:?} and the run did not end with it. \
                 The gap this row pins is {:?}\n{log}",
                layout.expect.gap
            );
        };
        let want = layout
            .expect
            .files
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, b)| b)
            .expect("an arrives name is a payload name");
        assert!(
            bytes == want,
            "{stem}: {name} arrived and is not byte-exact (got {} bytes, expected {})\n{log}",
            bytes.len(),
            want.len()
        );
    }
    for name in &layout.expect.payload {
        if layout.expect.arrives.contains(name) {
            continue;
        }
        assert!(
            at(name).is_none(),
            "{stem}: {name} arrived, and this row declares it does not. If the engine now \
             handles this layout, the fix is to delete [expect] complete/gap/arrives from \
             the profile, not to add the name to arrives. The gap text was: {:?}\n{log}",
            layout.expect.gap
        );
    }
}

/// Every regular file under `out`, as (out-relative '/'-joined name,
/// bytes), in a stable order.
///
/// The twin of `e2e_norar::out_tree` - see this file's header for why
/// it is written here rather than imported. Sorted by the joined
/// relative name rather than by directory-walk order, so a profile
/// whose expectation lists a nested file can state one order and mean
/// it.
fn out_tree(out: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, base: &Path, v: &mut Vec<(String, Vec<u8>)>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for path in rd.flatten().map(|e| e.path()) {
            if path.is_dir() {
                walk(&path, base, v);
            } else if let Ok(bytes) = std::fs::read(&path) {
                let rel = path
                    .strip_prefix(base)
                    .expect("a walked path is under the walk root")
                    .components()
                    .filter_map(|c| match c {
                        std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("/");
                v.push((rel, bytes));
            }
        }
    }
    let mut v = Vec::new();
    walk(out, out, &mut v);
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

/// The client config naming every mock the profile asked for.
///
/// `retention_days: 0` is unlimited - the retention plane is a serve
/// plane no profile selects yet, and a row that wants a backdated post
/// gets it from the generator's NZB dates rather than from a dial
/// written here.
fn write_config(dir: &Path, servers: &[&MockServer]) -> PathBuf {
    let entries: Vec<String> = servers
        .iter()
        .map(|s| {
            format!(
                "{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"retention_days\":0}}",
                s.addr.ip(),
                s.addr.port()
            )
        })
        .collect();
    let path = dir.join("config.json");
    std::fs::write(&path, format!("{{\"servers\":[{}]}}", entries.join(",")))
        .expect("write config");
    path
}

/// Run the real binary once and return (stdout then stderr, exit 0).
///
/// `NZBFAST_NO_ENRICH=1` in the CHILD environment, which is the half
/// that matters: this is a real process, not a test build, so
/// `identity::may_call_out()`'s unit-test answer does not reach it and
/// nothing else would stop an enrichment worker from hitting TMDB
/// (CLAUDE.md invariant 5).
fn run_get(config: &Path, nzb: &Path, out: &Path) -> (String, bool) {
    let mut cmd = get_cmd(
        config,
        nzb,
        out,
        &[("NZBFAST_NO_ENRICH", "1")],
        &[],
        GET_CONNS,
        GET_WINDOW,
    );
    // `output_under_test` rather than a bare `Command::output`: cargo
    // re-links the uplifted binary on every invocation, so a spawn can
    // answer NotFound for a file that is there before and after. The
    // measurement is in that function's own header.
    let child = harness::output_under_test(&mut cmd);
    (
        format!(
            "{}\n----- stderr (a SEPARATE stream: not in sequence with stdout above) -----\n{}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        ),
        child.status.success(),
    )
}
