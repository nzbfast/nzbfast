//! Two large single-file creates at once, when the machine has room.
//!
//! # Why this is the one exception to "serial by default"
//!
//! A PAR2 create over ONE large file is bound by the whole-file MD5 the
//! File Description packet requires: one serial chain on one core. The
//! engine's fold pacer (`nzbkit::par2gen`'s `paced_width`) narrows the
//! fold beside it to the few workers that keep pace, so on a big machine
//! such a create leaves most of the cores idle. Measured 13 Sep 2026 on an
//! M3 Ultra, two creates of the same 8.86 GB file started together took
//! 11.51 / 11.47 / 11.59 s against 11.40 / 11.37 / 11.44 for one
//! (research/PARFAST-SINGLE-FILE-MD5-HEADROOM-2026-09-13.md, "Two creates
//! at once"), so a queue of such files run two at a time finishes in about
//! half the wall.
//!
//! It buys NOTHING for one job - each create is exactly as fast as it was -
//! and anything that is not that shape (several members, the transform, a
//! multi-batch create, a verify, a repair) keeps the queue's ordinary rules.
//!
//! # The rule
//!
//! A queued create is started beside a running one, whatever
//! `concurrency` says, only when ALL of these hold:
//!
//! * pairing is on (`performance.pair_large_creates`);
//! * both are creates of exactly one file starting at exponent 0, with the
//!   same process-global knobs (threads, memory, the joint solve) - the
//!   engine has one of each, and two jobs setting different values would
//!   run under whichever wrote last;
//! * the running create's pacer has settled ([`nzbkit::mem::paced_folds`]
//!   reports exactly it), because until it has there is no measured width
//!   to budget against;
//! * each of the two jobs' half of the machine leaves its fold MORE than
//!   the pacer's floor ([`nzbkit::par2gen::PACED_WIDTH_FLOOR`]) once its
//!   chain has a core - never on a box where the pacer would already sit
//!   at its floor, which is where the fold starts competing with the chain
//!   (the 8-vCPU Zen 4 rows in the note above);
//! * the machine has a core for each chain plus the running create's
//!   settled fold width twice over (the second create is budgeted at the
//!   width the first one settled at);
//! * the second create would itself take the paced single-file route in
//!   what the memory budget has LEFT beside the first
//!   ([`nzbkit::par2gen::single_file_create_paces`]): the engine divides
//!   the remaining budget for a create that starts beside another, and a
//!   second create whose recovery rows no longer fit one batch would fall
//!   off the fused route and cost more than it saves.
//!
//! A create that fails the rule waits in `queued` for the next tick rather
//! than starting and blocking, so the table says what is actually running.

use crate::job::JobSpec;
use crate::planner;
use crate::settings::Settings;

/// What pairing needs to know about a create before it runs: its one
/// member's length, the set's geometry, and the engine knobs it will set.
#[derive(Debug, Clone, PartialEq)]
pub struct PairShape {
    pub length: u64,
    pub block_size: u64,
    pub recovery_blocks: u64,
    pub knobs: Knobs,
}

/// The process-global engine knobs a create sets, resolved exactly as
/// `runner::run_create` resolves them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Knobs {
    pub threads: Option<usize>,
    pub memory_mb: Option<u64>,
    pub fast_solver: bool,
}

/// A create's pairing shape, or `None` for anything that can never pair:
/// another job kind, a create over no file or several, a `-f` create (the
/// fused route is written for exponent 0 only), or a spec the planner
/// refuses. This reads the filesystem (the source's length), so a caller
/// holding a lock the host's polls also take must not call it under that
/// lock.
pub fn shape_of(spec: &JobSpec, settings: &Settings) -> Option<PairShape> {
    let JobSpec::Create { create } = spec else {
        return None;
    };
    if create.first_recovery_block != 0 {
        return None;
    }
    // `left_out` is DROPPED here on purpose and this is the one call
    // site where that is right: this function answers "are these two
    // creates a pair the scheduler may fuse", not "what will the user
    // be told". The run and the preview both expand again and both
    // state it; a scheduler hint that also emitted warnings would
    // publish the same sentence a third time from a place with no pane
    // to put it in.
    let expanded = planner::expand_sources(
        &create.sources,
        create.path_mode,
        create.base_path.as_deref(),
        planner::SourceRules::Par2,
    )
    .ok()?;
    let [only] = expanded.members.as_slice() else {
        return None;
    };
    let preview = planner::preview(create).ok()?;
    Some(PairShape {
        length: only.length,
        block_size: preview.block_size,
        recovery_blocks: preview.recovery_blocks,
        knobs: Knobs {
            threads: create.perf.threads.or(settings.performance.threads),
            memory_mb: create.perf.memory_mb.or(settings.performance.memory_mb),
            fast_solver: settings.performance.fast_solver,
        },
    })
}

/// The machine as the scheduler reads it at the moment of deciding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Machine {
    /// `nzbkit::mem::cpu_workers()`: the pool width every engine site sizes
    /// itself from, which is what the two creates will actually run under.
    pub cores: usize,
    pub paced: nzbkit::mem::PacedFolds,
}

impl Machine {
    pub fn now() -> Machine {
        Machine {
            cores: nzbkit::mem::cpu_workers(),
            paced: nzbkit::mem::paced_folds(),
        }
    }
}

/// Why a second create was not started. Each names the clause of the rule
/// in the module doc that refused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The two jobs would set different process-global knobs.
    Knobs,
    /// Half the machine, less a core for the chain, leaves the fold at or
    /// under the pacer's floor.
    Floor { cores: usize },
    /// No settled pacer to budget against: the running create has not
    /// published a width yet (or is not on the paced route at all), or
    /// more than one create is pacing.
    NotSettled { paced_creates: usize },
    /// The chains and the settled folds need more cores than there are.
    Cores { need: usize, have: usize },
    /// The second create would not take the paced single-file route in
    /// what is left of the memory budget.
    Route,
}

/// Admit `next` beside `running`, the one create already running? The
/// whole rule of the module doc, with every input passed in so it can be
/// tested at machines this one is not. `next_paces` is
/// [`nzbkit::par2gen::single_file_create_paces`] for `next`, asked at the
/// same moment as `machine`.
pub fn admit_second(
    machine: Machine,
    running: &PairShape,
    next: &PairShape,
    next_paces: bool,
) -> Result<(), Refusal> {
    if running.knobs != next.knobs {
        return Err(Refusal::Knobs);
    }
    let floor = nzbkit::par2gen::PACED_WIDTH_FLOOR;
    // Each job's half of the machine, less its chain's core.
    if (machine.cores / 2).saturating_sub(1) <= floor {
        return Err(Refusal::Floor {
            cores: machine.cores,
        });
    }
    if machine.paced.creates != 1 {
        return Err(Refusal::NotSettled {
            paced_creates: machine.paced.creates,
        });
    }
    let need = 2 * (1 + machine.paced.fold_workers);
    if need > machine.cores {
        return Err(Refusal::Cores {
            need,
            have: machine.cores,
        });
    }
    if !next_paces {
        return Err(Refusal::Route);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::{
        BlockSpec, CreateSpec, PathMode, RecoverySpec, Source, UnicodePolicy, VerifySpec,
        VolumeSpec,
    };
    use nzbkit::mem::PacedFolds;

    fn shape(threads: Option<usize>) -> PairShape {
        PairShape {
            length: 8_858_370_048,
            block_size: 4_429_188,
            recovery_blocks: 100,
            knobs: Knobs {
                threads,
                memory_mb: None,
                fast_solver: false,
            },
        }
    }

    fn machine(cores: usize, creates: usize, fold_workers: usize) -> Machine {
        Machine {
            cores,
            paced: PacedFolds {
                creates,
                fold_workers,
            },
        }
    }

    /// The acceptance box: 32 cores, the first create's pacer settled at
    /// four (it went 32 -> 4 in two moves on the M3 Ultra).
    #[test]
    fn a_big_machine_with_a_settled_pacer_admits_the_second_create() {
        assert_eq!(
            admit_second(machine(32, 1, 4), &shape(None), &shape(None), true),
            Ok(())
        );
        // Sixteen is still room for two chains and two folds of four.
        assert_eq!(
            admit_second(machine(16, 1, 4), &shape(None), &shape(None), true),
            Ok(())
        );
    }

    /// `NZBFAST_CPU_WORKERS=4`, and every small box: half of four is two, one
    /// of which is the chain's, which leaves the fold under the pacer's
    /// floor however the running create is doing. Six is AT the floor and is
    /// refused too.
    #[test]
    fn a_box_where_the_pacer_would_sit_at_its_floor_never_pairs() {
        for cores in [1, 2, 3, 4, 5, 6, 7] {
            assert_eq!(
                admit_second(machine(cores, 1, 2), &shape(None), &shape(None), true),
                Err(Refusal::Floor { cores }),
                "{cores} cores"
            );
        }
        // Eight is the first width with a fold above the floor per job.
        assert_eq!(
            admit_second(machine(8, 1, 3), &shape(None), &shape(None), true),
            Ok(())
        );
    }

    /// A core for each chain PLUS the settled width twice over: the 8-vCPU
    /// Zen 4 settled at three (a fit) and a pacer at four does not fit.
    #[test]
    fn the_chains_and_the_settled_folds_must_fit_the_cores() {
        assert_eq!(
            admit_second(machine(8, 1, 4), &shape(None), &shape(None), true),
            Err(Refusal::Cores { need: 10, have: 8 })
        );
        // A pacer that has not moved off the published maximum can never
        // fit, which is how "not settled yet" reads on a single create.
        assert_eq!(
            admit_second(machine(32, 1, 32), &shape(None), &shape(None), true),
            Err(Refusal::Cores { need: 66, have: 32 })
        );
    }

    #[test]
    fn no_settled_pacer_means_nothing_to_budget_against() {
        assert_eq!(
            admit_second(machine(32, 0, 0), &shape(None), &shape(None), true),
            Err(Refusal::NotSettled { paced_creates: 0 })
        );
        assert_eq!(
            admit_second(machine(32, 2, 8), &shape(None), &shape(None), true),
            Err(Refusal::NotSettled { paced_creates: 2 })
        );
    }

    /// The engine's own answer for the second create is final: a set whose
    /// rows no longer fit one batch in what the budget has left, or that
    /// takes the transform, is refused even on a machine with room.
    #[test]
    fn a_second_create_off_the_paced_route_is_refused() {
        assert_eq!(
            admit_second(machine(32, 1, 4), &shape(None), &shape(None), false),
            Err(Refusal::Route)
        );
    }

    #[test]
    fn different_process_global_knobs_never_pair() {
        assert_eq!(
            admit_second(machine(32, 1, 4), &shape(Some(8)), &shape(None), true),
            Err(Refusal::Knobs)
        );
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "parfast-session-pairing-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("temp dir");
        p
    }

    fn create(dir: &std::path::Path, names: &[&str]) -> CreateSpec {
        for n in names {
            std::fs::write(dir.join(n), vec![3u8; 64_000]).expect("member");
        }
        CreateSpec {
            sources: names
                .iter()
                .map(|n| Source {
                    path: dir.join(n),
                    recursive: false,
                })
                .collect(),
            path_mode: PathMode::Basename,
            base_path: None,
            block: Some(BlockSpec::Size { size: 4_096 }),
            recovery: Some(RecoverySpec::Percent { percent: 10.0 }),
            output: dir.join("set.par2"),
            volumes: VolumeSpec::Pow2,
            first_recovery_block: 0,
            comment: String::new(),
            overwrite: false,
            std_naming: false,
            unicode: UnicodePolicy::Auto,
            perf: Default::default(),
        }
    }

    #[test]
    fn only_a_one_file_create_from_exponent_zero_has_a_shape() {
        let d = tmp("shape");
        let settings = Settings::default();
        let one = create(&d, &["a.bin"]);
        let got = shape_of(
            &JobSpec::Create {
                create: one.clone(),
            },
            &settings,
        )
        .expect("a one-file create has a shape");
        assert_eq!(got.length, 64_000);
        assert_eq!(got.block_size, 4_096);
        let preview = planner::preview(&one).expect("preview");
        assert_eq!(got.recovery_blocks, preview.recovery_blocks);
        assert_eq!(got.knobs.threads, None);

        let two = create(&d, &["a.bin", "b.bin"]);
        assert_eq!(
            shape_of(&JobSpec::Create { create: two }, &settings),
            None,
            "two members never pair"
        );
        let mut late = one.clone();
        late.first_recovery_block = 5;
        assert_eq!(
            shape_of(&JobSpec::Create { create: late }, &settings),
            None,
            "a -f create is off the fused route"
        );
        let verify = JobSpec::Verify {
            verify: VerifySpec {
                par2: d.join("set.par2"),
                extra_dirs: Vec::new(),
                options: Default::default(),
            },
        };
        assert_eq!(shape_of(&verify, &settings), None);

        // The knobs are resolved the way the runner resolves them: the
        // job's own, else the Settings pane's.
        let mut s = Settings::default();
        s.performance.threads = Some(6);
        s.performance.fast_solver = true;
        let got = shape_of(&JobSpec::Create { create: one }, &s).expect("shape");
        assert_eq!(
            got.knobs,
            Knobs {
                threads: Some(6),
                memory_mb: None,
                fast_solver: true
            }
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The engine's route question, on the two sides of its size floor. The
    /// positive shape is small enough in rows (1% of 2,048 one-MiB blocks)
    /// that its accumulators sit under the engine's smallest budget share
    /// whatever else this test process is creating at the time.
    #[test]
    fn the_engine_says_which_single_file_creates_take_the_paced_route() {
        assert!(nzbkit::par2gen::single_file_create_paces(
            2 << 30,
            1 << 20,
            21
        ));
        assert!(
            !nzbkit::par2gen::single_file_create_paces(64 << 20, 1 << 20, 4),
            "under the fused route's 1 GiB floor"
        );
        assert!(!nzbkit::par2gen::single_file_create_paces(
            2 << 30,
            1 << 20,
            0
        ));
        assert!(!nzbkit::par2gen::single_file_create_paces(2 << 30, 0, 21));
    }
}
