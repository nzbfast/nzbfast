//! Every integration test in this crate except the one build-gated
//! elapsed-time suite, compiled into ONE test binary.
//!
//! Why: each `[[test]]` target is a separate executable that statically
//! links the whole crate graph, and linking those is the single biggest
//! cost in CI's Windows leg. This is the same change
//! `crates/nzbfast/tests/integration/main.rs` made for that crate on
//! 17 Aug 2026 (28 executables to 1); nzbkit was simply never given the
//! same treatment, and still paid 27 separate links on every push -
//! nine of those targets held a SINGLE test each.
//!
//! WHAT THIS ACTUALLY BOUGHT, measured on CI after it landed - and read
//! this before the prediction below it, because the prediction was
//! WRONG and is kept only so nobody re-derives it.
//!
//! CI archives 42 binaries before, 20 after. `build test archive` on
//! windows-build, mean of the runs either side:
//!
//!   before        817s      windows-unit slowest shard  486s
//!   rars only    ~827s (2)                             ~316s (2)
//!   + this       ~826s (5)                             ~333s (5)
//!
//! So the build step is UNCHANGED. The whole windows-unit win belongs
//! to the rars opt-level change that landed just before this, not to
//! this commit. What this commit did buy is real but smaller and
//! elsewhere: the archive artifact halved, 220,539,754 -> 114,638,636
//! bytes, and the four shards' artifact download fell from 47s to 10s
//! in total. Plus the isolation findings below, which is arguably the
//! larger return.
//!
//! WHY THE PREDICTION FAILED, since the arithmetic looked sound. It was
//! this: the span between the last `Compiling` line and `Finished` was
//! 8m19s for 42 binaries, so ~11.9s each, so dropping 19 of them saves
//! ~3.5 min. Two errors. That span is NOT pure linking - the big crates
//! are still in codegen throughout it, and only their `Compiling` line
//! has already been printed. And merging 20 test crates into one
//! removes link work but also removes COMPILE PARALLELISM: 20 small
//! crates compile concurrently across the runner's cores, one merged
//! crate does not. On a 4-vCPU runner those two effects cancel.
//!
//! The lesson generalises past this file: per-binary link cost is not a
//! constant you can multiply. Measure the step, not a derived rate.
//!
//! This does NOT weaken isolation: nextest runs every test in its own
//! PROCESS regardless of which binary it lives in, so these tests are as
//! isolated from each other as they were when each had its own
//! executable. What DOES change is a plain `cargo test -p nzbkit
//! --test integration`, which now puts every module in one process -
//! and that is a gain, not a risk: it is the only way the "test A leaves
//! process-global state that test B reads" class is visible at all, the
//! class CLAUDE.md's `unit-one-process` note exists for. Verified green
//! in that single-process shape before this landed.
//!
//! ADDING A TEST: put the file beside this one and add a `mod` line
//! below. A new top-level `tests/*.rs` still becomes its own target, so
//! nothing silently changes behaviour - but prefer a module here unless
//! the test genuinely needs its own executable.
//!
//! THREE MORE STAY THEIR OWN TARGETS, and for a reason that is not
//! about cost: `delivery_cost`, `lzma_dict_window_rss` and
//! `nested_container_buffer_rss` each install a `#[global_allocator]`
//! to count live bytes. That attribute is per-BINARY and may appear
//! once, so merging them is not merely awkward, it does not compile -
//! `cannot define multiple global allocators`, which is how this was
//! found. Even singly it would be wrong: the counting allocator would
//! then be measuring all 24 other modules' allocations too, so the
//! numbers these three exist to produce would stop meaning anything.
//! A test that instruments the allocator needs its own executable.
//!
//! AND THREE STAY OUT BECAUSE THEY ASSERT ON PROCESS-GLOBAL PRODUCT
//! STATE, which is the second rule this merge discovered and the one
//! worth reading before adding a `mod` line below.
//!
//! `holds_cap_default` and `partials_cap_default` each assert a budget
//! default is UNPUBLISHED and then publish one, so they poison each
//! other: run together, the second reads 80530620 where it demands
//! 268435456 (this is not hypothetical - it is what the first merged
//! build did). holds_cap_default's own header already said publishing
//! one "would change the default under" a suite that shares the
//! process; it simply had no way to be wrong while every target was
//! its own executable. `rate_floor` asserts on the session-end census,
//! also process-global, and read all zeros beside its neighbours.
//!
//! These pass under nextest either way, because nextest gives every
//! test its own process - which is exactly why the coupling was
//! invisible and why `cargo test --test integration` is the shape that
//! shows it (CLAUDE.md's `unit-one-process` note is about this class).
//! Do NOT "fix" one of these by merging it and running only nextest.
//! A test whose subject is a process-global needs its own executable.
//!
//! `tls` WAS A FOURTH AND IS NOT ANY MORE, on 23 Aug 2026, and the
//! difference is the reason this paragraph exists rather than a note
//! saying it flakes. Its symptom was identical to the three above - red
//! in-process under parallel threads, green under nextest - and its
//! cause was not in the test at all. Both TLS modules bring a private
//! CA, and `tls_client_config` cached the built config in two
//! `OnceLock`s, so the FIRST connection anywhere in the process latched
//! its trust anchors and every later one silently got them: a second CA
//! was read, ignored, and could not connect. That is the client's
//! defect, not the suite's, and it was never only about tests - an
//! embedder pointing the client at a new CA after its first connection
//! had exactly the same silence. The cache is keyed by the CA path now
//! (see `tls_client_config` in `crates/nzbkit-base/src/nntp/tls.rs`), the two
//! modules take a guard from `tls_env` so that only one CA is in force
//! at a time, and neither uses `std::env::set_var` any more - the
//! `unsafe` on that call was justified by "the only test in this
//! binary", which is a claim a merge falsifies.
//!
//! So the rule above is worth reading in both directions: ask whether
//! the process-global belongs to the TEST or to the PRODUCT before
//! concluding that the test needs its own executable. Three of these
//! four really did own theirs. The fourth was reporting a bug.
//!
//! `conn_tuner` stays its own target on purpose: its
//! `required-features = ["heavy-tests"]` gate (TODO 116b) is per-target,
//! and that gate is what keeps it out of per-push CI - it races a
//! throttled mock over a connection ladder and its home is nightly.yml.
//! Folding it in here would BUILD it on every push again, which is the
//! exact cost that gate was added to remove.

//! ONE NAMING TRAP, and it is new with this file. `crates/nzbfast` has
//! a test target called `integration` too, so a BARE `binary(integration)`
//! in a nextest filter now matches BOTH crates' binaries where it used to
//! mean nzbfast's alone. Every existing filter is already safe - the two
//! overrides in `.config/nextest.toml` that name it are written
//! `package(nzbfast) and binary(integration) and test(...)`, and no `-E`
//! expression in CLAUDE.md, ci-private.yml or nightly.yml mentions it at
//! all (they name only the seven build-gated heavy binaries). Keep the
//! `package(...)` half on anything new. The name is shared deliberately
//! rather than made unique: this file and nzbfast's are the same idea and
//! a reader who learns one should find the other, and `package()` is the
//! qualifier nextest gives you for exactly this.

// Shared helper, declared once here rather than in each module: a module
// file's children resolve against a directory named after it, so a
// per-file `mod scratch;` would look for tests/integration/scratch/.
// The five modules that use it carry `use crate::scratch;`.
#[path = "../scratch/mod.rs"]
mod scratch;

// FIVE OF THESE ONLY EXIST WITH THE INDEXER, and say so here rather than
// leaving the slim build to find out. `cargo check -p nzbkit
// --no-default-features --all-targets` (the configuration every phone
// build starts from) was red from the day this file was assembled until
// 3 Sep 2026 on exactly these modules: each reaches `nzbkit::index`,
// which `src/lib.rs` declares under `#[cfg(feature = "indexer")]`, and a
// test module has no `required-features` of its own the way a
// `[[test]]` target does - the gate has to sit on the `mod` line. This
// is the ONE place the cfg belongs: widening the production `cfg` so the
// slim binary carries the index to satisfy a test is the mistake the
// mobile-targets note in CLAUDE.md warns about. The two examples that
// reach the index (`indexscan_bench`, `sidecar_fold_walk`) carry the
// same rule as `required-features = ["indexer"]` in Cargo.toml, because
// an example IS a target. ci-private's `slim-check` job runs the nzbkit
// slim line beside the nzbfast one so this cannot rot in silence again.

#[cfg(feature = "indexer")]
mod auto_vacuum_ingest_cost;
#[cfg(feature = "indexer")]
mod compact_abort_latency;
mod fmp4_remux;
mod fuzz_seed_corpus;
#[cfg(feature = "indexer")]
mod index_integrity_regressions;
mod ladder_tail_rig;
mod live_tune;
mod live_verify;
mod loss_doubt;
mod lzma_dict_admission;
mod mediaprobe;
mod par2_parse;
mod par2gen_interop;
mod par2repair_dir;
mod par2repair_namepath;
mod par2repair_parity;
mod par2repair_reference;
#[cfg(feature = "indexer")]
mod provider_demote_rig;
#[cfg(feature = "indexer")]
mod scoreboard_parity_measure;
mod steer_rig;
mod store_promote_cost;
mod tls;
mod tls_chaos;
mod tls_env;
