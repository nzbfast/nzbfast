# Vendoring `rars`

`vendor/rars/` is a curated copy of the `rars` crate from our perf fork of
[bitplane/rars](https://github.com/bitplane/rars). It is **not** a git subtree
or submodule — it is a mirrored subset, produced by
[`sync-from-fork.sh`](sync-from-fork.sh).

Upstream-tracking policy is FREEZE + cherry-pick: watch the fork for decoder
fixes, port selectively, re-run the gates, then re-vendor.

## What is vendored

| Path | Source in fork | How |
| --- | --- | --- |
| `src/**` | `crates/rars/src/**` | exact mirror (`rsync --delete`) |
| `tests/fixtures/**` | `crates/rars/tests/fixtures/**` | **exact mirror — all of it** |
| `COPYING` | fork repo-root `COPYING` | copied |
| `Cargo.toml` | `crates/rars/Cargo.toml` | **hand-maintained, see below** |

Not vendored: `tests/*.rs` (fork integration tests — we run only the inline
`--lib` tests), `benches/`, `fuzz/`, `python/`, `scripts/`, `target/`.

## Why `tests/fixtures/**` must always come along

The rars unit tests live **inline** in `src/lib.rs` and load inputs via
`env!("CARGO_MANIFEST_DIR")/tests/fixtures/rar15_40/...`. If any referenced
fixture is missing, `cargo test -p rars --lib` fails with `NotFound` on a clean
checkout.

This exact bug shipped once: an earlier sync copied `src/` but dropped
`tests/fixtures/`, and it was hotfixed by hand-vendoring only the two fixtures
the then-current tests happened to read. Hand-picking fixtures re-introduces the
same fragility — the next inline test that references a third fixture breaks
again. So the sync mirrors the **whole** fixtures tree; do not trim it to a
subset.

## Re-vendoring to a newer fork rev

```sh
# 1. Sync src/ + tests/fixtures/ + COPYING from your fork checkout.
RARS_FORK=~/path/to/rars ./vendor/rars/sync-from-fork.sh

# 2. Reconcile Cargo.toml BY HAND *only if* the fork's [dependencies] changed.
#    The vendored manifest deliberately differs from the fork's:
#      - de-workspaced deps (concrete versions, not `.workspace = true`)
#      - version = "0.4.6+nzbfast"
#      - [lints.rust] unsafe_code = "forbid", unused_must_use = "deny"
#      - no [dev-dependencies], no [[bench]] (not vendored)
#    The script never overwrites Cargo.toml, so it survives a re-sync.

# 3. Gate: must stay green.
cargo test -p rars --lib

# 4. Commit.
git add -A vendor/rars
git commit -m "vendor/rars: sync to fork rev <rev>"
```

## Local divergences (re-apply after every sync)

`sync-from-fork.sh` mirrors `src/**` with `rsync --delete`, so anything we
change under `src/` is GONE the moment someone re-vendors. Keep the ledger
below current, and walk it after every sync. Each entry names a marker
comment carrying the same date, so `git grep 'nzbfast-local change'` under
`vendor/rars/src` finds what should be here.

| Date | What | Where |
| --- | --- | --- |
| 2026-08-20 | `delta_decode_into`: the RAR 5 filter path reuses one delta buffer per member instead of allocating and zeroing a fresh one per filter block. Adds the `delta_scratch` field on both RAR 5 output structs and a fourth argument to `apply_filter_to_range`. `delta_decode` (the allocating shape) stays for RAR 2.9 and the tests. | `src/codec/filters.rs`, `src/codec/rar50.rs` |
| 2026-08-20 | Streaming legacy (RAR 2/3) recovery repair, C7: `repair_protect_to_file`/`_to_path` on the rar15_40 `Archive` scan protected sectors by bounded range reads and patch a cloned/copied destination in place, instead of `repair_protect_head`'s two whole-volume buffers (2.02 GiB -> 11 MiB peak RSS on a 1 GiB volume). Adds `Error::LegacyRepairTooLarge` (budget refusal, incl. the compressed-NEWSUB decode pre-check), reroutes the `ArchiveReader::repair_recovery_to_file`/`_to_path` Rar15To40 arms, and adds 7 `streaming_protect_*` lib tests plus the `legacy_rar3_streaming_repair_matches_winrar_byte_for_byte` leg in `tests/winrar_recovery.rs`. `repair_protect_head` (buffered) stays as the tests' oracle. | `src/rar15_40.rs`, `src/lib.rs`, `src/error.rs`, `tests/winrar_recovery.rs` |
| 2026-08-20 | C7 rider (sweep 8 M9): `repair_protect_sectors` pass 1 bails at `parity_sectors + 1` mismatches (same `InvalidHeader(exceeds_parity)` value as the post-scan check) instead of collecting every damaged sector index first - the unbounded `Vec<usize>` grew source_len/64 bytes on a widely-corrupt volume before any check ran, breaking the documented peak-memory contract. The `working > budget` check also moved above the `used_slots` allocation it already accounts for. | `src/rar15_40.rs` |

## Deep gate before a release (decoder changes especially)

The `--lib` gate above and the fuzzers use small inputs, so they are blind to
size-dependent decode bugs: back-references reaching past the streaming window
(>64 MiB), solid cross-member history, and volume-split members only appear in
large real archives. The fork carries a real-`rar` round-trip rig for exactly
these axes at `crates/rars/tests/real_archive_diff.rs`. It is NOT vendored (a
`tests/*.rs` file) and needs a local `rar` 7.x, so run it in the fork checkout
before cutting a release or dropping the external `unrar` fallback:

```sh
cargo test -p rars --test real_archive_diff -- --ignored --nocapture
```

It builds ~76 MiB archives across RAR5/RAR7 dictionary sizes (128 MiB..1 GiB),
solid multi-file sets, and multivolume splits, and asserts rars decodes each
byte-for-byte. This is what would have caught the 64 MiB streaming-window cap.

The whole export ships in the public repo (`vendor` is in
`packaging/PUBLIC_MANIFEST`; `/vendor/` is leak-scan-exempt as third-party
source), which satisfies build-from-source.
