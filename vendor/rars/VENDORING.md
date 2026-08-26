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
#      - [lints.rust] unsafe_code = "deny" (was forbid until the NEON
#        blake2sp entry, 22 Aug 2026), unused_must_use = "deny"
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
| 2026-08-22 | Sweep 8 M10: `clone_prefill` no longer unlinks the caller-claimed `dest` and then `std::fs::copy`s to the same NAME. The caller takes that path with `create_new` precisely so no symlink can be followed through, and the unlink threw the claim away - a link installed in the window received the whole volume, outside the job, and the `symlink_metadata` guard ran after the damage. The copy now lands in a staging directory this call creates exclusively (`create_dir` refuses an existing entry of any kind) and is published with `rename`, which replaces a link at the target rather than following it; the reflink/clonefile win survives because the copy destination still does not exist. Adds `stage_beside` and `open_repair_dest` (`O_NOFOLLOW` on unix) - the three repair-to-path entry points open `dest` right after the prefill, and a prefill that DECLINED leaves whatever is there alone. Three new lib tests. Cargo.toml gains a unix-only `libc` dep, constants only (`unsafe_code = "forbid"` still holds). | `src/recovery/stream.rs`, `src/rar50.rs`, `src/rar15_40.rs`, `Cargo.toml` |
| 2026-08-22 | NEON BLAKE2sp leaves (TODO 11 later list): `src/rar50/blake2sp.rs` became `blake2sp/{mod,portable,many}.rs`. `LeafSet` trait over the eight leaf states; `portable.rs` is the old `blake2s_simd` + 4-thread team (every non-aarch64 target), `many.rs` is a four-lane NEON kernel (aarch64 default) that compresses four leaves per pass. `Hasher` is now an alias for `TreeHasher<DefaultLeaves>`, so the extract.rs call sites did not change. **Cargo.toml `unsafe_code` went `forbid` -> `deny`**: `many.rs` carries the crate's ONE unsafe block, the call that enters the `#[target_feature(enable = "neon")]` kernel (stable Rust offers no safe way in, and the argument is in the module comment); `unsafe_is_confined_to_the_neon_entry` pins it to that single file. Measured on an M5 Max, 1 GiB: 0.87 CPU-s vs 1.88 for the thread team. Tests hold both kernels to `blake2s_simd`'s blake2sp on every length 0..1536 and on random inputs/chunkings. **In the fork** since 22 Aug 2026 (perf branch 1b84503, which ported every unported row above it as well - the fork had sat at c586ae2 of 24 Jul); the fork crate owns its own `[lints]` table to carry the `deny`. | `src/rar50/blake2sp/`, `Cargo.toml` |
| 2026-08-22 | TODO 17c item 1: `pipe_stored_chunks` keeps every pooled buffer at its full `STORED_PIPE_BUF` length for life and carries the fill level beside it, instead of truncating to the read count, clearing on the way back to the pool and growing again with `resize(STORED_PIPE_BUF, 0)`. That memset ran on EVERY round trip - 1 MiB per chunk, 1 GiB per GiB extracted - over bytes `read` was about to overwrite. The data channel now carries `(Vec<u8>, usize)`. Measured on a 1 GiB real-`rar` `-m0` member, 42 paired runs: 30 pairs faster, median paired CPU ratio 0.973-0.978. | `src/rar50/extract.rs` |
| 2026-08-22 | TODO 17c item 2: `next_x86_opcode_scalar` (BOTH copies) searches with `memchr`/`memchr2` instead of a masked byte loop. `cmp_mask` is only ever `0xff` (E8) or `0xfe` (E8E9), and masking with `0xfe` accepts exactly `0xe8`/`0xe9`, so the two are a one- and a two-byte search; any other mask keeps the byte loop, and a new lib test in each file pins that arm (both copies were collapsed to one the next day - see the 2026-08-23 row, and re-apply that row after this one). Scan primitive 2481 -> 7237 MiB/s (E8) and 2282 -> 4009 MiB/s (E8E9) at ~1.5% opcode density; end to end on a 129 MiB x86 payload with 1199 filter blocks, 14 paired runs: median paired wall ratio 0.961. `Cargo.toml` gains `memchr = "2"`, already in the workspace lockfile via aho-corasick. | `src/fast.rs`, `src/codec/fast.rs`, `Cargo.toml` |
| 2026-08-22 | TODO 17c item 1 rider: a lib test drives `pipe_stored_chunks` through a ragged read schedule (1 MiB, 7, 300 KB, 1, ~1 MB) and asserts the consumer sees exactly the content and the CRC matches, so no part of a previous round can reach either past the fill level. Test only; the row above is the change it guards. | `src/rar50/extract.rs` |
| 2026-08-22 | TODO 17b: the PPMd glue pass's step-1 threading is its own `Suballocator::thread_free_blocks`, held to a literal node-by-node front-insertion reference by two free-list fixtures. The O(n) build itself is older (29 Jul 2026, `78feeafbb`, replacing the reference's quadratic prepend); nothing pinned that it produced the SAME list, and the pre-existing glue tests cannot tell the orders apart because they only assert which blocks merged. The order sets which cell the next allocation takes, so it decides model-restart timing and decoder compatibility. Reversing the bucket walk fails both fixtures. | `src/codec/ppmd.rs` |
| 2026-08-22 | Split STORED members get the whole-file CRC on their last fragment. Both stored branches of the RAR 5 volume writer (`write_stored_volumes_impl`, and the stored fallback inside `write_compressed_volume_set_impl` that an incompressible entry takes) passed `None` for `data_crc32`, so such a set carried no checksum anywhere and `extract_volumes_to` returned Ok on corrupt bytes - every nzbfast fixture built by `Rar50VolumeWriter` over an incompressible payload was unverifiable. The compressed branch already did this. Adds `stored_split_volumes_carry_a_final_crc_and_refuse_corruption` (lib test, both writers, corruption refused with `checksum mismatch`). **In the fork** since 23 Aug 2026 (perf f17ff11, the exact patch; a lib test there too). | `src/rar50/write/volume.rs`, `src/lib.rs` |
| 2026-08-22 | TODO 17e: `reconstruct_data_volumes` has no per-byte fallback any more - `erasure_correction_matrix`'s error propagates. The fallback existed because a full-length 255-symbol codeword scanned alpha^0 twice and could not derive coefficients; that root-scan fix is older (29 Jul 2026, `7fc3ecdfd`, the `.max(1)` on the scan range) and **this row depends on it** - re-applying the deletion without it would turn a decodable set into a `DecodeFailed`. The per-byte Forney loop moved into the test module, where it stays as the differential oracle. `no_full_length_erasure_set_needs_a_per_byte_fallback` sweeps 200+55, 250+5 and 128+127 at one erasure and at the whole parity budget. | `src/recovery/rar3.rs` |
| 2026-08-23 | TODO 17c item 2, follow-up: `next_x86_opcode` and its `_impl`/`_scalar` helpers have ONE definition again. The row above converted BOTH byte-identical copies to `memchr` and left the duplication in place, so the same function was maintained twice with a near-duplicate lib test in each file. `src/codec/fast.rs` keeps `match_length` (and the `fast`-gated portable-simd imports it needs) and now carries `pub(crate) use crate::fast::next_x86_opcode;`, so the five `super::fast::next_x86_opcode` call sites in `codec/filters.rs` and `codec/rar50.rs` and the `crate::fast::` one in `src/x86_filter_scan.rs` resolve unchanged. The two test modules were merged into `src/fast.rs`, keeping the lane-boundary fixture, the E8-vs-E8E9 separation and the fallback arm for a mask no caller uses; net -83 lines, 763 rars tests green. Pure refactor: a temporary differential harness ran both copies over a 1 MiB pseudorandom corpus across 6 masks x 7 start offsets x 8 end bounds and both digested to `0xfd50b90bcddaa56e` before AND after the collapse. | `src/fast.rs`, `src/codec/fast.rs` |
| 2026-08-25 | `growable_buffer_read_blocks_until_bytes_arrive` waits for the reader to BLOCK (spinning on `blocked_waits()` under a 30s loud timeout) instead of sleeping 20 ms and hoping. The sleep was standing in for "the reader has reached the point where it must wait", and on a Windows runner executing six test shards at once, thread start-up plus scheduling outran it: the writer appended first, the reader found all six bytes on its first call, `blocked_waits` was 0 and the assertion failed. Intermittent windows-unit red; took main red on 25 Aug 2026 at baf2be1c (run 32803615314, shard 4/6, both nextest tries). Test only - no production code moves, and the data assertion was never affected. | `src/source.rs` |
| 2026-08-26 | `OwnedRangeReader`'s File and Stream arms, and `BlockingRangeReader`, return `UnexpectedEof` (`short_range()`) when the inner read answers 0 with bytes still owed, instead of `Ok(0)`. `Ok(0)` on a range that ended short is indistinguishable from a clean end, and both sequential extract walks (`rar50/extract.rs`, `rar15_40/extract.rs`) read it as "this fragment is finished" and move to the NEXT fragment - so a volume whose payload was cut short (a chase whose yEnc size fell short of the header's range, a file truncated after parse) still "extracted", with later members decoded from the wrong bytes and a member carrying no CRC of its own written truncated in silence. The exact-range path (`stream_read_exact`) has always failed closed on the same input; this is the sequential path agreeing with it. Adds `a_range_that_ends_early_fails_rather_than_reading_as_eof` (all three readers). Found by the 26 Aug 2026 full-tree bug sweep, finding 5. | `src/source.rs` |
| 2026-08-26 | `repair_prefix_streaming_impl` tests `damaged.is_empty()` BEFORE `states.is_empty() || slots.is_empty()`, and a group that is damaged with no usable record is now `TooManyDamagedShards` rather than a silent `continue`. Skipping it left no trace, so an archive whose every damaged group was skipped returned `Ok(vec![])` - the value the API contract reserves for "the record says the prefix is already intact". The caller cannot tell the two apart: `crates/nzbfast/src/rarfix.rs` renamed its destination over the volume on that answer and reported the volume repaired, over a byte-for-byte copy of the broken one with the member CRCs still wrong. The empty-rows arm below already answered `TooManyDamagedShards` for the same situation whenever slots existed but were unusable, so this is that answer reaching the case it could not see. Adds `a_damaged_group_with_no_usable_record_is_refused_not_reported_intact`. Found by the 26 Aug 2026 full-tree bug sweep, finding 6. | `src/recovery/stream.rs` |

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
