# The CREATE's row gate at 4 MiB on GFNI-256, both pools, 16 Sep 2026

Lane `parfast-create-rowgate-4mib-gfni256`. The CREATE-side companion to
the two landed 4 MiB REPAIR rounds - `rounds/w4mib-2026-09-16/`
(`-t16`) and `rounds/t4m4-2026-09-16/` (`-t4`) - which together
recommend a second rung on the block-size clause at 416 and deliberately
move nothing, because `create_ntt_min_rows` asks
`ntt_min_missing(block_size)` and would move with it. Written up in
an internal note.

- **Box** intel-core-ultra-9-386h (Core Ultra 9 386H, GFNI-256, 16 cores, 31.4 GB,
  Windows 11 build 10.0.26200), under the per-box rig lock, one sitting
  from 15:07:14Z.
- **Binary** parfast built on the box from `06d5734b7` - the commit BOTH
  4 MiB repair rounds built, chosen so the create numbers are comparable
  with them rather than merely contemporary. That commit's
  `par2gen/ntt_range.rs` is byte-identical to origin/main, and the only
  `par2repair/fastpar.rs` delta is an unrelated cgroup budget clamp, so
  nothing on the row-gate path moved between the two.
- **Harness** origin/main's `wcomb.ps1` (`1ad3f260...`) and `plib.ps1`
  (`3b0e254e...`), NOT the copies `06d5734b7` carries - that tree
  predates `-Residency` and `Wait-FixtureSettle`, and a round launched on
  it loses both silently.
- **Fixture** 16 x 1,024 MiB at 4 MiB blocks, `-c640`: n = 4,096, a
  16 GiB corpus. The same shape both repair rounds used. n = 4,096 clears
  the x86 INPUT floor of 2,048 on its own, without which the forced arm
  silently folds.
- **One ladder, both pools** (`-Threads 4,16`, interleaved per rung), so
  the two pools are measured under identical box conditions. This is the
  one methodological difference from the landed `-t4` round, which
  measured its pool in a sitting of its own.
- **Rungs** 320,352,384,416,448,480,512,544 - eight, bracketing the 416
  the repair side recommends, with three rungs below it. The create
  writes its own `cr.par2` per leg, so a rung is not bounded by the
  fixture's `-c640`.
- **Arms** `fold force force2 fold2` at every rung, so every cell carries
  its own A/A pair and no verdict is read without a floor under it.

## Why this round is independent of two open claims

Neither arm depends on the shipped constant being right. `fold` forces
`NZBFAST_NTT=0`; `force` sets `NZBFAST_CREATE_NTT_MIN_ROWS=0`, which sets
the admission threshold to ZERO rather than to a row count. So no rung -
including the 320 one, which sits below the gate's 352 - can fall through
to the fold the way an inherited nibble row count did on another lane's
smoke cell today. That is what lets this round measure the crossover
while `NTT_MIN_MISSING_GFNI256_LARGE_BLOCK`'s own correctness is open on
other lanes.

**Both arms are the SAME BINARY**, differing only by environment
variable. There is no recompilation anywhere in this ladder, so inlining
and code layout are identical between the arms by construction - which
matters on this part, where a lane measured an arm running 8-14% SLOWER
while doing strictly more work, reproducibly, from code layout alone.

## Files

Filled in when the round completes.

## Files

| file | what |
|---|---|
| `coreultra9-gfni256-create-4m-n4096-t4-t16-ladder.log` | the round: 64 legs, both pools, rungs 320..544 |
| `coreultra9-gfni256-create-4m-n4096-build-fixture-settle.log` | the build, fixture create and `Wait-FixtureSettle` from the first launch |

**Every leg in the ladder log is used.** 64 legs, all `rc=0`, all
`match=1` on the cross-arm SHA-256, all path-asserted. Nothing excluded,
nothing re-measured, no contaminated sitting.

The second log is the FIRST launch, which built the binary and the
fixture, ran the settle guard to completion, and then died at its first
ladder line on a defect in this lane's own wrapper script: `-Threads 4,16`
and `-Rungs 320,...` were passed unquoted, so PowerShell coerced the
arrays to `"4 16"` on the way into `wcomb.ps1`'s `[string]` parameters and
`Split(',')` handed `[int]` one unparseable element. It is kept because it
carries the `BIN`, `CREATE`, `FIXTURE` and `FIXTURE-SETTLE` lines the
ladder log does not - the relaunch ran `-NoBuild` against the fixture this
log built, so the two together are the round. The rig lock was released
cleanly on that failure; no orphan.

`Wait-FixtureSettle` held the first leg **456 s**, releasing when foreign
CPU fell from 146.9% to 4.7% - Windows Search walking a freshly written
16 GiB corpus. Without it the low rungs would have been contaminated
exactly as the 16 Sep round's were.
