# The four-thread pool at 4 MiB on GFNI-256, 16 Sep 2026

Lane `parfast-4mib-t4-row-gate-16sep`. The `-t4` companion to the `-t16`
round in `rounds/w4mib-2026-09-16/`: the same fixture shape, the
same commit, the same three ladders, four threads instead of sixteen.
Written up in an internal note, section
"The four-thread pool at 4 MiB: the two pools cross together, and the
clause is wrong for both (16 Sep 2026)".

- **Box** intel-core-ultra-9-386h (Core Ultra 9 386H, GFNI-256, 16 cores, 32 GB,
  Windows 11), under the per-box rig lock, three sittings 10:26Z-13:11Z.
- **Binary** parfast 1.5.0-beta.3 built on the box from `06d5734b7`, the
  commit the `-t16` round and the 1 MiB `k` round built. sha256
  `79747be2...`, 4,173,312 bytes - the same byte count as the `-t16`
  round's `4b8077ff...`, a different hash because the build embeds its
  own path and the round roots differ.
- **Harness** origin/main's `wcomb.ps1` (`d56c541c...`) and `plib.ps1`
  (`3eade0f5...`), which is NOT the `39bf5aba...` the `-t16` round ran.
  The differences are a fixture rung bound, a refused leg restoring the
  fixture, `Wait-FixtureSettle`, and `-NttBudget` narrowing to resident
  legs only. The first three are refusals and a wait; the fourth cannot
  bite because neither round passed `-NttBudget` on a windowed ladder.
- **Fixture** 16 x 1,024 MiB at 4 MiB blocks, `-c640`: n = 4,096, a
  16 GiB corpus, one fixture for every ladder here.
- **96 legs, all `restored=16/16`**, every transform leg path-asserted
  and residency-asserted.

## Which legs are in the published tables

| file | legs | used |
|---|---:|---|
| `...t4-resident-ladder.log` | 20 | all (m = 384..512) |
| `...t4-resident-ladder-low-rungs.log` | 8 | all (m = 320, 352) |
| `CONTAMINATED-t4-resident-low-rungs-during-rar15-round.log` | 8 | **NONE** |
| `...t4-windowed-m8192-ladder.log` | 20 | all (m = 416..544) |
| `...t4-windowed-m8192-low-rungs.log` | 8 | **m = 384 only** |
| `...t4-windowed-m8192-m352-rerun.log` | 4 | all (m = 352) |
| `...t4-windowed-m4096-ladder.log` | 20 | **m = 448, 480 only** |
| `...t4-windowed-m4096-low-rungs.log` | 8 | all (m = 384, 416) |

Two exclusions, for two different reasons, and neither is a judgement
call about an inconvenient number:

**1. Contamination.** Between 12:29Z and 12:42Z another lane ran a rars
round (`rar15-decoder-costs-x86-16sep`) on this box. It took neither the
rig lock nor a `parfast` process, so the standard free-check could not
see it, and `Require-QuietBox`'s ceiling is 10% of the whole box floored
at one core - 160% here - so one saturated core passes under it. The
legs it caught ran at foreign CPU to 120% of a core with A/A spreads to
11.9%, against 0.2-2.6% on the same ladders' clean rungs. They were
re-measured on a quiet box; the same cell moved 6-11% (m = 320 fold
164.77 CPU-s quiet against 175.48 and 182.95 contaminated). The
contaminated resident file is kept, named, and used by nothing. The
contaminated `-m8192` m = 352 legs sit in the `low-rungs` file beside a
clean m = 384, so that file is used one rung only.

**2. Slabbing.** On the `-m4096` ladder, m = 512, 544 and 576 solve in
TWO slabs (`slab_width` 2 MiB, `windows=2 win_slices=2056/2056`) where
384-480 solve in one (`windows=3 win_slices=1028/1028/1028`), and the
force leg duly drops ~17 CPU-s at the boundary. That is a different
shape, not a continuation of the curve - the same thing the `-t16` round
excluded at its own m = 512, and the 1 MiB round before it. The boundary
sits at m = 512 on this fixture and budget on BOTH pools, so it is a
property of m and the budget rather than of the thread count. Excluding
them does not move the crossover (441 either way): the crossing is
between 416 and 448, below the boundary.

## Reducing

    python3 harness/rowgate.py read <log> [<log> ...]

`read_ladder` groups by `(label, threads)`, so the low-rung files merge
into their ladder's table by sharing its `-Label`. To reproduce the
published tables exactly, feed the files the table above marks "all",
and filter the partial ones:

    # -m8192
    cat ...m8192-ladder.log ...m8192-m352-rerun.log > /tmp/w.log
    grep ' m=384 ' ...m8192-low-rungs.log >> /tmp/w.log
    # -m4096
    cat ...m4096-ladder.log ...m4096-low-rungs.log \
      | grep -v ' m=512 \| m=544 \| m=576 ' > /tmp/w4.log
