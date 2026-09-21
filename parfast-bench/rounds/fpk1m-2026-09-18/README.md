# Does the fold's parallelism give out at high m on a NON-nibble part?

Lane `fold-parallelism-knee-18sep`, **arm 2** of the fold-parallelism-knee
chip. One sitting on **intel-core-ultra-9-386h** (Core Ultra 9 386H, GFNI+AVX2, the
fleet's only GFNI-256 part), 18 Sep 2026.

**Status: RAN AND COMPLETE.** Three ladders, two sittings, one fixture and one
binary, 04:37Z-07:00Z, 144 legs, every leg `rc=0`. Everything above the Result
section was written and landed on origin BEFORE the sitting - the question, the two
ladders, the confound this part carries, the falsification rule and the guard
on what the round does not license - so none of it is fitted to the numbers.
The Result section says what actually happened.

## The finding this tests, which is NOT what this round measures

Three banked rounds on **intel-i5-10600kf** (i5-10600KF, 6c/12t, AVX2 without GFNI =
the nibble class) agree that the **fold's** effective parallelism (`cpu`/`wall`)
gives out at high `m` while the **transform's** does not:

| | evidence |
|---|---|
| **64 KiB** | `-t12` fold holds 10.1-11.2 up to m=2048 and drops to **6.08 / 6.05** at m=4096, independently in `cf-two-binary-control-2026-09-16/` and `wcomb-k-nibble-2026-09-16/`. `-t4` and `-t6` hold theirs throughout. |
| **1 MiB** | `-t12` never pays at ANY rung - efficiency 0.54-0.60 of the pool throughout, and at m=2048 it is **worse in wall** than `-t6` (153.303 s against 147.593 s). `t6-1mib-nibble-smt-2026-09-16/`. |
| **not the pool, not memory** | in that same 64 KiB control the `-t12` FORCE arm at m=4096 holds **8.89** at a LARGER footprint (1,029 MB) than the collapsing fold cell (682.5 MB). A working-set / bandwidth threshold was ranked first and then refuted by that control. |
| **not load** | `cf-load-term-2026-09-16/` read the same cell at 17%, 48%, 83% and 14% of a core of foreign CPU: 6.09 / 6.08 / 6.07 / 6.10, a 0.5% spread across a fivefold change in box load. |

Under the wall-time rule (memory topic
`nzbfast-wall-time-is-the-deciding-metric`) this is a **wall** finding: at
64 KiB m=4096, twelve threads buy essentially nothing over six.

**What is in doubt is its generality.** Every round above is on ONE part, and
intel-i5-10600kf is this fleet's only nibble-class box - so "SMT never pays at 1 MiB"
is currently a property of that silicon and not of the fold.

## The falsification rule, fixed in advance

- **If the shape appears here too** - `cpu`/`wall` for the fold falling as the
  pool widens, while the force arm's holds at the same rungs and pools - the
  mechanism is a property of the **fold** and deserves a constant's attention.
- **If it does not** - the fold's efficiency tracking the force arm's across
  the pool ladder - the banked finding is an **i5-10600KF story** and must be
  labelled as one, and the 1 MiB `-t12` readings banked so far stop being
  evidence about the fold at all.

Either outcome is a result. Neither moves a constant in this round.

## The confound this part carries, and why there are two ladders

**The two boxes do not disagree only about GFNI.** On the i5 the ladder
decomposes cleanly: `-t4` -> `-t6` adds two *physical* cores, `-t6` -> `-t12`
adds **no cores at all** and is pure SMT. intel-core-ultra-9-386h has **no SMT** and is
**hybrid** - 16C/16T as 4 P-cores (0-3), 8 E (4-11), 4 LP-E (12-15) - with a
measured **1.43x single-thread swing decided purely by where Windows puts an
unpinned thread** (`.claude/MACHINES.md`). So an unpinned `-t12` here is 4 P +
8 E, and a fall in `cpu`/`wall` at `-t12` is explicable by **core class** with
no reference to the fold at all.

An unpinned ladder on this part therefore **cannot answer the question alone**.

| ladder | pools | affinity | reps | what it is for |
|---|---|---|---|---|
| **A** `fpku` | `-t4,6,12` | unpinned | 2 | The leg-for-leg analogue of the banked 1 MiB nibble ladder: same rungs, same budget, same fixture shape. What the chip asks for, read **with the confound named**. Builds the fixture. |
| **B** `fpke` | `-t4,6,8` | `0xFF0` (E-cores 4-11) | 1 | A **homogeneous** pool ladder: one core class, no SMT, no placement. The cleanest statement this part can make of "does fold parallelism give out as the pool grows". |
| **C** `fpkc` | `-t4,6,12` | unpinned | 1 | Added AFTER A and B answered the question and raised a new one: the two boxes differ in **two** ways at once. C forces the i5's own NIBBLE kernel (`NZBFAST_GF16_FORCE=avx2`) onto this GFNI part, holding kernel class fixed and leaving SMT as the only remaining difference. Its premise and its limits are in `fpkc-round.ps1`. |

Ladder A's **class-neutral** reading is the **fold-vs-force contrast within a
pool**: both arms run at every rung in the same sitting on the same cores, so
whatever core class an unpinned `-t12` lands on, *both arms land on it*. That
is the same instrument the i5's own refutation of the bandwidth hypothesis
used, and it transfers to a hybrid part unchanged.

Ladder B is not a luxury here. `crband-2026-09-18` measured on this very part
that the **unpinned full-box** crossover swings **30 rows** across four
sittings while the `-t4` arm replicates within 6 - so an unpinned wide arm on
this box is the least trustworthy thing it offers.

The driver **probes the core classes** (fixed work, timed, one core per mask)
before any ladder, and ladder B's premise - that cores 4-11 are one class - is
checked rather than trusted: a core-11 time that does not match core-4's is a
reason to **throw ladder B away** rather than to publish it.

## Shape

16 members x 512 MiB, slice 1,048,576, n=8,192, created `-c2048`. Rungs
**192, 512, 1024, 2048** (m=2048 is the last legal rung against `-c2048`, and
this is the banked round's own rung set, which is what makes ladder A a
leg-for-leg analogue). `-Budget 2048`, `NZBFAST_NTT_BUDGET` 12 GiB - both the
banked round's values, for the same reasons its driver gives.

## What this round does not license

- **One part, one sitting, one block size, one payload.** An agreement with
  the i5 would be two parts agreeing, not a law; a disagreement would *locate*
  the finding on the i5, not explain it.
- **CPU-seconds do not compare across masks.** Ladder B's E-core seconds must
  never be read against ladder A's mixed-placement seconds. What compares is
  the **shape** of `cpu`/`wall` against pool size *within* a ladder, and the
  fold/force ratio *within* a cell.
- **State the rung set beside every fitted figure.** `--rungs` is a free
  parameter; refitting the same legs on a different set moved `c_f` by 18% once.
- **Do not splice curves across block sizes.** A 1 MiB curve and a 64 KiB curve
  are two regimes, not one falling line.
- **Take the box from the LOG's own `host` field**, never from a lane's
  self-description or a commit subject.
- **No constant moves.** Not `NTT_WINDOW_COMBINE_X86`, not `NTT_MIN_MISSING*`.
  This produces evidence; `crates/` is untouched whatever it finds.

## Arm 1 of the chip, and why it is not here

Arm 1 - the m=3072 rung between the 64 KiB ladder's last holding point
(m=2048) and its collapsed one (m=4096), at `-t4`/`-t6`/`-t12` - is a
**intel-i5-10600kf** round, and intel-i5-10600kf was HELD throughout this sitting by
`parfast-nibble-third-window-shape-18sep` (lock taken 03:18Z, a live
multi-invocation round). Arm 2 needs no queue on the contended box and the
chip names it the more valuable of the two, so it is what ran. Arm 1 remains
open.

## Result

**The shape does not reproduce, and it is not the kernel class.** The full
write-up, with every table and the ranked candidates, is the 18 Sep 2026
section of an internal note beginning "The
fold's parallelism on a NON-nibble part". In one paragraph:

The fold's `cpu/wall` per thread at 1 MiB **holds** as the pool widens on this
part and **rises** with m at the widest pool - 0.908 to 0.957 unpinned `-t12`,
0.924 to 0.964 pinned to the eight E-cores, 0.945 to 0.972 with the nibble
kernel forced - where the same reducer over the banked i5 log reads 0.598 to
0.542 and falling. With core class cancelled by the fold-vs-force ratio at the
same rung it says the same: **1.09-1.18 here against 0.72-0.63 on the i5**. In
wall, which decides, the `-t6` to `-t12` step at m=2048 makes the fold **6.4%
slower** on the i5 and **24.2% faster** here. Ladder C's kernel force is real
rather than inert - the nibble kernel costs **1.67-1.72x** the CPU at every
pool - so kernel class is refuted and **SMT is what is left standing**, ranked
first rather than proved.

The claim that survives is narrower than the one tested and should replace it:
**on a part with SMT the fold cannot convert sibling threads into wall, and the
transform can** - on the i5 the same six siblings gained the transform 13.8% of
wall and cost the fold 6.4%.

One correction fell out of re-reading the banked log through this reducer: at
1 MiB the i5's `-t12` efficiency is roughly **flat in m**, so the collapse is in
the **pool** dimension and not the high-m dimension the finding has been carried
under. The 64 KiB m=4096 cliff is a separate claim this fixture (`-c2048`)
cannot reach.

**Quality of the sitting.** 144 legs, every one `rc=0` and `restored=16/16`; all
108 resident legs `windows=0`; ladder B's affinity read back `0xFF0` on all 36;
all 36 of ladder C carried `gf16force=avx2`; `lock_waits=0` throughout; foreign
CPU median 12.3% of one core against the banked i5 nibble round's 69-72%.

**No constant moved.** `crates/` is untouched.
