# `4m-t16` is not broken by its peak, and the 19,082 MB was never its peak (17 Sep 2026)

Lane `parfast-t16-peak-vs-budget-17sep`, closing item 3 of
an internal note.

**NO BOX TIME WAS TAKEN, and that is the result rather than a shortfall.** The
brief was to run a `-t16` ladder at a smaller `NZBFAST_NTT_BUDGET` against one at
20 GiB on intel-core-ultra-9-386h and see whether moving the peak moves the arm's
monotonicity. The premise does not survive contact with the logs the brief is
built on: the suspect is refuted three ways from already-banked data, and the
discriminator could not have separated it even if it had been real. The fleet's
only GFNI-256 part was HELD with a two-deep queue when this lane started, so
~90 minutes of it were not spent confirming arithmetic.

Everything below is reproduced by `t16-peak-audit.py` in this directory: no
arguments, no box, no network, ~15 s.

## 1. The 19,082 MB is the fixture CREATE's peak, not a measurement leg

The figure comes from this line in `poolladder4m-2026-09-17/logs/plt16.log`:

    CREATE rc=0 wall=19.79 cpu=280.875 peak_mb=19082.9

It appears in that one log and in no other arm's because **arm 1 of the pool
round is the arm that builds the 16 GiB fixture** - the driver runs `4m-t16`
first precisely so the create is unpinned, and the other four arms then ran
`-NoBuild` against what it made. They have **zero** CREATE lines.

So "19,082 MB against 16,429-16,490 MB on every other arm" compares a CREATE
peak against FORCE-LEG peaks. It is not a difference between the arms. `4m-t16`'s
own force legs peak at **16,510.5-16,521.9 MB**.

**And the same figure appears in a FOUR-THREAD round**, which settles it without
any argument about CREATE-versus-LEG semantics:

| log | ladder | CREATE peak |
|---|---|---:|
| `t4m4-2026-09-16/...-4m-n4096-t4-resident-ladder.log` | **t4** | 19,077.9 MB |
| `w4mib-2026-09-16/...-4m-n4096-resident-ladder.log` | t16 | 19,082.3 MB |
| `poolladder4m-2026-09-17/logs/plt16.log` | t16 | 19,082.9 MB |

`wcomb` builds the fixture unpinned whatever the ladder's thread count, so
**~19,080 MB is the CREATE's number on this fixture and belongs to no arm.** A
figure that shows up in a `-t4` round was never a property of sixteen threads.

## 2. The like-for-like peak ladder has no step at t16

Force-leg peaks across the pool round's five arms, which is the comparison the
sentence above meant to make:

| arm | threads | min peak MB | max peak MB | core mix |
|---|---:|---:|---:|---|
| `4m-e4` | 4 | 16,426.0 | 16,429.3 | `0xF0`, four E |
| `4m-p4` | 4 | 16,425.5 | 16,429.2 | `0xF`, four P |
| `4m-e8` | 8 | 16,453.7 | 16,460.1 | `0xFF0`, eight E |
| `4m-m12` | 12 | 16,482.4 | 16,490.9 | `0xFFF`, 4 P + 8 E |
| `4m-t16` | 16 | 16,510.5 | 16,521.9 | unpinned, all 16 |

**+7.0 MB per thread, dead linear, and t16 sits on the line** - 84.5 MB and
0.51% above the four-thread arms over twelve extra threads. That is per-thread
scratch. There is no anomaly at sixteen threads to explain.

## 3. The peak is IDENTICAL in the three sittings where the arm failed

Four sittings exist of this exact shape - unpinned, 4 MiB, n = 4,096, resident,
sixteen threads, 20 GiB budget - checked same-shape on `affinity`, `slice`, `n`
and `residency` before comparing:

| sitting | monotone | min peak MB | max peak MB | worst A/A |
|---|---|---:|---:|---:|
| `pinaff4m-2026-09-16/logs/attempt1/pint16.log` | **NO** | 16,510.6 | 16,522.0 | 24.1% |
| `pinaff4m-2026-09-16/logs/attempt2/pint16.log` | **NO** | 16,510.7 | 16,521.9 | 17.4% |
| `pinaff4m-2026-09-16/logs/attempt3/pint16.log` | **NO** | 16,510.8 | 16,521.6 | 21.2% |
| `poolladder4m-2026-09-17/logs/plt16.log` | yes | 16,510.5 | 16,521.9 | 12.8% |

The whole spread across four sittings is **11.5 MB**, and the three failures and
the one success are interleaved inside it. **A quantity that is the same when the
effect is present and when it is absent is not the cause** - which is the
reasoning the landed round used to kill the no-spare-core hypothesis, applied to
the suspect that was supposed to replace it.

The monotonicity verdicts agree with the independent
`pinaff4m-2026-09-16/ladder-monotonicity-audit.py`, run over the same four logs.

## 4. The briefed discriminator could not have separated it anyway

This holds independently of 1-3, so it would have stood even if the peak had been
real. Retention cuts a window at `retained_bytes > budget`
(`crates/nzbkit-base/src/par2repair/reconstruct.rs`, the
`if let Some(budget) = ntt_budget` block), and `retained_bytes` stops when the
corpus is exhausted. The corpus is `n_present * block_size`:

| m | n_present | corpus | resident @ 20 GiB | resident @ 12 GiB |
|---:|---:|---:|---|---|
| 320 | 3,776 | 14.75 GiB | yes | **NO** |
| 352 | 3,744 | 14.62 GiB | yes | **NO** |
| 384 | 3,712 | 14.50 GiB | yes | **NO** |
| 416 | 3,680 | 14.38 GiB | yes | **NO** |
| 448 | 3,648 | 14.25 GiB | yes | **NO** |

The 20 GiB budget clears the widest corpus by 5.25 GiB, **so it never binds**.
Any budget above the corpus leaves retention - and therefore the peak - exactly
where it is; any budget below it cuts a window, which `-Residency resident`
refuses by design (`wcomb.ps1`: "the forced arm WINDOWED, so this ladder is
measuring `ntt_window_row_gate` and not the resident gate").

**So the knob moves the peak ONLY by changing which side of the gate the leg is
on. Peak and residency are not separable by it, and there is no budget value that
moves the peak and keeps the leg resident.** The brief's suggested 12 GiB is
below the corpus at every rung, so it refuses at every rung - arithmetic, not a
prediction. The brief anticipated a possible refusal and said to report it rather
than work around it; the refusal is total and is reported here without spending
the box to watch it happen.

The banked windowed ladders corroborate the mechanism from the other side:
`w4mib-2026-09-16`'s `m4096` and `m8192` arms peak at 5.4 GB and 9.8 GB with
`windows=2/3` and `windows=1`, `residency=windowed`. A smaller budget does move
the peak - by windowing.

## 5. Foreign CPU does not explain the failures either

Cheap, and worth banking because it is the obvious next suspect:

| sitting | rung | A/A floor | foreign max |
|---|---:|---:|---:|
| attempt1 | 416 | 24.1% | 40% |
| attempt3 | 416 | 21.2% | **12%** |
| attempt2 | 320 | 17.4% | 20% |
| attempt3 | 352 | 14.8% | **9%** |
| poolladder | 448 | **3.1%** | **116%** |

The worst floors sit at the lowest foreign readings, and the highest foreign
reading in the whole corpus produced a clean rung. The two are not tracking each
other, so "a neighbour's load broke it" is not supported by the logs that exist.

## What is left, as a lead and not a finding

**The perturbation is in the FORCE arm only, and it is rung-localised.** Across
all four sittings the fold column is monotone and reproducible at every rung
(m = 384 spans 305.6-311.8 CPU-s over four sittings, m = 448 spans 348.3-355.3);
every one of the 10-24% A/A floors above belongs to the force arm, and they
cluster at m = 320/352/416 while m = 384 is firm in all four. Since F/T is
fold/force, a non-monotone ladder at these rungs is a force-arm perturbation
rather than a property of the gate.

That narrows the hunt from "the arm" to "the forced NTT leg at particular row
counts", but it names no mechanism and this lane did not measure one. It is
written down so the next lane starts from it rather than from the peak.

## Stated limits

- **Nothing here was measured by this lane.** Every number is re-read from logs
  banked by the four sittings named above, plus two arithmetic derivations from
  the shipped source. The value of the result is exactly the value of those logs.
- **Arm 4 is a reading of the code as it stands at this commit.** If retention or
  the residency assertion changes, re-derive rather than quoting the table.
- **Three failing sittings and one passing one is a small sample**, and this lane
  did not add to it. What is refuted is the peak as the discriminating quantity,
  not the existence of the failure - which remains real, reproducible three times
  in four, and unexplained.
- **The lead in the section above is an observation over four sittings with no
  replicate of its own**, and the rung clustering could be chance at this sample
  size. It is not a finding and must not be cited as one.
