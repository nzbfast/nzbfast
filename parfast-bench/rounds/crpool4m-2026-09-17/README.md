# The CREATE's pool ladder at 4 MiB on GFNI-256, WITH PLACEMENT CONTROLLED

<!-- claim:wcomb-run-create-affinity-assert-18sep -->
> **CLAIMED 2026-09-18T01:26:49Z** by `<user>` on `apple-m3-ultra-512gb`, claim id `wcomb-run-create-affinity-assert-18sep`, gen `62841d4e`, lease to **2026-09-18T13:26:49Z**.
> Nobody else should start this. Ledger: an internal note (`tools/claims.py list --open`).
> **Past that lease with nothing closing it, READ origin/main FIRST** - an abandoned-looking claim is far more often work that
> landed than work that is free (bench-suite item 0a1, TODO 229). Then post a RELEASE saying why, and claim it again.
<!-- /claim:wcomb-run-create-affinity-assert-18sep -->

Lane `parfast-create-pool-ladder-4mib-17sep`, item 4 of
an internal note.

**Status: RAN AND COMPLETE.** One sitting on intel-core-ultra-9-386h, 22:20:10Z-00:39:38Z
on 17-18 Sep 2026, five ladders, 160 legs, every leg `rc=0`. Everything above
the Result section was written and landed on origin BEFORE the sitting - the
premise, the arm table, the guard on what the round does not license, and the
rung widening - so none of it was fitted to the numbers. The Result section says
what actually happened.

## The question, in one grep

```
grep -c affinity rounds/crg4-2026-09-16/*.log   ->   0
```

The landed create round ran `-Phase create` at threads 4 and 16 with **no
`-Affinity` on any leg**. Its headline pool comparison - resident CPU crossover
**381 at `-t4` against 365 at `-t16`** - is therefore a **16-row gap measured
across two UNPINNED pools**.

The 17 Sep pinned repair sitting
(`rounds/pinaff4m-2026-09-16/`, written up in
an internal note) measured **placement ALONE
swinging the crossover 42-52 rows at FIXED pool size** on this same part. So
the create's 16 rows sit inside the confound by a factor of three, and cannot
currently be attributed to pool size at all.

That is the identical arithmetic that voided the repair's "one second rung
serves both pools" clause - a 14-row gap against a 42-52 row confound. It has
never been applied to the create half.

**Why it is not a tidy-up.** The section "The CREATE at 4 MiB: it crosses BELOW
the repair, and 416 is the wrong rung for it" recommends "**384 is the only
candidate that serves both paths**" against a repair that wants 416. That
arithmetic rests on where the create crosses **on each pool**. If the create's
pool ORDERING (`-t4` above `-t16`) is a placement artefact, the case for 384
needs re-reading. **This lane is not chartered to move a constant**: it
measures, and says what the measurement does and does not license.

## The SECOND question, which is sharper than the pool one and comes free

Reading the create section's argument closely changes what this round is worth.
"384 is the only candidate that serves both paths" does **not** rest mainly on
the 16-row `-t4`/`-t16` ordering. It rests on a DIRECTION: at 4 MiB the create
crosses **below** the repair on both pools - resident ~381 (`-t4`) and ~365
(`-t16`) against the repair's landed **391** and **405** - so the create wants
the gate lower exactly where the repair wants it higher, and 416 would cost the
create up to 6.5% over 35 rows on four threads and 13.8% over 51 rows on
sixteen.

**Every one of those four numbers was taken unpinned.** So the direction itself
- the whole load-bearing claim - has never been checked at controlled
placement either, and the 42-52 row placement swing is larger than the 10-40
row create-under-repair margins it is claimed from.

This round gets that check for nothing, because its arms are the repair pool
ladder's arms. `rounds/poolladder4m-2026-09-17/` read the REPAIR
crossover at five masks: `e4` 344, `e8` 378, `p4` 381, `t16` 398, `m12` 405.
This round reads the CREATE crossover at **those same five masks on the same
part with the same binary**. Subtracting mask for mask gives the create-under-
repair margin at matched placement - a comparison that has never existed on any
block size - and it is the quantity the 384 recommendation actually needs.

- If the create sits below the repair at **every** mask, the direction is
  confirmed far more strongly than the unpinned pair confirmed it, and 384's
  case is stronger than the evidence that was available when it was written.
- If any matched pair **inverts**, the direction is placement-dependent and the
  arithmetic behind 384 needs re-reading, which is what item 4 was written to
  find out.

Either way this lane moves no constant. It reports the margins and says what
they license.

## The cell

- **Box** intel-core-ultra-9-386h (Core Ultra 9 386H, GFNI-256, 4 P cores 0-3, 8 E cores
  4-11, 4 LP-E cores 12-15, 31.4 GB, Windows 11), the fleet's **only GFNI-256
  part**, so no other box substitutes.
- **Binary** parfast from `06d5734b7` - the commit both landed 4 MiB repair
  rounds, the landed create round and both pinned sittings used. Gated on its
  **4,173,312-byte COUNT and never on a sha256**: the build embeds its own
  path, so the hash differs per root by construction and gating on it cost the
  previous lane a launch.
- **Harness** origin/main's `wcomb.ps1` (`70fe0efe...`, **byte-identical to the
  copy the 17 Sep pool ladder ran**) and `plib.ps1` (`1a714068...`, which HAS
  moved since that round - three commits, all lock/orphan/closing-vocabulary
  and `Get-OwnPidTree` walking ancestors as well as descendants, so the change
  is in foreign-CPU accounting and the rig lock, not in the leg).
- **Fixture** 16 x 1,024 MiB at 4 MiB blocks, `-c640`: n = 4,096, a 16 GiB
  corpus - the same shape all four banked 4 MiB rounds used. n = 4,096 clears
  the x86 input floor of 2,048 on its own.
- **Arms** mirror `poolladder-round.ps1`'s table, because the comparison only
  means something against arms placed the same way:

  | arm | mask | cores | threads | what |
  |---|---|---|---|---|
  | `4mc-t16` | none | all 16 | 16 | UNPINNED, MIXED. **Must run first**: `-Affinity` arms every leg INCLUDING the fixture create. Ties to crg4's unpinned `-t16` create = 365. |
  | `4mc-e4` | `0xF0` | 4-7 | 4 | four E, ONE class - the pool-4 anchor, half of both comparisons |
  | `4mc-e8` | `0xFF0` | 4-11 | 8 | eight E, SAME class - **with `4mc-e4`, the within-class POOL STEP** |
  | `4mc-p4` | `0xF` | 0-3 | 4 | four P, one class - **with `4mc-e4`, the same-pool CLASS PAIR** |
  | `4mc-m12` | `0xFFF` | 0-11 | 12 | 4 P + 8 E, MIXED and stated as mixed - a placement data point, never a rung of the within-class ladder |

  **Arm order differs from the repair round in one place, deliberately**: that
  round ran `m12` fourth and `p4` fifth, this one swaps them. A sitting cut
  short after four arms has then discharged the brief in full (arms 2+3 are the
  pool step, arms 2+4 are the class pair) and loses only the mixed control -
  which existed on the repair path to test the no-spare-core hypothesis, and
  **that hypothesis is already dead**.

- **Rungs** 288,320,352,384,416,448,480,512 - wider at the TOP than the repair
  round's 320..448 set and one lower at the bottom, for the reason the
  wall-time section below gives (256 was dropped to pay for 480 and 512). The create crosses below the repair on this part
  (365/381 against an unpinned repair 398), so applying that ~33-row offset to
  the five pinned repair crossings (344/378/381/398/405) puts the expected
  create crossings near 311/345/348/365/372: `4mc-e4` is the arm at risk of
  crossing under a 320 floor, and **an arm with no crossing in range answers
  nothing**. The two extra rungs are cheap here in a way they would not be on
  the repair path - a create leg at this shape walls 25-43 s unpinned against a
  repair leg's 65-88 s.
- **No rung can fall through to the fold.** The forced arm sets
  `NZBFAST_CREATE_NTT_MIN_ROWS=0`, so `rows_and_present_admitted`'s floor
  clause reads `count >= 0 && n_slices >= create_ntt_min_present()`, and
  n = 4,096 clears the x86 floor of 2,048 - admission holds at every rung
  including 256. `wcomb`'s own path assert (`plan prep ... cold build(s)`)
  refuses any leg that took the other path anyway.
- **Arms** `fold force force2 fold2` at every rung, one rep, `-Residency
  resident`, `-NttBudget` 20 GiB, so every cell carries its own A/A pair.

## Two traps that decide whether the result is publishable

- **CPU-seconds do not compare across masks.** The class probe reads P/E at
  **1.74x** on this part. An 8 E-core arm burning more CPU than a 4 P-core arm
  is not doing more work. Only the **crossover** compares across arms, because
  it is a ratio of fold to force WITHIN one arm on one core mix.
- **A tight A/A floor is agreement, not correctness.** The floor is a MAX over
  reps and is blind to a perturbation hitting both copies of a rung; one rung
  of the pinned round reported a 0.5% floor while visibly broken. Every ladder
  here is screened with
  `rounds/pinaff4m-2026-09-16/ladder-monotonicity-audit.py` for
  monotonicity as well as floor, and the rungs **bracketing** each crossing are
  checked for firmness.
- **One sitting is not a replicate.** The repair round needed two independent
  whole sittings before it trusted a figure, and more reps cannot firm a rung
  (the floor is a max over reps). A single sitting is reported as one sitting.

## A pre-round screen of the round this one continues, and what it does NOT say

`ladder-monotonicity-audit.py` over `crg4-2026-09-16`'s ladder log, run before
taking any box time:

```
 thr label                 mono   worst floor
   4 res4m                 NO            9.6%
full-box (threads>=16) ladders:   1   non-monotone:   0  (0%)
sub-box  (threads< 16) ladders:   1   non-monotone:   1  (100%)
```

So the landed create's **`-t4` ladder is non-monotone** and its `-t16` ladder is
clean. **This does not condemn the 381**, and saying it did would be the exact
misreading the audit's own header warns against - it is a SCREEN and a
non-monotone table with a high floor is the instrument declaring its noise.
Read where the failure is:

- The dip is **480 -> 512** (F/T 1.178 -> 1.170, 0.7%), against A/A floors of
  0.9% and 0.3% at those two rungs. The dip is INSIDE the pair's own noise.
- It sits **far above the crossing**, which is bracketed by 352 (F/T 0.923,
  floor 1.8%) and 384 (1.008, floor 0.3%) - and **both bracketing rungs are
  firm**, which is the condition the pinned round's trap note names.
- The 9.6% worst floor is the **320** rung, also below the crossing and not one
  of its brackets.

So `-t4`'s 381 survives the screen on the stated test, and this round inherits
it as a usable prior rather than as a suspect number. Recorded here because a
screen that was run and passed is worth as much as one that found something,
and because the next lane should not have to re-run it to find that out.

## What this round does NOT license, committed to IN ADVANCE

Written before the sitting, so it cannot be trimmed to fit whatever the
numbers turn out to say.

**Nobody has ruled on 384, or on 416, or on giving the create its own clause.**
The create section's own "Owed after this lane" puts that decision to the maintainer by
name - "384 (serving both paths at a 4.4% worst cell) or 416 (the repair's own
optimum, at 13.8% to the create), or whether `create_ntt_min_rows` stops
borrowing `ntt_min_missing` and takes its own clause at ~372. the maintainer's call; three
lanes have now measured the inputs and none has moved the constant." That is
still true and this lane is the fourth. **No sentence in this round's write-up
may be read as a decision having been taken**, by the maintainer or by anyone, and
anything downstream that cites this round as "384 ships" is citing it wrongly.

**This round moves no constant and recommends no rung.** It measures where the
create crosses at five controlled placements and reports the margins.

Three specific misreadings to refuse in advance:

- **A confounded input is not a wrong answer.** Showing that the 381/365 pair
  is inside the placement confound does NOT show 384 is wrong, or that 416 is
  right. It shows the evidence under whichever rung is chosen is weaker than it
  reads. Those are different claims and only the second is this round's.
- **The `~372` create-only candidate is a midpoint of the same two unpinned
  numbers.** If the pool ordering is a placement artefact then ~372 inherits
  the confound exactly as 384 does, so this round cannot be cited FOR the
  own-clause alternative either. It cuts both ways or it cuts neither.
- **Five arms on one part in one sitting is not a general result.** The 42-52
  row placement swing is a Core Ultra 9 386H figure. Nothing here says how much
  placement matters on a part whose core classes are not 4 P / 8 E / 4 LP-E,
  and no other box on this fleet is GFNI-256 to check it against.

The previous lane recorded a commitment of this shape and it cut against that
lane's own result; this one is recorded in the same spirit.

## WALL BEATS CPU, and on this shape they disagree by 28-43 rows

**the maintainer's standing rule, 17 Sep 2026** (memory topic
`nzbfast-wall-time-is-the-deciding-metric`): *"people care about wall times much
more than cpu times... so that should be our deciding factor whenever we get a
choice in the matter. always improve wall times."*

That lands on this campaign hard, because **every figure the 4 MiB rung
recommendation was built from is a CPU crossover**, and on this part the wall
crossover is systematically higher. Reduced from the banked logs, no box time:

| path | pool | CPU | **wall** | wall-CPU | log |
|---|---|---:|---:|---:|---|
| repair | `-t4` | 391 | **427** | +36 | `t4m4-2026-09-16` |
| repair | `-t16` | 405 | **>448** | >+43 | `w4mib-2026-09-16` |
| create | `-t4` | 381 | **422** | +41 | `crg4-2026-09-16` |
| create | `-t16` | 365 | **393** | +28 | `crg4-2026-09-16` |

**What SURVIVES the switch to wall.** The direction does. The create still
crosses below the repair on both pools - by 5 rows at `-t4` (427 against 422)
and by more than 55 at `-t16` (>448 against 393), against the CPU margins of 10
and 40. So the load-bearing claim of the create section is **not** inverted by
the rule, and nobody should read this table as overturning it.

**What does NOT survive is the LEVEL, and the level is what a rung is.** All
three candidates - 384, 416 and the create-only ~372 - are CPU-derived, and all
three sit **below both of the create's wall crossings (422 and 393)**. In wall
terms a gate at 384 admits the transform across `[384, 422]` on the four-thread
pool where the fold is still the cheaper wall, so 384 is not the conservative
choice there that its CPU arithmetic makes it: **on wall at `-t4`, 416 sits
closer to the crossing than 384 does**, which is the opposite of the CPU-based
"416 would cost the create 13.8%". That 13.8% is a CPU cost.

**This does not pick a rung and must not be read as doing so.** It says the
inputs to that choice were measured in the metric that the maintainer has now said loses a
disagreement, and that re-pricing them in wall moves them 28-43 rows. The
decision stays exactly where "Owed after this lane" put it.

**Weight the two wall figures differently, because the boxes were not alike.**
The hygiene rule is measure CPU to learn the mechanism, confirm the decision
with wall on a QUIET box. The repair `-t16` ladder's foreign CPU ran at a
**median of 52% of a core and a max of 109%**; the create ladder's ran at
**11-12%**. Wall is far more load-sensitive than CPU, so the `>448` repair bound
is the weakest number in the table and the create's two are the strongest. Said
here so the table is not quoted flat.

### What it changed about this round, before it ran

The rung set. A crossover round has to **bracket the crossing it means to
report**, and under this rule that is the WALL crossing. Two of the pinned
repair pool ladder's five arms (`4m-t16`, `4m-m12`) read `wall m ~ >448` and
never crossed inside 320..448 at all - they answered the CPU question and
returned a non-answer on the deciding one. A create ladder pinned to four
E-cores over the same rungs would have risked exactly that.

So the rungs moved from 256..448 to **288..512**: 480 and 512 guard the wall
crossing, and 256 was dropped to pay for them (it guarded a CPU crossing that
288 also brackets). Eight create rungs cost about what five repair rungs do,
because a create leg at this shape walls 25-43 s against a repair leg's 65-88 s.

**Every table in the Result section will quote both crossovers and name the
divergence.** `rowgate.py read` prints both already, so this is discipline
rather than tooling.

## The PROPORTIONALITY LIMIT, and the third quantity this round must report

**the maintainer ruled on the wall rule, 17 Sep 2026, and it carries a limit** - wall wins
a disagreement *"unless there's something excessive and it's an extremely
unfair trade, like, 10x the cpu for a little bit better wall"*. **He is
deliberately NOT ruling on the 4 MiB rung today**, and the reason is this
round's own finding: all three candidates are CPU-derived and all three sit
below both of the create's wall crossings.

That limit is not a footnote here - it lands squarely on this shape, because
**the band between the CPU crossover and the wall crossover IS the region where
the two metrics disagree**, and therefore the only region where the limit can
ever bite. Inside it the transform is cheaper in CPU while the fold is faster
in wall, so choosing by wall means choosing the fold and paying CPU for it. The
limit asks: *how much CPU, for how much wall?*

Computed straight from the banked create ladder - fold against transform, only
the rungs where the two metrics actually disagree:

| arm | m | CPU F/T | wall F/T | fold CPU cost | fold wall gain | **ratio** |
|---|---:|---:|---:|---:|---:|---:|
| create `-t4` | 384 | 1.007 | 0.914 | +0.7% | +8.6% | **0.1x** |
| create `-t4` | 416 | 1.067 | 0.988 | +6.7% | +1.2% | **5.7x** |
| create `-t16` | 384 | 1.046 | 0.975 | +4.6% | +2.5% | **1.9x** |

**The trade is not constant across the band - it degrades steeply.** At 384 on
four threads the fold buys 8.6% better wall for 0.7% more CPU, which is an
excellent trade by any reading. At 416 the same choice buys 1.2% better wall
for 6.7% more CPU - **5.7x**, over half way to the 10x the maintainer named as excessive,
and the trend is steep enough that a rung further up could cross it.

**So the wall rule and its limit can point opposite ways within one band, and
which one governs depends on the rung.** That is a fact about this shape, not a
tension in the rule: near the CPU crossover wall is nearly free, and near the
wall crossover it is dear. None of the banked rungs reaches 10x, so nothing
here is excluded by the limit today - but nothing here had the pinned arms
either, and an E-core-pinned arm is exactly where a wide CPU/wall divergence
would show up hardest.

### What this round will therefore report, per arm

Three quantities, not one, and the third is new to this campaign:

1. the **CPU crossover** - the mechanism, robust to a loaded box;
2. the **wall crossover** - the decision, per the standing rule, with the box's
   foreign-CPU figure quoted beside it so its weight is visible;
3. **the trade ratio at every rung inside the band between them** - fold CPU
   cost over fold wall gain, in the table above's form, so the proportionality
   limit can be applied by eye rather than re-derived.

A round that reported only (2) would satisfy the rule and hide the limit. A
round that reported only (1) would not move a constant at all. Reporting the
band is what makes the pair of rulings usable together.

## Files

| file | what |
|---|---|
| `logs/crt16.log` | `4mc-t16` - unpinned, 16 threads, all cores. Built the fixture. 32 legs |
| `logs/cre4.log` | `4mc-e4` - mask `0xF0`, cores 4-7, four E, `-t4`. 32 legs |
| `logs/cre8.log` | `4mc-e8` - mask `0xFF0`, cores 4-11, eight E, `-t8`. 32 legs |
| `logs/crp4.log` | `4mc-p4` - mask `0xF`, cores 0-3, four P, `-t4`. 32 legs |
| `logs/crm12.log` | `4mc-m12` - mask `0xFFF`, cores 0-11, 4 P + 8 E, `-t12`. 32 legs |
| `crpool-driver.log` | the round driver: load gates, class probe, extract, build, byte gate, per-arm ARGV and ARM-DONE |
| `crpool-round.ps1` | the driver itself |

**160 legs, all `rc=0`, all `match=1` on the cross-arm SHA-256, all
`residency=resident`, all path-asserted, `lock_waits=0` on every arm.** Nothing
excluded, nothing re-measured, no contaminated sitting. One sitting,
22:20:10Z-00:39:38Z.

**Provenance.** Binary built on the box from `06d5734b7`, gated at **4,173,312
bytes** (sha `CEDEFE20...`, which matches no other round by design - the build
embeds its own path). Harness `wcomb.ps1` `70fe0efe...` and `plib.ps1`
`1a714068...`, stamped on every LEG line. Note that `harness/wcomb.ps1`
on main has since moved to `5b4719ec...`; **this round ran `70fe0efe`**, so
diff against that blob and not against today's file.


## Result

**All five arms crossed IN RANGE in BOTH metrics** - no `>512` lower bounds
anywhere. The rung widening was load-bearing: two of the pinned *repair*
ladder's five arms returned `wall m ~ >448` on the deciding metric, and this
round would have done the same at 320..448.

| arm | mask | cores | thr | **CPU** | **wall** | wall-CPU |
|---|---|---|---:|---:|---:|---:|
| `4mc-e4` | `0xF0` | 4 E | 4 | **367** | **373** | +6 |
| `4mc-t16` | none | all 16 | 16 | **387** | **411** | +24 |
| `4mc-m12` | `0xFFF` | 4P+8E | 12 | **389** | **408** | +19 |
| `4mc-e8` | `0xFF0` | 8 E | 8 | **393** | **409** | +16 |
| `4mc-p4` | `0xF` | 4 P | 4 | **394** | **410** | +16 |

### 1. Item 4's answer, and it is stronger than "confounded": the sign is wrong

The landed unpinned create comparison read `-t4` **381** against `-t16` **365**
and concluded the SMALLER pool crosses HIGHER by 16 rows.

With the core class held **fixed at E** and only the pool moved, this round
reads **367 at pool 4 against 393 at pool 8**: the **BIGGER pool crosses
HIGHER, by 26 rows**. The controlled pool term has the **opposite sign** to the
unpinned reading.

And placement alone at **fixed pool size four** moves the crossover **27 rows**
(`4mc-e4` 367 against `4mc-p4` 394) - larger than the 16-row gap the landed
comparison rests on, and the unpinned `-t4` reading of 381 sits *inside* that
[367, 394] span.

**So the 16 rows are not a pool effect at all.** They are smaller than the
placement spread at fixed pool size, and the real pool term points the other
way.

### 2. Both terms are real, and about equal on this path

- **pool**, within the E class, 4 -> 8 threads: **+26** CPU (367 -> 393), **+36**
  wall (373 -> 409)
- **class**, at fixed pool four, E -> P: **+27** CPU (367 -> 394), **+37** wall
  (373 -> 410)

The repair path's own figures are +28..+34 (pool) and +37 (class), so the
create's terms are slightly smaller and the same order. Neither term dominates
here, which is itself worth knowing: on the repair path the pool step was the
larger of the two.

### 3. Wall does not invert the ranking, but the gap grows with the pool

Same ordering in wall as in CPU. The wall crossover sits above the CPU one at
every arm, and the gap grows monotonically with pool size: **+6** (pool 4, E),
**+16** (pool 4, P and pool 8), **+19** (pool 12), **+24** (pool 16).

### 4. The mechanism is CONFIRMED on the create path - and is ~2.5x weaker

`parfast-4mib-pool8-class-isolation-17sep` proposed, off the repair path hours
earlier, that **the fold parallelises better than the forced transform**, so a
wider pool penalises force more in elapsed time than in CPU. That predicts the
wall-minus-CPU gap should order like fold-over-force parallel efficiency. At
m = 448, threads actually used (`cpu/wall`):

| arm | thr | fold | force | **ratio** |
|---|---:|---:|---:|---:|
| `4mc-e4` | 4 | 3.98 | 3.89 | **1.022** |
| `4mc-p4` | 4 | 3.96 | 3.85 | **1.030** |
| `4mc-e8` | 8 | 7.85 | 7.54 | **1.041** |
| `4mc-m12` | 12 | 11.65 | 10.98 | **1.061** |
| `4mc-t16` | 16 | 15.55 | 14.33 | **1.085** |

**Same ordering as the wall-minus-CPU gap, on a different path, from an
independent sitting.** The prediction holds.

**But it is about 2.5x weaker here.** The repair spread is 1.027 -> 1.235; this
create spread is 1.022 -> 1.085. That is why the repair's wall gaps reach +59
and unbounded where these stop at +24. So the mechanism generalises across
paths and its MAGNITUDE does not.

### 5. The proportionality band exists but is UNSAMPLED, and that is informative

**No rung in this round has the transform cheaper in CPU AND the fold faster in
wall.** The disagreement bands are 6-24 rows wide and the rung grid is 32 rows,
so every band falls *between* measured rungs. At every rung actually measured,
CPU and wall agree on the verdict.

So **the proportionality limit has nothing to bite on here** - which contrasts
sharply with the banked unpinned `-t4`, whose +41-row band did contain rungs 384
and 416 and produced the 0.1x / 5.7x degradation. Under controlled placement the
band is narrower than that unpinned reading suggested, so part of the +41 was
placement, not mechanism.

**Owed**: a fine ladder at ~8-row spacing across one arm's band would price the
trade properly. This round cannot, and does not pretend to.

### 6. The full-box pathology is REPAIR-specific

`4mc-t16`, the create's full-box arm, is **monotone**. The repair's `4m-t16` has
now been non-monotone in **four of five** sittings at this shape. So that
failure is not a property of sixteen threads on this part - it does not follow
the core count across paths.

Screening: four of five arms monotone. `4mc-p4` is not (worst floor 1.2%), and
its dip is 480 -> 512, **above** its crossing, with both bracketing rungs firm
at 0.3% and 0.4% - so its 394 stands on the stated test. The softest reading
here is `4mc-t16`'s own, bracketed at 3.2% and 3.4%; the other four bracket at
0.3-1.7%.

### 7. One discrepancy I cannot resolve and am not hiding

My unpinned `-t16` reads **387** CPU where `crg4`'s read **365** - a **22-row
swing on the same configuration, same binary, same fixture shape**. Candidates:
a different rung grid (288..512 against 320..544, and the crossover is
log-interpolated), a solo ladder against `crg4`'s two-pools-interleaved-in-one,
and a different fixture instance. Not resolvable from one sitting.

It bounds what an UNPINNED reading is worth, and it is larger than the entire
16-row gap item 4 was written about.

### What this licenses, and what it does not

**It does not pick a rung.** Per the guard committed before the sitting.

What it does establish, for the decision that is waiting on it:

- The create's controlled crossings span **367-394 in CPU** and **373-411 in
  wall**.
- **The wall spread across placements is 38 rows. The distance between the two
  candidate rungs, 384 and 416, is 32 rows.** So the choice being deliberated is
  *smaller than the placement spread of the quantity it is trying to track*.
- 384 sits above `4mc-e4`'s wall crossing (373) and below the other four
  (408-411). 416 sits above all five. Neither is uniformly conservative for the
  create, and which one errs depends on the core mix the user happens to get.
- A single shared constant cannot track a quantity that moves 38 rows with
  placement alone. That is an argument about *what a row gate can express*, not
  an argument for any of the three candidates - and note it applies to the
  create-only ~372 exactly as it applies to 384 and 416.

### Stated limits

- **ONE SITTING.** The repair round needed two independent whole sittings before
  it trusted a figure, and more reps cannot firm a rung (the A/A floor is a max
  over reps). These are one sitting's numbers.
- **ONE PART, ONE PAYLOAD, ONE BLOCK SIZE.** Core Ultra 9 386H, random bytes,
  4 MiB. No other box on this fleet is GFNI-256.
- **THE CREATE PATH HAS NO AFFINITY ASSERT** - see the section below. The pins
  are evidenced, not asserted.
- **The proportionality trade is unpriced here**, per section 5.

## The instrument gap this round found: the create path does not verify its pins

**`wcomb.ps1`'s affinity readback assert and the `affinity=` / `affinity_got=`
LEG fields exist only in `Run-Cell`** (the repair phases) - the assert is at
line 724 of `wcomb.ps1` `70fe0efe`, and `Run-Create` begins at line 743 and has
neither. The docstring's promise that "THE MASK IS READ BACK and refused on
mismatch... A pin that silently failed would publish an unpinned leg under a
pinned arm's name" **is true of the repair phases only**.

The mask *is* applied: `-Affinity` is global via `Set-LegAffinity`, `plib`'s
`Invoke-Leg` pins every child including a create leg, and the per-arm
`AFFINITY mask=... cores=N of 16` header is on every log. `plib` even records
the readback as `affGot`. But on the create path **nothing reads it, nothing
refuses on it, and nothing prints it**, so a failed pin is invisible in the log.

Not closable from the log, so it is **bounded from the measurements** instead,
and they are unambiguous. Force-arm wall at m = 448:

| arm | mask | cores | force wall |
|---|---|---|---:|
| `4mc-e4` | `0xF0` | 4 E | 67.94 s |
| `4mc-p4` | `0xF` | 4 P | 42.49 s |
| `4mc-e8` | `0xFF0` | 8 E | 38.83 s |
| `4mc-m12` | `0xFFF` | 4P+8E | 25.63 s |
| `4mc-t16` | none | all 16 | 22.44 s |

- **E/P at pool four = 1.599x**, against the class probe's 1.72x single-thread
  P/E. Right magnitude, right direction.
- **4E -> 8E = 1.750x** speedup against an ideal 2.00x. Right magnitude.
- Four masks, four distinct and correctly-ordered speeds. **Failed pins would
  have made these arms identical.**

That is strong evidence, and it is not the assert. **The fix belongs in
`Run-Create`**, not in the next round's reasoning: give the create phase the
same readback refusal and the same two LEG fields the repair phase has. Until
then every pinned create round on any box repeats this argument.

