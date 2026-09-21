# The CREATE's PROPORTIONALITY BAND at 8-row resolution, and whether an INTERLEAVED ladder moves the crossover

Lane `parfast-create-band-and-interleave-18sep`, items **1 and 2** of
an internal note.

**Status: RAN AND COMPLETE.** One sitting on intel-core-ultra-9-386h,
01:44:51Z-03:04:40Z on 18 Sep 2026, three ladders, 104 legs, every leg `rc=0`.
Everything above the Result section was written and landed on origin
(`df015f244`) BEFORE the sitting - the two questions, the ladder table, the
ordering argument with its stated price, the guard on what the round does not
license, and one candidate refuted by reading - so none of it was fitted to the
numbers. The Result section says what actually happened.

**In one paragraph.** Interleaving is REFUTED as the cause of the 22-row
unpinned `-t16` swing: solo and interleaved landed 2 rows apart in CPU and 5 in
wall against one fixture in one sitting. It is the sitting - the four unpinned
`-t16` readings on this part span 30 rows, and three of the four are bracketed
on the low side by a rung inside its own A/A floor, so **that crossover is not
a measurable quantity at this resolution**. The unpinned `-t4` arm is the
exception and replicates within 6 rows across two sittings, so the instability
belongs to the FULL-BOX pool. The fine band ladder MISSED its band for exactly
that reason - a band 6-35 rows wide cannot be aimed at when its location moves
30 - which makes "price the band" a task that needs a PINNED arm first. Two
rungs were priced anyway, at 3.2x and 1.8x, and re-pricing the banked ladder
with a wall A/A floor shows the **5.7x currently quoted in the standing
wall-time rule is unresolved**, its wall gain of +1.17% sitting inside a 1.36%
floor. No constant moved.

## Why these two items are one chip and one sitting

They are different cells but they share a fixture, and a fixture on this box
costs a ~2 min build, a 16 GiB create and a 456-745 s settle. The box is the
scarce thing: intel-core-ultra-9-386h is the fleet's **only GFNI-256 part**, so no other
box substitutes, and two lanes were queued behind this one.

It also makes item 2 **stronger**. Its question is whether INTERLEAVING moves
the crossover, and running both ladders against one fixture instance holds the
fixture fixed - which is exactly the control that isolates interleaving from
the "different fixture instance" candidate the round before could not separate.

## Item 1 - the proportionality band, unpriced

the maintainer's wall-time rule (memory topic `nzbfast-wall-time-is-the-deciding-metric`)
carries a limit: wall wins a disagreement *"unless there's something excessive
and it's an extremely unfair trade, like, 10x the cpu for a little bit better
wall"*. **The band between the CPU crossover and the wall crossover is the only
region where the two metrics disagree**, so it is the only region where that
limit can ever bite.

`rounds/crpool4m-2026-09-17/` could not sample it. Its bands are 6-24
rows and its rung grid is 32, so every band fell *between* measured rungs and
CPU and wall agreed at every rung it measured.

**This matters for something already in the standing rule.** The 0.1x-at-384 /
5.7x-at-416 trade degradation now recorded there came off the banked
**UNPINNED** `-t4` (`rounds/crg4-2026-09-16/`), whose band was 41 rows
wide. Under controlled placement crpool4m read bands of 6-24, so **part of that
41 was placement and not mechanism**, and those two figures should not be quoted
as a pinned result. Ladder `cband` is what replaces them.

**A narrow band means small differences, so UNRESOLVED rungs are the expected
case and not a failure.** "The trade cannot be priced at this resolution on this
part" is publishable and is exactly what the limit needs to know. No tolerance
is widened to manufacture a verdict.

## Item 2 - why the same unpinned arm read 365 and then 387

crpool4m's unpinned `-t16` read **387** CPU where `crg4`'s read **365**: 22 rows
on the same configuration, binary and fixture shape, larger than the entire
16-row gap that round was chartered to investigate.

Two thirds of it was settled with no box time by
`rounds/crpool4m-2026-09-17/regrid-and-arm-split.py`, re-run here
before taking the box and reproducing cell for cell:

- **The rung grid is REFUTED.** On the common grid 320..512 every reading is
  identical to its own-grid reading (`crg4` `-t16` 365/393, `crg4` `-t4`
  381/422, `4mc-t16` 387/411). Not a reduction artefact.
- **The swing is LOCATED in the fold arm.** Between the sittings the fold is
  5.8% cheaper in CPU (6.1% wall) and the force only 3.0% (2.6%). A crossover is
  where fold/force = 1, so symmetric noise cancels; that ~3 pp differential IS
  the 22 rows.

What survives: `crg4` ran its two pools **INTERLEAVED** in one ladder
(`-Threads 4,16`) where crpool4m ran a solo `-t16`; the fixture was a different
instance; and `crg4`'s sitting was noisier.

### A FOURTH candidate, found by reading and refuted before the sitting

**The two banked rounds did not run the same harness, and nobody had noticed.**
`crg4` ran plib `3b0e254e` + wcomb `1ad3f260` (commit `e11512488`); crpool4m ran
plib `1a714068` + wcomb `70fe0efe` (commit `e1731b0ee`). That is **878 inserted
lines** across the two files - the affinity feature, `-Payload`, the create-path
residency assert and a rewritten foreign-CPU accounting. A harness delta between
the two sittings being invisible is exactly the shape of defect this campaign
keeps finding, so it was diffed line by line rather than assumed inert.

**It cannot reach an unpinned create leg:**

- `Invoke-Leg`'s **only** change is the affinity block, guarded by
  `if ($affWant)`, and `$affWant` is `0` on an unpinned leg - PowerShell treats
  `0` as false, so the block does not execute and `wall`/`cpu` are produced by
  identical code.
- The create argv is **byte-identical when `-Budget` is unset**: the newer
  version builds `c -q -t$threads -s$slice -c$m` and appends ` -m$budget` only
  `if ($budget -ne 'big')`. Neither banked round passed `-Budget`, and neither
  does this one.
- `-Payload` defaults to `random`, which is the historical member-writing loop
  to the byte, and the fixture directory name is unchanged for it.
- `-Residency` on the create path went from silently inert to asserted. An
  assert refuses a leg; it does not change the work a leg does.

**So the harness is not the 22 rows**, and the three candidates the handoff
names remain the three.

**But one READING does not survive it.** Foreign-CPU accounting *did* change:
`Get-OwnPidTree` now resolves an ancestor-walking own-pid set and
`Measure-ForeignDelta` is new. So `crg4`'s "12% median" and crpool4m's "8%
median" **were measured by two different instruments** and are not a
like-for-like noise comparison. The handoff leans on that pair when it ranks the
"noisier sitting" candidate; it should lean less hard. In this round
`foreign_cpu` is quoted **within** the sitting and never across the two banked
ones.

## The cell

- **Box** intel-core-ultra-9-386h (Core Ultra 9 386H, GFNI-256, 4 P cores 0-3, 8 E cores
  4-11, 4 LP-E cores 12-15, 31.4 GB, Windows 11).
- **Binary** parfast from `06d5734b7`, gated on its **4,173,312-byte COUNT and
  never on a sha256** - the build embeds its own path, so the hash differs per
  root by construction.
- **Harness** `wcomb.ps1` sha `70fe0efe` and `plib.ps1` sha `1a714068`:
  **crpool4m's exact pair**, chosen so ladder `csolo` differs from the reading
  it is trying to reproduce in nothing but the fixture instance, the sitting and
  its position in the sitting.
- **Fixture** 16 x 1,024 MiB at 4 MiB blocks, `-c640`: n = 4,096, a 16 GiB
  corpus - the shape all five banked 4 MiB rounds used. n = 4,096 clears the x86
  input floor of 2,048 on its own, so no rung here can fall through to the fold.
- **Ladders** three, all **UNPINNED**, `-Phase create`, `fold force force2
  fold2` at every rung, one rep, `-Residency resident`, `-NttBudget` 20 GiB:

  | # | label | threads | rungs | what |
  |---|---|---|---|---|
  | 1 | `4mcb-band` | 16 | 384,392,400,408,416 | **item 1** - 8-row spacing across `4mc-t16`'s band (CPU 387, wall 411), the widest of crpool4m's five. Builds the fixture |
  | 2 | `4mcb-solo` | 16 | 320,352,384,416,448,480,512 | **item 2** - the shape crpool4m read 387 from |
  | 3 | `4mcb-inter` | 4,16 | 320,352,384,416,448,480,512 | **item 2** - the shape `crg4` read 365/381 from |

  Ladders 2 and 3 run the **common grid** `regrid-and-arm-split.py` established,
  so both readings are comparable to 387 and 365 with no re-gridding step and no
  grid candidate to re-open. Every ladder carries a **distinct `-Label`**:
  `rowgate.py read` groups by (label, threads), and `cinter`'s `-t16` legs must
  not fold into `csolo`'s.

### The ordering, and what it costs

All three ladders are unpinned, so `-Affinity` arms nothing and the "arm 1 must
be unpinned" rule - which exists because `-Affinity` pins the **fixture create**
too - is satisfied by every ordering. The ordering is therefore free, and it is
chosen for item 2:

**`cband` runs first and builds the fixture, so that `csolo` and `cinter` are
symmetric** - both post-settle, neither carrying the 16 GiB create and its
456-745 s settle. Item 2's whole question is a contrast between those two, and
the contrast is worth more than either one's tie to a banked number.

**The price, stated in advance:** crpool4m's 387 was read from a ladder in
position 1 that built its own fixture, and `csolo` is in position 2. A `csolo`
that does not reproduce 387 therefore has **ladder position** as a residual
explanation this round cannot exclude.

**The ordering buys back more than it costs**, and this is the reason for it:
`cband` and `csolo` are both unpinned `-t16` and **share the rungs 384 and
416**. Comparing their fold and force readings at those two rungs is a
within-sitting, same-configuration estimate of exactly that position-plus-repeat
term - which no other ordering provides, and which nothing in this campaign has
ever measured. It is a free internal control.

## What this round does NOT license, committed to IN ADVANCE

Written before the sitting, so it cannot be trimmed to fit whatever the numbers
turn out to say. crpool4m recorded a commitment of this shape and it is the
reason that round's conclusions held when its numbers would have allowed a
stronger claim.

**NO CONSTANT MOVES.** The rung decision - 384 against 416 against
`create_ntt_min_rows` taking its own clause at ~372 - is **the maintainer's**, it is open,
and it is explicitly waiting on wall-based inputs. This lane is the fifth to
measure inputs and the fifth not to move anything. No sentence in this write-up
may be read as a decision having been taken, and anything downstream citing it
as "384 ships" is citing it wrongly.

**A PRICED BAND IS NOT A CHOSEN RUNG.** Item 1 produces a trade ratio per rung.
A ratio under 10x does not say a rung is right; it says the proportionality
limit does not **exclude** it. Those are different claims and only the second is
this round's.

**AN UNRESOLVED BAND IS NOT A CLEAN BILL.** If the rungs inside the band come
back inside their own A/A floors, the honest statement is "the trade cannot be
priced at this resolution on this part" - **not** "the trade is small", and
**not** "the metrics agree".

**ITEM 2 CANNOT CLEAR AN INTERLEAVED LADDER, ONLY CONVICT ONE.** If solo and
interleaved land together, that is evidence the mechanism is not interleaving
*in this cell*, at this pool pair, on this part. It does not certify the other
interleaved ladders in the campaign, which use different pools and shapes.

**ONE SITTING IS NOT A REPLICATE**, and more reps cannot firm a rung: the A/A
floor is a MAX over reps.

**ONE PART, ONE PAYLOAD, ONE BLOCK SIZE.** Core Ultra 9 386H, random bytes,
4 MiB, n = 4,096. No other box on this fleet is GFNI-256.

## Reading rules this round is held to

- **WALL DECIDES, CPU EXPLAINS.** Both crossovers are quoted on every table and
  any divergence is named with its size. `rowgate.py read` prints both.
- **CPU-SECONDS DO NOT COMPARE ACROSS MASKS.** Inert here since all three
  ladders are unpinned, but `cinter`'s `-t4` and `-t16` legs are two different
  pools and only their CROSSOVERS compare.
- **A tight A/A floor is agreement, not correctness.** Every ladder is screened
  with `rounds/pinaff4m-2026-09-16/ladder-monotonicity-audit.py` and
  the rungs BRACKETING each crossing are checked for firmness before any
  crossover is believed.

## Files

| file | what |
|---|---|
| `crband-round.ps1` | the driver: load gates, class probe, extract, build, byte gate, per-ladder ARGV, rc=17 retry |
| `crband-driver.log` | the driver's own log |
| `logs/cband.log` | ladder 1, `4mcb-band`, unpinned `-t16`, 5 rungs. Builds the fixture |
| `logs/csolo.log` | ladder 2, `4mcb-solo`, unpinned `-t16`, 7 rungs |
| `logs/cinter.log` | ladder 3, `4mcb-inter`, unpinned `-Threads 4,16`, 7 rungs |

## Result

**RAN AND COMPLETE.** One sitting on intel-core-ultra-9-386h, **01:44:51Z-03:04:40Z** on
18 Sep 2026, three ladders, **104 legs, every leg `rc=0`, `match=1` on the
cross-arm SHA-256, `residency=resident`, and `lock_waits=0` on all three.**
Nothing excluded, nothing re-measured. `cband` 20 legs (27 min, including the
16 GiB fixture create and a 989 s settle), `csolo` 28 (14 min), `cinter` 56
(33 min). Binary built on the box from `06d5734b7` and gated at 4,173,312
bytes; harness `wcomb.ps1` `70fe0efe` + `plib.ps1` `1a714068`, crpool4m's exact
pair. Box released and the root deleted; 37.9 GB.

### 1. Item 2 is answered: INTERLEAVING IS REFUTED, and it is the SITTING

Against **one fixture instance in one sitting**, the two shapes land on top of
each other:

| ladder | shape | **CPU** | **wall** | foreign median / max |
|---|---|---:|---:|---|
| `4mcb-solo` | `-t16` SOLO | **359** | **394** | 8% / 78% |
| `4mcb-inter` | `-t16` INTERLEAVED with `-t4` | **357** | **389** | 7% / 32% |

**Two rows apart in CPU and five in wall.** Interleaving is not the mechanism,
and the 22 rows have to come from somewhere else. Put beside the two banked
readings, all four unpinned `-t16` create crossovers on this part:

| sitting | ladder | shape | CPU | wall |
|---|---|---|---:|---:|
| 16 Sep | `crg4` `res4m` | interleaved | 365 | 393 |
| 17 Sep | `crpool4m` `4mc-t16` | solo | **387** | **411** |
| 18 Sep | `crband` `csolo` | solo | 359 | 394 |
| 18 Sep | `crband` `cinter` | interleaved | 357 | 389 |

**The spread is 30 rows in CPU and 22 in wall, and it does not sort by shape.**
The two solo readings are 28 rows apart from each other; the two interleaved
readings are 8 apart; a solo and an interleaved from the same sitting are 2
apart. Shape explains none of it and sitting explains all of it.

### 2. The `-t4` arm REPLICATES, so this is a FULL-BOX problem

The same interleaved ladder's other pool, against `crg4`'s, two days apart:

| sitting | pool | CPU | wall |
|---|---|---:|---:|
| 16 Sep `crg4` | `-t4` | 381 | 422 |
| 18 Sep `cinter` | `-t4` | **387** | **427** |

**Six rows in CPU, five in wall** - the same order as the repair path's PINNED
replication (344->349, 378->377, 398->401, within 5). So "an unpinned reading
is unreliable" is too broad a conclusion: **the unpinned `-t4` create arm is as
reproducible as a pinned one, and it is the unpinned FULL-BOX arm that is
not.** That is a sharper statement than the handoff could make, and it is new.

It also re-reads the unpinned pool "term". Within this one interleaved ladder
the smaller pool crosses HIGHER by **30 rows** (`-t4` 387 against `-t16` 357),
where `crg4` measured +16 and crpool4m's *controlled* arms measured the
opposite sign (+26 for the bigger pool). So the unpinned pool ordering is not
merely confounded by placement, as crpool4m established - **its magnitude is
itself unstable by 14 rows between sittings.**

### 3. And no single one of these numbers is precise, which is the real finding

Take each crossing and ask whether the rungs BRACKETING it are firm - the test
crpool4m's own trap note names. Distance of `F/T` from 1 at the bracketing
rung, against that rung's own A/A floor:

| reading | lower bracket | upper bracket |
|---|---|---|
| `crg4` `-t16` 365 | 352: 3.0% vs 1.8% **firm** | 384: 4.6% vs 2.9% **firm** |
| `crpool4m` `-t16` 387 | 384: 1.0% vs 3.2% **INSIDE** | 416: 9.2% vs 3.4% firm |
| `csolo` 359 | 352: 1.7% vs 2.0% **INSIDE** | 384: 5.9% vs 0.5% firm |
| `cinter` `-t16` 357 | 352: 1.5% vs 1.8% **INSIDE** | 384: 7.2% vs 1.6% firm |

**Three of the four are bracketed on the low side by a rung whose distance from
the crossing is inside that rung's own noise.** `crg4`'s 365 is the only one
firmly bracketed both ways, and **the 387 is both the outlier and among the
softest**, which crpool4m's README half-said about itself ("the softest reading
here is `4mc-t16`'s own, bracketed at 3.2% and 3.4%").

So the honest form of the answer to item 2 is not "an unpinned create reading
is worth +/- 15 rows". It is: **the unpinned full-box create crossover is not a
measurable quantity at this rung resolution on this part.** Every reading of it
is a three-digit number resting on at least one bracket it cannot resolve, and
the four of them span 30 rows. Quoting any of them - 365, 387, 359 - to the row
is quoting past the instrument.

### 4. Item 1: the fine ladder MISSED ITS BAND, for the reason item 2 just gave

`cband` was positioned on crpool4m's `4mc-t16` band, CPU 387 to wall 411. In
this sitting that arm's band is **[359, 394]**. The ladder's rungs 384-416 sit
mostly *above* it, and its own reduction says so: **CPU crossover `<384`** (it
never crossed in range) and every rung from 392 up reads `ntt` in both metrics.

| m | cpu F/T | wall F/T | cost% | gain% | aa_cpu | aa_wall | verdict |
|---:|---:|---:|---:|---:|---:|---:|---|
| 384 | 1.043 | 0.946 | +4.3 | +5.4 | **35.5** | **33.8** | unres |
| 392 | 1.100 | 1.015 | +10.0 | -1.5 | 1.2 | 1.6 | agree |
| 400 | 1.104 | 1.022 | +10.4 | -2.2 | 1.1 | 0.6 | agree |
| 408 | 1.113 | 1.031 | +11.3 | -3.1 | 4.0 | 4.3 | agree |
| 416 | 1.138 | 1.054 | +13.8 | -5.4 | 1.7 | 1.2 | agree |

**`cband`'s own wall crossover of 390 is NOT usable** and is not quoted as a
result anywhere here: it is interpolated across the 384 rung, and that rung is
the ruined one (section 6).

**This is not bad luck, it is a structural result about the cell, and it is
worth more than the table would have been.** The band on this arm is 6-35 rows
wide and its LOCATION moves 30 rows between sittings. **A band cannot be
pre-positioned to 8-row resolution when its position is only known to +/- 15
rows.** Pricing the create's proportionality band therefore requires a PINNED
arm first - which is a concrete, checkable prerequisite the handoff did not
know it needed, and which the repair path's 5-row pinned replication says is
achievable.

### 5. Two rungs priced honestly anyway, and neither is near the limit

`band-trade.py` (this directory) prices the trade at every rung and, unlike
`rowgate.py read`, computes an A/A floor on **wall** as well as CPU - which
matters because the ratio's denominator is the wall gain, a small number.

| ladder | m | cost% (floor) | gain% (floor) | **ratio** |
|---|---:|---|---|---:|
| `csolo` `-t16` | 384 | +5.9 (0.5) | +1.8 (0.7) | **3.2x** |
| `cinter` `-t4` | 416 | +4.8 (0.7) | +2.6 (0.4) | **1.8x** |
| `cinter` `-t16` | 384 | +7.2 (1.6) | +0.7 (**1.4**) | unres |

Both priced rungs clear both floors comfortably. Re-pricing the banked `crg4`
ladder the same way gives **0.1x** at `-t4` m=384 (priced) and **1.9x** at
`-t16` m=384 (priced, but marginal: +4.6 against a 2.9% floor and +2.5 against
2.3%).

**And it removes a figure from the standing rule.** The **5.7x** at `crg4`
`-t4` m=416 - currently a bullet in memory topic
`nzbfast-wall-time-is-the-deciding-metric`, described there as "over half way
to the 10x the maintainer named as excessive" - has a wall gain of **+1.17% against a
1.36% wall A/A floor on that rung**. Its denominator does not clear its own
noise. Hand-checked leg by leg: fold 35.488/35.195, force 36.000/35.517. **5.7x
is not a measured quantity and must not be quoted as one.**

So the complete set of honestly priced create trade ratios now on record is
**0.1x, 1.8x, 1.9x and 3.2x**. The largest is 3.2x. **No create rung has ever
been measured at a trade approaching the 10x limit, and the figure that came
closest was an artefact of an unfloored denominator.** That does not choose a
rung; it says the proportionality limit does not currently exclude any of them.

### 6. The instrument finding: a ladder's FIRST rung is a warm-up ramp

`cband`'s m=384 is ruined, and the four legs say exactly how - a monotone rise
across the rung, with foreign CPU at 3-5% throughout, so it is not foreign load
and the 989 s settle had completed (`FIXTURE-SETTLE ok=1 foreign_cpu=16.9`):

```
fold  cpu=248.4   force cpu=271.5   force2 cpu=288.9   fold2 cpu=336.4
```

`fold2` is 35% dearer than `fold`, and m=392 is already at steady state with a
1.2% floor. **The ramp is confined to the first rung**, and `fold2`'s 336
matches `csolo`'s independent 340 at the same rung.

**All three ladders in this campaign that BUILT their own fixture show it, and
no other ladder does:**

| ladder | first rung | fold -> fold2 | aa_F |
|---|---:|---|---:|
| `crg4` `-t4` | 320 | 106.1 -> 116.3 | **9.6%** |
| `crpool4m` `4mc-t16` | 288 | 162.6 -> 188.1 | **15.7%** |
| `crband` `cband` | 384 | 248.4 -> 336.4 | **35.5%** |

against 0.1-2% at a typical rung. **Why the medians survive it and the floor
does not**, which is the part worth internalising: the arm order is ABBA (fold,
force, force2, fold2), so a LINEAR drift of `d` per leg adds `1.5d` to both
arms' medians and cancels exactly in the ratio - that is what ABBA is for. A
warm-up is not linear, so only the CURVATURE leaks through, while the fold
arm's A/A spans three legs of ramp and the force arm's spans one. **The floor
blowing up while the verdict stays plausible is the designed behaviour, not a
malfunction** - and it is why the first rung must be read as a refusal rather
than as a number.

**The cheap fix for any future ladder here: spend the first rung.** Put a
throwaway rung below the range you care about, or build the fixture on a ladder
whose lowest rung you are willing to discard. crpool4m and `crg4` both absorbed
this at a rung far below their crossing and were unharmed; `cband` put its
first rung *inside* the region it was measuring and lost it.

### 7. The within-sitting position control, which the ordering bought

`cband` and `csolo` are both unpinned `-t16` and share rungs 384 and 416, at
positions 1 and 2 of the sitting. 384 is `cband`'s ruined rung, so the control
reads at 416:

| | `cband` (ladder 1) | `csolo` (ladder 2) | apart |
|---|---:|---:|---:|
| CPU F/T | 1.138 | 1.122 | 1.4% |
| wall F/T | 1.054 | 1.041 | 1.2% |

Using `csolo`'s local slope (`F/T` rises 0.063 over the 32 rows from 384 to
416), **1.4% in `F/T` is worth about 8 rows.** So ladder position plus repeat
inside one sitting is a real but modest term - and it is **well under the
30-row between-sitting spread**, which is the comparison the control exists to
make. The stated price of the ordering (section "The ordering, and what it
costs") is therefore paid and bounded: `csolo` sitting at position 2 rather
than 1 can account for roughly 8 of the 28 rows between it and crpool4m's 387,
not for all of them.

### 8. Screening

`ladder-monotonicity-audit.py` over all three logs - **and the audit was blind
when this lane first ran it; see below**:

```
   4 4mcb-inter            NO            1.6%  logs/cinter.log
full-box (threads>=16) ladders:   3   non-monotone:   0  (0%)
sub-box  (threads< 16) ladders:   1   non-monotone:   1  (100%)
```

All three full-box ladders are monotone. `cinter`'s `-t4` is not: its dip is
480 -> 512 (`F/T` 1.160 -> 1.142) at floors of 0.5% and 1.2%, **above** its
crossing, which is bracketed by 384 (floor 1.0%) and 416 (floor 0.7%). Same
shape as every previous sitting's non-monotone arm, and its 387 stands on the
stated test.

Foreign CPU by ladder: `cband` median 7% / max 43%, `csolo` 8% / 78%,
`cinter` `-t4` 9% / 81%, `cinter` `-t16` 7% / 32%. Both 78-81% maxima are on
`fold` legs at m=320, below every crossing.

### A tool that was reporting a clean bill over nothing

`rounds/pinaff4m-2026-09-16/ladder-monotonicity-audit.py` - the screen
this round and every round in the campaign is required to pass - **matched
nothing and printed `full-box ladders: 0   non-monotone: 0` with exit 0** on
every log, from `9cb6c5fbf` (2026-09-17T21:35Z) when `rowgate.py read`'s table
header gained a `create|repair` phase token that the audit's regex did not
follow. Found here by running the mandated pre-round screen over `crg4` and
getting zero ladders out of the very log whose non-monotone `-t4` ladder
crpool4m's README quotes a result for.

Fixed in this round's work, and the fix is a pointer repair rather than a new
behaviour - it restores **two independently banked screen outputs byte for
byte** (`crg4`'s `4 res4m NO 9.6%` and crpool4m's `4 4mc-p4 NO 1.2%` with four
of five arms monotone). Reducing zero ladders out of a non-empty file list now
REFUSES with exit 2: failing to find is failing, and a screen that cannot
locate its subject must not read as a screen that passed.

### What this licenses, and what it does not

**It moves no constant and recommends no rung**, per the guard committed before
the sitting. Every bullet there stands. In particular the round did NOT price
the band as a curve, and nothing here says 384, 416 or ~372 is right or wrong.

What it establishes for the decision that is waiting:

- **Interleaving is refuted** as the cause of the 22-row swing (2 rows, direct,
  one fixture, one sitting), and the `cinter` ladder is therefore evidence that
  the campaign's other interleaved ladders do not need re-reading *for this
  reason*. It does not certify them at other pools or shapes.
- **The unpinned full-box create crossover is not measurable at this
  resolution.** Four readings span 30 rows and three of the four rest on a
  bracket inside its own floor. **Every unpinned figure in this campaign
  inherits that** - including the 381/365 pair the 384 recommendation was
  argued from, whose 16-row gap is half the spread of one of its own terms.
- **The unpinned `-t4` arm is the exception and replicates within 6 rows**, so
  the instability is a property of the full-box pool, not of unpinned
  measurement.
- **Pricing the proportionality band needs a PINNED arm.** This is now a
  measured prerequisite and not a preference: an 8-row ladder cannot be aimed
  at a band located to +/- 15 rows.
- **The largest honestly-priced create trade on record is 3.2x**, and the 5.7x
  that reads as "over half way to excessive" is not a measurement.

### Stated limits

- **ONE SITTING**, and more reps cannot firm a rung: the A/A floor is a max over
  reps. The solo-vs-interleaved contrast is one comparison on one fixture.
- **`cband` did not answer item 1 as chartered.** What it produced is a reason
  the question cannot be asked that way on an unpinned arm, plus one ruined
  rung that turned into section 6. Two band rungs were priced from the *other*
  two ladders, opportunistically, not from the ladder built for it.
- **ONE PART, ONE PAYLOAD, ONE BLOCK SIZE.** Core Ultra 9 386H, random bytes,
  4 MiB, n = 4,096. No other box on this fleet is GFNI-256.
- **The position control reads at one rung**, 416, because the other shared rung
  was the ruined one. An 8-row position term is one measurement.
- **Item 2's "different fixture instance" candidate is retired only for the
  solo-vs-interleaved contrast**, which shared a fixture by construction. The
  between-sitting comparisons in section 1 still differ in fixture instance as
  well as sitting, and this round cannot separate those two.

### Owed

- **A pinned band ladder.** Pin an arm (the repair path's `e4`-style mask), find
  its crossovers, then put 8-row rungs across the band it actually has. The
  pinned arms replicate within 5 rows, so the band can be aimed at.
- **Why the unpinned full-box arm is unstable where the unpinned `-t4` arm is
  not.** 4 P + 8 E + 4 LP-E all in play against four threads the scheduler
  places consistently is the obvious hypothesis and it is not tested here.
- **Spend the first rung**, in every future ladder on this rig.
