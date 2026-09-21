# Where in 17-48% of a core does the `c_f` load term turn on?

Lane `cf-load-term-knee-rung-18sep`, gen `cde69af2`, on intel-i5-10600kf
(i5-10600KF, 6c/12t, AVX2 without GFNI = the nibble class). The first
"Owed after this lane" bullet of the 18 Sep co-tenant-footprint section in
an internal note, owed since the load lane
and untouched by two lanes since.

**Status: everything in this file except the Result section was written and
landed BEFORE the sitting's numbers were reduced**, and the driver
(`cfknee.ps1`), which carries the same predictions in its header, landed
before a single leg ran. The question, the arm order, the buffer, the
equal-n rule, what confirms and what refutes, and the guard on what the
round does not license are all fixed in advance and none of them is fitted
to the outcome. That is the practice `crpool4m`, `crband`, `crpin4m` and
`cfbuf` used, and it is why their conclusions held when their numbers would
have allowed stronger claims.

## The question

The banked load round measured `c_f` at three total `foreign_cpu` levels and
no more:

| arm | total `foreign_cpu` | `c_f` at `-t12` | per point of foreign CPU |
|---|---:|---:|---:|
| Q | 17% | (reference) | - |
| L50 | 48% | +8.7% | 0.28% |
| L90 | 83% | +20.0% | 0.30% |

and reported the response as "close to linear in `foreign_cpu` across the two
levels". **Two points that both sit at or above 48 cannot distinguish a
response that is linear FROM THE BASELINE from one with a THRESHOLD anywhere
inside the 31-point gap neither of them sampled.** A load term that is free
below some level and then turns on would produce exactly these two numbers.
So the knee is **bracketed, not located**, and every use of that coefficient
below 48 points is an extrapolation into unmeasured ground.

## The measurement

**One more generator level.** An ask of 10% of one core on a box idling near
18-22 lands total `foreign_cpu` near 29 - inside the gap, at roughly its lower
third, which is where a threshold would most plausibly sit and where a linear
response and a threshold differ most.

**Predictions, fixed before any leg ran** (they are also in `cfknee.ps1`'s
header, landed first):

- **LINEAR from the baseline** -> `c_f` at ~29 reads about **+3.4%** over quiet
  (0.28%/pt x 12 points).
- **A THRESHOLD above ~29** -> it reads about **0%**, inside the noise floor.
- **CONVEX / front-loaded** -> it reads **well above +3.4%**.

All three are distinguishable only because the noise floor is measured in the
same sitting rather than assumed.

## The buffer, which is the thing that would ruin this round

**Every loaded legset runs at `-BufKiB 4096`, loadgen.ps1's default, and that
is the point of the round rather than a default left alone.** All three banked
points (17 / 48 / 83) were taken there. The 18 Sep buffer round then found
that a co-tenant whose working set **leaves** this part's 12 MiB L3 moves
`c_f` **1.44x more per point of foreign CPU** than one that fits inside it -
so buffer size is a second free parameter of every one of those three figures.
**A new point taken at a different buffer is not on the same curve as the
points whose knee it is supposed to locate**, and would be a fourth number
rather than a fifth point. 4096 is stated here, held fixed in the driver, and
stated again in the write-up.

**The same finding is why this rung may not be bought off a box with a
standing co-tenant**, which is the cheap answer and is wrong. amd-ryzen-9800x3d idles
at `foreign_cpu` ~42-55 from SignalRgb, squarely in the gap and free for the
taking - but **nothing is known about SignalRgb's footprint**, so a knee
located against it is a knee in that co-tenant's own coefficient wearing the
load term's name, which is precisely the substitution the buffer round
refutes. It is also a Zen 5 part with AVX-512 and GFNI, not the nibble class,
so no `c_f` from it is comparable with any banked cell at all.

## Arm order

`q1 g10a g72a qm g72b g10b q2` - **a mirror, with quiet legsets at BOTH ENDS
and one in the MIDDLE.**

The load lane's whole `-t4` arm was **withdrawn** because its single closing
quiet legset did not land back on its opening one (+6.8%, nearly half the
effect it was measuring) and it could not then tell drift from effect. Three
quiet points give a drift **curve** where two give only a gap; a mirror
cancels a linear drift in the **mean** of each level's pair. The 18 Sep
sitting passed the same check at +0.0% CPU and +0.3% wall - that is its
result, not a property of the box, and this round assumes nothing from it.

**Why `g72` is here at all**, when 83 is already banked and the buffer round
already replicated 4 MiB at ~88: because splicing is the failure mode this
campaign keeps finding. The two segments 17->29 and 29->48 have to be compared
like for like, and a segment whose endpoints come from two sittings with two
baselines is not that. Running the high level HERE puts quiet (~19-22), ~29
and ~88 in **one sitting, against one baseline, on one instrument**, so the
per-point figures are internally comparable - and the 4 MiB coefficient
replicates for a third time as a by-product. It costs two legsets, about
14 minutes.

## The ladder and the reduction

`wcomb.ps1 -Phase measure` at 64 KiB, n = 16,384, `-Reps 1 -Threads 4,12`,
**rungs m = 192, 512, 1024, 2048, 4096** - identical to the banked load
round's and the buffer round's. Stated rather than left implicit because
`c_f` is a least-squares slope over a fold that is not linear in m, so the
rung set is a free parameter of every figure and a round that moved it would
not be extending those points, it would be starting a new curve.

Reduced with `harness/cfdriftsum.py --rungs 192,512,1024,2048,4096`,
which fits CPU **and wall** off the same selected leg so the two metrics are
like for like.

**EQUAL-n.** Three quiet legsets against two per load level, and
`wcombsum.best()` takes a **minimum**, so a three-legset unit sits low for no
reason but the extra draw and would **inflate every ratio here**. The
reduction therefore passes **every legset as its own unit** and compares means
of per-legset fits, which is free of the bias entirely. Do not reduce this
round by pooling `q1`+`qm`+`q2` into one baseline unit against a two-legset
load arm.

**Noise floor to beat: 8% at the full pool, 11% at `-t4`** (the within-sitting
drift census). An effect inside that band is not a measurement and the report
says so. The `-t4` arm is run because it costs nothing extra on the same
legset and an independent arm agreeing in sign is worth having, and it is
**not expected to decide anything**: its floor is 11% and the load lane
withdrew its `-t4` arm outright.

## The instrument, which crosses nothing

Binary `8983A55A4E260BA3...` = origin/main `4fedd8b33`, **the same source
commit the banked load round built from**, reused off `wcomb-16sep` rather
than rebuilt, and hash-gated fatally in the driver. Fixture: that round's
64 KiB set, n = 16,384, **copied** (the legs damage and restore slices, and
four rounds now read that one; `wcomb-16sep` is not this lane's and is only
read). Harness **pinned at `07a24a959`** - `plib.ps1` `20CB3299332113BD`,
`wcomb.ps1` `60DED61D70BC4ABD` - both verified against the banked round's
before staging and again on the box after staging; generator `loadgen.ps1`
`9698D5DEB71A399D`, **byte-identical** to the banked copy.

origin/main's harness has since gained per-leg frequency and thermal fields,
which makes it a **different instrument** from the one every cell here is read
against. `foreign_cpu` is consequently the **pre-`9686ac296` definition**:
comparable with the banked cells and with nothing taken after that commit. The
generator's achieved level is reported separately, closed-loop against its own
`TotalProcessorTime` and independent of the harness sampler entirely.

## What confirms, what refutes, and what this round does not license

**It answers the owed question either way.** A reading near +3.4% says the
response is linear from the baseline and there is no knee to find - the
coefficient may be used across the range, which is what every extrapolation in
the campaign has been assuming without evidence. A reading near 0% says there
is a threshold above ~29 and every sub-48 extrapolation has been **too large**.
A reading well above +3.4% says the response is front-loaded and they have
been **too small**. The round is only spent if the answer lands between the
distinguishable cases *and* the sitting's own drift is large, and the three
quiet legsets are what make that visible rather than silent.

**REFUTED if** `q2` does not land back on `q1` within the noise floor. Then
the sitting cannot separate drift from effect and the arm is withdrawn, as the
load lane's `-t4` arm was - not corrected.

**NO CONSTANT MOVES.** Not `NTT_WINDOW_COMBINE_X86`, not any
`NTT_MIN_MISSING*`. `crates/` is untouched whatever this finds.

**NO COEFFICIENT MEASURED HERE IS A CORRECTION FACTOR FOR A BANKED CELL.**
That rule is in the section this round extends, and the buffer round's 1.44x
is the argument for it: if footprint changes the coefficient by half again,
then no single coefficient transfers between co-tenants - **including any of
this round's own**. What a knee licenses is a statement about the SHAPE of the
response to this generator at this buffer on this part, and nothing more.

## Result

Written after the numbers, and after everything above was landed.

**Seven legsets, 154 legs, 13:32:22Z to 14:18:10Z, every one `rc=0` and
`restored=16/16`, zero failures.** Generator achieved levels read closed-loop
off the generator's own `TotalProcessorTime`: the 10% ask delivered a steady
**13%** and the 72% ask 67-71%, so the point lands at a measured median
`foreign_cpu` of **29.3** rather than the 29 aimed at.

**The drift check PASSES.** At `-t12`, `q2` lands -2.8% CPU and -2.7% wall on
`q1`, and the three quiet legsets span 2.9% / 2.8% against a bar of 8%. So no
arm below needs drift-correcting and none is withdrawn.

| unit | foreign | `c_f` CPU | vs quiet | `c_f` WALL | vs quiet |
|---|---:|---:|---:|---:|---:|
| quiet (`q1` `qm` `q2`) | 18.0 | 4.2587e-6 | (base) | 7.2583e-7 | (base) |
| **`g10` (`g10a` `g10b`)** | **29.3** | 4.4485e-6 | **+4.46%** | 7.5796e-7 | **+4.43%** |
| `g72` (`g72a` `g72b`) | 82.4 | 5.0822e-6 | +19.34% | 8.6296e-7 | +18.89% |

### 1. THERE IS NO THRESHOLD - the load term is already on at 29%

Both `g10` legsets sit above **all three** quiet legsets, in **both metrics**,
with no overlap (worst loaded beats best quiet by 2.7% either way). A threshold
above ~29 predicted about 0%; it is refuted.

### 2. AND IT IS NOT LINEAR EITHER - the response is FRONT-LOADED by about 1.5x

| segment | points of foreign CPU | `c_f` CPU | per point | WALL per point |
|---|---:|---:|---:|---:|
| **quiet -> `g10`** | +11.3 | +4.46% | **0.395 %/pt** | **0.392 %/pt** |
| quiet -> `g72` | +64.4 | +19.34% | 0.300 %/pt | 0.293 %/pt |
| **`g10` -> `g72`** | +53.1 | +14.25% | **0.268 %/pt** | 0.261 %/pt |

The banked round's 0.28 and 0.30 %/pt both START at 17, so both average over
the steep bottom segment and neither can see it. **`g10`->`g72` is the first
measurement in this campaign that excludes the bottom of the range, and it is
the lowest per-point figure anywhere in it.**

### 3. THE RUNG SIGNATURE is what makes a +4.46% excursion readable at all

+4.46% is **inside the published 8% bar**, and on that number alone this round
would have to report that it had not measured anything. It is not alone. Per
rung at `-t12`, against the quiet arm mean:

| arm | m=192 | m=512 | m=1024 | m=2048 | **m=4096** |
|---|---:|---:|---:|---:|---:|
| `g10` CPU | -0.4% | -0.0% | +0.6% | +1.3% | **+4.0%** |
| `g72` CPU | +1.3% | +0.6% | +1.5% | +4.9% | **+17.6%** |
| quiet's OWN spread | 3.5% | 1.9% | 1.7% | 1.3% | 2.8% |

**The two levels have the SAME shape** - flat across the bottom three rungs,
small at m=2,048, the whole effect at m=4,096 - and `g10`'s is `g72`'s scaled
down: **0.227 in the top rung against 0.231 in fitted `c_f`**. Drift has no
reason to concentrate at one rung, still less to scale by the same factor in
two places. That is an independent check the 8% bar does not carry, and it is
why the `g10` point is reported as a measurement rather than as noise.

### 4. The 4 MiB coefficient replicates a THIRD time

+19.34% CPU / +18.89% wall at 82.4 points, against the banked **+20.0%** (at
83) and the buffer round's **+18.7%** (at 88). Three sittings, three drivers,
one instrument, one binary.

### 5. CPU and WALL agree everywhere to within half a point

+4.46 against +4.43, +19.34 against +18.89, and the same at every rung. Under
the standing wall-time rule wall is the deciding metric where the two disagree;
here it does not disagree, so nothing turns on the choice.

### 6. The `-t4` arm resolves nothing at `g10`, exactly as pre-registered

Its quiet spread is 6.4% CPU / 5.8% wall, and `q2` alone exceeds both `g10`
legsets, so the two overlap and the +3.03% there is not separable from drift.
It agrees in SIGN at both levels, and its `g72` arm (+16.67%) lands on the
buffer round's own `-t4` 4 MiB figure (+16.8%). Quoted for the sign and for
that replication, and for nothing else.

### The equal-n rule, measured rather than obeyed

Pooling the three quiet logs into one unit puts it **1.5% LOW** against the
mean of the three per-legset fits, and would have reported `g10` as **+6.01%**
instead of +4.46%. The mean-of-per-legset-fits reading is stable across every
subsetting tried: +4.46 (three quiet), +4.54 (`q1`+`q2`), +3.67 (`q1`+`qm`).

### What this does NOT change

**The 16 Sep residual is untouched.** The banked 0.30 %/pt was already fitted
over a span starting at 17, so it already averages the steep segment.
Recomputing that sitting's +55-point extrapolation piecewise gives +16.1%
against the banked +16.7% - inside the noise, and the "other 52%" stands
exactly where the load round left it.

### What it DOES change

**Extrapolating to a SMALL load difference.** Two sittings a few points of
`foreign_cpu` apart move `c_f` about **1.4x more** than 0.28-0.30 %/pt
implies. That is the conservative direction for a campaign whose cells are
compared across sittings, and it is the practical content of this round.

### The generator delivers 13% for an ask of 10, and the selftest is why that is known

`loadgen.ps1` alternates a 2 ms burn against a `Thread.Sleep(2)` that Windows
rounds up to ~15.6 ms, so its control range collapses at the bottom end. The
selftest - run at 10% here precisely because that is this round's untried
configuration - read `achieved_pct=14.4` over 44.5 s including startup, and
the in-leg heartbeats settled at a steady 13%. **The ask is not the level**,
and every figure above is quoted against the measured median `foreign_cpu`
rather than the ask.

### Stated limits

- **One part, one block size, one fixture, one co-runner, one buffer.**
  i5-10600KF, 64 KiB, n = 16,384, `-BufKiB 4096`. Nothing transfers to another
  class, block size or footprint - the buffer round's 1.44x is the reason.
- **NO COEFFICIENT HERE IS A CORRECTION FACTOR**, including this round's own.
  What is licensed is a statement about the SHAPE of the response to this
  generator at this buffer on this part.
- **The gap is split, not filled.** There is still no point between 20 and 29,
  and none between 29 and 48. The first segment is measurably steeper than the
  second; WHERE inside 18-29 that steepness lives is untested.
- **The magnitude of the front-loading is directional.** 0.395 against 0.268
  %/pt is a 1.47x ratio, but the difference between the measured +4.46% and a
  linear prediction of +3.2% is 1.2 points, far inside the 8% bar. The SIGN is
  carried by the rung signature; the RATIO is not independently established.
- **`foreign_cpu` is the pre-`9686ac296` definition**, comparable with the
  banked cells and with nothing taken after that commit.

### What moved

**NO CONSTANT MOVED.** `NTT_WINDOW_COMBINE_X86` stays at 312, no
`NTT_MIN_MISSING*` moves, `crates/` is untouched.
