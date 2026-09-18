# sitting2 - the replicate, and the arm the first sitting owed

Lane `parfast-4mib-pool8-class-isolation-17sep`. Items 1 and 2 of
an internal note, run together because
that handoff says to and because item 2's arm is only readable against item 1's.

The first sitting is one directory up. Read its README first; this one states
only what differs.

## The two questions

**1. Replicate.** The first sitting read the resident CPU crossover move 344 to
378 - **+34 rows** - when the pool doubled from four E-cores to eight with the
core class held fixed. That rests on ONE sitting against a stated sub-box
reproducibility envelope of 3 to 7 rows, so the EFFECT is safe and the NUMBER is
not replicated.

**More reps cannot do this job.** The A/A floor is a MAX over reps, so it is
monotonically non-decreasing in rep count: adding reps can only raise the bar a
rung has to clear, never firm the rung. Only an independent whole sitting buys
confidence. This round is therefore ONE rep per rung, exactly as the first was,
on a rebuilt binary and a rebuilt fixture.

**2. Isolate class at fixed pool size eight**, which is the real open question.
The first sitting moved pool 4 to pool 8 **within** the E class, and cannot say
whether the +34 belongs to the POOL or to the E CLASS, because E is the only
class on this part wide enough to grow (4 P and 4 LP-E are whole classes). An
arm at mask `0xFF` - cores 0-3 (P) plus 4-7 (E), eight threads - sits at the
**same pool size** as `0xFF0` with a different core mix, which isolates class at
fixed pool size eight exactly as the pinned sitting isolated it at fixed pool
size four. That arm was deliberately not run in the first sitting and its
absence is recorded at the site in its driver under "NOT RUN, and deliberately".

**Written down before the legs ran, so it cannot be fitted afterwards:** the
first sitting read `4m-e8` at 378 and `4m-p4` at 381. If `0xFF` at t8 lands NEAR
378, the +34 is the POOL. If it lands WELL ABOVE, part of the +34 is the class
and the pool term is smaller than the first sitting says.

## The arms

| log | label | mask | cores | class | threads | why |
|---|---|---|---|---|---:|---|
| `logs/p2t16.log` | `4m2-t16` | none | 0-15 | 4P+8E+4LPE MIXED | 16 | builds the fixture; a by-product |
| `logs/p2e8.log` | `4m2-e8` | `0xFF0` | 4-11 | E only | 8 | THE REPLICATE of 378 |
| `logs/p2pe8.log` | `4m2-pe8` | `0xFF` | 0-7 | 4P+4E **MIXED** | 8 | THE NEW ARM |
| `logs/p2e4.log` | `4m2-e4` | `0xF0` | 4-7 | E only | 4 | the pool-4 anchor |

`4m2-t16` runs FIRST for the same mechanical reason it did in the first sitting:
`wcomb` builds the fixture on the first ladder and `-Affinity` arms every leg
including that create, so a pinned arm first would build 37.8 GB on four cores.
`4m2-e4` runs LAST because it already carries three banked readings (343, 346,
344) across two prior sittings, so it is the arm a sitting cut short can afford
to lose where `4m2-e8` and `4m2-pe8` are not.

`4m-p4` and `4m-m12` are **not run**: p4 moves neither question and has three
banked readings, and m12 was the spare-core test, a hypothesis the first sitting
already killed directly by bringing `4m-t16` back monotone at 398 while leaving
no core idle.

## The labels carry a `4m2-` prefix and that is load-bearing twice

`rowgate.py` groups by (label, threads). Arms 2 and 3 are **both eight threads**,
so a shared label would reduce them into one group - which is precisely the
comparison this round exists to make, destroyed. The prefix also keeps every
number here separable from the first sitting's `4m-` labels when both are read
together, which they will be.

## Reduce

    python3 harness/rowgate.py read rounds/poolladder4m-2026-09-17/sitting2/logs/p2e8.log

Screen before believing any crossover:

    python3 rounds/pinaff4m-2026-09-16/ladder-monotonicity-audit.py \
        rounds/poolladder4m-2026-09-17/sitting2/logs/*.log

## The one thing a reader gets wrong

**CPU-seconds do not compare across masks.** P/E is 1.74x on this part, so
`4m2-pe8` - which has four P-cores in it - will burn fewer CPU-seconds than
`4m2-e8`, which has none, for the same work. That is not `4m2-pe8` doing less.
Only the CROSSOVER compares across arms, because it is a ratio of fold to force
WITHIN one arm on one core mix.

## Wall AND CPU, both reported, and why the wall figure carries a warning here

A standing rule arrived from the maintainer during this sitting, relayed by the 1.6.0
release lane: **wall time beats CPU time whenever the two disagree**, because
that is what people actually experience. His words as relayed: "people care
about wall times much more than cpu times... so that should be our deciding
factor whenever we get a choice in the matter."

This round is the shape where that bites hardest, which is why it is written
down here rather than left to the reader. Arm 3 (`0xFF`) contains four P-cores
and arm 2 (`0xFF0`) contains none, and this sitting's own class probe read P/E
at **1.71x** before any leg ran. Two arms at the same pool size whose cores
differ by 1.71x will not rank the same in elapsed seconds as in CPU seconds.
**If the arms rank differently in wall than in CPU, that divergence is the
headline of this round and not a footnote.**

No new apparatus was needed: `rowgate.py read` already prints both, per (label,
threads), as `crossover (log-interpolated, median): CPU m ~ <x>   wall m ~ <y>`.

**The warning, and it is specific to this gate on this part.** `rowgate.py`'s
own header records a measured reason it made CPU the verdict for the row gate:
"Wall divides the fold by the pool and adds storage to both arms; the 2 Sep 2026
'~400 on the Core Ultra' was a storage-bound wall reading." That is this box's
silicon, and that is one spurious wall crossover already produced on it. So on
the row gate specifically, a wall crossover has a recorded failure mode in which
it measures the SSD rather than the gate.

That does not put the rule and the apparatus in conflict - where the transform
starts beating the fold is a MECHANISM question, and CPU is the robust quantity
for one - but it does set what this round may and may not conclude. It reports
both crossovers for every arm and states whether the ranking differs; where they
diverge it says whether the wall figure is inside the 2 Sep storage-bound
failure mode or clear of it; and it does NOT promote a wall crossover to a
shipping verdict without that check, because a disk number wearing a gate
number's label is worse than either.

**A work item falls out of this and is owed to the maintainer rather than answered here:**
if wall is to be the deciding metric for the row-gate constant, the 2 Sep
storage confound has to be retired first, and nobody has done that. That is a
measurement somebody must take, not an objection to the rule.

### The rule now carries this, so cite the rule and not this file

The hazard above was folded INTO the standing rule rather than kept as an
exception to it. Memory topic `nzbfast-wall-time-is-the-deciding-metric` now
carries a bullet naming this case: wall can be bounded by a DEVICE rather than
by the mechanism under study, which is a second confound distinct from load, and
the row gate's wall crossover cannot be promoted to a shipping verdict until it
is shown clear of the 2 Sep storage-bound failure mode.

The general form, which is the part worth carrying to other rounds:
**before a wall figure settles a constant, say what it is bounded BY.**

## The result

Held the box 19:55:07Z to 21:45:19Z, ONE sitting, four ladders, 80 legs, every
arm `rc=0` with 20 legs and `lock_waits=0` - so nobody took an inter-ladder gap.

Resident crossover at 4 MiB, n=4096, rungs 320/352/384/416/448, one rep:

| arm | mask | cores | class | thr | CPU | wall | first sitting (CPU) |
|---|---|---|---|---:|---:|---:|---:|
| `4m2-e4` | `0xF0` | 4-7 | E | 4 | **349** | 359 | 344 (and 343/346 before) |
| `4m2-e8` | `0xFF0` | 4-11 | E | 8 | **377** | 436 | 378 |
| `4m2-pe8` | `0xFF` | 0-7 | 4P+4E MIXED | 8 | **390** | >448 | - (new) |
| `4m2-t16` | none | 0-15 | MIXED | 16 | **401** | >448 | 398 |

### Item 1 - the pool step replicates, and the number wants restating

344 to 378 is +34; 349 to 377 is +28. Both are far outside the stated 3-to-7-row
envelope, on two independent sittings with separately built binaries and
fixtures. **The effect is confirmed. The number should be quoted as +28 to +34
rather than as +34**, which is what one sitting could support and two cannot.

### Item 2 - both terms are real, and the pool is the larger one

`0xFF` at t8 landed at **390** against `0xFF0`'s 377. That is **not** "near" it -
13 rows is about twice the envelope - but it is clearly smaller than the ~30-row
pool step. So the two effects are real and roughly separable:

- **doubling the pool within one class** moves the gate **~28 to ~34 rows**;
- **swapping half the pool from E to P at FIXED pool size eight** moves it a
  further **13 rows**.

The 13 is a **lower bound, and the bias is in the safe direction.** The `m=384`
fold leg on that arm ran with `foreign_cpu=126.3%` of a core and is the higher
of its A/A pair (242.44 against its twin's 233.34, which is the rung's 3.9%
floor). Contamination inflates *fold*, which raises F/T, which pulls the
crossing *down*. Re-reading that rung on the clean twin alone puts the arm at
**~401** rather than 390, so the class term is 13 to 24 rows and the reported 13
is the conservative end.

Sanity check against the first sitting: a **full** class swap at pool 4
(`4m-e4` 344 to `4m-p4` 381) was +37, and this **half** swap at pool 8 is +13 to
+24. Half of 37 is 18.5, which sits inside that interval. The two sittings agree
on the size of a P-for-E substitution.

This does not reassign the pool term. `e4` and `e8` are both pure-E, so class is
held fixed there *by construction*; what `pe8` adds is a second, independent
axis. The "one second rung serves both pools" clause is therefore void twice
over - pool size moves this gate by ~30 rows and placement moves it another
13-24 at fixed pool size.

### Monotonicity - read this before quoting any of the above

All three **sub-box** arms are monotone. **`4m2-t16` is not**, worst A/A floor
**11.0% at m=320**.

That is the **fifth** sitting of that arm and it has now been non-monotone in
**four of five**. The first sitting's monotone 398 is the outlier, and its
inference that the failure "is not reproducible and is not a property of the
configuration" **does not survive this sitting**. Its 401 is still quotable on
exactly the ground the first sitting's number was - the soft rung at 320 sits
well BELOW the crossing, and the rungs bracketing 401 are firm at 0.7% and 0.9% -
but the arm is not fixed.

One thing for item 3 (`parfast-t16-peak-vs-budget-17sep`), taken in passing and
not chased: `4m2-t16` peaked at **16,511 MB** here, against the other arms'
16,455-16,456 and against the **19,082 MB** the first sitting saw. So that arm's
peak is not stable across sittings either, which weakens the peak hypothesis as
stated - the one quantity that "visibly differs" did not differ this time, and
the arm still broke.

### Wall against CPU

The ranking is the **same** in wall as in CPU - no inversion - but the wall
crossover sits systematically **above** the CPU one and the gap **grows with the
pool**: +10 rows at pool 4, +59 at pool 8, and unbounded at the two widest arms,
whose wall crossings run off the top of the ladder and are therefore **lower
bounds and not measurements**.

The mechanism predicts that pattern across all four arms. **The fold parallelises
better than the forced transform**, so a wider pool penalises force more in
elapsed time than in CPU. Fold-over-force parallel efficiency at m=448:

| arm | thr | fold speedup | force speedup | ratio | wall - CPU |
|---|---:|---:|---:|---:|---:|
| `4m2-e4` | 4 | 3.85x | 3.75x | 1.027 | +10 |
| `4m2-e8` | 8 | 7.26x | 6.52x | 1.113 | +59 |
| `4m2-pe8` | 8 | 7.03x | 6.18x | 1.139 | >+58 |
| `4m2-t16` | 16 | 12.55x | 10.16x | 1.235 | >+47 |

Same ordering in the ratio as in the gap.

**These wall figures are NOT the 2 Sep storage-bound failure mode, and that was
checked rather than assumed.** A device-bound wall would be roughly invariant to
the core mix. The force-leg wall at m=448 is 31.77 s at `t16`, 39.51 at `pe8`,
46.21 at `e8` and 73.85 at `e4` - a 2.3x spread that tracks compute capability,
where a disk-bound reading would converge. Every leg ran `residency=resident`
with a 16.5 GB peak on a 31.4 GB box, so nothing paged, and `ffs_s` is
`feed+fold+solve`, a compute phase rather than a device term.

**The consequence, stated as a question for the maintainer and not as a decision taken
here:** if wall is the deciding metric, then a row-gate constant fitted to the
CPU crossover switches to the transform **earlier than wall-optimal** - by about
10 rows at four threads and about 59 at eight. Nothing in this round moves a
constant; this says only what the two metrics would choose differently.

**NO CONSTANT MOVED by this lane.**

## Scope of the parallelism claim, after a contradiction with the windowed-ask lane

The windowed-ask lane measured the OPPOSITE sign on the nibble class at 1 MiB,
n=8192, unpinned `-t12`: effective parallelism across m=192..512 of FORCE 9.33,
9.42, 9.58, 9.94, 9.91, 9.43 (rising) against FOLD 7.23, 6.97, 6.85, 6.73, 6.72,
6.66 (falling), with the transform 26.0% faster in wall at m=320 while costing
14.5% more CPU. Their wall crossover sits BELOW their CPU one; mine sits above.

**So the claim in this round is scoped, and stated as a property of THIS regime
rather than of the fold or the transform.** Per-rung efficiency here, from the
same legs:

| arm | m=320 | 352 | 384 | 416 | 448 |
|---|---:|---:|---:|---:|---:|
| `4m2-e4` fold/force | 1.014 | 1.025 | 1.038 | 1.027 | 1.027 |
| `4m2-e8` fold/force | 1.097 | 1.104 | 1.100 | 1.112 | 1.113 |
| `4m2-pe8` fold/force | 1.137 | 1.133 | 1.139 | 1.122 | 1.138 |
| `4m2-t16` fold/force | 1.213 | 1.250 | 1.206 | 1.250 | 1.235 |

**Two differences from their reading, and the second is the more interesting.**

1. **Sign.** The ratio is above 1 in every arm at every rung here: the fold
   parallelises better. Theirs is below 1 (7.23/9.33 = 0.775 falling to 0.706).
2. **Trend.** **Mine is FLAT in m** - e4 1.014 to 1.027, e8 1.097 to 1.113, pe8
   1.137 to 1.138, t16 1.213 to 1.235, with no monotone drift and no inversion
   anywhere. Theirs TRENDS, force rising while fold falls. So in this regime the
   fold-vs-force parallelism gap is a property of the POOL and not of m, which
   shifts the crossover by a roughly constant factor rather than bending the
   curve. That is a different shape of claim from theirs, not just a different
   sign, and it is the part most likely to be quoted out of regime.

**Where the two actually part company is the FOLD, not the force.** Normalising
to pool size on the two HOMOGENEOUS arms, which are the only ones where
`cpu/wall` is a clean parallel efficiency (the mixed arms span core classes that
differ by 1.71x, so dividing their speedup by a thread count is meaningless):

- `4m2-e4`, 4 E-cores: fold **96%** of pool, force **94%**.
- `4m2-e8`, 8 E-cores: fold **91%**, force **82%**.

Their force at 9.33-9.94 on 12 logical is **78-83%**, which sits right on this
round's `e8` force figure of 82%. Their fold at 6.66-7.23 on 12 logical is
**56-60%**, which is far below any fold measured here. **The force readings
agree; it is their fold that is the outlier**, so an explanation should be
looking at the fold's scaling and not at the transform's.

**A hypothesis that would explain it, offered as a hypothesis and NOT measured
here.** This part is **16C/16T** - `.claude/MACHINES.md` records the firmware
topology as 4 P (0-3), 8 E (4-11), 4 LP-E (12-15) with no SMT - so every thread
in every arm above had a physical core to itself. A 12-**logical** pool may well
contain SMT siblings sharing execution units. A compute-dense fold would lose to
sibling contention while a more latency-bound transform would gain from it,
which flips the sign of exactly this ratio and would put a fold at 56-60% of
logical pool while leaving force near 80%. **What would settle it** is the other
lane's physical-vs-logical core count, which costs nothing to look up and which
this round cannot see; if that box is 6C/12T, the two results stop
contradicting each other and become one story about SMT. Block size (4 MiB
against 1 MiB) and pinning are the other two candidate terms and are not
separated here either.

**Until one of those is done, neither result generalises.** Quote this one as:
*on GFNI-256 Core Ultra 9 386H, 16C/16T, at 4 MiB / n=4096, with the pool pinned
to homogeneous physical cores, the fold parallelises better than the forced
transform by 1.01x to 1.24x, flat in m.* Not as "the fold parallelises better".

### RESOLVED, same night: it was SMT, and the two results are one story

The lookup was made and the hypothesis above is **confirmed**. The other lane's
box is `intel-i5-10600kf`: **i5-10600KF, 6c/12t** (`.claude/MACHINES.md`, verified here
rather than taken on report). Their own description of their arms matches:
their `t4` is four threads on four physical cores with no sibling anywhere, and
their `t12` is twelve threads on six cores, so **every core carries a sibling**.

**So "widen the pool" meant physically different things on the two boxes.** This
part is 16C/16T, so `e4` to `e8` added four real physical E-cores. Their `t4` to
`t12` step *is* the SMT transition. There was never a reason to expect the two
to share a sign, and neither reading is wrong.

Their side corroborates the fold-is-the-outlier normalisation from their own
direction: at `t12` their **force** efficiency is flat to 0.5% across the whole
ladder (0.855 to 0.852) while their **fold** steps from 0.892 at m=128 to 0.600
at m=192. Sibling indifference in the transform, sibling contention in the fold -
which is exactly the pattern that put their fold at 56-60% of a logical pool
while leaving their force on top of this round's 82%. Their `t12` wall crossover
of 155 sits *inside* that m=128..192 interval where the fold's efficiency steps;
they explicitly do not claim causation off one ladder, and neither does this
note, but the coincidence is exact.

**What does NOT change: the flat-versus-trending difference stands, and it is
still the sharper warning.** SMT explains the *sign*. It does not make a
pool-constant factor and an m-dependent trend the same kind of claim. Here the
ratio is flat in m (1.01x to 1.24x, no monotone drift, no inversion), so the gap
shifts a crossover; theirs trends, so it bends the curve. A reader who takes the
SMT resolution as licence to pool the two numbers will still get a wrong
constant. Keep the scoped sentence.

### CORRECTION to the flat-versus-trending claim: my grid sits entirely above their knee

The claim two sections up - that this round's ratio is FLAT where theirs TRENDS,
and that this is "a different SHAPE of claim, not just a different sign" - **was
not a like-for-like comparison and is withdrawn in that form.**

The other lane decomposed its own curve rather than defending the word "trend",
and it is not a trend: it is a **knee followed by approximately flat**. Their
fold/force ratio at `t12` runs 128=1.043, 192=0.704, then 256=0.686, 320=0.671,
384=0.665, 448=0.655, 512=0.652. The full range is -37.5%, but **-0.339 of it
falls in the single interval m=128 to 192 - 87% of the entire drop.**

**Their rungs run 128-512. This round's run 320-448.** Every rung here is above
m=320, so their knee sits below this grid entirely. On the **matched window
320 to 448**:

| ladder | drift 320 -> 448 |
|---|---:|
| `4m2-pe8` | +0.09% |
| `4m2-e4` | +1.28% |
| `4m2-e8` | +1.46% |
| `4m2-t16` | +1.81% |
| their `t12` | -2.38% |
| their `t4` | -2.41% |

So on the rungs the two rounds share, **both are approximately flat** - this one
drifting slightly up, theirs slightly down, a residual of about 3 to 4 percentage
points. That residual is consistent in sign across all four arms here and both of
theirs, so it is probably real, but it is a modest difference in slope and **not
a different kind of claim.** What made it look like one was comparing their
knee-inclusive 128-512 range against this round's above-knee-only window.

**The limit this puts on THIS round, which is the part worth keeping: a ladder
sampled wholly above a knee reports flat whether or not one exists.** Nothing
here excludes a knee below m=320 on this part, because nothing here sampled
there. The other lane was careful to frame this as a bound on inference rather
than a claim about this part, and it is recorded the same way.

**The discriminator is two legs**: one rung at m=128 or m=192 on this round's
existing ladder shape. If the ratio is still ~1.0-1.2 there, this part genuinely
has no knee and the residual slope difference stands on its own. If it jumps,
both rounds were measuring the same shape through different windows. **Not run
here** - the box was already released and its root deleted, so the marginal cost
is a full rebuild and a 37.9 GB fixture rather than two legs. It is written into
the follow-on handoff for whoever next holds that part **with a fixture already
built**, where it really is two legs.

What survives unchanged: the SMT resolution of the sign, and the fold-is-the-
outlier normalisation, neither of which depends on the slope comparison.

### The knee question is now DECISIVE on this part, not merely open

Sharpened the same night. The obvious alternative reading - "the knee is a
property of the fold at small m whatever the pool", which would have made it not
about SMT at all - **is excluded by the windowed-ask lane's own existing data.**
`intel-i5-10600kf` is 6c/12t, so their `t4` is four threads on four physical cores with
no sibling anywhere: a no-SMT control on their own part. Step deltas in the
fold/force ratio, same fold, fixture, rungs and sitting: `t4` goes -0.063 then
-0.041/-0.022/-0.006/-0.017/+0.019, largest-over-next **1.6x**, no knee;
`t12` goes -0.339 then -0.017/-0.016/-0.005/-0.011/-0.003, largest-over-next
**19.8x**, a sharp knee. **The knee lives only in the wide arm.**

That leaves **two** candidates - SMT, or pool width - and their part cannot
separate them, because `t4` to `t12` moves both and adds two physical cores on
the way.

**This part settles it, and supplies its own control.** It is 16C/16T with no
SMT anywhere, so `4m2-e8` is **a wide pool with no siblings** - the cell neither
round has - and `4m2-e4` is the matching narrow arm at the same zero SMT. That
pair moves **pool width with SMT held fixed at zero**, which is exactly what
their arms cannot do. A knee in `e8` but not `e4` means pool width and the SMT
attribution is wrong; no knee in either means SMT is implicated and their reading
survives a test it could have failed.

Hence item 5 of the follow-on handoff is **eight legs across two arms**, not the
four this note first proposed, and it is decisive either way rather than
suggestive. Still not run here, for the reason given above: the box was released
and its root deleted, so the cost is a rebuild and a 37.9 GB fixture rather than
eight legs. It is folded into items 3 and 4, which both build one.
