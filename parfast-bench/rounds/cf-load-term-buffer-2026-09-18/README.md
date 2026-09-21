# Does a co-tenant's CACHE FOOTPRINT move `c_f` at a FIXED CPU level?

Lane `cf-load-term-buffer-and-placement-18sep`, gen `4ddfcf76`, on intel-i5-10600kf
(i5-10600KF, 6c/12t, AVX2 without GFNI = the nibble class). The three
"Owed after this lane" bullets of the within-sitting drift census
(an internal note, the 18 Sep drift section).

**Status: everything in this file except the Result section was written and
landed BEFORE the sitting's numbers were reduced.** The question, the arm
order, the equal-n rule, the topology, what confirms and what refutes, and the
guard on what the round does not license are all fixed in advance and none of
them is fitted to the outcome. That is the practice `crpool4m`, `crband` and
`crpin4m` used, and it is why their conclusions held when their numbers would
have allowed stronger claims.

## The question

The banked load round measured a synthetic co-runner moving `c_f` by **+20.0%
at `-t12`** for +66 points of foreign CPU, extrapolated that to the 16 Sep
sitting's own +55 points, and got **+16.7% against +34.6% observed** - so load
explained 48% and **the other 52% was left open with no evidence to rank
candidates**. The drift census then ranked three candidates and put this one
first.

`rounds/cf-load-term-2026-09-16/loadgen.ps1` line 5 is
`[int]$BufKiB = 4096`, and the comment at lines 39-41 says the 4 MiB default is
"a third of" this part's 12 MiB L3, **chosen deliberately as a realistic
neighbour rather than a pathological thrasher**. So the banked coefficient was
measured against a co-runner that never leaves cache and is close to a pure-ALU
spin. The 16 Sep co-tenant that produced the excursion was Adobe's updater,
which does file I/O and touches far more memory **at the same CPU cost**.

**The hypothesis is therefore not "load matters" - that is measured - but that
`foreign_cpu` IS THE WRONG INDEPENDENT VARIABLE.** It counts a co-tenant's CPU
and says nothing about its cache and memory footprint, and the two co-tenants
being compared differ in footprint by construction, because the synthetic one
was deliberately sized to fit in L3.

## What confirms it, and what refutes it, fixed in advance

**CONFIRMS**: the same ~66 points of foreign CPU buy a substantially larger
`c_f` excursion at a buffer above L3 than the banked +20.0%, and it concentrates
at m = 2,048 and m = 4,096 rather than spreading across the rungs. The census
found the bottom three rungs agree to 1-3% across four sittings, two binaries
and four days, **so a mechanism that moves them is NOT this one** and a result
that moved them would be evidence of something else having gone wrong.

**REFUTES**: the bigger buffer buys little more than 4 MiB did. That is a real
result and it sends the residual back to candidates 2 and 3. It is to be
reported plainly and not softened.

**NOT DISTINGUISHABLE**: this sitting's own noise floor is the bar. The census
puts it at **8% at a full pool and 11% at `-t4`/`-t6`**, and this round
measures its own with three quiet legsets. An effect inside that band is not a
measurement, and the honest report is "not distinguishable from drift".

## The design

**Fifteen legsets, one sitting.** Phase A runs first because it is the decisive
one and a sitting that dies halfway should die with phase A banked.

### Phase A - the buffer sweep (item 1)

`q1 b4a b24a b96a qm b96b b24b b4b q2`, 64 KiB fixture, `-Reps 1 -Threads 4,12`.

**The only thing that moves between loaded arms is `-BufKiB`.** Same target
percent (72 of one core, closed-loop against the generator's own
`TotalProcessorTime`), same access pattern, same stride. 4,096 KiB is the
CONTROL and is the banked default; **24,576 is 2x L3 and 98,304 is 8x L3**.
Three points rather than one because **a monotone response in buffer size at
fixed CPU is much stronger evidence than a single point**, and it is the same
legset cost each time.

**The access pattern is NOT touched.** Changing stride or randomising the walk
would move two things at once and break the comparison with the banked 4 MiB
coefficient, and `-BufKiB` is precisely the parameter the census's check names.

**The order is a MIRROR and it is load-bearing rather than tidy.** The
two-binary sitting drifted monotonically 7.6% CPU / 8.2% wall across 40 minutes
with nothing changed, and its A-B-B-A order is the only reason its result
survived. A mirror cancels a linear drift in the mean of each buffer's pair.
Quiet legsets at BOTH ends AND in the middle: the load lane's whole `-t4` arm
was withdrawn because its single closing quiet legset did not land back on its
opening one, and three quiet points give a drift CURVE where two give a gap.

**The arm units are EQUAL-n, and that is not cosmetic.** `wcombsum.best()`
selects the MINIMUM-CPU leg per rung, so a three-legset quiet unit read against
two-legset loaded ones would bias the quiet arm down and **inflate every ratio
printed against it**. `qm` is held out of the arm table and used only for the
drift curve; the per-legset table carries the same comparison free of that bias.

### Phase B - pinned against unpinned at a narrow pool (item 2)

`u1 p55a pFa pFb p55b u2`, `-Reps 2 -Threads 4`, no load at all.

**The topology was READ, not assumed** (`GetLogicalProcessorInformation`):
cores pair as (0,1) (2,3) (4,5) (6,7) (8,9) (10,11), so **`0x55` is four
DISTINCT physical cores and `0xF` is four threads sharing TWO cores as SMT
siblings**. Both are run because they BRACKET whatever an unpinned pool gets.

**COMPARE THE SPREADS, NOT THE LEVELS.** Pinning moves the level too - a
P-core second and an SMT-sibling second buy different work, which is
`wcomb.ps1`'s own documented rule - and the level is not the question. The
unpinned arm runs at the same cadence inside the same block, because a spread
measured over a 60-minute span is not comparable with one measured over 15.

### Item 3 is NOT in this driver, deliberately

Item 3 edits `wcomb.ps1`, which makes a NEW instrument. Every leg here runs on
the harness **pinned at `07a24a959`** so it can be read against the banked
corpus, and item 3 was done afterwards on a separate root
(`cfpwr18sep`, `pwr.log`). Not one leg in phase A or B is measured on the
edited harness. That is why the two halves of this lane carry different harness
hashes rather than one.

## The instrument

| | |
|---|---|
| binary | `8983A55A4E260BA3...` = origin/main `4fedd8b33`, the SAME SOURCE COMMIT the banked load round built from, reused off `wcomb-16sep` rather than rebuilt |
| fixture | `wcomb-16sep`'s 64 KiB set, n = 16,384, COPIED into this lane's root (legs damage and restore slices; three rounds now read that one) |
| harness | pinned `07a24a959`: `plib.ps1` `20CB3299332113BD`, `wcomb.ps1` `60DED61D70BC4ABD`, both verified against the banked hashes BEFORE staging |
| generator | `loadgen.ps1` `9698D5DEB71A399D`, **byte-identical** to the banked round's |
| rungs | m = 192, 512, 1024, 2048, 4096 - a free parameter of every `c_f`, so no figure here is comparable with one fitted on another set |

`foreign_cpu` is the **PRE-`9686ac296`** definition, the same as the banked
round's: comparable with it, and with nothing taken after that commit.

## The rig protocol, and one gap this lane did not close

The **acquire-then-load** pattern is inherited verbatim from `cfload.ps1`: the
lock is probed free with NO generator alive, released, and only then is the
load started and the legset entered, with a short retry budget so a lost race
costs seconds of somebody else's box rather than minutes. The residual is the
sub-second gap between that release and `wcomb`'s own `CreateNew`. **Narrowed
to that floor, not closed.**

**Claim `riglock-waiter-blind-to-late-arrivals` is open about THIS box and this
lane does not fix it.** A waiter's ahead-list is fixed at arm time and
`Test-BoxFree`'s census names parfast, cargo and rustc only, so a lane arriving
later - or any non-cargo tool - is invisible twice over, and on 18 Sep a driver
took this lock inside another lane's claimed window. This round took the box
with the lock absent, no parfast/cargo/rustc alive and a `DONE` as the last
coordination line, and it logs a **wider census before every legset** (the lock
holder's own text, plus the top six foreign processes by CPU) so a cell taken
under a neighbour is identifiable afterwards rather than merely wrong. **That
is visibility, not exclusion**, and the claim stays open.

## What this round cannot license, whatever it finds

**NO CONSTANT MOVES.** Not `NTT_WINDOW_COMBINE_X86`, not any
`NTT_MIN_MISSING*`. `crates/` is untouched by items 1 and 2 whatever they find.

**No coefficient measured here is a correction factor and no banked cell may be
retro-corrected from one.** That rule is the banked load round's and it applies
harder here, not less: this round's whole finding, if it confirms, is that the
coefficient depends on a property of the co-tenant that `foreign_cpu` does not
measure - which is an argument that **no** single coefficient transfers between
co-tenants, including any of this round's own.

## Result

**ITEM 1 IS CONFIRMED, AND NOT IN THE SHAPE THE CHECK PREDICTED.** A co-tenant
whose working set exceeds L3 moves `c_f` substantially more than one that fits
inside it **at the same CPU cost** - but the response does NOT scale with
buffer size. It **saturates at L3**: 24 MiB and 96 MiB are indistinguishable
from each other and both are far above 4 MiB.

**Phase A: nine legsets, 198 legs, every one `rc=0` and `restored=16/16`, zero
failures.** Per-legset `c_f` against the sitting's own quiet baseline, in run
order, in BOTH metrics fitted like for like:

| legset | buffer | foreign | `c_f` CPU | `c_f` WALL |
|---|---|---:|---:|---:|
| `q1` | - | 19% | (baseline) | (baseline) |
| `b4a` | 4 MiB | 88% | +18.9% | +18.3% |
| `b24a` | 24 MiB | 88% | +27.4% | +26.6% |
| `b96a` | 96 MiB | 81% | +28.3% | +28.0% |
| `qm` | - | 21% | **+1.2%** | +1.0% |
| `b96b` | 96 MiB | 83% | +22.2% | +21.7% |
| `b24b` | 24 MiB | 85% | +30.5% | +30.2% |
| `b4b` | 4 MiB | 80% | +18.5% | +18.7% |
| `q2` | - | 17% | **+0.0%** | +0.3% |

(`-t12`. The `-t4` column runs +16.9, +28.2, +30.7, [+1.4], +23.1, +26.6,
+16.7, [+3.0] and says the same thing independently.)

### The sitting is the quietest in the corpus, and that is what makes the rest readable

**`q2` lands back on `q1` to +0.0% in CPU and +0.3% in wall at `-t12`, and the
mid-sitting `qm` is +1.2%.** At `-t4` the three quiet legsets span 3.0%. The
load lane's whole `-t4` arm was withdrawn because exactly this check failed
there (+6.8%); here it passes at both pools, against census bars of 8% (full
pool) and 11% (narrow). **So no arm below is drift-corrected, because there is
almost no drift to correct** - and the mirror order was still what made that
knowable rather than assumed.

### The separation, which is the finding

| pool | in-L3 (4 MiB) | above L3 (24 + 96 MiB) | gap |
|---|---:|---:|---:|
| `-t12` | **+18.7%** | **+27.1%** | 8.4 pts |
| `-t4` | **+16.8%** | **+27.1%** | 10.3 pts |

**At both pools, independently, all four above-L3 legsets exceed both in-L3
legsets with NO OVERLAP** - the gap between the worst above-L3 legset and the
best in-L3 one is 3.3 points at `-t12` and 6.2 at `-t4`. The two in-L3 legsets
agree to **0.4 points at `-t12` and 0.2 at `-t4`**, which is the tightest pair
in the sitting and is what makes the comparison carry.

**The 4 MiB control REPLICATES THE BANKED COEFFICIENT**, which is the check
that licenses reading any of this against the banked round: +18.7% here
against the banked **+20.0%**, on the same source commit, the same fixture,
the same rung set and a harness pinned to the same two hashes.

### `foreign_cpu` IS the wrong independent variable, quantified

Normalising each legset by its own points of foreign CPU over the quiet
baseline - which is the comparison the census's candidate 1 actually names:

| pool | in-L3 | above L3 | ratio |
|---|---:|---:|---:|
| `-t12` | 0.289 %/pt | 0.416 %/pt | **1.44x** |
| `-t4` | 0.259 %/pt | 0.417 %/pt | **1.61x** |

**The same point of foreign CPU buys about half again as much `c_f` when the
co-tenant's working set leaves L3.** The cleanest single cell is `b96a`, which
delivered a LARGER excursion (+28.3%) than `b4a` (+18.9%) while reading LOWER
foreign CPU (81 against 88): more slowdown for less of the quantity that was
supposed to be the independent variable.

### It SATURATES at L3 - the prediction that was wrong, and why the miss matters

The check was written expecting a **monotone response in buffer size**, and
said so: "a monotone response in buffer size at fixed CPU is much stronger
evidence than a single point". It is not monotone. At `-t12` the arm means are
+18.7 (4 MiB), +29.0 (24 MiB), +25.3 (96 MiB); at `-t4`, +16.8, +27.4, +26.9.
**24 MiB and 96 MiB cannot be told apart** - their own pair spreads are 3.1 and
6.1 points at `-t12`, larger than the difference between them.

**That is a better result than monotonicity would have been, and the round
should not be read as having half-missed.** A cache-eviction mechanism predicts
a step, not a ramp: once the co-runner's working set exceeds the 12 MiB L3 it
evicts the whole of it on every pass, and making it four times larger still
cannot evict more than all of it. A response that kept growing to 96 MiB would
have pointed at memory BANDWIDTH rather than cache residency. The step at L3 is
the sharper mechanistic claim, and it was found because three buffer sizes were
run instead of the one the check asked for.

### Where it lands in the rungs

Pre-registered: the excursion should concentrate at m = 2,048 and m = 4,096,
and a mechanism that moved the bottom three rungs would NOT be this one.

**Half-met, and the half that failed is in the conservative direction.** At
`-t12` the bottom three rungs agree to within about 3% across every arm
(+2.5/+3.0/+3.3 at m=192, +0.5/+0.7/+1.4 at m=512, -0.1/-0.0/+1.0 at m=1024),
so the mechanism does not touch them - as required. But **m = 2,048 does not
separate the arms either** (+5.4/+5.9/+5.4): the entire difference between
buffers lives at **m = 4,096 alone** (+16.8 / +25.0 / +20.3). At `-t4` both top
rungs carry it, but that pool's bottom rungs swing +-7 to 9% and are not worth
reading. So the effect is narrower than predicted, not broader.

### What it does to the "other 52%"

| | points of foreign CPU | predicted `c_f` | of the observed +34.6% |
|---|---:|---:|---:|
| banked 4 MiB coefficient (0.303 %/pt) | 55 | +16.7% | 48% |
| this round, in-L3 (0.289 %/pt) | 55 | +15.9% | 46% |
| **this round, above L3 (0.416 %/pt)** | 55 | **+22.9%** | **66%** |

**Load with a realistic footprint explains about two thirds of the 16 Sep
excursion rather than about half.** The residual falls from a factor of 1.153
to **1.096, i.e. 9.6%**, against a full-pool drift bar of 8% - so what is left
is now the same size as the drift the census already measured, where before it
was twice that. The two known mechanisms together very nearly close the
excursion.

**THEY DO NOT CLOSE IT, AND THIS IS NOT A CORRECTION FACTOR.** 9.6% is above
8%, not inside it, so a gap remains. And the round's own finding is the reason
no coefficient here may be applied to the 16 Sep sitting as a correction:
**if the co-tenant's footprint changes the coefficient by 1.44x, then no single
coefficient transfers between co-tenants - including any of this round's own.**
Adobe's updater is not this generator either; it does file I/O, which this
generator does not do at all. The honest claim is directional - `foreign_cpu`
undercounts a co-tenant that leaves cache, by roughly half again on this part -
and not a number to subtract from a banked cell.

**NO CONSTANT MOVED.** `NTT_WINDOW_COMBINE_X86` stays at 312, no
`NTT_MIN_MISSING*` moves, and `crates/` is untouched.

## ITEM 2 and ITEM 3

Both are written up in full in the campaign document's section of the same
date, an internal note. In brief: pinning a
4-thread pool collapses its legset-to-legset `c_f` spread from **7.0% to
0.3%**, and the two placements such a pool can get differ by **43.6%** in
level, so the narrow-pool drift the census measured is PLACEMENT. And
`wcomb.ps1` now records per-leg frequency and thermal state, with `pkg_w`
reading `na` because Windows does not surface Intel RAPL to user mode on any
box of this fleet without a kernel driver.
