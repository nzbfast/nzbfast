# The create's PROPORTIONALITY BAND, priced on PINNED arms where it can be aimed at

Lane `parfast-pinned-band-ladder-4mib`, **item 1** of
an internal note.

**Status: RAN AND COMPLETE.** One sitting, five ladders, 144 legs, all `rc=0`. Everything
above that section, and the whole of `crpin-round.ps1`'s header, was written and
**landed on origin (`a229b74be`) BEFORE the box was taken** - the question, the
ladder table, the forced ordering, the harness argument, the spent first rung,
and the guard on what the round does not license. None of it is fitted to the
numbers. This is the practice `crpool4m` and `crband` both used and it is why
their conclusions held when their numbers would have allowed stronger claims.

## The question

the maintainer's wall-time rule (memory topic `nzbfast-wall-time-is-the-deciding-metric`)
carries a limit: wall wins a disagreement *"unless there's something excessive
and it's an extremely unfair trade, like, 10x the cpu for a little bit better
wall"*. **The band between the CPU crossover and the wall crossover is the only
region where the two metrics disagree**, so it is the only region where that
limit can ever bite. It has never been priced on the create path.

Two rounds have tried, and both failed for the same reason from opposite
directions:

| round | what it did | why it missed |
|---|---|---|
| `crpool4m` (17 Sep) | 32-row rung grid, five arms | its bands are 6-24 rows, so **every band fell between measured rungs**. CPU and wall agreed at every rung it measured - an artefact of the grid, not a finding |
| `crband` (18 Sep) | 8-row rungs on crpool4m's widest band | **the band moved.** In crband's own sitting that arm's band was [359, 394] and the ladder sat mostly above it |

**The second failure is what makes this round possible.** crband measured the
reason rather than guessing it: on an **unpinned** arm the band's *location*
moves 30 rows between sittings while the band itself is 6-35 rows wide, so it
cannot be aimed at. **Pinned arms replicate within 5 rows** (repair path, two
sittings: 344->349, 378->377, 398->401). So the order of operations is **pin,
then find the band, then place the fine rungs** - and the finding step has to
happen *in this sitting*, because "replicates within 5" is a claim about 5 rows
and the rung spacing here is 4.

## The cell

- **Box** intel-core-ultra-9-386h (Core Ultra 9 386H, GFNI-256, 4 P cores 0-3, 8 E cores
  4-11, 4 LP-E cores 12-15, 31.4 GB, Windows 11). The fleet's only GFNI-256
  part, so no other box substitutes.
- **Binary** parfast from `06d5734b7`, gated on its **4,173,312-byte COUNT and
  never on a sha256** - the build embeds its own path, so the hash differs per
  root by construction.
- **Fixture** 16 x 1,024 MiB at 4 MiB blocks, `-c640`: n = 4,096, a 16 GiB
  corpus - the shape all six banked 4 MiB rounds used. n = 4,096 clears the x86
  input floor of 2,048 on its own, so no rung here can fall through to the fold.
- **Ladders** five, `-Phase create`, `fold force force2 fold2` at every rung,
  one rep, `-Residency resident`, `-NttBudget` 20 GiB, `-Slice 4194304
  -MemberMiB 1024 -Recovery 640`, a distinct `-Label` each:

  | # | label | mask | cores | threads | rungs | what |
  |---|---|---|---|---|---|---|
  | 1 | `4mcp-warm` | none | all 16 | 16 | 288,320,352,384,416 | **UNPINNED - builds the fixture.** m=288 spent as a warm-up rung |
  | 2 | `4mc-e8` | `0xFF0` | 4-11 | 8 | 288..512 | replicate crpool4m CPU 393 / wall 409, **and locate this arm's band here** |
  | 3 | `4mc-p4` | `0xF` | 0-3 | 4 | 288..512 | replicate crpool4m CPU 394 / wall 410, **and locate this arm's band here** |
  | 4 | `4mc-e8-fine` | `0xFF0` | 4-11 | 8 | **computed from ladder 2** | **the deliverable** - 4-row rungs across the band `4mc-e8` actually has |
  | 5 | `4mc-p4-fine` | `0xF` | 0-3 | 4 | **computed from ladder 3** | **the deliverable** - 4-row rungs across the band `4mc-p4` actually has |

### The ordering is FORCED, unlike crband's

`-Affinity` arms every leg **including the fixture create**, so a pinned ladder
cannot run first. Ladder 1 is unpinned and builds the fixture. Its numbers are a
bonus - it adds a fifth reading to the four banked unpinned `-t16` create
crossovers, which span 30 rows and which crband established are not a measurable
quantity at this resolution. **Nothing in this round rests on it.**

**Its first rung is spent on purpose.** Three of three fixture-building ladders
in this campaign show a warm-up ramp confined to the first rung, with A/A floors
of 9.6% / 15.7% / **35.5%** against 0.1-2% typical. crband put its first rung
*inside* the region it was measuring and lost it. m=288 is far below every
banked unpinned `-t16` crossover (357, 359, 365, 387), so the ramp lands on a
rung nothing depends on. Note the ramp is a property of **building the fixture**,
not of being first - crband's own finding is that no other ladder shows it - so
ladders 2-5 do not discount their bottom rungs.

### Ladders 2 and 3 do two jobs, which is why they cannot be cut

1. They **replicate** crpool4m's pinned *create* crossovers on the same grid,
   testing the 5-row pinned-replication claim **on the create path** - it has
   only ever been shown on the repair path.
2. They **locate each arm's band in this sitting**, which is what ladders 4 and
   5 are aimed off.

Cutting 2 or 3 does not save a deliverable, it destroys one.

### The band step, and why it is a script

`bandplan.py` (this directory) runs **on the box**, between ladder 3 and ladder
4, and places the fine rungs from the crossovers ladders 2 and 3 just wrote -
minutes earlier, on the same fixture, in the same sitting. **4-row spacing and
not 8**: crpool4m's pinned bands are 16 rows and an 8-row grid fits only two
rungs in 16.

**It refuses rather than guesses.** `rowgate.py`'s `cross()` returns a bare
`<N`, `>N` or `?` when a ladder never crossed in range; a fine ladder placed off
one of those is aimed at nothing. `bandplan.py` then prints `REFUSE`, the driver
**skips that fine ladder**, and the round record says which and why. **It never
falls back to crpool4m's band** - aiming at a banked band is the exact move that
cost crband its ladder.

It was validated on the Mac before the sitting against crpool4m's own `cre8.log`
and `crp4.log`, where it reproduces the published bands (393/409 and 394/410,
16 rows each) and places 8 rungs at 4-row spacing across each.

## The harness, checked rather than assumed

**This round uses a NEWER harness than the round it is replicating**, which is
the class of defect this campaign keeps finding, so it was diffed rather than
trusted. Eight commits touch `plib.ps1`/`wcomb.ps1` between crpool4m's
`e1731b0ee` and this round's tip.

- **`Invoke-Leg` - the function that produces `wall` and `cpu` - is BYTE-
  IDENTICAL** between the two (function-body sha `a70460e39b66` on both sides),
  and so is `Measure-ForeignDelta`. This is a **stronger** statement than crband
  could make about its own harness delta: crband argued its delta could not
  reach an *unpinned* leg because the affinity block is guarded by
  `if ($affWant)`. A byte-identical timing function covers **pinned** legs too,
  which is what this round runs.
- wcomb's delta is entirely (a) `-Rungs`/`-Threads` validation before the rig
  lock, (b) a `-Residency`/`-Phase measure` refusal - neither of which this
  round trips - (c) the create-path affinity readback assert, which fires
  *after* the leg and **refuses** it rather than changing the work it did, and
  (d) two new LEG fields plus an exception log.
- **What does differ:** `Get-OwnPidTree` was refactored into
  `Resolve-OwnPidSet`, which is the own-pid set feeding **foreign-CPU
  accounting**. So `foreign_cpu` here is not a like-for-like instrument with
  crpool4m's and is quoted **within this sitting only**.

**The pins are ASSERTED, and crpool4m's were not.** `Run-Create` got the
affinity readback assert in `3bbe3d94d`, so every pinned LEG line carries
`affinity=` and `affinity_got=` and wcomb refuses the leg on a mismatch.
crpool4m had to argue its pins from timings, and every pinned create round
repeated that argument until this landed. The driver additionally **counts** the
readbacks per ladder (`AFFINITY-AUDIT`) rather than inferring them from the
absence of a failure, because a harness older than `3bbe3d94d` would emit no
`affinity=` field at all - the silent-wrong case.

## What this round does NOT license, committed to IN ADVANCE

**NO CONSTANT MOVES.** The rung decision - 384 against 416 against
`create_ntt_min_rows` taking its own clause at ~372 - is **the maintainer's**, it is open,
and five lanes have now measured inputs without moving anything. This is the
sixth. No sentence here may be read as a decision having been taken, and
anything downstream citing it as "384 ships" is citing it wrongly.

**A PRICED BAND IS NOT A CHOSEN RUNG.** A ratio under 10x does not say a rung is
right; it says the proportionality limit does not **exclude** it. Those are
different claims and only the second is this round's.

**AN UNRESOLVED BAND IS NOT A CLEAN BILL.** A narrow band means small
differences, so rungs coming back inside their own A/A floors is the **expected**
case, not a failure. The honest statement is then "the trade cannot be priced at
this resolution on this part" - **not** "the trade is small", and **not** "the
metrics agree". No tolerance is widened to manufacture a verdict.

**A PINNED BAND IS NOT AN UNPINNED ONE.** Whatever ratio comes out is a ratio
for a pinned arm on a fixed core mix. crpool4m measured placement *alone*
swinging the create crossover 27 rows at fixed pool size, so these figures do
not transfer to a machine running unpinned - which is every user.

**REPLICATION IS A TWO-SITTING CLAIM.** If ladders 2 and 3 land within 5 rows of
crpool4m's, that is **one** independent repeat on the create path. It is not a
general claim that pinned create arms are stable, and **one sitting is not a
replicate**. More reps cannot firm a rung: the A/A floor is a MAX over reps.

**ONE PART, ONE PAYLOAD, ONE BLOCK SIZE.** Core Ultra 9 386H, random bytes,
4 MiB, n = 4,096.

## Reading rules this round is held to

- **WALL DECIDES, CPU EXPLAINS.** Both crossovers are quoted on every table and
  any divergence is named with its size.
- **CPU-SECONDS DO NOT COMPARE ACROSS MASKS** - P/E is ~1.72-1.74x on this part,
  so an 8 E-core arm burning more CPU than a 4 P-core arm is not doing more
  work. Only the **crossover** compares across arms.
- **A tight A/A floor is agreement, not correctness.** Every ladder is screened
  with `pinaff4m-2026-09-16/ladder-monotonicity-audit.py`, and the rungs
  **bracketing** each crossing are checked for firmness - **and**, per crband,
  the bracketing rung's own distance from `F/T = 1` must exceed that rung's A/A
  floor, a second test three of four banked unpinned readings **fail**.

## Files

| file | what |
|---|---|
| `crpin-round.ps1` | the driver: load gates, class probe, extract, build, byte gate, per-ladder ARGV, affinity audit, the band step, rc=17 retry |
| `bandplan.py` | places the fine rungs from a coarse ladder's own log; REFUSES rather than falling back to a banked band |
| `crpin-driver.log` | the driver's own log |
| `logs/cpwarm.log` | ladder 1, unpinned `-t16`, builds the fixture |
| `logs/cpe8.log` | ladder 2, mask `0xFF0`, `-t8`, crpool4m's grid |
| `logs/cpp4.log` | ladder 3, mask `0xF`, `-t4`, crpool4m's grid |
| `logs/cpe8f.log` | ladder 4, mask `0xFF0`, `-t8`, 4-row rungs across ladder 2's band |
| `logs/cpp4f.log` | ladder 5, mask `0xF`, `-t4`, 4-row rungs across ladder 3's band |

## Result

**RAN AND COMPLETE.** One sitting on intel-core-ultra-9-386h, **10:59:05Z-13:11:32Z** on
18 Sep 2026, five ladders, **144 legs, every leg `rc=0`, `lock_waits=0` on all
five**, binary gated at 4,173,312 bytes from `06d5734b7`. `cpwarm` 20 legs
(including the 16 GiB fixture create and its settle), `cpe8` 32, `cpp4` 32,
`cpe8f` 32, `cpp4f` 28. Nothing excluded, nothing re-measured. Box released and
the root deleted; 37.8 GB.

**In one paragraph.** The create's proportionality band is **priced**, for the
first time on that path. On the pinned eight-E-core arm the trade **degrades
steeply across the band - 0.2x, 3.2x, 5.0x, 6.9x** - and **6.9x is the largest
honestly-priced create trade on record**, against a prior complete set of 0.1x,
1.8x, 1.9x and 3.2x. It **approaches the maintainer's 10x limit without reaching it**, so
the limit still excludes no rung. This was only aimable because the pinned arms
**replicated crpool4m's create crossovers within 2-6 rows** two days apart, which
carries the 5-row pinned-replication claim onto the create path for the first
time. Two rungs inside the band came back **unresolved**, which is the expected
case and is reported as a refusal. The p4 arm is **non-monotone in both its
ladders**, replicating crpool4m's finding about that same arm, and `cpe8f`'s
**wall crossover never crossed by its top rung**, so that ladder is not quotable
for wall. No constant moved.

### 1. THE DELIVERABLE: the band is priced, and the trade degrades steeply

`4mc-e8-fine`, mask `0xFF0`, eight E-cores, **monotone**, 4-row rungs placed
from this sitting's own coarse log:

| m | cpu F/T | wall F/T | cost% | gain% | aa_cpu | aa_wall | **ratio** |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 392 | 0.991 | 0.946 | -0.9 | +5.4 | 0.9 | 1.2 | agree |
| 396 | 0.993 | 0.951 | -0.7 | +4.9 | 1.1 | 0.9 | agree |
| 400 | 1.007 | 0.962 | +0.7 | +3.8 | 0.5 | 0.1 | **0.2x** |
| 404 | 1.020 | 0.979 | +2.0 | +2.1 | 1.9 | 2.1 | **unres** |
| 408 | 1.022 | 0.976 | +2.2 | +2.4 | 2.5 | 2.5 | **unres** |
| 412 | 1.034 | 0.989 | +3.4 | +1.1 | 0.2 | 0.4 | **3.2x** |
| 416 | 1.036 | 0.993 | +3.6 | +0.7 | 0.7 | 0.6 | **5.0x** |
| 420 | 1.042 | 0.994 | +4.2 | +0.6 | 0.4 | 0.6 | **6.9x** |

**The degradation crpool4m observed by hand is real and is now measured on a
ladder built for it.** The mechanism is visible in the columns: `cost` rises
slowly and monotonically (+0.7 to +4.2) while `gain` **collapses** (+3.8 to
+0.6) as the wall crossover is approached. The ratio is a quotient whose
denominator is going to zero, which is exactly why it blows up at the top of the
band and exactly why the wall A/A floor `band-trade.py` adds is load-bearing:
at 420 the gain is +0.6% against a 0.6% floor, so **420 is the last rung that
can be priced at all** and the next one up would be unresolvable by construction.

**Two rungs are UNRESOLVED and that is the designed outcome, not a gap.** At 404
and 408 both sides of the ratio sit inside their own A/A floors (+2.0 against
1.9, +2.1 against 2.1; +2.2 against 2.5, +2.4 against 2.5). Per the commitment
above this is reported as *the trade cannot be priced at this resolution on this
part at those rungs* - **not** as a small trade and **not** as the metrics
agreeing. A narrow band means small differences, so this was expected.

`4mc-p4-fine`, mask `0xF`, four P-cores - **and this ladder is NON-MONOTONE, so
every figure in it carries that flag**:

| m | cpu F/T | wall F/T | cost% | gain% | **ratio** |
|---:|---:|---:|---:|---:|---:|
| 404 | 1.005 | 0.975 | +0.5 | +2.5 | **0.2x** |
| 408 | 1.018 | 0.987 | +1.8 | +1.3 | **1.3x** |
| 412 | 0.984 | 0.954 | -1.6 | +4.6 | agree **(the dip)** |
| 416 | 1.036 | 1.003 | +3.6 | -0.3 | agree |

The m=412 cell reverses direction between 408 and 416 at floors of 0.4% and
0.6%. **A tight floor is agreement, not correctness** - this is the case that
rule exists for, and it is why the monotonicity screen is run as well as the
floor. The p4 numbers are reported but should not be read against the e8 ladder
rung for rung.

### 2. The pinned arms REPLICATED, which is what made the aiming possible

| arm | crpool4m 17 Sep | this sitting | CPU apart | wall apart |
|---|---|---|---:|---:|
| `4mc-e8` `0xFF0` | CPU 393 / wall 409 | **CPU 396 / wall 415** | 3 | 6 |
| `4mc-p4` `0xF` | CPU 394 / wall 410 | **CPU 396 / wall 412** | 2 | 2 |

**Two days apart, a different fixture instance, a different harness build, and
three of the four readings are inside 3 rows.** The repair path's 5-row pinned
replication (344->349, 378->377, 398->401) now has a create-path counterpart.
Set against the unpinned full-box arm's **30-row** spread across four sittings,
this is the whole reason a fine ladder could be aimed at all - and it is the
prerequisite crband identified without being able to test.

The wall reading on `4mc-e8` is 6 rows out, marginally outside the 5-row claim,
and section 5 gives a reason to think coarse wall crossovers are the softest
quantity here.

### 3. The pins are ASSERTED, not argued

**All 124 pinned legs carry `affinity=` and `affinity_got=` and read them back
EQUAL** - `cpe8` 32/32 at `0xFF0`, `cpp4` 32/32 at `0xF`, `cpe8f` 32/32,
`cpp4f` 28/28. crpool4m had to argue its pins from timings and every pinned
create round repeated that argument until `3bbe3d94d` landed. This one reads
them back, and the driver **counts** the readbacks per ladder rather than
inferring them from the absence of a failure, because a harness older than that
commit would emit no `affinity=` field at all.

The class probe also confirmed the premise the `0xFF0` mask rests on: P-core0
7.805 s against E-core4 13.513 s (**P/E = 1.731**, matching the documented
1.72-1.74x), and **E-core8 at 13.568 s matches E-core4 to 0.4%**, so cores 4-11
are one class and `4mc-e8` is a within-class pool rather than a mixed one.

### 4. Screening: what is firm and what is not

`bracket-firmness.py` (this directory), both tests, both metrics:

| ladder | metric | crossing | lower bracket | upper bracket | verdict |
|---|---|---:|---|---|---|
| `4mc-e8` | CPU | 396 | 384: 3.1% vs 1.8% firm | 416: 5.1% vs 1.5% firm | **FIRM both sides** |
| `4mc-e8` | wall | 415 | 384: 7.2% vs 1.8% firm | 416: 0.2% vs 1.2% **INSIDE** | rests on noise |
| `4mc-p4` | CPU | 396 | 384: 2.3% vs 0.5% firm | 416: 3.8% vs 0.1% firm | **FIRM both sides** |
| `4mc-p4` | wall | 412 | 384: 5.5% vs 0.6% firm | 416: 0.7% vs 0.2% firm | **FIRM both sides** |
| `4mc-e8-fine` | CPU | 398 | 396: 0.7% vs 1.1% **INSIDE** | 400: 0.7% vs 0.5% firm | rests on noise |
| `4mc-e8-fine` | wall | - | **never crossed by 420** | - | **not quotable** |
| `4mc-p4-fine` | CPU | 401 | 400: 0.2% vs 0.5% **INSIDE** | 404: 0.5% vs 0.3% firm | rests on noise |
| `4mc-p4-fine` | wall | 416 | 412: 4.6% vs 0.6% firm | 416: 0.3% vs 0.3% firm | **FIRM both sides** |

**Three of the eight crossings here are firm on both sides, where three of four
banked UNPINNED readings failed that test entirely.** Pinning buys firmness as
well as repeatability. Note the pattern in the fine ladders: a 4-row grid puts
the bracketing rungs so close to the crossing that their distance from `F/T = 1`
is *necessarily* small, so a fine ladder's own crossover is harder to bracket
firmly than a coarse one's. **That is a property of the grid, not a defect of
the sitting** - and it means a fine ladder is the right instrument for pricing
the band and the *wrong* one for locating the crossing. The coarse ladder locates,
the fine ladder prices. This round needed both and that is why it ran both.

Monotonicity: **`4mc-p4` and `4mc-p4-fine` are non-monotone** (worst floors 1.8%
and 1.0%); `cpwarm`, `4mc-e8` and `4mc-e8-fine` are monotone. crpool4m found
`4mc-p4` non-monotone in its own sitting, so **that replicates and is a property
of the arm rather than of either sitting**.

### 5. The fine ladders read HIGHER than their coarse parents, in all four

| arm | coarse CPU | fine CPU | coarse wall | fine wall |
|---|---:|---:|---:|---:|
| e8 | 396 | **398** | 415 | **>420** |
| p4 | 396 | **401** | 412 | **416** |

All four move up, which is systematic rather than noise-shaped. Part of it is
**ladder position and repeat**, and this round can bound that term because the
coarse and fine ladders of each arm **share rung 416**:

| | coarse (position 2/3) | fine (position 4/5) | apart |
|---|---:|---:|---:|
| e8 cpu F/T | 1.051 | 1.036 | 1.5% |
| e8 wall F/T | 1.002 | 0.993 | 0.9% |
| p4 cpu F/T | 1.038 | 1.036 | 0.2% |
| p4 wall F/T | 1.007 | 1.003 | 0.4% |

On the e8 arm `F/T` rises 0.035 over the 20 rows from 400 to 420, so **1.5% in
`F/T` is worth about 8 rows** - enough to account for the e8 shift on its own.
On p4 the same term is 0.2%, about one row, and cannot account for its 5-row
CPU shift. So the two arms disagree about the cause and this round should not be
read as having isolated it. What it does establish is that **a crossover
interpolated across a 32-row gap and one measured on a 4-row grid are not the
same quantity**, which matters for every coarse reading in this campaign.

### 6. The first-rung warm-up ramp is now FOUR of four, and spending it worked

`cpwarm` built the fixture and its m=288 rung came back with an **A/A floor of
15.0%**, against 3.2-8.2% at its other four rungs - the same family as the three
banked fixture-building ladders (9.6%, 15.7%, 35.5%) and against 0.1-2% at a
typical rung elsewhere. **Four of four.**

**The pre-registered remedy worked.** m=288 sits far below this arm's crossover
of 376, so the ruined rung was one nothing depended on. crband put its first
rung *inside* the region it was measuring and lost a rung it needed; this round
spent one on purpose and lost nothing. That is the cheapest possible instance of
the fix and it is now tested rather than merely recommended.

### 7. `cpwarm` is NOT quotable, and the reason is NOT the neighbouring lane

`cpwarm` ran at a **foreign-CPU median of 81% of a core (max 157%)** against
8-12% on all four pinned ladders, with elevated floors at every rung. Its
376/403 is **not quoted as a reading anywhere here**. It was a bonus by design
and no conclusion of this round rests on it.

**What it is not.** Lane `codex-parfast-create-hotpaths-18sep` disclosed that a
defective first driver of its own built a binary from **11:02:12Z to 11:04:19Z**
and asked whether it had touched this round. **It did not touch a single timed
leg: `cpwarm`'s first LEG is at 11:26:14Z, twenty-two minutes later.** The
overlap was with the fixture CREATE and with this round's own `cargo build`,
neither of which is a measurement, and the fixture's content is unaffected. That
disclosure was the right call and is recorded here because the answer is
checkable rather than because it changed anything. One figure is withdrawn on
account of it: this round's own build took 129.6 s with a second cargo build
racing it, so **that is not quotable as a build time**.

**What it probably is.** `cpwarm` ran 11:26-11:35Z, immediately after the 16 GiB
fixture create and its settle, and the foreign CPU decays away over the
following ladders (81% -> 8% -> 12% -> 11% -> 8%). Peak memory is
**essentially identical across all five ladders** (18.1-18.5 GB), so memory
pressure is not the differentiator and time-since-fixture-write is. Post-write
OS background activity is the natural candidate. **This is stated as a
hypothesis and not as a finding** - the box was handed on at 13:14Z and probing
it now would land on another lane's round.

### 8. What this round did NOT license, re-stated after the numbers

Every guard above was written before the sitting. They hold:

- **NO CONSTANT MOVED.** The strongest thing here is a 6.9x at m=420 on one
  pinned arm. At **m=384** both arms *agree* (the fold is cheaper **and** faster,
  so there is no trade to price at all); at **m=416** the e8 arm prices at
  **5.0x** and the p4 arm shows a negative wall gain. That is an input to the
  384-against-416 decision and **is not that decision**, which remains the maintainer's and
  open. This is the sixth lane to measure inputs and the sixth to move nothing.
- **A priced band is not a chosen rung.** 6.9x is under 10x, so the
  proportionality limit does not **exclude** m=420 on this arm. It does not
  follow that m=420 is right, and nothing here says so.
- **An unresolved band is not a clean bill.** 404 and 408 are refusals.
- **A pinned band is not an unpinned one.** These are ratios for fixed core
  mixes. crpool4m measured placement alone swinging the create crossover 27 rows
  at fixed pool size, so none of this transfers to a machine running unpinned,
  which is every user.
- **One sitting is not a replicate.** Ladders 2 and 3 are **one** independent
  repeat of crpool4m on the create path. The fine ladders have no repeat at all.

### 9. Files and how to re-reduce

```
python3 harness/rowgate.py read rounds/crpin4m-2026-09-18/logs/cpe8f.log
python3 rounds/crband-2026-09-18/band-trade.py rounds/crpin4m-2026-09-18/logs/cpe8f.log
python3 rounds/crpin4m-2026-09-18/bracket-firmness.py rounds/crpin4m-2026-09-18/logs/cpe8f.log
python3 rounds/pinaff4m-2026-09-16/ladder-monotonicity-audit.py rounds/crpin4m-2026-09-18/logs/*.log
```

**Run the monotonicity audit FROM THE REPO ROOT.** It resolves `rowgate.py`
relative to the working directory, so from inside this round directory it
reduces zero ladders and says so - `REFUSED: ... reporting its own BLINDNESS`.
That is the audit behaving correctly and it was hit once while reducing this
round; the fix is the path you call it from, never the refusal.
