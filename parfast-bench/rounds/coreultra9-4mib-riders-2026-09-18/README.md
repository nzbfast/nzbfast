# Four commissioned riders on one 4 MiB fixture (18 Sep 2026)

Lane `coreultra9-4mib-riders-sitting-18sep`, gen `09e5f607`.

**Status: PRE-REGISTERED. Written and landed on origin BEFORE the box was
taken.** Everything in this file and the whole of `zrider-round.ps1`'s header -
the four questions, the ladder table, the forced and chosen ordering, the spent
first rung, and the guard on what the round does not license - predates the
first leg. None of it is fitted to the numbers. This is the practice
`crpool4m`, `crband` and `crpin` all used, and it is why their conclusions held
when their numbers would have allowed stronger claims. Results are appended at
the end under a heading that says so.

## Why one sitting

Four cells, commissioned separately by three handoffs, and **every one of them
was written as a rider on "the next round that builds a 4 MiB fixture on this
part"**. None justifies taking intel-core-ultra-9-386h - the fleet's only GFNI-256 part,
and contended - on its own. Lane `parfast-4mib-knee-below-320` released its
claim on exactly that reasoning on 18 Sep: with no fixture on the box, its four
legs would have cost a rebuild, a 16 GiB create and a ~745 s settle. **One
fixture pays that once for all four.**

| cell | commissioned by | ladders |
|---|---|---|
| (A) is the fold/force knee POOL WIDTH or SMT? | item 5, an internal note | `zp3e8`, `zp3e4` |
| (B) where does the e8 create band END? | item 1, an internal note | `ze8top` |
| (C) is `4mc-p4`'s non-monotonicity a property of the ARM? | item 3, same file | `zp4rep` |
| (D) does INTERLEAVING explain the 22-row unpinned swing? | item 2, an internal note | `zsolo`, `zint`, `zdrift` |

## The cell

- **Box** intel-core-ultra-9-386h (Core Ultra 9 386H, GFNI-256, 4 P cores 0-3, 8 E cores
  4-11, 4 LP-E cores 12-15, 31.4 GB, Windows 11). The fleet's only GFNI-256
  part, so no other box substitutes.
- **Binary** parfast from `06d5734b7`, gated on its **4,173,312-byte COUNT and
  never on a sha256** - the build embeds its own path, so the hash differs per
  root by construction.
- **Fixture** 16 x 1,024 MiB at 4 MiB blocks, `-c640`: n = 4,096, a 16 GiB
  corpus - the shape all banked 4 MiB rounds on this part used. n = 4,096
  clears the x86 input floor of 2,048 on its own, so no rung here can fall
  through to the fold.
- **ONE fixture serves BOTH phases**, and that is checked rather than assumed:
  `wcomb.ps1` names the fixture `fix-<slice>-<mib>` with no phase in the name
  (line 329), and `-Recovery` is honoured at CREATE ONLY (line 542), so the two
  `rowgate` ladders reuse the `create` ladders' `fix-4194304-1024`. All eight
  ladders pass `-Recovery 640` regardless, which is what both banked recipes
  specify.
- **Common to every ladder**: `fold force force2 fold2` at every rung, one rep,
  `-Residency resident`, `-NttBudget` 20 GiB, `-Slice 4194304 -MemberMiB 1024
  -Recovery 640`, and a **distinct `-Label`** (`rowgate.py` groups by
  `(label, threads)`).

## The nine ladders

| # | tag | label | phase | mask | cores | threads | rungs | what |
|---|---|---|---|---|---|---|---|---|
| 1 | `zwarm` | `4mr-warm` | create | none | all 16 | 16 | 288 | **builds the fixture, legs DISCARDED** |
| 2 | `zsolo` | `4mr-t16-solo` | create | none | all 16 | 16 | 288..512 | (D) arm A, **solo** |
| 3 | `zint` | `4mr-int` | create | none | all 16 | **4,16** | 288..512 | (D) arm B, **interleaved** |
| 4 | `zdrift` | `4mr-t16-drift` | create | none | all 16 | 16 | 384,416 | (D) **drift control** |
| 5 | `zp3e8` | `4m3-e8` | **rowgate** | `0xFF0` | 4-11 | 8 | 128,192,256 | (A) **wide pool, no siblings** |
| 6 | `zp3e4` | `4m3-e4` | **rowgate** | `0xF0` | 4-7 | 4 | 128,192,256 | (A) narrow control |
| 7 | `ze8top` | `4mr-e8-top` | create | `0xFF0` | 4-11 | 8 | 420..440 by 4 | (B) close the band |
| 8 | `zp4rep` | `4mr-p4-rep` | create | `0xF` | 0-3 | 4 | 408,412,416 | (C) the third rep |
| 9 | `zp3pe8` | `4m3-pe8` | **rowgate** | `0xFF` | 0-7 | 8 | 128,192,256 | (A) **optional** mixed-class arm |

### Ladder 1 is a one-rung SPENT ladder, and it is the one design choice this round makes that its ancestors did not

Four of four fixture-building ladders in this campaign show a warm-up ramp
**confined to the first rung**, with A/A floors of 9.6% / 15.7% / 35.5% against
0.1-2% typical, and `crband` established the ramp is a property of **building
the fixture** rather than of being first. `crpin` answered that by spending its
builder's first rung and keeping the rest of that ladder as a bonus reading.

**That answer does not work here**, because this round's largest cell is a
comparison *between two unpinned ladders*. If the solo arm built the fixture and
the interleaved arm did not, the ramp would sit on one side of the comparison
and not the other, and the asymmetry would be confounded with the very quantity
being measured. So the ramp is spent on a ladder that is in **neither** arm.
m=288 is far below every banked unpinned `-t16` crossover (357, 359, 365, 387),
so it lands on a rung nothing depends on, and **ladder 1's four legs are
discarded - they are not a fifth reading and are not reduced.**

### The ordering is forced at the top and chosen below it

**Forced:** `-Affinity` arms every leg *including the fixture create*, so a
pinned ladder cannot run first.

**Chosen:** ladders 2, 3 and 4 are adjacent because they are one cell and their
comparison is exactly what ladder position would otherwise contaminate. Ladders
5 and 6 are adjacent for the same reason - they are the two halves of one
two-by-two. Ladders 8 and 9 are last because they are the cheapest and the only
ones whose loss destroys no deliverable.

**Ladder 9 is taken only because the fixture is warm.** Item 5 offers a third,
MIXED-class arm (`0xFF`, four P plus four E) under exactly that condition - *"if
the fixture is already warm and it is cheap"* - and says in as many words that it
is **not needed for the verdict**. It asks a different question from the e8/e4
pair: whether a mixed-class wide pool knees like a single-class one. Being last
costs it nothing analytically, because the knee statistic is computed **within**
a ladder, so between-ladder drift does not enter it. It is stated as mixed
wherever it is quoted, and it is never a rung of the within-class ladder.

### Ladder 4 is why cell (D) is three ladders and not two

Ladder position is itself a confound for a solo-against-interleaved comparison.
`crpin`'s within-sitting position control bounded ladder-position-plus-repeat at
**1.5% of `F/T` on e8, about 8 rows**. The effect being chased is 22 rows, so
position cannot fully explain it - **but that is an argument, not a
measurement**, and this sitting can make the measurement for about five minutes
of legs. Ladder 4 repeats ladder 2 at only the two rungs its crossover
interpolates from, *after* ladder 3, so the drift it reports over positions
2 -> 4 bounds the drift over 2 -> 3 conservatively.

**If ladder 4's two rungs do not bracket**, `rowgate.py` prints `?` and the
honest report is "the `-t16` crossover left [384,416] during the sitting", which
is a **larger** drift finding than a bracketed one and must not be written up as
a failed control.

**A two-rung ladder reduces, and this was checked rather than assumed** before
launch - a control that produced nothing would have been discovered at the end
of a three-hour sitting. Filtering the banked `crpin` `cpe8` log down to just
m=384 and m=416 and handing it to `rowgate.py` gives a clean table and **both**
crossovers, and they come out at CPU 396 / wall 415 - **identical to the full
eight-rung ladder's**. That is a stronger result than the check needed: it says a
coarse ladder's crossover is determined entirely by its two bracketing rungs, so
ladder 4 is measuring the same quantity ladder 2 does by the same arithmetic, not
an approximation to it. (It is also independent confirmation of the mechanism
`rounds/crossover-bias-2026-09-18/` found - that the apparent bias
"flips sign with which rung happens to be the lower bracket".)

### Ladder 7 is not a band aim, and does not violate crpin's "aim from your own sitting" rule

`bandplan.py` exists because a **band's location** moves between sittings. 420
is not a band edge: it is the **rung** `crpin` actually measured and published a
6.9x ratio at, and ladder 7 extends literally above it at the same 4-row
spacing. What it inherits from another sitting is a rung number, not a band.

## What this round does not license

- **NO CONSTANT MOVES.** The rung decision - 384 against 416 against
  `create_ntt_min_rows` taking its own clause at ~372 - is the maintainer's, it is open,
  and six lanes have now measured inputs without moving anything. This is the
  seventh.
- **A priced band is not a chosen rung.** A ratio under 10x does not say a rung
  is right; it says the proportionality limit does not *exclude* it.
- **An unresolved rung is not a clean bill.** Rungs coming back inside their own
  A/A floors is the expected case for a narrow band. The honest statement is
  "the trade cannot be priced at this resolution on this part" - **not** "the
  trade is small" and **not** "the metrics agree". No floor is widened to
  manufacture a rung.
- **A level is not a step.** Ladders 5 and 6 are the first rungs ever run below
  320 on this part. The banked 320..448 data shows pool doubling with zero
  siblings *raises* the fold/force ratio here where the i5's pool-plus-SMT step
  lowers it - that is a **level** statement over a range that never touches the
  knee interval. Only the three-rung step statistic is the verdict.
- **Cell (C) cannot confirm its candidate mechanism.** Item 3 names the OS
  parking or boosting P-cores differently under a 4-thread pin. Ladder 8 can say
  whether the reversal reproduces a **third** time; it cannot say why.
- **One sitting is not a replicate**, and more reps cannot firm a rung: the A/A
  floor is a MAX over reps.
- **One part, one payload, one block size.** No other box on this fleet is
  GFNI-256, and nothing here transfers to a machine running unpinned, which is
  every user.

### Unpinned is deliberate on ladders 1-4 and is not a lapse

Section 5 of an internal note says to
pin to cores 0-3 on this part and that unpinned legs are not data. **That
finding is about a single-thread leg** - a whole-file MD5 is one serial 64-step
chain on one core - landing on an LP-E core, measured at a 1.43x swing. No leg
in this round is single-threaded, and **cell (D) is *about* an unpinned
reading**: its subject is why two unpinned sittings disagreed by 22 rows, so
pinning it would delete the question. Ladders 5-8 are pinned and read their
masks back.

## Reduction

Everything reduces **on the Mac** (no python on the rig):

```sh
python3 harness/rowgate.py read <log>                       # per-arm crossovers, CPU and wall
python3 harness/kneeratio.py <zp3e8.log> <zp3e4.log>        # cell (A) - the knee statistic
python3 rounds/crpin4m-2026-09-18/bracket-firmness.py ...   # screen the bracketing rungs
python3 rounds/pinaff4m-2026-09-16/ladder-monotonicity-audit.py ...  # FROM THE REPO ROOT
```

**`kneeratio.py` is the single copy of cell (A)'s arithmetic**, written and
CI-selftested by the lane that banked the recipe so a second round does not
write a second copy. It REFUSES to compute the statistic from fewer than three
rungs, which is why the grid is 128/192/256.

**THIS ROUND'S LOGS ARE NOT UTF-16, AND THAT IS CHECKED RATHER THAN HOPED.**
The trap is real - `rowgate.py` answers `REFUSED: no legs` on a UTF-16 file,
which reads exactly like a dead round, and the `gfni256-four-window` sitting on
this same box the same day hit it - but it comes from **`Tee-Object`**, which
writes UTF-16. Nothing in this round's path uses it: `wlaunch.ps1` starts the
driver as `cmd.exe /c powershell ... > $log 2> $err` and `Invoke-Ladder` runs
each ladder as `cmd /c "powershell ... > $log 2>&1"`, both byte-stream
redirects. The banked `crpin` logs, produced by the same two mechanisms, are
ASCII. **`file(1)` every log on arrival anyway** - the cost of checking is
nothing and the cost of not checking is a round that reads as dead.

## A DONE line is not a verdict, and this round's carries the leg counts

Handed to this lane by `gfni256-four-window-shape-1mib-18sep` while it held this
box, and acted on before launch. Its driver posts a completion NOTE
automatically when its ladder loop exits, and **the identical wording had been
posted four hours earlier by its own attempt 1 - a sitting that ran ZERO legs**
and was retracted. Its six ladders had each hit `wcomb`'s `rc=17` LOCK-BUSY, and
because a non-zero exit from a called `.ps1` does not throw in PowerShell, a
`try/catch` read a busy rig as a finished ladder: all six "completed" in 0.4
seconds. **The text is evidence that the loop exited, never that anything was
measured.** No reader of that coordination file could tell the two postings
apart.

This round inherits the `rc=17` retry that stops that particular cause, but the
cause is not the lesson - the OUTCOME is, because any path that returns 0 having
run no leg reads as a pass. Two changes:

- **`rc=0` with zero legs is a REFUSAL** (`ZRIDER-EMPTY-LADDER`, rc 21) and ends
  the round on the spot. It is deliberately not an `rc=17`-style retry: `rc=17`
  means "somebody else has the box", which is a reason to ask again later, where
  `rc=0`-with-no-legs means the instrument returned success having done nothing,
  and waiting fixes nothing about it.
- **The DONE line states the per-ladder leg counts** (`LEGS PER LADDER:
  zwarm=4 zsolo=32 ...`) and says in the line itself that it is posted
  automatically, so read the counts and not the word DONE. An automatically
  posted line cannot be a verdict, but it can carry the number that is one.

This is CLAUDE.md's standing trap in a new place: `0 passed` is never a verdict,
and a green line over zero tests has the same shape as a green line over a
passing suite. **Read the count, not the exit code.**

## A coordination post is not landed until the READER can see it

Handed to this lane by `gfni256-four-window-shape-1mib-18sep` as it closed,
minutes before this round took the box. **Its DONE took three attempts and the
first two both reported success:**

| attempt | result | why it looked fine |
|---|---|---|
| `Add-Content` over ssh with a here-string | **rc=1, wrote nothing** | caught only by re-reading |
| `cmd /c type f >> dest` | **rc=0, wrote UTF-16LE** | the ssh default shell here is PowerShell, so `>>` was *PowerShell's* redirect and PS5 writes UTF-16 by default. In the file as mojibake, matches nothing |
| redirect moved inside `cmd` | **rc=0, correct ASCII, still unparseable** | it inherited a stray NUL from the UTF-16 line above and began **one byte in from column 0**, so `findstr /B` missed it |

**The generalisation is narrower and nastier than "re-read the box":** `rc=0`
from the append is worth nothing, the line being *present* is worth nothing, and
the line being correct ASCII is worth nothing. The only check that counts is
**the one the reader performs** - a match on a rostered marker word **at column
0**. Anything weaker passes on all three of those failures.

This round's `Post` therefore writes through `[IO.File]::Open(...Append...)`
with a `UTF8Encoding($false)` StreamWriter (no BOM, no PS5 UTF-16 default - the
same path this lane's own QUEUED lines took, which `parfast-rigs.sh`
demonstrably parsed), emits a leading CRLF when the file's last byte is not a
newline, and then **re-reads and confirms a line-start match**, logging
`ZRIDER-COORD-POST-UNVERIFIED` when it cannot find its own line back. Tested at
byte level against both cases before launch.

It is `ZRIDER-EMPTY-LADDER`'s twin one layer down the pipe: that guard refuses
an **exit** that verified no **legs**, this one refuses a **write** that
verified no **read**.

## Box discipline

- `wcomb` takes the rig lock **per ladder**, so an inspector sees eight separate
  holds and **the gaps between them are not openings**. The CLAIM line says so.
- Every ladder gates on lock-free AND no-parfast AND load under 25, **re-reads
  the coordination file** and stands down at a ladder boundary on any open
  `CLAIM` that is not this lane's, and waits out an `rc=17` LOCK-BUSY rather
  than dying. Every other non-zero rc ends the round on the spot - those are the
  instrument refusing, and retrying one would launder a refusal into a number.
- The re-read guard is here because the lane that skipped it lost a whole
  sitting the same morning: `gfni256-four-window-shape-1mib-18sep` checked the
  lock and the process list, could not see a CLAIM posted two minutes before its
  own, and ran **zero legs**. The guard classifies the **first token** against an
  open/close keyword roster and never substring-matches a line (bench-suite item
  0a5's fourth bullet). It was selftested against the real 243-line coordination
  file before launch, in all three directions: one open holder found, cleared by
  a `DONE`, and a late arrival caught.

- **The guard's first cut invented its rosters and got `TAKEOVER` backwards.**
  It had `TAKEOVER` and `ABANDON` as CLOSE keywords. The fleet has `TAKEOVER` in
  **`OPEN_KW`** - a hand-over *opens* a claim for whoever takes it - and
  `ABANDON` in neither roster at all. **Classifying an open word as a close is
  the dangerous direction**: it reads a held box as free and takes it out from
  under somebody, which is exactly what memory topic
  `nzbfast-free-box-test-fails-three-ways` is about. It was caught by reading
  `.claude/tools/parfast-rigs-parse.py`'s `OPEN_KW` / `CLOSE_KW` rather than
  trusting a commit message, and item 0a3 had already said why - *"do not guess
  the classification from the word"*, four pairs on this fleet contradict their
  own spelling. The same read supplied `WITHDRAWN` (a close) against
  `WITHDRAWING` (not one, `5383c1db1`), which the first cut had neither of.

- **`foreign-claim-selftest.ps1` in this directory is what stops the next edit
  reintroducing it.** 15 cases on a synthetic coordination file, no box and no
  network; it **extracts** the function from `zrider-round.ps1` rather than
  carrying a copy, so the thing under test is the one that actually runs.
  Mutation-checked: putting `TAKEOVER` back into the close roster fails case 7
  and exits 1.
- **Poll at 600 s at the loosest and prefer not polling at all** - every ssh poll
  spawns a PowerShell under sshd *outside* the round's pid tree and lands in the
  round's own `foreign_cpu`.
- **Never kill by pattern**; resolve the pid. `-ExecutionPolicy Bypass` for
  anything that dot-sources `plib.ps1`.
- **scp a `.ps1` and run it with `-File`.** An inline `powershell -Command "..."`
  over ssh mangles quoting on these boxes; empty stdout there is a syntax error,
  not a dead box. This lane hit it on its first call and switched.

---

# RESULTS (appended 18 Sep 2026, after the sitting)

Everything above this line was written and landed on origin/main **before the
box was taken**. Nothing above has been edited to fit what follows.

**The sitting.** 18:55:07Z - 21:17:51Z, nine ladders, one 4 MiB / n=4096
fixture, **180 legs**. Every leg `rc=0`; every leg `restored=16/16` or
`match=1`; zero lock waits; zero stand-downs; `ZRIDER-ROUND end rc=0`. All
**72 pinned legs read their mask back EQUAL** (`zp3e8` 12/12 `0xFF0`, `zp3e4`
12/12 `0xF0`, `ze8top` 24/24 `0xFF0`, `zp4rep` 12/12 `0xF`, `zp3pe8` 12/12
`0xFF`). Binary byte-gated at 4,173,312 from `06d5734b7`. Logs are ASCII, as
predicted.

**The class probe confirmed this round's premise on the box** rather than from
`.claude/MACHINES.md`: fixed work on E-cores 4, 8 and 11 took 13.239 / 13.306 /
13.273 s, agreeing within **0.51%**, so `0xFF0` at `-t8` really is eight cores
of one class. P-core0 took 7.651 s and LP-E core12 15.883 s, giving **P/E =
1.734** against the campaign's quoted 1.72-1.74x - an independent reproduction
of a constant this round did not set out to measure.

## Screens first, because two results are qualified by them

`ladder-monotonicity-audit.py` (from the repo root) and `bracket-firmness.py`:

| ladder | monotone | CPU crossover | CPU brackets | wall crossover | wall brackets |
|---|---|---|---|---|---|
| `zsolo` t16 | yes | **366** | **firm both sides** | 393 | **rests on noise** (384: 2.2% vs 4.0% floor) |
| `zint` t16 | yes | **366** | **firm both sides** | **391** | **firm both sides** |
| `zint` t4 | **no** | 387 | firm | 424 | firm |
| `zdrift` t16 | (2 rungs) | <384 | cannot bracket | 393 | rests on noise |
| `zp3e8` / `zp3e4` / `zp3pe8` | yes | >256 | - | >256 | - |
| `ze8top` | yes | <420 | **cannot be quoted for CPU** | 421 | **rests on noise** (420: 0.5% vs 4.8% floor) |
| `zp4rep` | **no** | 414 | firm both sides | never crossed by 416 | **cannot be quoted for wall** |

## (D) Is the 22-row unpinned swing INTERLEAVING? No - and the firm metric says so

| arm | CPU | wall |
|---|---|---|
| `zsolo` - SOLO `-t16` | **366** (firm) | 393 (noise) |
| `zint` - INTERLEAVED `-t16`, same fixture, binary, sitting | **366** (firm) | **391** (firm) |
| `zdrift` - `zsolo` repeated at 384/416 AFTER `zint` | <384 | 393 (noise) |

**Zero rows apart in CPU, with both brackets firm on both arms.** Two rows apart
in wall, though the solo arm's wall crossover rests on noise and is not
independently quotable. **Interleaving is excluded** as the cause of the
`crpool4m` (387) against `crg4` (365) gap, and the drift control puts ladder
position at about **zero rows** over the sitting (`zdrift` wall 393 = `zsolo`
wall 393).

**What replaces it, and it is the number item 2 said nobody had.** This sitting's
SOLO arm read **366**, which is `crg4`'s 365 and *not* `crpool4m`'s 387. With
interleaving and position both excluded, the residual is the sitting itself: **an
unpinned `-t16` create crossover is worth roughly +/- 11 rows between sittings**,
and every unpinned number in this campaign inherits that - including the 381/365
pair the 384 recommendation rests on.

**A design miss in the drift control, recorded so the next lane does not repeat
it.** Its two rungs were placed at 384/416, the WALL crossover's brackets. The
CPU crossover is 366, *below* its bottom rung, so the control could not bracket
CPU at all - and CPU is the metric that came back firm. **A two-rung drift
control can only control the metric it brackets**, and when CPU and wall cross 27
rows apart, two rungs cannot do both. It still did its job on wall; it was
half as strong as designed.

## (A) Is the fold/force knee POOL WIDTH or SMT? Pool width is excluded

First rungs ever run below 320 on this part. Fold/force ratio:

| arm | mask, pool | m=128 | m=192 | m=256 |
|---|---|---:|---:|---:|
| `4m3-e4` - narrow, no siblings | `0xF0`, 4 E | 0.9876 | 1.0057 | 1.0091 |
| `4m3-e8` - **wide, no siblings** | `0xFF0`, 8 E | 1.0316 | 1.0700 | 1.0764 |
| `4m3-pe8` - wide, MIXED class | `0xFF`, 4P+4E | 1.0853 | 1.1086 | 1.1288 |

**The ratio RISES with m in all three arms, where the i5's wide arm FALLS 37.5%
across the same 128-to-192 interval. Opposite sign, in every arm** - so this is
a statement about direction, not about magnitude, and it does not depend on any
statistic being resolvable. **Doubling the pool at fixed zero SMT moves the
shape essentially not at all** (`e4` and `e8` rise together), which is precisely
the comparison the i5's `-t4` -> `-t12` step cannot make, because that step moves
SMT and width together.

**So: POOL WIDTH IS EXCLUDED, and SMT survives as the i5-side candidate** - item
5's second branch, "a knee that needs siblings cannot appear on a part that has
none". The two parts also differ in kind: the i5's *own* no-SMT `-t4` control
falls where all three arms here rise, across a different kernel class (AVX2
nibble against GFNI-256) and a different block size, so the transfer is bounded.

**THE KNEE STATISTIC IS NOT QUOTABLE ON EITHER ARM, and this is the honest
limit.** `kneeratio.py` prints 6.1x (`e8`) and 5.4x (`e4`), which sit between the
published 16.3x (knee) and 1.6x (smooth). **They must not be quoted against
those.** The 192->256 step is 0.6% on `e8` and 0.3% on `e4` against A/A floors of
0.9-1.9%, so the *denominator* of largest/next is inside the floor and the ratio
is a quotient with an unresolved divisor. The first interval is real on `e8`
(3.7% against 1.3-1.8% floors) and marginal on `e4` (1.8% against 1.9%). The sign
result above stands independently of all of it.

## (B) Where does the e8 create band end? Nothing above ~421 is priceable

`ze8top`, `0xFF0` `-t8`, rungs 420..440. The CPU crossover is **below 420**, so
this ladder cannot be quoted for CPU. The wall crossover is **421** - but m=420's
own distance from `F/T = 1` is 0.5% against a 4.8% A/A floor, so that rung is
inside its own noise and the exact end is not resolvable.

**What IS firm: m=424 is firmly above the wall crossover** (3.2% against a 1.4%
floor). Past the wall crossover the gain is negative and the rung leaves the band
entirely, by the denominator argument `crpin` published. So **"no rung above 420
is priceable" was a legitimate answer and it is the answer**, and `crpin`'s 6.9x
at m=420 stands as **the last priceable rung and the bound on the create trade**.
No floor was widened to manufacture a rung.

## (C) Is `4mc-p4`'s non-monotonicity a property of the arm? Yes - third sitting

`zp4rep`, `0xF` `-t4`, rungs 408/412/416: `F/T` = 0.996 / **0.969** / 1.024. The
reversal at 412 **reproduces a third time**, at A/A floors of 1.2% / 0.4% / 0.4%,
which is tight - and `ladder-monotonicity-audit.py` flags the ladder
independently. **A defect that replicates three times is a property, not noise**,
and `crpool4m`'s same-pool CLASS PAIR is built on this arm.

**This round cannot say why and does not claim to.** Item 3's candidate - the OS
parking or boosting P-cores differently under a 4-thread pin - is untested here.
One *suggestive* observation, flagged as suggestive: the two non-monotone arms in
this sitting are `zp4rep` (`0xF`, four P-cores) and `zint`'s unpinned `-t4` half,
which is free to land on P-cores; the E-core `-t4` arm (`zp3e4`, `0xF0`) is
monotone. That is consistent with a P-core mechanism and is **not** a test of one.

## What this round does not license

Unchanged from the pre-registration, and checked against the numbers rather than
assumed: **no constant moved.** The 384-against-416-against-~372 decision is
the maintainer's, it is open, and this is the seventh lane to measure inputs without moving
anything. A priced band is not a chosen rung. An unresolved rung is not a clean
bill - two of the four cells here are qualified by their own A/A floors and say
so above. One sitting is not a replicate. One part, one payload, one block size;
nothing here transfers to a machine running unpinned, which is every user.

The graded tables in an internal note are
**unchanged** by this round: cell (A) adds rungs below their range rather than
moving any, and cell (D)'s finding is a +/- 11 row *uncertainty* on unpinned
readings, which is inside the 3-13 row replicate spread the campaign already
quotes.

## Box as left

Root `<rig>\zr18sep` **deleted** - 16 GiB fixture, source tree, tarball,
binary and helpers, 37.86 GB, C: went 344.9 -> 382.7 GB free. Nothing of this
lane is running; no shared binary, no system setting and no other lane's file was
touched. `<rig>\g4win-18sep` is **not this lane's** and was left alone.
The rig lock passed to `zswp2-rotated-rerun-18sep` at 21:27:17Z; this lane's
37.86 GB delete ran at ~22:40Z **inside that round** and was disclosed to them on
the coordination file - disk I/O, no CPU, but foreign load their legs may have
seen.
