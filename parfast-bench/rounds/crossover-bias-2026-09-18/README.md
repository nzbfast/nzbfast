# Is a 32-row crossover BIASED against a 4-row one? No - and here is what it is instead

Lane `crpin-coarse-vs-fine-bias-18sep`, **item 2** of
an internal note.

**NO LEG WAS RUN AND NO BOX WAS TAKEN.** Every figure here is a re-reduction of
logs already committed under `rounds/`. No constant moved;
`crates/nzbkit-base/src/par2repair/fastpar.rs` was not touched.

**The answer in one paragraph.** The bias is **not systematic**, so there is no
correction to apply and the 32-row crossovers in
an internal note stand as published. Over the
whole banked corpus the implied correction is positive in **74 of 146** 32-row
crossings - a coin toss at z = +0.17 - with a median size of 1.5 rows; applied
to the three cases where a fine ladder says what the answer is, it makes **all
three worse**. Simulating the coarse grid inside each fine ladder shows why: the
bias barely moves with the gap (which a curvature bias must do as `h^2`) and
flips sign with **which rung** happens to be the lower bracket. And the reason
it cannot be corrected is measurable directly - adjacent second differences of
`log(F/T)` disagree in sign in **69%** of 568 pairs, against the **73.2%** that
pure per-rung noise predicts, so the curvature a 32-row ladder appears to have
is its own rung scatter. What replaces the correction is a **grid term of about
1 to 4 rows** to carry beside every 32-row crossover, which is smaller than the
3-13 row replicate spread the campaign already quotes and therefore changes no
published claim. Separately, **crpin4m's "all four moved up" is not four
observations**: one is a bound, one is a null, and the two that are firm are the
same arm's two metrics off the same legs - and that arm is the one both sittings
call non-monotone.

## Files

| file | what |
|---|---|
| `crossbias.py` | the whole reduction: six arms plus `--selftest`. Imports `w3winred`, which imports `waskred` - the crossover arithmetic is theirs |
| `crossbias-output.txt` | the full run at `--boot 2000`, which is what the campaign-file section quotes |

    python3 rounds/crossover-bias-2026-09-18/crossbias.py --selftest
    python3 rounds/crossover-bias-2026-09-18/crossbias.py --boot 2000

Whole run: ~12 s on the dev Mac. `--pairs`, `--sim`, `--census`,
`--sensitivity` and `--curvature` select one arm.

## Why this could be done with no box

The handoff's item 2 lists three unranked candidates for crpin4m's observation.
The first - "log-interpolation bias across a 32-row gap" - is a claim about
**arithmetic applied to banked numbers**, and the campaign banks 146 reducible
32-row crossings and four ladders fine enough to be a reference. So the item is
answerable from the ledger, and its own handoff says so.

## The instrument, and the one piece of algebra

`crossover()` log-interpolates: with `y(m) = log(fold/force)` it takes the two
rungs bracketing `y = 0` and returns the root of the **chord** through them.
Writing the true curve locally as `y(m) = A(m-x) + B(m-x)^2` with `A > 0`, and
putting the true root at fraction `u` of an interval of width `h`:

    bias = x_chord - x_true = -h*beta*u*(1-u) / (1 + beta*(1-2u)),   beta = B*h/A

to first order **`-(B/A) * h^2 * u(1-u)`**. Three consequences, each of which is
a test this round runs rather than an assumption it makes:

1. **The sign is the curvature's.** Convex `y` puts the chord above the rising
   curve inside the interval, so it reaches zero early and the coarse ladder
   reads **low** - which is the direction crpin4m observed. Concave reads high.
   A campaign-wide correction needs the curvature to have one campaign-wide sign.
2. **It vanishes at both ends.** At `u = 0` or `u = 1` the crossing sits on a
   rung and the chord is exact, so the correction is not a per-ladder constant.
3. **It is quadratic in the gap.** 32 against 4 is a factor of 64, which is what
   makes a 4-row ladder usable as ground truth for an 8-to-28-row simulation.

`--selftest` pins the closed form against the numeric interpolation in sign,
magnitude and its vanishing at both ends, and pins the seven crpin4m crossovers
this round quotes. Three perturbations were checked to redden it by name: a
wrong published crossover, a disarmed `0 <= u <= 1` guard, and an inverted sign
convention.

## The population, and the one cell that is REFUSED

Inventorying every banked ladder's rung set gives **three** cells carrying both
a coarse and a fine ladder on one box, binary, fixture and pool. Two are
usable:

| cell | coarse | fine | note |
|---|---|---|---|
| `4mc-e8` `0xFF0` `-t8` | `crpin4m` `cpe8` 32-row | `cpe8f` 4-row | one sitting |
| `4mc-p4` `0xF` `-t4` | `crpin4m` `cpp4` 32-row | `cpp4f` 4-row | one sitting; **both ladders non-monotone** |
| `4mcb` unpinned `-t16` | `crband` `csolo` 32-row | `cband` 8-row | **REFUSED** |

**The `cband` refusal is a finding, not an omission.** `crband`'s own README
records that it put its first rung inside the region it was measuring. That
rung, m = 384, carries a **fold A/A floor of 30.1% CPU and 28.9% wall** against
0.5-4.2% at its other four, and it is the only lower bracket every crossing in
that ladder has. So `cband` is not a fine reference, and its coarse-to-fine
difference - which is **negative** (-3.7 rows in wall, sign flipping in 0.0%) -
measures the ruined rung rather than the grid. The refusal is pinned in
`--selftest`, which re-measures the floor rather than trusting this sentence.

**That leaves the corpus with no clean second arm**, which is the single
biggest limit on this round and is what is owed.

## Arm by arm

### Arm 1 - the direct comparison, paired inside the draw

| cell | metric | coarse | fine | fine - coarse | sd | sign flips |
|---|---|---:|---:|---:|---:|---:|
| `4mc-e8` | CPU | 396.43 | 398.02 | **+1.59** | 2.0 | **24.2%** |
| `4mc-e8` | wall | 415.27 | **bound** (`above_last`) | - | - | - |
| `4mc-p4` | CPU | 396.40 | 401.23 | **+4.83** | 1.1 | 0.0% |
| `4mc-p4` | wall | 412.48 | 415.74 | **+3.25** | 0.5 | 0.0% |
| `4mcb` | both | - | - | **REFUSED** | - | - |

**"All four moved up" is not four observations.** The e8 wall comparison is a
bound and cannot be formed at all. The e8 CPU comparison is a **null** - its
sign flips in a quarter of resamples. The two that are firm are the **same
arm's two metrics, computed from the same legs**, so they are one observation
with two read-outs, not two; and that arm is the one crpool4m and crpin4m
**both** report as non-monotone, whose `m = 412` cell reverses direction between
408 and 416 at A/A floors of 0.4% and 0.6%. A tight floor is agreement, not
correctness, and this is the case that rule exists for.

### Arm 2 - the grid simulated INSIDE each fine ladder

Within one fine ladder the pair of rungs `h` apart that brackets the crossing
**is** a simulated coarse grid: same legs, same sitting, same ladder position,
so everything but the grid cancels by construction. Grouping the 27 simulated
biases by which rung was the lower bracket is the whole result:

| ladder | metric | lower rung | n | mean bias | across h |
|---|---|---:|---:|---:|---|
| `4mc-e8-fine` | CPU | 392 | 6 | **-1.69** | h 8 -> 28: -1.71 -> -1.17 |
| `4mc-e8-fine` | CPU | 396 | 5 | **+1.06** | h 8 -> 24: +0.14 -> +1.70 |
| `4mc-p4-fine` | CPU | 392 | 3 | **+3.52** | h 12 -> 24: +1.76 -> +5.71 |
| `4mc-p4-fine` | CPU | 396 | 3 | **-2.11** | h 8 -> 20: -1.25 -> -2.63 |
| `4mc-p4-fine` | CPU | 400 | 2 | -0.25 | h 8 -> 16: -0.28 -> -0.22 |
| `4mc-p4-fine` | wall | 392..408 | 5 | -1.12 | flat across h 8 -> 24 |
| `1m-res-bracket` | CPU | 288..320 | 3 | -0.37 | h 32 -> 64: +0.16 -> -0.80 |

**The gap does almost nothing and the rung choice does everything.** An `h^2`
law says the bias must grow **12-fold** from h = 8 to h = 28; the largest
observed growth within a group is **1.6-fold**, and one group shrinks. Between
groups - the same ladder, the same crossing, one rung moved by four rows - the
bias **flips sign** and moves 2.75 rows on e8 and 5.6 rows on p4. Fitting
`bias = C h^2 u(1-u)` per ladder leaves an rms residual of 1.35 against an rms
bias of 1.51 on e8 (the law explains about a tenth of it), and returns C values
of opposite sign on the two arms of one sitting. The `4mc-p4-fine` wall fit is
the honest absurdity that shows the fit is not measuring curvature: every point
sits at `u > 0.96`, where `u(1-u)` is nearly zero, so a real and constant -1.2
row offset is fitted as C = -0.22/row and would imply -57 rows at mid-interval.

### Arm 3 - the correction the algebra implies, over the whole corpus

For every banked 32-row crossing, `delta` is the root of the local **curve**
through that ladder's own rungs minus the root of the **chord** - both
recomputed inside every bootstrap draw so the difference is paired.

- **146 crossings reduced** (38 old-format logs skipped by name, the silent-
  garbage parse class the round-2 error-bar file documents).
- `delta > 0` - the coarse reading low, the correction up - in **74 of 146**.
  **z = +0.17.** A coin toss.
- `|delta|`: median **1.5** rows, 90th percentile 6.7, max 23.8.
- Distinguishable from zero (sign flips under 5%): 42 of 146, of which **16
  positive** - if anything leaning negative (z = -1.54), the **opposite** sign
  to the one crpin4m's observation would need.
- Per round, the positive fraction runs from 1/8 (`g4win`) to 14/19
  (`rowgate-09-15`) with no ordering by class, pool, block size or date.

### Arm 4 - arm 3 validated where the answer is known

| cell | metric | coarse | + delta | corrected | fine | error before -> after |
|---|---|---:|---:|---:|---:|---|
| `4mc-e8` | CPU | 396.43 | -0.60 | 395.83 | 398.02 | 1.59 -> 2.19 **WORSE** |
| `4mc-p4` | CPU | 396.40 | -0.85 | 395.55 | 401.23 | 4.83 -> 5.68 **WORSE** |
| `4mc-p4` | wall | 412.48 | -2.85 | 409.63 | 415.74 | 3.25 -> 6.11 **WORSE** |

Three of three, and **in the wrong direction every time**: the measured
curvature on those arms is concave over their own bracketing interval, so the
correction it implies points **down** while the fine ladder reads **up**.
Applying it would be worse than doing nothing, which is the whole verdict.

### Arm 5 - the rival explanation, priced

A crossover is a root of `log(F/T)`, so a cell wrong by `e` per cent moves it by
`e / (100 dy/dm)` rows. On these ladders one per cent of `F/T` is worth
**3.9-5.3 rows** at the coarse crossings and 0.8-5.1 at the fine ones, and the
bracketing rungs' own A/A floors are 0.03-1.74%. That prices "one bracketing
rung drew badly" at **1.3 to 3.6 rows** - the same size as every coarse-to-fine
gap in arm 1, present at **every** spacing, and not removable by refining the
grid.

### Arm 6 - why no correction is recoverable, measured directly

The chord bias is proportional to the second derivative of `log(F/T)`. A real
curvature changes slowly along a ladder, so adjacent second differences should
mostly **agree** in sign. Per-rung noise does the opposite: adjacent second
differences share two rungs with opposite weights, giving a correlation of
exactly **-2/3** and a Gaussian sign-**disagreement** rate of
`1/2 + arcsin(2/3)/pi` = **73.2%**.

Over 172 coarse ladder-metrics carrying four or more consecutive 32-row rungs:
**391 of 568 adjacent pairs disagree, 69%.** Three points below the pure-noise
prediction and twenty above what a resolved shape would give. **The curvature a
32-row ladder appears to have is, to within a few per cent, its own rung
scatter** - so there is nothing there to build a correction out of, and arm 3's
failure in arm 4 is the expected outcome rather than a surprise.

## What to do instead of a correction

**Carry a grid term of about 1 to 4 rows beside every 32-row crossover**, added
in quadrature to its bootstrap bar, and read it as an order of magnitude the way
both error-bar files read theirs. Arm 3's `|delta|` distribution (median 1.5,
90th percentile 6.7) and arm 5's rung-noise term (1.3-3.6) are two routes to the
same scale.

**Arm 5's arithmetic now lives in `w3winred.rung_noise` and is printed beside
every graded crossover** (18 Sep 2026, item 1 of
an internal note, which this file's own bullet
owed). `w3winred.py --grade` prints the bracketing pair, `u`, rows per one per
cent of `F/T`, the two bracketing rungs' A/A floors and the implied rung-noise
term under its bootstrap table, for any crossover in the campaign rather than
the seven quoted here. **One copy, called from both**: this file's arm 5 is the
printing and the ladder roster, the numbers come from there, and every figure in
the table above is unchanged by the move - both selftests pin it from their own
side, so a copy dragged back reddens. The two errors are printed **side by
side** and are not combined: how to fold a sampling bar into a systematic is a
judgement neither script makes for the reader.

**It changes no published claim.** The campaign's own external replicate
evidence is 3-13 rows (3.6 on the resident anchor across three nights, 13.6 on
the windowed cell, 3-7 on the pinned sub-box envelope, 2-6 on crpin4m's own
create-path replication), so a 1-4 row grid term is **inside** the scatter the
campaign already quotes and does not move a single row of either graded table.

## The corpus has grown since this sitting

Re-running `crossbias.py --boot 2000` on origin/main of 18 Sep 2026 prints **76
of 150** where the table above reads 74 of 146, and **401 of 584 = 69%** where
arm 6 reads 391 of 568 = 69%. That is four more banked ladder logs reaching the
two corpus-wide arms, not a change in any arithmetic: the verdicts (not
systematic, z near zero; the curvature is the rungs' own scatter) and every
per-cell figure are identical, and the banked `crossbias-output.txt` is this
lane's own sitting and is left as it was run. Checked against the tip before and
after the rung-noise move, which changes neither count.

## Stated limits

- **A fine ladder is a reference, not the truth.** Its own crossover carries the
  same chord bias at its own spacing; at 4 rows against 32 that residual is
  1/64 of the term being measured, which is what makes it usable.
- **No arm reaches h = 32 on a 4-row ladder.** They span 28 rows. The only
  simulated h = 32 in the corpus is `cband`'s, and `cband` is refused. Every
  statement about h = 32 here is an extrapolation in h - which is safe only
  because the measured h-dependence is near zero, and would not be if it were
  not.
- **Two usable cells, one box, one part, one payload, one block size, one
  phase.** Core Ultra 9 386H, GFNI-256, random bytes, 4 MiB, n = 4,096, the
  CREATE path. Arms 3, 5 and 6 reach the whole corpus; arms 1, 2 and 4 do not.
- **The one arm with a firm coarse-to-fine gap is non-monotone in both its
  ladders and in both sittings.** Its tight A/A floors are agreement, not
  correctness.
- **A bootstrap resamples the same legs.** A rung wrong in both its copies is
  invisible to it - the round-2 error-bar file's section 2 has the worked case,
  and `cband`'s m = 384 would be one if it were not caught by its floor.
- **Arm 3's `delta` is one instrument's** (a local quadratic through four rungs).
  It is not trusted on its own; it is validated in arm 4 and independently
  corroborated by arms 2 and 6, which share none of its arithmetic.
- **Nothing here is a statement about the WINDOWED or REPAIR paths' shape** in
  any direction other than arms 3, 5 and 6's corpus-wide counts.
- **NO CONSTANT MOVED.** The 384 / 416 / `create_ntt_min_rows` decision is the maintainer's
  and remains open. This lane is the seventh to measure an input and the seventh
  to move nothing.

## Owed after this lane

- **A clean second coarse/fine cell.** The corpus has exactly one usable arm
  with a firm gap and it is the non-monotone one. A `-t8` `0xFF0` pair on a
  MONOTONE arm - or a repeat of `cband` with its first rung spent below the
  region, which crpin4m has already shown works - would settle whether arm 1's
  +4.8 is the arm or the grid. **Needs intel-core-ultra-9-386h, so do not pre-mint a
  claim for it** (the handoff's own rule).
- **The rung-noise term belongs in the reducer, not in prose.** Arm 5 computes
  "rows per one per cent of `F/T`" from any ladder in four lines, and every
  crossover in this campaign would be better quoted with it beside the
  bootstrap bar. Nobody has put it there.
- **`4mc-p4`'s non-monotonicity is still item 3 of the same handoff** and is
  untaken. This round makes it more load-bearing than it was: that arm is now
  also the only firm evidence for the coarse-to-fine shift.
