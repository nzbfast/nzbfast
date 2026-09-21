# The random-drop null over the campaign's filtered fits (18 Sep 2026)

Lane `filtered-fit-random-drop-null-audit-18sep`, gen `539d1291`, item 1 of
an internal note.

**Reduction over banked data. No leg, no box, no rig lock, no constant.**

The write-up is the 18 Sep 2026 section "The random-drop null is NOT
steal-specific" at the end of
an internal note. Read that first; this
directory is the arithmetic behind it.

## Files

- `fitnull.py` - the null. `--selftest` first, always: it REFUSES unless every
  re-implementation reproduces the published table it stands in for.
- `null-200.txt` - `fitnull.py all --draws 200 --seed 1`, the run the handoff's
  200-draw floor asks for.
- `null-1000-seed7.txt` - the same at 1,000 draws under a different seed, as
  the stability check. The exhaustive enumeration is identical in both,
  because it is an enumeration.
- `legs.json` - the windows of all 202 legs the four reductions consume,
  banked so this directory is SELF-CONTAINED. Re-derive it with
  `fitnull.py --bank`; the selftest asserts it against the real round
  directories leg for leg whenever they are present.
- `sensitivity.txt` - `fitnull.py --sens`, the FLOOR and MERGE filters priced.
- `predictors.txt` - `fitnull.py --predictors`, which properties of a fit
  predict how wide its null is. None of them do, and r2 runs the wrong way.
- `selftest.txt` - the selftest's own output, banked so a later reader can
  see what it asserted on the day without running it.

## What it reduces, and what it does not touch

It reads, and never writes, an internal note
(section 8.17) and an internal note
(section 8.21). `leafsum.py` is UNCHANGED, so 8.17's provenance is
byte-identical; 8.21's reducer was never committed and is re-implemented here
from 8.21.4's own description, and cross-checked in the selftest against
`harness/nttfwsum.py`, which is that round's own committed reducer.

**CORRECTED 18 Sep 2026:** the sentence above used to read "8.21's reducer was
never committed". It is committed, at `harness/nttfwsum.py`, and the
selftest now runs it on the same legs and requires both knees to match. Nothing
computed here changed; the two agree exactly.

**Why `legs.json` exists and is not duplication.** Neither input round lives
under `rounds/`, so `export_parfast_evidence.py` mirrors this script
and not its legs, and `selftest-roster` requires the mirrored copy to be wired
too. A mirror that skipped its checks for want of inputs would be the green
line over nothing this repo's gates exist to refuse, so the windows are banked
here instead: the `research/` copy reduces the real legs and asserts the bank
against them leg for leg, the published copy reduces the bank, and both assert
8.17's and 8.21's published figures on every push.

## The one trap in reading the output

**Percentile 100.0 is not by itself a defect.** A filter chosen to remove a
bend lands at the extreme of a random-drop null by construction. What makes a
location readable is the null's WIDTH: 8.17's is 142 sources wide against a
1,121-source gap to its census, and the `ADDITIVE_MIN=64` arm's is 65% of the
quantity it claims to locate. Same percentile family, opposite verdicts.
