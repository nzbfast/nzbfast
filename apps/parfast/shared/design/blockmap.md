# The block map: the one rendering rule both apps must agree on

The block map is the signature visual (plan 5.2), it is the picture a user
decides from, and it is the one thing in this design that cannot be left to
each platform's judgement. The rule is written here, and the reference
implementation is `apps/parfast/mac/Sources/ParfastCore/BlockMapRule.swift` -
pure functions over a state array, pinned by
`Tests/ParfastAppTests/BlockMapRuleTests.swift`. Port that, do not re-derive
it.

## The rule

One cell per source block while they fit. Above `size.block_merge_threshold`
(4,000) cells cover many blocks each, and then:

1. **Ground = the MAJORITY state in the cell's range**, ties going to the
   state that matters more (the `rank` order: missing > damaged > misnamed >
   hashing > pending > present).
2. **Plus a tick along the bottom of the cell wherever the range holds at
   least one BAD block** (damaged or missing), in the worst bad state's
   colour, at least `minimum_mark_width` = 2 points wide.
3. The exact census goes in the line under the map and in the hover readout.
   The picture is for proportion and presence; the numbers are for numbers.

**Misnamed is NOT bad.** A file found under another name has its data on the
disk, costs no recovery blocks, and gets its own amber state. Counting it as
damage makes a set two renames from perfect look nearly lost - and on a thin
set it reads as unrepairable, refusing a repair that would have worked.

## Why, with the numbers

Two rules are obvious and both are wrong, in opposite directions, and both
fail SILENTLY on the screen the user is deciding from. Measured on the mock's
ten-thousand-block set - 188 damaged blocks, 1.88%, scattered through four of
twenty files, which is what dropped articles look like - at 400 columns:

| rule | 188 scattered damaged | one lone bad block in 10,000 |
|---|---|---|
| worst state wins | **19.5% of the strip red** for 1.88% damage | 1 cell red |
| majority state only | 0% red - **damage invisible** | **0 cells red** |
| majority + bad tick | 0% red, 19.5% ticked | **1 cell ticked** |

Worst-wins over-states damage by an order of magnitude: a repairable set
looks a fifth destroyed. Majority alone hides the single bad block that the
picture exists to reveal. The third rule does neither, and that is the whole
argument.

## Drawing it

Two implementation notes that both ports hit, from the Windows lane:

- **Draw in TWO PASSES, all grounds then all ticks.** A tick drawn cell by
  cell is covered by the next cell's ground once it is widened to the
  2-point floor, so the floor and a single-pass draw are quietly
  incompatible.
- **Merge adjacent cells sharing a ground into one shape before drawing.** A
  clean 1,000-block set is then one rectangle rather than a thousand. This is
  not only about node count: a separate fractional-width rect per cell
  antialiases a hairline between every pair, and a thousand of those read as
  grey stripes over a HEALTHY set.

## Provenance

The first cut of the mac app used worst-wins and the screenshot showed the
19.5% band, which is how it was caught. Chip C (the Windows lane) argued for
worst-wins on 12 Sep 2026 from the correct premise that a merged cell must
never hide a bad block - that premise is what the tick satisfies, and their
2-device-pixel floor on any bad mark is adopted above, because a sub-pixel
rectangle antialiases to nearly nothing and that is the same defect as not
drawing it.

Do not collapse this back to one rule without re-running the table.
