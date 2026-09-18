# poolladder4m-2026-09-17 - the pool-size ladder with the core class held FIXED

Lane `parfast-4mib-pinned-pool-ladder`. Write-up: the section "The pool-size
ladder with the core class held FIXED: doubling the pool moves the crossover +34
rows, and the full-box arm is monotone this time (17 Sep 2026)" at the end of
an internal note.

## The question

The 17 Sep pinned sitting held the pool at four threads and moved only the CPU
mask, and found placement alone swings the resident CPU crossover 42 to 52 rows -
three to four times the 14-row `-t4`/`-t16` gap the "one second rung serves both
pools" clause rests on. It could not then compare pool sizes, because the
comparison needed a `-t16` arm and that arm was non-monotone in every sitting.

This round asks the pool-size question in the one way that needs no full-box arm:
**move the pool with the core class held fixed.** On a Core Ultra 9 386H (4 P,
8 E, 4 LP-E) the E class is the only one wide enough to offer that step.

## The arms

| log | label | mask | cores | class | threads |
|---|---|---|---|---|---:|
| `logs/plt16.log` | `4m-t16` | none | 0-15 | 4P+8E+4LPE MIXED | 16 |
| `logs/ple4.log` | `4m-e4` | `0xF0` | 4-7 | E only | 4 |
| `logs/ple8.log` | `4m-e8` | `0xFF0` | 4-11 | E only | 8 |
| `logs/plm12.log` | `4m-m12` | `0xFFF` | 0-11 | 4P+8E MIXED | 12 |
| `logs/plp4.log` | `4m-p4` | `0xF` | 0-3 | P only | 4 |

`4m-t16` runs FIRST because `wcomb` builds the fixture on the first ladder and
`-Affinity` arms every leg including that create, so a pinned arm first would
build 37.8 GB on four cores.

## Files

- `poolladder-round.ps1` - the driver. Copied from
  `rounds/pinaff4m-2026-09-16/pinaff-round.ps1` with the arm table
  changed and ONE structural change: the tarball extraction and the `cargo
  build` are gated behind the same lock-free-and-quiet check a measurement arm
  is, because this round had to build its own binary and fixture and a build is
  foreign load to whoever is measuring.
- `poolladder-driver.log` - the sitting that produced the logs, 14:42:27Z to
  16:52:09Z.
- `poolladder-attempt1-shagate.log` - the launch that REFUSED and measured
  nothing, banked rather than dropped. It gated on the sha256 the chip brief
  quotes; that hash is path-dependent (the build embeds its own path) and cannot
  match from a different root, which the note records of the create lane's own
  build. The gate is now the 4,173,312-byte count. A wrong LENGTH still ends the
  round.

## Reduce

    python3 harness/rowgate.py read rounds/poolladder4m-2026-09-17/logs/ple8.log

Groups by (label, threads); the five labels are distinct so the five arms reduce
separately. Screen before believing any crossover:

    python3 rounds/pinaff4m-2026-09-16/ladder-monotonicity-audit.py \
        rounds/poolladder4m-2026-09-17/logs/*.log

All five came back monotone.

## The one thing a reader gets wrong

**CPU-seconds do not compare across masks.** A P-core second buys 1.74x what an
E-core second does on this part (class probe, in `poolladder-attempt1-shagate.log`),
so `4m-e8` burning more CPU than `4m-p4` is not more work. Only the CROSSOVER
compares across arms, because it is a ratio of fold to force WITHIN one arm on
one core mix.
