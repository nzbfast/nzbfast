# Driver for `mswp.log`

Fetched read-only from `apple-m3-ultra` (`.claude/MACHINES.md`) on 18 Sep 2026,
after the round had already run. This is a RECORD of the driver as found on
the box, not a verified reproduction of the round: nothing here was re-run.

| file | box path | sha256 | box mtime |
|---|---|---|---|
| `mswp.py` | `~/pubrun/mswp.py` | `7fb1be8f18f815ba806368cb975acabaaf13e08599a075343ccd7896f5a850fd` | 2026-09-11T00:02:05Z |
| `mlad.py` | `~/pubrun/mlad.py` | `fa231ea573cd216828b92017888921da38083eb0468b62850c588ec2c6e8284b` | 2026-09-10T12:15:18Z |

`mswp.py` is the driver that wrote `mswp.log` (the file's own docstring:
"mswp.py - ROUND 4, the create + verify size sweep"). `mlad.py` is this
box's own copy of the 15% ladder driver, fetched alongside it per the chip
instructions; no log in this tree is attributed to it by name.

Local copies were re-hashed after transfer and match the box byte for byte.

## Cross-check against the log

`mswp.log` carries `BIN parfast sha256=...` and `BIN par2turbo sha256=...`
lines for the two binaries under test but no `HARNESS ... sha256=` line for
the driver script itself, so there is nothing in the log to check
`mswp.py`'s hash against. Not verified; noted rather than guessed.

## Arm-order classification (per the rubric in
an internal note section 1)

`mswp.py`'s create-sweep loop (l.105-116):

```
for g in SIZES:
    ...
    for r in REDS:
        for arm in ("parfast", "turbo"):
```

runs `parfast` then `turbo` in every `(size, redundancy)` cell with no
rotation. The r=20 gate cross-verifies with whichever tool did NOT create
the set, and the `parfast`-created set additionally gets a two-rep,
two-tool verify pass (`for vrep in (1, 2): for varm in ("parfast", "turbo")`,
l.152-153) - also fixed order, parfast first. **FIXED** (parfast always
first), consistent with the census's section-1 note that both of the two
not-in-tree published drivers "run parfast before turbo in every cell."
