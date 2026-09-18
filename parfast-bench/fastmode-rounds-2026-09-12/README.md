# fast-mode rounds, 12 Sep 2026

Raw logs behind an internal note.
Reduce with `harness/jsum.py --base off --test <arm> <log>`;
for the stage-1 pairings use `--base fast --test s1off` and read the
rung's `off`/`aa` floor, or on jx3 `--base s1on --test s1off --aa s1aa`.

| log | box | class | binary | arms |
|---|---|---|---|---|
| jx6-i5.log | intel-i5-10600kf i5-10600KF | Nibble | parfast-jx2 / -jd / -jb | off fast fastdir fastb s1off aa |
| jx7-i5.log | intel-i5-10600kf | Nibble | parfast-jg (stage-1 gate) | off fast aa |
| jx5-coreultra9.log | intel-core-ultra-9-386h Core Ultra 9 386H | Gfni256 | parfast-jx2 / -jb | off fast fastb s1off aa |
| jx8-coreultra9.log | intel-core-ultra-9-386h | Gfni256 | parfast-jg | off fast aa |
| jx2-m1.log | apple-m1-ultra-64gb M1 Ultra | NEON | parfast-jx2 | off fast aa |
| jx3-m1.log | apple-m1-ultra-64gb | NEON | parfast-jx2 | s1off s1on s1aa |

`jx6-i5-stage-lines.txt` is the per-leg `repair-timing` stage lines of
jx6, pulled from `<rig>\jcross-262144\logs\r*.err` on the box - the
durations the LEG line drops. Binaries are pinned by sha256 on each
log's BIN lines; all were built from `a62e5e798ff0` plus the stage-1
knob (`-dirty`), `parfast-jg` from `8fbab9b1a921` plus the gate.
