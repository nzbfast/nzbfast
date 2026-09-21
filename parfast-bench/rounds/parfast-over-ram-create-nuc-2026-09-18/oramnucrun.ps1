# oramnucrun.ps1 - the plan, baked in, because wlaunch.ps1 launches a script
# with -File and passes no arguments. Cells are gib:pct:arm:reps.
#
# ORDER IS DELIBERATE. The 24 GiB under-RAM control runs FIRST: it is cheap
# (~2 minutes a leg against up to ~15 for a 90 GiB over-RAM leg) and it is the
# DENOMINATOR of the acceptance ratio "a 1.4x-RAM create within 1.3x the
# under-RAM pace on the same box", so a round that dies half way still has the
# figure every over-RAM leg is measured against. Then 90 GiB at 15%, which is
# the shape TODO 345 still OWES (the 2.06x miss on the 62 GB desktop), then
# 90 GiB at 5%, which is the Reddit report's own shape.
#
# reps=1 FOR b3 ONLY, and that is defensible rather than thrifty:
# an internal note's predicate is that order and
# rep count matter where arms are expected to be CLOSE. b3 lacks both fixes
# and the effect is 2-5x on every banked round; b4 against tip is the pair
# that could be close, and both get two reps in mirrored order.
& D:\oramnuc-18sep\oramnuc.ps1 `
  -Root 'D:\oramnuc-18sep' -Tag 'oramnuc1' -MaxReps 2 `
  -Plan '24:5:b3:1;24:5:b4:2;24:5:tip:2;24:5:pp:2;24:15:b3:1;24:15:b4:2;24:15:tip:2;24:15:pp:2;90:15:b3:1;90:15:b4:2;90:15:tip:2;90:15:pp:2;90:5:b3:1;90:5:b4:2;90:5:tip:2;90:5:pp:2'
exit $LASTEXITCODE
