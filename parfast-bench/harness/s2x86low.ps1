param(
  # Defaulted rather than fixed, because the rungs worth spending the window on
  # depend on the UPPER round's finished table and not on its first repetition.
  # A single rep put the tie at 4,096; five may put it a rung either side, and
  # the ladder should be chosen after reading them.
  [string]$Rungs = '2048,2560,3072,3584,4096,4608',
  [int]$Reps = 5,
  # A round's tag names its log, and wlaunch refuses to overwrite one. A second
  # ladder off this file therefore needs its own tag or it cannot start.
  [string]$Tag = 's2x86low'
)
# s2x86low.ps1 - the LOWER half of the Avx512Gfni stage-2 ladder.
#
# WHY A SECOND ROUND. s2x86.ps1 climbs 4,096 to 12,288, which is the band NEON's
# crossing sits in (6,144 to 6,656) plus headroom above the constant. On Zen 5
# the first repetition put the factored arm AHEAD at 5,120 (+8.3%) and 6,144
# (+8.9%), with 4,096 a tie inside its own A/A floor - so the crossing is at or
# BELOW the bottom rung of that ladder and the round cannot see where. A
# crossover you can only bound from one side is not located.
#
# This ladder brackets it from underneath. 4,096 is deliberately REPEATED from
# the upper round: it is the join between the two, and two independent
# estimates of the same rung on the same box, an hour apart, are the only cheap
# check that the pair of rounds can be read as one ladder at all. If the two
# disagree at 4,096 by more than the floor, they cannot.
#
# 4,608 is in the default ladder because the tie may sit ABOVE 4,096 rather
# than below it: a sign flip bracketed only from one side is the same failure
# this round exists to fix, one ladder down.
#
# 2,048 is the bottom because x86's Forney gate is 1,280 and stage 1 must
# actually be the joint additive product on every leg - s2sum.py refuses the
# whole round otherwise, which is the right failure but an expensive way to
# discover a rung was too shallow.
#
# Everything else - arms, seeds, alternation, the SHA gate, the load guard - is
# s2x86.ps1's, unchanged. See that file's header for why both arms force
# NZBFAST_FORNEY_FACTOR and why the A/A arm is a second copy of the forced-off
# arm rather than the shipped solve.
& (Join-Path $PSScriptRoot 'jcross.ps1') -Slice 262144 `
    -Rungs $Rungs `
    -Reps $Reps -Arms 's2off,s2on,s2aa' -Tag $Tag
