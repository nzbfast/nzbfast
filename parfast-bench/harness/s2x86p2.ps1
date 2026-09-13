param([string]$Rungs = '7680,7936,8192,8448,8704', [int]$Reps = 3, [string]$Tag = 's2x86p2')
# s2x86p2.ps1 - is the shipped stage 2 anomalously fast at POWER-OF-TWO depths?
#
# THE OBSERVATION THIS TESTS. Across two Zen 5 ladders on 11 Sep 2026 the
# factored stage 2 beat the shipped one by 5-14% at every rung EXCEPT 2,048,
# 4,096 and 8,192, where the advantage collapsed into its own A/A floor or
# reversed. The absolute medians say it is the SHIPPED arm moving, not the
# factored one:
#
#   m            7168    7680    8192    10240
#   s2off        1.390   1.480   1.360   2.080     <- FALLS from 7,680 to 8,192
#   s2on         1.320   1.350   1.350   2.070     <- flat
#
# A cost that DROPS as m rises is not noise, and the same shape appears at
# 4,096 on both boxes independently.
#
# WHY IT MATTERS BEYOND CURIOSITY, AND WHY IT IS WORTH A BOX-HALF-HOUR.
# `JOINT_FACTOR_MIN_M` is 8,192 - itself a power of two - so the constant sits
# exactly on a depth where the shipped arm is at its strongest. Worse, a
# crossover ladder that samples powers of two (4,096 / 8,192 are the natural
# choices, and both prior rounds used them) measures the factored arm at its
# worst relative showing and would place the crossing too HIGH. If this
# reproduces it is a methodological finding about how every crossover in this
# campaign was located, not a fact about one constant.
#
# THE LADDER IS DENSE AND STRADDLES 8,192 rather than spanning decades: 7,680
# and 8,448 are 512 either side, 7,936 and 8,704 are 256 and 512 beyond. If the
# dip is a property of the value 8,192 it shows as a notch at one rung with its
# four neighbours smooth. If instead the whole 7,680-8,704 region is flat, the
# earlier readings were noise and the power-of-two story dies - which is the
# outcome that would matter most, because two ladders already rest on it.
#
# THREE reps rather than five, deliberately: the borrowed boxes go back at
# 20:00Z and a round that does not finish inside the window is worth less than
# a shorter one that does. The A/A arm still runs at every rung, so each rung
# carries its own floor and a null result stays readable.
& '<rig>\s2x86low.ps1' -Rungs $Rungs -Reps $Reps -Tag $Tag
