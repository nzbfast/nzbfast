# zen5.ps1 - the whole-arm confirmation on the first QUOTABLE Avx512Gfni part.
#
# `parfast --fast` is the DEFAULT on KernelClass::Avx512Gfni as of 9856e25f19,
# landed 11 Sep 2026. The evidence for that flip is a round on a shared virtual
# machine this campaign WITHDREW from timing quotation - 15 of 34 rungs above 5%
# spread, worst 99%. So a shipped default currently rests on numbers nobody will
# publish. This round is the first from bare metal in that class.
#
# Five rungs rather than jcross's fourteen, because this is a confirmation and
# not a crossing: 2,048 and 4,096 below JOINT_FACTOR_MIN_M where stage 2 falls
# back and only stage 1 is joint, 8,192 at the constant itself, and 12,288 and
# 16,384 as the positive control where the 10 Sep rounds measured 9-40%. Three
# arms, three repetitions, `aa` at every rung so the floor is paired and
# per-depth.
#
# BORROWED MACHINE, AND EVERY NUMBER CARRIES THAT. It is a desktop in use rather
# than a bench rig, so idleness is established per leg by the harness's own
# foreign-CPU guard and printed beside every timing, never assumed. A deadline
# is armed separately so nothing outlives the lending window.
& (Join-Path $PSScriptRoot 'jcross.ps1') -Slice 262144 -Rungs '2048,4096,8192,12288,16384' -Reps 3 -Arms 'off,fast,aa' -Tag 'zen5'
