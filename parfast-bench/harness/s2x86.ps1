# s2x86.ps1 - JOINT_FACTOR_MIN_M on the Avx512Gfni class.
#
# THE QUESTION. `forney::joint::JOINT_FACTOR_MIN_M` is 8,192. It decides
# whether stage 2 of the joint Forney solve takes its FACTORED evaluation;
# below it stage 2 takes the shipped arithmetic and stage 1 runs alone. The
# constant was measured on aarch64 ALONE - the crossover sits between 6,144
# and 6,656 there (JOINT-STAGE2-DEPTH-GATE-2026-09-11.md), plus a deliberate
# 1.23x margin under a bias-HIGH rule - and it was replicated on a second NEON
# generation but never on x86.
#
# WHY IT IS LIVE ON x86 ANYWAY. 9856e25f19 made joint_default_on() true for
# avx512_gfni_available(). So a default-on Zen 4 or Zen 5 past m = 8,192 now
# takes a factored stage 2 under a threshold measured on Apple silicon. That is
# bounded rather than alarming - the bias is HIGH, so the cost of being wrong
# is forgone gain and not a growing loss - which is exactly why it is worth a
# measurement rather than an alarm.
#
# THE BLOCKER THAT EXPIRED, AND THE EVIDENCE IT DID. Until 12:01Z on 11 Sep
# (9d91798cec) a GFNI part declined stage 1 until NZBFAST_GF16_ROWOP_GFNI was
# armed, so an x86 round would have had to hold stage 1 on the shipped
# arithmetic - a different composition from the NEON round and not a port of
# it. joint_stripe now consults gf16::scale_available(), and the zen5 round on
# this very box (<rig>\zen5.log, 17:22-17:45Z) printed
# `stage1=joint-whole-demand` on its --fast arm with NOTHING armed. Stage 1
# engages natively here, so this round is a straight port of the NEON one.
#
# DO NOT reach for NZBFAST_GF16_ROWOP_GFNI to "help" stage 1. On x86 it gates
# TWO subsystems: the fused butterfly AND gf16::inplace_scale_preferred(), so
# arming it also switches par2ntt's additive leaf from folding through a zeroed
# temporary to scaling in place. An arm defined as "the variable plus
# something" moves three things and isolates none of them.
#
# THE ARMS, and this is the single thing most likely to go wrong.
#   * BOTH arms set NZBFAST_FORNEY_JOINT=1, so stage 1 runs the additive
#     product on both sides and cannot contaminate the comparison. This is a
#     STAGE-2 measurement, not a whole-arm one.
#   * They differ ONLY in NZBFAST_FORNEY_FACTOR, forced `off` on one and `on`
#     on the other. Forced in BOTH directions deliberately: an arm left on a
#     default stops measuring the moment the default moves, and the default
#     moved today.
#   * s2aa is a SECOND COPY of s2off, never the shipped solve. Pairing a
#     forced-off arm against the shipped solve measures STAGE 1 - an A/B
#     wearing the name of a floor - and at these effect sizes it swamps the
#     crossing. The 4.6 round's first launch used the wrong arm and was
#     abandoned and relaunched rather than reported.
# All three arm definitions already live in jcross.ps1's $ArmTable; this file
# selects them and owns the LADDER, which is the only thing that differs from
# the crossover round.
#
# WHY ONE ROUND AND NOT TWO. The NEON round ran its A/A and its A/B as separate
# rounds an hour apart. Here all three arms run at every rung inside one round,
# on the SAME damage seed, with the order alternating by rep - so the floor is
# paired per-depth against the very legs it is a floor for, rather than against
# a different hour of the box. The A/B pair (s2off, s2on) sits adjacent in the
# arm order and the A/A pair (s2off, s2aa) sits at the two extremes, so the
# floor carries MORE within-rung drift than the measurement does. That is the
# conservative direction: it makes a win harder to claim, never easier.
#
# THE LADDER. Seven rungs reuse the NEON band (4,096 to 8,192) so the two
# classes are compared on the same depths, and 10,240 and 12,288 extend above
# the constant for two reasons: the crossing may simply sit higher on a part
# whose shipped `evaluate` path is better vectorised than NEON's, and the deep
# end is the POSITIVE CONTROL - if the factored arm does not win there, every
# other row of the round is void.
#
# THE CONTROL. Stage 1's mark is NOT a control: both stage marks are ATTRIBUTED
# shares of one fused wall, so a slower stage 2 mechanically shrinks stage 1's
# share. Read `verify_targets_volume_scan` - a phase this change cannot reach.
#
# BORROWED MACHINE. windows-gaming-pc-b and amd-ryzen-9800x3d are borrowed gaming PCs, lent for a
# stated window. A deadline is armed separately so nothing outlives it, and
# idleness is established per leg by the harness's own foreign-CPU guard and
# printed beside every timing rather than assumed.
& (Join-Path $PSScriptRoot 'jcross.ps1') -Slice 262144 `
    -Rungs '4096,5120,6144,6656,7168,7680,8192,10240,12288' `
    -Reps 5 -Arms 's2off,s2on,s2aa' -Tag 's2x86'
