# zen5rev.ps1 - re-validate joint_default_on() for Avx512Gfni on a QUOTABLE part.
#
# WHY THIS ROUND EXISTS, and it is not the same question zen5.ps1 asked.
#
# `joint_default_on()` returns true for `avx512_gfni_available()` since
# 9856e25f19. The comment carrying that flip names its evidence: one round on an
# EPYC 9354P, medians of THREE, and it says in as many words "THE SHALLOW BAND
# IS THE ONE THAT MATTERED". That band is 2,048 +4.4%, 4,096 +1.6%, 6,144 +3.7%.
#
# On 11 Sep 2026 the Zen 4 sign round measured that same box's A/A floor - the
# same arm against itself, paired per rung - at **13.6 to 36.9%**
# (JOINT-FACTOR-MIN-M-X86-2026-09-11.md section 19). Every shallow number above
# is inside it. The deep half of that round (+29.7/+24.9/+29.1%) clears the
# floor and survives; the half its own author called decisive does not.
#
# So a shipped default for an entire kernel class rests, in the band that
# matters, on numbers its box cannot support. That is not evidence the default
# is WRONG - it is the absence of evidence that it is right.
#
# WHY NOT JUST READ THE TWO ROUNDS ALREADY ON THESE BOXES. Both were run on
# 11 Sep and neither is quotable on its own:
#
#   * amd-ryzen-9800x3d `zen5` (48 legs) HOLDS its positive control and puts the shallow
#     band clear of its floor - but it recorded NO control phase at all, so the
#     A/A floor is its only evidence the box was quiet.
#   * windows-gaming-pc-b `zen5x` (129 legs) HAS a control phase and it held (A/B 1.30%
#     against A/A 1.60%), but `jsum.py` declares the round VOID on its own
#     positive control: m=16,384 reads +2.60% against a >3% threshold.
#
# THE 16,384 FAILURE IS STRUCTURAL AND IS WHY THIS LADDER STOPS AT 12,288. The
# fixture is 16,384 source blocks, so m=16,384 is the degenerate rung where
# EVERY source block is missing and the whole recovery pool is consumed. Both
# boxes collapse there independently (+3.50% on amd-ryzen-9800x3d, +2.60% on windows-gaming-pc-b)
# while both read +28 to +33% at 12,288. A positive control that lands on the
# full-rank case is not measuring the same thing the other rungs are. That is
# reported rather than fixed in `jsum.py`: the rule is not loosened to admit a
# round, which is the one edit that would make the check worthless.
#
# THE LADDER. Five shallow rungs across the band the default's own comment calls
# decisive, plus 12,288 as the positive control - the rung both prior rounds
# reproduce strongly, and the deepest one that is not degenerate. 1,536 is
# included because it is the first rung above x86's Forney gate (1,280) at which
# the two arms are different code at all; below it they are identical and the
# comparison is an end-to-end A/A by construction.
#
# FIVE reps rather than zen5.ps1's three. The effect in this band is 4-9% and
# these boxes' A/A floors run 0.5-6%, so three reps leaves the shallowest rung
# too close to its floor to carry a default.
#
# BOTH BOXES, same ladder, so the result is two parts rather than one - the
# standard the NEON constant met and the one section 9 of the x86 write-up says
# a class-wide claim needs. A disagreement between them is a finding, not an
# error to average away.
#
# BORROWED MACHINES. windows-gaming-pc-b and amd-ryzen-9800x3d are borrowed gaming PCs, cleared by
# him for this round on 11 Sep 2026. Idleness is established per leg by the
# harness's own foreign-CPU guard and printed beside every timing.
& (Join-Path $PSScriptRoot 'jcross.ps1') -Slice 262144 `
    -Rungs '1536,2048,3072,4096,6144,12288' `
    -Reps 5 -Arms 'off,fast,aa' -Tag 'zen5rev'
