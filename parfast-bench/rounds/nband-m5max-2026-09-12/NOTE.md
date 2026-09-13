# nband on the M5 Max, 12 Sep 2026 - the dense NEON check

Question: the AVX2/SSSE3 class (Nibble) loses across 2,048-6,144 with the
joint solve on, worst -12.9% at 5,120. NEON's default already ships ON, on a
14-rung ladder that took whole steps. Is there a narrower loss band between
those rungs on NEON?

Answer: no. Nine rungs at half-steps, three repetitions, an A/A control,
84/84 legs restored (sha256 of every member). Median wall, fast vs off:

    m      off    fast   delta   aa (A/A)
    2048   3.519  3.463  +1.6%   -1.6%
    2560   3.796  3.784  +0.3%   +0.7%
    3072   3.961  3.888  +1.8%   -0.7%
    3584   4.245  4.172  +1.7%   -0.7%
    4096   4.472  4.321  +3.4%   +0.1%
    4608   4.588  4.709  -2.6%   -1.1%
    5120   4.728  4.728  +0.0%   -0.3%
    5632   4.877  4.815  +1.3%   +0.6%
    6144   5.000  4.836  +3.3%   +0.0%

The one negative rung, 4,608, loses on all three paired repetitions but by
0.04-0.10 s, inside the +-1.6% the A/A shows. Stage labels are `no-label` on
every leg in this band (the joint factor's gate is 8,192), so the two arms
differ only in what the JOINT switch gates below that. Foreign CPU peaked at
166% of 1,800% on a few legs; the leg guard's ceiling is 200%.

Binary parfast-jx sha256 f7c2b523..., built from 8c3da7d70d2d. Harness:
harness/nband.py over jcross.py (the s2aa-less copy; nband uses
off/fast/aa only). The same round is running on the two London M1 Ultras.
