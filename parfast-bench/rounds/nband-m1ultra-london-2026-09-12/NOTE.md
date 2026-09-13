# nband on the London M1 Ultras, 12 Sep 2026 - the dense NEON check, second and third parts

Same round as rounds/nband-m5max-2026-09-12 (see its NOTE for the
question), same binary (parfast-jx f7c2b523..., built from 8c3da7d70d2d),
same nine half-step rungs, three repetitions, A/A control, SHA-256 gating.
Both boxes ran behind waitquiet.py after repeated load aborts; the log is
each box's `nband-wait.log` (waitquiet execs the round, so the round's
stdout lands in the launcher's file).

## M1 Ultra "b" (nband-m1ultra-b.log), 84/84 restored

    m      off    fast   delta   aa (A/A)
    2048   4.062  4.059  +0.1%   -0.8%
    2560   4.371  4.388  -0.4%   +0.4%
    3072   4.607  4.527  +1.7%   +0.3%
    3584   4.889  4.662  +4.6%   +0.3%
    4096   5.109  4.928  +3.5%   -0.4%
    4608   5.521  5.510  +0.2%   -0.0%
    5120   5.668  5.607  +1.1%   +0.5%
    5632   5.779  5.703  +1.3%   -0.3%
    6144   6.019  5.838  +3.0%   +0.4%

No loss band. The one negative rung (-0.4% at 2,560) is inside the A/A.
Two legs at 4,608 and 5,120 ran with 160-181% foreign CPU (the guard's
ceiling is 200%; one BOX-BUSY-WAIT pair at r3-m5120 waited it out); the
medians there are flat rather than adverse.

## M1 Ultra "a" (nband-m1ultra-a.log), 84/84 restored, 64 GB box

    m      off    fast   delta   aa (A/A)
    2048   4.114  4.035  +1.9%   +0.6%
    2560   4.381  4.408  -0.6%   -1.8%
    3072   4.637  4.580  +1.2%   -0.3%
    3584   4.977  4.737  +4.8%   +1.3%
    4096   5.202  4.924  +5.3%   -1.1%
    4608   5.460  5.496  -0.7%   +0.1%
    5120   5.696  5.649  +0.8%   -0.3%
    5632   5.836  5.762  +1.3%   -1.4%
    6144   6.126  5.912  +3.5%   -0.8%

No loss band. Both negatives (-0.6%, -0.7%) are inside the A/A's +-1.8%.
Two legs ran at 138-162% foreign CPU (a DriveGenius agent had to be booted
out of launchd for the night; the screensaver's WindowServer stayed).

## Across the three Apple parts

M5 Max, M1 Ultra a, M1 Ultra b: 27 rung-medians, worst -2.6% (M5 at 4,608,
0.1 s), best +5.3% (M1a at 4,096), every negative inside its own A/A. The
band where the AVX2 class loses up to 12.9% does not exist on NEON. The
shipping Apple default holds on every part measured.
