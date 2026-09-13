# zgfni2 on the Core Ultra 9 386H (Gfni256), 12 Sep 2026

The second-machine measurement the GFNI row-op flip was waiting on. Four
arms, all with the joint solve OFF: base (e0b44df99c31) and leaf
(3667a696d50b, deletes the inplace_scale gate arm), each with and without
NZBFAST_GF16_ROWOP_GFNI=1. 23 members, 23 GiB, 32,177 blocks at 100%
parity, two repetitions, every leg restored 23/23.

Repair, median wall (s):

    m       base    basegate  leaf    leafgate   gate vs base  gate vs leaf
    16384   242.9   240.7     237.6   241.1      +0.9%         -1.5%
    30000   458.9   465.9     452.6   450.5      -1.5%         +0.5%

A wash: every difference is inside 1.5% on two repetitions with 52-81%
foreign CPU on the box. No case for the flip from repair on this class, and
no case against it.

Create, one run per arm, same parity set (CREATE-IDENTICAL all_arms=True,
setsha 21F98ADD5355E7FF): base 99.0 s, basegate 126.9 s, leaf 127.9 s,
leafgate 158.6 s. That reads as the gate costing 25-30% at create, but the
basegate create ran at 83% foreign CPU against base's 19%, and a single run
each cannot separate the two. Re-run the creates before reading anything
into them.
