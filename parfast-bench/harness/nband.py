#!/usr/bin/env python3
"""nband.py - is the loss band on NEON too, where the default already ships ON?

The AVX2/SSSE3 class was measured tonight at 14 rungs and it LOSES across a
wide band - five consecutive rungs from 2,048 to 6,144, worst -12.9% at 5,120
against a 0.8% floor - with a further loss at 10,240 sitting between two wins.
That decided `Nibble` against flipping.

NEON's default was flipped ON, on 14 coarse rungs that showed no such band. But
the AVX2 ladder had the same 14 rungs and its worst loss sits at 5,120, which is
a rung BOTH ladders sampled - so coarseness is not the explanation there, and
the NEON evidence is not obviously thin. What has never been checked is whether
NEON has a narrower hole BETWEEN those rungs.

That matters more than an ordinary open question: NEON's default is already
shipping on every Mac. If there is a band, it is a regression users have.

So this is the same whole-arm A/B at nine rungs across the band the other class
lost in, half-steps where that ladder took whole ones, three repetitions, an
A/A control at every rung. It answers one question and nothing else.
"""
import os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
BAND = "2048,2560,3072,3584,4096,4608,5120,5632,6144"
cmd = [sys.executable, os.path.join(HERE, "jcross.py"),
       "--rungs", BAND, "--reps", "3", "--arms", "off,fast,aa", "--tag", "nband"]
print("NBAND-START rungs=%s" % BAND, flush=True)
sys.exit(subprocess.call(cmd))
