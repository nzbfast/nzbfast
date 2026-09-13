# zen5aa.ps1 - the SECOND MACHINE for a default that already ships on.
#
# `parfast --fast` is the default on KernelClass::Avx512Gfni since 9856e25f19.
# As of this afternoon the evidence for that is one shared virtual machine this
# campaign withdrew from timing quotation, plus ONE bare-metal round, on
# amd-ryzen-9800x3d, 45 legs. One round on one part is not a basis for a shipped
# default - I said exactly that about the deepest rung of that round and it
# applies to the round itself.
#
# windows-gaming-pc-b is its identical twin: same part, same memory, same Windows build. So
# this is `zen5.ps1` verbatim on a second physical machine, and if it agrees the
# default rests on two independent boxes rather than one.
#
# IT IS ALSO THE ONLY CROSS-MACHINE A/A THIS FLEET CAN RUN, and that is a
# second-order benefit rather than the reason. jcross SEEDS its payload, so the
# 4 GiB fixture is byte-identical across boxes; with the same binary, argv,
# rungs, arms and reps, whatever the two machines disagree by is the floor below
# which no cross-box number means anything. Worth having, but every claim this
# campaign publishes is a WITHIN-box ratio, which cancels box-to-box variation
# by construction - so this does not validate a published figure, and must not
# be sold as though it did.
#
# TWO HONEST CAVEATS, because this is a borrowed desktop and not a rig.
#
# The harness moved between the two runs. amd-ryzen-9800x3d ran at 17:22Z on jcross.ps1
# `823aa18a6508`; this runs on `151d794ac27a`, which adds the `ctrl_s` control
# field and a refusal gate over a failed smoke. Neither touches argv, the
# fixture, the damage, the arms or the timed section - Invoke-Leg measures the
# child process and both additions sit outside it - so the comparison holds.
# Stated rather than hidden, because a reader comparing two logs will see two
# different harness hashes and is entitled to know which differences are inert.
#
# And these are desktops in use. Idleness is established per leg by the guard
# and printed beside every timing, never assumed, and a deadline is armed
# separately so nothing outlives the lending window.
& (Join-Path $PSScriptRoot 'jcross.ps1') -Slice 262144 -Rungs '2048,4096,8192,12288,16384' -Reps 3 -Arms 'off,fast,aa' -Tag 'zen5aa'
