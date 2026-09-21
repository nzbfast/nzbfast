# zswp3run.ps1 - the launch line for the zswp3 re-run, the coreultra9 analogue of
# harness/iswp.ps1. Same geometry as the published zswp2 round's PROTOCOL line:
# sizes 10,15,20,23,30,40 GiB, redundancy 10,15,20, 16 threads, 2048 MB mem arm.
# The driver script is harness/swpcore.ps1 from origin/main, unchanged.
& "$PSScriptRoot\swpcore.ps1" -root $PSScriptRoot -sizes @(10,15,20,23,30,40) -reds @(10,15,20) -threads 16 -membudget_mb 2048 -round 'zswp3'
exit $LASTEXITCODE
