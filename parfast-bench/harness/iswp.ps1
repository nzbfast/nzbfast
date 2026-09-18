# The i5 create sweep. Same script as the coreultra9's, different geometry: 12
# logical cores, 64 GB, and the full 10-80 GiB size range the Apple round used,
# so the Intel and Apple sweeps compare size for size.
& '<rig>\swpcore.ps1' -root '<rig>' -sizes @(10,15,20,23,30,40,50,60,70,80) -reds @(10,15,20) -threads 12 -membudget_mb 2048 -round 'i5swp'
