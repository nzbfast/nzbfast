# The within-binary isolation of the band route, tip binary only.
# oramx.ps1 is the HOUSE harness, unmodified, and its fixture naming
# (f<gib>g.bin under $Root\fix) is exactly what oramnuc1 wrote, so the
# 90 GiB member is reused rather than rewritten.
#   main    = the tip build as it ships (gate refuses the mapping, bands take it)
#   nobands = NZBFAST_CREATE_STRIPE_BANDS=0, the copied windows, same binary
# Cells are gib:pct:arm:avail_gb:mem_mb:reps - no RAM lock (avail_gb 0), the
# box's own derived budget (mem_mb 0).
& D:\oramnuc-18sep\stage\tip\src\research\harness\oramx.ps1 `
  -Root 'D:\oramnuc-18sep' -Tag 'oramnuc2' `
  -Bin 'D:\oramnuc-18sep\stage\tip\src\target\release\parfast.exe' `
  -MaxReps 2 `
  -Plan '90:15:main:0:0:2;90:15:nobands:0:0:2;90:5:main:0:0:2;90:5:nobands:0:0:2'
exit $LASTEXITCODE
