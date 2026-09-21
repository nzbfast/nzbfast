# zen5-census.ps1 - READ-ONLY configuration census for windows-gaming-pc-b / amd-ryzen-9800x3d.
#
# Written 18 Sep 2026 for lane zen5-two-box-crossover-disagreement-18sep
# (an internal note, and the handoff
# an internal note).
#
# WHY IT EXISTS. windows-gaming-pc-b and amd-ryzen-9800x3d are nominally identical 9800X3D parts
# and read the same row-gate ladder 27 rows apart in CPU and 46 in wall.
# Decomposing the banked legs says the CPU CORES ARE MATCHED to about a
# percent (the fold arm's feed+fold+solve ratio is 1.012) and that what
# differs is the memory-bound NTT core (1.063) and an arm-independent I/O
# residual (~1.05). That points at memory and storage configuration - and
# NOTHING ON THIS FLEET HAS EVER READ EITHER. `.claude/MACHINES.md` records
# `62 GB RAM` and stops, and 62 GB says nothing about speed, rank or
# channel population. This script reads it instead of inferring it, which
# is the same discipline the KernelClass probe used on 16 Sep.
#
# WHAT IT DOES NOT DO. It starts no process, installs nothing, writes no
# file, and changes no service, power setting or system state. It is
# Get-CimInstance plus one three-second Get-Counter sample. It is still
# worth taking the rig lock and posting a CLAIM before running it: a census
# taken during a neighbour's timing round perturbs their legs, which is why
# the authoring lane did not run it at 13:30Z with codex mid-round.
#
# READ ConfiguredClockSpeed, NOT Speed. `Speed` is the module's rated
# clock; `ConfiguredClockSpeed` is what the memory controller actually
# runs it at, and EXPO/XMP being on or off is exactly the difference this
# is looking for. A pair that reads 6000/6000 on Speed and 6000/4800 on
# ConfiguredClockSpeed is the whole answer.
$ErrorActionPreference='Continue'
"HOST $env:COMPUTERNAME  ts=$([DateTime]::UtcNow.ToString('o'))"
foreach ($m in (Get-CimInstance Win32_PhysicalMemory | Sort-Object DeviceLocator)) {
  "DIMM loc=$($m.DeviceLocator) bank=$($m.BankLabel) cap_gb=$([math]::Round($m.Capacity/1GB,1)) speed=$($m.Speed) configured=$($m.ConfiguredClockSpeed) volt=$($m.ConfiguredVoltage) mfr=$($m.Manufacturer) part=$(($m.PartNumber -replace '\s+',''))  smbios=$($m.SMBIOSMemoryType) formfactor=$($m.FormFactor)"
}
$a = Get-CimInstance Win32_PhysicalMemoryArray | Select-Object -First 1
"MEMARRAY slots=$($a.MemoryDevices) maxcap_gb=$([math]::Round($a.MaxCapacityEx/1MB,0))"
$cs = Get-CimInstance Win32_ComputerSystem
"BOARD mfr=$((Get-CimInstance Win32_BaseBoard).Manufacturer) product=$((Get-CimInstance Win32_BaseBoard).Product) bios=$((Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion) biosdate=$((Get-CimInstance Win32_BIOS).ReleaseDate)"
"SYS ram_gb=$([math]::Round($cs.TotalPhysicalMemory/1GB,1)) model=$($cs.Model)"
# CurrentClockSpeed BELOW IS A NAMEPLATE-ISH INSTANTANEOUS FIGURE AND IS NOT
# A SUSTAINED-CLOCK MEASUREMENT. Read MaxClockSpeed as the part's nominal and
# treat CurrentClockSpeed as a sanity check only. If you need the real thing,
# take it deliberately - an internal note section 2a is
# the route that has been proved, and lane cf-thermal-drift-candidate3-18sep
# is why wcomb.ps1's own freq_mhz column must not be used for it: it derives
# perf_pct from a single un-refreshed read of a DELTA counter and moves 2.83x
# across legs whose occupancy and temperature are fixed.
foreach ($p in (Get-CimInstance Win32_Processor)) {
  "CPU name=$(($p.Name -replace '\s+',' ')) maxclk=$($p.MaxClockSpeed) curclk=$($p.CurrentClockSpeed) cores=$($p.NumberOfCores) logical=$($p.NumberOfLogicalProcessors) l2=$($p.L2CacheSize) l3=$($p.L3CacheSize)"
}
try { foreach ($d in (Get-CimInstance -Namespace root\Microsoft\Windows\Storage MSFT_PhysicalDisk)) {
  # MSFT_PhysicalDisk's media-type property is deliberately NOT read here:
  # its name opens with the six characters of intel-i5-10600kf, and
  # harness/ is published WHOLE to the public
  # site, so the box-name near-miss arm of tools/scrub-bench-logs.py refuses
  # the export over it - correctly, since it cannot know this one is a CIM
  # property. BusType and SpindleSpeed carry what this census actually needs
  # (NVMe against SATA, and 0 for solid state), so the field is dropped
  # rather than the gate taught a spelling that would then be REWRITTEN in
  # published content.
  "DISK fn=$($d.FriendlyName) bus=$($d.BusType) size_gb=$([math]::Round($d.Size/1GB,0)) spindle=$($d.SpindleSpeed)"
} } catch { "DISK-ERR $_" }
foreach ($d in (Get-CimInstance Win32_DiskDrive)) { "DRIVE model=$($d.Model) iface=$($d.InterfaceType) size_gb=$([math]::Round($d.Size/1GB,0))" }
try { $pp = Get-CimInstance -Namespace root\cimv2\power Win32_PowerPlan -Filter "IsActive=True"; "POWERPLAN $($pp.ElementName)" } catch { "POWERPLAN-ERR $_" }
"UPTIME_H $([math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalHours,1))"
"OS $((Get-CimInstance Win32_OperatingSystem).Caption) build=$((Get-CimInstance Win32_OperatingSystem).BuildNumber)"
"FOREIGN_CPU_PCT $([math]::Round(((Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3).CounterSamples | Measure-Object CookedValue -Average).Average,1))"
"CENSUS-END"
