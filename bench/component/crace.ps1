# crace.ps1 - archive CREATION race on Windows, the twin of crace.py.
#   powershell -File crace.ps1 -Payload DIR -Work DIR -Rounds N -Rar path -Ours path -SevenZ path -UnRar path [-Only store,m3] [-Label host]
# Same shapes, same rotate-then-mirror order, one process per cell; wall from
# a Stopwatch, CPU and peak working set from the exited process object, packed
# bytes summed over the outputs, and every RAR output verified with UnRAR t
# (rar's own too, so the verifier is the same for both arms). Inputs are
# read once first so both arms see a warm cache.
param(
  [Parameter(Mandatory=$true)][string]$Payload,
  [Parameter(Mandatory=$true)][string]$Work,
  [int]$Rounds = 2,
  [string]$Tools = "rar,ours,ours32,sevenz",
  [string]$Rar = "C:\Program Files\WinRAR\Rar.exe",
  [string]$Ours = "",
  [string]$SevenZ = "C:\Program Files\7-Zip\7z.exe",
  [string]$UnRar = "C:\Program Files\WinRAR\UnRAR.exe",
  [string]$Only = "store,storev,m3,m3v,rep,small,enc",
  [string]$Label = "win"
)
$ErrorActionPreference = "Continue"
$MB125 = 125000000
$shapes = [ordered]@{
  store  = @{ input = "rand.bin"; cmds = @{
      rar = "a -ma5 -m0 -ep -idq -y -o+ {out}.rar {inputs}"; ours = "a -m0 {out}.rar {inputs}";
      sevenz = "a -t7z -mx0 -bso0 -bsp0 -y {out}.7z {inputs}" } }
  storev = @{ input = "rand.bin"; cmds = @{
      rar = "a -ma5 -m0 -ep -idq -y -o+ -v125m {out}.rar {inputs}"; ours = "a -m0 -v$MB125 {out}.rar {inputs}" } }
  m3     = @{ input = "mixed.bin"; cmds = @{
      rar = "a -ma5 -m3 -ep -idq -y -o+ {out}.rar {inputs}"; ours = "a -m3 {out}.rar {inputs}";
      ours32 = "a -m3 -md33554432 {out}.rar {inputs}"; sevenz = "a -t7z -mx3 -bso0 -bsp0 -y {out}.7z {inputs}" } }
  m3v    = @{ input = "mixed.bin"; cmds = @{
      rar = "a -ma5 -m3 -ep -idq -y -o+ -v125m {out}.rar {inputs}"; ours = "a -m3 -v$MB125 {out}.rar {inputs}";
      ours32 = "a -m3 -md33554432 -v$MB125 {out}.rar {inputs}" } }
  rep    = @{ input = "rep.bin"; cmds = @{
      rar = "a -ma5 -m3 -ep -idq -y -o+ {out}.rar {inputs}"; ours = "a -m3 {out}.rar {inputs}";
      ours32 = "a -m3 -md33554432 {out}.rar {inputs}" } }
  small  = @{ input = "small\*"; cmds = @{
      rar = "a -ma5 -m3 -ep -idq -y -o+ {out}.rar {inputs}"; ours = "a -m3 {out}.rar {inputs}";
      ours32 = "a -m3 -md33554432 {out}.rar {inputs}" } }
  enc    = @{ input = "rand.bin"; cmds = @{
      rar = "a -ma5 -m0 -ep -idq -y -o+ -hpbenchpw {out}.rar {inputs}"; ours = "a -m0 -hpbenchpw {out}.rar {inputs}";
      sevenz = "a -t7z -mx0 -mhe=on -pbenchpw -bso0 -bsp0 -y {out}.7z {inputs}" } }
}
$bins = @{ rar = $Rar; ours = $Ours; sevenz = $SevenZ }
$tools = $Tools.Split(",")
$only = $Only.Split(",")
New-Item -ItemType Directory -Force -Path $Work | Out-Null
# warm inputs
foreach ($s in $only) { foreach ($f in (Get-ChildItem -Path (Join-Path $Payload $shapes[$s].input) -File)) {
  $fs = [System.IO.File]::OpenRead($f.FullName); $buf = New-Object byte[] (16MB)
  while ($fs.Read($buf, 0, $buf.Length) -gt 0) {}; $fs.Close() } }
$results = @{}
$packed = @{}
function Outputs($out) { Get-ChildItem -Path ($out + "*") -File -ErrorAction SilentlyContinue }
function Clear-Out($out) { Outputs $out | Remove-Item -Force -ErrorAction SilentlyContinue }
for ($r = 0; $r -lt $Rounds; $r++) {
  $k = $r % $tools.Count
  $rot = @($tools[$k..($tools.Count-1)]) + @(if ($k -gt 0) { $tools[0..($k-1)] })
  $orders = @(,$rot) + ,@($rot[($rot.Count-1)..0])
  foreach ($order in $orders) {
    foreach ($s in $only) {
      $inputs = ((Get-ChildItem -Path (Join-Path $Payload $shapes[$s].input) -File | Sort-Object FullName | ForEach-Object { '"' + $_.FullName + '"' }) -join " ")
      foreach ($tool in $order) {
        $tmpl = $shapes[$s].cmds[$tool]
        if (-not $tmpl) { continue }
        $key = if ($tool.StartsWith("ours")) { "ours" } else { $tool }
        $exe = $bins[$key]
        if (-not $exe) { continue }
        $out = Join-Path $Work "$s-$tool"
        Clear-Out $out
        $args = $tmpl.Replace("{out}", '"' + $out + '"').Replace("{inputs}", $inputs)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $p = Start-Process -FilePath $exe -ArgumentList $args -PassThru -Wait -NoNewWindow -RedirectStandardOutput "$Work\stdout.txt" -RedirectStandardError "$Work\stderr.txt"
        $sw.Stop()
        $wall = $sw.Elapsed.TotalSeconds
        $cpu = 0.0; $peak = 0
        try { $cpu = $p.TotalProcessorTime.TotalSeconds; $peak = [math]::Round($p.PeakWorkingSet64 / 1MB) } catch {}
        $files = @(Outputs $out)
        $bytes = ($files | Measure-Object -Property Length -Sum).Sum
        if (-not $bytes) { $bytes = 0 }
        $ver = "unverified"
        if ($p.ExitCode -ne 0) { $ver = "RC=" + $p.ExitCode }
        elseif ($files.Count -gt 0 -and $files[0].Name.EndsWith(".rar")) {
          $first = ($files | Sort-Object Name)[0].FullName
          $pw = if ($s -eq "enc") { "-pbenchpw" } else { "-p-" }
          $v = Start-Process -FilePath $UnRar -ArgumentList @("t", "-inul", $pw, ('"' + $first + '"')) -PassThru -Wait -NoNewWindow
          $ver = if ($v.ExitCode -eq 0) { "ok" } else { "UNRAR-T-FAIL(" + $v.ExitCode + ")" }
        } elseif ($files.Count -gt 0) {
          $pw = if ($s -eq "enc") { "-pbenchpw" } else { "-p-" }
          $v = Start-Process -FilePath $SevenZ -ArgumentList @("t", "-bso0", "-bsp0", $pw, ('"' + $files[0].FullName + '"')) -PassThru -Wait -NoNewWindow
          $ver = if ($v.ExitCode -eq 0) { "ok" } else { "7Z-T-FAIL(" + $v.ExitCode + ")" }
        }
        "CELL $Label round=$r shape=$s tool=$tool wall_s=$([math]::Round($wall,3)) cpu_s=$([math]::Round($cpu,2)) peak_mb=$peak bytes=$bytes files=$($files.Count) verify=$ver"
        $kk = "$s|$tool"
        if (-not $results.ContainsKey($kk)) { $results[$kk] = @() }
        $results[$kk] += ,@($wall, $cpu)
        $packed[$kk] = $bytes
        Clear-Out $out
      }
    }
  }
}
"== medians (wall s, cpu s, packed bytes)"
foreach ($s in $only) { foreach ($tool in $tools) { $kk = "$s|$tool"; if ($results.ContainsKey($kk)) {
  $w = ($results[$kk] | ForEach-Object { $_[0] } | Sort-Object)
  $c = ($results[$kk] | ForEach-Object { $_[1] } | Sort-Object)
  $mw = $w[[math]::Floor(($w.Count-1)/2)]; $mc = $c[[math]::Floor(($c.Count-1)/2)]
  "MED $Label $s $tool wall=$([math]::Round($mw,3)) cpu=$([math]::Round($mc,2)) bytes=$($packed[$kk])" } } }
