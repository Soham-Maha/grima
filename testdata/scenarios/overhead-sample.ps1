<#
  overhead-sample.ps1 — sample CPU and RSS of process sets for the overhead harness.

  Prints one line per sample and one SUMMARY per subject:

    SAMPLE label=<l> t=<s> dt=<s> procs=<n> cpu_s=<s> cpu_pct1=<p> rss_b=<b>
    SUMMARY label=<l> samples=<n> present=<n> procs_mean=<f> cpu_pct1_mean=<f> \
            cpu_pct1_peak=<f> cpu_seconds=<f> rss_mean_mib=<f> rss_peak_mib=<f> window_s=<f>

  CPU comes from Win32_Process UserModeTime+KernelModeTime deltas, so it is the
  processor time the set actually consumed; percent-of-one-core is
  delta_cpu / delta_wall * 100. RSS is the summed WorkingSetSize per sample.

  Subjects are ';'-separated entries with '|'-separated fields:

    label|kind|value|name|flags

  kind is 'pid' (value = decimal PID) or 'cmd' (value = substring of the process
  command line). name is a case-insensitive substring of the image name, '' for
  any. flags may contain 'tree' to add the process's descendants.

  A process that merely *mentions* value in its command line — this script does,
  because the value is in its own arguments — is not counted: the sampler's own
  PID is excluded and the name filter rejects the rest. For a tree subject whose
  root matches several processes (Git Bash runs a shim around the real bash, and
  both carry the same argument), the descendant sets are unioned, so nothing is
  counted twice.

  The run ends at -Seconds, or GraceSec after the first subject has been seen and
  then disappears (a workload's lifetime bounds the sample), or StartupGraceSec
  after start if the first subject was never seen at all.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Subjects,
  [Parameter(Mandatory = $true)][int]$Seconds,
  [double]$IntervalSec = 1.0,
  [string]$Out = '',
  [int]$GraceSec = 3,
  [int]$StartupGraceSec = 25
)

$ErrorActionPreference = 'Stop'
[System.Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::InvariantCulture

function F([double]$v) { $v.ToString('0.###', [Globalization.CultureInfo]::InvariantCulture) }

$self = $PID
$intervalMs = [int]([math]::Round($IntervalSec * 1000))
if ($intervalMs -lt 100) { $intervalMs = 100 }

$specs = New-Object System.Collections.ArrayList
foreach ($entry in ($Subjects -split ';')) {
  if ([string]::IsNullOrWhiteSpace($entry)) { continue }
  $f = @($entry -split '\|')
  while ($f.Count -lt 5) { $f += '' }
  $label = $f[0].Trim()
  if ($label -eq '') { $label = $f[1].Trim() + $f[2].Trim() }
  [void]$specs.Add([pscustomobject]@{
      Label = $label
      Kind  = $f[1].Trim().ToLowerInvariant()
      Value = $f[2]
      Name  = $f[3].Trim()
      Tree  = ($f[4] -match 'tree')
    })
}
if ($specs.Count -eq 0) { throw 'no subjects given' }
$primary = $specs[0]

$acc = @{}
foreach ($s in $specs) {
  $acc[$s.Label] = @{
    Samples = 0; Present = 0; SumDt = 0.0; SumCpu = 0.0; PeakPct = 0.0
    SumRss = 0.0; PeakRss = 0.0; SumProcs = 0; MaxProcs = 0; LastCpu = @{}
  }
}

$sw = [Diagnostics.Stopwatch]::StartNew()
$prev = 0.0
$seenPrimary = $false
$missingSince = $null
$lines = New-Object System.Collections.Generic.List[string]

while ($true) {
  $snap = Get-CimInstance -ClassName Win32_Process `
    -Property ProcessId, ParentProcessId, Name, CommandLine, UserModeTime, KernelModeTime, WorkingSetSize
  $byPid = @{}
  $kids = @{}
  foreach ($p in $snap) {
    $id = [int]$p.ProcessId
    $byPid[$id] = $p
    $ppid = [int]$p.ParentProcessId
    if (-not $kids.ContainsKey($ppid)) { $kids[$ppid] = New-Object System.Collections.Generic.List[int] }
    $kids[$ppid].Add($id)
  }

  $elapsed = $sw.Elapsed.TotalSeconds
  $dt = $elapsed - $prev
  if ($dt -le 0) { $dt = 0.001 }
  $prev = $elapsed

  $primaryCount = 0
  foreach ($s in $specs) {
    $roots = New-Object System.Collections.Generic.List[int]
    if ($s.Kind -eq 'cmd') {
      foreach ($p in $snap) {
        if ([int]$p.ProcessId -eq $self) { continue }
        if ($null -eq $p.CommandLine) { continue }
        if (-not $p.CommandLine.Contains($s.Value)) { continue }
        if ($s.Name -ne '' -and ($p.Name -notlike ('*' + $s.Name + '*'))) { continue }
        $roots.Add([int]$p.ProcessId)
      }
    }
    elseif ($s.Kind -eq 'pid') {
      $want = 0
      if ([int]::TryParse($s.Value, [ref]$want) -and $byPid.ContainsKey($want)) {
        $p = $byPid[$want]
        if ($s.Name -eq '' -or ($p.Name -like ('*' + $s.Name + '*'))) { $roots.Add($want) }
      }
    }
    else { throw "unknown subject kind: $($s.Kind)" }

    $set = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($r in $roots) {
      if (-not $set.Add($r)) { continue }
      if ($s.Tree) {
        $queue = New-Object System.Collections.Generic.Queue[int]
        $queue.Enqueue($r)
        while ($queue.Count -gt 0) {
          $cur = $queue.Dequeue()
          if ($kids.ContainsKey($cur)) {
            foreach ($c in $kids[$cur]) { if ($set.Add($c)) { $queue.Enqueue($c) } }
          }
        }
      }
    }

    $rss = 0.0
    $delta = 0.0
    $last = $acc[$s.Label].LastCpu
    foreach ($p_ in $set) {
      $proc = $byPid[$p_]
      $c = ([double]$proc.UserModeTime + [double]$proc.KernelModeTime) / 1e7
      $rss += [double]$proc.WorkingSetSize
      if ($last.ContainsKey($p_)) { $d = $c - $last[$p_]; if ($d -lt 0) { $d = 0.0 } } else { $d = 0.0 }
      $last[$p_] = $c
      $delta += $d
    }

    $n = $set.Count
    $a = $acc[$s.Label]
    $a.Samples++
    if ($n -gt 0) { $a.Present++ }
    $a.SumProcs += $n
    if ($n -gt $a.MaxProcs) { $a.MaxProcs = $n }
    $a.SumDt += $dt
    $a.SumCpu += $delta
    $a.SumRss += $rss
    if ($rss -gt $a.PeakRss) { $a.PeakRss = $rss }
    $pct = ($delta / $dt) * 100.0
    if ($pct -gt $a.PeakPct) { $a.PeakPct = $pct }

    if ($s.Label -eq $primary.Label) { $primaryCount = $n }
    $lines.Add(('SAMPLE label={0} t={1} dt={2} procs={3} cpu_s={4} cpu_pct1={5} rss_b={6}' -f @(
            $s.Label, (F $elapsed), (F $dt), $n, (F $delta), (F $pct), [long]$rss)))
  }

  if ($primaryCount -gt 0) {
    $seenPrimary = $true
    $missingSince = $null
  }
  elseif ($seenPrimary) {
    if ($null -eq $missingSince) { $missingSince = $elapsed }
    elseif (($elapsed - $missingSince) -ge $GraceSec) { break }
  }
  elseif ($elapsed -ge $StartupGraceSec) {
    $lines.Add("NOTE primary subject '$($primary.Label)' was never observed within ${StartupGraceSec}s")
    break
  }
  if ($elapsed -ge $Seconds) { break }

  Start-Sleep -Milliseconds $intervalMs
}

$window = $sw.Elapsed.TotalSeconds
foreach ($s in $specs) {
  $a = $acc[$s.Label]
  $mean = 0.0
  if ($a.SumDt -gt 0) { $mean = ($a.SumCpu / $a.SumDt) * 100.0 }
  $rssMean = 0.0
  $procsMean = 0.0
  if ($a.Samples -gt 0) {
    $rssMean = $a.SumRss / $a.Samples
    $procsMean = $a.SumProcs / [double]$a.Samples
  }
  $lines.Add(('SUMMARY label={0} samples={1} present={2} procs_mean={3} procs_max={4} ' +
      'cpu_pct1_mean={5} cpu_pct1_peak={6} cpu_seconds={7} rss_mean_mib={8} rss_peak_mib={9} window_s={10}') -f @(
      $s.Label, $a.Samples, $a.Present,
      (F $procsMean), $a.MaxProcs,
      (F $mean), (F $a.PeakPct), (F $a.SumCpu),
      (F ($rssMean / 1MB)), (F ($a.PeakRss / 1MB)), (F $window)))
}

if ($Out -ne '') { [IO.File]::WriteAllLines($Out, $lines) }
foreach ($l in $lines) { Write-Output $l }
