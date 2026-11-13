<#
Two-copy walk test for fc2-coop-probe (Far Cry 2, Steam 1.03).

Starts two patched TEST copies of the game (each with dinput8.dll from this repo in its bin
folder and its own profile folder), loads the save in each ("Story Mode" -> "Continue"),
connects them with `netstart`, walks the player of copy A on a circle with `walk`, and checks
from the probe logs and `pos` readings that copy B's avatar follows A while B's own player
stays put. Then it kills both copies (forced, so no exit-time profile writes) and checks that
the real profile folder did not change.

It presses Enter in the game windows, so do not use the keyboard while it runs.
Exit code 0 = all checks passed, 1 = a check failed, 2 = setup problem.

Example:
  powershell -ExecutionPolicy Bypass -File tests\two_copy_walk.ps1 `
    -CopyA <test copy A> -CopyB <test copy B> `
    -ProfileA FC2test_A -ProfileB FC2test_B -OutDir <results folder>
#>
param(
    [Parameter(Mandatory = $true)][string]$CopyA,
    [Parameter(Mandatory = $true)][string]$CopyB,
    [string]$ProfileA = 'FC2test_A',
    [string]$ProfileB = 'FC2test_B',
    [string]$RealProfile = 'Far Cry 2',
    [string]$Documents = [Environment]::GetFolderPath('MyDocuments'),
    [string]$OutDir = (Join-Path (Get-Location) 'fc2-test-results'),
    # address each copy sends to; anything but 127.x makes the probe bind on the network and
    # adds a check that packets from another address are dropped
    [string]$PeerIp = '127.0.0.1',
    # route the probes through relay/fc2_relay.py (udp stand-in transport) instead of straight to each other
    [switch]$Relay,
    [string]$Python = 'python',
    [double]$WalkRadius = 3,
    [double]$WalkSeconds = 20,
    [double]$WalkSpeed = 2,
    [int]$LoadTimeout = 240
)

$ErrorActionPreference = 'Stop'
$run = Join-Path $OutDir (Get-Date -Format 'yyyyMMdd-HHmmss')
New-Item -ItemType Directory -Force $run | Out-Null
$results = New-Object System.Collections.ArrayList
$procs = @{}

function Say($m) { $line = "[{0:HH:mm:ss}] {1}" -f (Get-Date), $m; Write-Output $line; Add-Content (Join-Path $run 'run.txt') $line }
function Check($name, [bool]$ok, $detail) {
    [void]$results.Add([pscustomobject]@{ check = $name; pass = $ok; detail = "$detail" })
    Say ("{0} {1}: {2}" -f ($(if ($ok) { 'PASS' } else { 'FAIL' })), $name, $detail)
}

Add-Type @"
using System; using System.Runtime.InteropServices;
public static class FcWin {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint f, UIntPtr e);
  [DllImport("user32.dll")] public static extern uint MapVirtualKey(uint code, uint type);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint f);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, int dx, int dy, uint d, UIntPtr e);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool SetWindowText(IntPtr h, string s);
}
"@

$copies = [ordered]@{
    A = @{ dir = $CopyA; profile = $ProfileA }
    B = @{ dir = $CopyB; profile = $ProfileB }
}
foreach ($k in $copies.Keys) {
    $c = $copies[$k]
    $c.bin = Join-Path $c.dir 'bin'
    $c.log = Join-Path $c.bin 'coop_probe.log'
    $c.cmd = Join-Path $c.bin 'coop_cmd.lua'
    $c.nat = Join-Path $c.bin 'coop_native.txt'
    $c.profileDir = Join-Path $Documents "My Games\$($c.profile)"
}
$realDir = Join-Path $Documents "My Games\$RealProfile"
$realMark = "My Games\$RealProfile\"

function LogLines($c) { if (Test-Path $c.log) { @(Get-Content $c.log -ErrorAction SilentlyContinue) } else { @() } }

function KillAll {
    foreach ($p in $procs.Values) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -Confirm:$false -ErrorAction SilentlyContinue } }
    Start-Sleep 2
}

# Window titles "A" / "B", to tell the copies apart. The game resets its title while loading, so this
# runs from every wait loop and puts the title back whenever it differs.
$titleSets = @{ A = 0; B = 0 }
function NameWindows {
    foreach ($k in $copies.Keys) {
        $p = $procs[$k]
        if (-not $p -or $p.HasExited) { continue }
        $p.Refresh()
        if ($p.MainWindowHandle -ne 0 -and $p.MainWindowTitle -ne $k) { [void][FcWin]::SetWindowText($p.MainWindowHandle, $k); $titleSets[$k]++ }
    }
}

# Kill switch: called from every wait loop. Any log line naming the real profile folder stops both copies.
function Guard {
    NameWindows
    foreach ($k in $copies.Keys) {
        $hit = LogLines $copies[$k] | Select-String -SimpleMatch $realMark | Select-Object -First 1
        if ($hit) { KillAll; Check "kill switch ($k)" $false "real profile path in log: $($hit.Line)"; throw 'killed' }
        $p = $procs[$k]
        if ($p -and $p.HasExited) { throw "copy $k exited by itself (code $($p.ExitCode))" }
    }
}

function WaitFor($what, [int]$seconds, [scriptblock]$cond) {
    $t0 = Get-Date
    while (((Get-Date) - $t0).TotalSeconds -lt $seconds) {
        Guard
        $r = & $cond
        if ($r) { return $r }
        Start-Sleep -Milliseconds 500
    }
    throw "timeout after $seconds s waiting for $what"
}

function Key($k, [byte]$vk) {
    $p = $procs[$k]; $p.Refresh()
    [void][FcWin]::SetForegroundWindow($p.MainWindowHandle); Start-Sleep -Milliseconds 200
    $sc = [byte][FcWin]::MapVirtualKey($vk, 0)
    [FcWin]::keybd_event($vk, $sc, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 80
    [FcWin]::keybd_event($vk, $sc, 2, [UIntPtr]::Zero)
}

# Relative mouse movement in steps (turns the player: the game reads it as look input).
function MouseX($k, [int]$dx) {
    $p = $procs[$k]; $p.Refresh()
    [void][FcWin]::SetForegroundWindow($p.MainWindowHandle); Start-Sleep -Milliseconds 200
    1..20 | ForEach-Object { [FcWin]::mouse_event(1, [int]($dx / 20), 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 30 }
}

# Runs Lua in a copy and returns __out (a nonce tags the answer so old lines are never read).
function Lua($k, $code) {
    $c = $copies[$k]; $nonce = [guid]::NewGuid().ToString('N').Substring(0, 8)
    WaitFor "lua channel free ($k)" 10 { -not (Test-Path $c.cmd) } | Out-Null
    Set-Content $c.cmd "__out = '$nonce ' .. ($code)" -Encoding ascii
    $line = WaitFor "lua answer ($k)" 15 { LogLines $c | Select-String "out\(\d+\)=$nonce " | Select-Object -Last 1 }
    ($line.Line -replace ".*out\(\d+\)=$nonce ", '')
}

function Native($k, $text) {
    $c = $copies[$k]
    WaitFor "native channel free ($k)" 10 { -not (Test-Path $c.nat) } | Out-Null
    Set-Content $c.nat $text -Encoding ascii
    WaitFor "native consumed ($k)" 10 { -not (Test-Path $c.nat) } | Out-Null
}

function Tick($line) { if ($line -match '^\[\s*(\d+) ') { [long]$Matches[1] } else { 0 } }
function Vec($s) { $v = $s -split '\s+' | Where-Object { $_ } | ForEach-Object { [double]$_ }; ,$v }
function Dist2D($a, $b) { [math]::Sqrt([math]::Pow($a[0] - $b[0], 2) + [math]::Pow($a[1] - $b[1], 2)) }

function Snapshot($dir) {
    $h = @{}
    if (Test-Path $dir) { Get-ChildItem $dir -Recurse -File -Force | ForEach-Object { $h[$_.FullName] = "{0}|{1:o}" -f $_.Length, $_.LastWriteTimeUtc } }
    $h
}
function DiffSnap($before, $after) {
    $n = @($after.Keys | Where-Object { -not $before.ContainsKey($_) }).Count
    $c = @($after.Keys | Where-Object { $before.ContainsKey($_) -and $before[$_] -ne $after[$_] }).Count
    $r = @($before.Keys | Where-Object { -not $after.ContainsKey($_) }).Count
    @{ new = $n; changed = $c; removed = $r; total = $n + $c + $r }
}

$exit = 0
try {
    # ---- setup checks ----
    if (@(Get-Process FarCry2 -ErrorAction SilentlyContinue).Count) { throw 'setup: a FarCry2 process is already running' }
    $hashes = @()
    foreach ($k in $copies.Keys) {
        $c = $copies[$k]
        foreach ($f in 'FarCry2.exe', 'Dunia.dll', 'dinput8.dll') { if (-not (Test-Path (Join-Path $c.bin $f))) { throw "setup: $k has no bin\$f" } }
        if (-not (Test-Path (Join-Path $c.profileDir 'GamerProfile.xml'))) { throw "setup: $($c.profileDir) has no GamerProfile.xml" }
        if (-not (Get-ChildItem (Join-Path $c.profileDir 'Saved Games') -Filter *.sav -ErrorAction SilentlyContinue)) { throw "setup: $($c.profileDir)\Saved Games has no .sav" }
        $hashes += (Get-FileHash (Join-Path $c.bin 'dinput8.dll')).Hash
        if (Test-Path $c.log) { Move-Item $c.log (Join-Path $c.bin ("coop_probe.{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))) }
        Remove-Item $c.cmd, $c.nat -ErrorAction SilentlyContinue
    }
    if ($hashes[0] -ne $hashes[1]) { throw 'setup: the two copies have different dinput8.dll files' }
    Say "probe dinput8.dll SHA-256 $($hashes[0].ToLower())"
    $realBefore = Snapshot $realDir
    $testBefore = @{}; foreach ($k in $copies.Keys) { $testBefore[$k] = Snapshot $copies[$k].profileDir }

    # ---- start both copies ----
    $x = 0
    foreach ($k in $copies.Keys) {
        $c = $copies[$k]
        $procs[$k] = Start-Process -FilePath (Join-Path $c.bin 'FarCry2.exe') -WorkingDirectory $c.bin -PassThru
        Say "started copy $k, pid $($procs[$k].Id)"
        WaitFor "profile read ($k)" 60 { LogLines $c | Select-String 'CreateFileW .*GamerProfile\.xml' } | Out-Null
        Start-Sleep 8
        $procs[$k].Refresh(); [void][FcWin]::SetWindowPos($procs[$k].MainWindowHandle, [IntPtr]::Zero, $x, 0, 0, 0, 5); $x += 1000
        NameWindows
    }
    foreach ($k in $copies.Keys) {
        $c = $copies[$k]
        $line = (LogLines $c | Select-String 'CreateFileW .*GamerProfile\.xml' | Select-Object -First 1).Line
        Check "profile $k" ($line -like "*My Games\$($c.profile)\GamerProfile.xml*") $line
    }

    # ---- load the save: Enter until the probe logs the .sav being opened ----
    foreach ($k in $copies.Keys) {
        $c = $copies[$k]; $n = 0
        while (-not (LogLines $c | Select-String '\.sav ') -and $n -lt 25) { Guard; Key $k 0x0D; $n++; Start-Sleep 4 }
        $line = (LogLines $c | Select-String '\.sav ' | Select-Object -First 1).Line
        Check "save $k" ($line -like "*My Games\$($c.profile)\*") "$n Enter presses; $line"
    }

    # ---- in the world: the player id answers in both, and is the same ----
    $ids = @{}
    foreach ($k in $copies.Keys) {
        $ids[$k] = WaitFor "player id ($k)" $LoadTimeout {
            # while the world loads the Lua call may fail or not be served; that only means "not yet"
            try { $v = Lua $k 'tostring(GetLocalPlayerId())' } catch { if ("$_" -like 'timeout*') { $v = $null } else { throw } }
            if ($v -match '^\d+$' -and $v -ne '0' -and $v -ne '18446744073709551615') { $v }
        }
    }
    Check 'same player id' ($ids.A -eq $ids.B) "A=$($ids.A) B=$($ids.B)"
    $pid0 = $ids.A

    # ---- link ----
    if ($Relay) {
        # probe A <-> relay A (9201) <-udp 9301/9302-> relay B (9202) <-> probe B
        $relayPy = Join-Path $PSScriptRoot '..\relay\fc2_relay.py'
        foreach ($r in @(@{k = 'A'; game = 9101; relay = 9201; loc = 9301; peer = 9302 }, @{k = 'B'; game = 9102; relay = 9202; loc = 9302; peer = 9301 })) {
            $procs["relay$($r.k)"] = Start-Process $Python -ArgumentList @('-I', '-u', "`"$relayPy`"", '--transport', 'udp', '--game-port', $r.game, '--relay-port', $r.relay, '--udp-local', $r.loc, '--udp-peer', $r.peer) `
                -RedirectStandardOutput (Join-Path $run "relay_$($r.k).log") -RedirectStandardError (Join-Path $run "relay_$($r.k).err") -WindowStyle Hidden -PassThru
        }
        Start-Sleep 2
        foreach ($k in 'A', 'B') { if ($procs["relay$k"].HasExited) { throw "relay $k exited: $(Get-Content (Join-Path $run "relay_$k.err") -Raw)" } }
        Native A "netstart 9101 127.0.0.1 9201 $pid0"
        Native B "netstart 9102 127.0.0.1 9202 $pid0"
    }
    else {
        Native A "netstart 9101 $PeerIp 9102 $pid0"
        Native B "netstart 9102 $PeerIp 9101 $pid0"
    }
    foreach ($k in $copies.Keys) {
        $up = WaitFor "socket up ($k)" 10 { LogLines $copies[$k] | Select-String 'net: socket up, local (\S+) -> peer (\S+)' | Select-Object -Last 1 }
        Say "info: $k $($up.Matches[0].Value)"
    }
    $bound = @{}
    foreach ($k in $copies.Keys) {
        $bound[$k] = WaitFor "avatar body bound ($k)" 60 { LogLines $copies[$k] | Select-String 'avatar body bound' | Select-Object -Last 1 }
    }
    foreach ($k in $copies.Keys) {
        $l = $bound[$k].Line
        if ($l -match 'bound: (\S+) \(local body (\S+)\)') { Check "avatar body $k" ($Matches[1] -ne $Matches[2]) "avatar $($Matches[1]), local $($Matches[2])" }
        else { Check "avatar body $k" $false "old log format, cannot compare: $l" }
    }
    Start-Sleep 6
    foreach ($k in $copies.Keys) {
        $net = @(LogLines $copies[$k] | Select-String '\] net: tx=(\d+) rx=(\d+)')
        if ($net.Count -lt 2) { Check "link $k" $false "$($net.Count) net: lines"; continue }
        $a = $net[[math]::Max(0, $net.Count - 6)]; $b = $net[-1]
        $rx = [int]$b.Matches[0].Groups[2].Value - [int]$a.Matches[0].Groups[2].Value
        $sec = ((Tick $b.Line) - (Tick $a.Line)) / 1000.0
        $rate = if ($sec -gt 0) { $rx / $sec } else { 0 }
        Check "link $k" ($rate -ge 10) ("{0:N1} packets/s received" -f $rate)
    }
    $avB = ((LogLines $copies.B | Select-String 'avatar spawned: (\d+)' | Select-Object -Last 1).Matches[0].Groups[1].Value)

    # ---- network mode: forged packets from another address (loopback) must be dropped by B ----
    if ($PeerIp -notlike '127.*') {
        $dropRe = '\] net: .* drop=(\d+)'
        $d0 = [int]((LogLines $copies.B | Select-String $dropRe | Select-Object -Last 1).Matches[0].Groups[1].Value)
        $pkt = New-Object byte[] 28
        [BitConverter]::GetBytes([uint32]0x43324346).CopyTo($pkt, 0)          # NET_MAGIC
        [BitConverter]::GetBytes([uint32]999999).CopyTo($pkt, 4)              # seq
        foreach ($i in 0..2) { [BitConverter]::GetBytes([single]1.0).CopyTo($pkt, 8 + 4 * $i) }   # position (1,1,1)
        $u = New-Object System.Net.Sockets.UdpClient
        1..30 | ForEach-Object { [void]$u.Send($pkt, $pkt.Length, '127.0.0.1', 9102); Start-Sleep -Milliseconds 20 }
        $u.Close()
        Start-Sleep 3
        $d1 = [int]((LogLines $copies.B | Select-String $dropRe | Select-Object -Last 1).Matches[0].Groups[1].Value)
        $forged = @(LogLines $copies.B | Select-String 'remote=\(1\.00 1\.00 1\.00\)').Count
        Check 'forged packets dropped' (($d1 - $d0) -ge 25 -and $forged -eq 0) ("drop counter +{0} for 30 forged packets from 127.0.0.1; remote showed the forged position {1} time(s)" -f ($d1 - $d0), $forged)
    }

    # ---- walk A, sample B ----
    $startTick = Tick ((LogLines $copies.B)[-1])
    Native A ("walk {0} {1} {2}" -f $WalkRadius, $WalkSeconds, $WalkSpeed)
    $t0 = Get-Date
    while (((Get-Date) - $t0).TotalSeconds -lt ($WalkSeconds + 3)) { Guard; Native B "pos $avB`r`npos $pid0"; Start-Sleep -Milliseconds 800 }
    $endTick = Tick ((LogLines $copies.B)[-1])

    $bl = LogLines $copies.B
    $samples = @(); $remote = @(); $own = @()
    foreach ($l in $bl) {
        $t = Tick $l
        if ($t -lt $startTick -or $t -gt $endTick) { continue }
        if ($l -match "pos ${avB}: x=(\S+) y=(\S+) z=(\S+)") { $samples += ,@($t, [double]$Matches[1], [double]$Matches[2]) }
        elseif ($l -match "pos ${pid0}: x=(\S+) y=(\S+) z=(\S+)") { $own += ,@($t, [double]$Matches[1], [double]$Matches[2]) }
        elseif ($l -match 'net: .* remote=\((\S+) (\S+) (\S+)\)') { $remote += ,@($t, [double]$Matches[1], [double]$Matches[2]) }
    }
    # avatar vs A's position (B's `remote`) at the nearest log second.
    # Skip a sample that sits on a jump in A's received position (the scripted `walk` releases the
    # body at the end and it keeps the velocity the teleport writes gave it, so A flies off for a
    # moment). In normal play the peer's position is continuous; pairing a pre-jump avatar sample
    # with a post-jump remote sample would measure the script, not the sync.
    $remSorted = @($remote | Sort-Object { [long]$_[0] })
    $jumps = @()
    for ($i = 1; $i -lt $remSorted.Count; $i++) {
        if ((Dist2D @($remSorted[$i - 1][1], $remSorted[$i - 1][2]) @($remSorted[$i][1], $remSorted[$i][2])) -gt 3.0) {
            $jumps += [long]$remSorted[$i][0]
        }
    }
    $errs = @(); $skipped = 0
    foreach ($s in $samples) {
        $near = $remote | Sort-Object { [math]::Abs($_[0] - $s[0]) } | Select-Object -First 1
        if (-not $near -or [math]::Abs($near[0] - $s[0]) -gt 1000) { continue }
        if (@($jumps | Where-Object { [math]::Abs($_ - [long]$s[0]) -le 1500 }).Count) { $skipped++; continue }
        $errs += Dist2D @($s[1], $s[2]) @($near[1], $near[2])
    }
    $xs = $samples | ForEach-Object { $_[1] }; $ys = $samples | ForEach-Object { $_[2] }
    $span = if ($samples.Count) { [math]::Max(($xs | Measure-Object -Max -Min | ForEach-Object { $_.Maximum - $_.Minimum }), ($ys | Measure-Object -Max -Min | ForEach-Object { $_.Maximum - $_.Minimum })) } else { 0 }
    $maxErr = if ($errs.Count) { ($errs | Measure-Object -Max).Maximum } else { 999 }
    $meanErr = if ($errs.Count) { ($errs | Measure-Object -Average).Average } else { 999 }
    $drift = if ($own.Count -ge 2) { ($own | ForEach-Object { Dist2D @($_[1], $_[2]) @($own[0][1], $own[0][2]) } | Measure-Object -Max).Maximum } else { 999 }
    Check 'walk samples' ($samples.Count -ge [int]($WalkSeconds / 2) -and $errs.Count -ge [int]($WalkSeconds / 2)) "$($samples.Count) avatar samples, $($errs.Count) paired with a remote position, $skipped skipped at a position jump"
    Check 'avatar moved' ($span -ge 1.5 * $WalkRadius) ("avatar span {0:N2} m (needs >= {1:N2})" -f $span, (1.5 * $WalkRadius))
    Check 'avatar follows A' ($maxErr -le 2.5 -and $meanErr -le 1.5) ("distance to A: mean {0:N2} m, max {1:N2} m (limits 1.5 / 2.5)" -f $meanErr, $maxErr)
    Check 'B player stays put' ($drift -le 0.5) ("max drift {0:N2} m over {1} samples (limit 0.5)" -f $drift, $own.Count)

    # ---- heading: turn A's player with the mouse, compare A's direction with B's avatar ----
    $diffs = @(); $angles = @()
    foreach ($dx in 600, -1200, 900) {
        Guard; MouseX A $dx; Start-Sleep 3
        Native A "pos $pid0"; Native B "pos $avB"
        $la = (LogLines $copies.A | Select-String "pos ${pid0}: .* dir=\((\S+),(\S+)\)" | Select-Object -Last 1).Matches[0]
        $lb = (LogLines $copies.B | Select-String "pos ${avB}: .* dir=\((\S+),(\S+)\)" | Select-Object -Last 1).Matches[0]
        $aa = [math]::Atan2([double]$la.Groups[2].Value, [double]$la.Groups[1].Value) * 180 / [math]::PI
        $ab = [math]::Atan2([double]$lb.Groups[2].Value, [double]$lb.Groups[1].Value) * 180 / [math]::PI
        $d = [math]::Abs((($aa - $ab) % 360 + 540) % 360 - 180)
        $diffs += $d; $angles += $aa
        Say ("info: heading A {0:N1} deg, B avatar {1:N1} deg, difference {2:N1} deg" -f $aa, $ab, $d)
    }
    $turned = ($angles | Measure-Object -Max -Min | ForEach-Object { $_.Maximum - $_.Minimum })
    Check 'A turned' ($turned -ge 30) ("A's heading range {0:N1} deg over 3 turns (needs >= 30)" -f $turned)
    Check 'avatar heading follows A' (($diffs | Measure-Object -Max).Maximum -le 15) ("max difference {0:N1} deg (limit 15)" -f ($diffs | Measure-Object -Max).Maximum)

    if ($Relay) {
        foreach ($k in 'A', 'B') {
            $st = Get-Content (Join-Path $run "relay_$k.log") -ErrorAction SilentlyContinue | Select-String 'stats from_game=(\d+) to_peer=(\d+) from_peer=(\d+) to_game=(\d+)' | Select-Object -Last 1
            $ok = $st -and [int]$st.Matches[0].Groups[2].Value -gt 100 -and [int]$st.Matches[0].Groups[4].Value -gt 100
            Check "relay $k carried traffic" $ok $(if ($st) { $st.Line } else { 'no stats line' })
        }
    }
    foreach ($k in $copies.Keys) {
        $p = $procs[$k]; $p.Refresh()
        Check "window title $k" ($p.MainWindowTitle -eq $k) ("title '{0}', set {1} time(s) during the run" -f $p.MainWindowTitle, $titleSets[$k])
    }
    foreach ($k in $copies.Keys) {
        $ll = LogLines $copies[$k]
        # Only an unhandled exception (the probe's `CRASH:` line) or a first-chance AV inside the
        # game/probe is a failure. First-chance AVs inside Windows libraries (SPFILEQ.dll,
        # SETUPAPI.dll, ...) are normal: those libraries handle them.
        $bad = @($ll | Select-String 'CRASH:|ACCESS VIOLATION .* at (Dunia|FC2|dinput8)\.dll\+')
        $sysAv = @($ll | Select-String 'ACCESS VIOLATION .* at (?!Dunia|FC2|dinput8)').Count
        Say "info: $k system-library first-chance AVs: $sysAv (handled, not a crash)"
        Check "no crash lines $k" ($bad.Count -eq 0) "$($bad.Count) crash line(s), $sysAv handled system AV line(s)"
    }
    @($samples | ForEach-Object { "avatar,{0},{1},{2}" -f $_[0], $_[1], $_[2] }) + @($remote | ForEach-Object { "remote,{0},{1},{2}" -f $_[0], $_[1], $_[2] }) + @($own | ForEach-Object { "own,{0},{1},{2}" -f $_[0], $_[1], $_[2] }) | Set-Content (Join-Path $run 'positions_b.csv')
}
catch {
    if ("$_" -like 'setup:*') { Say "SETUP: $_"; $exit = 2 } elseif ("$_" -ne 'killed') { Check 'run' $false "$_" }
}
finally {
    KillAll
    if ($realBefore) {
        $d = DiffSnap $realBefore (Snapshot $realDir)
        Check 'real profile untouched' ($d.total -eq 0) ("new {0}, changed {1}, removed {2}" -f $d.new, $d.changed, $d.removed)
        foreach ($k in $copies.Keys) { $d = DiffSnap $testBefore[$k] (Snapshot $copies[$k].profileDir); Say ("info: test profile {0}: new {1}, changed {2}, removed {3}" -f $k, $d.new, $d.changed, $d.removed) }
    }
    foreach ($k in $copies.Keys) { if (Test-Path $copies[$k].log) { Copy-Item $copies[$k].log (Join-Path $run "coop_probe_$k.log") } }
    $results | ConvertTo-Json | Set-Content (Join-Path $run 'results.json')
    $failed = @($results | Where-Object { -not $_.pass }).Count
    if ($exit -eq 0 -and ($failed -gt 0 -or $results.Count -eq 0)) { $exit = 1 }
    Say ("RESULT: {0} checks, {1} failed -> {2}  ({3})" -f $results.Count, $failed, $(if ($exit -eq 0) { 'PASS' } elseif ($exit -eq 2) { 'SETUP ERROR' } else { 'FAIL' }), $run)
}
exit $exit
