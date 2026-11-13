<#
Contact test for the safe-puppet change (Far Cry 2, Steam 1.03).

Starts two patched TEST copies, loads the same save in each, links them over loopback, waits for
the puppets, then captures screenshots of copy A while it stands in / walks into the other
player's puppet (W to walk forward, S to walk back). The point is to see the damage border and
the interaction prompt disappear, not to measure sync (two_copy_walk.ps1 does that).

It presses Enter and holds W/S, so do not use the keyboard or mouse while it runs.
Exit code 0 = ran and the real profile stayed unchanged, 1 = a check failed, 2 = setup problem.

Example:
  powershell -ExecutionPolicy Bypass -File tests\contact_test.ps1 `
    -CopyA <test copy A> -CopyB <test copy B> -OutDir <results folder>
#>
param(
    [Parameter(Mandatory = $true)][string]$CopyA,
    [Parameter(Mandatory = $true)][string]$CopyB,
    [string]$ProfileA = 'FC2test_A',
    [string]$ProfileB = 'FC2test_B',
    [string]$RealProfile = 'Far Cry 2',
    [string]$Documents = [Environment]::GetFolderPath('MyDocuments'),
    [string]$OutDir = (Join-Path (Get-Location) 'fc2-test-results'),
    [int]$LoadTimeout = 240
)

$ErrorActionPreference = 'Stop'
$run = Join-Path $OutDir (Get-Date -Format 'yyyyMMdd-HHmmss')
New-Item -ItemType Directory -Force $run | Out-Null
$results = New-Object System.Collections.ArrayList
$procs = @{}
$exit = 0

function Say($m) { $line = "[{0:HH:mm:ss}] {1}" -f (Get-Date), $m; Write-Output $line; Add-Content (Join-Path $run 'run.txt') $line }
function Check($name, [bool]$ok, $detail) {
    [void]$results.Add([pscustomobject]@{ check = $name; pass = $ok; detail = "$detail" })
    Say ("{0} {1}: {2}" -f ($(if ($ok) { 'PASS' } else { 'FAIL' })), $name, $detail)
}

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public struct FcRect { public int Left, Top, Right, Bottom; }
public static class FcWin {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint f, UIntPtr e);
  [DllImport("user32.dll")] public static extern uint MapVirtualKey(uint code, uint type);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint f);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool SetWindowText(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, ref FcRect r);
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
$titleSets = @{ A = 0; B = 0 }
function NameWindows {
    foreach ($k in $copies.Keys) {
        $p = $procs[$k]
        if (-not $p -or $p.HasExited) { continue }
        $p.Refresh()
        if ($p.MainWindowHandle -ne 0 -and $p.MainWindowTitle -ne $k) { [void][FcWin]::SetWindowText($p.MainWindowHandle, $k); $titleSets[$k]++ }
    }
}
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
function Hold($k, [byte]$vk, [int]$ms) {
    $p = $procs[$k]; $p.Refresh()
    [void][FcWin]::SetForegroundWindow($p.MainWindowHandle); Start-Sleep -Milliseconds 300
    $sc = [byte][FcWin]::MapVirtualKey($vk, 0)
    [FcWin]::keybd_event($vk, $sc, 0, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds $ms
    [FcWin]::keybd_event($vk, $sc, 2, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 400
}
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
    Start-Sleep -Milliseconds 300
}
function PosLine($k, $id, $label) {
    Native $k "pos $id"
    $line = (LogLines $copies[$k] | Select-String "pos ${id}: x=(\S+) y=(\S+) z=(\S+)" | Select-Object -Last 1)
    if ($line) { Say ("info: {0} {1}" -f $label, $line.Line) ; return $line }
    Say "info: $label no position line"
}
function Shot($k, $name) {
    $p = $procs[$k]; $p.Refresh()
    [void][FcWin]::SetForegroundWindow($p.MainWindowHandle); Start-Sleep -Milliseconds 600
    $r = New-Object FcRect
    if (-not [FcWin]::GetWindowRect($p.MainWindowHandle, [ref]$r)) { Say "shot $name failed: no window rect"; return }
    $w = $r.Right - $r.Left; $h = $r.Bottom - $r.Top
    if ($w -le 0 -or $h -le 0) { Say "shot $name failed: empty rect $w x $h"; return }
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($r.Left, $r.Top, 0, 0, $bmp.Size)
    $path = Join-Path $run "$name.png"
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Say "shot $name -> $path"
}
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

try {
    if (@(Get-Process FarCry2 -ErrorAction SilentlyContinue).Count) { throw 'setup: a FarCry2 process is already running' }
    foreach ($k in $copies.Keys) {
        $c = $copies[$k]
        foreach ($f in 'FarCry2.exe', 'Dunia.dll', 'dinput8.dll') { if (-not (Test-Path (Join-Path $c.bin $f))) { throw "setup: $k has no bin\$f" } }
        if (-not (Test-Path (Join-Path $c.profileDir 'GamerProfile.xml'))) { throw "setup: $($c.profileDir) has no GamerProfile.xml" }
        if (-not (Get-ChildItem (Join-Path $c.profileDir 'Saved Games') -Filter *.sav -ErrorAction SilentlyContinue)) { throw "setup: $($c.profileDir)\Saved Games has no .sav" }
        if (Test-Path $c.log) { Move-Item $c.log (Join-Path $c.bin ("coop_probe.{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))) }
        Remove-Item $c.cmd, $c.nat -ErrorAction SilentlyContinue
    }
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

    # ---- load the save ----
    foreach ($k in $copies.Keys) {
        $c = $copies[$k]; $n = 0
        while (-not (LogLines $c | Select-String '\.sav ') -and $n -lt 25) { Guard; Key $k 0x0D; $n++; Start-Sleep 4 }
        Check "save $k" ([bool](LogLines $c | Select-String '\.sav ')) "$n Enter presses"
    }

    $ids = @{}
    foreach ($k in $copies.Keys) {
        $ids[$k] = WaitFor "player id ($k)" $LoadTimeout {
            try { $v = Lua $k 'tostring(GetLocalPlayerId())' } catch { if ("$_" -like 'timeout*') { $v = $null } else { throw } }
            if ($v -match '^\d+$' -and $v -ne '0' -and $v -ne '18446744073709551615') { $v }
        }
    }
    Check 'same player id' ($ids.A -eq $ids.B) "A=$($ids.A) B=$($ids.B)"
    $pid0 = $ids.A

    # ---- link ----
    Native A "netstart 9101 127.0.0.1 9102 $pid0"
    Native B "netstart 9102 127.0.0.1 9101 $pid0"
    foreach ($k in $copies.Keys) {
        $up = WaitFor "socket up ($k)" 10 { LogLines $copies[$k] | Select-String 'net: socket up' | Select-Object -Last 1 }
        Say "info: $k $($up.Line)"
    }
    $av = @{}
    foreach ($k in $copies.Keys) {
        $av[$k] = WaitFor "avatar spawned ($k)" 60 {
            $m = LogLines $copies[$k] | Select-String 'avatar spawned: (\d+)' | Select-Object -Last 1
            if ($m) { $m.Matches[0].Groups[1].Value }
        }
        Say "info: $k sees puppet $($av[$k])"
    }
    foreach ($k in $copies.Keys) {
        WaitFor "avatar body bound ($k)" 60 { LogLines $copies[$k] | Select-String 'avatar body bound' | Select-Object -Last 1 } | Out-Null
    }
    foreach ($k in $copies.Keys) {
        $u = (LogLines $copies[$k] | Select-String 'avatar usable size 0: status (\S+)' | Select-Object -Last 1)
        $s = (LogLines $copies[$k] | Select-String 'avatar scripted collision group: status (\S+)' | Select-Object -Last 1)
        Check "safe puppet calls $($k)" ($u -and $u.Matches[0].Groups[1].Value -eq 'usable0' -and $s -and $s.Matches[0].Groups[1].Value -eq 'scripted') "usable=$($u.Matches[0].Groups[1].Value) scripted=$($s.Matches[0].Groups[1].Value)"
    }
    Start-Sleep 4

    # ---- contact: A stands at the puppet, then walks forward and back into it ----
    PosLine A $pid0 'A player before'
    PosLine A $av.A 'A puppet before'
    Shot A 'contact_1_standing'
    Hold A 0x57 2000   # W forward
    PosLine A $pid0 'A player after W'
    PosLine A $av.A 'A puppet after W'
    Shot A 'contact_2_forward'
    Hold A 0x53 2000   # S back
    PosLine A $pid0 'A player after S'
    PosLine A $av.A 'A puppet after S'
    Shot A 'contact_3_back'
    Start-Sleep 2
    Shot A 'contact_4_rest'

    foreach ($k in $copies.Keys) {
        $p = $procs[$k]; $p.Refresh()
        Check "window title $k" ($p.MainWindowTitle -eq $k) "title '$($p.MainWindowTitle)'"
    }
    foreach ($k in $copies.Keys) {
        $bad = @(LogLines $copies[$k] | Select-String 'CRASH:|ACCESS VIOLATION .* at (Dunia|FC2|dinput8)\.dll\+')
        Check "no crash lines $k" ($bad.Count -eq 0) "$($bad.Count) crash line(s)"
    }
}
catch { Say "STOPPED: $_"; $exit = 1 }
finally {
    KillAll
    $realAfter = Snapshot $realDir
    $d = DiffSnap $realBefore $realAfter
    Check 'real profile untouched' ($d.total -eq 0) "new $($d.new), changed $($d.changed), removed $($d.removed)"
    foreach ($k in $copies.Keys) {
        if ($testBefore[$k]) {
            $t = DiffSnap $testBefore[$k] (Snapshot $copies[$k].profileDir)
            Say "info: test profile $k new $($t.new), changed $($t.changed), removed $($t.removed)"
        }
    }
    $failed = @($results | Where-Object { -not $_.pass }).Count
    Say ("RESULT: {0} checks, {1} failed -> {2}  ({3})" -f $results.Count, $failed, $(if ($failed -eq 0 -and $exit -eq 0) { 'PASS' } else { 'FAIL' }), $run)
    if ($failed -gt 0 -or $exit -ne 0) { $exit = 1 }
}
exit $exit
