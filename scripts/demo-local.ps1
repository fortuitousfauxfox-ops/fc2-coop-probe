<#
Interactive local two-copy demo for fc2-coop-probe (Far Cry 2, Steam 1.03).

Starts two patched TEST copies on this PC, loads the same save in each, links them over
loopback (netstart), and leaves both windows open for you to play: click a window, move with
WASD and look with the mouse; the other window shows your avatar following you (idle pose,
no weapon, no walking animation). Nothing is installed and the real game/profile is only read.

  powershell -ExecutionPolicy Bypass -File scripts\demo-local.ps1 `
    -CopyA <test copy A> -CopyB <test copy B>

Do not touch keyboard or mouse until the script prints "DEMO READY" (it presses Enter to get
through the menus). Stop by closing both game windows, or press Ctrl+C here.
#>
param(
    [Parameter(Mandatory = $true)][string]$CopyA,
    [Parameter(Mandatory = $true)][string]$CopyB,
    [string]$ProfileA = 'FC2test_A',
    [string]$ProfileB = 'FC2test_B',
    [string]$RealProfile = 'Far Cry 2',
    [string]$Documents = [Environment]::GetFolderPath('MyDocuments'),
    [string]$CleanSave = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'fc2-coop\saves-clean\10172310974182.sav'),
    [int]$LoadTimeout = 240,
    [switch]$NoMoveWindows,
    [switch]$NoResetSaves,
    [switch]$ResetSavesOnly
)
$ErrorActionPreference = 'Stop'

$run = Join-Path (Join-Path $CopyA 'coop-runs') ("{0:yyyyMMdd-HHmmss}-demo" -f (Get-Date))
New-Item -ItemType Directory -Force $run | Out-Null
$procs = @{}

function Say($m) { $line = "[{0:HH:mm:ss}] {1}" -f (Get-Date), $m; Write-Output $line; Add-Content (Join-Path $run 'run.txt') $line }

Add-Type @"
using System; using System.Runtime.InteropServices;
public static class DemoWin {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint f, UIntPtr e);
  [DllImport("user32.dll")] public static extern uint MapVirtualKey(uint code, uint type);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint f);
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
$realBefore = $null

function LogLines($c) { if (Test-Path $c.log) { @(Get-Content $c.log -ErrorAction SilentlyContinue) } else { @() } }

# Kill switch: any log line naming the real profile folder stops both copies at once.
function Guard {
    foreach ($k in $copies.Keys) {
        $p = $procs[$k]
        if ($p -and -not $p.HasExited) {
            $p.Refresh()
            if ($p.MainWindowHandle -ne 0 -and $p.MainWindowTitle -ne $k) { [void][DemoWin]::SetWindowText($p.MainWindowHandle, $k) }
        }
        $hit = LogLines $copies[$k] | Select-String -SimpleMatch $realMark | Select-Object -First 1
        if ($hit) { throw "KILL SWITCH: the probe log names the real profile folder: $($hit.Line)" }
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
    [void][DemoWin]::SetForegroundWindow($p.MainWindowHandle); Start-Sleep -Milliseconds 200
    $sc = [byte][DemoWin]::MapVirtualKey($vk, 0)
    [DemoWin]::keybd_event($vk, $sc, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 80
    [DemoWin]::keybd_event($vk, $sc, 2, [UIntPtr]::Zero)
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
    "new $n, changed $c, removed $r"
}

# Both copies must start from the same world state. The game creates a new autosave slot while
# playing, so the two test profiles drift apart (and a spawned puppet can be baked into a save).
# Before every run: move all existing .sav files into this run's folder, then install the one
# pristine baseline in both profiles. Never touches a non-test profile.
function ResetSaves {
    if (-not (Test-Path $CleanSave)) { throw "clean save not found: $CleanSave" }
    $cleanName = Split-Path $CleanSave -Leaf
    $cleanHash = (Get-FileHash $CleanSave -Algorithm SHA256).Hash
    foreach ($k in $copies.Keys) {
        $c = $copies[$k]
        if ($c.profile -notmatch '^FC2test_') { throw "refusing to reset saves for non-test profile '$($c.profile)'" }
        if ($CleanSave.StartsWith($c.profileDir, [StringComparison]::OrdinalIgnoreCase)) { throw "clean save must not live inside the profile folder: $CleanSave" }
        $dir = Join-Path $c.profileDir 'Saved Games'
        if (-not (Test-Path $dir)) { throw "no Saved Games folder: $dir" }
        $backup = Join-Path $run "saves-backup-$k"
        New-Item -ItemType Directory -Force $backup | Out-Null
        $existing = @(Get-ChildItem $dir -Filter *.sav -File -ErrorAction SilentlyContinue)
        foreach ($f in $existing) { Move-Item $f.FullName (Join-Path $backup $f.Name) -Force }
        Copy-Item $CleanSave (Join-Path $dir $cleanName) -Force
        $h = (Get-FileHash (Join-Path $dir $cleanName) -Algorithm SHA256).Hash
        if ($h -ne $cleanHash) { throw "clean save copy failed in $dir" }
        Say "copy ${k}: moved $($existing.Count) save(s) aside; installed $cleanName (sha256 $cleanHash)"
    }
}

try {
    if (@(Get-Process FarCry2 -ErrorAction SilentlyContinue).Count) { throw 'a FarCry2 process is already running; close it first' }
    foreach ($k in $copies.Keys) {
        $c = $copies[$k]
        foreach ($f in 'FarCry2.exe', 'Dunia.dll', 'dinput8.dll') { if (-not (Test-Path (Join-Path $c.bin $f))) { throw "no bin\$f in $($c.dir)" } }
        if (-not (Test-Path (Join-Path $c.profileDir 'GamerProfile.xml'))) { throw "no GamerProfile.xml in $($c.profileDir)" }
        if (Test-Path $c.log) { Move-Item $c.log (Join-Path $c.bin ("coop_probe.{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))) }
        Remove-Item $c.cmd, $c.nat -ErrorAction SilentlyContinue
    }
    if (-not $NoResetSaves) { ResetSaves }
    foreach ($k in $copies.Keys) {
        $dir = Join-Path $copies[$k].profileDir 'Saved Games'
        if (-not (Get-ChildItem $dir -Filter *.sav -ErrorAction SilentlyContinue)) { throw "no .sav in $dir" }
    }
    if ($ResetSavesOnly) { Say 'saves reset; not launching (ResetSavesOnly)'; return }
    $realBefore = Snapshot $realDir
    Say "run folder: $run"
    Say 'starting both test copies; do not use the keyboard or mouse until the demo is ready'

    $x = 10
    foreach ($k in $copies.Keys) {
        $c = $copies[$k]
        $procs[$k] = Start-Process -FilePath (Join-Path $c.bin 'FarCry2.exe') -WorkingDirectory $c.bin -PassThru
        Say "started copy $k, pid $($procs[$k].Id)"
        WaitFor "profile read ($k)" 60 { LogLines $c | Select-String 'CreateFileW .*GamerProfile\.xml' } | Out-Null
        Start-Sleep 8
        if (-not $NoMoveWindows) {
            $procs[$k].Refresh()
            [void][DemoWin]::SetWindowPos($procs[$k].MainWindowHandle, [IntPtr]::Zero, $x, 10, 0, 0, 5)
        }
        $x += 1000
    }

    foreach ($k in $copies.Keys) {
        $c = $copies[$k]; $n = 0
        while (-not (LogLines $c | Select-String '\.sav ') -and $n -lt 25) { Guard; Key $k 0x0D; $n++; Start-Sleep 4 }
        $line = (LogLines $c | Select-String '\.sav ' | Select-Object -First 1).Line
        if (-not $line) { throw "copy $k did not open its save after 25 Enter presses" }
        Say "copy $k opened $($line -replace '^\S+ \S+ ', '')"
    }

    $ids = @{}
    foreach ($k in $copies.Keys) {
        $ids[$k] = WaitFor "player id ($k)" $LoadTimeout {
            try { $v = Lua $k 'tostring(GetLocalPlayerId())' } catch { if ("$_" -like 'timeout*') { $v = $null } else { throw } }
            if ($v -match '^\d+$' -and $v -ne '0' -and $v -ne '18446744073709551615') { $v }
        }
        Say "copy $k is in the world, player id $($ids[$k])"
    }
    if ($ids.A -ne $ids.B) { Say "WARNING: the copies report different player ids ($($ids.A) / $($ids.B)); is it the same save?" }

    Native A "netstart 9101 127.0.0.1 9102 $($ids.A)"
    Native B "netstart 9102 127.0.0.1 9101 $($ids.B)"
    foreach ($k in $copies.Keys) {
        $up = WaitFor "socket up ($k)" 10 { LogLines $copies[$k] | Select-String 'net: socket up' | Select-Object -Last 1 }
        Say "copy ${k}: $($up.Matches[0].Value)"
    }
    foreach ($k in $copies.Keys) {
        $a = WaitFor "avatar spawned ($k)" 60 { LogLines $copies[$k] | Select-String 'avatar spawned: (\d+)' | Select-Object -Last 1 }
        Say "copy $k sees the other player's avatar $($a.Matches[0].Groups[1].Value)"
    }
    Start-Sleep 4
    foreach ($k in $copies.Keys) {
        $net = @(LogLines $copies[$k] | Select-String '\] net: tx=(\d+) rx=(\d+)')
        if ($net.Count) { Say ("copy $k link: " + ($net[-1].Line -replace '^.*\] net: ', '')) }
    }

    Write-Output ''
    Write-Output '=== DEMO READY ==='
    Write-Output 'Two windows are open: A (left) and B (right), linked over loopback.'
    Write-Output 'Click a window to play it. Move with WASD, look with the mouse.'
    Write-Output 'The other window shows your avatar following you (idle pose, no weapon, no walk animation).'
    Write-Output 'Close both game windows, or press Ctrl+C here, to stop.'
    Write-Output ''
    Say 'DEMO READY'

    $last = Get-Date
    while ($true) {
        Start-Sleep -Seconds 2
        Guard
        $alive = @($copies.Keys | Where-Object { $procs[$_] -and -not $procs[$_].HasExited })
        if ($alive.Count -eq 0) { Say 'both game windows are closed'; break }
        if ($alive.Count -lt 2) { Say ("copy {0} closed; stopping the other one" -f (@($copies.Keys | Where-Object { $_ -notin $alive })[0])); break }
        if (((Get-Date) - $last).TotalSeconds -ge 10) {
            $last = Get-Date
            $net = LogLines $copies.A | Select-String '\] net: tx=(\d+) rx=(\d+)' | Select-Object -Last 1
            if ($net) { Say ("link: " + ($net.Line -replace '^.*\] net: ', '')) }
        }
    }
}
catch {
    if ("$_" -like 'KILL SWITCH*') { Say "STOPPED: $_" } else { Say "STOPPED: $_" }
}
finally {
    foreach ($p in $procs.Values) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
    Start-Sleep 2
    foreach ($k in $copies.Keys) {
        $c = $copies[$k]
        if (Test-Path $c.log) { Copy-Item $c.log (Join-Path $run "coop_probe_$k.log") -ErrorAction SilentlyContinue }
        $sv = @(Get-ChildItem (Join-Path $c.profileDir 'Saved Games') -Filter *.sav -File -ErrorAction SilentlyContinue)
        Say "copy ${k} saves at exit: $(($sv | ForEach-Object Name) -join ', ')"
    }
    $realAfter = Snapshot $realDir
    if ($null -ne $realBefore) { Say "real profile unchanged: $(DiffSnap $realBefore $realAfter)" }
    Say "stopped; logs and run.txt in $run"
}
