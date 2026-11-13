<#
Starts one patched TEST copy of Far Cry 2, loads its save, runs Lua snippets through the
probe's `coop_cmd.lua` channel, and (unless -KeepOpen) stops it. For API discovery and small
experiments; the two-copy launcher is scripts/demo-local.ps1.

  powershell -ExecutionPolicy Bypass -File scripts\probe-shell.ps1 `
    -Copy <test copy> -Lua "`__out = tostring(GetLocalPlayerId())"

Do not touch the keyboard or mouse while it presses Enter through the menus.
#>
param(
    [Parameter(Mandatory = $true)][string]$Copy,
    [string]$Profile = 'FC2test_A',
    [string]$RealProfile = 'Far Cry 2',
    [string]$Documents = [Environment]::GetFolderPath('MyDocuments'),
    [string[]]$Lua = @(),
    [string]$LuaFile,
    [string]$LuaDir,
    [string[]]$Native = @(),
    [switch]$SpawnPuppet,
    [int]$LoadTimeout = 240,
    [switch]$KeepOpen
)
$ErrorActionPreference = 'Stop'

$run = Join-Path (Join-Path $Copy 'coop-runs') ("{0:yyyyMMdd-HHmmss}-shell" -f (Get-Date))
New-Item -ItemType Directory -Force $run | Out-Null
$bin = Join-Path $Copy 'bin'
$log = Join-Path $bin 'coop_probe.log'
$cmd = Join-Path $bin 'coop_cmd.lua'
$nat = Join-Path $bin 'coop_native.txt'
$profileDir = Join-Path $Documents "My Games\$Profile"
$realDir = Join-Path $Documents "My Games\$RealProfile"
$realMark = "My Games\$RealProfile\"
$proc = $null
$realBefore = $null
$nativeExtra = @()

function Say($m) { $line = "[{0:HH:mm:ss}] {1}" -f (Get-Date), $m; Write-Output $line; Add-Content (Join-Path $run 'run.txt') $line }
function LogLines { if (Test-Path $log) { @(Get-Content $log -ErrorAction SilentlyContinue) } else { @() } }

Add-Type @"
using System; using System.Runtime.InteropServices;
public static class ShellWin {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint f, UIntPtr e);
  [DllImport("user32.dll")] public static extern uint MapVirtualKey(uint code, uint type);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool SetWindowText(IntPtr h, string s);
}
"@

function Guard {
    if ($proc -and -not $proc.HasExited) {
        $proc.Refresh()
        if ($proc.MainWindowHandle -ne 0 -and $proc.MainWindowTitle -ne 'S') { [void][ShellWin]::SetWindowText($proc.MainWindowHandle, 'S') }
    }
    $hit = LogLines | Select-String -SimpleMatch $realMark | Select-Object -First 1
    if ($hit) { throw "KILL SWITCH: the probe log names the real profile folder: $($hit.Line)" }
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
function Key([byte]$vk) {
    $proc.Refresh()
    [void][ShellWin]::SetForegroundWindow($proc.MainWindowHandle); Start-Sleep -Milliseconds 200
    $sc = [byte][ShellWin]::MapVirtualKey($vk, 0)
    [ShellWin]::keybd_event($vk, $sc, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 80
    [ShellWin]::keybd_event($vk, $sc, 2, [UIntPtr]::Zero)
}
function RunLua($code) {
    $nonce = [guid]::NewGuid().ToString('N').Substring(0, 8)
    WaitFor 'lua channel free' 10 { -not (Test-Path $cmd) } | Out-Null
    Set-Content $cmd "__out = '$nonce ' .. (function() $code end)()" -Encoding ascii
    $line = WaitFor 'lua answer' 20 { LogLines | Select-String "out\(\d+\)=$nonce " | Select-Object -Last 1 }
    ($line.Line -replace ".*out\(\d+\)=$nonce ", '')
}
function PosOf($id) {
    for ($i = 0; $i -lt 10; $i++) {
        WaitFor 'native channel free' 10 { -not (Test-Path $nat) } | Out-Null
        $seen = @(LogLines | Select-String "pos ${id}:").Count
        Set-Content $nat "pos $id" -Encoding ascii
        $line = WaitFor "pos $id" 15 { LogLines | Select-String "pos ${id}:" | Select-Object -Skip $seen -First 1 }
        if ($line.Line -match 'x=([-0-9.]+) y=([-0-9.]+) z=([-0-9.]+)') { return @([double]$Matches[1], [double]$Matches[2], [double]$Matches[3]) }
        Start-Sleep 1
    }
    throw "cannot read position: $($line.Line)"
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

try {
    if (@(Get-Process FarCry2 -ErrorAction SilentlyContinue).Count) { throw 'a FarCry2 process is already running; close it first' }
    foreach ($f in 'FarCry2.exe', 'Dunia.dll', 'dinput8.dll') { if (-not (Test-Path (Join-Path $bin $f))) { throw "no bin\$f in $Copy" } }
    if (-not (Test-Path (Join-Path $profileDir 'GamerProfile.xml'))) { throw "no GamerProfile.xml in $profileDir" }
    if (-not (Get-ChildItem (Join-Path $profileDir 'Saved Games') -Filter *.sav -ErrorAction SilentlyContinue)) { throw "no .sav in $profileDir\Saved Games" }
    if (Test-Path $log) { Move-Item $log (Join-Path $bin ("coop_probe.{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))) }
    Remove-Item $cmd, $nat -ErrorAction SilentlyContinue
    $realBefore = Snapshot $realDir
    Say "run folder: $run"
    Say 'starting the test copy; do not use the keyboard or mouse until it is in the world'

    $proc = Start-Process -FilePath (Join-Path $bin 'FarCry2.exe') -WorkingDirectory $bin -PassThru
    Say "started, pid $($proc.Id)"
    WaitFor 'profile read' 60 { LogLines | Select-String 'CreateFileW .*GamerProfile\.xml' } | Out-Null
    Start-Sleep 8
    $n = 0
    while (-not (LogLines | Select-String '\.sav ') -and $n -lt 25) { Guard; Key 0x0D; $n++; Start-Sleep 4 }
    if (-not (LogLines | Select-String '\.sav ')) { throw 'the save was not opened after 25 Enter presses' }
    $id = WaitFor 'player id' $LoadTimeout {
        try { $v = RunLua 'return tostring(GetLocalPlayerId())' } catch { if ("$_" -like 'timeout*') { $v = $null } else { throw } }
        if ($v -match '^\d+$' -and $v -ne '0' -and $v -ne '18446744073709551615') { $v }
    }
    Say "in the world, player id $id"

    if ($SpawnPuppet) {
        $p = PosOf $id
        $inv = [Globalization.CultureInfo]::InvariantCulture
        Say ("player at {0} {1} {2}" -f $p[0].ToString('0.000', $inv), $p[1].ToString('0.000', $inv), $p[2].ToString('0.000', $inv))
        $px = ($p[0] + 2.0).ToString('0.000', $inv)
        $py = $p[1].ToString('0.000', $inv)
        $pz = $p[2].ToString('0.000', $inv)
        $aid = RunLua "local e e = SpawnEntityFromArchetype(GetEntityName(GetLocalPlayerId()), $px, $py, $pz, 0, 0, 0) __av = tostring(e) return __av"
        Say "spawned puppet id $aid"
        if ($aid -match '^\d+$' -and $aid -ne '18446744073709551615') {
            Say "puppet valid: $(RunLua 'return tostring(IsEntityValid(__av))')"
            $nativeExtra += "ignore $aid"
        } else {
            Say 'puppet spawn failed; skipping dependent snippets'
        }
    }

    $snips = @($Lua)
    if ($LuaFile) {
        if (-not (Test-Path $LuaFile)) { throw "no $LuaFile" }
        $snips += [IO.File]::ReadAllText($LuaFile)
    }
    if ($LuaDir) {
        if (-not (Test-Path $LuaDir)) { throw "no $LuaDir" }
        Get-ChildItem $LuaDir -Filter *.lua | Sort-Object Name | ForEach-Object {
            $snips += [IO.File]::ReadAllText($_.FullName)
        }
    }
    foreach ($code in $snips) {
        Say "lua> $code"
        try { Say "out< $((RunLua $code))" } catch { Say "ERR< $_" }
    }

    $allNative = @($Native) + $nativeExtra
    if ($allNative.Count) {
        Say "native> $($allNative -join ' | ')"
        WaitFor 'native channel free' 10 { -not (Test-Path $nat) } | Out-Null
        Set-Content $nat ($allNative -join "`r`n") -Encoding ascii
        WaitFor 'native commands done' 300 { LogLines | Select-String 'native commands done' | Select-Object -Last 1 } | Out-Null
        Say 'native commands finished'
    }

    if ($KeepOpen) {
        Say 'KEEP OPEN: close the game window or press Ctrl+C to stop'
        while (-not $proc.HasExited) { Start-Sleep 2; Guard }
    }
}
catch { Say "STOPPED: $_" }
finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep 2
    if (Test-Path $log) { Copy-Item $log (Join-Path $run 'coop_probe.log') -ErrorAction SilentlyContinue }
    if ($null -ne $realBefore) { Say "real profile unchanged: $(DiffSnap $realBefore (Snapshot $realDir))" }
    Say "stopped; run.txt and log in $run"
}
