<#
Starts one side of a two-PC Far Cry 2 co-op probe session over Steam.

  host (PC A):  powershell -ExecutionPolicy Bypass -File scripts\start-coop.ps1 -Role host -TestDir <test copy> -SteamDll <steam_api64.dll>
  join (PC B):  powershell -ExecutionPolicy Bypass -File scripts\start-coop.ps1 -Role join -TestDir <test copy> -SteamDll <steam_api64.dll>

What it does: starts the patched test copy (window title A or B, kept for the whole run), presses Enter until the
probe log shows the save being opened (so do not use the keyboard until then), waits until the player id answers
through the probe's Lua channel, starts relay\fc2_relay.py with the Steam transport (host: friends-only lobby;
join: finds the friend's lobby, retrying every 10 s), connects the probe to the relay with `netstart`, then prints
the link state every 5 s. The join side also samples the avatar's and the own player's position every 2 s.
Stop with Ctrl+C or by closing the game; the logs then go to <test copy>\coop-runs\<time>\.

Kill switch: if the probe log ever names the real profile folder (My Games\Far Cry 2\), the game is killed at once.
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('host', 'join')][string]$Role,
    [Parameter(Mandatory = $true)][string]$TestDir,
    [Parameter(Mandatory = $true)][string]$SteamDll,
    [string]$Python = 'python',
    [string]$Invite,
    # join side: 'friend' finds a friend's lobby at once (retrying); 'wait' joins when you accept the host's
    # Steam invite or click Join Game on the host in the Steam friends list
    [ValidateSet('friend', 'wait')][string]$Join = 'friend',
    [string]$PlayerId,
    [int]$Seconds = 0
)
$ErrorActionPreference = 'Stop'
$kit = $PSScriptRoot
# the relay sits next to this script in the kit, or in ..\relay in the repository
$relayPy = if (Test-Path (Join-Path $kit 'fc2_relay.py')) { Join-Path $kit 'fc2_relay.py' } else { Join-Path $kit '..\relay\fc2_relay.py' }
$bin = Join-Path $TestDir 'bin'
$log = Join-Path $bin 'coop_probe.log'
$title = if ($Role -eq 'host') { 'A' } else { 'B' }
$gamePort = if ($Role -eq 'host') { 9101 } else { 9102 }
$relayPort = if ($Role -eq 'host') { 9201 } else { 9202 }
$runDir = Join-Path $TestDir ("coop-runs\{0:yyyyMMdd-HHmmss}-{1}" -f (Get-Date), $Role)
New-Item -ItemType Directory -Force $runDir | Out-Null
function Say($m) { $l = "[{0:HH:mm:ss}] {1}" -f (Get-Date), $m; Write-Output $l; Add-Content (Join-Path $runDir 'run.txt') $l }

Add-Type @"
using System; using System.Runtime.InteropServices;
public static class CoopWin {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint f, UIntPtr e);
  [DllImport("user32.dll")] public static extern uint MapVirtualKey(uint code, uint type);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool SetWindowText(IntPtr h, string s);
}
"@
$game = $null; $relay = $null

function LogLines { if (Test-Path $log) { @(Get-Content $log -ErrorAction SilentlyContinue) } else { @() } }
function Guard {
    if ($game -and -not $game.HasExited) {
        $game.Refresh()
        if ($game.MainWindowHandle -ne 0 -and $game.MainWindowTitle -ne $title) { [void][CoopWin]::SetWindowText($game.MainWindowHandle, $title) }
    }
    $hit = LogLines | Select-String -SimpleMatch 'My Games\Far Cry 2\' | Select-Object -First 1
    if ($hit) { if ($game -and -not $game.HasExited) { Stop-Process -Id $game.Id -Force }; throw "KILL SWITCH: the probe log names the real profile folder: $($hit.Line)" }
}
function WaitFor($what, [int]$s, [scriptblock]$cond) {
    $t0 = Get-Date
    while (((Get-Date) - $t0).TotalSeconds -lt $s) { Guard; if ($game.HasExited) { throw 'the game exited' }; $r = & $cond; if ($r) { return $r }; Start-Sleep -Milliseconds 500 }
    throw "timeout after $s s waiting for $what"
}
function Key([byte]$vk) {
    $game.Refresh(); [void][CoopWin]::SetForegroundWindow($game.MainWindowHandle); Start-Sleep -Milliseconds 200
    $sc = [byte][CoopWin]::MapVirtualKey($vk, 0)
    [CoopWin]::keybd_event($vk, $sc, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 80; [CoopWin]::keybd_event($vk, $sc, 2, [UIntPtr]::Zero)
}
function Lua($code) {
    $f = Join-Path $bin 'coop_cmd.lua'; $nonce = [guid]::NewGuid().ToString('N').Substring(0, 8)
    WaitFor 'lua channel' 10 { -not (Test-Path $f) } | Out-Null
    Set-Content $f "__out = '$nonce ' .. ($code)" -Encoding ascii
    $l = WaitFor 'lua answer' 15 { LogLines | Select-String "out\(\d+\)=$nonce " | Select-Object -Last 1 }
    $l.Line -replace ".*out\(\d+\)=$nonce ", ''
}
function Native($text) {
    $f = Join-Path $bin 'coop_native.txt'
    WaitFor 'native channel' 10 { -not (Test-Path $f) } | Out-Null
    Set-Content $f $text -Encoding ascii
    WaitFor 'native consumed' 10 { -not (Test-Path $f) } | Out-Null
}
function StartRelay {
    $rargs = @('-I', '-u', "`"$relayPy`"", '--transport', 'steam', '--steam-dll', "`"$SteamDll`"", '--game-port', $gamePort, '--relay-port', $relayPort)
    if ($Role -eq 'host') { $rargs += '--host'; if ($Invite) { $rargs += @('--invite', "`"$Invite`"") } } else { $rargs += @('--join', $Join) }
    $wd = Join-Path $kit 'steam-run'; New-Item -ItemType Directory -Force $wd | Out-Null
    Start-Process $Python -ArgumentList $rargs -WorkingDirectory $wd -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $runDir 'relay.log') -RedirectStandardError (Join-Path $runDir 'relay.err')
}

try {
    foreach ($f in 'FarCry2.exe', 'Dunia.dll', 'dinput8.dll') { if (-not (Test-Path (Join-Path $bin $f))) { throw "no bin\$f in $TestDir" } }
    if (-not (Test-Path $SteamDll)) { throw "no $SteamDll" }
    # Before any Enter is pressed: the copy must have its own profile + save-list folder and that folder a save.
    # Otherwise Story Mode offers only New Story, and Enter would start a new game.
    $db = [IO.File]::ReadAllBytes((Join-Path $bin 'Dunia.dll'))
    $prof = [Text.Encoding]::ASCII.GetString($db, 0xE0E094, 10)
    $list = [Text.Encoding]::ASCII.GetString($db, 0xE089A0, 19)
    if ($prof -eq '\Far Cry 2' -or -not $prof.StartsWith('\')) { throw "the copy's Dunia.dll is not patched at 0xE0E094 (profile folder): '$prof'" }
    if ($list -ne "My Games$prof\") { throw "the copy's Dunia.dll save-list folder at 0xE089A0 is '$list', expected 'My Games$prof\'" }
    $pdir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) "My Games$prof"
    if (-not (Test-Path (Join-Path $pdir 'GamerProfile.xml'))) { throw "no GamerProfile.xml in $pdir" }
    if (-not (Get-ChildItem (Join-Path $pdir 'Saved Games') -Filter *.sav -ErrorAction SilentlyContinue)) { throw "no .sav in $pdir\Saved Games: Story Mode would offer only New Story" }
    Say "copy uses its own profile and save list: $pdir"
    if (Get-Process FarCry2 -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$bin\*" }) { throw 'this test copy is already running' }
    if (Test-Path $log) { Move-Item $log (Join-Path $bin ("coop_probe.{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))) }
    Remove-Item (Join-Path $bin 'coop_cmd.lua'), (Join-Path $bin 'coop_native.txt') -ErrorAction SilentlyContinue

    $game = Start-Process (Join-Path $bin 'FarCry2.exe') -WorkingDirectory $bin -PassThru
    Say "game started (pid $($game.Id)), window title $title"
    $pl = WaitFor 'profile read' 60 { LogLines | Select-String 'CreateFileW .*GamerProfile\.xml' | Select-Object -First 1 }
    Say "profile: $($pl.Line -replace '^\S+ \S+ ', '')"
    Start-Sleep 6
    $n = 0
    while (-not (LogLines | Select-String '\.sav ') -and $n -lt 25) { Guard; Key 0x0D; $n++; Start-Sleep 4 }
    $sl = LogLines | Select-String '\.sav ' | Select-Object -First 1
    if (-not $sl) { throw 'the save was not opened after 25 Enter presses' }
    Say "save: $($sl.Line -replace '^\S+ \S+ ', '')"
    $id = WaitFor 'player id' 240 { try { $v = Lua 'tostring(GetLocalPlayerId())' } catch { if ("$_" -like 'timeout*') { $v = $null } else { throw } }; if ($v -match '^\d+$' -and $v -ne '0' -and $v -ne '18446744073709551615') { $v } }
    Say "in the world, player id $id"
    if ($PlayerId -and $PlayerId -ne $id) { Say "WARNING: expected player id $PlayerId - is it the same save on both PCs?" }

    $relay = StartRelay
    $t0 = Get-Date
    while ($true) {
        Start-Sleep 3; Guard
        if ($game.HasExited) { throw 'the game exited while waiting for the relay' }
        $rl = Get-Content (Join-Path $runDir 'relay.log') -ErrorAction SilentlyContinue
        if ($rl | Select-String 'peer is talking|LOBBY \d+ created|entered lobby') { break }
        if ($relay.HasExited) {
            Say ("relay stopped: " + (($rl | Select-Object -Last 1), (Get-Content (Join-Path $runDir 'relay.err') -ErrorAction SilentlyContinue | Select-Object -Last 1) -join ' '))
            if ($Role -eq 'host' -or ((Get-Date) - $t0).TotalMinutes -gt 10) { throw 'relay could not start' }
            Say 'retrying in 10 s (the host may not have a lobby yet)'; Start-Sleep 10
            Copy-Item (Join-Path $runDir 'relay.log') (Join-Path $runDir ("relay-try-{0:HHmmss}.log" -f (Get-Date))) -ErrorAction SilentlyContinue
            $relay = StartRelay
        }
    }
    Say 'relay up'
    Native "netstart $gamePort 127.0.0.1 $relayPort $id"
    Say "probe connected to the relay (netstart $gamePort 127.0.0.1 $relayPort)"

    $avatar = $null; $last = Get-Date; $sample = Get-Date; $start = Get-Date
    while (-not $game.HasExited -and (-not $Seconds -or ((Get-Date) - $start).TotalSeconds -lt $Seconds)) {
        Start-Sleep -Milliseconds 500; Guard
        if (-not $avatar) { $a = LogLines | Select-String 'avatar spawned: (\d+)' | Select-Object -Last 1; if ($a) { $avatar = $a.Matches[0].Groups[1].Value; Say "avatar of the other player spawned: $avatar" } }
        if ($Role -eq 'join' -and $avatar -and ((Get-Date) - $sample).TotalSeconds -ge 2) { $sample = Get-Date; Native "pos $avatar`r`npos $id" }
        if (((Get-Date) - $last).TotalSeconds -ge 5) {
            $last = Get-Date
            $net = LogLines | Select-String '\] net: ' | Select-Object -Last 1
            $st = Get-Content (Join-Path $runDir 'relay.log') -ErrorAction SilentlyContinue | Select-String 'stats ' | Select-Object -Last 1
            Say ("{0} | {1}" -f $(if ($net) { $net.Line -replace '^\S+ \S+ ', '' } else { 'no net line yet' }), $(if ($st) { $st.Line } else { 'no relay stats yet' }))
            if ($relay.HasExited) {
                # restart the relay and keep the game running (this used to end the run, and the finally block closed
                # the game); the host's new relay makes a new lobby, the joiner's finds the friend's lobby again
                Say 'relay exited: restarting it, the game keeps running'
                Copy-Item (Join-Path $runDir 'relay.log') (Join-Path $runDir ("relay-until-{0:HHmmss}.log" -f (Get-Date))) -ErrorAction SilentlyContinue
                Start-Sleep 3
                $relay = StartRelay
            }
        }
    }
}
catch { Say "STOPPED: $_" }
finally {
    if ($relay -and -not $relay.HasExited) { Stop-Process -Id $relay.Id -Force -ErrorAction SilentlyContinue }
    if ($game -and -not $game.HasExited) { Stop-Process -Id $game.Id -Force -ErrorAction SilentlyContinue }
    if (Test-Path $log) { Copy-Item $log (Join-Path $runDir 'coop_probe.log') }
    $hits = @(Get-Content (Join-Path $runDir 'coop_probe.log') -ErrorAction SilentlyContinue | Select-String -SimpleMatch 'My Games\Far Cry 2\').Count
    Say "stopped; logs in $runDir; real-profile mentions in the probe log: $hits"
}
