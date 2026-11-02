<#
Starts one side of a two-PC Far Cry 2 co-op probe session over Steam.

  host (PC A):  powershell -ExecutionPolicy Bypass -File scripts\start-coop.ps1 -Role host -TestDir <test copy> -SteamDll <steam_api64.dll>
  join (PC B):  powershell -ExecutionPolicy Bypass -File scripts\start-coop.ps1 -Role join -TestDir <test copy> -SteamDll <steam_api64.dll>

What it does: starts the patched test copy (window title A or B, kept for the whole run), presses Enter until the
probe log shows the save being opened (so do not use the keyboard until then), waits until the player id answers
through the probe's Lua channel, starts relay\fc2_relay.py with the Steam transport under -AppId (default 19900
Far Cry 2; host: friends-only lobby with its Steam name, probe build and save; join: before the game starts, lists
friends hosting such a lobby and asks which one, then keeps rejoining that host's lobby), connects the probe to the relay with `netstart`, then prints
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
    # join side: 'pick' lists friends hosting a co-op lobby and lets you choose one before the game starts (one host
    # is taken at once); 'friend' takes the first friend's lobby found (retrying); 'wait' joins when you accept the
    # host's Steam invite or click Join Game on the host in the Steam friends list
    [ValidateSet('pick', 'friend', 'wait')][string]$Join = 'pick',
    # Steam AppID the relay runs under, the same on both PCs: 19900 = Far Cry 2 (the account must own it; friends
    # see "Far Cry 2"), 480 = Spacewar (any account)
    [int]$AppId = 19900,
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
function Say($m) {
    $l = "[{0:HH:mm:ss}] {1}" -f (Get-Date), $m; Write-Output $l
    # someone reading run.txt at the same moment made Add-Content fail, and under ErrorActionPreference Stop that ended
    # the run and closed the game: retry a few times, then give up on that line only
    for ($i = 0; $i -lt 5; $i++) { try { [IO.File]::AppendAllText((Join-Path $runDir 'run.txt'), $l + "`r`n"); break } catch { Start-Sleep -Milliseconds 50 } }
}

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
function Sha8($path) { if (Test-Path $path) { (Get-FileHash $path -Algorithm SHA256).Hash.Substring(0, 8) } else { '' } }
function NewestSave { Get-ChildItem (Join-Path $pdir 'Saved Games') -Filter *.sav -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1 }
$joinArg = $Join
function StartRelay {
    $rargs = @('-I', '-u', "`"$relayPy`"", '--transport', 'steam', '--steam-dll', "`"$SteamDll`"", '--appid', $AppId, '--game-port', $gamePort, '--relay-port', $relayPort)
    if ($Role -eq 'host') {
        $rargs += '--host'; if ($Invite) { $rargs += @('--invite', "`"$Invite`"") }
        # shown in the joiner's host picker, which warns when its probe build or save differs
        $sv = NewestSave
        $rargs += @('--lobby-data', "build=$(Sha8 (Join-Path $bin 'dinput8.dll'))")
        if ($sv) { $rargs += @('--lobby-data', "save=$($sv.Name)", '--lobby-data', "savehash=$(Sha8 $sv.FullName)") }
    } else { $rargs += @('--join', $joinArg) }
    $wd = Join-Path $kit 'steam-run'; New-Item -ItemType Directory -Force $wd | Out-Null
    Start-Process $Python -ArgumentList $rargs -WorkingDirectory $wd -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $runDir 'relay.log') -RedirectStandardError (Join-Path $runDir 'relay.err')
}
function AppIdHint($errFile) {
    if (Get-Content $errFile -ErrorAction SilentlyContinue | Select-String -SimpleMatch 'InitFlat under AppID') {
        throw "Steam would not start the relay under AppID $AppId (does this Steam account own Far Cry 2?). Run both PCs with -AppId 480 (Spacewar) instead."
    }
}
# join side, before the game starts: asks the relay for friends hosting a co-op lobby (relay --list) and lets the
# owner pick one; returns 'friend:<host steamid>' so the relay keeps rejoining that host's lobby
function PickHost {
    $wd = Join-Path $kit 'steam-run'; New-Item -ItemType Directory -Force $wd | Out-Null
    $out = Join-Path $runDir 'lobbies.json'; $myBuild = Sha8 (Join-Path $bin 'dinput8.dll')
    $interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
    while ($true) {
        Remove-Item $out -ErrorAction SilentlyContinue
        $largs = @('-I', '-u', "`"$relayPy`"", '--transport', 'steam', '--steam-dll', "`"$SteamDll`"", '--appid', $AppId, '--list', "`"$out`"")
        # test with one Steam account: lobby ids to list besides the friends' ones (our own host lobby)
        foreach ($x in "$env:FC2COOP_LIST_EXTRA" -split ',') { if ($x -match '^\d+$') { $largs += @('--list-extra', $x) } }
        $p = Start-Process $Python -ArgumentList $largs `
            -WorkingDirectory $wd -WindowStyle Hidden -PassThru -Wait `
            -RedirectStandardOutput (Join-Path $runDir 'relay-list.log') -RedirectStandardError (Join-Path $runDir 'relay-list.err')
        AppIdHint (Join-Path $runDir 'relay-list.err')
        # ForEach-Object: PowerShell 5.1 passes a JSON array on as one object
        $hosts = @(if (Test-Path $out) { Get-Content $out -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ } })
        if ($hosts.Count -gt 0) {
            # Write-Host: the function's output is its return value
            Write-Host ''
            for ($i = 0; $i -lt $hosts.Count; $i++) {
                $h = $hosts[$i]; $notes = @()
                if ($h.build -and $h.build -ne $myBuild) { $notes += "other probe build $($h.build), ours $myBuild" }
                if ($h.save) {
                    $mine = Join-Path (Join-Path $pdir 'Saved Games') $h.save
                    if (-not (Test-Path $mine)) { $notes += "we have no $($h.save)" } elseif ($h.savehash -and (Sha8 $mine) -ne $h.savehash) { $notes += "our $($h.save) differs" }
                }
                Write-Host ("  {0}) {1}   save {2}{3}" -f ($i + 1), $h.steam_name, $(if ($h.save) { $h.save } else { '?' }), $(if ($notes) { '   WARNING: ' + ($notes -join '; ') } else { '' }))
            }
            $pick = -1
            if ($hosts.Count -eq 1 -or -not $interactive) { $pick = 0; Write-Host '  -> taking 1' }
            else {
                while ($pick -lt 0) {
                    $r = Read-Host "Host number (1-$($hosts.Count)), r = refresh, q = quit"
                    if ($r -eq 'q') { throw 'no host picked' }
                    if ($r -eq 'r') { break }
                    $n = 0; if ([int]::TryParse($r, [ref]$n) -and $n -ge 1 -and $n -le $hosts.Count) { $pick = $n - 1 }
                }
                if ($pick -lt 0) { continue }
            }
            $h = $hosts[$pick]
            Say "host picked: $($h.steam_name) (save $($h.save), build $($h.build))" | Write-Host
            return "friend:$($h.host)"
        }
        Say "no friend is hosting a co-op lobby under AppID $AppId yet; looking again in 5 s (Ctrl+C to stop)" | Write-Host
        Start-Sleep 5
    }
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
    if ($Role -eq 'join' -and $Join -eq 'pick') { $joinArg = PickHost | Select-Object -Last 1 }
    $reloadFlag = Join-Path $bin 'coop_reload.txt'
    Remove-Item $reloadFlag -ErrorAction SilentlyContinue
    # starts the game, presses Enter until the newest save is loaded and returns the player id (also used to start it
    # again when the probe asks for a reload together with the host)
    function StartGame {
        if (Test-Path $log) { Move-Item $log (Join-Path $bin ("coop_probe.{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))) }
        Remove-Item (Join-Path $bin 'coop_cmd.lua'), (Join-Path $bin 'coop_native.txt') -ErrorAction SilentlyContinue
        $script:game = Start-Process (Join-Path $bin 'FarCry2.exe') -WorkingDirectory $bin -PassThru
        Say "game started (pid $($game.Id)), window title $title"
        $pl = WaitFor 'profile read' 60 { LogLines | Select-String 'CreateFileW .*GamerProfile\.xml' | Select-Object -First 1 }
        Say "profile: $($pl.Line -replace '^\S+ \S+ ', '')"
        Start-Sleep 6
        $n = 0
        while (-not (LogLines | Select-String '\.sav ') -and $n -lt 25) { Guard; Key 0x0D; $n++; Start-Sleep 4 }
        $sl = LogLines | Select-String '\.sav ' | Select-Object -First 1
        if (-not $sl) { throw 'the save was not opened after 25 Enter presses' }
        Say "save: $($sl.Line -replace '^\S+ \S+ ', '')"
        $pid_ = WaitFor 'player id' 240 { try { $v = Lua 'tostring(GetLocalPlayerId())' } catch { if ("$_" -like 'timeout*') { $v = $null } else { throw } }; if ($v -match '^\d+$' -and $v -ne '0' -and $v -ne '18446744073709551615') { $v } }
        Say "in the world, player id $pid_"
        $pid_
    }
    $id = StartGame | Select-Object -Last 1   # the function also returns what Say printed
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
            AppIdHint (Join-Path $runDir 'relay.err')
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
    while (-not $Seconds -or ((Get-Date) - $start).TotalSeconds -lt $Seconds) {
        Start-Sleep -Milliseconds 500
        if ($game.HasExited) {
            # the probe ended the game to load the save the host just loaded (game over / reload on the host): make that
            # save the newest one, start the game again (Continue loads it) and connect it to the running relay
            if ($Role -ne 'join' -or -not (Test-Path $reloadFlag)) { break }
            $name = (Get-Content $reloadFlag -TotalCount 1).Trim(); Remove-Item $reloadFlag
            $sv = Join-Path (Join-Path $pdir 'Saved Games') $name
            if ($name -notmatch '^[\w.-]+\.sav$' -or -not (Test-Path $sv)) { Say "reload asked for '$name', not in the save folder: stopping"; break }
            Copy-Item $log (Join-Path $runDir ("coop_probe-until-{0:HHmmss}.log" -f (Get-Date))) -ErrorAction SilentlyContinue
            (Get-Item $sv).LastWriteTime = Get-Date
            Say "the host loaded ${name}: starting the game again with it"
            $id = StartGame | Select-Object -Last 1
            Native "netstart $gamePort 127.0.0.1 $relayPort $id"
            Say "probe connected to the relay again"
            $avatar = $null
            continue
        }
        Guard
        if (-not $avatar) { $a = LogLines | Select-String 'avatar spawned: (\d+)' | Select-Object -Last 1; if ($a) { $avatar = $a.Matches[0].Groups[1].Value; Say "avatar of the other player spawned: $avatar" } }
        if ($Role -eq 'join' -and $avatar -and ((Get-Date) - $sample).TotalSeconds -ge 2) {
            # position samples are only for the log: a probe slow to take the command file (10 s) used to end the run
            # and close the game; now that sample is skipped and the file removed
            $sample = Get-Date
            try { Native "pos $avatar`r`npos $id" } catch { Say "position sample skipped: $_"; Remove-Item (Join-Path $bin 'coop_native.txt') -ErrorAction SilentlyContinue }
        }
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
