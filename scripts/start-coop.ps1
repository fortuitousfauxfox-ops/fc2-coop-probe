<#
Starts one side of a two-PC Far Cry 2 co-op probe session over Steam.

  host (PC A):  powershell -ExecutionPolicy Bypass -File scripts\start-coop.ps1 -Role host -TestDir <test copy> -SteamDll <steam_api64.dll>
  join (PC B):  powershell -ExecutionPolicy Bypass -File scripts\start-coop.ps1 -Role join -TestDir <test copy> -SteamDll <steam_api64.dll>

What it does: starts the patched test copy (window title A or B, kept for the whole run), presses Enter until the
probe log shows the save being opened (so do not use the keyboard until then), waits until the player id answers
through the probe's Lua channel, starts relay\fc2_relay.py with the Steam transport under -AppId (default 19900
Far Cry 2; host: friends-only lobby with its Steam name, probe build and save; join: before the game starts, lists
friends hosting such a lobby and asks which one - Join Game in the Steam friends list or an accepted invite also
picks it - then keeps rejoining that host's lobby; -Lobby <id> skips the list, see steam-launch.ps1), connects the probe to the relay with `netstart`, then prints
the link state every 5 s. The join side also samples the avatar's and the own player's position every 2 s.
Stop with Ctrl+C or by closing the game; the logs then go to <test copy>\coop-runs\<time>\.

  from the game menu:  ... start-coop.ps1 -Role menu -TestDir <test copy> -SteamDll <steam_api64.dll>
The game starts at its menu and nothing presses keys. Story Mode shows Singleplayer and Cooperative; under
Cooperative, "Host a game" opens the friends lobby, "Join a friend's game" lists the friends hosting one (Join Game
in Steam works too while that list is open). Then the game's own Continue / Load Game rows load the save (the
joiner's copy of the host's save is made the newest, so Continue loads it). The probe and this script talk through
bin\coop_menu.txt (the probe's request) and bin\coop_menu_state.txt (status and friends' games for the menu).

Kill switch: if the probe log ever names the real profile folder (My Games\Far Cry 2\), the game is killed at once.
#>
param(
    # menu: host or join is picked in the game (Story Mode > Cooperative)
    [Parameter(Mandatory = $true)][ValidateSet('host', 'join', 'menu')][string]$Role,
    [Parameter(Mandatory = $true)][string]$TestDir,
    [Parameter(Mandatory = $true)][string]$SteamDll,
    [string]$Python = 'python',
    # host side: a friend's Steam name or SteamID to invite once the lobby exists, or 'pick' to choose from the
    # online friends before the game starts
    [string]$Invite,
    # join side: 'pick' lists friends hosting a co-op lobby and lets you choose one before the game starts (one host
    # is taken at once); 'friend' takes the first friend's lobby found (retrying); 'wait' joins when you accept the
    # host's Steam invite or click Join Game on the host in the Steam friends list
    [ValidateSet('pick', 'friend', 'wait')][string]$Join = 'pick',
    # Steam AppID the relay runs under, the same on both PCs: 19900 = Far Cry 2 (the account must own it; friends
    # see "Far Cry 2"), 480 = Spacewar (any account)
    [int]$AppId = 19900,
    # join side: this lobby id instead of -Join (steam-launch.ps1 passes Steam's +connect_lobby here)
    [ValidatePattern('^\d*$')][string]$Lobby,
    [string]$PlayerId,
    [int]$Seconds = 0
)
$ErrorActionPreference = 'Stop'
$kit = $PSScriptRoot
# the relay sits next to this script in the kit, or in ..\relay in the repository
$relayPy = if (Test-Path (Join-Path $kit 'fc2_relay.py')) { Join-Path $kit 'fc2_relay.py' } else { Join-Path $kit '..\relay\fc2_relay.py' }
$bin = Join-Path $TestDir 'bin'
$log = Join-Path $bin 'coop_probe.log'
$menuMode = $Role -eq 'menu'
# menu mode: the window keeps the copy's letter (test-a -> A), the role comes from the game menu
$title = if ($menuMode) { if ((Split-Path $TestDir -Leaf) -match '-([a-z])$') { $Matches[1].ToUpper() } else { 'FC2' } } elseif ($Role -eq 'host') { 'A' } else { 'B' }
function SetRole($r) {
    $script:Role = $r
    $script:gamePort = if ($r -eq 'host') { 9101 } else { 9102 }
    $script:relayPort = if ($r -eq 'host') { 9201 } else { 9202 }
}
if (-not $menuMode) { SetRole $Role }
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
# join side, before the game starts: a relay listing (relay --list --watch, every 5 s) shows the friends hosting a
# co-op lobby and the owner presses a host's number; Join Game on a friend in the Steam friends list or an accepted
# invite to the host's lobby also picks it (the listing runs under our AppID, so Steam hands those to it instead of
# starting the real game). Returns 'friend:<host steamid>' so the relay keeps rejoining that host's lobby.
function StartListing($out) {
    $wd = Join-Path $kit 'steam-run'; New-Item -ItemType Directory -Force $wd | Out-Null
    Remove-Item $out, "$out.join" -ErrorAction SilentlyContinue
    # the menu may start several listings in one run: keep the earlier logs
    foreach ($f in 'relay-list.log', 'relay-list.err') {
        $p = Join-Path $runDir $f
        if (Test-Path $p) { Move-Item $p (Join-Path $runDir ($f -replace '\.', ("-{0:HHmmss}." -f (Get-Date)))) -Force -ErrorAction SilentlyContinue }
    }
    $largs = @('-I', '-u', "`"$relayPy`"", '--transport', 'steam', '--steam-dll', "`"$SteamDll`"", '--appid', $AppId, '--list', "`"$out`"", '--watch', '--seconds', 3600)
    # test with one Steam account: lobby ids to list besides the friends' ones (our own host lobby)
    foreach ($x in "$env:FC2COOP_LIST_EXTRA" -split ',') { if ($x -match '^\d+$') { $largs += @('--list-extra', $x) } }
    Start-Process $Python -ArgumentList $largs -WorkingDirectory $wd -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $runDir 'relay-list.log') -RedirectStandardError (Join-Path $runDir 'relay-list.err')
}
# friends' co-op lobbies the listing wrote last (ForEach-Object: PowerShell 5.1 passes a JSON array on as one object)
function ReadHosts($out) { @(try { Get-Content $out -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json | ForEach-Object { $_ } } catch { }) }
# what differs between a host's lobby and this copy: probe build, the save it plays
function HostNotes($h) {
    $notes = @(); $myBuild = Sha8 (Join-Path $bin 'dinput8.dll')
    if ($h.build -and $h.build -ne $myBuild) { $notes += "other probe build $($h.build), ours $myBuild" }
    if ($h.save) {
        $mine = Join-Path (Join-Path $pdir 'Saved Games') $h.save
        if (-not (Test-Path $mine)) { $notes += "we have no $($h.save)" } elseif ($h.savehash -and (Sha8 $mine) -ne $h.savehash) { $notes += "our $($h.save) differs" }
    }
    $notes
}
function PickHost {
    $out = Join-Path $runDir 'lobbies.json'; $joinFile = "$out.join"
    $interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
    $lp = StartListing $out
    try {
        $shown = $null; $waitSaid = $false
        while ($true) {
            if (Test-Path $joinFile) {
                $j = Get-Content $joinFile -Raw -Encoding UTF8 | ConvertFrom-Json
                Say "Steam Join Game / invite: host $($j.steam_name)" | Write-Host
                return "friend:$($j.host)"
            }
            if ($lp.HasExited) {
                AppIdHint (Join-Path $runDir 'relay-list.err')
                throw ("the lobby listing stopped: " + (Get-Content (Join-Path $runDir 'relay-list.err') -ErrorAction SilentlyContinue | Select-Object -Last 1))
            }
            $hosts = @(ReadHosts $out)
            $now = ($hosts | ForEach-Object { $_.lobby }) -join ','
            if ($hosts.Count -gt 0 -and $now -ne $shown) {
                $shown = $now
                # Write-Host: the function's output is its return value
                Write-Host ''
                for ($i = 0; $i -lt $hosts.Count; $i++) {
                    $h = $hosts[$i]; $notes = HostNotes $h
                    Write-Host ("  {0}) {1}   save {2}{3}" -f ($i + 1), $h.steam_name, $(if ($h.save) { $h.save } else { '?' }), $(if ($notes) { '   WARNING: ' + ($notes -join '; ') } else { '' }))
                }
                if ($hosts.Count -eq 1 -or -not $interactive) {
                    Write-Host '  -> taking 1'; $h = $hosts[0]
                    Say "host picked: $($h.steam_name) (save $($h.save), build $($h.build))" | Write-Host
                    return "friend:$($h.host)"
                }
                Write-Host "Press the host's number (1-$([Math]::Min(9, $hosts.Count))), q = quit; Join Game in Steam works too"
            }
            if ($hosts.Count -eq 0 -and -not $waitSaid -and (Test-Path $out)) {
                $waitSaid = $true; $shown = $null
                Say "no friend is hosting a co-op lobby under AppID $AppId yet; waiting (or use Join Game on the host in the Steam friends list; Ctrl+C to stop)" | Write-Host
            }
            if ($hosts.Count -gt 0) { $waitSaid = $false }
            if ($interactive -and [Console]::KeyAvailable) {
                $k = [Console]::ReadKey($true).KeyChar
                if ($k -eq 'q') { throw 'no host picked' }
                $n = [int][char]$k - [int][char]'0'
                if ($n -ge 1 -and $n -le $hosts.Count) {
                    $h = $hosts[$n - 1]
                    Say "host picked: $($h.steam_name) (save $($h.save), build $($h.build))" | Write-Host
                    return "friend:$($h.host)"
                }
            }
            Start-Sleep -Milliseconds 200
        }
    }
    finally { if (-not $lp.HasExited) { Stop-Process -Id $lp.Id -Force -ErrorAction SilentlyContinue } }
}
# host side, before the game starts (-Invite pick): online friends from the relay (--friends), the ones playing Far
# Cry 2 first; returns the picked friend's SteamID for relay --invite, or nothing
function PickFriend {
    $wd = Join-Path $kit 'steam-run'; New-Item -ItemType Directory -Force $wd | Out-Null
    $out = Join-Path $runDir 'friends.json'
    Start-Process $Python -ArgumentList @('-I', '-u', "`"$relayPy`"", '--transport', 'steam', '--steam-dll', "`"$SteamDll`"", '--appid', $AppId, '--friends', "`"$out`"") `
        -WorkingDirectory $wd -WindowStyle Hidden -PassThru -Wait `
        -RedirectStandardOutput (Join-Path $runDir 'relay-friends.log') -RedirectStandardError (Join-Path $runDir 'relay-friends.err') | Out-Null
    AppIdHint (Join-Path $runDir 'relay-friends.err')
    $fr = @(if (Test-Path $out) { Get-Content $out -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ } })
    if ($fr.Count -eq 0) { Say 'no friend is online: no invite (the friend can still use Join Game on you in Steam)' | Write-Host; return }
    Write-Host ''
    for ($i = 0; $i -lt $fr.Count; $i++) { Write-Host ("  {0}) {1}{2}" -f ($i + 1), $fr[$i].steam_name, $(if ($fr[$i].in_game) { '   (in Far Cry 2)' } else { '' })) }
    if (-not ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected)) { Say 'no console: no invite' | Write-Host; return }
    $r = Read-Host "Friend to invite once the lobby is up (1-$($fr.Count), Enter = nobody)"
    $n = 0
    if ([int]::TryParse($r, [ref]$n) -and $n -ge 1 -and $n -le $fr.Count) {
        Say "will invite $($fr[$n - 1].steam_name)" | Write-Host
        return $fr[$n - 1].id
    }
}

# ---- menu mode: the probe's Story Mode > Cooperative rows ----
# bin\coop_menu_state.txt (written here, read by the probe; it exists while this script runs): line 1 the status the
# menu shows, then "<host steamid><TAB><label>" per friend's game or "@play" once a host is taken; bin\coop_menu.txt (written by the probe, removed
# here): host | join | pick <steamid> | cancel. The menu font has no Cyrillic, Steam names in it may show as "?".
$menuReq = Join-Path $bin 'coop_menu.txt'; $menuStateFile = Join-Path $bin 'coop_menu_state.txt'
# -Play: a host is taken ("@play" line), so the probe shows the load rows even when Steam Join Game picked it
function MenuState([string]$status, $hosts, [switch]$Play) {
    $lines = @($status) + @($hosts | Where-Object { $_ } | ForEach-Object { "$($_.host)`t$($_.label)" }) + @(if ($Play) { '@play' })
    $tmp = "$menuStateFile.tmp"
    [IO.File]::WriteAllText($tmp, ($lines -join "`r`n") + "`r`n", (New-Object Text.UTF8Encoding $false))
    Move-Item $tmp $menuStateFile -Force
}
function MenuRequest {
    if (-not (Test-Path $menuReq)) { return }
    $r = try { (Get-Content $menuReq -TotalCount 1 -ErrorAction Stop).Trim() } catch { return }
    Remove-Item $menuReq -ErrorAction SilentlyContinue
    Say "menu request: $r" | Write-Host
    $r
}
# waits in the game menu until the player hosts (returns 'host') or picks a friend's game (returns 'friend:<steamid>',
# Join Game in Steam counts while the friends' list is open); makes the joiner's copy of the host's save the newest
function MenuPick {
    $out = Join-Path $runDir 'lobbies.json'; $lp = $null; $hosts = @(); $shown = $null
    MenuState ''
    Say 'waiting for Story Mode > Cooperative in the game' | Write-Host
    try {
        while ($true) {
            Guard; if ($game.HasExited) { throw 'the game exited' }
            $r = MenuRequest; $h = $null
            if ($r -eq 'host') { $script:menuReady = 'Lobby open: load a game'; return 'host' }
            if ($r -eq 'join' -and -not $lp) { $lp = StartListing $out; $shown = $null; MenuState "Looking for friends' games..." }
            if ($r -eq 'cancel') {
                if ($lp -and -not $lp.HasExited) { Stop-Process -Id $lp.Id -Force -ErrorAction SilentlyContinue }
                $lp = $null; MenuState ''
            }
            if ($r -match '^pick (\d+)$') { $sid = $Matches[1]; $h = $hosts | Where-Object { "$($_.host)" -eq $sid } | Select-Object -First 1 }
            if ($lp -and -not $h) {
                if (Test-Path "$out.join") {
                    $j = Get-Content "$out.join" -Raw -Encoding UTF8 | ConvertFrom-Json
                    Say "Steam Join Game / invite: host $($j.steam_name)" | Write-Host
                    $h = [pscustomobject]@{ host = $j.host; steam_name = $j.steam_name; save = $null; savehash = $null }
                    $h2 = $hosts | Where-Object { "$($_.host)" -eq "$($j.host)" } | Select-Object -First 1
                    if ($h2) { $h = $h2 }
                } elseif ($lp.HasExited) {
                    AppIdHint (Join-Path $runDir 'relay-list.err')
                    MenuState 'Steam listing stopped'; $lp = $null
                } else {
                    $hosts = @(ReadHosts $out)
                    $now = ($hosts | ForEach-Object { "$($_.lobby)" }) -join ','
                    if ($now -ne $shown -and (Test-Path $out)) {
                        $shown = $now
                        $rows = @($hosts | Select-Object -First 4 | ForEach-Object {
                            $n = HostNotes $_
                            [pscustomobject]@{ host = $_.host; label = "$($_.steam_name)$(if ($n) { ' (!)' })" } })
                        MenuState $(if ($hosts.Count) { 'Pick a friend' } else { 'No friend is hosting yet' }) $rows
                        foreach ($x in $hosts) { Say "friend's game: $($x.steam_name) save $($x.save) $((HostNotes $x) -join '; ')" | Write-Host }
                    }
                }
            }
            if ($h) {
                Say "host picked: $($h.steam_name) (save $($h.save), build $($h.build))" | Write-Host
                $notes = @(HostNotes $h)
                if ($notes) { Say "WARNING: $($notes -join '; ')" | Write-Host }
                $sv = if ($h.save) { Join-Path (Join-Path $pdir 'Saved Games') $h.save }
                if ($sv -and (Test-Path $sv) -and (-not $h.savehash -or (Sha8 $sv) -eq $h.savehash)) { (Get-Item $sv).LastWriteTime = Get-Date; $script:menuReady = "Continue loads $($h.save)" }
                elseif ($h.save) { $script:menuReady = "Load $($h.save) (warning)" }
                else { $script:menuReady = 'Load the host''s save' }
                # one Steam account (FC2COOP_LIST_EXTRA): our own lobby, which friend:<id> never finds - join it by id
                if ($h.lobby -and ("$env:FC2COOP_LIST_EXTRA" -split ',') -contains "$($h.lobby)") { return "$($h.lobby)" }
                return "friend:$($h.host)"
            }
            Start-Sleep -Milliseconds 300
        }
    }
    finally { if ($lp -and -not $lp.HasExited) { Stop-Process -Id $lp.Id -Force -ErrorAction SilentlyContinue } }
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
    if ($Role -eq 'join' -and $Lobby) { $joinArg = $Lobby; Say "joining lobby $Lobby (Steam Join Game / invite)" }
    elseif ($Role -eq 'join' -and $Join -eq 'pick') { $joinArg = PickHost | Select-Object -Last 1 }
    if ($Role -eq 'host' -and $Invite -eq 'pick') { $Invite = PickFriend | Select-Object -Last 1 }
    $reloadFlag = Join-Path $bin 'coop_reload.txt'
    Remove-Item $reloadFlag -ErrorAction SilentlyContinue
    # starts the game, presses Enter until the newest save is loaded and returns the player id (also used to start it
    # again when the probe asks for a reload together with the host)
    function LaunchGame {
        # right after the game exited (reload together) its process may still hold the log for a moment: the move
        # failed with "file in use" on PC2 and ended the run, so retry for up to 15 s
        for ($i = 0; (Test-Path $log); $i++) {
            try { Move-Item $log (Join-Path $bin ("coop_probe.{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))) -ErrorAction Stop; break }
            catch { if ($i -ge 30) { throw }; Start-Sleep -Milliseconds 500 }
        }
        Remove-Item (Join-Path $bin 'coop_cmd.lua'), (Join-Path $bin 'coop_native.txt') -ErrorAction SilentlyContinue
        $script:game = Start-Process (Join-Path $bin 'FarCry2.exe') -WorkingDirectory $bin -PassThru
        Say "game started (pid $($game.Id)), window title $title"
        $pl = WaitFor 'profile read' 60 { LogLines | Select-String 'CreateFileW .*GamerProfile\.xml' | Select-Object -First 1 }
        Say "profile: $($pl.Line -replace '^\S+ \S+ ', '')"
    }
    # after a save was opened: the player id once the probe's Lua channel answers in the world
    function PlayerInWorld {
        $sl = LogLines | Select-String '\.sav ' | Select-Object -First 1
        Say "save: $($sl.Line -replace '^\S+ \S+ ', '')"
        $pid_ = WaitFor 'player id' 240 { try { $v = Lua 'tostring(GetLocalPlayerId())' } catch { if ("$_" -like 'timeout*') { $v = $null } else { throw } }; if ($v -match '^\d+$' -and $v -ne '0' -and $v -ne '18446744073709551615') { $v } }
        Say "in the world, player id $pid_"
        $pid_
    }
    function StartGame {
        LaunchGame
        Start-Sleep 6
        $n = 0
        # in a menu-mode copy Story Mode starts with Singleplayer, whose first row is Continue: Enter still gets there
        while (-not (LogLines | Select-String '\.sav ') -and $n -lt 25) { Guard; Key 0x0D; $n++; Start-Sleep 4 }
        if (-not (LogLines | Select-String '\.sav ')) { throw 'the save was not opened after 25 Enter presses' }
        PlayerInWorld
    }
    # menu mode: "Stop co-op" while waiting sets $relayStopped and returns
    function WaitRelay {
        $t0 = Get-Date; $script:relayStopped = $false
        while ($true) {
            Start-Sleep 3; Guard
            if ($game.HasExited) { throw 'the game exited while waiting for the relay' }
            if ($menuMode -and (MenuRequest) -eq 'cancel') { $script:relayStopped = $true; return }
            $rl = Get-Content (Join-Path $runDir 'relay.log') -ErrorAction SilentlyContinue
            if ($rl | Select-String 'peer is talking|LOBBY \d+ created|entered lobby') { break }
            if ($relay.HasExited) {
                Say ("relay stopped: " + (($rl | Select-Object -Last 1), (Get-Content (Join-Path $runDir 'relay.err') -ErrorAction SilentlyContinue | Select-Object -Last 1) -join ' '))
                AppIdHint (Join-Path $runDir 'relay.err')
                if ($Role -eq 'host' -or ((Get-Date) - $t0).TotalMinutes -gt 10) { throw 'relay could not start' }
                Say 'retrying in 10 s (the host may not have a lobby yet)'; Start-Sleep 10
                Copy-Item (Join-Path $runDir 'relay.log') (Join-Path $runDir ("relay-try-{0:HHmmss}.log" -f (Get-Date))) -ErrorAction SilentlyContinue
                $script:relay = StartRelay
            }
        }
        Say 'relay up'
    }
    if ($menuMode) {
        Remove-Item $menuReq, $menuStateFile -ErrorAction SilentlyContinue
        LaunchGame
        while ($true) {
            $pick = MenuPick | Select-Object -Last 1
            if ($pick -eq 'host') { SetRole host } else { SetRole join; $joinArg = $pick }
            Say "menu: playing as $Role$(if ($Role -eq 'join') { " ($joinArg)" })"
            $relay = StartRelay
            MenuState $(if ($Role -eq 'host') { 'Opening the lobby...' } else { 'Joining the host...' }) -Play
            WaitRelay
            # the player loads the save with the game's own rows; "Stop co-op" in the menu goes back to the choice
            $stopped = $relayStopped
            if (-not $stopped) { MenuState $script:menuReady -Play }
            while (-not $stopped -and -not (LogLines | Select-String '\.sav ')) {
                Guard; if ($game.HasExited) { throw 'the game exited' }
                if ((MenuRequest) -eq 'cancel') { $stopped = $true; break }
                Start-Sleep -Milliseconds 500
            }
            if (-not $stopped) { break }
            Say 'menu: co-op stopped before loading'
            if ($relay -and -not $relay.HasExited) { Stop-Process -Id $relay.Id -Force -ErrorAction SilentlyContinue }
            $relay = $null
        }
        MenuState 'In game' -Play
        $id = PlayerInWorld | Select-Object -Last 1
        # the copy's coop_flags.txt / coop_auto.txt are made for one role: the one picked in the menu wins
        Native "npcsync $Role`r`nworldsync $Role"
    } else {
        $id = StartGame | Select-Object -Last 1   # the function also returns what Say printed
        if ($PlayerId -and $PlayerId -ne $id) { Say "WARNING: expected player id $PlayerId - is it the same save on both PCs?" }
        $relay = StartRelay
        WaitRelay
    }
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
    # the probe shows "Needs start-coop" again once the state file is gone
    Remove-Item $menuReq, $menuStateFile -ErrorAction SilentlyContinue
    if ($relay -and -not $relay.HasExited) { Stop-Process -Id $relay.Id -Force -ErrorAction SilentlyContinue }
    if ($game -and -not $game.HasExited) { Stop-Process -Id $game.Id -Force -ErrorAction SilentlyContinue }
    if (Test-Path $log) { Copy-Item $log (Join-Path $runDir 'coop_probe.log') }
    $hits = @(Get-Content (Join-Path $runDir 'coop_probe.log') -ErrorAction SilentlyContinue | Select-String -SimpleMatch 'My Games\Far Cry 2\').Count
    Say "stopped; logs in $runDir; real-profile mentions in the probe log: $hits"
}
