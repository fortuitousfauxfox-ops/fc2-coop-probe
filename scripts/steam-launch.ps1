<#
Steam launch wrapper for Far Cry 2 (AppID 19900): routes Steam's Join Game / accepted invites into start-coop.

When the co-op relay is not running (nothing of ours under AppID 19900), Join Game on a friend in a co-op lobby or an
accepted invite makes Steam start Far Cry 2 itself with "+connect_lobby <lobby id>", i.e. the real install. With this
wrapper set as the game's launch options in Steam, that start becomes start-coop's join on the test copy instead;
any other start (no +connect_lobby) runs exactly the command Steam gave, so the game starts as before.

Steam > Library > Far Cry 2 > Properties > Launch options (one line, own paths):
  powershell -ExecutionPolicy Bypass -File "<kit>\steam-launch.ps1" -TestDir <test copy> -SteamDll <steam_api64.dll> -Python <python> %command%

While start-coop already waits in its host list (-Join pick) or runs, Steam hands Join Game / invites to the running
relay instead (callback 333), and this wrapper is not involved.
#>
# no positional binding: everything after the named parameters is Steam's command
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][string]$TestDir,
    [Parameter(Mandatory = $true)][string]$SteamDll,
    [string]$Python = 'python',
    # Steam's %command%: the game's exe and its arguments
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Command
)
$ErrorActionPreference = 'Stop'
$kit = $PSScriptRoot
$logFile = Join-Path $kit 'steam-launch.log'
function Note($m) { try { [IO.File]::AppendAllText($logFile, ("[{0:yyyy-MM-dd HH:mm:ss}] {1}`r`n" -f (Get-Date), $m)) } catch { } }

$i = [Array]::IndexOf([string[]]$Command, '+connect_lobby')
if ($i -ge 0 -and $i + 1 -lt $Command.Count -and $Command[$i + 1] -match '^\d+$') {
    $lobby = $Command[$i + 1]
    Note "Join Game / invite for lobby ${lobby}: start-coop join on $TestDir"
    $sc = Join-Path $kit 'start-coop.ps1'
    # a console of its own, kept open after the run, so the owner sees the link state and the result
    Start-Process powershell -Wait -ArgumentList @('-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$sc`"", '-Role', 'join',
        '-TestDir', "`"$TestDir`"", '-SteamDll', "`"$SteamDll`"", '-Python', "`"$Python`"", '-Lobby', $lobby)
}
elseif ($Command.Count -gt 0) {
    Note "plain start: $($Command[0])"
    $exe = $Command[0]
    $rest = @($Command | Select-Object -Skip 1 | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } })
    $p = if ($rest.Count) { Start-Process $exe -ArgumentList $rest -WorkingDirectory (Split-Path $exe) -PassThru } else { Start-Process $exe -WorkingDirectory (Split-Path $exe) -PassThru }
    $p.WaitForExit()  # Steam counts the game as running while this wrapper runs
}
else { Note 'no command from Steam (is %command% missing in the launch options?)' }
