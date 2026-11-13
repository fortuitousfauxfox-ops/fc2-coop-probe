# Commands and control files

The probe reads these files in the test copy's `bin` folder (next to `FarCry2.exe`). `start-coop.ps1` writes the
ones a normal session needs; the rest are for testing and research.

## Files

| File | What |
|---|---|
| `coop_flags.txt` | read at start: `npchost` (host) or `npcjoin` (joiner); `noautodraw` keeps the save's own auto-draw setting |
| `coop_auto.txt` | commands run once the player is ready, separated by `;`; `$ME` is replaced by the player's entity id |
| `coop_native.txt` | native commands, one per line; picked up and deleted |
| `coop_cmd.lua` | a Lua 4.0 chunk run on the game's main thread; the result is what it puts in `__out` |
| `coop_probe.log` | the probe's log (UTF-8); `start-coop` moves it into `coop-runs\<time>\` after a run |
| `coop_menu.txt`, `coop_menu_state.txt` | the in-game Cooperative menu and `start-coop -Role menu` talk through these |
| `coop_reload.txt` | written by the joiner when the host loaded a save, for `start-coop` to restart the game |

A normal session uses, for example, `worldsync host;avmode np player.MainCharacter.PawnPlayerNetwork 0 0 0` in the
host's `coop_auto.txt` (`worldsync join;...` for the joiner); `start-coop` adds `npcsync` and `netstart`.

## Session

| Command | What |
|---|---|
| `netstart <local port> <peer ip> <peer port> <entity>` | connect to the peer (or to the local relay) |
| `worldsync host\|join\|off` | time of day from the host |
| `npcsync host [radius]\|join\|off` | NPC sync role (radius default 80 m) |
| `avmode np <archetype> [yaw] [x] [y]` / `avmode body` | how the other player's avatar is shown |
| `hitsync 0\|1` | hit sync between players and NPCs (default 1) |
| `vehsync 0\|1` | vehicle sync (default 1) |
| `sigsync 0\|1`, `doorsync 0\|1` | replay of the other player's grenade throw and doors |
| `savegame 0` | save to quicksave.sav like the menu |
| `menuquit` | back to the main menu |
| `notice <text>` | show a message in the game's top-left corner |

## NPCs (host and joiner)

| Command | What |
|---|---|
| `npcstat` | per NPC: trigger pulls on the host and the puppet, health, state |
| `npcdiff 0\|1` | each live puppet against the host, one line a second |
| `npcinterp <ms>` | puppets follow the host's path this far behind (300 default, 0 off) |
| `npchitsrc 0\|1` | the joiner's hits reach the host as hits by the host's player (default 1) |
| `reinfblock 0\|1` | the joiner's own reinforcement spawning off (default 1) |
| `npcfire 0\|1` | puppets replay the host's trigger pulls (default 1; see issue #1) |
| `avai 0\|1` | host, experiment: the next avatar is `coop.PawnPlayerAI` so host NPCs fight the joiner; needs `tools/make_avatar_ai.py` |
| `npcanim`, `nmssync`, `nmslayers 2\|3`, `npcface`, `npcz`, `npcflag`, `npcsigdrop`, `npcrespawn`, `nsgsync` | finer switches for puppet animation, facing and height (see the source) |

## Testing and research

| Command | What |
|---|---|
| `pos <id>`, `setpos <id> x y z`, `tpb x y z` | read or set an entity's position; `tpb` moves the own body (see issue #8) |
| `findbody <id>`, `getcomp <id> <key>` | find a physics body, a component by type |
| `stimlog <avatar\|me\|id>` | log the events (stims) an entity receives |
| `vehme`, `vehseats`, `vehseat`, `vehexit`, `vehenter`, `vehgetin`, `vehgetout` | vehicle seats by hand |
| `pawnsig <id> <crc32>`, `bbset <id> <key> <u64>`, `animvars <id>`, `beautprof <id> <hash>` | state machine signal, blackboard value, animation inputs, beautifier profile |
| `mapdbg`, `mapsign`, `mapyaw`, `maparch` | map arrow placement |
| `vcall`, `vcallp`, `vcall1`, `xhook`, `dumpd` | calls and hooks for reverse engineering only |

The full list is the command parser in `src/probe.c` (function `run_native`).
