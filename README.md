# fc2-coop-probe: Far Cry 2 co-op (prototype)

A two-player co-op prototype for the **Far Cry 2** campaign (Steam, version 1.03, Dunia engine).
It is a `dinput8.dll` proxy that you drop into a **test copy** of the game: the joiner loads the
host's save, the two games connect over a Steam relay, and each player sees the other as an
animated avatar in the same world. It is **not** a finished mod: see the status below and the
[open issues](https://github.com/HitchLangley/fc2-coop-probe/issues).

Maintained by [HitchLangley](https://github.com/HitchLangley). Started from
[MortyRei/fc2-coop-probe](https://github.com/MortyRei/fc2-coop-probe) (initial import, MIT);
everything after that is developed here, on the `main` branch.

This repository is a combined fork of
[HitchLangley/fc2-coop-probe](https://github.com/HitchLangley/fc2-coop-probe) (MIT, works above
included) with the physics, collision and entity-transform research written up in the
[coop-anything](https://github.com/cranebeaker/coop-anything/tree/main/games/far-cry-2) Far Cry 2
notes: see [docs/FINDINGS-physics-and-transform.md](docs/FINDINGS-physics-and-transform.md) and
the probe commands and scripts added alongside it.

## Status (November 2026)

Tested with two copies of the game on one PC; items marked "two PCs" were also run between two PCs
over Steam. The newest work (enemies, NPC fights) has not been run on two PCs yet.

| Area | State |
|---|---|
| Joining | Works (two PCs): Story Mode > Cooperative menu row, Steam friend lobby, Steam "Join Game"; the joiner loads the host's save; reload together |
| Partner avatar | Works: walking and running animations, heading, weapons with switch animations, shots, grenade throw, doors, map and GPS in the hand |
| Player hits | Works: a hit on the other player's avatar damages that player |
| Vehicles | Works on one PC: both players in one car, seats with animations |
| Time of day | Synced from the host |
| NPCs | The host runs all NPCs; the joiner shows them as puppets: movement, idle actions (sitting, smoking), mounted guns. Fights are rough (see issues) |
| Enemies attacking the joiner | Experiment, off by default (`avai 1` on the host, needs a patched entity library): host NPCs shoot the joiner and the hits take the joiner's health |
| Not synced yet | Missions and story, pickups and other world state, death and revive, alarms at outposts |

Known problems are tracked in [Issues](https://github.com/HitchLangley/fc2-coop-probe/issues).

## What has been built

Everything below was made and checked in this repository after the initial import. "Two PCs" means it also ran
between two PCs on different networks over Steam.

### Joining and the menu
- **Cooperative in the game's own menu.** Story Mode now opens a choice of **Singleplayer** and **Cooperative**.
  Cooperative offers **Host a game** and **Join a friend's game** (a list of up to four friends hosting, with their
  Steam names), a status line, and **Stop co-op**. Two PCs.
- **Steam friends lobby under Far Cry 2's own AppID** (19900), so friends see "Far Cry 2". The host's lobby carries its
  Steam name, the probe build and the save's hash; the joiner is warned about a different build or save. Two PCs.
- **Steam "Join Game" and invites** reach the joiner's session while it waits in the friends list. Two PCs.
- **Joining from the host's save**: the joiner loads the same save, is placed 2 m beside the host, and the avatars
  appear. Two PCs.
- **Reload together**: when the host loads a save, the joiner restarts with the same file and reconnects. Two PCs.
- **Host leaves → joiner goes back to the main menu** (after a short notice). One PC.
- **Notices in the game's corner**: "player … is joining / has left", with Steam names. Two PCs.

### The other player
- **Animated avatar**: walking, running, heading and aim from the other player, through the game's own network
  player code (it slid in an idle pose at the start). Two PCs.
- **Weapons in the avatar's hands**, with the game's holster and draw animations when switching; the map and the GPS
  are held like the other player holds them. One PC.
- **Shots and hits**: the avatar fires where the other player fired, and a hit on the avatar damages that player.
  Two PCs.
- **Grenade throws and doors** play on the avatar; a door opens for both. One PC.
- **The other player's arrow on the map**: the host's arrow is green, the joiner's yellow (a new map icon built from
  the game's own arrow). Two PCs.
- **Vehicles**: a car driven by one player moves for the other; the avatar gets in, drives and gets out with the
  game's animations; two players in one car. One PC.

### The world and NPCs
- **Time of day** follows the host.
- **One world of NPCs**: the host's AI runs every NPC; the joiner shows them as puppets that walk the host's path,
  play the same idle actions (sitting on boxes, smoking, phone calls) and man the same mounted guns. The joiner's own
  reinforcements are switched off. One PC.
- **NPCs react to the joiner**: the joiner's hits alarm the host's NPCs; hands-up and shove reactions to the joiner
  are passed to the host. One PC.
- **Enemies fight the joiner** (experiment, off by default, `avai 1`): host NPCs see and shoot the joiner's avatar
  and the hits take the joiner's health. One PC.

### Tools for development
- A Lua channel and about a hundred native commands inside the running game ([commands](docs/COMMANDS.md)).
- Scripts that set up test copies, fetch the Steam library, start a co-op session from the menu, and route Steam's
  Join Game into it ([scripts](scripts)).
- Python tools for the game's archives and entity libraries, used to build the map icon, the two-sided hand map and
  the experimental AI avatar ([tools](tools)).
- An automated test that drives two game copies on one PC and checks positions and heading.

## Read this first

- Single-player campaign only. Do not use it online; PunkBuster is not touched and nothing
  here is meant to be used in other people's multiplayer games.
- **Use a copy of the game folder, never your real install.** Back up before you change
  anything. The proxy is loaded only if `dinput8.dll` sits next to `FarCry2.exe`.
- Every address (RVA) in `src/probe.c` is for this `Dunia.dll` only:
  SHA-256 `6353936a54aa841350bb30ff005727859cdef1aa10c209209b220b399e862765`,
  20,183,176 bytes (Steam build id 52164). Other builds need new addresses.
- The game files are not included and not needed here.

## Quick start

You need: Far Cry 2 from Steam (version 1.03), two test copies of the game folder (or one per PC), Python 3 (64-bit)
and, on each PC, a Steam account that owns Far Cry 2 and is a friend of the other player's account.

1. **Test copy.** `scripts/setup-copy.ps1 -Letter A -PrivateDir <folder>` (host) or `-Letter B` (joiner) copies your
   install, checks the
   `Dunia.dll` build and patches the copy so that it runs next to the normal game with its own profile and saves.
   It never touches the real install or the real saves.
   `-PrivateDir` holds a `GamerProfile.xml` and the one save both players load; it goes into the copy's own profile.
2. **Entity library patch.** The avatar needs the network player archetype from the Far Cry 2 modding guide's
   "Pre-gathered Files (NO CHANGES)" patch (`patch.fat` / `patch.dat` in `Data_Win32`). On top of it,
   `tools/make_peer_arrow.py` adds the other player's map arrow and `tools/make_map_twosided.py` makes the hand map
   visible from both sides. Game files are not shipped here; each tool builds the patch from your own copy.
3. **Steam library.** `scripts/get-steam-api.ps1` downloads `steam_api64.dll` (Steamworks.NET, checked by SHA-256)
   for the relay.
4. **Build or take the probe** (`dinput8.dll`, see Build below) and put it into the copy's `bin` folder.
5. **Play.** On both PCs run
   `powershell -ExecutionPolicy Bypass -File scripts\start-coop.ps1 -Role menu -TestDir <test copy> -SteamDll <steam_api64.dll>`.
   In the game: Story Mode → Cooperative → **Host a game** (host) or **Join a friend's game** (joiner, pick the host),
   then load the save with the game's own Continue. The joiner needs the host's save file in its profile.

`-Role host` and `-Role join` start the same session without the menu. [Manual setup](docs/MANUAL-SETUP.md) has the
older, fully manual way and a direct UDP link without Steam.

## Build

32-bit MinGW (gcc 9.2 was used):

```
gcc -O1 -shared -o dinput8.dll src/probe.c src/probe.def -lws2_32 -static-libgcc
```

or run `build.bat`. Copy `dinput8.dll` into the `bin` folder of the test copy (next to
`FarCry2.exe`). On start it writes `coop_probe.log` in that folder.

## Documentation

- [How it works](docs/HOW-IT-WORKS.md): who runs what, the avatar, hits, NPCs, vehicles, menu and Steam, the packets.
- [Commands and control files](docs/COMMANDS.md).
- [Manual setup](docs/MANUAL-SETUP.md): byte patches by hand, the Lua and command files, a direct link, the relay alone.
- [Physics off and the entity transform](docs/FINDINGS-physics-and-transform.md): why the puppet
  must be non-physical, how to switch physics off with the engine setter, the collision switches
  that do not work, and the engine transform setter found with a hardware watchpoint.
- Research notes and dated evidence: the Far Cry 2 write-up in
  [coop-anything](https://github.com/cranebeaker/coop-anything/tree/main/games/far-cry-2).

## Tools

| Tool | What |
|---|---|
| `tools/fat_extract.py` | read and extract files from the game's FAT2 archives (with LZO1X) |
| `tools/fcb.py` | read Dunia binary object files such as the entity libraries |
| `tools/make_peer_arrow.py` | build a patch pair with the other player's yellow map arrow |
| `tools/make_map_twosided.py` | build a patch pair whose hand map materials are two-sided |
| `tools/make_avatar_ai.py` | build a patch pair with `coop.PawnPlayerAI`, the avatar that host NPCs can fight (`avai 1`) |
| `relay/fc2_relay.py` | the Steam relay that `start-coop` runs |
| `scripts/*.ps1` | set up a copy, get the Steam library, start a session, Steam launch wrapper |

## Automated two-copy test

`tests/two_copy_walk.ps1` runs the two-copy setup above without a human: it starts both test
copies, presses Enter until each has loaded the save from its own profile, runs `netstart` on
both, walks copy A's player on a circle with `walk`, and checks from the logs and `pos`
readings that copy B's avatar follows A while B's own player stays put. Then it turns A's
player three times with relative mouse movement and checks that B's avatar faces the same
way (within 15 degrees). A kill switch stops
both copies if a log line names the real profile folder, and the real profile folder is
compared with a snapshot afterwards. Both copies must already be patched and have their
profiles; the script does not patch anything.

```
powershell -ExecutionPolicy Bypass -File tests\two_copy_walk.ps1 -CopyA <test copy A> -CopyB <test copy B> -OutDir <results folder>
```

With `-Relay` the probes talk to two `relay/fc2_relay.py` processes (udp transport) instead of to
each other, and two more checks require both relays to have carried traffic. With
`-PeerIp <this PC's LAN address>` both copies use the network mode, and a further check
sends 30 forged packets from `127.0.0.1` to copy B and requires them to be dropped. The windows
are titled `A` and `B` so they are easy to tell apart.

It presses Enter and moves the mouse in the game windows, so leave keyboard and mouse alone for
the ~2.5 minutes it runs. Exit code 0 = pass, 1 = a check failed, 2 = setup problem; `run.txt`,
`results.json`, `positions_b.csv` and both logs go to `<results folder>\<timestamp>\`. The check
`B player stays put` is the one that catches the avatar-binding bug (with the unfixed probe
B's own player was dragged 16 m); `avatar heading follows A` fails on a probe without the
heading code (the avatar stays at 0 degrees).

## Known limits

See [Issues](https://github.com/HitchLangley/fc2-coop-probe/issues) for the current list. Direct UDP has no NAT traversal (use the
Steam relay), and every address in `src/probe.c` is for this exact `Dunia.dll` build only.

## License

MIT, see [LICENSE](LICENSE).
