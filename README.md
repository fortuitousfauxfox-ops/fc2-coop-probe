# fc2-coop-probe: Far Cry 2 co-op (prototype)

A two-player co-op prototype for the **Far Cry 2** campaign (Steam, version 1.03, Dunia engine).
It is a `dinput8.dll` proxy that you drop into a **test copy** of the game: the joiner loads the
host's save, the two games connect over a Steam relay, and each player sees the other as an
animated avatar in the same world. It is **not** a finished mod: see the status below and the
[open issues](https://github.com/HitchLangley/fc2-coop-probe/issues).

Maintained by [HitchLangley](https://github.com/HitchLangley). Started from
[MortyRei/fc2-coop-probe](https://github.com/MortyRei/fc2-coop-probe) (initial import, MIT);
everything after that is developed here, on the `sync/avatar-world-npc` branch.

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

## Read this first

- Single-player campaign only. Do not use it online; PunkBuster is not touched and nothing
  here is meant to be used in other people's multiplayer games.
- **Use a copy of the game folder, never your real install.** Back up before you change
  anything. The proxy is loaded only if `dinput8.dll` sits next to `FarCry2.exe`.
- Every address (RVA) in `src/probe.c` is for this `Dunia.dll` only:
  SHA-256 `6353936a54aa841350bb30ff005727859cdef1aa10c209209b220b399e862765`,
  20,183,176 bytes (Steam build id 52164). Other builds need new addresses.
- The game files are not included and not needed here.

## Build

32-bit MinGW (gcc 9.2 was used):

```
gcc -O1 -shared -o dinput8.dll src/probe.c src/probe.def -lws2_32 -static-libgcc
```

or run `build.bat`. Copy `dinput8.dll` into the `bin` folder of the test copy (next to
`FarCry2.exe`). On start it writes `coop_probe.log` in that folder.

## Use

The game is controlled through two files that you create in the same `bin` folder. The
probe polls them from the game's main loop about four times a second, runs them and
**deletes** them.

### `coop_cmd.lua`: Lua code

The code runs in the game's main Lua state. Put the answer into the global `__out` (a string);
it is logged as `cmd executed (N bytes) status=S out(L)=...`. `print` and `_ALERT` show
nothing in this build. Examples:

```lua
__out = "alive " .. (1 + 2)
__out = GetLocalPlayerId()
__out = tostring(IsEntityValid(GetLocalPlayerId()))
s = "" foreach(globals(), function(k, v) s = s .. k .. " " end) __out = s
```

Lua is 4.0: use `foreach`, `getn`, `..`; there is no `#`. Status 0 is success, 1 a run error,
3 a syntax error. Entity ids are 64-bit and come as decimal strings.

### `coop_native.txt`: native commands, one per line

| Command | What it does |
|---|---|
| `pos <id>` | Log position and direction of the entity (matrix at `entity+0x30`) |
| `setpos <id> <x> <y> <z>` | Write the entity matrix position once (does not stick; the body overrides it) |
| `ent <id> <len>` | Log the entity object address, vtable and `len` bytes as hex, with a float column |
| `peek <hexaddr> <len>` | Hex dump of memory (float column) |
| `poke <hexaddr> <hex32>` / `pokef <hexaddr> <float>` | Write a 32-bit value / a float |
| `scan <x> <y>` | Scan memory for the float pair (tolerance 0.01; y within 16 bytes after x) |
| `findbody <id>` | Find the Havok body (class vtable RVA `0xE67658`) nearest to the entity and cache it |
| `posb` / `tpb <x> <y> <z>` | Read / write the cached body's position (teleport) |
| `walk <radius> <seconds> <speed>` | Move the cached (local) body on a circle every frame (needs `netstart` running) |
| `hold <id> <x> <y> <z>` / `unhold` | Write the entity matrix position every tick (does not stick; kept as the negative test) |
| `follow <id> <hex offsets>` / `tp <id> <x> <y> <z> <hex offsets>` | Follow a pointer chain from the entity; write the position at its end |
| `bodyvel` / `avvel <x> <y> <z> <hexoffset>` | Write three floats into the cached / avatar body at an offset |
| `netstart <localport> <peerip> <peerport> <id>` | Open the UDP transport and start the avatar logic (peer `127.x`: loopback only; any other address: listens on all interfaces, accepts packets from that address only) |
| `netstop` | Stop it and remove the avatar |

## Two copies on one PC

Each test copy needs three same-length byte patches in its own `Dunia.dll` (the copy of the
file in that test folder, never the original; keep a backup). Offsets for the build above:

1. **Mutex name.** The string `FarCry2Instance` (file offset `0xE08950`): change one
   character (for example `FarCry2InstancA` / `FarCry2InstancB`) so both copies can run.
2. **Profile folder.** The 10-byte string `\Far Cry 2` (file offset `0xE0E094`, next to
   `\GamerProfile.xml` and `\My Games`): replace it with another 10-byte string (for example
   `\FC2test_A` / `\FC2test_B`). The profile and the save that is opened then come from
   `Documents\My Games\FC2test_A\`. Give each copy that folder with a copy of your
   `GamerProfile.xml` (set `Fullscreen="0"` and a small resolution) and, to load a save, a
   `Saved Games` folder with a copy of one `.sav`. Without a profile file the client quits.
3. **Save list folder.** The 19-byte string `My Games\Far Cry 2\` (file offset `0xE089A0`):
   replace it with the same folder, e.g. `My Games\FC2test_A\`. The list of saves behind
   Continue / Load Game is built from this folder. Without this patch a copy lists the saves in
   your real profile folder, and on a PC where the game never ran it lists none (only
   New Story). This patch alone does not move the profile: patch 2 does that (check the
   `CreateFileW ... GamerProfile.xml` and `... .sav` lines in `coop_probe.log`).

Expect 17 changed bytes in total compared with the original `Dunia.dll`.

Then start each copy by hand, press Continue, and wait until you are in the world.

Then, in each `bin` folder, create `coop_native.txt` (the entity id of the main character
is the same in both copies when they load the same save; get it with `GetLocalPlayerId()`):

```
netstart 9101 127.0.0.1 9102 <id>     (copy A)
netstart 9102 127.0.0.1 9101 <id>     (copy B)
```

The log shows `net: tx=... rx=... drop=...` once a second. After the first packet each copy
spawns an avatar of the peer (`SpawnEntityFromArchetype` with the local player's own name),
makes it invincible (`CFCXCountersComponent_SetInvincible`) and drives its body.

### Two PCs

Give each copy the other PC's address instead of `127.0.0.1` (for example
`netstart 9101 <IP of PC B> 9102 <id>` on A and `netstart 9102 <IP of PC A> 9101 <id>` on B).
With a non-loopback peer the probe binds its port on all interfaces and counts only packets
of the right size and magic from the peer's IP (the source port is not checked, NAT may change
it); everything else increments `drop`. The PCs must reach each other: same LAN, a virtual LAN
(VPN), or UDP port forwarding. There is no NAT traversal, relay or encryption, so the port is
open to anyone who can reach it (only the peer's packets are used). Tested so far only with both
copies on one PC, sending to that PC's own LAN address.

### Through Steam, without IP addresses: `relay/fc2_relay.py`

A relay next to each game copy carries the probe's packets, so friends don't need IPs or port
forwarding. The probe talks only to its local relay: `netstart <game port> 127.0.0.1 <relay port> <id>`.
Python 3, 64-bit; the Steam transport also needs the Steam client running and `steam_api64.dll`
from the Steamworks.NET Standalone release 2025.164.1 (`Windows-x64/steam_api64.dll`,
SHA-256 `eb17909a76668cf9ae0b92a618a34a50f6c73d3a6787cb4dd8ce36a8b10bfb75`; not included here).
It runs as Steam's free "Spacewar" app (AppID 480), so friends see you as "playing Spacewar".

```
host:   python relay\fc2_relay.py --transport steam --host --steam-dll <steam_api64.dll> --game-port 9101 --relay-port 9201 [--invite "<friend's Steam name>"]
friend: python relay\fc2_relay.py --transport steam --join friend --steam-dll <steam_api64.dll> --game-port 9102 --relay-port 9202
   or:  python relay\fc2_relay.py --transport steam --join wait   --steam-dll <steam_api64.dll> --game-port 9102 --relay-port 9202
```

The host creates a friends-only lobby (tagged `fc2coop=1`), sets its Steam rich presence `connect` to
`+connect_lobby <id>`, and logs the id; the friend joins by id (`--join <id>`), with `--join friend`, which
finds a friend hosting one, or with `--join wait`, which joins when the friend accepts the host's Steam
invite (`--invite`) or clicks Join Game on the host in the Steam friends list (Steam callbacks 333 and 337;
start the relay before accepting, otherwise Steam starts the real Spacewar instead). Sessions are accepted only
from lobby members; probe packets go unreliable on channel 0, a keep-alive and goodbye go reliable on
channel 1, and a peer silent for 20 s is dropped. `--transport udp --udp-local <port> --udp-peer <port>`
is a stand-in that relays over plain UDP, used by the test to run the whole chain on one PC.

### Two PCs over Steam: `scripts/`

- `scripts/setup-copy.ps1 -Letter A|B -PrivateDir <folder> [-Probe <dinput8.dll>]`: finds the game, checks
  the Dunia.dll hash, copies the install to `<drive>\fc2-coop\test-<letter>`, backs up and applies the three
  patches above (checks 17 changed bytes), installs the probe, and creates `Documents\My Games\FC2test_<letter>`
  from `-PrivateDir` (one `GamerProfile.xml` and the one `.sav` both PCs load).
- `scripts/get-steam-api.ps1`: downloads Steamworks.NET Standalone 2025.164.1 and checks the zip and
  `steam_api64.dll` hashes.
- `scripts/start-coop.ps1 -Role host|join -TestDir <copy> -SteamDll <steam_api64.dll> [-Python <python.exe>]
  [-Invite "<friend's Steam name>"] [-Join friend|wait]`:
  checks the copy's patches and that its profile folder has a save (so Enter can never start a New Story),
  starts the copy (window title `A` / `B`, kept for the run), presses Enter until the save opens, waits for the
  player id, starts the relay (host: lobby; join: finds the friend's lobby, retrying for up to 10 min), runs
  `netstart`, prints the link state every 5 s, and on the join side samples the avatar's and the own player's
  position every 2 s. Kill switch on the real profile path; logs in `<copy>\coop-runs\<time>-<role>\`.

Tested:
- the whole chain through two udp relays with both copies on one PC (the two-copy test with `-Relay`);
- **two PCs on different networks, two Steam accounts that are friends (Steam 1.03 on both)**, 2026-10-25:
  the joining relay found the host's lobby through the friends list, the session was accepted, and the first
  message was decoded with the sender identity at offset 16 (x64). Probe packets went both ways at about 16/s
  for ~7 minutes with 0 dropped on both sides and no disconnect. `walk 3 20 2` on the host: on the joining PC the
  avatar (sampled every 2 s) went round about two circles of radius ~3 m centred on the expected point
  (2 m/s x 20 s = 40 m), while that PC's own player stayed within ~0.1 m. The owner saw the avatar move on both
  screens. When the joining PC stopped, the host marked the peer down after the 20 s timeout.
  Heading was not exercised in that run (`walk` does not turn the player);
- **heading across the two PCs**, 2026-10-25: the host's player turned with the mouse 171.3 → 81.3 → -171.3 →
  77.6 degrees; the joining PC's avatar (sampled every 2 s) showed the same four headings, 1-2 s later (the
  sample step), while staying in place;
- **Steam invite**, 2026-10-25: host `--invite <name>`, joining relay `--join wait`; when the invite was accepted
  on the second PC, the relay got callback 333, entered the lobby, and the link and avatar came up within 3 s;
- **Join Game** from the Steam friends list, 2026-10-25: host without an invite, joining relay `--join wait`;
  Join Game on the host in the second PC's friends list joined the host's new lobby, also through callback
  **333** (the host is in a joinable lobby; 337 with only a connect string was not observed, but is handled);
- in all these runs: 0 dropped, no crash lines, neither probe log named a real profile folder; when one side
  stopped, the other marked the peer down after the 20 s timeout.
- Not tested yet: Join Game or an invite while the relay is not running (Steam then starts the real Spacewar),
  longer sessions, packet loss.

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

## How it works

- `DllMain` loads the real `dinput8.dll` and a watcher thread patches the import table
  of `Dunia.dll` (`bind`, `connect`, `sendto`, `recvfrom`, `WSASendTo`, `WSARecvFrom`,
  `getaddrinfo`, `gethostbyname`, `CreateFileA/W`, `PeekMessageA/W`, `PostQuitMessage`).
- An inline detour on `lua_gettop` captures the Lua state; the Lua entry points are
  `lua_dobuffer`, `lua_getglobal`, `lua_settop` and `luaL_check_lstr` at fixed RVAs.
- `PeekMessage` runs on the main thread when no script runs, so commands, the per-frame body
  writes and the transport run there.
- The physics body is found by scanning memory in 64 KiB chunks with `ReadProcessMemory`
  (a plain read can fault when another thread frees a page) for objects of one class and
  taking the one whose motion transform is nearest to the entity. Heap addresses change every
  session; the class does not.
- Heading: the body is an upright capsule whose rotation is always identity; where a pawn faces
  is the yaw in the entity matrix (`entity+0x30`, rows `(d0,d1,0)`, `(-d1,d0,0)`, `(0,0,1)`). For
  the local player the controller rewrites it every frame from mouse look; the avatar has no
  controller, so the rotation the probe writes there each tick stays (smoothed 25 % per tick).
  Writing the body's rotation, or calling `TeleportEntity` with angles, changes nothing;
  `SpawnEntityFromArchetype` only uses its last argument (yaw in degrees) at spawn.
- An exception filter and a vectored handler log access violations. Many at start-up come
  from system libraries and are harmless.

## Known limits

See [Issues](https://github.com/HitchLangley/fc2-coop-probe/issues) for the current list. Direct UDP has no NAT traversal (use the
Steam relay), and every address in `src/probe.c` is for this exact `Dunia.dll` build only.

## License

MIT, see [LICENSE](LICENSE).
