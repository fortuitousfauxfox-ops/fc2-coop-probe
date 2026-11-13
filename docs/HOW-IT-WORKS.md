# How it works

Everything runs inside the game through `dinput8.dll`: the game loads it like the real DirectInput library, the probe
loads the real one and then hooks into `Dunia.dll` (Steam 1.03 only; all addresses are for that build). A small Python
relay next to each game carries the probe's UDP datagrams over Steam.

## Who runs what

- **Host** (copy A, or PC 1): plays normally and owns the world. Its AI runs every NPC.
- **Joiner** (copy B, or PC 2): loads the host's save and connects. Its own NPC AI is paused; it shows the host's
  NPCs as puppets, and its own reinforcement spawning is switched off at the source.
- **Each side** sends its own player 20 times a second and shows the other player as an avatar.

## The other player's avatar

The avatar is spawned from the network archetype `player.MainCharacter.PawnPlayerNetwork` (it comes with the modding
guide's entity library patch) and made invincible. It is driven like a remote player in the game's own multiplayer:
the sender encodes its player with the game's ThirdParty encoder into a "memento"; the receiver writes those fields
into the avatar's memento and the game's NetPlayer code applies them (position, velocity, aim, stance, fire). The
weapon in the hands travels by archetype name; switching uses the game's own holster and draw. State machine signals
(grenade throw, doors) are replayed from an allow list, and a door's id and side travel with it.

## Hits and damage

The shooter's window decides. A hit on the avatar is packed and applied to the other player there; the avatar's own
stims on the local player are dropped. The joiner's hits on NPCs go to the host; an NPC's hit on the avatar on the
host goes to the joiner. A bump filter drops collision damage while the two players touch.

## NPCs

The host scans AI pawns within 80 m of either player and sends them in NPC1 packets (position, velocity, aim, state
bits, health, trigger pulls). On the joiner each NPC becomes a puppet: its agent is paused and it gets the avatar
treatment (net component, memento, NetPlayer). On top of that:

- move state ids per animation layer (NMS1) and the movement resources (clips) and blackboard values the host's NPC
  has loaded (NDP1), so idle actions, smart terrain (sitting, smoking) and mounted guns play the same;
- the host's recent path (puppets follow it 300 ms behind), yaw and height;
- weapons (NWPN) and animation inputs (NANM);
- reactions of the joiner's puppets to the joiner's player (aimed at, shoved) go back to the host's NPC (NRE1);
- NPCs the joiner's world lacks are spawned there; the joiner's own NPCs the host does not have are removed (not
  within 15 s after the player jumps).

## Vehicles

Each side sends the vehicle its player is in; the host also sends vehicles moving near either player. The avatar
gets in and out through its own state machine, so it plays the game's get-in, driving and get-out animations.

## Menu, Steam and saves

- The Story Mode page gets a Singleplayer / Cooperative choice. Under Cooperative, "Host a game" and "Join a
  friend's game" talk to `scripts/start-coop.ps1 -Role menu` through two small files.
- The relay (`relay/fc2_relay.py`, Python + `steam_api64.dll`) runs under Far Cry 2's AppID 19900: the host opens a
  friends lobby with its name, probe build and save hash; the joiner lists friends hosting one. Steam's "Join Game"
  works while the list is open.
- The joiner loads the host's save (its copy is made the newest). When the host loads a save, the joiner restarts
  with the same file. When the host leaves, the joiner returns to the main menu.
- Messages in the game's top-left corner: a player joining or leaving.
- The map shows the other player's arrow (host green, joiner yellow; an extra archetype in the patch).

## Packets

| Magic | Direction | What |
|---|---|---|
| (by size) | both | own player: position, heading, ThirdParty fields, weapon, shot, time of day (host) |
| `HIT1` | both | our player hit the avatar |
| `NHT1` | joiner → host | the joiner hit an NPC |
| `NSHT` | host → joiner | an NPC hit the avatar |
| `NPC1` | host → joiner | NPC snapshot |
| `NREQ` / `NARC` | joiner ↔ host | spawn request and archetype answer for an NPC the joiner lacks |
| `NWPN`, `NANM`, `NMS1`, `NDP1` | host → joiner | NPC weapon, animation inputs, move states, movement resources |
| `NRE1` | joiner → host | a puppet reacted to the joiner's player |
| `VEH1` | both | vehicles |
| `SIG1`, `DOR1` | both | state machine signals (grenade, doors), door id and side |
| `RLD1` | host → joiner | the host loaded a save |
| `BYE1` | both | the game closes or reloads |
| `NAM1` | relay → own game | the peer's Steam name |

## Low-level details

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
- An exception filter and a vectored handler log access violations. Many at start-up come
  from system libraries and are harmless.

