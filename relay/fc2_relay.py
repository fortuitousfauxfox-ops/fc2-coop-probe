"""
fc2_relay: carries the probe's position packets between two players, next to the game.

The probe (dinput8.dll in the game) keeps its own UDP transport and talks to this relay on
127.0.0.1: `netstart <game port> 127.0.0.1 <relay port> <id>`. The relay forwards every packet
to the other player's relay and hands what comes back to the probe.

Transports:
  udp    the other relay is reached over UDP (default 127.0.0.1): a stand-in to test the whole
         chain with two game copies on one PC, without Steam.
  steam  Steam (AppID 480 "Spacewar"): friends-only lobby, invite, P2P messages through Valve's
         relay network by SteamID. No IP addresses, no port forwarding. Needs the Steam client
         running and a 64-bit steam_api64.dll with the flat API (Steamworks.NET Standalone
         2025.164.1, SHA-256 eb17909a...fb75). See coop-anything playbook/networking-steam-spacewar.md.

Examples (game copy A host, copy B joins; probe in each copy: netstart <game port> 127.0.0.1 <relay port>):
  python fc2_relay.py --transport udp --game-port 9101 --relay-port 9201 --udp-local 9301 --udp-peer 9302
  python fc2_relay.py --transport udp --game-port 9102 --relay-port 9202 --udp-local 9302 --udp-peer 9301
  python fc2_relay.py --transport steam --host --steam-dll <path to steam_api64.dll> [--invite "<friend name>"]
  python fc2_relay.py --transport steam --join <lobby id> --steam-dll <path to steam_api64.dll>
  python fc2_relay.py --transport steam --join friend --steam-dll ...   (finds a friend hosting fc2coop)
  python fc2_relay.py --transport steam --join wait --steam-dll ...     (joins when you accept the host's Steam
                                                                          invite or click Join Game in the friends list)

Frames between relays: channel 0 = probe packets as they are (unreliable); channel 1 = control
(b"ka" keep-alive every second, b"bye"). A peer silent for 20 s is dropped.
"""
import argparse
import ctypes
import os
import socket
import sys
import time

KEEPALIVE_S = 1.0
BATCH_S = 0.05      # pack game datagrams for this long into one transport message
BATCH_MAX = 1100    # bytes per packed message (under one network packet)
TIMEOUT_S = 20.0
LOBBY_KEY, LOBBY_VAL = b"fc2coop", b"1"


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


# ---------------------------------------------------------------- transports
class UdpTransport:
    """Stand-in: frames over plain UDP to one fixed peer (1 byte channel + payload)."""

    def __init__(self, local_port, peer_host, peer_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1" if peer_host.startswith("127.") else "0.0.0.0", local_port))
        self.sock.setblocking(False)
        self.peer = (peer_host, peer_port)
        self.peer_name = "%s:%d" % self.peer
        log("udp transport: local %d -> peer %s" % (local_port, self.peer_name))

    def ready(self):
        return True

    def send(self, channel, data, reliable=False):
        try:
            self.sock.sendto(bytes([channel]) + data, self.peer)
        except OSError:
            pass

    def poll(self):
        out = []
        while True:
            try:
                d, addr = self.sock.recvfrom(2048)
            except BlockingIOError:
                break
            except ConnectionResetError:  # ICMP port unreachable from an earlier send: peer not up yet
                continue
            if addr[0] != self.peer[0] or not d:
                continue
            out.append((d[0], d[1:]))
        return out

    def close(self):
        self.send(1, b"bye")
        self.sock.close()


class CallbackMsg(ctypes.Structure):
    _pack_ = 8
    _fields_ = [("user", ctypes.c_int32), ("callback", ctypes.c_int32),
                ("param", ctypes.c_void_p), ("param_size", ctypes.c_int32)]


class FriendGameInfo(ctypes.Structure):
    _pack_ = 8
    _fields_ = [("game_id", ctypes.c_uint64), ("ip", ctypes.c_uint32), ("game_port", ctypes.c_uint16),
                ("query_port", ctypes.c_uint16), ("lobby", ctypes.c_uint64)]


class SteamTransport:
    """Steam lobby + ISteamNetworkingMessages, flat C API through ctypes (64-bit steam_api64.dll)."""

    def __init__(self, dll_path, host, join, invite):
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            sys.exit("steam transport: needs 64-bit Python (steam_api64.dll)")
        here = os.getcwd()
        if not os.path.exists(os.path.join(here, "steam_appid.txt")):
            with open(os.path.join(here, "steam_appid.txt"), "w") as f:
                f.write("480")
        d = self.d = ctypes.CDLL(dll_path)
        P, U64, I32, B, S = ctypes.c_void_p, ctypes.c_uint64, ctypes.c_int32, ctypes.c_bool, ctypes.c_char_p

        def fn(name, res, *args):
            f = getattr(d, name)
            f.restype, f.argtypes = res, list(args)
            return f

        self.f = {
            "IsSteamRunning": fn("SteamAPI_IsSteamRunning", B),
            "InitFlat": fn("SteamAPI_InitFlat", I32, ctypes.c_char_p),
            "Shutdown": fn("SteamAPI_Shutdown", None),
            "GetHSteamPipe": fn("SteamAPI_GetHSteamPipe", I32),
            "MD_Init": fn("SteamAPI_ManualDispatch_Init", None),
            "MD_RunFrame": fn("SteamAPI_ManualDispatch_RunFrame", None, I32),
            "MD_Next": fn("SteamAPI_ManualDispatch_GetNextCallback", B, I32, ctypes.POINTER(CallbackMsg)),
            "MD_Free": fn("SteamAPI_ManualDispatch_FreeLastCallback", None, I32),
            "MD_CallResult": fn("SteamAPI_ManualDispatch_GetAPICallResult", B, I32, U64, P, I32, I32, ctypes.POINTER(B)),
            "User": fn("SteamAPI_SteamUser_v023", P),
            "MM": fn("SteamAPI_SteamMatchmaking_v009", P),
            "Friends": fn("SteamAPI_SteamFriends_v018", P),
            "NM": fn("SteamAPI_SteamNetworkingMessages_SteamAPI_v002", P),
            "GetSteamID": fn("SteamAPI_ISteamUser_GetSteamID", U64, P),
            "BLoggedOn": fn("SteamAPI_ISteamUser_BLoggedOn", B, P),
            "CreateLobby": fn("SteamAPI_ISteamMatchmaking_CreateLobby", U64, P, I32, I32),
            "JoinLobby": fn("SteamAPI_ISteamMatchmaking_JoinLobby", U64, P, U64),
            "LeaveLobby": fn("SteamAPI_ISteamMatchmaking_LeaveLobby", None, P, U64),
            "SetLobbyData": fn("SteamAPI_ISteamMatchmaking_SetLobbyData", B, P, U64, S, S),
            "GetLobbyData": fn("SteamAPI_ISteamMatchmaking_GetLobbyData", S, P, U64, S),
            "GetLobbyOwner": fn("SteamAPI_ISteamMatchmaking_GetLobbyOwner", U64, P, U64),
            "NumMembers": fn("SteamAPI_ISteamMatchmaking_GetNumLobbyMembers", I32, P, U64),
            "MemberByIndex": fn("SteamAPI_ISteamMatchmaking_GetLobbyMemberByIndex", U64, P, U64, I32),
            "InviteUserToLobby": fn("SteamAPI_ISteamMatchmaking_InviteUserToLobby", B, P, U64, U64),
            "SetRichPresence": fn("SteamAPI_ISteamFriends_SetRichPresence", B, P, S, S),
            "ClearRichPresence": fn("SteamAPI_ISteamFriends_ClearRichPresence", None, P),
            "InviteDialog": fn("SteamAPI_ISteamFriends_ActivateGameOverlayInviteDialog", None, P, U64),
            "FriendCount": fn("SteamAPI_ISteamFriends_GetFriendCount", I32, P, I32),
            "FriendByIndex": fn("SteamAPI_ISteamFriends_GetFriendByIndex", U64, P, I32, I32),
            "FriendName": fn("SteamAPI_ISteamFriends_GetFriendPersonaName", S, P, U64),
            "FriendState": fn("SteamAPI_ISteamFriends_GetFriendPersonaState", I32, P, U64),
            "FriendGame": fn("SteamAPI_ISteamFriends_GetFriendGamePlayed", B, P, U64, ctypes.POINTER(FriendGameInfo)),
            "IdSet": fn("SteamAPI_SteamNetworkingIdentity_SetSteamID64", None, P, U64),
            "IdGet": fn("SteamAPI_SteamNetworkingIdentity_GetSteamID64", U64, P),
            "Send": fn("SteamAPI_ISteamNetworkingMessages_SendMessageToUser", I32, P, P, P, ctypes.c_uint32, I32, I32),
            "Recv": fn("SteamAPI_ISteamNetworkingMessages_ReceiveMessagesOnChannel", I32, P, I32, ctypes.POINTER(P), I32),
            "Accept": fn("SteamAPI_ISteamNetworkingMessages_AcceptSessionWithUser", B, P, P),
            "Close": fn("SteamAPI_ISteamNetworkingMessages_CloseSessionWithUser", B, P, P),
            "MsgRelease": fn("SteamAPI_SteamNetworkingMessage_t_Release", None, P),
        }
        F = self.f
        if not F["IsSteamRunning"]():
            sys.exit("steam transport: the Steam client is not running")
        err = ctypes.create_string_buffer(1024)
        r = F["InitFlat"](err)
        if r != 0:
            sys.exit("steam transport: SteamAPI_InitFlat failed (%d): %s" % (r, err.value.decode(errors="replace")))
        F["MD_Init"]()
        self.pipe = F["GetHSteamPipe"]()
        self.user, self.mm, self.fr, self.nm = F["User"](), F["MM"](), F["Friends"](), F["NM"]()
        self.me = F["GetSteamID"](self.user)
        log("steam: init ok, logged on=%s, own id ...%s" % (F["BLoggedOn"](self.user), str(self.me)[-4:]))
        self.lobby, self.peer, self.host = 0, 0, host
        # the joiner looks for the friend's lobby again 5 s after a failed entry or after the host left (it used to stay
        # put: once a lobby had vanished, "could not enter lobby (response 2)" and no further try); the host checks its
        # lobby every 30 s and makes a new one if Steam no longer lists it
        self.join_mode, self.rejoin_at, self.lobby_check = join, 0.0, time.time() + 30
        # session requests are accepted after the callback loop, not inside it: both relays logged the SteamNetworking
        # assert "!IsLocked()" and soon after each saw the other leave the lobby; and a peer that the lobby no longer
        # lists is kept while its messages keep coming (unlisted_at), it only counts as gone after 15 s of silence
        self.pending_accept, self.unlisted_at, self.last_rx = [], 0.0, 0.0
        self.peer_name = "(none yet)"
        self.invite = invite
        self.sender_offset = None
        self.ident = ctypes.create_string_buffer(160)
        self.msgs = (P * 32)()
        if host:
            F["CreateLobby"](self.mm, 1, 2)  # 1 = friends-only, 2 players
            log("steam: creating friends-only lobby ...")
        elif join == "friend":
            lobby = self.find_friend_lobby()
            if not lobby:
                sys.exit("steam transport: no friend is hosting an fc2coop lobby right now")
            F["JoinLobby"](self.mm, lobby)
            log("steam: joining lobby %d ..." % lobby)
        elif join == "wait":
            # joined later by on_callback: an accepted invite (333) or Join Game in the friends list (337)
            log("steam: waiting for a Steam invite or Join Game from the friends list ...")
        else:
            F["JoinLobby"](self.mm, int(join))
            log("steam: joining lobby %s ..." % join)

    # -- helpers
    def find_friend_lobby(self):
        F, info = self.f, FriendGameInfo()
        for i in range(F["FriendCount"](self.fr, 4)):  # 4 = immediate friends
            fid = F["FriendByIndex"](self.fr, i, 4)
            if F["FriendGame"](self.fr, fid, ctypes.byref(info)) and (info.game_id & 0xFFFFFF) == 480 and info.lobby:
                log("steam: friend %s is in a Spacewar lobby" % F["FriendName"](self.fr, fid).decode(errors="replace"))
                return info.lobby
        return 0

    def identity(self, steamid):
        ctypes.memset(self.ident, 0, len(self.ident))
        self.f["IdSet"](self.ident, steamid)
        return self.ident

    def is_member(self, steamid):
        F = self.f
        return self.lobby and any(F["MemberByIndex"](self.mm, self.lobby, i) == steamid
                                  for i in range(F["NumMembers"](self.mm, self.lobby)))

    def pick_peer(self):
        F = self.f
        for i in range(F["NumMembers"](self.mm, self.lobby)):
            m = F["MemberByIndex"](self.mm, self.lobby, i)
            if m != self.me:
                self.unlisted_at = 0.0
                if m != self.peer:
                    self.peer = m
                    self.peer_name = F["FriendName"](self.fr, m).decode(errors="replace")
                    log("steam: peer is %s" % self.peer_name)
                return
        if self.peer:
            if not self.unlisted_at:
                self.unlisted_at = time.time()
                log("steam: peer is no longer listed in the lobby; keeping it while its messages arrive")
            return
        self.peer, self.peer_name = 0, "(none yet)"

    def leave_and_retry(self):
        if self.lobby:
            self.f["LeaveLobby"](self.mm, self.lobby)
            self.lobby = 0
        self.rejoin_at = time.time() + 5
        log("steam: looking for the friend's lobby again in 5 s")

    def upkeep(self):
        F, now = self.f, time.time()
        if self.peer and self.unlisted_at and now - self.unlisted_at > 15 and now - self.last_rx > 15:
            log("steam: peer left the lobby (unlisted and silent for 15 s)")
            self.peer, self.peer_name, self.unlisted_at = 0, "(none yet)", 0.0
            if not self.host and self.join_mode == "friend":
                self.leave_and_retry()
        if self.rejoin_at and now >= self.rejoin_at:
            lobby = self.find_friend_lobby()
            if lobby:
                self.rejoin_at = 0
                F["JoinLobby"](self.mm, lobby)
                log("steam: joining lobby %d ..." % lobby)
            else:
                self.rejoin_at = now + 5
        if self.host and self.lobby and now >= self.lobby_check:
            self.lobby_check = now + 30
            if F["NumMembers"](self.mm, self.lobby) < 1:
                log("steam: lobby %d is gone, creating a new one" % self.lobby)
                self.lobby, self.peer, self.peer_name = 0, 0, "(none yet)"
                F["CreateLobby"](self.mm, 1, 2)

    def on_callback(self, cb, param):
        F = self.f
        if cb == 513:  # LobbyCreated: arrives twice on real Steam (call result + broadcast)
            result, lobby = ctypes.c_int32.from_address(param).value, ctypes.c_uint64.from_address(param + 8).value
            if result == 1 and lobby and lobby != self.lobby:
                self.lobby = lobby
                F["SetLobbyData"](self.mm, lobby, LOBBY_KEY, LOBBY_VAL)
                F["SetRichPresence"](self.fr, b"connect", b"+connect_lobby %d" % lobby)
                log("steam: LOBBY %d created (friends-only); friend joins with --join %d or --join friend" % (lobby, lobby))
                if self.invite:
                    self.invite_friend(self.invite)
            elif result != 1:
                log("steam: lobby creation failed, result %d" % result)
        elif cb == 504:  # LobbyEnter
            lobby, response = ctypes.c_uint64.from_address(param).value, ctypes.c_uint32.from_address(param + 16).value
            if response != 1:
                log("steam: could not enter lobby %d (response %d)" % (lobby, response))
                if not self.host and self.join_mode == "friend":
                    self.leave_and_retry()
                return
            if not self.host:
                tag = F["GetLobbyData"](self.mm, lobby, LOBBY_KEY)
                if tag != LOBBY_VAL:
                    log("steam: lobby %d is not an fc2coop lobby; leaving" % lobby)
                    F["LeaveLobby"](self.mm, lobby)
                    return
            self.lobby = lobby
            log("steam: entered lobby %d" % lobby)
            self.pick_peer()
        elif cb == 506:  # LobbyChatUpdate: someone joined or left
            self.pick_peer()
        elif cb == 1251:  # SteamNetworkingMessagesSessionRequest: identity at offset 0
            sid = F["IdGet"](ctypes.c_void_p(param))
            if self.is_member(sid):
                ident = ctypes.create_string_buffer(ctypes.string_at(param, 136), 160)  # SteamNetworkingIdentity, 136 bytes
                self.pending_accept.append(ident)
            else:
                log("steam: ignored a session request from someone not in the lobby")
        elif cb == 1252:
            log("steam: session failed")
        elif cb == 333:  # GameLobbyJoinRequested: lobby (u64) at 0, friend (u64) at 8
            lobby = ctypes.c_uint64.from_address(param).value
            if lobby == self.lobby:
                return
            log("steam: invite or Join Game accepted (lobby), joining lobby %d" % lobby)
            F["JoinLobby"](self.mm, lobby)
        elif cb == 337:  # GameRichPresenceJoinRequested: friend (u64) at 0, connect string (char[256]) at 8
            connect = ctypes.string_at(param + 8, 256).split(b"\0", 1)[0].decode(errors="replace")
            parts = connect.split()
            if len(parts) == 2 and parts[0] == "+connect_lobby" and parts[1].isdigit():
                lobby = int(parts[1])
                if lobby != self.lobby:
                    log("steam: Join Game from the friends list, joining lobby %d" % lobby)
                    F["JoinLobby"](self.mm, lobby)
            else:
                log("steam: Join Game with an unknown connect string %r, ignored" % connect)

    def invite_friend(self, name):
        F = self.f
        for i in range(F["FriendCount"](self.fr, 4)):
            fid = F["FriendByIndex"](self.fr, i, 4)
            if F["FriendName"](self.fr, fid).decode(errors="replace").lower() == name.lower():
                ok = F["InviteUserToLobby"](self.mm, self.lobby, fid)
                log("steam: invite to %s sent: %s" % (name, ok))
                return
        log("steam: no friend named %r" % name)

    # -- transport interface
    def ready(self):
        return self.peer != 0

    def send(self, channel, data, reliable=False):
        if not self.peer:
            return
        buf = ctypes.create_string_buffer(data, len(data))
        flags = 8 | 1 if reliable else 0 | 1  # Reliable 8 / Unreliable 0, + NoNagle 1
        self.f["Send"](self.nm, self.identity(self.peer), buf, len(data), flags, channel)

    def poll(self):
        F = self.f
        F["MD_RunFrame"](self.pipe)
        self.upkeep()
        msg = CallbackMsg()
        while F["MD_Next"](self.pipe, ctypes.byref(msg)):
            if msg.callback == 703:  # SteamAPICallCompleted: call (u64), callback (i32), size (u32)
                call = ctypes.c_uint64.from_address(msg.param).value
                cb = ctypes.c_int32.from_address(msg.param + 8).value
                size = ctypes.c_uint32.from_address(msg.param + 12).value
                buf, failed = ctypes.create_string_buffer(size), ctypes.c_bool()
                if F["MD_CallResult"](self.pipe, call, buf, size, cb, ctypes.byref(failed)) and not failed.value:
                    self.on_callback(cb, ctypes.addressof(buf))
            else:
                self.on_callback(msg.callback, msg.param)
            F["MD_Free"](self.pipe)
        while self.pending_accept:
            ok = F["Accept"](self.nm, self.pending_accept.pop(0))
            log("steam: accepted session from a lobby member (%s)" % ok)
        out = []
        for ch in (0, 1, 2):
            n = F["Recv"](self.nm, ch, self.msgs, len(self.msgs))
            for i in range(n):
                m = self.msgs[i]
                data_ptr = ctypes.c_void_p.from_address(m).value
                size = ctypes.c_int32.from_address(m + 8).value  # x64: size at 8, sender identity at 16
                sender = F["IdGet"](ctypes.c_void_p(m + 16))
                if self.sender_offset is None:
                    self.sender_offset = 16
                    log("steam: first message, sender identity read at offset 16 (x64)")
                if sender == self.peer and 0 < size <= 2048:
                    self.last_rx = time.time()
                    out.append((ch, ctypes.string_at(data_ptr, size)))
                F["MsgRelease"](ctypes.c_void_p(m))
        return out

    def close(self):
        F = self.f
        self.send(1, b"bye", reliable=True)
        if self.lobby:
            F["LeaveLobby"](self.mm, self.lobby)
        F["ClearRichPresence"](self.fr)
        F["Shutdown"]()


# ---------------------------------------------------------------- relay loop
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--transport", choices=["udp", "steam"], required=True)
    ap.add_argument("--game-port", type=int, required=True, help="the probe's local port (first netstart argument)")
    ap.add_argument("--relay-port", type=int, required=True, help="port this relay listens on for the probe (127.0.0.1)")
    ap.add_argument("--udp-local", type=int, help="udp: this relay's port towards the other relay")
    ap.add_argument("--udp-peer", type=int, help="udp: the other relay's port")
    ap.add_argument("--udp-host", default="127.0.0.1", help="udp: the other relay's address")
    ap.add_argument("--steam-dll", help="steam: path to steam_api64.dll")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--host", action="store_true", help="steam: create a friends-only lobby")
    g.add_argument("--join", help="steam: lobby id, 'friend' to find a friend hosting, or 'wait' for a Steam invite / Join Game")
    ap.add_argument("--invite", help="steam host: friend's Steam name to invite once the lobby exists")
    ap.add_argument("--seconds", type=float, default=0, help="stop after this many seconds (0 = run until Ctrl+C)")
    a = ap.parse_args()

    if a.transport == "udp":
        if a.udp_local is None or a.udp_peer is None:
            sys.exit("udp transport needs --udp-local and --udp-peer")
        tr = UdpTransport(a.udp_local, a.udp_host, a.udp_peer)
    else:
        if not a.steam_dll or not (a.host or a.join):
            sys.exit("steam transport needs --steam-dll and --host or --join")
        tr = SteamTransport(a.steam_dll, a.host, a.join, a.invite)

    game = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    game.bind(("127.0.0.1", a.relay_port))
    game.setblocking(False)
    game_addr = ("127.0.0.1", a.game_port)
    log("relay up: probe 127.0.0.1:%d <-> relay 127.0.0.1:%d <-> %s" % (a.game_port, a.relay_port, a.transport))

    stats = dict(from_game=0, to_peer=0, from_peer=0, to_game=0, dropped=0)
    # game datagrams are packed into one transport message per 50 ms (channel 2: [u16 length][datagram]...), at most
    # BATCH_MAX bytes each: one Steam message per datagram (~80 a second with NPC sync) broke the Steam link after
    # 15-20 s in two runs; a relay still accepts single datagrams on channel 0
    batch, last_flush = [], time.time()
    kinds = {}  # game datagrams per kind (first 4 bytes, the probe's packet magic) since the last stats line
    last_ka = last_heard = last_stat = time.time()
    last_name = 0.0
    t0, peer_alive = time.time(), False
    try:
        while not a.seconds or time.time() - t0 < a.seconds:
            now = time.time()
            # probe -> peer
            while True:
                try:
                    d, addr = game.recvfrom(2048)
                except (BlockingIOError, ConnectionResetError):
                    break
                if addr[0] != "127.0.0.1":
                    stats["dropped"] += 1
                    continue
                stats["from_game"] += 1
                k = d[:4].decode("latin-1") if len(d) >= 4 and all(32 <= c < 127 for c in d[:4]) else "%08x" % int.from_bytes(d[:4].ljust(4, b"\x00"), "little")
                kinds[k] = kinds.get(k, 0) + 1
                if tr.ready():
                    if sum(len(x) + 2 for x in batch) + len(d) + 2 > BATCH_MAX:
                        tr.send(2, b"".join(len(x).to_bytes(2, "little") + x for x in batch))
                        stats["to_peer"] += 1
                        batch, last_flush = [], now
                    batch.append(d)
            if batch and (now - last_flush >= BATCH_S or not tr.ready()):
                if tr.ready():
                    tr.send(2, b"".join(len(x).to_bytes(2, "little") + x for x in batch))
                    stats["to_peer"] += 1
                batch, last_flush = [], now
            # peer -> probe
            for ch, d in tr.poll():
                last_heard = now
                if not peer_alive:
                    peer_alive = True
                    log("peer is talking (%s)" % tr.peer_name)
                if ch == 0 or ch == 2:
                    stats["from_peer"] += 1
                    parts = [d] if ch == 0 else []
                    i = 0
                    while ch == 2 and i + 2 <= len(d):
                        n = int.from_bytes(d[i:i + 2], "little")
                        parts.append(d[i + 2:i + 2 + n])
                        i += 2 + n
                    for x in parts:
                        try:
                            game.sendto(x, game_addr)
                            stats["to_game"] += 1
                        except OSError:
                            pass
                elif d == b"bye":
                    log("peer said goodbye")
                    peer_alive = False
            if now - last_ka >= KEEPALIVE_S and tr.ready():
                tr.send(1, b"ka", reliable=True)
                last_ka = now
            # the other player's name for the probe's on-screen notice ("Игрок <name> подключается"): NAM1 + UTF-8,
            # every 3 s while the peer is up (the probe shows it once per session)
            if peer_alive and now - last_name >= 3 and tr.peer_name and not str(tr.peer_name).startswith("("):
                last_name = now
                try:
                    game.sendto(b"NAM1" + str(tr.peer_name).encode("utf-8")[:60], game_addr)
                except OSError:
                    pass
            if peer_alive and now - last_heard > TIMEOUT_S:
                log("peer silent for %d s, dropped" % TIMEOUT_S)
                peer_alive = False
            if now - last_stat >= 5:
                last_stat = now
                log("stats " + " ".join("%s=%d" % kv for kv in stats.items()) + " peer=%s" % ("up" if peer_alive else "down") +
                    " | game datagrams by kind: " + " ".join("%s=%d" % kv for kv in sorted(kinds.items(), key=lambda x: -x[1])))
                kinds = {}
            time.sleep(0.002)
    except KeyboardInterrupt:
        pass
    finally:
        log("stopping; " + " ".join("%s=%d" % kv for kv in stats.items()))
        tr.close()
        game.close()


if __name__ == "__main__":
    main()
