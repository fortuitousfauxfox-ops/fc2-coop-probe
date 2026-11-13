# Builds a patch pair whose entity library has one more archetype, coop.PawnPlayerAI: a copy of
# player.MainCharacter.PawnPlayerNetwork plus the CFCXAIComponent of player.MainCharacter.PawnPlayer (with the player's
# CPawnAgent / PlayerBrain). Target selection and stim handling of the NPC AI read component FE4090 (= that component) of
# the other entity, and the network archetype does not have it, so a host's NPCs could not perceive the avatar.
# The archetype is appended as the last child of the last root group ("coop", see make_peer_arrow.py), which ends at EOF, so
# nothing moves and back references (absolute offsets) stay valid.
# Usage: python -I make_avatar_ai.py <Data_Win32 of a copy> <out dir> [--stealth]
#   reads that copy's patch.fat/.dat, writes <out>/patch.fat and <out>/patch.dat; --stealth also copies CStealthComponent
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fat_extract as fx  # noqa: E402
import fcb  # noqa: E402

BS = chr(92)
root_dir, out_dir = sys.argv[1], sys.argv[2]
extra = ['CStealthComponent'] if '--stealth' in sys.argv[3:] else []
patch_fat = os.path.join(root_dir, 'patch.fat')
LIB = 'generated' + BS + 'entitylibrarypatchoverride.fcb'
NAME, HIDNAME, DISID = 0xFE11D138, 0xB9295CC7, 0x052A103F
GROUP, NEW = b'coop', b'PawnPlayerAI'
FULL = GROUP + b'.' + NEW
crc = lambda b: zlib.crc32(b) & 0xFFFFFFFF

lib = fx.read_file(patch_fat, LIB)
_, (ver, flags, tobj, tval), root = fcb.load_bytes(lib)


def val(o, h):
    return dict((k, v) for k, v in o.values).get(h)


def find_arch(name):
    for g in root.children:
        for a in g.children:
            if (val(g, NAME) or b'').rstrip(b'\0') + b'.' + (val(a, NAME) or b'').rstrip(b'\0') == name:
                return a
    raise SystemExit('no archetype ' + name.decode())


group = root.children[-1]
assert val(group, NAME) == GROUP + b'\0' and group.end == len(lib), (val(group, NAME), group.end, len(lib))
assert not any(val(a, NAME) == NEW + b'\0' for a in group.children), 'already built'
net = find_arch(b'player.MainCharacter.PawnPlayerNetwork')
# --ai-from=<archetype>: whose CFCXAIComponent to copy (default the player's)
src = next((x.split('=', 1)[1] for x in sys.argv[3:] if x.startswith('--ai-from=')), 'player.MainCharacter.PawnPlayer')
ply = find_arch(src.encode())


def comps(o):
    # the object below an archetype that holds the components (the one with a CPawn child)
    if any(c.hash == crc(b'CPawn') for c in o.children):
        return o
    for c in o.children:
        r = comps(c)
        if r is not None:
            return r
    return None


net_c, ply_c = comps(net), comps(ply)
add = [c for c in ply_c.children if c.hash in [crc(n.encode()) for n in ['CFCXAIComponent'] + extra]]
assert len(add) == 1 + len(extra), len(add)
print('network archetype: %d components; added: %s' % (len(net_c.children), [hex(c.hash) for c in add]))


def packed(n):
    return bytes([n]) if n < 0xFE else b'\xff' + struct.pack('<I', n)


def write(o):
    if o.ref is not None:
        return bytearray(b'\xfe' + struct.pack('<I', o.ref))
    out = bytearray(packed(len(o.children)) + struct.pack('<I', o.hash) + packed(len(o.values)))
    for h, v in o.values:
        out += struct.pack('<I', h)
        out += b'\xfe' + struct.pack('<I', v[1]) if not isinstance(v, bytes) else packed(len(v)) + v
    for c in o.children:
        out += write(c)
    return out


net.values = [(h, NEW + b'\0' if h == NAME else v) for h, v in net.values]
# hidName and disEntityId are in the archetype's "Entity" child; a duplicate id makes the spawn return an invalid id
ent = net.children[0]
vals = []
for h, v in ent.values:
    if h == HIDNAME:
        v = FULL + b'\0'
    elif h == DISID and isinstance(v, bytes) and len(v) == 8:
        v = struct.pack('<Q', 0x434F4F5000000002)   # an id no stock archetype uses (PeerPosition is ...01)
    vals.append((h, v))
ent.values = vals
net.hash = crc(FULL)
net_c.children = net_c.children + add
# CPawn.bIsAI = 1: with 0 the agent's init takes the global "player agent" pointer [11652108], and the AI then reads
# components only the real player has (crash at Dunia+9635EF).
BISAI = crc(b'bIsAI')
pawn = next(c for c in net_c.children if c.hash == crc(b'CPawn'))
print('CPawn bIsAI was', val(pawn, BISAI))
pawn.values = [(h, v) for h, v in pawn.values if h != BISAI] + [(BISAI, b'')]
blob = write(net)
objs, nv = fcb.count(net)

assert lib[group.start] == len(group.children) < 0xFD
new_lib = bytearray(lib)
new_lib[group.start] += 1
struct.pack_into('<II', new_lib, 8, tobj + objs, tval + nv)
new_lib += blob
_, hdr2, root2 = fcb.load_bytes(bytes(new_lib))
assert root2.end == len(new_lib) and len(root2.children) == len(root.children), root2.end
assert fcb.count(root2) == (hdr2[2] + 1, hdr2[3]), (fcb.count(root2), hdr2)
print('library: %d -> %d bytes; objects +%d, values +%d' % (len(lib), len(new_lib), objs, nv))

fat = open(patch_fat, 'rb').read()
n = struct.unpack_from('<I', fat, 12)[0]
entries = {}
for i in range(n):
    h, a, b, c = struct.unpack_from('<IIII', fat, 16 + i * 16)
    entries[h] = (a, b, c)
os.makedirs(out_dir, exist_ok=True)
with open(os.path.join(root_dir, 'patch.dat'), 'rb') as src, open(os.path.join(out_dir, 'patch.dat'), 'wb') as dst:
    while True:
        chunk = src.read(1 << 20)
        if not chunk:
            break
        dst.write(chunk)
    while dst.tell() % 4:
        dst.write(b'\0')
    off = dst.tell()
    dst.write(new_lib)
entries[crc(LIB.lower().encode())] = (0, len(new_lib) | ((off & 3) << 30), off >> 2)
with open(os.path.join(out_dir, 'patch.fat'), 'wb') as f:
    f.write(fat[:12] + struct.pack('<I', len(entries)))
    for h in sorted(entries):
        f.write(struct.pack('<IIII', h, *entries[h]))
    f.write(fat[16 + n * 16:])
back = fx.read_file(os.path.join(out_dir, 'patch.fat'), LIB)
assert back == bytes(new_lib)
print('written', out_dir, 'entries', len(entries))
