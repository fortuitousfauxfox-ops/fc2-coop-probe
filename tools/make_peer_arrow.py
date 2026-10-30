# Builds a patch.fat/patch.dat pair with a yellow copy of the player's map arrow for the co-op probe:
# - graphics\objects\mapcompass\final_objective_iconz.xbt: the map icon atlas with green turned yellow (DXT5: in every
#   block the red of both colour endpoints is raised to their green, so green -> yellow while white and grey stay);
# - graphics\_materials\madeslongchamps-m-1604200830886768.xbm: the player arrow's material on that atlas;
# - graphics\objects\mapcompass\icon_playerpoy.xbg: the player arrow's model (icon_playerpos.xbg) with that material.
#   (The yellow underground mission arrow is a white atlas region under a (2, 1.83, 0) tint; the player arrow's region
#   is green, so giving it that material left it green.) Every new path has the length of the one it replaces;
# - generated\entitylibrarypatchoverride.fcb: the existing override library plus a 28th root group "coop" with one
#   archetype "PeerPosition" (spawned as coop.PeerPosition), cloned from gadgets.ObjectiveIcons.PlayerPosition with the
#   model / descriptor paths and their hashes changed. The group is appended at the end of the file (the root's
#   children run to the end), so nothing else moves; the root child count and the header totals are updated.
# Usage: python -I make_peer_arrow.py <Data_Win32 of a copy> <out dir>   (writes <out>/patch.fat and <out>/patch.dat)
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fat_extract as fx  # noqa: E402
import fcb  # noqa: E402

BS = chr(92)
root_dir, out_dir = sys.argv[1], sys.argv[2]
# the stock patch pair to start from (default: the copy's own; must not already hold the coop group)
patch_dir = sys.argv[3] if len(sys.argv) > 3 else root_dir
patch_fat = os.path.join(patch_dir, 'patch.fat')
worlds_fat = os.path.join(root_dir, 'worlds', 'worlds.fat')
LIB = 'generated' + BS + 'entitylibrarypatchoverride.fcb'
OLD_XBG = 'graphics' + BS + 'objects' + BS + 'mapcompass' + BS + 'icon_playerpos.xbg'
NEW_XBG = 'graphics' + BS + 'objects' + BS + 'mapcompass' + BS + 'icon_playerpoy.xbg'
OLD_XML = OLD_XBG[:-4] + '.xml'
NEW_XML = NEW_XBG[:-4] + '.xml'
crc = lambda s: zlib.crc32(s.lower().encode()) & 0xFFFFFFFF

# 1. atlas, material, model
OLD_XBT = 'graphics' + BS + 'objects' + BS + 'mapcompass' + BS + 'final_objective_icons.xbt'
NEW_XBT = OLD_XBT.replace('icons.xbt', 'iconz.xbt')
xbt = fx.read_file(worlds_fat, OLD_XBT)
dds = xbt.index(b'DDS ')
h, w = struct.unpack_from('<II', xbt, dds + 12)
mips = struct.unpack_from('<I', xbt, dds + 28)[0]
assert xbt[dds + 84:dds + 88] == b'DXT5', xbt[dds + 84:dds + 88]
new_xbt = bytearray(xbt.replace(OLD_XBT.encode(), NEW_XBT.encode()))
pos, turned = dds + 128, 0
for m in range(mips):
    bw, bh = max(1, ((w >> m) + 3) >> 2), max(1, ((h >> m) + 3) >> 2)
    for k in range(bw * bh):
        b = pos + 16 * k + 8          # colour part of the block (after 8 bytes of alpha)
        for e in (b, b + 2):
            c = new_xbt[e] | new_xbt[e + 1] << 8
            r, g, bl = c >> 11, (c >> 5) & 63, c & 31
            if (g >> 1) > r:
                c = (g >> 1) << 11 | g << 5 | bl
                new_xbt[e], new_xbt[e + 1] = c & 255, c >> 8
                turned += 1
    pos += 16 * bw * bh
assert pos == len(new_xbt), (pos, len(new_xbt))
print('atlas: %dx%d, %d mips, %d endpoints turned yellow' % (w, h, mips, turned))
xbg = fx.read_file(worlds_fat, OLD_XBG)
m_old = xbg[xbg.index(b'GRAPHICS' + BS.encode() + b'_MATERIALS'):].split(b'\0')[0]
assert m_old.endswith(b'7.xbm') and xbg.count(m_old) == 1, m_old
m_new = m_old[:-5] + b'8.xbm'
NEW_XBM = m_new.decode().lower()
xbm = fx.read_file(worlds_fat, m_old.decode().lower())
assert xbm.count(OLD_XBT.encode()) == 1
new_xbm = xbm.replace(OLD_XBT.encode(), NEW_XBT.encode())
new_xbg = xbg.replace(m_old, m_new)
for path in (NEW_XBT, NEW_XBM, NEW_XBG):
    assert fx.read_file(worlds_fat, path) is None, path + ' exists already'
print('material:', m_old.decode(), '->', m_new.decode())

# 2. the library: clone the archetype
lib = fx.read_file(patch_fat, LIB)
d, (ver, flags, tobj, tval), root = fcb.load_bytes(lib) if hasattr(fcb, 'load_bytes') else (None, None, None)
NAME = 0xFE11D138
gadgets = next(c for c in root.children if dict((h, v) for h, v in c.values).get(NAME) == b'gadgets\0')
arch = next(c for c in gadgets.children if dict((h, v) for h, v in c.values).get(NAME) == b'ObjectiveIcons.PlayerPosition\0')


def has_refs(o):
    return o.ref is not None or any(not isinstance(v, bytes) for h, v in o.values) or any(has_refs(c) for c in o.children)


assert not has_refs(arch), 'the archetype uses back references'
reps = [(OLD_XBG.encode(), NEW_XBG.encode()), (b'graphics' + BS.encode() + b'Objects' + BS.encode() + b'MapCompass' + BS.encode() + b'Icon_PlayerPos.xbg',
                                           b'graphics' + BS.encode() + b'Objects' + BS.encode() + b'MapCompass' + BS.encode() + b'Icon_PlayerPoy.xbg'),
        (OLD_XML.encode(), NEW_XML.encode())]
hreps = {struct.pack('<I', crc(OLD_XBG)): struct.pack('<I', crc(NEW_XBG)), struct.pack('<I', crc(OLD_XML)): struct.pack('<I', crc(NEW_XML))}
HIDNAME, DISID = 0xB9295CC7, 0x052A103F
changed = []


def fix_values(o):
    vals = []
    for h, v in o.values:
        nv = v
        if h == NAME and v == b'ObjectiveIcons.PlayerPosition\0':
            nv = b'PeerPosition\0'
        elif h == HIDNAME and v == b'gadgets.ObjectiveIcons.PlayerPosition\0':
            nv = b'coop.PeerPosition\0'
        elif h == DISID and len(v) == 8:
            nv = struct.pack('<Q', 0x434F4F5000000001)   # an id no stock archetype uses
        else:
            for a, b in reps:
                nv = nv.replace(a, b)
            if len(nv) == 4 and nv in hreps:
                nv = hreps[nv]
        if nv != v:
            changed.append((hex(h), v[:60], nv[:60]))
        vals.append((h, nv))
    o.values = vals
    for c in o.children:
        fix_values(c)


fix_values(arch)
arch.hash = zlib.crc32(b'coop.PeerPosition') & 0xFFFFFFFF   # its own object id, not the original's 256A1FF9
for c in changed:
    print('changed', *c)


def packed(n):
    return bytes([n]) if n < 0xFE else b'\xff' + struct.pack('<I', n)


def write(o):
    out = bytearray(packed(len(o.children)) + struct.pack('<I', o.hash) + packed(len(o.values)))
    for h, v in o.values:
        out += struct.pack('<I', h) + packed(len(v)) + v
    for c in o.children:
        out += write(c)
    return out


group_vals = [(h, (b'coop\0' if h == NAME else v)) for h, v in gadgets.values]
group = bytearray(packed(1) + struct.pack('<I', gadgets.hash) + packed(len(group_vals)))
for h, v in group_vals:
    group += struct.pack('<I', h) + packed(len(v)) + v
group += write(arch)
objs, vals = fcb.count(arch)
assert lib[16] == len(root.children) < 0xFD, lib[16]
new_lib = bytearray(lib)
new_lib[16] += 1
struct.pack_into('<II', new_lib, 8, tobj + objs + 1, tval + vals + len(group_vals))
new_lib += group
# the result must parse back to the end, with the new group last
d2, hdr2, root2 = fcb.load_bytes(bytes(new_lib))
assert root2.end == len(new_lib) and len(root2.children) == len(root.children) + 1
assert fcb.count(root2) == (hdr2[2] + 1, hdr2[3]), (fcb.count(root2), hdr2)
print('library:', len(lib), '->', len(new_lib), 'bytes; objects +%d, values +%d' % (objs + 1, vals + len(group_vals)))

# 3. the archive: stock entries, the library replaced, the model added; data appended to a copy of patch.dat
fat = open(patch_fat, 'rb').read()
n = struct.unpack_from('<I', fat, 12)[0]
entries = {}
for i in range(n):
    h, a, b, c = struct.unpack_from('<IIII', fat, 16 + i * 16)
    entries[h] = (a, b, c)
os.makedirs(out_dir, exist_ok=True)
dat_out = os.path.join(out_dir, 'patch.dat')
with open(os.path.join(patch_dir, 'patch.dat'), 'rb') as src, open(dat_out, 'wb') as dst:
    while True:
        chunk = src.read(1 << 20)
        if not chunk:
            break
        dst.write(chunk)
    for path, data in ((LIB, bytes(new_lib)), (NEW_XBG, new_xbg), (NEW_XBM, new_xbm), (NEW_XBT, bytes(new_xbt))):
        off = dst.tell()
        dst.write(data)
        entries[crc(path)] = (0, len(data) | ((off & 3) << 30), off >> 2)
        print('archive:', path, len(data), 'bytes at', off)
with open(os.path.join(out_dir, 'patch.fat'), 'wb') as f:
    f.write(fat[:12] + struct.pack('<I', len(entries)))
    for h in sorted(entries):
        f.write(struct.pack('<IIII', h, *entries[h]))
    f.write(fat[16 + n * 16:])
# read back through the extractor
assert fx.read_file(os.path.join(out_dir, 'patch.fat'), LIB) == bytes(new_lib)
assert fx.read_file(os.path.join(out_dir, 'patch.fat'), NEW_XBG) == new_xbg
print('done:', out_dir)
