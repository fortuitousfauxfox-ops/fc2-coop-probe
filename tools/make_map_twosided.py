# Builds a patch pair that makes the hand map's materials two-sided, so the other player's avatar shows the map from
# both sides (the map is a first-person model: from the front of the avatar it was see-through).
# The three materials of graphics\objects\mapcompass\map.xbg (MAPTOP, MAPCONTOUR, MAPCONTOURALPHA, shader Generic) get
# the switch TwoSided = 1, written like the vegetation materials do: in the section of one-byte switches (the one with
# AlphaTestEnabled) an entry {u32 name length without the NUL, name, NUL, u32 value}; that section's count +1; the sizes in the
# file header (+0x14) and the LTMD chunk (+0x28, +0x2C) grow by the entry size.
# Usage: python -I make_map_twosided.py <Data_Win32 of a copy> <out dir>   (reads that copy's patch.fat/.dat, writes
# <out>/patch.fat and <out>/patch.dat: the same archive plus the three materials)
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fat_extract as fx  # noqa: E402

BS = chr(92)
root_dir, out_dir = sys.argv[1], sys.argv[2]
patch_fat = os.path.join(root_dir, 'patch.fat')
worlds_fat = os.path.join(root_dir, 'worlds', 'worlds.fat')
crc = lambda s: zlib.crc32(s.lower().encode()) & 0xFFFFFFFF
MATS = ['graphics' + BS + '_materials' + BS + 'jfcarrier2-m-' + n + '.xbm' for n in ('1708200746783136', '0307200865578952', '0307200863141764')]


def two_sided(x):
    i = x.index(b'AlphaTestEnabled\0')
    # walk back to the section count: entries {u32 len, name, NUL, u32 value}; the count is the u32 before the first entry
    p = i - 4                          # length field of AlphaTestEnabled
    assert struct.unpack_from('<I', x, p)[0] == 16
    cnt_at = p - 4
    cnt = struct.unpack_from('<I', x, cnt_at)[0]
    assert 1 <= cnt < 64, cnt
    q = cnt_at + 4
    for _ in range(cnt):               # check the section really is {len, name, NUL, u32}
        n = struct.unpack_from('<I', x, q)[0]
        assert x[q + 4 + n] == 0, (q, n)
        q += 4 + n + 1 + 4
    assert b'TwoSided\0' not in x
    entry = struct.pack('<I', 8) + b'TwoSided\0' + struct.pack('<I', 1)
    y = bytearray(x[:cnt_at] + struct.pack('<I', cnt + 1) + x[cnt_at + 4:q] + entry + x[q:])
    for off in (0x14, 0x28, 0x2C):
        struct.pack_into('<I', y, off, struct.unpack_from('<I', y, off)[0] + len(entry))
    assert y[0x20:0x24] == b'LTMD'
    return bytes(y)


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
    for path in MATS:
        assert crc(path) not in entries, path + ' already in the patch'
        new = two_sided(fx.read_file(worlds_fat, path))
        while dst.tell() & 3:
            dst.write(b'\0')
        off = dst.tell()
        dst.write(new)
        entries[crc(path)] = (0, len(new) | ((off & 3) << 30), off >> 2)
        print('archive:', path, len(new), 'bytes at', off)
with open(os.path.join(out_dir, 'patch.fat'), 'wb') as f:
    f.write(fat[:12] + struct.pack('<I', len(entries)))
    for h in sorted(entries):
        f.write(struct.pack('<IIII', h, *entries[h]))
    f.write(fat[16 + n * 16:])
for path in MATS:
    assert b'TwoSided' in fx.read_file(os.path.join(out_dir, 'patch.fat'), path)
print('done:', out_dir)
