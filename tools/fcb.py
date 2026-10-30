# Reader for Dunia binary object files ('nbCF' v2, e.g. generated\entitylibrarypatchoverride.fcb).
# Layout as read here: header 'nbCF', u16 version, u16 flags, u32 total objects, u32 total values; then the root
# object. Object: packed child count (or 0xFE + u32 offset of an identical object written earlier), u32 name hash,
# packed value count, values {u32 hash, packed size, data}, then the children. Packed: one byte < 0xFE, or 0xFF + u32.
import struct
import sys


class Obj:
    __slots__ = ('start', 'end', 'hash', 'values', 'children', 'ref')


def packed(d, p):
    v = d[p]
    if v == 0xFF:
        return struct.unpack_from('<I', d, p + 1)[0], p + 5
    return v, p + 1


def read_obj(d, p, depth=0):
    o = Obj()
    o.start = p
    o.ref = None
    if d[p] == 0xFE:
        o.ref = struct.unpack_from('<I', d, p + 1)[0]
        o.end = p + 5
        o.hash, o.values, o.children = None, [], []
        return o
    n, p = packed(d, p)
    o.hash = struct.unpack_from('<I', d, p)[0]
    p += 4
    nv, p = packed(d, p)
    o.values = []
    for _ in range(nv):
        h = struct.unpack_from('<I', d, p)[0]
        p += 4
        if d[p] == 0xFE:
            o.values.append((h, ('ref', struct.unpack_from('<I', d, p + 1)[0])))
            p += 5
            continue
        size, p = packed(d, p)
        o.values.append((h, d[p:p + size]))
        p += size
    o.children = []
    for _ in range(n):
        c = read_obj(d, p, depth + 1)
        o.children.append(c)
        p = c.end
    o.end = p
    return o


def load(fn):
    d = open(fn, 'rb').read()
    assert d[:4] == b'nbCF', d[:4]
    ver, flags, tobj, tval = struct.unpack_from('<HHII', d, 4)
    root = read_obj(d, 16)
    return d, (ver, flags, tobj, tval), root


def count(o):
    objs, vals = 1, len(o.values)
    for c in o.children:
        a, b = count(c)
        objs += a
        vals += b
    return objs, vals


if __name__ == '__main__':
    d, hdr, root = load(sys.argv[1])
    print('header', hdr, 'root ends at', root.end, 'of', len(d), 'root children', len(root.children), 'root hash', hex(root.hash))
    print('counted (objects, values)', count(root))
    for c in root.children[:40]:
        name = next((v for h, v in c.values if h == 0xFE11D138 and isinstance(v, bytes)), b'')
        print(hex(c.start), hex(c.hash or 0), 'children', len(c.children), name[:40])


def load_bytes(d):
    assert d[:4] == b'nbCF', d[:4]
    ver, flags, tobj, tval = struct.unpack_from('<HHII', d, 4)
    return d, (ver, flags, tobj, tval), read_obj(d, 16)
