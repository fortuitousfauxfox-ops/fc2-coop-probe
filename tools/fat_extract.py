# Extracts files from a FAT2 v5 archive (Far Cry 2). Index: 'FAT2' 5 flags count, then 16-byte entries
# {crc32(lowercase path with backslashes), a, b, c}: uncompressed size a >> 2, scheme a & 3 (0 stored, 1 LZO1X),
# stored size b & 0x3FFFFFFF, byte offset (c << 2) | (b >> 30) - worked out from consecutive entries in worlds.fat.
# Usage: python -I fat_extract.py <archive.fat> <out dir> <path> [path...]
import os
import struct
import sys
import zlib


def lzo1x_decompress(src, out_len):
    """Plain LZO1X-1 decompressor (the format liblzo's lzo1x_decompress reads)."""
    dst = bytearray()
    ip = 0

    def run_len(t, bits):
        nonlocal ip
        if t == 0:
            t = (1 << bits) - 1
            while src[ip] == 0:
                t += 255
                ip += 1
            t += src[ip]
            ip += 1
        return t

    def copy_match(dist, n):
        p = len(dst) - dist
        if p < 0:
            raise ValueError('lzo: match before start')
        for k in range(n):
            dst.append(dst[p + k])

    t = src[ip]
    state = 0
    if t > 17:
        ip += 1
        t -= 17
        dst += src[ip:ip + t]
        ip += t
        state = 4 if t >= 4 else t
    else:
        state = 0
    while True:
        t = src[ip]
        ip += 1
        if t >= 64:
            dist = ((t >> 2) & 7) + (src[ip] << 3) + 1
            ip += 1
            n = (t >> 5) - 1 + 2
        elif t >= 32:
            n = run_len(t & 31, 5) + 2
            v = src[ip] | (src[ip + 1] << 8)
            ip += 2
            dist = (v >> 2) + 1
            t = v
        elif t >= 16:
            n = run_len(t & 7, 3) + 2
            v = src[ip] | (src[ip + 1] << 8)
            ip += 2
            dist = ((t & 8) << 11) + (v >> 2)
            if dist == 0:
                break   # end of stream
            dist += 0x4000
            t = v
        else:
            if state == 0:
                n = run_len(t, 4) + 3
                dst += src[ip:ip + n]
                ip += n
                state = 4
                continue
            if state == 4:
                dist = (t >> 2) + (src[ip] << 2) + 2049
                ip += 1
                n = 3
            else:
                dist = (t >> 2) + (src[ip] << 2) + 1
                ip += 1
                n = 2
        copy_match(dist, n)
        lit = t & 3
        dst += src[ip:ip + lit]
        ip += lit
        state = lit
    if len(dst) != out_len:
        raise ValueError('lzo: %d bytes, expected %d' % (len(dst), out_len))
    return bytes(dst)


def read_index(fat):
    d = open(fat, 'rb').read()
    n = struct.unpack_from('<I', d, 12)[0]
    idx = {}
    for i in range(n):
        h, a, b, c = struct.unpack_from('<IIII', d, 16 + i * 16)
        idx[h] = (a >> 2, a & 3, b & 0x3FFFFFFF, (c << 2) | (b >> 30))
    return idx


def read_file(fat, path, idx=None):
    idx = idx or read_index(fat)
    e = idx.get(zlib.crc32(path.lower().encode()) & 0xFFFFFFFF)
    if not e:
        return None
    usize, scheme, size, off = e
    with open(fat[:-4] + '.dat', 'rb') as f:
        f.seek(off)
        data = f.read(size)
    if scheme == 1:
        data = lzo1x_decompress(data, usize)
    elif scheme != 0:
        raise ValueError('compression scheme %d' % scheme)
    return data


if __name__ == '__main__':
    fat, out = sys.argv[1], sys.argv[2]
    idx = read_index(fat)
    os.makedirs(out, exist_ok=True)
    for path in sys.argv[3:]:
        data = read_file(fat, path, idx)
        if data is None:
            print('missing', path)
            continue
        name = os.path.join(out, path.replace('\\', '_'))
        open(name, 'wb').write(data)
        print(path, len(data), 'bytes ->', name)
