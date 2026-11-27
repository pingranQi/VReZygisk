#!/usr/bin/env python3
"""Create malformed ELF section/hash samples from a trusted host ELF."""
import pathlib
import struct
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: mutate_elf.py <input-elf> <output-dir>", file=sys.stderr)
        return 2

    source = pathlib.Path(sys.argv[1]).read_bytes()
    output = pathlib.Path(sys.argv[2])
    output.mkdir(parents=True, exist_ok=True)

    if source[:4] != b"\x7fELF" or source[4] != 2 or source[5] != 1:
        raise SystemExit("test input must be ELF64 little-endian")

    e_shoff = struct.unpack_from("<Q", source, 40)[0]
    e_shentsize, e_shnum = struct.unpack_from("<HH", source, 58)
    if e_shentsize != 64 or e_shnum == 0 or e_shoff + e_shentsize * e_shnum > len(source):
        raise SystemExit("test input has invalid section table")

    gnu_hash = None
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        sh_type = struct.unpack_from("<I", source, off + 4)[0]
        if sh_type == 0x6FFFFFF6:
            gnu_hash = (off, struct.unpack_from("<Q", source, off + 24)[0],
                        struct.unpack_from("<Q", source, off + 32)[0])
            break
    if gnu_hash is None:
        raise SystemExit("test input has no SHT_GNU_HASH section")

    # Regression VR-06: out-of-file section offset must be rejected before d_buf[0].
    bad_section = bytearray(source)
    shdr_off, _, sh_size = gnu_hash
    struct.pack_into("<Q", bad_section, shdr_off + 24, 0x7FFFFFFF)
    struct.pack_into("<Q", bad_section, shdr_off + 32, max(sh_size, 32))
    (output / "gnu_hash_section_oob.elf").write_bytes(bad_section)

    # Regression VR-07: bucket index must be checked before reading the chain.
    bad_chain = bytearray(source)
    _, hash_off, hash_size = gnu_hash
    if hash_off + hash_size > len(bad_chain) or hash_size < 32:
        raise SystemExit("GNU hash section too small for mutation")
    nbuckets, symoffset, bloom_size, shift2 = struct.unpack_from("<IIII", bad_chain, hash_off)
    if bloom_size == 0:
        bloom_size = 1
        struct.pack_into("<I", bad_chain, hash_off + 8, bloom_size)
    bucket_off = hash_off + 16 + bloom_size * 8
    if bucket_off + 4 > hash_off + hash_size:
        raise SystemExit("GNU hash bucket outside section")
    struct.pack_into("<I", bad_chain, hash_off, 1)
    struct.pack_into("<I", bad_chain, bucket_off, 0x40000000)
    (output / "gnu_hash_chain_oob.elf").write_bytes(bad_chain)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
