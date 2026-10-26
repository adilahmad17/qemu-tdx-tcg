#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# mktdxbios.py ELF OUT: a 64 KiB firmware image for the emulated TDX guest
# tests. A TD starts in 32-bit flat protected mode at 0xFFFFFFF0 (the last 16
# bytes of the image, mapped below 4 GiB); the stub there jumps to the test
# ELF's entry, which the generic loader (-device loader,file=ELF) places in
# RAM. For every vCPU but the first (RSI = vCPU index), it halts.
import struct
import sys

XEN_ELFNOTE_PHYS32_ENTRY = 18


def pvh_entry(data):
    """The 32-bit entry of the PVH ELF note, else the ELF entry."""
    e_entry, e_phoff = struct.unpack_from('<QQ', data, 0x18)
    e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, _, p_offset, _, _, p_filesz = struct.unpack_from('<IIQQQQ', data, off)
        if p_type != 4:                             # PT_NOTE
            continue
        pos, end = p_offset, p_offset + p_filesz
        while pos + 12 <= end:
            namesz, descsz, ntype = struct.unpack_from('<III', data, pos)
            name = data[pos + 12:pos + 12 + namesz].rstrip(b'\0')
            desc_off = pos + 12 + ((namesz + 3) & ~3)
            if name == b'Xen' and ntype == XEN_ELFNOTE_PHYS32_ENTRY:
                return int.from_bytes(data[desc_off:desc_off + descsz], 'little')
            pos = desc_off + ((descsz + 3) & ~3)
    return e_entry


elf, out = sys.argv[1], sys.argv[2]
with open(elf, 'rb') as f:
    data = f.read()
if data[:4] != b'\x7fELF' or data[4] != 2:
    sys.exit(f'{elf}: not a 64-bit ELF file')
entry = pvh_entry(data)
if entry >= 1 << 32:
    sys.exit(f'{elf}: entry {entry:#x} is not a 32-bit address')

size = 0x10000
base = 0x100000000 - size
img = bytearray(size)
code_at = base + 0xff80
# 32-bit code: test %esi,%esi; jnz 1f; jmp entry; 1: hlt; jmp 1b
code = bytearray(b'\x85\xf6')                  # test %esi,%esi
code += b'\x75\x05'                            # jnz +5 (over the jmp)
rel = (entry - (code_at + len(code) + 5)) & 0xffffffff
code += b'\xe9' + struct.pack('<I', rel)       # jmp entry
code += b'\xf4\xeb\xfd'                        # 1: hlt; jmp 1b
img[0xff80:0xff80 + len(code)] = code
# the reset vector: jmp to the stub (rel8 = 0xff80 - (0xfff0 + 2))
img[0xfff0:0xfff2] = b'\xeb' + bytes([(0xff80 - 0xfff2) & 0xff])
with open(out, 'wb') as f:
    f.write(img)
