#!/usr/bin/env python3
"""Convert an ESP32-S3 firmware .bin to a loadable ELF for Ghidra/objdump/GDB.

Parses the ESP32 app image header, extracts all segments, and writes a
minimal ELF32 (Xtensa) with both program headers and section headers so
that disassemblers and debuggers can load it directly.

Usage:
    python3 bin2elf.py app.bin firmware.elf

The input can be either:
  - A raw flash dump from esptool read_flash (starts with 0xE9 magic byte)
  - A PlatformIO build output (.pio/build/M5CoreS3/firmware.bin)

The output ELF has no symbol table (symbols are lost in the .bin), but
Ghidra's auto-analysis will recover most function boundaries.
"""
import struct
import sys
import os

EM_XTENSA = 94
ET_EXEC = 2
PT_LOAD = 1
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_WRITE = 0x1


def parse_segments(data):
    """Parse ESP32 app image and return (entry_point, [(addr, bytes), ...])."""
    if data[0] != 0xE9:
        print(f"Error: not an ESP32 app image (magic 0x{data[0]:02X}, expected 0xE9)",
              file=sys.stderr)
        sys.exit(1)

    num_segments = data[1]
    entry_point = struct.unpack_from('<I', data, 4)[0]
    segments = []
    off = 24  # extended header size

    for i in range(num_segments):
        addr = struct.unpack_from('<I', data, off)[0]
        sz = struct.unpack_from('<I', data, off + 4)[0]
        seg_data = data[off + 8:off + 8 + sz]
        segments.append((addr, seg_data))
        off += 8 + sz

    return entry_point, segments


def segment_name(addr, idx):
    """Assign a section name based on the load address."""
    if 0x42000000 <= addr < 0x43000000:
        return '.flash.text'
    elif 0x3C000000 <= addr < 0x3D000000:
        return '.flash.rodata'
    elif 0x40370000 <= addr < 0x40380000:
        return '.iram0.text'
    elif 0x3FC80000 <= addr < 0x3FD00000:
        return f'.dram0.data' if idx <= 1 else f'.dram0.bss'
    return f'.segment{idx}'


def segment_flags(addr):
    """Return (ELF p_flags, sh_flags) based on address range."""
    if addr >= 0x40000000:
        return 5, SHF_ALLOC | SHF_EXECINSTR  # R|X
    elif 0x3FC00000 <= addr < 0x3FD00000:
        return 6, SHF_ALLOC | SHF_WRITE      # R|W
    return 4, SHF_ALLOC                       # R


def build_elf(entry_point, segments):
    """Build a complete ELF32 binary with program and section headers."""
    ehdr_size = 52
    phdr_size = 32
    shdr_size = 40
    num_phdrs = len(segments)
    # Sections: one per segment + null + shstrtab
    num_shdrs = len(segments) + 2

    # Build section name string table
    shstrtab = b'\x00'  # null entry
    section_info = []
    for i, (addr, seg_data) in enumerate(segments):
        name = segment_name(addr, i)
        name_offset = len(shstrtab)
        shstrtab += name.encode() + b'\x00'
        section_info.append((name, name_offset))
    shstrtab_name_offset = len(shstrtab)
    shstrtab += b'.shstrtab\x00'

    # Layout: ehdr | phdrs | padding | segment data | shstrtab | shdrs
    headers_size = ehdr_size + (phdr_size * num_phdrs)
    data_start = (headers_size + 0xF) & ~0xF  # align to 16 bytes

    # Calculate segment data offsets
    file_offset = data_start
    seg_offsets = []
    for addr, seg_data in segments:
        seg_offsets.append(file_offset)
        file_offset += len(seg_data)

    # shstrtab offset
    shstrtab_offset = file_offset
    file_offset += len(shstrtab)

    # Section headers at the end
    shdr_offset = (file_offset + 3) & ~3  # align to 4

    # ELF header
    elf = bytearray()
    elf += b'\x7fELF'
    elf += struct.pack('5B', 1, 1, 1, 0, 0)  # 32-bit, LE, current, SYSV
    elf += b'\x00' * 7
    elf += struct.pack('<HHIIIIIHHHHHH',
                       ET_EXEC, EM_XTENSA, 1,
                       entry_point,
                       ehdr_size,          # e_phoff
                       shdr_offset,        # e_shoff
                       0x00000300,         # e_flags (Xtensa)
                       ehdr_size,          # e_ehsize
                       phdr_size,          # e_phentsize
                       num_phdrs,          # e_phnum
                       shdr_size,          # e_shentsize
                       num_shdrs,          # e_shnum
                       num_shdrs - 1)      # e_shstrndx (last section)

    # Program headers
    for i, (addr, seg_data) in enumerate(segments):
        pflags, _ = segment_flags(addr)
        elf += struct.pack('<IIIIIIII',
                           PT_LOAD,
                           seg_offsets[i],
                           addr, addr,
                           len(seg_data), len(seg_data),
                           pflags, 4)

    # Pad to data_start
    elf += b'\x00' * (data_start - len(elf))

    # Segment data
    for addr, seg_data in segments:
        elf += seg_data

    # String table
    elf += shstrtab

    # Pad to shdr_offset
    elf += b'\x00' * (shdr_offset - len(elf))

    # Section headers
    # [0] NULL
    elf += b'\x00' * shdr_size

    # [1..N] segment sections
    for i, (addr, seg_data) in enumerate(segments):
        _, shflags = segment_flags(addr)
        elf += struct.pack('<IIIIIIIIII',
                           section_info[i][1],  # sh_name
                           SHT_PROGBITS,        # sh_type
                           shflags,             # sh_flags
                           addr,                # sh_addr
                           seg_offsets[i],       # sh_offset
                           len(seg_data),        # sh_size
                           0, 0,                # sh_link, sh_info
                           4,                   # sh_addralign
                           0)                   # sh_entsize

    # [N+1] .shstrtab
    elf += struct.pack('<IIIIIIIIII',
                       shstrtab_name_offset,
                       SHT_STRTAB, 0, 0,
                       shstrtab_offset, len(shstrtab),
                       0, 0, 1, 0)

    return bytes(elf)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.bin> <output.elf>")
        print(f"\nConverts an ESP32-S3 firmware .bin to ELF for disassembly.")
        print(f"The input must start with the ESP32 magic byte 0xE9.")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    data = open(input_path, 'rb').read()
    entry_point, segments = parse_segments(data)

    print(f"ESP32-S3 firmware: {len(data)} bytes, {len(segments)} segments")
    print(f"Entry point: 0x{entry_point:08X}")
    for i, (addr, seg_data) in enumerate(segments):
        name = segment_name(addr, i)
        print(f"  {name}: 0x{addr:08X} ({len(seg_data)} bytes)")

    elf_data = build_elf(entry_point, segments)
    open(output_path, 'wb').write(elf_data)
    print(f"\nELF written: {output_path} ({len(elf_data)} bytes)")
    print(f"Load in Ghidra (Xtensa:LE:32:default) or use xtensa-esp32s3-elf-objdump -d")


if __name__ == '__main__':
    main()
