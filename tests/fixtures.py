"""Synthetic ELF64 fixtures built in-memory — no compiler needed."""

import struct

PT_GNU_RELRO = 0x6474E552
PT_GNU_STACK = 0x6474E551


def build_elf(section_names, e_type=3, phdrs=(), trailing=b""):
    """Build a minimal valid ELF64-LE file.

    section_names: e.g. [".symtab", ".debug_info"]. A .shstrtab section
    is added automatically. phdrs: list of (p_type, p_flags).
    trailing: extra bytes appended after the headers (string payload).
    """
    ehsize = 64
    phentsize = 56
    shentsize = 64
    phoff = ehsize if phdrs else 0
    shoff = ehsize + phentsize * len(phdrs)

    names = [""] + list(section_names) + [".shstrtab"]
    shstrtab = b"\x00"
    name_offsets = {"" : 0}
    for name in names[1:]:
        name_offsets[name] = len(shstrtab)
        shstrtab += name.encode() + b"\x00"
    shnum = len(names)
    shstrndx = shnum - 1

    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little-endian
    struct.pack_into("<HHIQQQIHHHHHH", header, 16,
                     e_type, 0x3E, 1, 0, phoff, shoff, 0,
                     ehsize, phentsize, len(phdrs),
                     shentsize, shnum, shstrndx)

    phdr_bytes = b"".join(
        struct.pack("<IIQQQQQQ", p_type, p_flags, 0, 0, 0, 0, 0, 0)
        for p_type, p_flags in phdrs)

    strtab_off = shoff + shentsize * shnum
    sections = b""
    for name in names:
        sh_offset = strtab_off if name == ".shstrtab" else 0
        sh_size = len(shstrtab) if name == ".shstrtab" else 0
        sections += struct.pack(
            "<IIQQQQIIQQ", name_offsets[name], 0, 0, 0,
            sh_offset, sh_size, 0, 0, 0, 0)

    return bytes(header) + phdr_bytes + sections + shstrtab + trailing
