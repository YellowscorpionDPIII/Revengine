"""Minimal ELF64 little-endian parser, stdlib only.

Reads just enough to answer the scorer's questions: section names,
program header types, and machine/file type. Returns best-effort results
and never raises on malformed input — callers treat missing data as
"unknown", not as "absent".
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

ET_EXEC = 2
ET_DYN = 3

PT_GNU_RELRO = 0x6474E552
PT_GNU_STACK = 0x6474E551

PF_X = 0x1


@dataclass
class ElfInfo:
    is_elf: bool = False
    is_64bit: bool = False
    is_little_endian: bool = False
    e_type: int | None = None
    sections: list[str] = field(default_factory=list)
    program_types: list[int] = field(default_factory=list)
    gnu_stack_executable: bool | None = None  # None = unknown
    has_gnu_relro: bool = False

    @property
    def is_pie(self) -> bool | None:
        if self.e_type is None:
            return None
        return self.e_type == ET_DYN

    def has_section(self, name: str) -> bool:
        return name in self.sections

    def has_debug_sections(self) -> bool:
        return any(s.startswith(".debug") or s.startswith(".zdebug")
                   for s in self.sections)


def parse_elf(data: bytes) -> ElfInfo:
    info = ElfInfo()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return info
    info.is_elf = True
    ei_class = data[4]
    ei_data = data[5]
    info.is_64bit = ei_class == 2
    info.is_little_endian = ei_data == 1
    if not info.is_64bit or not info.is_little_endian:
        return info  # 32-bit / big-endian: recognised, not parsed further.

    try:
        (e_type, _machine, _ver, _entry, e_phoff, e_shoff, _flags,
         _ehsize, phentsize, phnum, shentsize, shnum,
         shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    except struct.error:
        return info
    info.e_type = e_type

    # Program headers (56 bytes each for ELF64).
    if e_phoff and phentsize >= 56 and phnum:
        for i in range(phnum):
            off = e_phoff + i * phentsize
            if off + 56 > len(data):
                break
            try:
                p_type, p_flags = struct.unpack_from("<II", data, off)
            except struct.error:
                break
            info.program_types.append(p_type)
            if p_type == PT_GNU_RELRO:
                info.has_gnu_relro = True
            elif p_type == PT_GNU_STACK:
                info.gnu_stack_executable = bool(p_flags & PF_X)

    # Section headers (64 bytes each) + section-name string table.
    if e_shoff and shentsize >= 64 and shnum and shstrndx < shnum:
        headers = []
        for i in range(shnum):
            off = e_shoff + i * shentsize
            if off + 64 > len(data):
                break
            try:
                sh_name, _t, _f, _a, sh_offset, sh_size = struct.unpack_from(
                    "<IIQQQQ", data, off)
            except struct.error:
                break
            headers.append((sh_name, sh_offset, sh_size))
        if headers and shstrndx < len(headers):
            _, str_off, str_size = headers[shstrndx]
            strtab = data[str_off:str_off + str_size]
            for sh_name, _, _ in headers:
                end = strtab.find(b"\x00", sh_name)
                if end == -1:
                    continue
                try:
                    info.sections.append(strtab[sh_name:end].decode("ascii"))
                except UnicodeDecodeError:
                    continue
    return info
