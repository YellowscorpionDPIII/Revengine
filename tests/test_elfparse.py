import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from revengine.elfparse import parse_elf
from fixtures import build_elf, PT_GNU_RELRO, PT_GNU_STACK


class TestElfParse(unittest.TestCase):
    def test_sections_and_debug(self):
        data = build_elf([".symtab", ".debug_info"])
        info = parse_elf(data)
        self.assertTrue(info.is_elf)
        self.assertTrue(info.is_64bit)
        self.assertIn(".symtab", info.sections)
        self.assertTrue(info.has_debug_sections())

    def test_pie_and_hardening_segments(self):
        data = build_elf([], e_type=3,
                         phdrs=[(PT_GNU_RELRO, 4), (PT_GNU_STACK, 6)])
        info = parse_elf(data)
        self.assertTrue(info.is_pie)
        self.assertTrue(info.has_gnu_relro)
        self.assertFalse(info.gnu_stack_executable)

    def test_exec_stack_flagged(self):
        data = build_elf([], phdrs=[(PT_GNU_STACK, 7)])  # R+W+X
        info = parse_elf(data)
        self.assertTrue(info.gnu_stack_executable)

    def test_non_elf(self):
        info = parse_elf(b"hello, this is not an elf file" * 4)
        self.assertFalse(info.is_elf)
        self.assertIsNone(info.is_pie)

    def test_truncated(self):
        info = parse_elf(b"\x7fELF" + b"\x00" * 10)
        self.assertFalse(info.is_elf)  # too short for a header


if __name__ == "__main__":
    unittest.main()
