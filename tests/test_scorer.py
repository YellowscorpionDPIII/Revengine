import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from revengine.checks import analyze
from revengine.scorer import score
from fixtures import build_elf, PT_GNU_RELRO, PT_GNU_STACK


def _write_temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


class TestScorer(unittest.TestCase):
    def test_exposed_binary_scores_high(self):
        payload = (b"https://internal.example.com/admin "
                   b"api_key = hunter2-value-here "
                   b"/home/dennis/build/secret-config")
        data = build_elf([".symtab", ".debug_info"], e_type=2, trailing=payload)
        path = _write_temp(data)
        try:
            result = score(analyze(path))
        finally:
            os.unlink(path)
        # debug 25 + symbols 20 + strings 15 + entropy 10 + pie 5 = 75
        # (relro/execstack unknown or passing; dynsym depends on nm)
        self.assertGreaterEqual(result.value, 70)
        self.assertEqual(result.band, "highly reversible")
        self.assertIn("debug", result.failed)
        self.assertIn("symbols", result.failed)
        self.assertTrue(result.recommendations)

    def test_hardened_binary_scores_low(self):
        # No symtab/debug, PIE + RELRO + non-exec stack, high-entropy body
        # (packed), no readable strings.
        import random
        random.seed(1)
        body = bytes(random.randrange(256) for _ in range(8192))
        data = build_elf([], e_type=3,
                         phdrs=[(PT_GNU_RELRO, 4), (PT_GNU_STACK, 6)],
                         trailing=body)
        path = _write_temp(data)
        try:
            result = score(analyze(path))
        finally:
            os.unlink(path)
        self.assertLess(result.value, 30)
        self.assertEqual(result.band, "hardened")

    def test_unknown_checks_reported_not_scored(self):
        data = b"not an elf file at all, just text " * 10
        path = _write_temp(data)
        try:
            result = score(analyze(path))
        finally:
            os.unlink(path)
        self.assertIn("symbols", result.unknown)
        self.assertIn("debug", result.unknown)


if __name__ == "__main__":
    unittest.main()
