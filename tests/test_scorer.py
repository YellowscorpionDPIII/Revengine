import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from revengine.checks import analyze
from revengine.scorer import (FAMILIES, FAMILY_MAP, PRESETS,
                              UNMEASURED_FAMILIES, WEIGHTS, score)
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

    # Paper alignment (arXiv:2608.11469 v2, §3): the mapping from
    # checks to the paper's nine technique families must stay complete
    # and honest — every check mapped, every family accounted for
    # exactly once between measured and unmeasured.
    def test_paper_mapping_covers_every_check(self):
        self.assertEqual(set(FAMILY_MAP), set(WEIGHTS))
        measured = set()
        for families in FAMILY_MAP.values():
            for fam in families:
                self.assertIn(fam, FAMILIES)
                measured.add(fam)
        self.assertTrue(set(UNMEASURED_FAMILIES).isdisjoint(measured))
        self.assertEqual(measured | set(UNMEASURED_FAMILIES),
                         set(FAMILIES))
        self.assertEqual(len(FAMILIES), 9)
        self.assertEqual(len(PRESETS), 8)

    def test_paper_weights_sum_to_100(self):
        # A binary failing every check scores exactly 100; weights
        # must not drift silently.
        self.assertEqual(sum(WEIGHTS.values()), 100)

    def test_score_reports_paper_families(self):
        payload = (b"https://internal.example.com/admin "
                   b"/home/dennis/build/secret-config")
        data = build_elf([".symtab", ".debug_info"], e_type=2,
                         trailing=payload)
        path = _write_temp(data)
        try:
            result = score(analyze(path))
        finally:
            os.unlink(path)
        self.assertEqual(result.paper["debug"], ["F1"])
        self.assertEqual(result.paper["strings"], ["F1", "F3"])
        # Every reported family is a real paper family, and every
        # failed check appears in the mapping.
        for check_id, families in result.paper.items():
            self.assertIn(check_id, result.failed)
            for fam in families:
                self.assertIn(fam, FAMILIES)
        # Generic-hardening checks carry no paper family.
        if "pie" in result.paper:
            self.assertEqual(result.paper["pie"], [])


if __name__ == "__main__":
    unittest.main()
