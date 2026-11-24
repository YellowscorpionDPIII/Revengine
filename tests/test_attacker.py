import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from revengine.attacker import probe
from revengine.authz import AuthorizationError
from revengine.cli import main as cli_main
from fixtures import build_elf


def _write_temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


class TestAttacker(unittest.TestCase):
    def test_probe_requires_authorization(self):
        path = _write_temp(build_elf([".symtab"]))
        try:
            with self.assertRaises(AuthorizationError):
                probe(path, confirmed=False)
        finally:
            os.unlink(path)

    def test_probe_refuses_system_paths(self):
        with self.assertRaises(AuthorizationError):
            probe("/bin/ls", confirmed=True)

    def test_probe_finds_evidence_tied_findings(self):
        payload = (b"https://api.example.com/v2 "
                   b"token = abcdef0123456789 "
                   b"/home/dennis/src/main.c")
        path = _write_temp(build_elf([".symtab"], trailing=payload))
        try:
            report = probe(path, confirmed=True)
        finally:
            os.unlink(path)
        ids = {f.id for f in report.findings}
        self.assertIn("network-endpoints", ids)
        self.assertIn("embedded-credentials", ids)
        self.assertIn("symbol-names", ids)
        for finding in report.findings:
            self.assertTrue(finding.evidence or finding.id == "no-findings")
        # No secret values leak into the report.
        blob = str(report.to_dict())
        self.assertNotIn("abcdef0123456789", blob)

    def test_probe_flags_signing_secret(self):
        secret = b"a1b2c3d4" * 16
        payload = b"secret_key_base = " + secret
        path = _write_temp(build_elf([], trailing=payload))
        try:
            report = probe(path, confirmed=True)
        finally:
            os.unlink(path)
        ids = {f.id for f in report.findings}
        self.assertIn("signing-secrets", ids)
        blob = str(report.to_dict())
        self.assertNotIn(secret.decode(), blob)

    def test_cli_score_runs(self):
        path = _write_temp(build_elf([".symtab", ".debug_info"]))
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli_main(["score", path])
            self.assertEqual(rc, 0)
            self.assertIn("highly reversible", out.getvalue())
        finally:
            os.unlink(path)

    def test_cli_probe_refuses_without_flag(self):
        path = _write_temp(build_elf([]))
        try:
            rc = cli_main(["probe", path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
