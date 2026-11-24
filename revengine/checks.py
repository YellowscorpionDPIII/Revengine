"""Static checks shared by the scorer (B) and the probe (A).

Each check returns a CheckResult with a machine-readable id, a boolean
(or None when the answer is genuinely unknown), human-readable detail,
and evidence. Unknown is never silently treated as absent.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

from .elfparse import parse_elf, ElfInfo
from .stringsx import scan_strings, max_window_entropy, StringReport


@dataclass
class CheckResult:
    id: str
    title: str
    passed: bool | None  # True = good (hardened), False = exposure, None = unknown
    detail: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class Analysis:
    path: str
    size: int
    elf: ElfInfo
    strings: StringReport
    max_entropy: float
    checks: list[CheckResult] = field(default_factory=list)

    def get(self, check_id: str) -> CheckResult | None:
        for c in self.checks:
            if c.id == check_id:
                return c
        return None


def _external_tool_output(cmd: list[str], timeout: int = 20) -> str | None:
    if shutil.which(cmd[0]) is None:
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout, check=False)
        return out.stdout
    except (subprocess.SubprocessError, OSError):
        return None


def analyze(path: str) -> Analysis:
    with open(path, "rb") as f:
        data = f.read()
    elf = parse_elf(data)
    strings = scan_strings(data)
    analysis = Analysis(path=path, size=len(data), elf=elf,
                        strings=strings,
                        max_entropy=max_window_entropy(data))
    analysis.checks = [
        _check_symbols(elf),
        _check_debug(elf),
        _check_strings(strings),
        _check_pie(elf),
        _check_relro(elf),
        _check_exec_stack(elf),
        _check_entropy(analysis.max_entropy),
        _check_dynamic_symbols(path),
    ]
    return analysis


def _check_symbols(elf: ElfInfo) -> CheckResult:
    if not elf.is_elf:
        return CheckResult("symbols", "Symbol table stripped", None,
                           "Not an ELF file; symbol status unknown.")
    present = elf.has_section(".symtab")
    return CheckResult(
        "symbols", "Symbol table stripped", not present,
        "Symbol table (.symtab) present — function/variable names aid "
        "analysis." if present else "No .symtab section found.",
        [".symtab"] if present else [])


def _check_debug(elf: ElfInfo) -> CheckResult:
    if not elf.is_elf:
        return CheckResult("debug", "Debug info removed", None,
                           "Not an ELF file; debug status unknown.")
    found = [s for s in elf.sections if s.startswith(".debug")
             or s.startswith(".zdebug")]
    return CheckResult(
        "debug", "Debug info removed", not found,
        f"Debug sections present: {', '.join(found)}." if found
        else "No debug sections found.",
        found)


def _check_strings(strings: StringReport) -> CheckResult:
    # Signing/master secrets weigh heaviest: one leaked signing key
    # forges sessions for any user, unlike a single API key.
    exposure = (strings.count("signing_secret") * 5
                + strings.count("credential_like") * 3
                + strings.count("url")
                + strings.count("email")
                + strings.count("path"))
    detail = (f"{strings.total_strings} strings; "
              f"{strings.count('url')} URLs, "
              f"{strings.count('email')} emails, "
              f"{strings.count('path')} filesystem paths, "
              f"{strings.count('credential_like')} credential-like patterns "
              f"(values redacted), "
              f"{strings.count('signing_secret')} signing/master-secret "
              f"pattern(s) (values redacted), "
              f"{strings.count('hex_blob')} long hex blobs.")
    evidence = [f"@{h.offset} {h.kind}: {h.preview}"
                for h in strings.hits[:10]]
    return CheckResult("strings", "Sensitive strings minimised",
                       exposure == 0, detail, evidence)


def _check_pie(elf: ElfInfo) -> CheckResult:
    if elf.is_pie is None:
        return CheckResult("pie", "Position-independent (PIE)", None,
                           "File type unknown; PIE status unknown.")
    return CheckResult(
        "pie", "Position-independent (PIE)", bool(elf.is_pie),
        "ET_DYN (PIE)." if elf.is_pie else "ET_EXEC (fixed addresses).")


def _check_relro(elf: ElfInfo) -> CheckResult:
    if not elf.is_elf:
        return CheckResult("relro", "RELRO present", None,
                           "Not an ELF file; RELRO status unknown.")
    return CheckResult(
        "relro", "RELRO present", elf.has_gnu_relro,
        "PT_GNU_RELRO segment present." if elf.has_gnu_relro
        else "No PT_GNU_RELRO segment.")


def _check_exec_stack(elf: ElfInfo) -> CheckResult:
    if elf.gnu_stack_executable is None:
        return CheckResult("execstack", "Non-executable stack", None,
                           "No PT_GNU_STACK segment; stack executability unknown.")
    return CheckResult(
        "execstack", "Non-executable stack",
        not elf.gnu_stack_executable,
        "Stack is executable (PT_GNU_STACK +X)." if elf.gnu_stack_executable
        else "Stack is non-executable.")


def _check_entropy(max_entropy: float) -> CheckResult:
    # High entropy suggests packing/encryption (harder to read statically);
    # low entropy means content is plainly readable. Neither is "good" on
    # its own — this check reports readability, not virtue.
    if max_entropy >= 7.5:
        return CheckResult("entropy", "Content readability", True,
                           f"Max 4K-window entropy {max_entropy:.2f} bits/byte — "
                           "content appears packed or encrypted.")
    return CheckResult("entropy", "Content readability", False,
                       f"Max 4K-window entropy {max_entropy:.2f} bits/byte — "
                       "content is plainly readable.")


def _check_dynamic_symbols(path: str) -> CheckResult:
    out = _external_tool_output(["nm", "-D", "--defined-only", path])
    if out is None:
        return CheckResult("dynsym", "Dynamic symbols minimised", None,
                           "`nm` unavailable; dynamic symbol count unknown.")
    names = [line.split()[-1] for line in out.splitlines()
             if line.strip() and " " in line.strip()]
    return CheckResult(
        "dynsym", "Dynamic symbols minimised", len(names) <= 50,
        f"{len(names)} exported dynamic symbols.",
        names[:10])
