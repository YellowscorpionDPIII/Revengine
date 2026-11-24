"""A (internal only): the probe.

Turns static analysis into evidence-tied behaviour findings. Every
finding carries its evidence (offsets, matched patterns, check ids) and
a confidence. The probe never asserts more than the evidence supports:
a URL string is evidence the binary *references* an endpoint, not proof
it contacts one at runtime.

The probe is the measurement engine for B. It is not distributed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .checks import Analysis, analyze
from .authz import require_authorization


@dataclass
class Finding:
    id: str
    claim: str
    confidence: str  # high | medium | low
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"id": self.id, "claim": self.claim,
                "confidence": self.confidence, "evidence": self.evidence}


@dataclass
class ProbeReport:
    path: str
    findings: list[Finding] = field(default_factory=list)
    narrative: str | None = None  # LLM-drafted, evidence-cited; None when no LLM

    def to_dict(self) -> dict:
        return {"path": self.path,
                "findings": [f.to_dict() for f in self.findings],
                "narrative": self.narrative}


def probe(path: str, confirmed: bool, llm=None) -> ProbeReport:
    require_authorization(path, confirmed)
    analysis = analyze(path)
    findings = _findings_from(analysis)
    report = ProbeReport(path=path, findings=findings)
    if llm is not None:
        report.narrative = llm.draft_narrative(findings)
    return report


def _findings_from(analysis: Analysis) -> list[Finding]:
    findings: list[Finding] = []
    strings = analysis.strings

    urls = [h for h in strings.hits if h.kind == "url"]
    if urls:
        findings.append(Finding(
            "network-endpoints",
            f"Binary references {len(urls)} URL(s); may contact network "
            "endpoints at runtime.",
            "medium",
            [f"@{h.offset} {h.preview}" for h in urls[:10]]))

    creds = [h for h in strings.hits if h.kind == "credential_like"]
    if creds:
        findings.append(Finding(
            "embedded-credentials",
            f"{len(creds)} credential-like pattern(s) embedded in the "
            "binary (values redacted). Treat as exposed secrets until "
            "proven otherwise.",
            "high",
            [f"@{h.offset} {h.preview}" for h in creds[:10]]))

    signing = [h for h in strings.hits if h.kind == "signing_secret"]
    if signing:
        findings.append(Finding(
            "signing-secrets",
            f"{len(signing)} signing/master-secret pattern(s) embedded "
            "(values redacted) — e.g. a Rails secret_key_base or other "
            "session-signing key. One leaked signing key can forge "
            "sessions for any user; treat as exposed until proven "
            "otherwise, and note rotating it invalidates every "
            "session.",
            "high",
            [f"@{h.offset} {h.preview}" for h in signing[:10]]))

    paths = [h for h in strings.hits if h.kind == "path"]
    if paths:
        findings.append(Finding(
            "filesystem-paths",
            f"{len(paths)} build/host filesystem path(s) embedded; "
            "leaks build environment layout.",
            "high",
            [f"@{h.offset} {h.preview}" for h in paths[:10]]))

    symtab = analysis.get("symbols")
    if symtab is not None and symtab.passed is False:
        findings.append(Finding(
            "symbol-names",
            "Symbol table present: function and variable names are "
            "available to any analyst.",
            "high", symtab.evidence))

    debug = analysis.get("debug")
    if debug is not None and debug.passed is False:
        findings.append(Finding(
            "debug-info",
            "Debug sections present: source paths and line info "
            "available to any analyst.",
            "high", debug.evidence))

    entropy = analysis.get("entropy")
    if entropy is not None:
        if entropy.passed is True:
            findings.append(Finding(
                "packed-content",
                "High-entropy regions suggest packing or encryption; "
                "static reading alone will miss behaviour.",
                "medium", [entropy.detail]))
        else:
            findings.append(Finding(
                "readable-content",
                "Content is plainly readable; static analysis covers "
                "most of the binary.",
                "high", [entropy.detail]))

    dynsym = analysis.get("dynsym")
    if dynsym is not None and dynsym.passed is False:
        findings.append(Finding(
            "exported-surface",
            "Large exported dynamic symbol surface.",
            "medium", dynsym.evidence))

    if not findings:
        findings.append(Finding(
            "no-findings",
            "No behaviour indicators found by static checks. This is "
            "absence of evidence, not evidence of absence.",
            "low", []))
    return findings
