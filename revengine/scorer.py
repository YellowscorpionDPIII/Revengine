"""B (shipped): the reversibility scorer.

Scores 0–100 where HIGHER means MORE reversible — easier for AI-assisted
analysis to understand the build. Weights are v0 heuristics, documented
here and tunable; they are not claims about any paper's methodology.

TODO: align check weights and recommendation wording with the five
protection steps in the Anthropic/OpenAI/Google reverse-engineering
paper (arXiv 2608.11469) once verified against the paper itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .checks import Analysis

# Weight of each failed check toward the 0–100 score.
WEIGHTS = {
    "debug": 25,
    "symbols": 20,
    "strings": 15,
    "dynsym": 10,
    "entropy": 10,
    "pie": 5,
    "relro": 5,
    "execstack": 10,
}

RECOMMENDATIONS = {
    "debug": ("Strip debug info from release builds",
              "Remove .debug sections (e.g. strip, or build with "
              "-g0). Debug info hands an analyst source paths, line "
              "numbers, and variable names."),
    "symbols": ("Strip the symbol table",
                "Ship without .symtab. Keep an unstripped copy only "
                "for your own crash analysis, never in the release."),
    "strings": ("Reduce sensitive string exposure",
                "Remove or protect embedded URLs, filesystem paths, "
                "and credential-like values. Never ship secrets in "
                "the binary at all — load them at runtime. Signing / "
                "master secrets (e.g. Rails secret_key_base) are the "
                "worst case: one leak forges sessions for any user, "
                "and rotating the key invalidates every session, so "
                "keep them in env or an encrypted credentials store, "
                "never in code or a binary."),
    "dynsym": ("Minimise exported dynamic symbols",
               "Limit visibility (e.g. -fvisibility=hidden) and "
               "export only the API surface you intend."),
    "entropy": ("Consider obfuscation or packing trade-offs",
                "Plainly readable content is trivially analysable. "
                "Packing/obfuscation raises the bar but complicates "
                "debugging and can look hostile to scanners — weigh it."),
    "pie": ("Build position-independent (PIE)",
            "PIE complicates static address assumptions. Enable "
            "with -pie -fPIE where your platform supports it."),
    "relro": ("Enable RELRO",
              "Link with -Wl,-z,relro,-z,now to harden the GOT."),
    "execstack": ("Mark the stack non-executable",
                  "Link with -Wl,-z,noexecstack."),
}


@dataclass
class Score:
    value: int  # 0–100, higher = more reversible
    band: str   # hardened | moderate | highly reversible
    failed: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    recommendations: list[tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"score": self.value, "band": self.band,
                "failed_checks": self.failed,
                "unknown_checks": self.unknown,
                "recommendations": [
                    {"title": t, "detail": d}
                    for t, d in self.recommendations]}


def score(analysis: Analysis) -> Score:
    total = 0
    failed: list[str] = []
    unknown: list[str] = []
    for check in analysis.checks:
        if check.passed is None:
            unknown.append(check.id)
        elif not check.passed:
            failed.append(check.id)
            total += WEIGHTS.get(check.id, 0)
    value = min(100, total)
    if value < 30:
        band = "hardened"
    elif value < 60:
        band = "moderate"
    else:
        band = "highly reversible"
    recs = [RECOMMENDATIONS[cid] for cid in failed if cid in RECOMMENDATIONS]
    return Score(value=value, band=band, failed=failed,
                 unknown=unknown, recommendations=recs)
