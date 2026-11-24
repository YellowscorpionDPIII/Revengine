"""B (shipped): the reversibility scorer.

Scores 0–100 where HIGHER means MORE reversible — easier for AI-assisted
analysis to understand the build.

Paper alignment — verified 2026-11-24 against the paper itself
(arXiv:2608.11469 v2, "The Next Challenge for Agentic Cybersecurity: A
Realistic, Contamination-Free Reverse Engineering Benchmark", SRE-Bench;
see paper-five-steps-verified.md at the repo root):

- The paper does NOT contain five protection steps. "Five" in the paper
  is the five RE domains (network protocols, firmware, games, format
  parsers, malware). The "five steps" claim was a misreading of those
  domains, and no weight in this scorer is aligned to it.
- What the paper actually has: 44 protection primitives in nine
  technique families (§3, "Protection and Obfuscation"), eight
  protection presets P1–P8 (Table 6, §B.9), and Appendix B design rules
  ("fold, don't branch"; everything feeds the key; minimize plaintext
  residency; deception rather than denial).
- The scorer's static checks measure the ABSENCE of the paper's
  protections. FAMILY_MAP below ties each check to the families whose
  protection it evidences the absence of.
- Coverage honesty: only families F1–F3 are measurable by static ELF
  checks. F4–F9 (measurement-keyed anti-debugging, self-checksumming,
  online licensing, loader virtualization, anti-dump, anti-re-hosting)
  are runtime / server-side properties a static scan cannot see, and
  presets P5–P8 need an off-box key and server logic. A low score
  therefore means "no static exposure found", NOT "P8-grade
  protection". Never claim preset equivalence from a score.
- Weights remain v0 heuristics, now with a stated rationale per check
  tied to the family it evidences. They are not the paper's numbers —
  the paper publishes no per-family weights.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .checks import Analysis

# The paper's nine technique families (arXiv:2608.11469 v2, §3).
# Primitive counts are the paper's own: 5+4+5+8+3+4+6+5+4 = 44.
FAMILIES = {
    "F1": "Obfuscation and string deception (5 primitives)",
    "F2": "Per-page authenticated encryption (4 primitives)",
    "F3": "Lazy decryption and residency minimization (5 primitives)",
    "F4": "Measurement-keyed anti-debugging (8 primitives)",
    "F5": "Self-checksumming and anti-tamper coupling (3 primitives)",
    "F6": "Online licensing with per-run key delivery (4 primitives)",
    "F7": "Loader-logic virtualization (6 primitives)",
    "F8": "Anti-dump detection and deception (5 primitives)",
    "F9": "Anti-re-hosting (4 primitives)",
}

# Presets P1–P8 (Table 6, §B.9): graded difficulty rungs, from eager
# whole-image decryption (P1/P5, most tractable) to strict and
# server-side variants (P4/P8, least tractable). All share a common
# baseline — per-page authenticated encryption, fold-not-branch keying,
# self-checksumming, loader virtualization, and the obfuscation and
# stripping layers.
PRESETS = ("P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8")

# Which paper families each static check evidences the absence of.
# An empty tuple means the check is generic hardening with no direct
# paper family — it stays in the score as a v0 heuristic, labelled so.
FAMILY_MAP: dict[str, tuple[str, ...]] = {
    # Debug sections hand an analyst source paths, line numbers, and
    # variable names — they defeat the obfuscation/stripping layer
    # that is part of every preset's shared baseline (F1).
    "debug": ("F1",),
    # A shipped symbol table defeats the same stripping layer (F1).
    "symbols": ("F1",),
    # Exposed strings are exactly what F1's string deception protects,
    # and plaintext resident in the file violates F3's residency
    # minimization (App. B.3: minimize plaintext residency).
    "strings": ("F1", "F3"),
    # Exported dynamic symbols aid analysis through the same
    # stripping layer (F1).
    "dynsym": ("F1",),
    # Low entropy = plaintext resident and readable, i.e. no F2
    # authenticated encryption and no F3 lazy decryption / residency
    # minimization. High entropy is consistent with those layers
    # being present, not proof of them — so this is a weak proxy.
    "entropy": ("F2", "F3"),
    # Generic hardening; the paper's nine families do not cover it.
    "pie": (),
    "relro": (),
    "execstack": (),
}

# Families no static ELF check can measure: runtime / server-side
# properties. Together with F1–F3 above, these cover all nine.
UNMEASURED_FAMILIES = ("F4", "F5", "F6", "F7", "F8", "F9")

# Weight of each failed check toward the 0–100 score. Rationale, tied
# to the families in FAMILY_MAP above:
#   debug 25 — the largest single analyst aid; nullifies F1 and the
#     stripping layer every preset assumes.
#   symbols 20 — same layer as debug, minus source-level detail.
#   strings 15 — F1 string deception + F3 residency. The check's own
#     internal signing_secret x5 weighting (checks.py) is untouched.
#   dynsym 10 — F1, capped: exported symbols help, but less than a
#     full symbol table.
#   entropy 10 — proxy for F2/F3; weak evidence, so capped low.
#   pie 5 / relro 5 — generic hardening, no paper family; small.
#   execstack 10 — generic hardening, but an executable stack is a
#     direct exploitation aid, so weighted above pie/relro.
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
    # Failed check id -> paper families whose protection the failure
    # evidences the absence of (FAMILY_MAP; empty list = no paper
    # family, generic hardening only).
    paper: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"score": self.value, "band": self.band,
                "failed_checks": self.failed,
                "unknown_checks": self.unknown,
                "paper_families": self.paper,
                "recommendations": [
                    {"title": t, "detail": d}
                    for t, d in self.recommendations]}


def score(analysis: Analysis) -> Score:
    total = 0
    failed: list[str] = []
    unknown: list[str] = []
    paper: dict[str, list[str]] = {}
    for check in analysis.checks:
        if check.passed is None:
            unknown.append(check.id)
        elif not check.passed:
            failed.append(check.id)
            total += WEIGHTS.get(check.id, 0)
            paper[check.id] = list(FAMILY_MAP.get(check.id, ()))
    value = min(100, total)
    if value < 30:
        band = "hardened"
    elif value < 60:
        band = "moderate"
    else:
        band = "highly reversible"
    recs = [RECOMMENDATIONS[cid] for cid in failed if cid in RECOMMENDATIONS]
    return Score(value=value, band=band, failed=failed,
                 unknown=unknown, recommendations=recs, paper=paper)
