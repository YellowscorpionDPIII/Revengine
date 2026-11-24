# RevEngine

Measure how reversible a build is to AI-assisted analysis — and prove the
measurement with an internal probe that tries to understand the binary.

## Shape: build both, ship one

- **B — the scorer (shipped).** Scores a build 0–100 (higher = more
  reversible) and reports concrete protection fixes. This is the product.
- **A — the probe (internal only).** Runs the same static analysis and
  turns it into evidence-tied behaviour findings. A is the measurement
  engine that keeps B honest. It is never distributed as a standalone
  tool, and it only runs on files the operator explicitly confirms they
  are authorised to analyse.

This keeps B's scores real (an actual adversary tried) without handing
out a weapon, and answers the conflict-of-interest question cleanly:
the attacker exists only to test the defense.

RevEngine plugs into Mira's AI Evaluation Platform (project 5): the same
eval-harness pattern as scoring model configs, pointed at binaries.

## What it checks (v0, stdlib only, ELF64)

Symbol table, debug sections, sensitive strings (URLs, emails, paths,
credential-like patterns — values redacted), PIE, RELRO, executable
stack, content entropy, exported dynamic symbols. Unknowns are reported
as unknown, never scored as safe.

Weights are v0 heuristics, each tied to the paper's taxonomy with a
stated rationale (see `scorer.py`). The paper is arXiv 2608.11469 v2
(SRE-Bench): **there are no "five protection steps" in it** — that was
a misreading of the paper's five RE domains (network protocols,
firmware, games, format parsers, malware). What the paper actually
has is 44 protection primitives in nine technique families (§3) and
eight presets P1–P8 (Table 6, §B.9). Verified against the paper
itself; see `paper-five-steps-verified.md`.

| check | weight | paper families evidenced when failed |
|---|---|---|
| debug sections | 25 | F1 — obfuscation and string deception |
| symbol table | 20 | F1 |
| sensitive strings | 15 | F1, F3 — string deception; residency minimization |
| dynamic symbols | 10 | F1 |
| content readability (entropy) | 10 | F2, F3 — authenticated encryption; lazy decryption |
| PIE / RELRO / exec stack | 5 / 5 / 10 | none — generic hardening, no paper family |

Honest gap: only F1–F3 are measurable by static ELF checks. F4–F9
(measurement-keyed anti-debugging, self-checksumming, online
licensing, loader virtualization, anti-dump, anti-re-hosting) are
runtime / server-side properties a static scan cannot see, and
presets P5–P8 need an off-box key and server logic. A low score means
"no static exposure found", not "P8-grade protection".

## Install & run

```sh
pip install -e .
revengine score ./your-binary
revengine score ./your-binary --json
revengine probe ./your-binary --i-am-authorized
```

The probe refuses without `--i-am-authorized` and refuses system paths.
That is a guardrail, not enforcement — it cannot verify ownership.

Optional LLM narrative (local only, off by default):

```sh
REVENGINE_LLM_URL=http://127.0.0.1:8080/completion \
  revengine probe ./your-binary --i-am-authorized --llm
```

The model sees finding summaries only, never raw binary bytes, and must
cite finding ids. Point it at the Nano's llama.cpp server. No cloud
calls, ever.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

23 tests, all stdlib, synthetic ELF fixtures built in-memory (no
compiler needed). Also smoke-tested against a real system binary.

## Layout

```
revengine/
  elfparse.py   minimal ELF64 parser (sections, program headers)
  stringsx.py   string extraction, pattern flagging, entropy
  checks.py     the 8 static checks shared by A and B
  scorer.py     B: weights, bands, recommendations
  attacker.py   A: evidence-tied behaviour findings
  authz.py      authorisation gate for the probe
  llm.py        optional local-llama.cpp narrative hook
  cli.py        score / probe commands
tests/          fixtures + unit tests
```

## Status

v0.1 starter, written 2026-11-18. Next: real-binary validation set
(before/after hardening pairs), Mach-O/PE parsers, and aligning weights
with the paper's nine families and eight presets (arXiv 2608.11469 v2).
Live at github.com/YellowscorpionDPIII/Revengine.
