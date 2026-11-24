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

Weights are v0 heuristics. TODO: align them with the five protection
steps in the Anthropic/OpenAI/Google reverse-engineering paper
(arXiv 2608.11469) once verified against the paper itself.

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

20 tests, all stdlib, synthetic ELF fixtures built in-memory (no
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
with the paper's five steps. Live at
github.com/YellowscorpionDPIII/Revengine.
