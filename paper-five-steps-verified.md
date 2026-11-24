# Paper verification: arXiv:2608.11469 — the "five protection steps"

Verified against the paper itself (arXiv HTML v2, fetched 2026-11-24), not from
the X post or any secondary summary.

## Verdict up front

**The paper does NOT contain five protection steps.** The phrase "protection
steps" never appears, and the word "steps" occurs only twice in the entire
paper, neither time as a protection taxonomy. The premise that the paper
defines five protection steps is wrong, and RevEngine's scorer weights
cannot be aligned to them.

What the paper actually contains for protection:

- **44 distinct protection primitives, organized into nine technique
  families** (§3, "Protection and Obfuscation").
- **Eight protection presets** (P1–P8, Table 6, §B.9).
- **Five RE domains** (network protocols, firmware, games, format parsers,
  malware) — this "five" is the likely source of the misreading.
- **Six deterministically graded tasks per instance**; 262 instances;
  1,572 tasks total.

## Paper identity

- **Title:** The Next Challenge for Agentic Cybersecurity: A Realistic,
  Contamination-Free Reverse Engineering Benchmark
- **arXiv:** 2608.11469 [cs.CR] — https://arxiv.org/abs/2608.11469
- **Benchmark name:** SRE-Bench
- **Versions:**
  - **v1** — submitted 11 Aug 2026. 8 authors. Evaluated five frontier LLMs
    (GPT-5.6-Sol, Claude-Opus-5, GPT-5.5, Grok-4.5, GLM-5.2), ~$31.4K.
  - **v2 (current)** — last revised 1 Oct 2026. 13 authors. Evaluated 13
    agentic settings across 11 models, including five internal unconstrained
    settings with safeguards disabled and no budget cap. No v3 exists as of
    the 2026-11-24 check.
- **Authors (v2):** Jeremy Spence (Columbia), Nicholas Assaderaghi
  (Columbia), Feng Xiao (Google DeepMind), Jinhao Zhu (UC Berkeley),
  Nikil Ravi (Vals AI), Xiangyu Qi (OpenAI), Matthew Jagielski (Anthropic),
  Raluca Ada Popa (Google DeepMind / UC Berkeley), Eric Wallace (OpenAI),
  Guannan Wei (Tufts), Yangruibo Ding (UCLA), Zhuo Zhang (Columbia).
- **Authors (v1):** the same minus Feng Xiao, Xiangyu Qi, Matthew
  Jagielski, and Eric Wallace.
- **"Anthropic/OpenAI/Google paper" — partly accurate, for v2 only:**
  authors include people at Anthropic, OpenAI, and Google DeepMind, but it
  is a multi-institution academic paper led from Columbia / UC Berkeley,
  not a corporate paper. v1 had no Anthropic/OpenAI/Google-affiliated
  author at all.

## What the paper actually says about protection (§3)

Verbatim, §3, "Protection and Obfuscation":

> "To model this, SRE-Bench includes an in-house binary protection suite
> that transforms an unprotected Linux ELF into a hardened, functionally
> equivalent variant."

> "It provides 44 distinct protection primitives organized into nine
> technique families."

> "These primitives can be composed to construct stronger, layered
> protections, including: (1) Obfuscation and string deception
> (5 primitives). (2) Per-page authenticated encryption (4 primitives).
> (3) Lazy decryption and residency minimization (5 primitives).
> (4) Measurement-keyed anti-debugging (8 primitives). (5)
> Self-checksumming and anti-tamper coupling (3 primitives). (6) Online
> licensing with per-run key delivery (4 primitives). (7) Loader-logic
> virtualization (6 primitives). (8) Anti-dump detection and deception
> (5 primitives). (9) Anti-re-hosting (4 primitives)."

Primitive counts sum to 44 (5+4+5+8+3+4+6+5+4). "More than half of these
primitives, primarily in families (3), (4), (7), (9), and (8), have no
publicly available implementations."

Appendix B ("Protection Suite Details") expands the design in eight
subsections — B.1 threat model and the governing rule ("fold, don't
branch"), B.2 everything feeds the key, B.3 minimizing plaintext
residency, B.4 establishing exclusive control, B.5 virtualized loader
logic, B.6 binding to a genuine launch and off-box keys, B.7 deception
rather than denial, B.8 anti-agent deterrents (a reported negative
result) — and B.9 preset summary. Its framing line:

> "It makes no claim of unbreakability: the goal is to *raise the cost*
> of analysis in measurable, tunable steps, which is what makes it useful
> as a benchmark generator rather than as a security product."

That is one of only two occurrences of the word "steps" in the paper. The
other is §4: "each run is capped at 500 model steps and 6 hours of
wall-clock time."

## The eight protection presets (Table 6, §B.9)

Every preset shares a common baseline — "per-page authenticated
encryption, fold-not-branch keying, self-checksumming, loader
virtualization, and the obfuscation and stripping layers" — and they differ
along four axes: whether decryption is lazy, whether observation is keyed
into decryption continuously (the *strict* presets), whether the key is
off-box, and whether the runtime responds to a detected dump by
misdirecting the analyst.

| ID | Preset | Lazy | Strict | Anti-re-host | Off-box key | Server logic | Anti-dump |
|----|--------|------|--------|--------------|-------------|--------------|-----------|
| P1 | protected-eager | – | – | ✓ | – | – | – |
| P2 | protected-eager-strict | – | ✓ | ✓ | – | – | • |
| P3 | protected-demand | ✓ | – | ✓ | – | – | – |
| P4 | protected-demand-strict | ✓ | ✓ | ✓ | – | – | ✓ |
| P5 | licensed-eager | – | – | – | ✓ | shard | – |
| P6 | licensed-demand | ✓ | – | – | ✓ | shard | – |
| P7 | licensed-demand-material | ✓ | ✓ | – | ✓ | material | ✓ |
| P8 | licensed-demand-superops | ✓ | ✓ | – | ✓ | operators | ✓ |

(• = available but requires an author-supplied decoy.)

## Every "five" in the paper (full-text search)

The word "five" occurs exactly four times:

1. Abstract/§4: "five in internal unconstrained settings" — of the 13
   agentic settings, eight public-facing and five internal.
2. §1/§3: "five representative RE domains: network protocols, firmware,
   games, format parsers, and malware."
3. §3: "spanning five domains that together cover the breadth of
   real-world RE practice."
4. §A.1: "(6) a capstone that requires all five above to hold within a
   single session" — the five scored anchors of the network-protocol
   task ladder, plus a capstone as the sixth task.

None of these is a protection taxonomy. The most plausible origin of the
"five protection steps" claim is a misreading of the **five RE domains**
(or, secondarily, the five scored anchors in §A.1).

## Comparison with the 0xCodila X post

**Direct comparison was not possible.** The X post
(https://x.com/0xcodila/status/2119859587293528490) could not be
retrieved: the x.com fetch is blocked by domain policy, and web search
did not surface the tweet's text. Do not treat the comparison below as a
verified quote of the post.

What is established from the paper itself and from independent sources:

- **"Five protection steps" is not in the paper.** Any summary attributing
  five protection steps to arXiv:2608.11469 is wrong on the paper's own
  text. The paper's protection taxonomy is nine families / 44 primitives
  / eight presets.
- **REA is not in the paper.** REA (Reverse Engineer Anything,
  morluto/rea) is a separate, real project — an MIT-licensed MCP server
  that gives coding agents Ghidra/Hopper/IDA access — and it is not
  mentioned anywhere in the paper's text. The paper's related work (§2)
  covers RE *benchmarks* (NYU CTF Bench, Cybench, CTF-Dojo, CTFTiny,
  CREBench, AgentRE-Bench, CrackMeBench), not REA.
- **"RevEngine" is not in the paper.** RevEngine is Dennis's own project
  name; nothing in the paper uses it.
- **v1 vs v2 matters for any summary.** A summary written from v1
  (8 authors, 5 models, $31.4K) understates v2 (13 authors, 13 settings
  across 11 models, ~$566K unconstrained token cost). The X post is dated
  2026-11-09, after v2 (1 Oct 2026), so it should describe v2.

## Consequence for RevEngine

The README's TODO — "align them with the five protection steps in the
Anthropic/OpenAI/Google reverse-engineering paper (arXiv 2608.11469) once
verified against the paper itself" — is now verified and **cannot be done
as written: there are no five steps**. The honest alignment targets from
the paper are:

1. The **nine technique families** (§3) — the closest thing to a
   protection taxonomy. A scorer could weight checks against these nine
   families.
2. The **eight presets** (Table 6, §B.9) — graded difficulty rungs, from
   eager whole-image decryption (P1/P5, most tractable) to strict and
   server-side variants (P4/P8, least tractable).
3. The **design rules in Appendix B** — "fold, don't branch"; everything
   feeds the key; minimize plaintext residency; deception rather than
   denial.

Recommendation: update the README TODO to name the nine families and the
eight presets, and do not cite "five protection steps" anywhere.

## RAG corpus note (for Tracy, the RAG updater agent)

This paper is a RAG corpus source for the Mira/RevEngine RAG pipeline.
Rules for this source:

- The canonical source is the arXiv paper itself
  (https://arxiv.org/abs/2608.11469), current version v2 (1 Oct 2026).
- **Future updates must be re-verified against the paper itself, never
  from summaries, X posts, or secondary write-ups.** The "five protection
  steps" error is the proof of why: a summary-level claim that does not
  exist in the paper.
- On any new arXiv version (v3+), re-run this verification: re-fetch the
  HTML, re-check the protection taxonomy (§3), the preset table (§B.9),
  and the author list, and update this file with the new version's date
  and any changed counts.
- Do not ingest REA (morluto/rea) material as if it were part of this
  paper; it is a separate project. Do not ingest "RevEngine" claims about
  the paper; RevEngine is our project, not the paper's.
- Verified 2026-11-24 from arXiv HTML v2 (1777 lines read) and the arXiv
  abs page (v1/v2 history). X post text unverified — x.com fetch blocked.
