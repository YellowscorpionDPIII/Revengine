"""RevEngine: measure how reversible a build is to AI-assisted analysis.

Two halves, one codebase:
  - B (shipped): the reversibility scorer. Scores a build and reports
    protection recommendations.
  - A (internal only): the probe. Runs the same static analysis and turns
    it into evidence-tied behaviour findings. A is the measurement engine
    that keeps B honest. It is never distributed as a standalone tool.

Stdlib only. No cloud calls unless a local LLM endpoint is configured.
"""

__version__ = "0.1.0"
