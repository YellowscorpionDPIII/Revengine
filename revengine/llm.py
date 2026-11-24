"""Optional local-LLM narrative hook for the probe.

Default is OFF: with no endpoint configured, the probe returns findings
only and no narrative is generated. When REVENGINE_LLM_URL is set, the
client posts to a llama.cpp-compatible /completion endpoint (the Nano's
inference server) and drafts a narrative that must cite finding ids.
The model never sees raw binary bytes — only the finding summaries.

No cloud calls. Ever, from this module.
"""

from __future__ import annotations

import json
import os
import urllib.request

from .attacker import Finding

DEFAULT_URL = "http://127.0.0.1:8080/completion"

PROMPT_TEMPLATE = """You are drafting a behaviour summary from static-analysis findings.
Rules: only claim what the findings support. Cite finding ids like [id].
Never invent endpoints, credentials, or behaviour not in the findings.
If a finding is uncertain, say so.

Findings:
{findings}

Write a short behaviour summary (under 200 words), citing finding ids.
"""


class LocalLlamaClient:
    def __init__(self, url: str | None = None, timeout: int = 60):
        self.url = url or os.environ.get("REVENGINE_LLM_URL", DEFAULT_URL)
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> "LocalLlamaClient | None":
        if os.environ.get("REVENGINE_LLM_URL"):
            return cls()
        return None

    def draft_narrative(self, findings: list[Finding]) -> str | None:
        body = "\n".join(
            f"- [{f.id}] ({f.confidence}) {f.claim} Evidence: "
            f"{'; '.join(f.evidence[:3])}" for f in findings)
        payload = json.dumps({
            "prompt": PROMPT_TEMPLATE.format(findings=body),
            "n_predict": 300,
            "temperature": 0.2,
        }).encode()
        req = urllib.request.Request(
            self.url, data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode())
        except Exception as exc:  # noqa: BLE001 — LLM is best-effort
            return f"[narrative unavailable: {exc}]"
        text = result.get("content", "").strip()
        return text or None
