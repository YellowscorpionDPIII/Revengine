"""Authorization gate for the internal probe (A).

The probe only runs on files the operator explicitly confirms they are
authorised to analyse. This is a guardrail, not enforcement: it stops
accidental misuse and creates a record of the operator's assertion. It
cannot verify ownership. Be honest about that limit in any docs.
"""

from __future__ import annotations

import os

SYSTEM_PREFIXES = ("/bin", "/sbin", "/usr/bin", "/usr/sbin",
                   "/System", "/Windows", "C:\\Windows")


class AuthorizationError(Exception):
    pass


def require_authorization(path: str, confirmed: bool) -> None:
    if not confirmed:
        raise AuthorizationError(
            "Refusing to probe without explicit authorisation. Re-run with "
            "--i-am-authorized, confirming you own this binary or are "
            "authorised to analyse it.")
    real = os.path.realpath(path)
    if real.startswith(SYSTEM_PREFIXES):
        raise AuthorizationError(
            f"Refusing to probe system path: {real}. Analyse a copy under "
            "your own working directory instead.")
    if not os.path.isfile(real):
        raise AuthorizationError(f"Not a file: {path}")
