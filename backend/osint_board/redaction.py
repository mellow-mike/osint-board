"""Keep credentials out of logs, error messages and soak reports.

Several free APIs put the key in the URL (NASA FIRMS in the path, OpenCellID in the query string), and httpx,
``raise_for_status`` and our own retry logging all repeat the URL. :func:`redact` masks every secret value the
process knows about (module secrets from the environment plus any value registered at runtime) and common
credential query parameters.
"""

from __future__ import annotations

import os
import re
import threading

MASK = "***"
_MIN_LEN = 6  # shorter values are too likely to collide with ordinary text

_QUERY = re.compile(
    r"(?i)([?&](?:api[_-]?key|apikey|key|token|access_token|auth|client_secret|password|secret)=)[^&#\s'\"]+"
)
_lock = threading.Lock()
_registered: set[str] = set()


def register_secret(value: str | None) -> None:
    """Remember a secret so later :func:`redact` calls mask it (called by ``ModuleContext.secret``)."""
    if value and len(value) >= _MIN_LEN:
        with _lock:
            _registered.add(value)


def _known_secrets() -> list[str]:
    env = [
        v
        for k, v in os.environ.items()
        if k.startswith("OSINT_MODULE_") and not k.endswith("_CONFIG") and v and len(v) >= _MIN_LEN
    ]
    with _lock:
        values = set(env) | _registered
    return sorted(values, key=len, reverse=True)  # longest first so a secret containing another is fully masked


def redact(text: object) -> str:
    """``str(text)`` with known secrets and credential query parameters replaced by ``***``."""
    out = str(text)
    for secret in _known_secrets():
        if secret in out:
            out = out.replace(secret, MASK)
    return _QUERY.sub(lambda m: m.group(1) + MASK, out)
