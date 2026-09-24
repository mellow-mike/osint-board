"""DeBounce — is an e-mail address disposable (free, no key); full deliverability check with an API key.

Catalog: debounce · free_api · lookup · access=freemium · phase 1
Without a key the free disposable-domain endpoint answers; ``OSINT_MODULE_DEBOUNCE_API_KEY`` switches to the
validation API (syntax, spam trap, accept-all, deliverable, role account; paid credits after the free ones).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import verdict
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

DISPOSABLE_URL = "https://disposable.debounce.io/"
VALIDATE_URL = "https://api.debounce.io/v1/"

#: validation API ``code`` → (reason, verdict label)
CODES: dict[str, tuple[str, str]] = {
    "1": ("syntax error", "invalid"),
    "2": ("spam trap", "risky"),
    "3": ("disposable", "disposable"),
    "4": ("accept-all", "risky"),
    "5": ("deliverable", "deliverable"),
    "6": ("invalid", "invalid"),
    "7": ("unknown", "unknown"),
    "8": ("role account", "role"),
}


def _flag(value: Any) -> bool | None:
    text = str(value).strip().lower()
    return True if text in ("true", "1") else False if text in ("false", "0") else None


def parse_disposable(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    """``{"disposable": "true"}`` from the free endpoint."""
    disposable = _flag(payload.get("disposable"))
    if disposable is None:
        raise ValueError(f"debounce: unexpected response {str(payload)[:200]}")
    return [
        verdict(
            target,
            "debounce",
            label="disposable" if disposable else "not disposable",
            category="disposable_email",
            confidence=0.9 if disposable else 0.6,
            etype=EntityType.EMAIL_VERDICT,
            disposable=disposable,
            domain=target.value.rpartition("@")[2].lower(),
        )
    ]


def parse_validation(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    """``{"debounce": {"code": "5", "result": "Safe to Send", "reason": "Deliverable", ...}, "success": "1"}``."""
    d = payload.get("debounce") or {}
    if _flag(payload.get("success")) is not True or not isinstance(d, dict) or "code" not in d:
        error = d.get("error") if isinstance(d, dict) else None
        raise RuntimeError(f"debounce: {error or 'validation failed'}")
    reason, label = CODES.get(str(d["code"]), (str(d.get("reason") or "unknown").lower(), "unknown"))
    return [
        verdict(
            target,
            "debounce",
            label=label,
            category="email_validation",
            confidence=0.85,
            etype=EntityType.EMAIL_VERDICT,
            code=str(d["code"]),
            reason=reason,
            result=d.get("result"),
            role=_flag(d.get("role")),
            free_email=_flag(d.get("free_email")),
            disposable=label == "disposable",
            did_you_mean=d.get("did_you_mean") or None,
        )
    ]


@module("debounce")
class Debounce(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        key = self.ctx.secret()
        if key:
            payload = await self.ctx.http.get_json(VALIDATE_URL, params={"api": key, "email": target.value})
            emits = parse_validation(payload, target)
        else:
            payload = await self.ctx.http.get_json(DISPOSABLE_URL, params={"email": target.value})
            emits = parse_disposable(payload, target)
        for e in emits:
            yield e
