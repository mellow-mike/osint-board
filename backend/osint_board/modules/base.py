"""Module framework.

A module is a small class that declares which catalog entry it implements and does one of three things:

* :class:`LookupModule` — given a target entity, yield :class:`Emit` objects (enrichment).
* :class:`FeedModule` — periodically (``poll``) or continuously (``stream``) yield global data for the globe.
* :class:`ExtractModule` — scan collected content for identifiers.

Modules never touch the database or the search index. They emit; the platform persists, links, geolocates
and indexes. That keeps every module unit-testable with a pure function and a fixture file.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from osint_board.catalog.models import ModuleSpec
from osint_board.config import Settings, get_settings
from osint_board.logging import get_logger
from osint_board.modules.http import HttpClient
from osint_board.modules.types import Content, Emit, EntityRef


class AuthorizationError(PermissionError):
    """Raised when an active module is invoked outside an authorised scope."""


@dataclass(slots=True)
class Scope:
    """What an investigation is allowed to touch actively (docs/10-security-legal.md)."""

    investigation_id: str | None = None
    allow_active: bool = False
    targets: list[str] = field(default_factory=list)  # domains / CIDRs authorised for active probing

    def permits_active(self, target: EntityRef) -> bool:
        if not self.allow_active:
            return False
        if not self.targets:
            return True
        return any(
            target.value == t or target.value.endswith("." + t) or _cidr_contains(t, target.value) for t in self.targets
        )


def _cidr_contains(cidr: str, value: str) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(value) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


@dataclass(slots=True)
class ModuleContext:
    spec: ModuleSpec
    settings: Settings = field(default_factory=get_settings)
    scope: Scope = field(default_factory=Scope)
    config: dict[str, Any] = field(default_factory=dict)  # per-module settings from the DB / env
    rate_per_sec: float = 5.0
    log: Any = field(init=False, default=None)
    http: HttpClient = field(init=False, default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.log = get_logger(f"module.{self.spec.id}")
        self.http = HttpClient(self.settings, self.spec.id, rate_per_sec=self.rate_per_sec)

    def secret(self, name: str = "API_KEY") -> str | None:
        return self.config.get(name.lower()) or self.settings.module_secret(self.spec.id, name)

    def require_secret(self, name: str = "API_KEY") -> str:
        value = self.secret(name)
        if not value:
            raise RuntimeError(
                f"module {self.spec.id} needs OSINT_MODULE_{self.spec.id.upper()}_{name.upper()} (see .env.example)"
            )
        return value

    def check_authorized(self, target: EntityRef) -> None:
        if self.spec.requires_authorization and not self.scope.permits_active(target):
            raise AuthorizationError(
                f"{self.spec.id} is an active module; {target.value} is not in an authorised scope"
            )


class BaseModule(ABC):
    #: catalog id this class implements; set by the ``@module("id")`` decorator
    module_id: ClassVar[str]
    #: default outbound request rate (overridable per deployment)
    rate_per_sec: ClassVar[float] = 5.0

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.spec = ctx.spec
        self.log = ctx.log

    async def setup(self) -> None:  # noqa: B027 - optional hook
        """Called once before the first run (validate keys, warm caches)."""


class LookupModule(BaseModule):
    @abstractmethod
    def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        """Enrich ``target``; ``target.type`` is guaranteed to be in ``spec.consumes``."""


class FeedModule(BaseModule):
    """Global data producer. Implement ``poll`` (pull on a cadence) and/or ``stream`` (push, long-lived)."""

    async def poll(self) -> AsyncIterator[Emit]:  # pragma: no cover - default is "no pull"
        return
        yield  # noqa: RUF027 - makes this an async generator

    async def stream(self) -> AsyncIterator[Emit]:  # pragma: no cover - default is "no push"
        return
        yield

    @property
    def is_streaming(self) -> bool:
        return type(self).stream is not FeedModule.stream


class ExtractModule(BaseModule):
    @abstractmethod
    def extract(self, content: Content) -> Iterable[Emit]:
        """Synchronous, CPU-bound scan over content."""
