"""Module registry: catalog spec + implementation class + status."""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from typing import Any, TypeVar

from osint_board.catalog import Catalog, ModuleSpec, load_catalog
from osint_board.config import Settings, get_settings
from osint_board.modules.base import BaseModule, FeedModule, ModuleContext, Scope

T = TypeVar("T", bound=type[BaseModule])

_IMPLEMENTATIONS: dict[str, type[BaseModule]] = {}


def module(module_id: str) -> Callable[[T], T]:
    """Class decorator binding an implementation to a catalog id."""

    def deco(cls: T) -> T:
        if module_id in _IMPLEMENTATIONS and _IMPLEMENTATIONS[module_id] is not cls:
            raise RuntimeError(f"module {module_id} implemented twice: {_IMPLEMENTATIONS[module_id]} and {cls}")
        cls.module_id = module_id
        _IMPLEMENTATIONS[module_id] = cls
        return cls

    return deco


class ModuleStatus(StrEnum):
    IMPLEMENTED = "implemented"
    PLANNED = "planned"
    RETIRED = "retired"  # defunct upstream; capability lives in a replacement service


@dataclass(frozen=True, slots=True)
class ModuleInfo:
    spec: ModuleSpec
    impl: type[BaseModule] | None

    @property
    def status(self) -> ModuleStatus:
        if self.impl is not None:
            return ModuleStatus.IMPLEMENTED
        if self.spec.is_retired:
            return ModuleStatus.RETIRED
        return ModuleStatus.PLANNED


class Registry:
    def __init__(
        self,
        catalog: Catalog,
        implementations: dict[str, type[BaseModule]] | None = None,
        *,
        settings: Settings | None = None,
    ) -> None:
        self.catalog = catalog
        self._impl = implementations if implementations is not None else _IMPLEMENTATIONS
        self.settings = settings  # None: the process settings (get_settings()) at instantiate time
        unknown = set(self._impl) - {m.id for m in catalog.modules}
        if unknown:
            raise RuntimeError(f"implementations without catalog entry: {sorted(unknown)}")

    @classmethod
    def discover(cls, catalog: Catalog | None = None) -> Registry:
        importlib.import_module("osint_board.modules.impl")
        return cls(catalog or load_catalog())

    def get(self, module_id: str) -> ModuleInfo:
        return ModuleInfo(self.catalog.module(module_id), self._impl.get(module_id))

    def all(self) -> list[ModuleInfo]:
        return [self.get(m.id) for m in self.catalog.modules]

    def implemented(self) -> list[ModuleInfo]:
        return [i for i in self.all() if i.impl is not None]

    def feeds(self) -> list[ModuleInfo]:
        """Feed modules, plus lookups whose implementation also polls on a catalog cadence (``tor_exit_nodes``)."""
        return [
            i
            for i in self.implemented()
            if i.spec.mode == "feed" or (i.spec.cadence and i.impl is not None and issubclass(i.impl, FeedModule))
        ]

    def for_input(self, entity_type: str, *, implemented_only: bool = True) -> list[ModuleInfo]:
        """Modules accepting ``entity_type``, ordered by catalog priority (high first) then id."""
        rank = {"high": 0, "normal": 1, "low": 2}
        found = [
            i
            for i in self.all()
            if entity_type in i.spec.consumes and (i.impl is not None or not implemented_only) and not i.spec.is_retired
        ]
        return sorted(found, key=lambda i: (rank.get(i.spec.priority, 1), i.spec.id))

    def module_config(self, module_id: str) -> dict[str, Any]:
        """Per-deployment options for ``module_id`` (``OSINT_MODULE_<ID>_CONFIG``, see :meth:`Settings.module_config`)."""
        return (self.settings or get_settings()).module_config(module_id)

    def instantiate(self, module_id: str, *, scope: Scope | None = None, config: dict | None = None) -> BaseModule:
        """Build ``module_id`` with its context. ``ctx.config`` is the deployment config
        (``OSINT_MODULE_<ID>_CONFIG``) overlaid with ``config`` (per run: the API, the worker, tests)."""
        info = self.get(module_id)
        if info.impl is None:
            raise LookupError(f"module {module_id} is {info.status.value}, not implemented")
        settings = self.settings or get_settings()
        ctx = ModuleContext(
            spec=info.spec,
            settings=settings,
            scope=scope or Scope(),
            config={**settings.module_config(module_id), **(config or {})},
            rate_per_sec=info.impl.rate_per_sec,
        )
        return info.impl(ctx)

    def coverage(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in ModuleStatus}
        for info in self.all():
            counts[info.status.value] += 1
        return counts

    def __iter__(self) -> Iterable[ModuleInfo]:
        return iter(self.all())


@lru_cache(maxsize=1)
def get_registry() -> Registry:
    return Registry.discover()
