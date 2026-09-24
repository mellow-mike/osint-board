from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest

os.environ.setdefault("OSINT_ENV", "test")
ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def catalog():
    from osint_board.catalog import load_catalog

    return load_catalog(ROOT / "catalog")


@pytest.fixture(scope="session")
def registry(catalog):
    from osint_board.modules.registry import Registry

    return Registry.discover(catalog)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@dataclass
class Route:
    needle: str
    body: bytes
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    method: str | None = None


class FakeHttp:
    """Routes ``HttpClient`` requests to canned responses so module ``lookup``/``poll`` run offline."""

    def __init__(self) -> None:
        self.routes: list[Route] = []
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def route(
        self,
        needle: str,
        body: str | bytes | None = None,
        *,
        file: str | None = None,
        json_body: Any = None,
        status: int = 200,
        headers: dict[str, str] | None = None,
        method: str | None = None,
    ) -> FakeHttp:
        if file is not None:
            data = (FIXTURES / file).read_bytes()
        elif json_body is not None:
            data = json.dumps(json_body).encode()
        elif isinstance(body, str):
            data = body.encode()
        else:
            data = body or b""
        self.routes.append(Route(needle, data, status, headers or {}, method))
        return self

    def respond(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        self.calls.append((method, url, kwargs))
        full = str(httpx.URL(url, params=kwargs["params"])) if kwargs.get("params") else url
        for r in self.routes:
            if r.needle in full and (r.method is None or r.method == method):
                headers = {"content-type": "application/json" if r.body[:1] in (b"{", b"[") else "text/plain"}
                headers.update(r.headers)
                return httpx.Response(r.status, content=r.body, headers=headers, request=httpx.Request(method, url))
        raise AssertionError(f"unrouted {method} {url}")

    def urls(self) -> list[str]:
        return [u for _, u, _ in self.calls]


@pytest.fixture
def fake_http(monkeypatch) -> FakeHttp:
    from osint_board.modules.http import HttpClient

    router = FakeHttp()

    async def fake_request(self, method, url, *, retries=3, tor=False, **kwargs):  # noqa: ANN001
        return router.respond(method, url, **kwargs)

    monkeypatch.setattr(HttpClient, "request", fake_request)
    return router


@pytest.fixture
def run_lookup(registry):
    """``await run_lookup("module_id", "ip", "203.0.113.7")`` → list of emissions, offline."""
    from osint_board.entities.types import EntityType
    from osint_board.modules.base import Scope
    from osint_board.modules.types import EntityRef

    async def _run(module_id: str, etype: str, value: str, *, config: dict | None = None, allow_active=False):
        mod = registry.instantiate(module_id, scope=Scope(allow_active=allow_active), config=config or {})
        target = EntityRef(EntityType(etype), value)
        await mod.setup()
        return [e async for e in mod.lookup(target)]

    return _run


@pytest.fixture
def run_poll(registry):
    async def _run(module_id: str, *, config: dict | None = None):
        mod = registry.instantiate(module_id, config=config or {})
        await mod.setup()
        return [e async for e in mod.poll()]

    return _run


class FakeAnswerRecord:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


@dataclass
class DnsRule:
    name: str
    records: list[str]
    rtype: str = "A"
    nameserver: str | None = None
    raises: type[Exception] | None = None
    message: str = ""


class FakeDns:
    """Answers ``dns.asyncresolver.Resolver.resolve`` from rules; unknown names are NXDOMAIN."""

    def __init__(self) -> None:
        self.rules: list[DnsRule] = []
        self.queries: list[tuple[str, str, list[str]]] = []

    def on(
        self,
        name: str,
        records: list[str] | None = None,
        *,
        rtype: str = "A",
        nameserver: str | None = None,
        raises=None,
        message: str = "",
    ) -> FakeDns:  # noqa: ANN001
        self.rules.append(DnsRule(name.rstrip(".").lower(), records or [], rtype, nameserver, raises, message))
        return self

    async def resolve(self, resolver, qname, rdtype="A", *args, **kwargs):  # noqa: ANN001
        import dns.rdatatype
        import dns.resolver

        name = str(qname).rstrip(".").lower()
        rtype = rdtype if isinstance(rdtype, str) else dns.rdatatype.to_text(rdtype)
        servers = list(getattr(resolver, "nameservers", []) or [])
        self.queries.append((name, rtype, servers))
        for rule in self.rules:
            if rule.name == name and rule.rtype == rtype and (rule.nameserver is None or rule.nameserver in servers):
                if rule.raises is not None:
                    raise rule.raises(rule.message) if rule.message else rule.raises()
                return [FakeAnswerRecord(r) for r in rule.records]
        raise dns.resolver.NXDOMAIN


@pytest.fixture
def fake_dns(monkeypatch) -> FakeDns:
    import dns.asyncresolver

    fake = FakeDns()

    async def resolve(self, qname, rdtype="A", *args, **kwargs):  # noqa: ANN001
        return await fake.resolve(self, qname, rdtype, *args, **kwargs)

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)
    return fake
