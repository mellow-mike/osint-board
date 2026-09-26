"""Phase-2 active internal recon modules: DNS brute force, zone transfer, TCP port scan, subdomain takeover,
plus the authorisation gate (OSINT_PASSIVE_ONLY) that guards the ones that probe a target.

Offline: DNS is answered by ``fake_dns``, HTTP by ``fake_http``, the zone transfer and the TCP connect are
mocked. No real network."""

from __future__ import annotations

import asyncio

import dns.zone
import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.base import AuthorizationError, Scope
from osint_board.modules.impl.dns_axfr import records_to_emits, zone_records
from osint_board.modules.impl.port_scanner import COMMON_PORTS, select_ports
from osint_board.modules.impl.subdomain_takeover import assess, cname_from_record, match_service
from osint_board.modules.types import EntityRef

DOMAIN = EntityRef(EntityType.DOMAIN, "example.com")


def _passive(mod, value: bool) -> None:
    """Force OSINT_PASSIVE_ONLY on a module's context regardless of the test environment."""
    mod.ctx.settings = mod.ctx.settings.model_copy(update={"passive_only": value})


# ---- authorisation gate --------------------------------------------------------------------------------------

def test_active_module_refused_without_scope(registry):
    mod = registry.instantiate("port_scanner", scope=Scope(allow_active=False))
    _passive(mod, True)
    with pytest.raises(AuthorizationError):
        mod.ctx.check_authorized(EntityRef(EntityType.IP, "203.0.113.5"))


def test_active_module_allowed_within_scope(registry):
    mod = registry.instantiate("port_scanner", scope=Scope(allow_active=True, targets=["203.0.113.0/24"]))
    _passive(mod, True)
    mod.ctx.check_authorized(EntityRef(EntityType.IP, "203.0.113.5"))  # in scope: no raise


def test_active_module_refused_outside_scope_targets(registry):
    mod = registry.instantiate("port_scanner", scope=Scope(allow_active=True, targets=["10.0.0.0/8"]))
    _passive(mod, True)
    with pytest.raises(AuthorizationError):
        mod.ctx.check_authorized(EntityRef(EntityType.IP, "203.0.113.5"))


def test_passive_only_off_bypasses_gate(registry):
    mod = registry.instantiate("port_scanner", scope=Scope(allow_active=False))
    _passive(mod, False)  # operator opted the whole instance into active scanning
    mod.ctx.check_authorized(EntityRef(EntityType.IP, "203.0.113.5"))  # no raise


@pytest.mark.parametrize("module_id", ["dns_bruteforce", "dns_axfr", "port_scanner"])
async def test_active_lookup_refuses_when_passive(registry, module_id):
    mod = registry.instantiate(module_id, scope=Scope(allow_active=False))
    _passive(mod, True)
    with pytest.raises(AuthorizationError):
        [e async for e in mod.lookup(DOMAIN if module_id != "port_scanner" else EntityRef(EntityType.IP, "203.0.113.5"))]


def test_subdomain_takeover_is_not_gated(registry, catalog):
    assert catalog.module("subdomain_takeover").requires_authorization is False
    assert catalog.module("dns_axfr").requires_authorization is True
    assert catalog.module("dns_bruteforce").requires_authorization is True


# ---- dns_bruteforce ------------------------------------------------------------------------------------------

async def test_dns_bruteforce_finds_hosts(registry, fake_dns):
    fake_dns.on("www.example.com", ["203.0.113.10"], rtype="A")
    fake_dns.on("mail.example.com", ["203.0.113.11"], rtype="A")
    mod = registry.instantiate("dns_bruteforce", scope=Scope(allow_active=True),
                               config={"wordlist": ["www", "mail", "absent"]})
    emits = [e async for e in mod.lookup(DOMAIN)]
    hosts = {e.value for e in emits if e.type is EntityType.HOSTNAME}
    ips = {e.value for e in emits if e.type is EntityType.IP}
    assert hosts == {"www.example.com", "mail.example.com"}
    assert ips == {"203.0.113.10", "203.0.113.11"}
    assert all(e.type in (EntityType.HOSTNAME, EntityType.IP) for e in emits)


async def test_dns_bruteforce_drops_wildcard_answers(registry, fake_dns):
    mod = registry.instantiate("dns_bruteforce", scope=Scope(allow_active=True),
                               config={"wordlist": ["ghost", "real"]})

    async def fake_wildcard(resolver, domain):  # noqa: ANN001
        return {"203.0.113.99"}

    mod._wildcard_ips = fake_wildcard
    fake_dns.on("ghost.example.com", ["203.0.113.99"], rtype="A")  # only the wildcard address -> dropped
    fake_dns.on("real.example.com", ["203.0.113.20"], rtype="A")   # a distinct address -> kept
    emits = [e async for e in mod.lookup(DOMAIN)]
    assert {e.value for e in emits if e.type is EntityType.HOSTNAME} == {"real.example.com"}


# ---- dns_axfr ------------------------------------------------------------------------------------------------

ZONE_TEXT = """\
@ 300 IN SOA ns1.example.com. admin.example.com. 1 2 3 4 5
@ 300 IN NS ns1.example.com.
@ 300 IN A 203.0.113.1
www 300 IN A 203.0.113.10
api 300 IN A 203.0.113.11
mail 300 IN CNAME www
"""


def _zone():
    return dns.zone.from_text(ZONE_TEXT, origin="example.com.")


def test_zone_records_and_emits():
    records = zone_records(_zone())
    kinds = {(n, t) for n, t, _ in records}
    assert ("www.example.com", "A") in kinds and ("mail.example.com", "CNAME") in kinds
    emits = records_to_emits(records, DOMAIN, "ns1/203.0.113.1")
    by_type = {}
    for e in emits:
        by_type.setdefault(e.type, set()).add(e.value)
    assert "203.0.113.10" in by_type[EntityType.IP]
    assert "www.example.com" in by_type[EntityType.HOSTNAME]
    assert any(v.startswith("www.example.com A ") for v in by_type[EntityType.DNS_RECORD])
    assert all(e.type in (EntityType.DNS_RECORD, EntityType.HOSTNAME, EntityType.IP) for e in emits)


async def test_dns_axfr_lookup_on_success(registry, fake_dns):
    fake_dns.on("example.com", ["ns1.example.com."], rtype="NS")
    fake_dns.on("ns1.example.com", ["203.0.113.1"], rtype="A")
    mod = registry.instantiate("dns_axfr", scope=Scope(allow_active=True))

    async def fake_fetch(server_ip, domain):  # noqa: ANN001
        assert server_ip == "203.0.113.1"
        return _zone()

    mod._fetch_zone = fake_fetch
    emits = [e async for e in mod.lookup(DOMAIN)]
    assert {e.value for e in emits if e.type is EntityType.IP} >= {"203.0.113.10", "203.0.113.11"}
    assert "www.example.com" in {e.value for e in emits if e.type is EntityType.HOSTNAME}


async def test_dns_axfr_lookup_when_refused(registry, fake_dns):
    fake_dns.on("example.com", ["ns1.example.com."], rtype="NS")
    fake_dns.on("ns1.example.com", ["203.0.113.1"], rtype="A")
    mod = registry.instantiate("dns_axfr", scope=Scope(allow_active=True))

    async def refused(server_ip, domain):  # noqa: ANN001
        return None

    mod._fetch_zone = refused
    assert [e async for e in mod.lookup(DOMAIN)] == []


# ---- port_scanner --------------------------------------------------------------------------------------------

def test_select_ports():
    assert select_ports({"ports": [443, 80, 80, 22]}) == [22, 80, 443]
    assert select_ports({"top": 3}) == list(COMMON_PORTS)[:3]
    assert select_ports({}) == list(COMMON_PORTS)


class _FakeWriter:
    def close(self):
        pass

    async def wait_closed(self):
        pass


async def test_port_scanner_reports_open_ports(registry, monkeypatch):
    open_ports = {22, 443}

    async def fake_open_connection(host, port):
        if port in open_ports:
            return object(), _FakeWriter()
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    mod = registry.instantiate("port_scanner", scope=Scope(allow_active=True),
                               config={"ports": [22, 80, 443], "timeout": 0.5})
    emits = [e async for e in mod.lookup(EntityRef(EntityType.IP, "203.0.113.5"))]
    assert {e.meta["port"] for e in emits} == {22, 443}
    assert all(e.type is EntityType.OPEN_PORT and e.meta["protocol"] == "tcp" for e in emits)
    assert {e.meta["service"] for e in emits} == {"ssh", "https"}


async def test_port_scanner_timeout_is_closed(registry, monkeypatch):
    async def always_hang(host, port):
        await asyncio.sleep(10)

    monkeypatch.setattr(asyncio, "open_connection", always_hang)
    mod = registry.instantiate("port_scanner", scope=Scope(allow_active=True),
                               config={"ports": [22], "timeout": 0.05})
    assert [e async for e in mod.lookup(EntityRef(EntityType.IP, "203.0.113.5"))] == []


# ---- subdomain_takeover --------------------------------------------------------------------------------------

def test_match_service_and_assess():
    assert match_service("abandoned.s3.amazonaws.com").name == "AWS S3"
    assert match_service("mysite.example.net") is None
    heroku = match_service("dead.herokuapp.com")
    assert assess(heroku, "nxdomain", None) == ("CNAME target is unregistered (Heroku)", 0.9)
    gh = match_service("user.github.io")
    assert assess(gh, "ok", "There isn't a GitHub Pages site here.")[1] == 0.95
    assert assess(gh, "ok", "<h1>Welcome to my blog</h1>") is None


def test_cname_from_record():
    assert cname_from_record("sub.example.com CNAME x.s3.amazonaws.com") == ("sub.example.com", "x.s3.amazonaws.com")
    assert cname_from_record("sub.example.com A 1.2.3.4") is None


async def test_subdomain_takeover_via_body(registry, fake_dns, fake_http):
    fake_dns.on("sub.example.com", ["abandoned.s3.amazonaws.com."], rtype="CNAME")
    fake_dns.on("abandoned.s3.amazonaws.com", ["52.216.1.1"], rtype="A")
    fake_http.route("sub.example.com", body="<Error><Code>NoSuchBucket</Code></Error>")
    mod = registry.instantiate("subdomain_takeover")
    emits = [e async for e in mod.lookup(EntityRef(EntityType.HOSTNAME, "sub.example.com"))]
    assert len(emits) == 1
    assert emits[0].type is EntityType.VULNERABILITY and emits[0].meta["service"] == "AWS S3"


async def test_subdomain_takeover_via_nxdomain(registry, fake_dns):
    fake_dns.on("app.example.com", ["dead.herokuapp.com."], rtype="CNAME")
    # no A rule for dead.herokuapp.com -> NXDOMAIN -> claimable without fetching
    mod = registry.instantiate("subdomain_takeover")
    emits = [e async for e in mod.lookup(EntityRef(EntityType.HOSTNAME, "app.example.com"))]
    assert [e.meta["service"] for e in emits] == ["Heroku"]


async def test_subdomain_takeover_live_site_is_clean(registry, fake_dns, fake_http):
    fake_dns.on("blog.example.com", ["user.github.io."], rtype="CNAME")
    fake_dns.on("user.github.io", ["185.199.108.153"], rtype="A")
    fake_http.route("blog.example.com", body="<html><body>Welcome to my blog</body></html>")
    mod = registry.instantiate("subdomain_takeover")
    assert [e async for e in mod.lookup(EntityRef(EntityType.HOSTNAME, "blog.example.com"))] == []


async def test_subdomain_takeover_from_dns_record(registry, fake_dns, fake_http):
    fake_dns.on("gone.myshopify.com", ["23.227.38.65"], rtype="A")  # CNAME target still resolves
    fake_http.route("shop.example.com", body="Sorry, this shop is currently unavailable")
    mod = registry.instantiate("subdomain_takeover")
    record = EntityRef(EntityType.DNS_RECORD, "shop.example.com CNAME gone.myshopify.com")
    emits = [e async for e in mod.lookup(record)]
    assert [e.meta["service"] for e in emits] == ["Shopify"]
