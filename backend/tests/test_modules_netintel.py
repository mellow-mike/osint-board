"""Registry, passive-DNS and host-intel API modules (ARIN, RIPEstat, BGPView, Robtex, HackerTarget, ...)."""

from __future__ import annotations

import json

import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.impl.arin import parse_nets, parse_poc, parse_refs
from osint_board.modules.impl.hackertarget import parse_hostsearch
from osint_board.modules.impl.ripe import parse_whois_records
from osint_board.modules.impl.robtex import parse_pdns as robtex_pdns
from osint_board.modules.impl.urlscan import search_query
from osint_board.modules.types import EntityRef


def _by_type(emits):
    out: dict[EntityType, list[str]] = {}
    for e in emits:
        out.setdefault(e.type, []).append(e.value)
    return out


def _load(fixtures_dir, name):
    return json.loads((fixtures_dir / "netintel" / name).read_text())


async def test_arin_ip_uses_rdap(fake_http, run_lookup):
    fake_http.route("rdap.arin.net/registry/ip/203.0.113.7", file="rdap_ip_arin.json")
    emits = _by_type(await run_lookup("arin", "ip", "203.0.113.7"))
    assert emits[EntityType.NETBLOCK] == ["203.0.113.0/24"] and emits[EntityType.COMPANY] == ["Example Networks LLC"]
    assert set(emits[EntityType.EMAIL]) == {"abuse@example.com", "jane.doe@example.com"} and emits[
        EntityType.PERSON
    ] == ["Jane Doe"]
    assert EntityType.WHOIS_RECORD not in emits  # not in the catalog's produces list for arin


async def test_arin_reverse_searches(fake_http, run_lookup, fixtures_dir):
    refs = parse_refs(_load(fixtures_dir, "arin_pocs.json"), "poc")
    assert refs == [("JDOE12-ARIN", "Doe, Jane"), ("ABUSE99-ARIN", "Abuse Desk")]
    poc = parse_poc(_load(fixtures_dir, "arin_poc.json"))
    assert poc["name"] == "Jane Doe" and poc["emails"] == ["jane.doe@example.com"]
    assert poc["address"] == "100 Main Street, Suite 4, Anytown, 90210, CA, UNITED STATES"
    assert parse_nets(_load(fixtures_dir, "arin_poc_nets.json"))[0]["cidrs"] == ["203.0.113.0/24"]
    fake_http.route("/rest/pocs;domain=example.com", file="netintel/arin_pocs.json")
    fake_http.route("/rest/poc/JDOE12-ARIN/nets", file="netintel/arin_poc_nets.json").route(
        "/rest/poc/ABUSE99-ARIN/nets", json_body={"nets": {}}
    )
    fake_http.route("/rest/poc/JDOE12-ARIN", file="netintel/arin_poc.json").route(
        "/rest/poc/ABUSE99-ARIN", "", status=404
    )
    emits = _by_type(await run_lookup("arin", "email", "someone@example.com"))
    assert emits[EntityType.PERSON] == ["Jane Doe"] and emits[EntityType.NETBLOCK] == ["203.0.113.0/24"]
    assert emits[EntityType.EMAIL] == ["jane.doe@example.com"] and emits[EntityType.COMPANY] == ["Example Networks LLC"]
    fake_http.route("/rest/orgs;name=Example", file="netintel/arin_orgs.json").route(
        "/rest/org/EXAMP/nets", file="netintel/arin_poc_nets.json"
    )
    fake_http.route("/rest/org/EXAMP/asns", file="netintel/arin_org_asns.json").route(
        "/rest/org/EXAMP", file="netintel/arin_org.json"
    )
    emits = _by_type(await run_lookup("arin", "company", "Example Networks"))
    assert emits[EntityType.ASN] == ["AS64500"] and emits[EntityType.NETBLOCK] == ["203.0.113.0/24"]
    assert emits[EntityType.PHYSICAL_ADDRESS] == ["100 Main Street, Anytown, 90210, CA, UNITED STATES"]


async def test_ripe_ip_and_asn(fake_http, run_lookup, fixtures_dir):
    fake_http.route("prefix-overview", file="netintel/ripestat_prefix_overview.json").route(
        "abuse-contact-finder", file="netintel/ripestat_abuse.json"
    )
    fake_http.route("/whois/", file="netintel/ripestat_whois.json")
    emits = await run_lookup("ripe", "ip", "203.0.113.7")
    by = _by_type(emits)
    assert by[EntityType.NETBLOCK][0] == "203.0.113.0/24" and by[EntityType.ASN] == ["AS64500"]
    assert by[EntityType.COMPANY] == ["Example Networks LLC"] and set(by[EntityType.EMAIL]) == {
        "abuse@example.com",
        "noc@example.com",
    }
    assert by[EntityType.PHYSICAL_ADDRESS] == ["100 Main Street, Anytown, US"]
    fake_http.route("as-overview", file="netintel/ripestat_as_overview.json").route(
        "announced-prefixes", file="netintel/ripestat_announced.json"
    )
    by = _by_type(await run_lookup("ripe", "asn", "AS64500"))
    assert by[EntityType.NETBLOCK][:2] == ["203.0.113.0/24", "2001:db8::/32"] and by[EntityType.COMPANY] == [
        "Example Networks LLC"
    ]
    whois = parse_whois_records(_load(fixtures_dir, "ripestat_whois.json"), EntityRef(EntityType.IP, "203.0.113.7"))
    assert [e.value for e in whois if e.type is EntityType.ASN] == ["AS64500"]


async def test_bgpview(fake_http, run_lookup):
    fake_http.route("/ip/203.0.113.7", file="netintel/bgpview_ip.json")
    by = _by_type(await run_lookup("bgpview", "ip", "203.0.113.7"))
    assert (
        by[EntityType.NETBLOCK] == ["203.0.113.0/24"]
        and by[EntityType.ASN] == ["AS64500"]
        and by[EntityType.COMPANY] == ["Example Networks LLC"]
    )
    fake_http.route("/asn/64500/prefixes", file="netintel/bgpview_asn_prefixes.json").route(
        "/asn/64500", file="netintel/bgpview_asn.json"
    )
    by = _by_type(await run_lookup("bgpview", "asn", "AS64500", config={"base_url": "https://mirror.example/"}))
    assert by[EntityType.NETBLOCK] == ["203.0.113.0/24", "2001:db8::/32"] and by[EntityType.COMPANY] == [
        "Example Networks LLC"
    ]
    assert fake_http.urls()[-1].startswith("https://mirror.example/asn/64500")


async def test_robtex(fake_http, run_lookup, fixtures_dir):
    fake_http.route("/ipquery/203.0.113.7", file="netintel/robtex_ipquery.json").route(
        "/pdns/reverse/203.0.113.7", file="netintel/robtex_pdns_reverse.txt"
    )
    by = _by_type(await run_lookup("robtex", "ip", "203.0.113.7"))
    assert by[EntityType.ASN] == ["AS64500"] and by[EntityType.NETBLOCK] == ["203.0.113.0/24"]
    assert set(by[EntityType.HOSTNAME]) == {
        "www.example.com",
        "mail.example.com",
        "old.example.com",
        "host7.example.com",
        "cdn.example.net",
    }
    fake_http.route("/pdns/forward/example.com", file="netintel/robtex_pdns_forward.txt")
    by = _by_type(await run_lookup("robtex", "domain", "example.com"))
    assert by[EntityType.IP] == ["203.0.113.7"] and by[EntityType.HOSTNAME] == ["ns1.example.net", "mx.example.org"]
    fake_http.route("/asquery/64500", file="netintel/robtex_asquery.json")
    assert _by_type(await run_lookup("robtex", "asn", "AS64500"))[EntityType.NETBLOCK] == [
        "203.0.113.0/24",
        "2001:db8::/32",
    ]
    emits = robtex_pdns(
        (fixtures_dir / "netintel/robtex_pdns_forward.txt").read_text(), EntityRef(EntityType.DOMAIN, "example.com")
    )
    assert emits[0].meta["last_seen"].year == 2025 and emits[1].relation == "ns_target"


async def test_hackertarget(fake_http, run_lookup, fixtures_dir):
    emits = parse_hostsearch(
        (fixtures_dir / "netintel/hackertarget_hostsearch.txt").read_text(),
        "example.com",
        EntityRef(EntityType.DOMAIN, "example.com"),
    )
    assert [(e.type.value, e.value) for e in emits][:3] == [
        ("hostname", "www.example.com"),
        ("ip", "203.0.113.7"),
        ("hostname", "mail.example.com"),
    ]
    assert not any(e.value == "notexample.com" for e in emits) and any(e.type is EntityType.DOMAIN for e in emits)
    fake_http.route("hostsearch", file="netintel/hackertarget_hostsearch.txt").route(
        "reverseiplookup", file="netintel/hackertarget_reverseip.txt"
    )
    by = _by_type(await run_lookup("hackertarget", "domain", "example.com", config={"api_key": "k"}))
    assert (
        set(by[EntityType.HOSTNAME]) == {"www.example.com", "mail.example.com"}
        and fake_http.calls[-1][2]["params"]["apikey"] == "k"
    )
    by = _by_type(await run_lookup("hackertarget", "ip", "203.0.113.7"))
    assert by[EntityType.HOSTNAME] == ["www.example.com", "cdn.example.net"]
    fake_http.routes.clear()
    fake_http.route("hostsearch", file="netintel/hackertarget_quota.txt")
    with pytest.raises(RuntimeError, match="API count exceeded"):
        await run_lookup("hackertarget", "domain", "example.com")


async def test_dnsdumpster(fake_http, run_lookup, monkeypatch):
    with pytest.raises(RuntimeError):
        await run_lookup("dnsdumpster", "domain", "example.com")
    monkeypatch.setenv("OSINT_MODULE_DNSDUMPSTER_API_KEY", "dd-key")
    fake_http.route("api.dnsdumpster.com/domain/example.com", file="netintel/dnsdumpster_domain.json")
    emits = await run_lookup("dnsdumpster", "domain", "example.com")
    by = _by_type(emits)
    assert set(by[EntityType.HOSTNAME]) == {
        "www.example.com",
        "blog.example.com",
        "mx.example.org",
        "ns1.example.com",
        "ghs.example.net",
    }
    assert by[EntityType.DOMAIN] == ["example.com"] and set(by[EntityType.IP]) == {
        "203.0.113.7",
        "198.51.100.5",
        "203.0.113.53",
    }
    ip = next(e for e in emits if e.type is EntityType.IP)
    assert ip.parent.value == "www.example.com" and ip.meta["asn"] == "AS64500"
    assert fake_http.calls[-1][2]["headers"]["X-API-Key"] == "dd-key"


async def test_mnemonic(fake_http, run_lookup):
    fake_http.route("/pdns/v3/example.com", file="netintel/mnemonic_pdns.json").route(
        "/pdns/v3/203.0.113.7", file="netintel/mnemonic_pdns_ip.json"
    )
    by = _by_type(await run_lookup("mnemonic_pdns", "domain", "example.com"))
    assert by[EntityType.IP] == ["203.0.113.7"] and by[EntityType.HOSTNAME] == ["ns1.example.net", "mx.example.org"]
    assert by[EntityType.DNS_RECORD][0] == "example.com A 203.0.113.7"
    by = _by_type(await run_lookup("mnemonic_pdns", "ip", "203.0.113.7"))
    assert by[EntityType.HOSTNAME] == ["www.example.com", "cdn.example.net"]


async def test_circl(fake_http, run_lookup, monkeypatch):
    with pytest.raises(RuntimeError):
        await run_lookup("circl_lu", "domain", "example.com")
    monkeypatch.setenv("OSINT_MODULE_CIRCL_LU_USERNAME", "u")
    monkeypatch.setenv("OSINT_MODULE_CIRCL_LU_PASSWORD", "p")
    fake_http.route("/pdns/query/example.com", file="netintel/circl_pdns.txt").route(
        "/pdns/query/203.0.113.7", file="netintel/circl_pdns.txt"
    )
    fake_http.route("/v2pssl/query/203.0.113.7", file="netintel/circl_pssl.json").route(
        "/v2pssl/cquery/3f786850e387550fdab836ed7e6dc881de23001b", file="netintel/circl_pssl_cert.json"
    )
    by = _by_type(await run_lookup("circl_lu", "domain", "example.com"))
    assert by[EntityType.IP] == ["203.0.113.7"] and by[EntityType.HOSTNAME] == ["ns1.example.net", "mx.example.org"]
    assert fake_http.calls[-1][2]["auth"] == ("u", "p")
    by = _by_type(await run_lookup("circl_lu", "ip", "203.0.113.7"))
    assert by[EntityType.CERTIFICATE] == ["sha1:3f786850e387550fdab836ed7e6dc881de23001b"] and by[
        EntityType.HOSTNAME
    ] == ["example.com"]
    by = _by_type(await run_lookup("circl_lu", "certificate", "sha1:3f786850e387550fdab836ed7e6dc881de23001b"))
    assert by[EntityType.IP] == ["203.0.113.7", "203.0.113.8"]


async def test_threatminer(fake_http, run_lookup):
    fake_http.route("domain.php?q=example.com&rt=2", file="netintel/threatminer_domain_pdns.json")
    fake_http.route("domain.php?q=example.com&rt=5", file="netintel/threatminer_subdomains.json")
    fake_http.route("domain.php?q=example.com&rt=6", file="netintel/threatminer_reports.json")
    by = _by_type(await run_lookup("threatminer", "domain", "example.com"))
    assert by[EntityType.IP] == ["203.0.113.7", "203.0.113.8"] and by[EntityType.HOSTNAME] == [
        "www.example.com",
        "dev.example.com",
    ]
    assert len(by[EntityType.VERDICT]) == 1
    fake_http.route("host.php?q=203.0.113.7&rt=2", file="netintel/threatminer_host_pdns.json")
    fake_http.route("host.php?q=203.0.113.7&rt=4", file="netintel/threatminer_samples.json")
    fake_http.route("host.php?q=203.0.113.7&rt=6", file="netintel/threatminer_none.json")
    by = _by_type(await run_lookup("threatminer", "ip", "203.0.113.7"))
    assert by[EntityType.HOSTNAME] == ["www.example.com"] and by[EntityType.HASH] == [
        "d41d8cd98f00b204e9800998ecf8427e"
    ]
    assert EntityType.VERDICT not in by
    fake_http.routes.clear()
    fake_http.route("threatminer", "down", status=503)
    with pytest.raises(RuntimeError):
        await run_lookup("threatminer", "email", "a@example.com")


async def test_leakix(fake_http, run_lookup, monkeypatch):
    monkeypatch.setenv("OSINT_MODULE_LEAKIX_API_KEY", "lk")
    fake_http.route("leakix.net/host/203.0.113.7", file="netintel/leakix_host.json")
    emits = await run_lookup("leakix", "ip", "203.0.113.7")
    by = _by_type(emits)
    assert by[EntityType.OPEN_PORT] == ["203.0.113.7:443", "203.0.113.7:22"] and by[EntityType.SOFTWARE] == [
        "nginx 1.18.0",
        "OpenSSH 8.9",
    ]
    geo = next(e for e in emits if e.type is EntityType.GEO_POINT)
    assert geo.geo.precision == "city" and geo.geo.lat == 37.75
    leak = next(e for e in emits if e.type is EntityType.BREACH_RECORD)
    assert leak.meta["severity"] == "high" and leak.meta["plugin"] == "ElasticSearchOpenPlugin"
    fake_http.route("leakix.net/domain/example.com", file="netintel/leakix_host.json").route(
        "api/subdomains/example.com", file="netintel/leakix_subdomains.json"
    )
    by = _by_type(await run_lookup("leakix", "domain", "example.com"))
    assert by[EntityType.HOSTNAME] == ["www.example.com", "dev.example.com"]


async def test_urlscan(fake_http, run_lookup):
    assert search_query(EntityRef(EntityType.IP, "203.0.113.7")) == "page.ip:203.0.113.7"
    assert search_query(EntityRef(EntityType.URL, "https://example.com/x")) == 'page.url:"https://example.com/x"'
    fake_http.route("/api/v1/search/", file="netintel/urlscan_search.json")
    fake_http.route("/result/11111111-2222-3333-4444-555555555555/", file="netintel/urlscan_result.json")
    fake_http.route("/result/66666666-7777-8888-9999-000000000000/", "", status=404)
    emits = await run_lookup("urlscan", "domain", "example.com", config={"api_key": "us"})
    by = _by_type(emits)
    assert by[EntityType.URL] == ["https://example.com/login", "https://cdn.example.net/x.js"]
    assert by[EntityType.HOSTNAME] == ["cdn.example.net"] and set(by[EntityType.IP]) == {"203.0.113.7", "198.51.100.9"}
    assert by[EntityType.SOFTWARE] == ["nginx/1.18.0", "cloudflare"]
    assert by[EntityType.VERDICT] == ["urlscan.io: https://example.com/login scan verdict malicious"]
    assert by[EntityType.HASH] == ["094fd325049b8a9cf6d3e5ef2a6d4cc52a93b13cf9c0e0c1e9fd8ee2a0ae0b7c"]
    assert (
        fake_http.calls[0][2]["params"]["q"] == "domain:example.com"
        and fake_http.calls[0][2]["headers"]["API-Key"] == "us"
    )
