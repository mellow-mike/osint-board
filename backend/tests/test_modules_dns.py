"""DNSBL, DNS-filter and OpenNIC modules against a fake resolver."""

from __future__ import annotations

import dns.resolver
import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.impl.opennic import parse_servers
from osint_board.modules.impl.project_honeypot import decode_httpbl
from osint_board.modules.impl.surbl import decode_bitmask

REF = "93.184.216.34"


async def test_dronebl_codes(fake_dns, run_lookup):
    fake_dns.on("7.113.0.203.dnsbl.dronebl.org", ["127.0.0.8", "127.0.0.13"])
    emits = await run_lookup("dronebl", "ip", "203.0.113.7")
    assert len(emits) == 1 and emits[0].type is EntityType.VERDICT
    assert (
        emits[0].meta["reasons"] == ["SOCKS proxy", "brute force attacker"]
        and emits[0].meta["zone"] == "dnsbl.dronebl.org"
    )
    assert await run_lookup("dronebl", "ip", "203.0.113.8") == []


async def test_dnsbl_netblock_enumerates_hosts(fake_dns, run_lookup):
    fake_dns.on("2.113.0.203.bl.spamcop.net", ["127.0.0.2"]).on("9.113.0.203.bl.spamcop.net", ["127.0.0.2"])
    emits = await run_lookup("spamcop", "netblock", "203.0.113.0/28")
    assert [e.meta["indicator"] for e in emits] == ["203.0.113.2", "203.0.113.9"]
    assert len(fake_dns.queries) == 14


async def test_spamhaus_error_codes_and_dqs(fake_dns, run_lookup):
    fake_dns.on("7.113.0.203.zen.spamhaus.org", ["127.0.0.2", "127.0.0.4"])
    fake_dns.on("8.113.0.203.zen.spamhaus.org", ["127.255.255.254"])
    fake_dns.on("7.113.0.203.mykey.zen.dq.spamhaus.net", ["127.0.0.10"])
    emits = await run_lookup("spamhaus_zen", "ip", "203.0.113.7")
    assert emits[0].meta["reasons"] == ["SBL (spam source)", "XBL (exploited host / CBL)"]
    assert await run_lookup("spamhaus_zen", "ip", "203.0.113.8") == []  # public-resolver error code, not a listing
    emits = await run_lookup("spamhaus_zen", "ip", "203.0.113.7", config={"api_key": "mykey"})
    assert emits[0].meta["reasons"] == ["PBL (ISP maintained policy block)"]


async def test_surbl_domain_and_ip(fake_dns, run_lookup):
    assert decode_bitmask(["127.0.0.24"]) == ["phishing (PH)", "malware (MW)"]
    fake_dns.on("bad.example.multi.surbl.org", ["127.0.0.8"]).on("7.113.0.203.multi.surbl.org", ["127.0.0.16"])
    emits = await run_lookup("surbl", "hostname", "www.bad.example")
    assert emits[0].meta["indicator"] == "bad.example" and emits[0].meta["reasons"] == ["phishing (PH)"]
    emits = await run_lookup("surbl", "ip", "203.0.113.7")
    assert emits[0].meta["reasons"] == ["malware (MW)"]
    fake_dns.on("blocked.example.multi.surbl.org", ["127.0.0.1"])
    assert await run_lookup("surbl", "domain", "blocked.example") == []


async def test_uceprotect_levels(fake_dns, run_lookup):
    fake_dns.on("7.113.0.203.dnsbl-1.uceprotect.net", ["127.0.0.2"]).on(
        "7.113.0.203.dnsbl-3.uceprotect.net", ["127.0.0.2"]
    )
    emits = await run_lookup("uceprotect", "ip", "203.0.113.7")
    assert [e.meta["list"] for e in emits] == ["level 1 (IP)", "level 3 (ASN)"]
    assert emits[0].value == "UCEPROTECT: 203.0.113.7 listed on level 1 (IP)"


async def test_project_honeypot(fake_dns, run_lookup, monkeypatch):
    assert decode_httpbl(["127.10.30.6"]) == {"types": ["harvester", "comment spammer"], "days": 10, "threat_score": 30}
    assert decode_httpbl(["127.0.1.0"])["types"] == ["search engine"]
    with pytest.raises(RuntimeError):
        await run_lookup("project_honeypot", "ip", "203.0.113.7")
    monkeypatch.setenv("OSINT_MODULE_PROJECT_HONEYPOT_API_KEY", "abcdefghijkl")
    fake_dns.on("abcdefghijkl.7.113.0.203.dnsbl.httpbl.org", ["127.10.30.6"]).on(
        "abcdefghijkl.8.113.0.203.dnsbl.httpbl.org", ["127.0.1.0"]
    )
    emits = await run_lookup("project_honeypot", "ip", "203.0.113.7")
    assert emits[0].meta["threat_score"] == 30 and emits[0].confidence == 0.65
    assert await run_lookup("project_honeypot", "ip", "203.0.113.8") == []  # search engines are not abuse


@pytest.mark.parametrize(
    ("module_id", "filter_server", "answer", "reason", "filter_name"),
    [
        ("cloudflare_dns", "1.1.1.2", ["0.0.0.0"], "sinkhole 0.0.0.0", "malware"),
        ("opendns", "208.67.222.123", ["146.112.61.106"], "sinkhole 146.112.61.106", "FamilyShield"),
        ("quad9", "9.9.9.9", None, "nxdomain", "secure"),
        ("adguard_dns", "94.140.14.15", ["0.0.0.0"], "sinkhole 0.0.0.0", "family"),
        ("cleanbrowsing", "185.228.168.10", None, "nxdomain", "adult"),
        ("dns_for_family", "94.130.180.225", None, "nxdomain", "default"),
        ("yandex_dns", "77.88.8.88", None, "nxdomain", "safe"),
        ("comodo_dns", "8.26.56.26", None, "nxdomain", "secure"),
    ],
)
async def test_dns_filters_block(fake_dns, run_lookup, registry, module_id, filter_server, answer, reason, filter_name):
    impl = registry.get(module_id).impl
    # the host resolves normally everywhere except on the filtering resolver under test
    for name, servers in impl.FILTERS.items():
        if name != filter_name:
            fake_dns.on("bad.example", [REF], nameserver=servers[0])
    if answer is not None:
        fake_dns.on("bad.example", answer, nameserver=filter_server)
    else:
        fake_dns.on("bad.example", nameserver=filter_server, raises=dns.resolver.NXDOMAIN)
    fake_dns.on("bad.example", [REF])  # reference / system resolver
    emits = await run_lookup(module_id, "hostname", "bad.example")
    assert len(emits) == 1, [e.meta for e in emits]
    v = emits[0]
    assert v.type is EntityType.VERDICT and v.meta["filter"] == filter_name and v.meta["reason"] == reason
    assert v.meta["category"] == "dns_filter" and v.value.endswith(f"blocked by {filter_name} filter")


async def test_dns_filter_not_blocked_and_unresolvable(fake_dns, run_lookup):
    fake_dns.on("good.example", [REF])
    assert await run_lookup("cloudflare_dns", "domain", "good.example") == []
    assert await run_lookup("cloudflare_dns", "url", "https://nxdomain.example/x") == []  # never reported


async def test_dns_filter_refused_counts_as_blocked(fake_dns, run_lookup):
    fake_dns.on(
        "bad.example",
        nameserver="9.9.9.9",
        raises=dns.resolver.NoNameservers,
        message="Server 9.9.9.9 UDP port 53 answered REFUSED",
    )
    fake_dns.on("bad.example", [REF])
    emits = await run_lookup("quad9", "domain", "bad.example")
    assert emits and emits[0].meta["reason"] == "refused"


async def test_opennic(fake_dns, fake_http, run_lookup):
    assert parse_servers([{"host": "ns1.example", "ip": "10.0.0.1"}, {"ip": "10.0.0.2"}, "10.0.0.2"]) == [
        "10.0.0.1",
        "10.0.0.2",
    ]
    fake_http.route("api.opennic.org", json_body=[{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}])
    fake_dns.on("wiki.geek", ["203.0.113.40"], nameserver="10.0.0.1").on(
        "wiki.geek", ["2001:db8::40"], rtype="AAAA", nameserver="10.0.0.1"
    )
    emits = await run_lookup("opennic", "hostname", "wiki.geek")
    assert [(e.type, e.value, e.meta["rrtype"]) for e in emits] == [
        (EntityType.IP, "203.0.113.40", "A"),
        (EntityType.IP, "2001:db8::40", "AAAA"),
    ]
    assert emits[0].relation == "resolves_to" and emits[0].meta["nameservers"] == ["10.0.0.1", "10.0.0.2"]
    fake_http.route("api.opennic.org", "down", status=500)
    emits = await run_lookup("opennic", "hostname", "wiki.geek", config={"nameservers": ["10.0.0.1"]})
    assert len(emits) == 2
