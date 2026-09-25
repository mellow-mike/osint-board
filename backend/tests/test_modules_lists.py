"""List-based threat modules: every one is exercised offline through the shared list cache."""

from __future__ import annotations

import json

import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.impl.abuse_ch import parse_feodo, parse_malwarebazaar, parse_urlhaus
from osint_board.modules.impl.threatfox import parse_recent_csv, parse_search
from osint_board.modules.impl.tor_exit_nodes import parse_onionoo
from osint_board.modules.lists import CACHE
from osint_board.modules.types import EntityRef


@pytest.fixture(autouse=True)
def _fresh_cache():
    CACHE.clear()
    yield
    CACHE.clear()


def _verdicts(emits):
    return [e for e in emits if e.type is EntityType.VERDICT]


@pytest.mark.parametrize(
    ("module_id", "needle", "fixture", "etype", "value", "kind", "note"),
    [
        ("blocklist_de", "lists.blocklist.de", "lists/blocklist_de_all.txt", "ip", "203.0.113.7", "ip", None),
        (
            "blocklist_de",
            "lists.blocklist.de",
            "lists/blocklist_de_all.txt",
            "netblock",
            "203.0.113.0/24",
            "member",
            None,
        ),
        ("cins_army", "cinsscore.com", "lists/cins_ci_badguys.txt", "ip", "203.0.113.8", "ip", None),
        ("greensnow", "greensnow", "lists/blocklist_de_all.txt", "ip", "192.0.2.99", "ip", None),
        ("cleantalk", "firehol", "lists/cleantalk_7d.ipset", "ip", "203.0.113.9", "ip", None),
        (
            "coinblocker",
            "CoinBlockerLists",
            "lists/coinblocker_list.txt",
            "hostname",
            "miner.evil-example.net",
            "host",
            None,
        ),
        ("coinblocker", "CoinBlockerLists", "lists/coinblocker_list.txt", "domain", "evil-example.net", "member", None),
        ("botvrij", "botvrij.eu", "lists/botvrij_domain.txt", "domain", "bad-example.org", "host", "malware: Emotet"),
        (
            "stevenblack_hosts",
            "StevenBlack",
            "lists/stevenblack_hosts.txt",
            "hostname",
            "ads.bad-example.org",
            "host",
            None,
        ),
        (
            "openphish",
            "openphish",
            "lists/openphish_feed.txt",
            "url",
            "https://login.bad-example.org/secure/",
            "url",
            None,
        ),
        ("openphish", "openphish", "lists/openphish_feed.txt", "hostname", "login.bad-example.org", "host", None),
        (
            "phishstats",
            "phishstats",
            "lists/phishstats_score.csv",
            "ip",
            "198.51.100.23",
            "ip",
            "score 5.10 (2026-09-20 11:02:33)",
        ),
        (
            "vxvault",
            "vxvault",
            "lists/vxvault_urls.txt",
            "url",
            "http://malware.bad-example.org/dl/payload.exe",
            "url",
            None,
        ),
        ("voipbl", "voipbl", "lists/voipbl.txt", "ip", "203.0.113.77", "network", None),
        ("voipbl", "voipbl", "lists/voipbl.txt", "netblock", "198.51.100.0/24", "network", None),
        ("multiproxy", "multiproxy", "lists/multiproxy.txt", "ip", "203.0.113.7", "ip", "port 8080"),
        (
            "cybercrime_tracker",
            "cybercrime-tracker",
            "lists/cybercrime_all.txt",
            "hostname",
            "panel.bad-example.org",
            "host",
            "/gate.php",
        ),
        (
            "cybercrime_tracker",
            "cybercrime-tracker",
            "lists/cybercrime_all.txt",
            "ip",
            "198.51.100.23",
            "ip",
            "/admin/login.php",
        ),
        (
            "alienvault_iprep",
            "reputation.alienvault.com",
            "lists/alienvault_reputation.txt",
            "ip",
            "203.0.113.7",
            "ip",
            "Malicious Host US",
        ),
        ("emerging_threats", "emergingthreats", "lists/et_block_ips.txt", "ip", "203.0.113.50", "network", None),
    ],
)
async def test_list_modules_match(fake_http, run_lookup, module_id, needle, fixture, etype, value, kind, note):
    fake_http.route(needle, file=fixture)
    emits = await run_lookup(module_id, etype, value)
    verdicts = _verdicts(emits)
    assert verdicts, f"{module_id} produced no verdict for {value}"
    hit = next((v for v in verdicts if v.meta["match"] == kind), None)
    assert hit is not None, [v.meta for v in verdicts]
    assert hit.parent is not None and hit.relation == "flagged_by" and hit.meta["source"]
    if note:
        assert hit.meta["note"] == note
    assert all(v.value.startswith(v.meta["source"]) for v in verdicts)


async def test_list_module_no_match_and_cache(fake_http, run_lookup):
    fake_http.route("cinsscore.com", file="lists/cins_ci_badguys.txt")
    assert await run_lookup("cins_army", "ip", "192.0.2.1") == []
    assert await run_lookup("cins_army", "ip", "203.0.113.7")
    assert len(fake_http.urls()) == 1  # second lookup served from the process-wide cache


async def test_list_module_all_downloads_failed_raises(fake_http, run_lookup):
    fake_http.route("cinsscore.com", "gone", status=404)
    with pytest.raises(RuntimeError):
        await run_lookup("cins_army", "ip", "203.0.113.7")


async def test_emerging_threats_two_lists(fake_http, run_lookup):
    fake_http.route("compromised-ips", file="lists/et_compromised.txt").route(
        "emerging-Block-IPs", file="lists/et_block_ips.txt"
    )
    verdicts = _verdicts(await run_lookup("emerging_threats", "ip", "198.51.100.23"))
    assert {v.meta["list"] for v in verdicts} == {"compromised-ips", "emerging-Block-IPs"}


async def test_alienvault_falls_back_to_otx(fake_http, run_lookup, monkeypatch):
    monkeypatch.setenv("OSINT_MODULE_ALIENVAULT_OTX_API_KEY", "otx-key")
    fake_http.route("reputation.alienvault.com", "gone", status=404)
    fake_http.route(
        "otx.alienvault.com",
        json_body={"pulse_info": {"count": 2, "pulses": [{"name": "Scanner pulse"}, {"name": "C2"}]}, "reputation": 0},
    )
    verdicts = _verdicts(await run_lookup("alienvault_iprep", "ip", "203.0.113.7"))
    assert len(verdicts) == 1 and verdicts[0].meta["pulses"] == ["Scanner pulse", "C2"]
    assert fake_http.calls[-1][2]["headers"]["X-OTX-API-KEY"] == "otx-key"


def test_onionoo_parse(fixtures_dir):
    emits = parse_onionoo(json.loads((fixtures_dir / "lists/onionoo_details.json").read_text()))
    assert [e.key for e in emits] == [
        "tor:ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        "tor:0123456789ABCDEF0123456789ABCDEF01234567",
    ]
    exit_relay = emits[0]
    assert exit_relay.type is EntityType.TOR_RELAY and exit_relay.layer == "tor"
    assert exit_relay.geo and exit_relay.geo.precision == "city" and exit_relay.geo.lat == 52.52
    assert exit_relay.meta["relay_role"] == "exit" and exit_relay.meta["addresses"] == ["203.0.113.7", "2001:db8::7"]
    assert emits[1].meta["relay_role"] == "middle" and exit_relay.observed_at.year == 2026


def test_onionoo_without_coordinates_falls_back_to_the_country_centroid(fixtures_dir):
    """Onionoo dropped latitude/longitude/city_name; relays are placed at their country (a halo, never a pin)."""
    emits = parse_onionoo(json.loads((fixtures_dir / "lists/onionoo_country_only.json").read_text()))
    placed = {e.meta["nickname"]: e.geo for e in emits}
    assert placed["BaumiMiddleRelays"].precision == "country" and placed["BaumiMiddleRelays"].source.startswith(
        "onionoo"
    )
    assert (placed["luexit"].lat, placed["luexit"].lon) == (49.8, 6.1)
    assert placed["nowhere"] is None  # no country, no position: the sink skips it


async def test_tor_exit_lookup_and_poll(fake_http, run_lookup, run_poll):
    fake_http.route("torbulkexitlist", file="lists/tor_exit_list.txt").route(
        "onionoo.torproject.org", file="lists/onionoo_details.json"
    )
    emits = await run_lookup("tor_exit_nodes", "ip", "203.0.113.7")
    assert any(e.type is EntityType.VERDICT and e.meta["list"] == "bulk exit list" for e in emits)
    relays = [e for e in emits if e.type is EntityType.TOR_RELAY]
    assert relays and relays[0].relation == "runs" and relays[0].parent.value == "203.0.113.7"
    polled = await run_poll("tor_exit_nodes")
    assert len(polled) == 2 and all(e.layer == "tor" for e in polled)


def test_abuse_ch_parsers(fixtures_dir):
    feodo = parse_feodo((fixtures_dir / "lists/feodo_ipblocklist.json").read_text())
    assert "203.0.113.7" in feodo.ips and feodo.notes["203.0.113.7"] == "QakBot (online)"
    target = EntityRef(EntityType.DOMAIN, "bad-example.org")
    emits = parse_urlhaus(json.loads((fixtures_dir / "lists/urlhaus_host.json").read_text()), target)
    assert emits[0].type is EntityType.VERDICT and emits[0].meta["tags"] == ["Emotet", "doc", "exe"]
    assert [e.value for e in emits if e.type is EntityType.URL] == [
        "http://bad-example.org/dl/payload.exe",
        "http://bad-example.org/x.doc",
    ]
    assert parse_urlhaus({"query_status": "no_results"}, target) == []
    h = EntityRef(EntityType.HASH, "d41d8cd98f00b204e9800998ecf8427e")
    emits = parse_malwarebazaar(json.loads((fixtures_dir / "lists/malwarebazaar_hash.json").read_text()), h)
    assert emits[0].meta["signature"] == "AgentTesla"
    assert {e.value for e in emits if e.type is EntityType.HASH} == {
        "094fd325049b8a9cf6d3e5ef2a6d4cc52a93b13cf9c0e0c1e9fd8ee2a0ae0b7c",
        "3f786850e387550fdab836ed7e6dc881de23001b",
    }


async def test_abuse_ch_lookup_lists_and_api(fake_http, run_lookup):
    fake_http.route("text_online", file="lists/urlhaus_online.txt").route(
        "feodotracker", file="lists/feodo_ipblocklist.json"
    )
    fake_http.route("sslbl.abuse.ch", file="lists/sslbl_ips.csv").route(
        "urlhaus-api.abuse.ch/v1/host/", file="lists/urlhaus_host.json"
    )
    ip_verdicts = _verdicts(await run_lookup("abuse_ch", "ip", "198.51.100.23"))
    assert [v.meta["list"] for v in ip_verdicts] == ["SSL Blacklist"]
    with pytest.raises(RuntimeError):  # hashes need the API key
        await run_lookup("abuse_ch", "hash", "d41d8cd98f00b204e9800998ecf8427e")
    emits = await run_lookup("abuse_ch", "domain", "bad-example.org", config={"api_key": "k"})
    assert any(e.meta.get("list") == "URLhaus online" and e.meta["match"] == "member" for e in _verdicts(emits))
    assert any(e.meta.get("label") == "hosts malware URLs" for e in _verdicts(emits))
    post = next(c for c in fake_http.calls if c[0] == "POST")
    assert post[2]["headers"]["Auth-Key"] == "k" and post[2]["data"] == {"host": "bad-example.org"}


def test_threatfox_parsers(fixtures_dir):
    target = EntityRef(EntityType.IP, "203.0.113.7")
    emits = parse_search(json.loads((fixtures_dir / "lists/threatfox_search.json").read_text()), target)
    assert (
        emits[0].type is EntityType.VERDICT
        and emits[0].confidence == 0.95
        and emits[0].meta["indicator"] == "203.0.113.7:443"
    )
    assert [e.value for e in emits if e.type is EntityType.MALWARE_FAMILY] == ["Cobalt Strike"]
    lst = parse_recent_csv((fixtures_dir / "lists/threatfox_recent.csv").read_text())
    assert "203.0.113.7" in lst.ips and lst.notes["203.0.113.7"] == "Cobalt Strike (botnet_cc)"
    assert "bad-example.org" in lst.hosts


async def test_threatfox_lookup_without_and_with_key(fake_http, run_lookup):
    fake_http.route("export/csv/recent", file="lists/threatfox_recent.csv").route(
        "threatfox-api.abuse.ch", file="lists/threatfox_search.json"
    )
    emits = await run_lookup("threatfox", "domain", "bad-example.org")
    assert [e.value for e in emits if e.type is EntityType.MALWARE_FAMILY] == ["Emotet"]
    emits = await run_lookup("threatfox", "ip", "203.0.113.7", config={"api_key": "k"})
    assert fake_http.calls[-1][2]["json"] == {"query": "search_ioc", "search_term": "203.0.113.7"}
    assert [e.value for e in emits if e.type is EntityType.MALWARE_FAMILY] == ["Cobalt Strike"]
