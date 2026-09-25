"""Shared module helpers: list parsing/matching, DNS interpretation, bucket permutations, RDAP parsing."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from osint_board.entities.types import EntityType
from osint_board.modules.buckets import classify, parse_listing, permutations
from osint_board.modules.dnsutil import DnsAnswer, classify_filtered, interpret_codes, reverse_labels
from osint_board.modules.helpers import (
    host_emit,
    host_of,
    host_ref,
    hosts_in,
    name_candidates,
    registrable_domain,
    to_datetime,
    verdict,
)
from osint_board.modules.lists import IndicatorList, match, parse_csv, parse_lines
from osint_board.modules.rdap import parse_rdap, rdap_path, record_emits
from osint_board.modules.types import EntityRef


def test_parse_lines_formats():
    text = "# comment\n; other\n0.0.0.0 ads.example.net\n127.0.0.1 localhost\n203.0.113.7 # trailing\n198.51.100.0/24\nhttps://x.example/p\nd41d8cd98f00b204e9800998ecf8427e\n"
    lst = parse_lines(text)
    assert lst.hosts == {"ads.example.net", "x.example"}
    assert lst.ips == {"203.0.113.7"} and [str(n) for n in lst.networks] == ["198.51.100.0/24"]
    assert lst.urls == {"https://x.example/p"} and lst.hashes == {"d41d8cd98f00b204e9800998ecf8427e"}
    assert parse_lines("a b c\nd e f\n", column=1).hosts == {"b", "e"}
    assert parse_csv('"h","x.example","note"\n"h","y.example","n2"\n', 1, note_column=2).notes["y.example"] == "n2"


def test_match_kinds():
    lst = IndicatorList()
    for token in ("203.0.113.7", "198.51.100.0/24", "bad.example", "sub.bad.example", "https://phish.example/login"):
        lst.add(token)
    assert [m.kind for m in match(lst, EntityType.IP, "203.0.113.7")] == ["ip"]
    assert [m.kind for m in match(lst, EntityType.IP, "198.51.100.9")] == ["network"]
    assert [m.kind for m in match(lst, EntityType.NETBLOCK, "203.0.113.0/24")] == ["member"]
    assert [m.kind for m in match(lst, EntityType.NETBLOCK, "198.51.0.0/16")] == ["network"]
    assert [m.kind for m in match(lst, EntityType.DOMAIN, "bad.example")] == ["host", "member"]
    assert [m.kind for m in match(lst, EntityType.HOSTNAME, "www.bad.example")] == ["parent_host"]
    assert [m.kind for m in match(lst, EntityType.URL, "https://phish.example/login")] == ["url", "url_host"]
    assert [m.kind for m in match(lst, EntityType.URL, "https://phish.example/login/extra")] == ["url", "url_host"]
    assert [m.kind for m in match(lst, EntityType.HOSTNAME, "phish.example")] == ["host"]
    assert match(lst, EntityType.IP, "192.0.2.1") == [] and match(lst, EntityType.HASH, "abc") == []


def test_dns_helpers():
    assert reverse_labels("203.0.113.7") == "7.113.0.203"
    assert reverse_labels("2001:db8::1").startswith("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2")
    assert interpret_codes(["127.0.0.2", "127.0.0.9"], {"127.0.0.2": "spam", "9": "proxy"}) == ["spam", "proxy"]
    assert interpret_codes(["127.0.1.4"], {}) == ["code 127.0.1.4"]
    ref = DnsAnswer("ok", ("93.184.216.34",))
    assert classify_filtered(DnsAnswer("nxdomain"), ref, ()) == "nxdomain"
    assert classify_filtered(DnsAnswer("ok", ("0.0.0.0",)), ref, ("0.0.0.0",)) == "sinkhole 0.0.0.0"
    assert (
        classify_filtered(DnsAnswer("ok", ("146.112.61.106",)), ref, ("146.112.61.0/24",)) == "sinkhole 146.112.61.106"
    )
    assert classify_filtered(DnsAnswer("ok", ("93.184.216.34",)), ref, ("0.0.0.0",)) is None
    assert classify_filtered(DnsAnswer("nxdomain"), DnsAnswer("nxdomain"), ()) is None
    assert classify_filtered(DnsAnswer("error"), ref, ()) is None


def test_bucket_helpers():
    names = permutations(["example"])
    assert names[0] == "example" and "example-backup" in names and "www-example" in names and "examplebackup" in names
    assert all(3 <= len(n) <= 63 for n in names) and len(permutations(["example"], limit=5)) == 5
    assert permutations(["Ex ample!"]) == []
    body = '<?xml version="1.0"?><ListBucketResult><Name>b</Name><Contents><Key>a.txt</Key></Contents><Contents><Key>b/c.pdf</Key></Contents></ListBucketResult>'
    assert classify(200, body) == "public" and parse_listing(body) == ["a.txt", "b/c.pdf"]
    assert classify(403, "") == "private" and classify(404, "") == "missing" and classify(301, "") == "private"
    assert classify(400, "<Code>InvalidBucketName</Code>") == "missing" and classify(200, "<html>") == "private"


def test_helpers_misc():
    assert (
        host_of("https://User@Example.com:8443/x") == "example.com"
        and host_of(EntityRef(EntityType.HOSTNAME, "A.B.example.")) == "a.b.example"
    )
    assert (
        registrable_domain("mail.example.co.uk") == "example.co.uk"
        and registrable_domain("203.0.113.7") == "203.0.113.7"
    )
    assert len(hosts_in("203.0.113.0/24")) == 254 and hosts_in("203.0.112.0/22", limit=10) == [
        f"203.0.112.{i}" for i in range(1, 11)
    ]
    assert hosts_in("203.0.113.7/32") == ["203.0.113.7"]
    v = verdict(EntityRef(EntityType.IP, "203.0.113.7"), "Src", label="listed", category="c", extra=None, note="n")
    assert (
        v.value == "Src: 203.0.113.7 listed"
        and v.relation == "flagged_by"
        and "extra" not in v.meta
        and v.meta["note"] == "n"
    )
    assert to_datetime(1700000000) == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)
    assert to_datetime("2026-09-20 11:02:33").tzinfo is UTC and to_datetime("2026-09-20T11:02:33Z").hour == 11
    assert (
        to_datetime("20240301") == datetime(2024, 3, 1, tzinfo=UTC)
        and to_datetime("nope") is None
        and to_datetime(None) is None
    )
    assert name_candidates(EntityRef(EntityType.DOMAIN, "example.co.uk"))[:2] == ["example", "example.co.uk"]
    assert name_candidates(EntityRef(EntityType.COMPANY, "Example Corp, Inc.")) == [
        "example",
        "examplecorpinc",
        "example-corp-inc",
    ]


def test_rdap_parse_and_emits(fixtures_dir):
    doc = json.loads((fixtures_dir / "rdap_ip_arin.json").read_text())
    rec = parse_rdap(doc)
    assert rec.object_class == "ip network" and rec.cidrs == ["203.0.113.0/24"] and rec.country == "US"
    assert rec.events["registration"].startswith("2010") and rec.remarks == ["Documentation prefix (TEST-NET-3)"]
    assert [c.handle for c in rec.contacts] == ["EXAMP-ARIN", "ABUSE99-ARIN", "JDOE12-ARIN"]
    assert rec.contacts[0].kind == "org" and rec.contacts[0].addresses == [
        "100 Main Street, Suite 4, Anytown, CA, 90210, United States"
    ]
    assert rec.contacts[1].emails == ["abuse@example.com"] and rec.contacts[1].phones == ["+1-555-0100"]
    target = EntityRef(EntityType.IP, "203.0.113.7")
    emits = record_emits(rec, target, "arin")
    by_type = {}
    for e in emits:
        by_type.setdefault(e.type, []).append(e.value)
    assert by_type[EntityType.NETBLOCK] == ["203.0.113.0/24"] and by_type[EntityType.COUNTRY] == ["US"]
    assert by_type[EntityType.COMPANY] == ["Example Networks LLC", "Example Networks LLC"]
    assert by_type[EntityType.PERSON] == ["Jane Doe"] and set(by_type[EntityType.EMAIL]) == {
        "abuse@example.com",
        "jane.doe@example.com",
    }
    assert by_type[EntityType.PHONE] == ["+1-555-0100"] and len(by_type[EntityType.PHYSICAL_ADDRESS]) == 2
    assert emits[0].type is EntityType.WHOIS_RECORD and emits[0].meta["range"] == "203.0.113.0 - 203.0.113.255"
    assert (
        rdap_path(EntityRef(EntityType.ASN, "AS64500")) == "/autnum/64500"
        and rdap_path(EntityRef(EntityType.EMAIL, "a@b")) is None
    )


def test_host_ref_matches_host_emit():
    target = EntityRef(EntityType.DOMAIN, "example.com")
    for host in ("example.com", "Mail.Example.com."):
        emitted = host_emit(host, "example.com", target)
        assert host_ref(host, "example.com") == EntityRef(emitted.type, emitted.value)
    email = verdict(
        EntityRef(EntityType.EMAIL, "a@example.com"), "src", label="disposable", etype=EntityType.EMAIL_VERDICT
    )
    assert email.type is EntityType.EMAIL_VERDICT and email.value == "src: a@example.com disposable"
