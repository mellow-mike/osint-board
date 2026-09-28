"""Phase-2 passive recon modules: look-alike domains, page analysis and non-standard headers.

Offline: the permutation engine and the page/header analysers are pure; DNS resolution for the look-alike
lookup is answered by ``fake_dns`` and page fetches by ``fake_http``. No real network."""

from __future__ import annotations

import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.base import Scope
from osint_board.modules.impl.cross_referencer import linked_sites
from osint_board.modules.impl.page_info import Form, analyze_page
from osint_board.modules.impl.similar_domains import permutations, split_domain
from osint_board.modules.impl.strange_headers import classify_header, is_standard, parse_header
from osint_board.modules.types import EntityRef

# ---- similar_domains: permutation engine (pure) --------------------------------------------------------------


def test_split_domain_uses_public_suffix_list():
    assert split_domain("mail.example.co.uk") == ("example", "co.uk")
    assert split_domain("https://www.example.com/path") == ("example", "com")
    assert split_domain("bareword") is None  # no registrable suffix


def test_permutations_cover_the_classic_fuzzers():
    perms = permutations("example.com")
    by_fuzzer: dict[str, set[str]] = {}
    for p in perms:
        by_fuzzer.setdefault(p.fuzzer, set()).add(p.domain)

    assert "example.com" not in {p.domain for p in perms}  # the original is never a "similar" domain
    assert "exampl.com" in by_fuzzer["omission"]
    assert "examples.com" in by_fuzzer["addition"]
    assert "eample.com" not in perms  # sanity: omission removed exactly one char, kept the rest
    assert "example.net" in by_fuzzer["tld-swap"] and "example.com" not in by_fuzzer["tld-swap"]
    assert any(d.count(".") == 2 for d in by_fuzzer["subdomain"])  # a dot was inserted into the name
    assert {"omission", "addition", "transposition", "repetition", "replacement", "insertion", "tld-swap"} <= set(
        by_fuzzer
    )


def test_permutations_are_valid_hostnames_and_deduped():
    perms = permutations("example.com")
    domains = [p.domain for p in perms]
    assert len(domains) == len(set(domains))  # deduped across fuzzers
    for d in domains:
        for label in d.split("."):
            assert label and not label.startswith("-") and not label.endswith("-")
            assert set(label) <= set("abcdefghijklmnopqrstuvwxyz0123456789-")


def test_permutations_of_unresolvable_input_is_empty():
    assert permutations("bareword") == []


def test_bitsquatting_flips_every_bit_of_every_character():
    domains = {p.domain for p in permutations("example.com")}
    name, expected = "example", set()
    for i, ch in enumerate(name):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if flipped in "abcdefghijklmnopqrstuvwxyz0123456789-":
                expected.add(f"{name[:i]}{flipped}{name[i + 1 :]}.com")
    assert len(expected) > 20 and expected <= domains
    bitsquats = {p.domain for p in permutations("example.com") if p.fuzzer == "bitsquatting"}
    assert {"gxample.com", "mxample.com"} <= bitsquats  # 'e' ^ 0x02, 'e' ^ 0x08: no other fuzzer reaches them


def test_tld_swaps_come_first_so_a_candidate_cap_keeps_them():
    perms = permutations("internationalbusinessmachines.com")
    swaps = [p for p in perms if p.fuzzer == "tld-swap"]
    assert len(perms) > 600 and perms[: len(swaps)] == swaps


async def test_similar_domains_reports_registered_lookalikes(registry, fake_dns):
    fake_dns.on("examples.com", ["203.0.113.9"], rtype="A")  # a resolvable look-alike (addition)
    fake_dns.on("example.net", ["ns1.parking.example"], rtype="NS")  # parked: NS only, no address
    mod = registry.instantiate("similar_domains", scope=Scope())
    emits = [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "example.com"))]

    similar = {e.value: e for e in emits if e.type is EntityType.SIMILAR_DOMAIN}
    assert set(similar) == {"examples.com", "example.net"}  # only the ones that exist
    assert similar["examples.com"].meta["registered"] and similar["examples.com"].meta["addresses"] == ["203.0.113.9"]
    assert similar["example.net"].meta["fuzzer"] == "tld-swap" and similar["example.net"].meta["addresses"] == []

    # a resolvable look-alike is also emitted as a pivotable domain; the parked (NS-only) one is not
    domains = {e.value for e in emits if e.type is EntityType.DOMAIN}
    assert domains == {"examples.com"}


async def test_similar_domains_emit_all_includes_unregistered(registry, fake_dns):
    fake_dns.on("examples.com", ["203.0.113.9"], rtype="A")
    mod = registry.instantiate("similar_domains", scope=Scope(), config={"emit_all": True})
    emits = [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "example.com"))]
    similar = {e.value: e for e in emits if e.type is EntityType.SIMILAR_DOMAIN}
    assert "exampl.com" in similar and similar["exampl.com"].meta["registered"] is False
    assert similar["exampl.com"].confidence < similar["examples.com"].confidence


async def test_similar_domains_stops_at_nxdomain(registry, fake_dns):
    mod = registry.instantiate("similar_domains", scope=Scope())
    assert [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "example.com"))] == []
    asked = [rtype for name, rtype, _ in fake_dns.queries if name == "exampl.com"]
    assert asked == ["A"]  # NXDOMAIN answers for the name, so AAAA and NS are not asked


async def test_similar_domains_does_not_call_a_failed_lookup_unregistered(registry, fake_dns):
    import dns.exception

    for rtype in ("A", "AAAA", "NS"):
        fake_dns.on("exampl.com", rtype=rtype, raises=dns.exception.Timeout)
    mod = registry.instantiate("similar_domains", scope=Scope(), config={"emit_all": True})
    similar = {e.value for e in [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "example.com"))]}
    assert "exampl.com" not in similar and "exmple.com" in similar  # timed out: unknown, not free to register


async def test_similar_domains_subdomain_split_pivots_on_its_registrable_domain(registry, fake_dns):
    fake_dns.on("exa.mple.com", ["203.0.113.10"], rtype="A")
    mod = registry.instantiate("similar_domains", scope=Scope())
    emits = [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "example.com"))]
    assert {e.value: e.meta["fuzzer"] for e in emits if e.type is EntityType.SIMILAR_DOMAIN} == {
        "exa.mple.com": "subdomain"
    }
    assert {e.value for e in emits if e.type is EntityType.DOMAIN} == {"mple.com"}  # not the host exa.mple.com


# ---- page_info: analyser (pure) + lookup dispatch ------------------------------------------------------------


def test_analyze_page_reads_forms_and_embeds(fixtures_dir):
    html = (fixtures_dir / "web" / "page_info_login.html").read_text()
    info = analyze_page(html, "https://site.example/login")

    assert info.title == "Members — Sign in"
    assert info.takes_passwords and info.has_login_form and info.has_upload_form
    assert info.generator == "WordPress 6.4.2" and info.meta_refresh == "/dashboard"
    assert info.external_form_hosts == ["auth.partner.example", "uploads.plain.example"]
    assert info.insecure_password_form is False  # the password form posts over https
    assert info.frame_hosts == ["widgets.thirdparty.net"]
    assert info.legacy_plugins == ["object"]
    assert info.external_scripts == 1  # the third-party script only; the local one does not count
    assert info.comment_count == 1
    assert set(info.summary()["flags"]) == {
        "password",
        "login",
        "upload",
        "external-form",
        "meta-refresh",
        "legacy-plugin",
    }


def test_analyze_page_flags_credentials_over_http():
    html = '<form method=post action="/login"><input type=password name=p></form>'
    info = analyze_page(html, "http://insecure.example/login")
    assert info.takes_passwords and info.insecure_password_form
    assert "insecure-credentials" in info.summary()["flags"]


def test_analyze_page_flags_an_http_page_posting_passwords_to_https():
    html = '<form method=post action="https://secure.example/login"><input type=password name=p></form>'
    assert analyze_page(html, "http://insecure.example/login").insecure_password_form  # the page can be rewritten


def test_analyze_page_sees_password_fields_outside_a_form():
    html = "<div id=app><input type=email name=user><input type=password name=pass><button>Go</button></div>"
    info = analyze_page(html, "http://spa.example/")
    assert info.forms == [] and info.takes_passwords and info.has_login_form and info.insecure_password_form


def test_analyze_page_treats_the_same_site_as_first_party():
    html = (
        '<form action="https://login.example.com/session"><input name=u><input type=password name=p></form>'
        '<iframe src="https://cdn.example.com/widget"></iframe><iframe src="https://widgets.other.net/x"></iframe>'
        '<script src="https://static.example.com/app.js"></script>'
    )
    info = analyze_page(html, "https://www.example.com/")
    assert info.external_form_hosts == [] and info.frame_hosts == ["widgets.other.net"] and info.external_scripts == 0


def test_analyze_page_resolves_relative_urls_against_base_href():
    html = (
        '<base href="http://external.example/">'
        '<form action="login"><input name=u><input type=password name=p></form>'
        '<script src="app.js"></script><iframe src="widget"></iframe>'
    )
    info = analyze_page(html, "https://site.example/")
    # the relative action submits to http://external.example/login: another site, over plain HTTP
    assert info.external_form_hosts == ["external.example"] and info.insecure_password_form
    assert info.external_scripts == 1 and info.frame_hosts == ["external.example"]


def test_analyze_page_survives_malformed_urls():
    html = (
        '<base href="http://[bad"><form action="http://[x"><input type=password></form>'
        '<iframe src="http://[y"></iframe><script src="data:text/javascript,1"></script>'
    )
    info = analyze_page(html, "https://site.example/")  # urljoin raises ValueError on these
    assert info.takes_passwords and info.external_form_hosts == [] and info.frame_hosts == []
    assert info.external_scripts == 0


def test_login_form_needs_a_username_field():
    assert Form(has_password=True, inputs=["password"]).is_login is False
    assert Form(has_password=True, inputs=["text", "password"]).is_login is True


async def test_page_info_lookup_over_raw_content(registry):
    mod = registry.instantiate("page_info", scope=Scope())
    target = EntityRef(
        EntityType.RAW_CONTENT,
        "https://site.example/login",
        meta={"text": "<title>Hi</title><form><input type=password></form>", "url": "https://site.example/login"},
    )
    emits = [e async for e in mod.lookup(target)]
    assert len(emits) == 1 and emits[0].type is EntityType.PAGE_INFO
    assert emits[0].meta["takes_passwords"] is True and emits[0].meta["source"] == "page_info"


async def test_page_info_lookup_fetches_a_url(registry, fake_http, fixtures_dir):
    fake_http.route(
        "site.example/login",
        body=(fixtures_dir / "web" / "page_info_login.html").read_text(),
        headers={"content-type": "text/html; charset=utf-8"},
    )
    mod = registry.instantiate("page_info", scope=Scope())
    emits = [e async for e in mod.lookup(EntityRef(EntityType.URL, "https://site.example/login"))]
    assert len(emits) == 1 and emits[0].meta["has_login_form"] is True


async def test_page_info_fetches_raw_content_that_arrives_without_its_text(registry, fake_http, fixtures_dir):
    # the API and CLI hand a lookup only (type, value); a spider page's value is its URL
    fake_http.route(
        "site.example/login",
        body=(fixtures_dir / "web" / "page_info_login.html").read_text(),
        headers={"content-type": "text/html"},
    )
    mod = registry.instantiate("page_info", scope=Scope())
    emits = [e async for e in mod.lookup(EntityRef(EntityType.RAW_CONTENT, "https://site.example/login"))]
    assert len(emits) == 1 and emits[0].meta["has_login_form"] is True

    blob = EntityRef(EntityType.RAW_CONTENT, "base64:3f2a")  # decoded content: nothing to fetch
    assert [e async for e in mod.lookup(blob)] == []
    assert len(fake_http.calls) == 1


async def test_page_info_skips_server_error_pages(registry, fake_http):
    fake_http.route("site.example", body="<h1>502 Bad Gateway</h1>", status=502, headers={"content-type": "text/html"})
    mod = registry.instantiate("page_info", scope=Scope())
    assert [e async for e in mod.lookup(EntityRef(EntityType.URL, "https://site.example/"))] == []


# ---- strange_headers: classifier (pure) + lookup ------------------------------------------------------------


def test_is_standard_knows_the_registered_field_set():
    assert is_standard("Content-Type") and is_standard("strict-transport-security")
    assert not is_standard("X-Backend-Server")


@pytest.mark.parametrize(
    ("name", "value", "category", "leak"),
    [
        ("Content-Type", "text/html", None, None),
        ("Strict-Transport-Security", "max-age=1", None, None),
        ("X-Custom-Flag", "yes", "custom", False),
        ("X-Backend-Server", "web03.internal", "information-leak", True),
        ("X-Upstream-Addr", "10.0.0.5:8080", "information-leak", True),
        ("X-Debug-Token", "abc123", "debug", True),
        ("X-Powered-By", "PHP/8.1.2", "information-leak", True),
        ("X-Served-By", "cache-lax-1", "backend-fingerprint", True),
        ("X-Cache", "HIT", "backend-fingerprint", False),
        ("Public-Key-Pins", 'pin-sha256="abc"; max-age=10', None, None),  # registered, just rare
        # addresses anywhere in the value, not only as a whole token
        ("X-Origin", "for=10.1.2.3;proto=https", "information-leak", True),
        ("X-Origin", "[fd00::1]:8443", "information-leak", True),
        # whole words: a device header is not a "dev" switch, nor a build header a "test" one
        ("X-Device-Type", "desktop", "custom", False),
        ("X-Latest-Build", "yes", "custom", False),
        ("X-MiniProfiler-Ids", '["a1"]', "debug", True),
        # tracing / correlation ids name a request, they are not debug output
        ("X-Amzn-Trace-Id", "Root=1-5f84c7a9-0123456789abcdef01234567", "backend-fingerprint", False),
        ("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "backend-fingerprint", False),
        # a timing or a rate is not a software version; a product/version or a version header is
        ("X-Response-Time", "0.123", "custom", False),
        ("X-Ratelimit-Reset", "1695812345.5", "custom", False),
        ("X-AspNet-Version", "4.0.30319", "information-leak", True),
        ("X-AspNetMvc-Version", "5.2", "information-leak", True),
        ("Proxy-Status", "ExampleCDN; error=http_protocol_error", None, None),  # RFC 9209
        # internal means internal ranges, not ipaddress.is_private (which covers the public documentation nets)
        ("X-Origin", "203.0.113.7", "custom", False),
        ("X-Origin", "100.64.1.2", "information-leak", True),  # carrier-grade NAT
        ("X-Origin", "::ffff:10.0.0.5", "information-leak", True),
    ],
)
def test_classify_header(name, value, category, leak):
    result = classify_header(name, value)
    if category is None:
        assert result is None
    else:
        assert result.category == category and result.info_leak is leak


def test_parse_header_prefers_meta_then_falls_back_to_text():
    meta_ref = EntityRef(EntityType.HTTP_HEADER, "X-Foo: bar", meta={"name": "X-Foo", "value": "bar"})
    assert parse_header(meta_ref) == ("x-foo", "bar")
    text_ref = EntityRef(EntityType.HTTP_HEADER, "X-Foo: bar")
    assert parse_header(text_ref) == ("x-foo", "bar")


async def test_strange_headers_lookup_emits_only_for_odd_headers(registry):
    mod = registry.instantiate("strange_headers", scope=Scope())
    strange = EntityRef(
        EntityType.HTTP_HEADER,
        "X-Backend-Server: web03.internal",
        meta={"name": "x-backend-server", "value": "web03.internal", "host": "site.example"},
    )
    emits = [e async for e in mod.lookup(strange)]
    assert len(emits) == 1
    e = emits[0]
    assert e.type is EntityType.HTTP_HEADER and e.meta["category"] == "information-leak"
    assert e.meta["info_leak"] is True and e.meta["host"] == "site.example"
    # the header itself is annotated: same entity, no header --exposes--> header self-loop
    assert e.value == strange.value and e.relation is None

    # an API run passes only the value; the spider's host / url must not be overwritten with nulls
    (bare,) = [e async for e in mod.lookup(EntityRef(EntityType.HTTP_HEADER, "X-Backend-Server: web03.internal"))]
    assert bare.meta["category"] == "information-leak" and "host" not in bare.meta and "url" not in bare.meta

    normal = EntityRef(
        EntityType.HTTP_HEADER, "Content-Type: text/html", meta={"name": "content-type", "value": "text/html"}
    )
    assert [e async for e in mod.lookup(normal)] == []


# ---- dns_srv: SRV service discovery (pure name/rdata parsing + fake_dns lookup) ------------------------------

from osint_board.modules.impl.dns_srv import COMMON_SRV, parse_srv, srv_names  # noqa: E402


def test_srv_names_are_fully_qualified_and_deduped():
    names = srv_names("Example.com", services=("_sip._tcp", "_sip._tcp", "_ldap._tcp.dc._msdcs"))
    assert names == ["_sip._tcp.example.com", "_ldap._tcp.dc._msdcs.example.com"]  # deduped, lower-cased
    assert srv_names("https://example.com/path")[0].endswith(".example.com")  # host_of a URL target


def test_parse_srv_reads_priority_weight_port_target():
    rec = parse_srv("10 60 5060 sip.example.com.")
    assert (rec.priority, rec.weight, rec.port, rec.target) == (10, 60, 5060, "sip.example.com")


@pytest.mark.parametrize(
    "rdata",
    ["0 0 0 .", "10 60 5060", "a b c d", "10 60 99999 host.example.com", "10 60 -1 host.example.com"],
)
def test_parse_srv_rejects_malformed_and_no_service_records(rdata):
    assert parse_srv(rdata) is None  # "." target (no such service), wrong arity, non-numeric, out-of-range port


async def test_dns_srv_reports_records_targets_and_addresses(registry, fake_dns):
    fake_dns.on("_sip._tcp.example.com", ["10 60 5060 sip.example.com", "20 0 5060 backup.example.com"], rtype="SRV")
    fake_dns.on("_autodiscover._tcp.example.com", ["0 0 0 ."], rtype="SRV")  # advertised as "not offered"
    fake_dns.on("sip.example.com", ["203.0.113.20"], rtype="A")
    fake_dns.on("sip.example.com", ["2001:db8::20"], rtype="AAAA")
    mod = registry.instantiate("dns_srv", scope=Scope())
    emits = [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "example.com"))]

    records = [e for e in emits if e.type is EntityType.DNS_RECORD]
    assert {e.meta["target"] for e in records} == {"sip.example.com", "backup.example.com"}
    assert all(e.meta["service"] == "_sip._tcp" and e.meta["rrtype"] == "SRV" for e in records)
    assert not any(r.meta.get("service") == "_autodiscover._tcp" for r in records)  # "." target dropped

    hosts = {e.value: e for e in emits if e.type is EntityType.HOSTNAME}
    assert set(hosts) == {"sip.example.com", "backup.example.com"}
    assert hosts["sip.example.com"].meta["port"] == 5060 and hosts["sip.example.com"].relation == "srv_target"

    # only the target that resolves contributes addresses, and each SRV target is resolved once
    ips = {e.value for e in emits if e.type is EntityType.IP}
    assert ips == {"203.0.113.20", "2001:db8::20"}


async def test_dns_srv_quiet_when_nothing_is_published(registry, fake_dns):
    mod = registry.instantiate("dns_srv", scope=Scope())
    assert [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "example.com"))] == []
    assert len(COMMON_SRV) > 40  # the shipped list is substantial


# ---- tld_searcher: same name under other TLDs (pure candidate/list parsing + fake_dns lookup) ----------------

from osint_board.modules.impl.tld_searcher import parse_iana_tlds, tld_candidates  # noqa: E402


def test_parse_iana_tlds_folds_case_and_drops_the_comment():
    text = "# Version 2024010100\nCOM\nNET\nXN--P1AI\nnet\n"
    assert parse_iana_tlds(text) == ["com", "net", "xn--p1ai"]  # lower-cased, comment gone, deduped


def test_tld_candidates_skip_own_suffix_and_dedupe_case():
    assert tld_candidates("example.com", ["net", "org", "com", "COM"]) == ["example.net", "example.org"]
    assert tld_candidates("mail.example.co.uk", ["com", "net"]) == ["example.com", "example.net"]  # bare name
    assert tld_candidates("example.com", ["a", "b", "c"], max_tlds=2) == ["example.a", "example.b"]
    assert tld_candidates("bareword", ["com"]) == []  # no registrable name


async def test_tld_searcher_reports_registered_names(registry, fake_dns):
    fake_dns.on("example.net", ["203.0.113.30"], rtype="A")
    fake_dns.on("example.io", ["ns1.parking.example"], rtype="NS")  # exists but parked (no address)
    mod = registry.instantiate("tld_searcher", scope=Scope(), config={"tlds": ["net", "org", "io"]})
    emits = [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "example.com"))]
    assert {e.value for e in emits} == {"example.net"}  # org is NXDOMAIN, io has no address
    assert emits[0].type is EntityType.DOMAIN and emits[0].meta["addresses"] == ["203.0.113.30"]


async def test_tld_searcher_include_parked_adds_ns_only_names(registry, fake_dns):
    fake_dns.on("example.net", ["203.0.113.30"], rtype="A")
    fake_dns.on("example.io", ["ns1.parking.example"], rtype="NS")
    mod = registry.instantiate("tld_searcher", scope=Scope(), config={"tlds": ["net", "io"], "include_parked": True})
    got = {e.value: e for e in [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "example.com"))]}
    assert set(got) == {"example.net", "example.io"}
    assert got["example.io"].meta["parked"] is True and got["example.net"].meta["parked"] is False


# ---- dns_lookaside: reverse-resolve neighbouring addresses (pure walk + fake_dns PTR lookup) -----------------

import dns.reversename  # noqa: E402

from osint_board.modules.impl.dns_lookaside import neighbor_ips  # noqa: E402


def _rev(ip: str) -> str:
    return dns.reversename.from_address(ip).to_text().rstrip(".")


def test_neighbor_ips_walks_outward_and_excludes_the_target():
    assert neighbor_ips("203.0.113.10", span=2) == ["203.0.113.9", "203.0.113.11", "203.0.113.8", "203.0.113.12"]
    assert "203.0.113.10" not in neighbor_ips("203.0.113.10", span=5)


def test_neighbor_ips_stays_inside_the_target_slash_24():
    neighbors = neighbor_ips("203.0.113.1", span=3)
    assert all(n.startswith("203.0.113.") for n in neighbors)  # never crosses into 203.0.112.x
    assert "203.0.113.0" in neighbors  # the network address is still a real neighbour


def test_neighbor_ips_ipv6_and_malformed():
    assert neighbor_ips("2001:db8::10", span=1) == ["2001:db8::f", "2001:db8::11"]
    assert neighbor_ips("not-an-ip", span=3) == []


async def test_dns_lookaside_reports_neighbours_and_flags_related(registry, fake_dns):
    fake_dns.on(_rev("203.0.113.10"), ["host10.example.com."], rtype="PTR")  # the target's own reverse name
    fake_dns.on(_rev("203.0.113.9"), ["host9.example.com."], rtype="PTR")  # same domain → related
    fake_dns.on(_rev("203.0.113.11"), ["mail.other.net."], rtype="PTR")  # different domain → not related
    # .8 and .12 have no PTR (NXDOMAIN) and must not be reported
    mod = registry.instantiate("dns_lookaside", scope=Scope(), config={"span": 2})
    emits = [e async for e in mod.lookup(EntityRef(EntityType.IP, "203.0.113.10"))]

    ips = {e.value: e for e in emits if e.type is EntityType.IP}
    assert set(ips) == {"203.0.113.9", "203.0.113.11"}  # only neighbours that reverse-resolve
    assert ips["203.0.113.9"].meta["related"] is True and ips["203.0.113.9"].meta["ptr"] == "host9.example.com"
    assert ips["203.0.113.11"].meta["related"] is False and ips["203.0.113.11"].relation == "neighbor_of"

    hosts = {e.value: e for e in emits if e.type is EntityType.HOSTNAME}
    assert set(hosts) == {"host9.example.com", "mail.other.net"}
    assert (
        hosts["host9.example.com"].relation == "reverse_of" and hosts["host9.example.com"].parent.value == "203.0.113.9"
    )


# ---- ssl_analyzer: certificate analysis (pure over getpeercert dict) + mocked handshake ----------------------

from datetime import UTC, datetime  # noqa: E402

from osint_board.modules.impl.ssl_analyzer import (  # noqa: E402
    analyze_certificate,
    host_matches,
    verify_error_verdict,
)

_NOW = datetime(2025, 7, 1, tzinfo=UTC)


def _cert(
    *,
    subject_cn="example.com",
    issuer_cn="R3",
    issuer_org="Let's Encrypt",
    not_before="May 01 00:00:00 2025 GMT",
    not_after="Aug 01 00:00:00 2025 GMT",
    sans=("example.com", "www.example.com"),
    ip_sans=(),
    serial="03A1",
):
    # a self-signed cert (issuer == subject) is expressed by issuer_org=None + issuer_cn == subject_cn
    issuer_rdns = []
    if issuer_org is not None:
        issuer_rdns.append((("organizationName", issuer_org),))
    issuer_rdns.append((("commonName", issuer_cn),))
    alt = tuple(("DNS", s) for s in sans) + tuple(("IP Address", ip) for ip in ip_sans)
    return {
        "subject": ((("commonName", subject_cn),),),
        "issuer": tuple(issuer_rdns),
        "serialNumber": serial,
        "notBefore": not_before,
        "notAfter": not_after,
        "subjectAltName": alt,
    }


@pytest.mark.parametrize(
    ("host", "names", "ok"),
    [
        ("example.com", ["example.com"], True),
        ("foo.example.com", ["*.example.com"], True),
        ("example.com", ["*.example.com"], False),  # a wildcard does not match the bare apex
        ("a.b.example.com", ["*.example.com"], False),  # nor two labels deep
        ("other.com", ["example.com", "www.example.com"], False),
    ],
)
def test_host_matches_rfc6125(host, names, ok):
    assert host_matches(host, names) is ok


def test_analyze_certificate_healthy():
    a = analyze_certificate(_cert(), "example.com", now=_NOW)
    assert a.issues() == [] and a.self_signed is False
    assert a.dns_names == ["example.com", "www.example.com"] and a.issuer_org == "Let's Encrypt"


def test_analyze_certificate_expired_and_expiring():
    assert any(
        c == "tls-expired"
        for _, c in analyze_certificate(_cert(not_after="Jun 01 00:00:00 2025 GMT"), "example.com", now=_NOW).issues()
    )
    soon = analyze_certificate(_cert(not_after="Jul 10 00:00:00 2025 GMT"), "example.com", now=_NOW)
    assert soon.expiring_soon and not soon.expired


def test_analyze_certificate_self_signed_and_over_long():
    ss = analyze_certificate(
        _cert(subject_cn="box.local", issuer_cn="box.local", issuer_org=None, sans=("box.local",)),
        "box.local",
        now=_NOW,
    )
    assert ss.self_signed and any(c == "tls-self-signed" for _, c in ss.issues())
    lng = analyze_certificate(
        _cert(not_before="Jan 01 00:00:00 2023 GMT", not_after="Dec 01 00:00:00 2025 GMT"), "example.com", now=_NOW
    )
    assert lng.over_long


def test_analyze_certificate_hostname_mismatch():
    assert analyze_certificate(_cert(sans=("example.com",)), "evil.com", now=_NOW).hostname_mismatch is True
    assert analyze_certificate(_cert(sans=("example.com",)), "example.com", now=_NOW).hostname_mismatch is False
    assert analyze_certificate(_cert(sans=("example.com",)), None, now=_NOW).hostname_mismatch is False


def test_analyze_certificate_ignores_cn_when_sans_are_present():
    # SAN other.example, CN target.example: the CN must not make target.example a covered name (RFC 6125)
    a = analyze_certificate(_cert(subject_cn="target.example", sans=("other.example",)), "target.example", now=_NOW)
    assert a.dns_names == ["other.example"] and a.hostname_mismatch is True


def test_analyze_certificate_falls_back_to_cn_only_when_no_san():
    a = analyze_certificate(_cert(subject_cn="legacy.example.com", sans=()), "legacy.example.com", now=_NOW)
    assert a.dns_names == ["legacy.example.com"] and a.hostname_mismatch is False


def test_analyze_certificate_matches_ip_targets_against_ip_sans():
    cert = _cert(subject_cn="host", sans=("host.example",), ip_sans=("203.0.113.7", "2001:db8::1"))
    assert analyze_certificate(cert, "203.0.113.7", now=_NOW).hostname_mismatch is False  # covered IP SAN
    assert analyze_certificate(cert, "2001:0db8:0:0:0:0:0:1", now=_NOW).hostname_mismatch is False  # canonicalised
    assert analyze_certificate(cert, "203.0.113.9", now=_NOW).hostname_mismatch is True  # a different address
    assert analyze_certificate(cert, "203.0.113.7", now=_NOW).ip_sans == ["203.0.113.7", "2001:db8::1"]
    # a cert with only DNS SANs does not cover a bare IP target
    assert analyze_certificate(_cert(sans=("host.example",)), "203.0.113.7", now=_NOW).hostname_mismatch is True


async def test_ssl_analyzer_lookup_emits_cert_sans_and_verdicts(registry):
    # a long-expired self-signed cert, deterministic for any real "now"; target is one of its SANs
    canned = _cert(
        subject_cn="self.example.com",
        issuer_cn="self.example.com",
        issuer_org=None,
        not_before="Jan 01 00:00:00 2019 GMT",
        not_after="Jan 01 00:00:00 2020 GMT",
        sans=("self.example.com", "www.example.com", "*.cdn.example.com"),
    )
    mod = registry.instantiate("ssl_analyzer", scope=Scope(), config={"port": 443})

    async def fake_fetch(host, port, server_name):
        assert (host, port, server_name) == ("self.example.com", 443, "self.example.com")
        return canned, None  # a certificate we could parse (verification not attempted here)

    mod._fetch_cert = fake_fetch
    emits = [e async for e in mod.lookup(EntityRef(EntityType.HOSTNAME, "self.example.com"))]

    certs = [e for e in emits if e.type is EntityType.CERTIFICATE]
    assert len(certs) == 1 and certs[0].meta["self_signed"] is True and certs[0].meta["expired"] is True

    sans = {e.value for e in emits if e.type is EntityType.HOSTNAME}
    assert sans == {"www.example.com"}  # the wildcard SAN and the target's own name are not re-emitted

    labels = {e.meta["label"] for e in emits if e.type is EntityType.VERDICT}
    assert {"certificate expired", "self-signed certificate"} <= labels


@pytest.mark.parametrize(
    ("message", "category"),
    [
        ("certificate has expired", "tls-expired"),
        ("self-signed certificate", "tls-self-signed"),
        ("self signed certificate in certificate chain", "tls-self-signed"),
        ("unable to get local issuer certificate", "tls-untrusted-issuer"),
        ("something unrecognised", "tls-untrusted"),
    ],
)
def test_verify_error_verdict(message, category):
    assert verify_error_verdict(message)[1] == category


async def test_ssl_analyzer_emits_a_verdict_for_an_untrusted_cert(registry):
    # verification failed (no dict), but we reached a real cert: the failure reason is still a verdict
    mod = registry.instantiate("ssl_analyzer", scope=Scope())

    async def fake_fetch(host, port, server_name):
        return None, "certificate has expired"

    mod._fetch_cert = fake_fetch
    emits = [e async for e in mod.lookup(EntityRef(EntityType.HOSTNAME, "expired.example"))]
    assert len(emits) == 1 and emits[0].type is EntityType.VERDICT
    assert emits[0].meta["category"] == "tls-expired" and emits[0].meta["detail"] == "certificate has expired"


async def test_ssl_analyzer_quiet_on_handshake_failure(registry):
    mod = registry.instantiate("ssl_analyzer", scope=Scope())

    async def fake_fetch(host, port, server_name):
        return None, None  # dead port / TLS error: nothing reached, no verdict

    mod._fetch_cert = fake_fetch
    assert [e async for e in mod.lookup(EntityRef(EntityType.IP, "203.0.113.5"))] == []


# ---- cross_referencer: link analysis (pure) + lookup --------------------------------------------------------


def test_linked_sites_returns_outbound_registrable_domains(fixtures_dir):
    html = (fixtures_dir / "web" / "cross_referencer_hit.html").read_text()
    sites = linked_sites(html, "https://partner.acme-holdings.net/")
    # blog.example.com collapses to example.com; the own site and relative/mailto links drop out
    assert sites == {"example.com", "example.org", "example.net", "twitter.com"}
    assert "acme-holdings.net" not in sites


async def test_cross_referencer_confirms_an_affiliate_on_a_backlink(registry, fake_http, fixtures_dir):
    fake_http.route(
        "partner.acme-holdings.net",
        body=(fixtures_dir / "web" / "cross_referencer_hit.html").read_text(),
        headers={"content-type": "text/html"},
    )
    mod = registry.instantiate("cross_referencer", scope=Scope(), config={"targets": ["example.com"]})
    emits = [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "partner.acme-holdings.net"))]

    affiliate = [e for e in emits if e.type is EntityType.AFFILIATE_LINK]
    domains = [e for e in emits if e.type is EntityType.DOMAIN]
    assert len(affiliate) == 1 and affiliate[0].value == "acme-holdings.net"
    assert affiliate[0].meta["links_to"] == ["example.com"] and affiliate[0].relation == "affiliated_with"
    assert [e.value for e in domains] == ["acme-holdings.net"]


async def test_cross_referencer_uses_scope_targets_as_a_fallback(registry, fake_http, fixtures_dir):
    fake_http.route(
        "partner.acme-holdings.net",
        body=(fixtures_dir / "web" / "cross_referencer_hit.html").read_text(),
        headers={"content-type": "text/html"},
    )
    mod = registry.instantiate("cross_referencer", scope=Scope(targets=["www.example.net"]))
    emits = [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "partner.acme-holdings.net"))]
    assert {e.meta["links_to"][0] for e in emits} == {"example.net"}


async def test_cross_referencer_is_a_noop_without_home_sites(registry, fake_http):
    mod = registry.instantiate("cross_referencer", scope=Scope())
    assert [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "partner.acme-holdings.net"))] == []
    assert fake_http.calls == []  # nothing to check against, so the candidate is never fetched


async def test_cross_referencer_skips_the_target_when_it_is_a_home_site(registry, fake_http):
    mod = registry.instantiate("cross_referencer", scope=Scope(), config={"targets": ["example.com"]})
    assert [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "www.example.com"))] == []
    assert fake_http.calls == []


async def test_cross_referencer_no_emit_without_a_backlink(registry, fake_http, fixtures_dir):
    fake_http.route(
        "partner.acme-holdings.net",
        body=(fixtures_dir / "web" / "cross_referencer_hit.html").read_text(),
        headers={"content-type": "text/html"},
    )
    mod = registry.instantiate("cross_referencer", scope=Scope(), config={"targets": ["never-linked.example"]})
    assert [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "partner.acme-holdings.net"))] == []


async def test_cross_referencer_no_self_loop_domain_for_an_apex_target(registry, fake_http, fixtures_dir):
    fake_http.route(
        "acme-holdings.net",
        body=(fixtures_dir / "web" / "cross_referencer_hit.html").read_text(),
        headers={"content-type": "text/html"},
    )
    mod = registry.instantiate("cross_referencer", scope=Scope(), config={"targets": ["example.com"]})
    emits = [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "acme-holdings.net"))]
    # the affiliate is recorded, but the apex target is not re-emitted as a domain (that would be a self-loop)
    assert [e.type for e in emits] == [EntityType.AFFILIATE_LINK]


async def test_cross_referencer_ignores_an_offsite_redirect(registry, fixtures_dir):
    # the candidate redirects to an unrelated site whose page links to the home site — the candidate must NOT be
    # confirmed, because the back-link is not on the candidate's own page
    mod = registry.instantiate("cross_referencer", scope=Scope(), config={"targets": ["example.com"]})
    html = (fixtures_dir / "web" / "cross_referencer_hit.html").read_text()

    async def fake_fetch(url):
        return "https://someone-else.test/landing", html  # final URL is off the candidate's registrable domain

    mod._fetch = fake_fetch
    assert [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "parked-candidate.example"))] == []


# ---- adblock_check: EasyList/EasyPrivacy matcher (adblock-rs bindings) ---------------------------------------------


def test_resource_links_extracts_fetch_candidates_only(fixtures_dir):
    from osint_board.modules.impl.adblock_check import resource_links

    html = (fixtures_dir / "web" / "adblock_sample.html").read_text()
    hits = resource_links(html, "https://victim.example/")
    kinds = {rtype for rtype, _ in hits}
    assert kinds == {"stylesheet", "script", "image", "subdocument"}
    urls = {url for _, url in hits}
    assert {
        "https://victim.example/assets/main.css",
        "https://trackers.example/ads.css",
        "https://cdn.widgets.example/w.js",
        "https://victim.example/img/logo.png",
        "https://ads.tracker.example/pixel.gif",
        "https://player.kubernetes.example/embed",
    } == urls  # data:/# fragment refs are not fetch candidates


async def test_adblock_lookup_reports_blocked_subresources(registry, fake_http, fixtures_dir):
    from osint_board.modules.impl import adblock_check

    adblock_check.CACHE.clear()  # rules cache is process-wide: tests swap rule sets around
    fake_http.route(
        "rules.example/easylist.txt", file="web/easylist_sample.txt", headers={"content-type": "text/plain"}
    )
    fake_http.route(
        "victim.example/",
        body=(fixtures_dir / "web" / "adblock_sample.html").read_text(),
        headers={"content-type": "text/html"},
    )
    mod = registry.instantiate("adblock_check", config={"lists": {"easylist": "https://rules.example/easylist.txt"}})
    emits = [e async for e in mod.lookup(EntityRef(EntityType.URL, "https://victim.example/"))]
    assert len(emits) == 1
    verdict = emits[0]
    assert verdict.type is EntityType.VERDICT
    assert verdict.meta["label"] == "2/6 sub-resources blocked"
    blocked = {b["url"] for b in verdict.meta["blocked"]}
    assert blocked == {
        "https://ads.tracker.example/pixel.gif",
        "https://trackers.example/ads.css",
    }
    assert verdict.meta["lists"] == ["easylist"] and verdict.meta["failed_lists"] == []
    assert fake_http.urls() == ["https://rules.example/easylist.txt", "https://victim.example/"]


async def test_adblock_lookup_clean_page_is_a_non_result(registry, fake_http, fixtures_dir):
    from osint_board.modules.impl import adblock_check

    adblock_check.CACHE.clear()
    fake_http.route(
        "rules.example/easylist.txt", file="web/easylist_sample.txt", headers={"content-type": "text/plain"}
    )
    fake_http.route(
        "victim.example/",
        body="<html><img src='/logo.png'></html>",
        headers={"content-type": "text/html"},
    )
    mod = registry.instantiate("adblock_check", config={"lists": {"easylist": "https://rules.example/easylist.txt"}})
    assert [e async for e in mod.lookup(EntityRef(EntityType.URL, "https://victim.example/"))] == []


async def test_adblock_lookup_raises_when_every_list_is_down(registry, fake_http):
    from osint_board.modules.impl import adblock_check

    adblock_check.CACHE.clear()
    mod = registry.instantiate(
        "adblock_check",
        config={"lists": {"one": "https://rules.example/a.txt", "two": "https://rules.example/b.txt"}},
    )
    with pytest.raises(RuntimeError, match="every filter-list download failed"):
        [e async for e in mod.lookup(EntityRef(EntityType.URL, "https://victim.example/"))]


def test_resource_links_resolves_base_and_classifies_fetching_relations(fixtures_dir):
    from osint_board.modules.impl.adblock_check import resource_links

    html = (fixtures_dir / "web" / "adblock_resources.html").read_text()
    assert resource_links(html, "https://site.example/pages/index.html") == [
        ("stylesheet", "https://cdn.example/assets/main.css"),
        ("image", "https://cdn.example/assets/favicon.ico"),
        ("script", "https://cdn.example/assets/main.js"),
        ("font", "https://cdn.example/assets/text.woff2"),
        ("object", "https://cdn.example/assets/plugin.swf"),
        ("image", "https://cdn.example/assets/poster.png"),
        ("media", "https://cdn.example/assets/clip.mp4"),
        ("image", "https://cdn.example/assets/button.png"),
        ("script", "https://cdn.example/assets/after-template.js"),
    ]


@pytest.mark.parametrize("base", ['<base href="http://[bad">', '<base href="">'])
def test_resource_links_invalid_or_empty_first_base_uses_document_url(base):
    from osint_board.modules.impl.adblock_check import resource_links

    html = base + '<base href="https://ignored.example/"><img src="logo.png">'
    assert resource_links(html, "https://site.example/pages/index.html") == [
        ("image", "https://site.example/pages/logo.png")
    ]


async def test_adblock_respects_exceptions_resource_types_domains_and_third_party(registry, fake_http, fixtures_dir):
    from osint_board.modules.impl import adblock_check

    adblock_check.CACHE.clear()
    fake_http.route("rules.example/options.txt", file="web/adblock_options.txt", headers={"content-type": "text/plain"})
    mod = registry.instantiate("adblock_check", config={"lists": {"options": "https://rules.example/options.txt"}})

    async def redirected_fetch(url):
        return "https://landing.example/page", (fixtures_dir / "web" / "adblock_options.html").read_text()

    mod._fetch = redirected_fetch
    emits = [e async for e in mod.lookup(EntityRef(EntityType.URL, "https://original.example/"))]
    assert len(emits) == 1
    assert emits[0].meta["url"] == "https://landing.example/page"
    assert emits[0].meta["blocked"] == [
        {"url": "https://assets.example/blocked.js", "type": "script"},
        {"url": "https://assets.example/tracker.png", "type": "image"},
        {"url": "https://assets.example/frame", "type": "subdocument"},
        {"url": "https://third.example/app.js", "type": "script"},
        {"url": "https://scoped.example/app.js", "type": "script"},
    ]


@pytest.mark.parametrize("ctype", ["text/plain", "text/html-invalid", "application/json", "image/svg+xml"])
async def test_adblock_ignores_non_html_pages(registry, fake_http, ctype):
    from osint_board.modules.impl import adblock_check

    adblock_check.CACHE.clear()
    fake_http.route("rules.example/list.txt", body="||tracker.example^")
    fake_http.route("site.example/", body='<img src="https://tracker.example/x">', headers={"content-type": ctype})
    mod = registry.instantiate("adblock_check", config={"lists": {"test": "https://rules.example/list.txt"}})
    assert [e async for e in mod.lookup(EntityRef(EntityType.URL, "https://site.example/"))] == []


@pytest.mark.parametrize("status", [301, 404, 503])
async def test_adblock_ignores_error_and_unresolved_redirect_pages(registry, fake_http, status):
    from osint_board.modules.impl import adblock_check

    adblock_check.CACHE.clear()
    fake_http.route("rules.example/list.txt", body="||tracker.example^")
    fake_http.route(
        "site.example/",
        body='<img src="https://tracker.example/x">',
        status=status,
        headers={"content-type": "text/html"},
    )
    mod = registry.instantiate("adblock_check", config={"lists": {"test": "https://rules.example/list.txt"}})
    assert [e async for e in mod.lookup(EntityRef(EntityType.URL, "https://site.example/"))] == []


@pytest.mark.parametrize(
    "url", ["data:text/html,foo", "file:///tmp/page", "https://[bad", "https://host:wrong/", "https:///"]
)
async def test_adblock_rejects_invalid_targets_without_fetching(registry, fake_http, url):
    mod = registry.instantiate("adblock_check")
    assert [e async for e in mod.lookup(EntityRef(EntityType.URL, url))] == []
    assert fake_http.calls == []


@pytest.mark.parametrize("lists", [{}, [], {"bad": "file:///tmp/list"}, {"bad": 123}])
async def test_adblock_rejects_invalid_list_configuration(registry, fake_http, lists):
    mod = registry.instantiate("adblock_check", config={"lists": lists})
    with pytest.raises(ValueError, match="adblock_check:"):
        [e async for e in mod.lookup(EntityRef(EntityType.URL, "https://site.example/"))]
    assert fake_http.calls == []


@pytest.mark.parametrize(
    ("body", "ctype", "status"),
    [("<html>upstream failure</html>", "text/html", 200), ("", "text/plain", 200), ("failure", "text/plain", 503)],
)
async def test_adblock_rejects_failed_or_non_list_downloads(registry, fake_http, body, ctype, status):
    from osint_board.modules.impl import adblock_check

    adblock_check.CACHE.clear()
    fake_http.route("rules.example/list.txt", body=body, status=status, headers={"content-type": ctype})
    mod = registry.instantiate("adblock_check", config={"lists": {"test": "https://rules.example/list.txt"}})
    with pytest.raises(RuntimeError, match="every filter-list download failed"):
        [e async for e in mod.lookup(EntityRef(EntityType.URL, "https://site.example/"))]


async def test_adblock_partial_rule_failure_reports_provenance_and_retries(registry, fake_http):
    from osint_board.modules.impl import adblock_check

    adblock_check.CACHE.clear()
    fake_http.route("rules.example/one.txt", body="||tracker.example^")
    fake_http.route(
        "site.example/", body='<img src="https://tracker.example/x">', headers={"content-type": "text/html"}
    )
    mod = registry.instantiate(
        "adblock_check",
        config={"lists": {"one": "https://rules.example/one.txt", "two": "https://rules.example/two.txt"}},
    )
    target = EntityRef(EntityType.URL, "https://site.example/")
    partial = [e async for e in mod.lookup(target)]
    assert partial[0].meta["lists"] == ["one"] and partial[0].meta["failed_lists"] == ["two"]
    fake_http.route("rules.example/two.txt", body="||other.example^")
    recovered = [e async for e in mod.lookup(target)]
    assert recovered[0].meta["lists"] == ["one", "two"] and recovered[0].meta["failed_lists"] == []
    assert fake_http.urls().count("https://rules.example/two.txt") == 2


async def test_adblock_rule_cache_expires_and_separates_configured_lists(registry, fake_http, monkeypatch):
    from types import SimpleNamespace

    from osint_board.modules.impl import adblock_check

    adblock_check.CACHE.clear()
    now = 10.0
    monkeypatch.setattr(adblock_check, "time", SimpleNamespace(monotonic=lambda: now))
    fake_http.route("rules.example/one.txt", body="||tracker.example^")
    fake_http.route("rules.example/two.txt", body="@@||tracker.example^")
    fake_http.route(
        "site.example/", body='<img src="https://tracker.example/x">', headers={"content-type": "text/html"}
    )
    one = registry.instantiate("adblock_check", config={"lists": {"test": "https://rules.example/one.txt"}, "ttl": 60})
    two = registry.instantiate("adblock_check", config={"lists": {"test": "https://rules.example/two.txt"}, "ttl": 60})
    target = EntityRef(EntityType.URL, "https://site.example/")
    assert len([e async for e in one.lookup(target)]) == 1
    assert len([e async for e in one.lookup(target)]) == 1
    assert fake_http.urls().count("https://rules.example/one.txt") == 1
    assert [e async for e in two.lookup(target)] == []
    now += 60
    assert len([e async for e in one.lookup(target)]) == 1
    assert fake_http.urls().count("https://rules.example/one.txt") == 2


async def test_adblock_concurrent_lookups_share_one_rules_download():
    import asyncio
    from types import SimpleNamespace

    import httpx

    from osint_board.modules.impl.adblock_check import _EngineCache

    cache = _EngineCache()
    downloads = []

    async def get(url, **kwargs):
        downloads.append(url)
        await asyncio.sleep(0)  # let the second caller arrive while the first fetch is in progress
        return httpx.Response(200, text="||tracker.example^", request=httpx.Request("GET", url))

    http = SimpleNamespace(get=get)
    lists = (("test", "https://rules.example/list.txt"),)
    engines = await asyncio.gather(cache.get(http, lists, 60), cache.get(http, lists, 60))
    assert engines[0] is engines[1]
    assert downloads == ["https://rules.example/list.txt"]
