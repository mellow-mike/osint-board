"""Phase-2 passive recon modules: look-alike domains, page analysis and non-standard headers.

Offline: the permutation engine and the page/header analysers are pure; DNS resolution for the look-alike
lookup is answered by ``fake_dns`` and page fetches by ``fake_http``. No real network."""

from __future__ import annotations

import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.base import Scope
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
