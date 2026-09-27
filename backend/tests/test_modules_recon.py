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

    normal = EntityRef(
        EntityType.HTTP_HEADER, "Content-Type: text/html", meta={"name": "content-type", "value": "text/html"}
    )
    assert [e async for e in mod.lookup(normal)] == []
