"""Phase-2 content extractors: web server/framework identifiers, cookies, errors, company & human names,
base64 decode and binary strings. All pure and offline (no network, no database)."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.extraction import ExtractorPipeline
from osint_board.modules.impl.base64_decoder import find_base64
from osint_board.modules.impl.binary_strings import extract_strings
from osint_board.modules.impl.company_name_extractor import find_companies
from osint_board.modules.impl.cookie_extractor import parse_set_cookie, software_for
from osint_board.modules.impl.error_string_extractor import find_errors
from osint_board.modules.impl.human_name_extractor import find_names
from osint_board.modules.impl.web_framework_identifier import parse_frameworks
from osint_board.modules.impl.web_server_identifier import parse_products, split_header
from osint_board.modules.types import Content, Emit, EntityRef

FIXTURES = Path(__file__).parent / "fixtures"
SRC = "https://x.example/page"


def _extract(registry, module_id: str, text: str, *, parent_type=EntityType.RAW_CONTENT, source=SRC):
    mod = registry.instantiate(module_id)
    content = Content(text, source_url=source, parent=EntityRef(parent_type, source))
    return list(mod.extract(content))


# ---- web_server_identifier -----------------------------------------------------------------------------------


def test_split_header():
    assert split_header("Server: nginx/1.18.0") == ("server", "nginx/1.18.0")
    assert split_header("nginx/1.18.0") == ("", "nginx/1.18.0")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("nginx/1.18.0 (Ubuntu)", [("nginx", "1.18.0")]),
        ("Apache/2.4.41 (Debian) OpenSSL/1.1.1", [("Apache", "2.4.41")]),
        ("PHP/8.1.2", [("PHP", "8.1.2")]),
        ("cloudflare", [("cloudflare", None)]),
    ],
)
def test_parse_products(value, expected):
    assert parse_products(value) == expected


def test_web_server_identifier_emits(registry):
    emits = _extract(
        registry, "web_server_identifier", "Server: nginx/1.18.0 (Ubuntu)", parent_type=EntityType.HTTP_HEADER
    )
    assert [(e.value, e.type) for e in emits] == [("nginx 1.18.0", EntityType.SOFTWARE)]
    assert emits[0].meta["version"] == "1.18.0" and emits[0].relation == "runs"
    assert emits[0].parent.type is EntityType.HTTP_HEADER


def test_web_server_identifier_powered_by_and_implied(registry):
    assert (
        _extract(registry, "web_server_identifier", "X-Powered-By: PHP/8.1.2", parent_type=EntityType.HTTP_HEADER)[
            0
        ].value
        == "PHP 8.1.2"
    )
    implied = _extract(registry, "web_server_identifier", "X-Vercel-Id: iad1::abcd", parent_type=EntityType.HTTP_HEADER)
    assert [e.value for e in implied] == ["Vercel"]


def test_web_server_identifier_ignores_unrelated_headers(registry):
    assert (
        _extract(
            registry,
            "web_server_identifier",
            "Content-Type: text/html; charset=utf-8",
            parent_type=EntityType.HTTP_HEADER,
        )
        == []
    )


# ---- cookie_extractor ----------------------------------------------------------------------------------------


def test_parse_set_cookie():
    c = parse_set_cookie("PHPSESSID=abc123; Path=/; HttpOnly; Secure; SameSite=Lax")
    assert c["name"] == "PHPSESSID" and c["attrs"]["httponly"] is True and c["attrs"]["samesite"] == "Lax"
    assert parse_set_cookie("=novalue") is None
    assert parse_set_cookie("") is None


@pytest.mark.parametrize(
    ("name", "product"),
    [
        ("PHPSESSID", "PHP"),
        ("wordpress_logged_in_x", "WordPress"),
        ("laravel_session", "Laravel"),
        ("random_name", None),
    ],
)
def test_cookie_software(name, product):
    assert software_for(name) == product


def test_cookie_extractor_emits(registry):
    emits = _extract(
        registry,
        "cookie_extractor",
        "Set-Cookie: PHPSESSID=abc; Path=/; HttpOnly; Secure; SameSite=Lax",
        parent_type=EntityType.HTTP_HEADER,
    )
    assert len(emits) == 1
    e = emits[0]
    assert e.type is EntityType.COOKIE and e.value == "PHPSESSID"
    assert e.meta["http_only"] and e.meta["secure"] and e.meta["same_site"] == "Lax"
    assert e.meta["reveals"] == "PHP" and e.relation == "sets"


def test_cookie_extractor_ignores_other_headers(registry):
    assert _extract(registry, "cookie_extractor", "Server: nginx", parent_type=EntityType.HTTP_HEADER) == []


# ---- web_framework_identifier --------------------------------------------------------------------------------


def test_parse_frameworks_generator_first():
    html = FIXTURES.joinpath("web/leaky_site.html").read_text()
    products = {p: v for p, v, _ in parse_frameworks(html)}
    assert products["WordPress"] == "6.4.2"  # from the generator meta tag
    assert products["jQuery"] == "3.6.0"
    assert products["Bootstrap"] == "5.3.1"
    assert "Laravel" in products  # csrf-token meta marker


def test_web_framework_identifier_emits(registry):
    html = '<meta name="generator" content="Drupal 10 (https://drupal.org)">'
    emits = _extract(registry, "web_framework_identifier", html)
    assert emits[0].value == "Drupal 10" and emits[0].meta["role"] == "generator"
    assert emits[0].relation == "built_with" and emits[0].type is EntityType.SOFTWARE


def test_web_framework_identifier_deduplicates(registry):
    html = '<script src="/wp-content/a.js"></script><link href="/wp-includes/b.css">'
    emits = _extract(registry, "web_framework_identifier", html)
    assert [e.value for e in emits] == ["WordPress"]  # two markers, one entity


# ---- error_string_extractor ----------------------------------------------------------------------------------


def test_find_errors_collapses_overlaps():
    text = "Warning: mysql_query(): supplied argument is not a valid MySQL result in /var/www/html/db.php on line 42"
    found = find_errors(text)
    techs = [t for _, t, _, _ in found]
    assert "PHP" in techs  # the widest signature wins for the warning line
    assert techs.count("MySQL") == 0  # the contained MySQL sub-matches are dropped
    # the filesystem path is a separate info-leak finding even though it sits inside the PHP warning
    assert any(cat == "leak" and "/var/www" in msg for msg, _, cat, _ in found)


@pytest.mark.parametrize(
    ("text", "tech"),
    [
        ('Traceback (most recent call last):\n  File "/a.py", line 1', "Python"),
        ("ORA-00933: SQL command not properly ended", "Oracle"),
        ("Server Error in '/app' Application. System.NullReferenceException", "ASP.NET"),
        ("org.postgresql.util.PSQLException: ERROR", "PostgreSQL"),
    ],
)
def test_error_signatures(registry, text, tech):
    emits = _extract(registry, "error_string_extractor", text)
    assert any(e.meta["technology"] == tech for e in emits)
    assert all(e.type is EntityType.ERROR_MESSAGE for e in emits)


def test_error_extractor_clean_page(registry):
    assert _extract(registry, "error_string_extractor", "<p>Welcome to our friendly homepage!</p>") == []


# ---- company_name_extractor ----------------------------------------------------------------------------------


def test_find_companies():
    html = FIXTURES.joinpath("web/leaky_site.html").read_text()
    found = {name for name, _, _ in find_companies(html)}
    assert "Acme Widgets Inc" in found
    assert "Global Holdings Ltd" in found


def test_company_extractor_copyright_without_suffix(registry):
    emits = _extract(registry, "company_name_extractor", "© 2023 Contoso. Privacy policy.")
    assert any(e.value == "Contoso" and e.meta["via"] == "copyright" for e in emits)
    assert all(e.type is EntityType.COMPANY for e in emits)


def test_company_extractor_rejects_boilerplate(registry):
    assert _extract(registry, "company_name_extractor", "Copyright All Rights Reserved") == []


# ---- human_name_extractor ------------------------------------------------------------------------------------


def test_find_names():
    html = FIXTURES.joinpath("web/leaky_site.html").read_text()
    names = {name for name, _, _ in find_names(html)}
    assert {"Jane Q. Smith", "Robert Miller", "Alice Johnson", "Michael O'Brien", "Dana Whitfield"} <= names


def test_human_name_rejects_roles_and_junk(registry):
    assert _extract(registry, "human_name_extractor", '<meta name="author" content="admin">') == []
    assert _extract(registry, "human_name_extractor", '<meta name="author" content="Support Team 24">') == []


def test_human_name_confidence_by_source(registry):
    meta = _extract(registry, "human_name_extractor", '<meta name="author" content="Grace Hopper">')[0]
    byline = _extract(registry, "human_name_extractor", "By Grace Hopper today")[0]
    assert meta.confidence > byline.confidence


# ---- base64_decoder ------------------------------------------------------------------------------------------


def test_find_base64_printable_only():
    encoded = base64.b64encode(b"contact admin@secret.example for the keys").decode()
    binary = base64.b64encode(bytes(range(0, 32)) * 4).decode()  # non-printable -> ignored
    found = find_base64(f"token={encoded} junk={binary}")
    assert len(found) == 1
    enc, decoded, _ = found[0]
    assert enc == encoded and decoded == "contact admin@secret.example for the keys"


def test_base64_urlsafe_and_data_uri():
    encoded = base64.urlsafe_b64encode(b"https://evil.example/callback").decode().rstrip("=")
    found = find_base64(f"redirect={encoded}")
    assert found and found[0][1] == "https://evil.example/callback"
    data_uri = "data:text/plain;base64," + base64.b64encode(b"admin@company.example").decode()
    assert find_base64(data_uri)[0][1] == "admin@company.example"


def test_base64_decoder_emits_and_carries_text(registry):
    encoded = base64.b64encode(b"reach me at ops@hidden.example").decode()
    emits = _extract(registry, "base64_decoder", f"data={encoded}")
    assert len(emits) == 1 and emits[0].type is EntityType.BASE64_STRING
    assert emits[0].meta["text"] == "reach me at ops@hidden.example"
    assert emits[0].relation == "decodes_to"


# ---- binary_strings ------------------------------------------------------------------------------------------


def test_extract_strings_ascii_and_utf16():
    ascii_run = b"\x7fELF\x02\x01" + b"http://c2.example/beacon\x00" + b"\xff\xfe"
    utf16 = "MZsecret".encode("utf-16-le")  # each char followed by NUL
    data = (ascii_run + utf16).decode("latin-1")
    strings = extract_strings(data)
    assert "http://c2.example/beacon" in strings
    assert "MZsecret" in strings
    assert "EL" not in strings  # ELF is 3 chars, below the 4-char minimum


def test_binary_strings_emits_raw_content_for_chaining(registry):
    data = (b"\x00\x01" + b"visit http://drop.example and mail x@drop.example\x00").decode("latin-1")
    emits = _extract(registry, "binary_strings", data, parent_type=EntityType.RAW_FILE, source="file://a.bin")
    assert len(emits) == 1
    e = emits[0]
    assert e.type is EntityType.RAW_CONTENT and e.relation == "strings_of"
    assert "http://drop.example" in e.meta["text"] and e.meta["count"] >= 1


def test_binary_strings_empty_when_no_runs(registry):
    data = bytes(range(0, 16)).decode("latin-1")
    assert _extract(registry, "binary_strings", data, parent_type=EntityType.RAW_FILE) == []


# ---- pipeline integration ------------------------------------------------------------------------------------


def test_pipeline_chains_binary_strings_then_email(registry):
    """binary_strings produces raw_content, which the pipeline then re-scans with the raw_content extractors."""
    data = (b"\x00\x01" + b"exfil to mole@buried.example via beacon\x00").decode("latin-1")
    emits = [
        Emit(
            EntityType.RAW_FILE,
            "file://mal.bin",
            relation="downloaded",
            parent=EntityRef(EntityType.URL, SRC),
            meta={"text": data},
        ),
    ]
    found = ExtractorPipeline(registry).run(emits)
    assert found["binary_strings"][0].type is EntityType.RAW_CONTENT
    assert {e.value for e in found["email_extractor"]} == {"mole@buried.example"}
