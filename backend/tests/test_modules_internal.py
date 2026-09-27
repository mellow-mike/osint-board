"""Internal phase-1 modules: extractors, DNS records, WHOIS, hosting ranges, PGP key servers, GLEIF."""

from __future__ import annotations

import pytest

from osint_board.entities.countries import country_code, find_countries
from osint_board.entities.types import EntityType
from osint_board.modules.impl import whois as whois_mod
from osint_board.modules.impl.hosting_provider import CACHE as RANGE_CACHE
from osint_board.modules.impl.hosting_provider import parse_aws, region_centroid
from osint_board.modules.impl.pgp_keyservers import parse_hkp_index
from osint_board.modules.impl.social_network_identifier import find_profiles
from osint_board.modules.impl.web_analytics_extractor import find_analytics_ids
from osint_board.modules.impl.whois import parse_whois_text, referral_server
from osint_board.modules.types import Content, EntityRef


def _by_type(emits):
    out: dict[EntityType, list[str]] = {}
    for e in emits:
        out.setdefault(e.type, []).append(e.value)
    return out


@pytest.mark.parametrize(
    ("module_id", "text", "expected"),
    [
        (
            "bitcoin_finder",
            "wallets 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 and bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq, not 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3",
            {"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"},
        ),
        (
            "ethereum_extractor",
            "send to 0x52908400098527886E0F7030069857D2E4169EE7 today",
            {"0x52908400098527886e0f7030069857d2e4169ee7"},
        ),
        (
            "hash_extractor",
            "md5 d41d8cd98f00b204e9800998ecf8427e sha256 094fd325049b8a9cf6d3e5ef2a6d4cc52a93b13cf9c0e0c1e9fd8ee2a0ae0b7c",
            {"d41d8cd98f00b204e9800998ecf8427e", "094fd325049b8a9cf6d3e5ef2a6d4cc52a93b13cf9c0e0c1e9fd8ee2a0ae0b7c"},
        ),
        ("phone_extractor", "call +44 20 7183 8750 or (415) 555-2671", {"+442071838750", "+14155552671"}),
        ("iban_extractor", "IBAN GB82WEST12345698765432 (bad: GB82WEST12345698765433)", {"GB82WEST12345698765432"}),
        ("credit_card_extractor", "card 4111 1111 1111 1111 exp 12/29", {"411111******1111"}),
    ],
)
def test_extractors(registry, module_id, text, expected):
    mod = registry.instantiate(module_id)
    emits = list(
        mod.extract(
            Content(text, source_url="https://x.example", parent=EntityRef(EntityType.URL, "https://x.example"))
        )
    )
    assert {e.value for e in emits} == expected
    assert all(
        e.relation == "mentioned_in" and e.parent is not None and e.meta["source_url"] == "https://x.example"
        for e in emits
    )


def test_country_extractor(registry):
    assert country_code("uk") == "GB" and country_code("gb") == "GB" and country_code("Nowhere") is None
    assert [
        c for c, _, _ in find_countries("Offices in the United Kingdom and Germany; the USA too. Germany again.")
    ] == ["GB", "DE", "US"]
    mod = registry.instantiate("country_extractor")
    emits = list(mod.extract(Content("Registered in Ireland, staff in India and indiana.")))
    assert [(e.value, e.meta["name"]) for e in emits] == [("IE", "Ireland"), ("IN", "India")]
    emits = list(mod.extract(Content("", parent=EntityRef(EntityType.PHONE, "+442071838750"))))
    assert [e.value for e in emits] == ["GB"] and emits[0].meta["via"] == "phone country code"


def test_web_analytics_extractor(registry):
    text = (
        "ga('create', 'UA-12345-1'); gtag('config', 'G-ABCDEF1234'); GTM-ABCD12 data-ad-client=\"pub-1234567890123456\" "
        "fbq('init', '1234567890123'); hjid:123456 ym(87654321, 'init'); _paq.push(['setSiteId', '7']); UA-12345-1 again"
    )
    ids = find_analytics_ids(text)
    assert [(p, i) for p, i, _ in ids] == [
        ("google_analytics", "UA-12345-1"),
        ("google_analytics_4", "G-ABCDEF1234"),
        ("google_tag_manager", "GTM-ABCD12"),
        ("google_adsense", "pub-1234567890123456"),
        ("facebook_pixel", "1234567890123"),
        ("hotjar", "123456"),
        ("yandex_metrika", "87654321"),
        ("matomo", "7"),
    ]
    emits = list(registry.instantiate("web_analytics_extractor").extract(Content(text)))
    assert (
        len(emits) == 8
        and emits[0].type is EntityType.WEB_ANALYTICS_ID
        and emits[0].meta["provider"] == "google_analytics"
    )


def test_social_network_identifier(registry):
    text = (
        "Follow https://x.com/jdoe and https://twitter.com/intent/tweet?x=1, https://www.linkedin.com/in/jane-doe-123/, "
        "code at https://github.com/jdoe and https://github.com/jdoe/tools, https://mastodon.example/@jdoe, "
        "https://www.youtube.com/@janedoe, https://t.me/jdoe_channel, https://medium.com/@jdoe/post-1"
    )
    found = find_profiles(text)
    assert [(p, u) for p, _, u in found] == [
        ("x", "jdoe"),
        ("linkedin", "jane-doe-123"),
        ("github", "jdoe"),
        ("youtube", "janedoe"),
        ("telegram", "jdoe_channel"),
        ("medium", "jdoe"),
        ("mastodon", "jdoe@mastodon.example"),
    ]
    emits = list(
        registry.instantiate("social_network_identifier").extract(
            Content("see profile", parent=EntityRef(EntityType.URL, "https://www.instagram.com/jdoe/"))
        )
    )
    assert [(e.value, e.meta["platform"]) for e in emits] == [("https://www.instagram.com/jdoe", "instagram")]


async def test_dns_raw_records(fake_dns, run_lookup):
    fake_dns.on("example.com", ["10 mx.example.org."], rtype="MX").on("example.com", ['"v=spf1 -all"'], rtype="TXT").on(
        "example.com", ["203.0.113.7"]
    )
    emits = await run_lookup("dns_raw_records", "domain", "example.com")
    assert [e.value for e in emits] == [
        "example.com A 203.0.113.7",
        "example.com MX 10 mx.example.org",
        'example.com TXT "v=spf1 -all"',
    ]
    assert all(e.type is EntityType.DNS_RECORD for e in emits) and emits[1].meta["rrtype"] == "MX"


async def test_whois_rdap(fake_http, run_lookup):
    fake_http.route("rdap.org/domain/example.com", file="internal/rdap_domain.json")
    emits = await run_lookup("whois", "domain", "example.com")
    by = _by_type(emits)
    assert by[EntityType.COMPANY] == ["Example Registrar, Inc.", "Example Networks LLC"]
    assert by[EntityType.EMAIL] == ["jane.doe@example.com"]
    assert next(e for e in emits if e.value == "Example Registrar, Inc.").relation == "registered_via"
    assert (
        by[EntityType.PHYSICAL_ADDRESS] == ["100 Main Street, Anytown, CA, 90210, US"] and EntityType.PERSON not in by
    )
    assert by[EntityType.WHOIS_RECORD] == ["rdap:domain:2336799_DOMAIN_COM-VRSN"]


async def test_whois_legacy_fallback(fake_http, run_lookup, fixtures_dir, monkeypatch):
    fake_http.route("rdap.org", "", status=404)
    texts = {
        "whois.iana.org": (fixtures_dir / "internal/whois_iana.txt").read_text(),
        "whois.verisign-grs.com": (fixtures_dir / "internal/whois_registry.txt").read_text(),
        "whois.example-registrar.com": (fixtures_dir / "internal/whois_registrar.txt").read_text(),
        "whois.arin.net": (fixtures_dir / "internal/whois_arin_referral.txt").read_text(),
        "whois.apnic.net": (fixtures_dir / "internal/whois_apnic.txt").read_text(),
    }
    queries: list[tuple[str, str]] = []

    async def fake_query(server, query, timeout=15.0):  # noqa: ANN001
        queries.append((server, query))
        return texts[server]

    monkeypatch.setattr(whois_mod, "whois_query", fake_query)
    assert (
        referral_server(texts["whois.iana.org"]) == "whois.verisign-grs.com"
        and referral_server(texts["whois.arin.net"]) == "whois.apnic.net"
    )
    fields = parse_whois_text(texts["whois.registrar" if False else "whois.example-registrar.com"])
    assert fields["registrant organization"] == ["Example Networks LLC"] and fields["registrant state/province"] == [
        "CA"
    ]
    emits = await run_lookup("whois", "domain", "www.example.com")
    by = _by_type(emits)
    assert queries == [
        ("whois.iana.org", "com"),
        ("whois.verisign-grs.com", "example.com"),
        ("whois.example-registrar.com", "example.com"),
    ]
    assert by[EntityType.COMPANY] == ["Example Networks LLC"] and by[EntityType.PERSON] == ["Jane Doe"]
    assert by[EntityType.EMAIL] == ["jane.doe@example.com", "admin@example.com"] and by[EntityType.PHONE] == [
        "+1.5550100"
    ]
    assert by[EntityType.PHYSICAL_ADDRESS] == ["100 Main Street, Anytown, CA, 90210, US"]
    record = next(e for e in emits if e.type is EntityType.WHOIS_RECORD)
    assert (
        record.meta["registrar"] == "Example Registrar, Inc." and record.meta["server"] == "whois.example-registrar.com"
    )
    queries.clear()
    by = _by_type(await run_lookup("whois", "ip", "203.0.113.7"))
    assert queries == [("whois.arin.net", "n + 203.0.113.7"), ("whois.apnic.net", "203.0.113.7")]
    assert by[EntityType.COMPANY] == ["Example Networks LLC"] and set(by[EntityType.EMAIL]) == {
        "noc@example.com",
        "abuse@example.com",
    }
    assert by[EntityType.PHONE] == ["+61255501234"] and by[EntityType.PHYSICAL_ADDRESS] == ["100 Main Street, Anytown"]


async def test_hosting_provider(fake_http, run_lookup, fixtures_dir):
    RANGE_CACHE._ranges, RANGE_CACHE._loaded = [], 0.0
    ranges = parse_aws((fixtures_dir / "internal/aws_ranges.json").read_text())
    assert [str(r.network) for r in ranges] == [
        "203.0.113.0/25",
        "203.0.113.0/24",
        "198.51.100.0/24",
        "2001:db8:1::/48",
    ] and ranges[0].region == "eu-west-1"
    assert (
        region_centroid("eu-west-1") == (53.3, -6.3)
        and region_centroid("Newark, US") == (40.7, -74.2)
        and region_centroid("nowhere") is None
    )
    fake_http.route("ip-ranges.amazonaws.com", file="internal/aws_ranges.json").route(
        "gstatic.com/ipranges", file="internal/gcp_ranges.json"
    )
    fake_http.route("cloudflare.com/ips-v4", file="internal/cloudflare_v4.txt").route(
        "cloudflare.com/ips-v6", file="internal/cloudflare_v6.txt"
    )
    fake_http.route("digitalocean.com/geo", file="internal/do_geo.csv").route(
        "geoip.linode.com", file="internal/linode_geo.csv"
    )
    fake_http.route("public_ip_ranges.json", file="internal/oracle_ranges.json").route(
        "api.fastly.com", file="internal/fastly_ips.json"
    )
    emits = await run_lookup("hosting_provider", "ip", "203.0.113.7")
    by = _by_type(emits)
    assert by[EntityType.COMPANY] == ["Amazon Web Services"] and by[EntityType.CLOUD_REGION] == ["amazon:eu-west-1"]
    region = next(e for e in emits if e.type is EntityType.CLOUD_REGION)
    assert (
        region.geo.lat == 53.3
        and region.geo.precision == "region"
        and region.layer == "cloud_regions"
        and region.meta["prefix"] == "203.0.113.0/25"
    )
    assert len(fake_http.calls) == 8
    by = _by_type(await run_lookup("hosting_provider", "ip", "192.0.2.200"))
    assert (
        by[EntityType.COMPANY] == ["Linode (Akamai)"]
        and by[EntityType.CLOUD_REGION] == ["linode:Newark, US"]
        and len(fake_http.calls) == 8
    )
    by = _by_type(await run_lookup("hosting_provider", "netblock", "203.0.113.0/24"))
    assert set(by[EntityType.COMPANY]) == {"Amazon Web Services", "Cloudflare", "DigitalOcean"}
    assert "digitalocean:Frankfurt am Main, DE" in by[EntityType.CLOUD_REGION]
    assert await run_lookup("hosting_provider", "ip", "8.8.8.8") == []


async def test_pgp_keyservers(fake_http, run_lookup, fixtures_dir):
    keys = parse_hkp_index((fixtures_dir / "internal/hkp_index.txt").read_text(), "s")
    assert [k["fingerprint"][:4] for k in keys] == ["0123", "FEDC", "AAAA"] and keys[0]["uids"][0] == {
        "name": "Jane Doe",
        "email": "jane.doe@example.com",
        "raw": "Jane Doe <jane.doe@example.com>",
    }
    assert keys[0]["created"].year == 2015 and keys[1]["flags"] == "r"
    fake_http.route("keys.openpgp.org", file="internal/hkp_index.txt").route(
        "keyserver.ubuntu.com", file="internal/hkp_index.txt"
    )
    emits = await run_lookup("pgp_keyservers", "domain", "example.com")
    by = _by_type(emits)
    assert by[EntityType.PGP_KEY] == [
        "0123456789ABCDEF0123456789ABCDEF01234567",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ]
    assert by[EntityType.EMAIL] == ["jane.doe@example.com", "jane@example.org", "sales@example.com"] and by[
        EntityType.PERSON
    ] == ["Jane Doe", "Jane Doe (work)"]
    assert len(fake_http.calls) == 1 and "ubuntu" in fake_http.urls()[0]
    by = _by_type(await run_lookup("pgp_keyservers", "email", "jane.doe@example.com"))
    assert by[EntityType.PGP_KEY] == ["0123456789ABCDEF0123456789ABCDEF01234567"] and by[EntityType.EMAIL] == [
        "jane@example.org"
    ]


async def test_gleif(fake_http, run_lookup):
    fake_http.route("lei-records/5493001KJTIIGC8Y1R12", file="internal/gleif_search.json").route(
        "lei-records?filter", file="internal/gleif_search.json"
    )
    by = _by_type(await run_lookup("gleif", "company", "Example Networks LLC"))
    assert by[EntityType.LEI] == ["5493001KJTIIGC8Y1R12"] and EntityType.COMPANY not in by
    assert by[EntityType.PHYSICAL_ADDRESS] == [
        "100 Main Street, Suite 4, Anytown, US-CA, 90210, US",
        "1 Harbour Road, Sydney, AU-NSW, 2000, AU",
    ]
    emits = await run_lookup("gleif", "lei", "5493001KJTIIGC8Y1R12")
    by = _by_type(emits)
    assert (
        by[EntityType.COMPANY] == ["Example Networks LLC"]
        and EntityType.LEI not in by
        and emits[0].meta["status"] == "ACTIVE"
    )


# ---- file_metadata: EXIF/TIFF/PDF metadata (pure parsers over hand-built bytes) ------------------------------

import struct  # noqa: E402
from datetime import datetime  # noqa: E402

from osint_board.modules.base import Scope  # noqa: E402
from osint_board.modules.impl.file_metadata import (  # noqa: E402
    detect_type,
    extract_metadata,
    jpeg_exif_block,
    parse_exif,
    parse_pdf_date,
    parse_pdf_info,
)
from osint_board.modules.types import EntityRef as _Ref  # noqa: E402


def _payload(typ, values):
    if typ == 2:  # ASCII
        b = values.encode("latin-1") + b"\x00"
        return len(b), b
    if typ == 1:  # BYTE
        return len(values), bytes(values)
    if typ == 3:  # SHORT
        return len(values), struct.pack(f"<{len(values)}H", *values)
    if typ == 4:  # LONG
        return len(values), struct.pack(f"<{len(values)}I", *values)
    if typ == 5:  # RATIONAL
        return len(values), b"".join(struct.pack("<II", n, d) for n, d in values)
    raise AssertionError(typ)


def _build_ifd(entries, overflow_base, overflow):
    out = struct.pack("<H", len(entries))
    for tag, typ, values in entries:
        count, payload = _payload(typ, values)
        if len(payload) <= 4:
            field = payload + b"\x00" * (4 - len(payload))
        else:
            field = struct.pack("<I", overflow_base + len(overflow))
            overflow += payload + (b"\x00" if len(payload) % 2 else b"")
        out += struct.pack("<HHI", tag, typ, count) + field
    return out + struct.pack("<I", 0)  # no next IFD


def _build_tiff(ifd0, exif=None, gps=None):
    n0 = len(ifd0) + (1 if exif else 0) + (1 if gps else 0)
    ifd0_size = 2 + 12 * n0 + 4
    exif_off = 8 + ifd0_size
    exif_size = (2 + 12 * len(exif) + 4) if exif else 0
    gps_off = exif_off + exif_size if exif else 8 + ifd0_size
    gps_size = (2 + 12 * len(gps) + 4) if gps else 0
    overflow_base = gps_off + gps_size

    ifd0 = list(ifd0)
    if exif is not None:
        ifd0.append((0x8769, 4, [exif_off]))
    if gps is not None:
        ifd0.append((0x8825, 4, [gps_off]))

    overflow = bytearray()
    body = _build_ifd(ifd0, overflow_base, overflow)
    if exif is not None:
        body += _build_ifd(exif, overflow_base, overflow)
    if gps is not None:
        body += _build_ifd(gps, overflow_base, overflow)
    return b"II" + struct.pack("<HI", 0x2A, 8) + body + bytes(overflow)


def _sample_jpeg():
    tiff = _build_tiff(
        ifd0=[
            (0x010F, 2, "ACME"),
            (0x0110, 2, "CoolCam"),
            (0x0131, 2, "OSINT 1.0"),
            (0x013B, 2, "Alice Ex"),
            (0x0132, 2, "2021:06:15 14:30:00"),
        ],
        exif=[(0x9003, 2, "2021:06:15 14:29:59")],
        gps=[
            (0x0001, 2, "N"),
            (0x0002, 5, [(51, 1), (30, 1), (0, 1)]),
            (0x0003, 2, "W"),
            (0x0004, 5, [(0, 1), (7, 1), (30, 1)]),
            (0x0005, 1, [0]),
            (0x0006, 5, [(100, 1)]),
        ],
    )
    app1 = b"Exif\x00\x00" + tiff
    return b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1 + b"\xff\xd9"


def test_detect_type():
    assert detect_type(_sample_jpeg()) == "jpeg"
    assert detect_type(b"%PDF-1.7\n...") == "pdf"
    assert detect_type(b"II\x2a\x00rest") == "tiff"
    assert detect_type(b"nonsense") == "unknown"


def test_parse_exif_reads_camera_author_time_and_gps():
    exif = parse_exif(jpeg_exif_block(_sample_jpeg()))
    assert exif["make"] == "ACME" and exif["model"] == "CoolCam" and exif["software"] == "OSINT 1.0"
    assert exif["artist"] == "Alice Ex" and exif["datetime_original"] == "2021:06:15 14:29:59"
    lat, lon, alt = exif["gps"]
    assert round(lat, 4) == 51.5 and round(lon, 4) == -0.125 and alt == 100.0  # W longitude is negative


def test_parse_exif_is_defensive_about_junk():
    assert parse_exif(b"") == {} and parse_exif(b"II\x2a\x00\xff\xff\xff\xff") == {}
    assert jpeg_exif_block(b"not a jpeg") is None


def test_extract_metadata_from_jpeg_collects_entities():
    meta = extract_metadata(_sample_jpeg())
    assert meta.file_type == "jpeg"
    assert "ACME CoolCam" in meta.software and "OSINT 1.0" in meta.software
    assert meta.people == ["Alice Ex"] and meta.gps[0] == 51.5
    assert meta.timestamps and meta.timestamps[0][1] == datetime(2021, 6, 15, 14, 29, 59)


def test_parse_pdf_date():
    from datetime import UTC, timedelta, timezone

    aware = parse_pdf_date("D:20210615143000+02'00'")
    assert aware == datetime(2021, 6, 15, 14, 30, tzinfo=timezone(timedelta(hours=2)))
    assert aware.utcoffset() == timedelta(hours=2)  # offset preserved: the real instant is 12:30 UTC
    assert parse_pdf_date("D:20210615143000Z") == datetime(2021, 6, 15, 14, 30, tzinfo=UTC)
    assert parse_pdf_date("D:2021") == datetime(2021, 1, 1, 0, 0, 0)  # naive when no offset is given
    assert parse_pdf_date("junk") is None


def test_parse_pdf_info_reads_literal_and_hex_strings():
    pdf = (
        b"%PDF-1.7\n1 0 obj<</Author (Jane Doe)/Producer (LibreOffice 7.5)"
        b"/Creator (Writer)/CreationDate (D:20210615143000)"
        b"/Title <feff0054004b>>>\nendobj\n"
    )
    info = parse_pdf_info(pdf)
    assert info["author"] == "Jane Doe" and info["producer"] == "LibreOffice 7.5"
    assert info["title"] == "TK"  # UTF-16BE hex string
    meta = extract_metadata(pdf)
    assert meta.people == ["Jane Doe"] and "LibreOffice 7.5" in meta.software
    assert meta.timestamps[0][1] == datetime(2021, 6, 15, 14, 30, 0)


async def test_file_metadata_lookup_over_inline_bytes(registry):
    mod = registry.instantiate("file_metadata", scope=Scope())
    target = _Ref(EntityType.RAW_FILE, "photo.jpg", meta={"text": _sample_jpeg().decode("latin-1")})
    emits = [e async for e in mod.lookup(target)]
    by_type = {}
    for e in emits:
        by_type.setdefault(e.type, []).append(e)

    (point,) = by_type[EntityType.GEO_POINT]
    assert point.geo.precision == "exact" and point.layer == "media" and round(point.geo.lat, 4) == 51.5
    assert {e.value for e in by_type[EntityType.PERSON]} == {"Alice Ex"}
    assert "ACME CoolCam" in {e.value for e in by_type[EntityType.SOFTWARE]}
    assert by_type[EntityType.TIMESTAMP][0].observed_at == datetime(2021, 6, 15, 14, 29, 59)


async def test_file_metadata_lookup_fetches_a_url(registry, fake_http):
    fake_http.route("files.example/photo.jpg", body=_sample_jpeg())
    mod = registry.instantiate("file_metadata", scope=Scope())
    emits = [e async for e in mod.lookup(_Ref(EntityType.RAW_FILE, "https://files.example/photo.jpg"))]
    assert any(e.type is EntityType.GEO_POINT for e in emits)


async def test_file_metadata_quiet_when_there_is_nothing_to_read(registry):
    mod = registry.instantiate("file_metadata", scope=Scope())
    # a decoded blob (no bytes, no fetchable URL) and an unknown file type both yield nothing
    assert [e async for e in mod.lookup(_Ref(EntityType.RAW_FILE, "base64:beef"))] == []
    assert [e async for e in mod.lookup(_Ref(EntityType.RAW_FILE, "x", meta={"text": "plain text, no exif"}))] == []
