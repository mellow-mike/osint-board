from __future__ import annotations

import pytest

from osint_board.entities.detect import base58check_ok, bech32_ok, classify, luhn_ok, mod97_ok, scan
from osint_board.entities.types import EntityType


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("203.0.113.7", EntityType.IP),
        ("2001:db8::1", EntityType.IP),
        ("203.0.113.0/24", EntityType.NETBLOCK),
        ("AS13335", EntityType.ASN),
        ("as13335", EntityType.ASN),
        ("example.com", EntityType.DOMAIN),
        ("mail.example.co.uk", EntityType.HOSTNAME),
        ("alice@example.com", EntityType.EMAIL),
        ("https://example.com/login?x=1", EntityType.URL),
        ("CVE-2024-3094", EntityType.VULNERABILITY),
        ("00:11:22:33:44:55", EntityType.WIFI_AP),
        ("0x52908400098527886E0F7030069857D2E4169EE7", EntityType.ETH_ADDRESS),
        ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", EntityType.BTC_ADDRESS),
        ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", EntityType.BTC_ADDRESS),
        ("d41d8cd98f00b204e9800998ecf8427e", EntityType.HASH),
        ("GB82WEST12345698765432", EntityType.IBAN),
        ("+442071838750", EntityType.PHONE),
        ("@jdoe_42", EntityType.USERNAME),
        ("48.8566, 2.3522", EntityType.GEO_POINT),
        ("48.8566N 2.3522E", EntityType.GEO_POINT),
        ("IMO 9811000", EntityType.VESSEL),
        ("310-410-1234-56789", EntityType.CELL_TOWER),
    ],
)
def test_classify_best_guess(token, expected):
    dets = classify(token)
    assert dets, token
    assert dets[0].type is expected, [d.type for d in dets]


def test_ambiguous_tokens_return_ranked_candidates():
    types = [d.type for d in classify("366999999")]  # MMSI-shaped: vessel first, then satellite guess
    assert types[0] is EntityType.VESSEL
    types = [d.type for d in classify("25544")]
    assert EntityType.SATELLITE in types
    types = [d.type for d in classify("a1b2c3")]
    assert EntityType.AIRCRAFT in types


def test_junk_is_not_detected():
    assert classify("hello world") == []
    assert classify("not_a_domain") == []
    assert [d.type for d in classify("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3")] == []  # bad checksum


def test_checksums():
    assert base58check_ok("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    assert not base58check_ok("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3")
    assert bech32_ok("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
    assert not bech32_ok("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx")
    assert mod97_ok("GB82WEST12345698765432", rearrange=True)
    assert not mod97_ok("GB82WEST12345698765433", rearrange=True)
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")


def test_scan_finds_mixed_identifiers():
    text = (
        "Contact ops@example.com or +1 415-555-2671. Host 203.0.113.7 (also 2001:db8::5) serves api.example.com; "
        "wallet 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2, md5 d41d8cd98f00b204e9800998ecf8427e, CVE-2021-44228."
    )
    found = {(d.type, d.normalized) for d in scan(text)}
    assert (EntityType.EMAIL, "ops@example.com") in found
    assert (EntityType.IP, "203.0.113.7") in found
    assert (EntityType.IP, "2001:db8::5") in found
    assert (EntityType.HOSTNAME, "api.example.com") in found
    assert (EntityType.BTC_ADDRESS, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") in found
    assert (EntityType.HASH, "d41d8cd98f00b204e9800998ecf8427e") in found
    assert (EntityType.VULNERABILITY, "CVE-2021-44228") in found
    assert any(t is EntityType.PHONE for t, _ in found)


def test_scan_restricts_types():
    found = scan("ops@example.com 203.0.113.7", {EntityType.EMAIL})
    assert {d.type for d in found} == {EntityType.EMAIL}
