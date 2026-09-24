"""Crypto, app-store, geocoding, WiGLE, dark-web search and bucket-finder modules."""

from __future__ import annotations

import base64
import json

import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.helpers import find_onion_urls
from osint_board.modules.impl.etherscan import parse_balance
from osint_board.modules.impl.nominatim import precision_for
from osint_board.modules.impl.wigle import auth_header
from osint_board.modules.types import EntityRef

ONION_A = "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"


def _by_type(emits):
    out: dict[EntityType, list[str]] = {}
    for e in emits:
        out.setdefault(e.type, []).append(e.value)
    return out


async def test_blockchain_com(fake_http, run_lookup):
    fake_http.route("blockchain.info/rawaddr/1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", file="misc/blockchain_rawaddr.json")
    emits = await run_lookup("blockchain_com", "btc_address", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    by = _by_type(emits)
    assert (
        by[EntityType.CRYPTO_BALANCE] == ["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2: 1.00000000 BTC"]
        and emits[0].meta["tx_count"] == 2
    )
    txs = [e for e in emits if e.type is EntityType.CRYPTO_TRANSACTION]
    assert (
        [t.relation for t in txs] == ["sent", "received"]
        and txs[0].meta["amount"] == -0.5001
        and txs[1].observed_at.year == 2023
    )
    fake_http.route("blockchain.info/rawaddr/", "", status=404)
    assert await run_lookup("blockchain_com", "btc_address", "1111111111111111111114oLvT2") == []


async def test_etherscan(fake_http, run_lookup, monkeypatch, fixtures_dir):
    assert (
        parse_balance(
            json.loads((fixtures_dir / "misc/etherscan_notok.json").read_text()),
            EntityRef(EntityType.ETH_ADDRESS, "0xabc"),
        )
        == []
    )
    with pytest.raises(RuntimeError):
        await run_lookup("etherscan", "eth_address", "0x52908400098527886E0F7030069857D2E4169EE7")
    monkeypatch.setenv("OSINT_MODULE_ETHERSCAN_API_KEY", "es")
    fake_http.route("action=balance", file="misc/etherscan_balance.json").route(
        "action=txlist", file="misc/etherscan_txlist.json"
    )
    emits = await run_lookup("etherscan", "eth_address", "0x52908400098527886E0F7030069857D2E4169EE7")
    by = _by_type(emits)
    assert by[EntityType.CRYPTO_BALANCE] == ["0x52908400098527886e0f7030069857d2e4169ee7: 1.500000 ETH"]
    txs = [e for e in emits if e.type is EntityType.CRYPTO_TRANSACTION]
    assert [t.relation for t in txs] == ["sent", "received"] and txs[1].meta["amount"] == 1.75
    assert fake_http.calls[-1][2]["params"]["chainid"] == 1 and fake_http.calls[-1][2]["params"]["apikey"] == "es"


async def test_apple_itunes(fake_http, run_lookup):
    fake_http.route("itunes.apple.com/search", file="misc/itunes_search.json")
    by = _by_type(await run_lookup("apple_itunes", "domain", "example.com"))
    assert by[EntityType.MOBILE_APP] == ["ios:com.example.wallet", "ios:com.example.tracker"]
    by = _by_type(await run_lookup("apple_itunes", "company", "Example Networks"))
    assert by[EntityType.MOBILE_APP] == ["ios:com.example.wallet", "ios:com.example.tracker"]
    assert fake_http.calls[-1][2]["params"]["term"] == "Example Networks"


async def test_nominatim(fake_http, run_lookup):
    assert (
        precision_for({"class": "highway", "type": "residential"}) == "street"
        and precision_for({"addresstype": "country"}) == "country"
    )
    fake_http.route("/search", file="misc/nominatim_search.json").route("/reverse", file="misc/nominatim_reverse.json")
    emits = await run_lookup(
        "nominatim",
        "physical_address",
        "Hôtel de Ville, Paris",
        config={"base_url": "https://geocoder.internal/nominatim/"},
    )
    assert [(e.type, e.geo.precision) for e in emits] == [
        (EntityType.GEO_POINT, "rooftop"),
        (EntityType.GEO_POINT, "city"),
    ]
    assert emits[0].value == "48.856697,2.351462" and emits[0].meta["country"] == "FR" and emits[0].confidence == 0.92
    assert fake_http.urls()[-1].startswith("https://geocoder.internal/nominatim/search")
    emits = await run_lookup("nominatim", "geo_point", "48.85668, 2.35146")
    assert (
        emits[0].type is EntityType.PHYSICAL_ADDRESS
        and emits[0].meta["precision"] == "street"
        and emits[0].value.startswith("Place de l")
    )
    assert fake_http.calls[-1][2]["params"]["lat"] == 48.85668


async def test_wigle(fake_http, run_lookup, monkeypatch):
    assert (
        auth_header("name:token") == "Basic " + base64.b64encode(b"name:token").decode()
        and auth_header("bmFtZTp0b2tlbg==") == "Basic bmFtZTp0b2tlbg=="
    )
    monkeypatch.setenv("OSINT_MODULE_WIGLE_API_KEY", "name:token")
    fake_http.route("api.wigle.net/api/v2/network/search", file="misc/wigle_search.json")
    emits = await run_lookup("wigle", "geo_point", "52.52, 13.405")
    assert [e.key for e in emits] == ["wifi:00:11:22:33:44:55", "wifi:66:77:88:99:aa:bb"]
    assert (
        emits[0].layer == "wifi"
        and emits[0].geo.precision == "street"
        and emits[0].meta["ssid"] == "ExampleCorp-Guest"
        and emits[0].observed_at.year == 2026
    )
    params = fake_http.calls[-1][2]["params"]
    assert params["latrange1"] == pytest.approx(52.515) and params["longrange2"] == pytest.approx(13.41)
    await run_lookup("wigle", "wifi_ap", "00-11-22-33-44-55")
    assert fake_http.calls[-1][2]["params"]["netid"] == "00:11:22:33:44:55"
    fake_http.routes.clear()
    fake_http.route("api.wigle.net", file="misc/wigle_fail.json")
    with pytest.raises(RuntimeError, match="too many queries"):
        await run_lookup("wigle", "keyword", "ExampleCorp")


async def test_darkweb_search(fake_http, run_lookup, fixtures_dir):
    found = find_onion_urls((fixtures_dir / "misc/ahmia_search.html").read_text())
    assert found[0] == (ONION_A + "/page", "Example leak discussion") and len(found) == 2
    fake_http.route("ahmia.fi/search", file="misc/ahmia_search.html").route(
        "onionsearchengine.com", file="misc/onionsearchengine.html"
    )
    by = _by_type(await run_lookup("ahmia", "domain", "example.com"))
    assert (
        by[EntityType.DARKWEB_MENTION]
        == [ONION_A + "/page", "http://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.onion/"]
        and len(by[EntityType.URL]) == 2
    )
    by = _by_type(await run_lookup("onionsearchengine", "domain", "example.com"))
    assert by[EntityType.DARKWEB_MENTION] == [
        ONION_A + "/forum",
        "http://yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy.onion/x.html",
    ]
    fake_http.route(".onion/search", file="misc/torch_search.html")
    by = _by_type(await run_lookup("torch", "domain", "example.com"))
    assert by[EntityType.DARKWEB_MENTION] == [ONION_A + "/market"]


async def test_s3_and_gcs_finders(fake_http, run_lookup):
    fake_http.route("example-backup.s3.amazonaws.com", file="misc/s3_listing.xml").route(
        "example.s3.amazonaws.com", file="misc/s3_denied.xml", status=403
    )
    fake_http.route("s3.amazonaws.com", file="misc/s3_missing.xml", status=404)
    emits = await run_lookup("s3_bucket_finder", "domain", "example.com", config={"max_candidates": 30})
    found = {e.value: e for e in emits}
    assert set(found) == {"https://example-backup.s3.amazonaws.com/", "https://example.s3.amazonaws.com/"}
    public = found["https://example-backup.s3.amazonaws.com/"]
    assert (
        public.meta["public"] is True
        and public.meta["objects"] == ["db/backup-2026-09-01.sql.gz", "logs/access.log"]
        and public.confidence == 0.6
    )
    assert found["https://example.s3.amazonaws.com/"].meta["public"] is False and public.relation == "may_own"
    assert len(fake_http.calls) == 30
    fake_http.routes.clear()
    fake_http.route("storage.googleapis.com/example-backup/", file="misc/s3_listing.xml").route(
        "storage.googleapis.com", "", status=404
    )
    emits = await run_lookup("gcs_bucket_finder", "company", "Example", config={"max_candidates": 10})
    assert [e.value for e in emits] == ["https://storage.googleapis.com/example-backup/"] and emits[0].meta[
        "provider"
    ] == "gcs"


async def test_azure_and_do_finders(fake_http, fake_dns, run_lookup):
    fake_dns.on("example.blob.core.windows.net", ["20.60.1.1"]).on("exampledev.blob.core.windows.net", ["20.60.1.2"])
    fake_http.route("example.blob.core.windows.net", file="misc/azure_listing.xml").route(
        "exampledev.blob.core.windows.net", "<Error>AuthenticationFailed</Error>", status=403
    )
    emits = await run_lookup("azure_blob_finder", "domain", "example.com", config={"max_candidates": 40})
    found = {e.meta["name"]: e for e in emits}
    assert set(found) == {"example", "exampledev"} and found["example"].meta["objects"] == ["public", "backups"]
    assert len(fake_http.calls) == 2  # everything else was NXDOMAIN and never probed
    fake_http.routes.clear()
    fake_http.calls.clear()
    fake_http.route("example.nyc3.digitaloceanspaces.com", "", status=403).route(
        "digitaloceanspaces.com", "", status=404
    )
    emits = await run_lookup("do_spaces_finder", "domain", "example.com", config={"max_candidates": 3})
    assert [e.value for e in emits] == ["https://example.nyc3.digitaloceanspaces.com/"] and len(fake_http.calls) == 27
