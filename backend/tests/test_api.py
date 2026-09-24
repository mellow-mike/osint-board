from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from osint_board.api.app import create_app
from osint_board.config import Settings
from osint_board.search.index import SearchDoc

from .conftest import ROOT


@pytest.fixture
async def client():
    settings = Settings(env="test", catalog_dir=ROOT / "catalog")
    app = create_app(settings, use_memory_index=True)
    async with app.router.lifespan_context(app):
        await app.state.osint.index.upsert(
            [
                SearchDoc(id="1", type="domain", value="example.com", label="example.com", tags=["seed"], degree=3),
                SearchDoc(id="2", type="hostname", value="mail.example.com", label="mail.example.com"),
                SearchDoc(
                    id="3", type="ip", value="203.0.113.7", label="203.0.113.7", has_geo=True, lat=37.4, lon=-122.1
                ),
            ]
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c


async def test_health(client):
    r = await client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["services"]["search"] == "memory"


async def test_catalog_endpoints(client):
    mods = (await client.get("/api/catalog/modules")).json()
    assert len(mods) == 239
    feeds = (await client.get("/api/catalog/modules", params={"mode": "feed"})).json()
    assert {m["id"] for m in feeds} >= {"usgs", "gdelt", "aisstream", "opensky", "celestrak", "nasa_firms"}
    one = (await client.get("/api/catalog/modules/usgs")).json()
    assert one["implementation_status"] == "implemented"
    assert (await client.get("/api/catalog/modules/nope")).status_code == 404
    layers = (await client.get("/api/catalog/layers")).json()
    assert {lyr["id"] for lyr in layers} >= {"maritime", "aviation", "space", "seismic", "fires"}
    cov = (await client.get("/api/catalog/coverage")).json()
    assert cov["total"] == 239 and cov["implemented"] >= 6
    assert len((await client.get("/api/catalog/services")).json()) >= 20
    assert len((await client.get("/api/catalog/entities")).json()) == 77


async def test_search_exact_and_fuzzy(client):
    r = (await client.get("/api/search", params={"q": "example.com"})).json()
    assert r["hits"][0]["value"] == "example.com" and r["hits"][0]["why"] == "exact"
    assert r["plan"]["detections"][0]["type"] == "domain"
    assert any(s["kind"] == "run_module" and s["payload"]["module"] == "crt_sh" for s in r["suggestions"])

    r = (await client.get("/api/search", params={"q": "exampl"})).json()
    assert {h["value"] for h in r["hits"]} == {"example.com", "mail.example.com"}

    r = (await client.get("/api/search", params={"q": "48.85, 2.35"})).json()
    assert r["plan"]["intents"][0] == "locate" and r["suggestions"][0]["kind"] == "fly_to"


async def test_search_parse_endpoint(client):
    r = (await client.get("/api/search/parse", params={"q": "icao:a1b2c3 layer:aviation"})).json()
    assert r["detections"][0]["type"] == "aircraft" and r["layers"] == ["aviation"]


async def test_layer_features_degrade_without_database(client):
    r = await client.get("/api/layers/seismic/features")
    assert r.status_code == 200
    assert r.json()["features"] == []
    assert (await client.get("/api/layers/nope/features")).status_code == 404
