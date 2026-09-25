from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from osint_board.api.app import create_app
from osint_board.config import Settings
from osint_board.search.index import SearchDoc

from .conftest import ROOT


class FakeSession:
    """Stands in for the database session: records each statement and answers with canned rows."""

    def __init__(self, rows: dict[str, list] | None = None) -> None:
        self.rows = rows or {}
        self.statements: list[tuple[str, dict]] = []

    async def execute(self, stmt, params=None):  # noqa: ANN001
        sql = str(stmt)
        self.statements.append((sql, params or {}))
        rows = next((r for needle, r in self.rows.items() if needle in sql), [])
        return SimpleNamespace(all=lambda: rows, scalar=lambda: rows[0] if rows else None)


@pytest.fixture
def app():
    return create_app(Settings(env="test", catalog_dir=ROOT / "catalog"), use_memory_index=True)


@pytest.fixture
async def client(app):
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


async def test_static_layers_read_static_features(app, client):
    from osint_board.api.deps import get_session

    relay = SimpleNamespace(
        key="ABCDEF0123456789",
        name="relay1",
        lon=13.4,
        lat=52.5,
        props={"name": "relay1", "precision": "city", "relay_role": "exit"},
        time=datetime(2026, 9, 24, tzinfo=UTC),
    )
    session = FakeSession({"FROM static_features": [relay]})

    async def fake_session():
        yield session

    app.dependency_overrides[get_session] = fake_session
    body = (await client.get("/api/layers/tor/features")).json()
    assert "FROM static_features" in session.statements[0][0] and session.statements[0][1]["layer"] == "tor"
    feat = body["features"][0]
    assert feat["id"] == "ABCDEF0123456789" and feat["geometry"]["coordinates"] == [13.4, 52.5]
    assert feat["properties"]["precision"] == "city" and feat["properties"]["entity_type"] == "tor_relay"

    # tiled layers (cell towers, Wi-Fi) only answer for a viewport
    assert (await client.get("/api/layers/cell_towers/features")).status_code == 400
    r = await client.get("/api/layers/cell_towers/features", params={"bbox": "13.3,52.4,13.5,52.6"})
    assert r.status_code == 200 and session.statements[-1][1]["minx"] == 13.3


async def test_investigation_graph(app, client):
    import uuid

    from osint_board.api.deps import get_session

    inv = uuid.uuid4()
    domain, page, email, lonely = (uuid.uuid4() for _ in range(4))

    def node(i, etype, value, **geo):
        return SimpleNamespace(
            id=i, type=etype, value=value, confidence=1.0, source_module="web_spider",
            geo_precision=geo.get("precision"), lon=geo.get("lon"), lat=geo.get("lat"),
        )  # fmt: skip

    def edge(a, b, rel, module="web_spider"):
        return SimpleNamespace(from_id=a, to_id=b, rel_type=rel, source_module=module, confidence=0.9)

    session = FakeSession(
        {
            "FROM entities": [
                node(domain, "domain", "example.com"),
                node(page, "url", "https://www.example.com/", precision="city", lon=-6.26, lat=53.35),
                node(email, "email", "info@example.com"),
                node(lonely, "ip", "203.0.113.7"),
            ],
            "FROM relations": [edge(domain, page, "crawled"), edge(page, email, "mentioned_in", "email_extractor")],
        }
    )
    known = {inv}

    async def get(model, key):  # noqa: ANN001
        return SimpleNamespace(id=key) if key in known else None

    session.get = get

    async def fake_session():
        yield session

    app.dependency_overrides[get_session] = fake_session
    body = (await client.get(f"/api/investigations/{inv}/graph")).json()
    degree = {n["value"]: n["degree"] for n in body["nodes"]}
    assert degree == {"example.com": 1, "https://www.example.com/": 2, "info@example.com": 1, "203.0.113.7": 0}
    assert [(e["rel_type"], e["source_module"]) for e in body["edges"]] == [
        ("crawled", "web_spider"),
        ("mentioned_in", "email_extractor"),
    ]
    assert body["edges"][1]["source"] == str(page) and body["truncated"] is False
    assert session.statements[1][1]["ids"] == [domain, page, email, lonely]
    assert (await client.get(f"/api/investigations/{uuid.uuid4()}/graph")).status_code == 404
    assert session.statements[0][1]["limit"] == 2001  # one extra row tells whether there is more
    small = (await client.get(f"/api/investigations/{inv}/graph", params={"limit": 2})).json()
    assert small["truncated"] is True and len(small["nodes"]) == 2
    assert [e["rel_type"] for e in small["edges"]] == ["crawled"]  # only edges between returned nodes


def _track(key: str, **props) -> SimpleNamespace:  # noqa: ANN003
    return SimpleNamespace(
        key=key, name="RYR1", kind=props.get("kind"), lon=8.0, lat=50.0, alt_m=10_000.0, props=props,
        time=datetime(2026, 9, 24, 12, tzinfo=UTC), heading=90.0, speed=450.0,
    )  # fmt: skip


async def test_live_layers_clamp_since_to_max_age(app, client):
    from osint_board.api.deps import get_session

    session = FakeSession(
        {
            "FROM tracks": [
                _track("aviation:4ca334", entity_type="aircraft", kind="large", altitude_m=10_000.0),
                _track("aviation:3c1234", kind="heavy"),  # stored before the sink wrote entity_type
            ]
        }
    )

    async def fake_session():
        yield session

    app.dependency_overrides[get_session] = fake_session
    before = datetime.now(tz=UTC)
    body = (await client.get("/api/layers/aviation/features", params={"since": "7d"})).json()
    sql, params = session.statements[-1]
    assert "kind AS entity_type" not in sql
    max_age = app.state.osint.catalog.layer("aviation").max_age_seconds
    assert max_age == 1200
    assert params["since"] >= before - timedelta(seconds=max_age)  # a week was asked for; 20 minutes is served
    first, second = (f["properties"] for f in body["features"])
    assert first["entity_type"] == "aircraft" and first["kind"] == "large"
    assert second["entity_type"] == "aircraft" and second["kind"] == "heavy"  # kind never leaks into entity_type

    # a narrower window than max_age is kept as asked
    await client.get("/api/layers/aviation/features", params={"since": "5m"})
    assert session.statements[-1][1]["since"] >= before - timedelta(minutes=5, seconds=5)
    # events layers without max_age keep the requested window
    await client.get("/api/layers/seismic/features", params={"since": "7d"})
    assert session.statements[-1][1]["since"] <= before - timedelta(days=6)
    # GDELT stamps events with the end of their 15-minute window, ahead of now: they must not be hidden
    await client.get("/api/layers/news/features", params={"since": "1h"})
    assert session.statements[-1][1]["until"] >= before + timedelta(minutes=15)


async def test_static_layers_filter_on_max_age(app, client):
    from osint_board.api.deps import get_session

    session = FakeSession()

    async def fake_session():
        yield session

    app.dependency_overrides[get_session] = fake_session
    before = datetime.now(tz=UTC)
    await client.get("/api/layers/tor/features")
    sql, params = session.statements[-1]
    assert "updated_at >= :since" in sql
    assert before - timedelta(hours=6, seconds=5) <= params["since"] <= before - timedelta(hours=5, minutes=59)
    await client.get("/api/layers/cell_towers/features", params={"bbox": "13.3,52.4,13.5,52.6", "since": "1h"})
    assert session.statements[-1][1]["since"].year == 1970  # no max_age: reference data is served whatever its age


async def test_unparseable_since_is_rejected(client):
    r = await client.get("/api/layers/seismic/features", params={"since": "garbage"})
    assert r.status_code == 400 and "since" in r.json()["detail"]
    # a duration past what datetime can represent is a bad request too, not a server error
    assert (await client.get("/api/layers/aviation/features", params={"since": "99999999999d"})).status_code == 400
    assert (
        await client.get("/api/layers/seismic/features", params={"since": "2026-09-24T10:00:00Z"})
    ).status_code == 200


async def test_large_responses_are_gzipped(app, client):
    from osint_board.api.deps import get_session

    rows = [
        SimpleNamespace(
            key=f"relay{i:04d}", name=f"relay{i}", lon=13.4, lat=52.5, props={"name": f"relay{i}", "precision": "city"},
            time=datetime(2026, 9, 24, tzinfo=UTC),
        )
        for i in range(200)
    ]  # fmt: skip
    session = FakeSession({"FROM static_features": rows})

    async def fake_session():
        yield session

    app.dependency_overrides[get_session] = fake_session
    r = await client.get("/api/layers/tor/features", headers={"accept-encoding": "gzip"})
    assert r.status_code == 200 and r.headers["content-encoding"] == "gzip" and r.json()["count"] == 200
    small = await client.get("/api/health", headers={"accept-encoding": "gzip"})
    assert "content-encoding" not in small.headers
