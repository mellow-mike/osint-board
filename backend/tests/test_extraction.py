"""The extractor pipeline and how the store links content-derived findings (no database, no network)."""

from __future__ import annotations

import json
import uuid

from osint_board.entities.types import EntityType
from osint_board.modules.extraction import ExtractorPipeline, content_of
from osint_board.modules.types import Emit, EntityRef
from osint_board.worker.store import EntityStore, entity_meta

TARGET = EntityRef(EntityType.DOMAIN, "example.com")
PAGE = "https://www.example.com/contact"
HTML = """<html><head><script>gtag('config', 'UA-1234567-1');</script></head>
<body>Write to <a href="mailto:press@example.com">press@example.com</a> or call +44 20 7183 8750.
Follow us: <a href="https://twitter.com/examplecorp">Twitter</a>. Donate: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT</body></html>"""


def page_emits() -> list[Emit]:
    return [
        Emit(EntityType.URL, PAGE, relation="links_to", parent=TARGET),
        Emit(
            EntityType.RAW_CONTENT,
            PAGE,
            relation="content_of",
            parent=EntityRef(EntityType.URL, PAGE),
            meta={"text": HTML, "content_type": "text/html", "source": "web_spider"},
        ),
    ]


def test_content_of():
    raw = page_emits()[1]
    c = content_of(raw)
    assert c.text == HTML and c.source_url == PAGE and c.content_type == "text/html"
    assert c.parent == EntityRef(EntityType.RAW_CONTENT, PAGE)
    assert content_of(Emit(EntityType.RAW_CONTENT, PAGE)) is None  # nothing to read
    phone = content_of(Emit(EntityType.PHONE, "+442071838750"))
    assert phone.text == "+442071838750" and phone.parent.type is EntityType.PHONE


def test_pipeline_runs_extractors_and_chains(registry):
    found = ExtractorPipeline(registry).run(page_emits())
    values = {mod: {(e.type.value, e.value) for e in emits} for mod, emits in found.items()}
    assert values["email_extractor"] == {("email", "press@example.com")}
    assert values["phone_extractor"] == {("phone", "+442071838750")}
    assert values["web_analytics_extractor"] == {("web_analytics_id", "UA-1234567-1")}
    assert values["bitcoin_finder"] == {("btc_address", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT")}
    assert values["social_network_identifier"] == {("social_profile", "https://x.com/examplecorp")}
    email = found["email_extractor"][0]
    assert email.parent == EntityRef(EntityType.RAW_CONTENT, PAGE) and email.meta["source_url"] == PAGE
    # second round: the phone number found on the page goes on to the country extractor
    countries = [e for e in found["country_extractor"] if e.parent and e.parent.type is EntityType.PHONE]
    assert [(c.value, c.parent.value) for c in countries] == [("GB", "+442071838750")]


def test_pipeline_dedupes_per_document(registry):
    pipeline = ExtractorPipeline(registry)
    twice = page_emits() + page_emits()
    assert len(pipeline.run(twice)["email_extractor"]) == 1  # the same page is scanned once
    other = Emit(EntityType.RAW_CONTENT, "https://www.example.com/about", meta={"text": "press@example.com"})
    emails = pipeline.run([*page_emits(), other])["email_extractor"]
    assert sorted(e.parent.value for e in emails) == ["https://www.example.com/about", PAGE]  # one edge per page


class NoGeo:
    async def resolve(self, etype, value, meta):  # noqa: ANN001
        return None


class RecordingSession:
    def __init__(self) -> None:
        self.entities: dict[tuple[str, str], uuid.UUID] = {}
        self.metas: dict[tuple[str, str], dict] = {}
        self.relations: list[tuple[uuid.UUID, uuid.UUID, str]] = []

    async def execute(self, stmt, params):  # noqa: ANN001
        sql = str(stmt)
        if "INSERT INTO entities" in sql:
            key = (params["type"], params["normalized"])
            eid = self.entities.setdefault(key, uuid.uuid4())
            self.metas[key] = json.loads(params["meta"])
            return type("R", (), {"scalar_one": lambda self: eid})()
        if "INSERT INTO relations" in sql:
            self.relations.append((params["from_id"], params["to_id"], params["rel_type"]))
        return None


async def test_store_links_findings_to_their_parent(registry):
    session = RecordingSession()
    store = EntityStore(session, NoGeo())
    emits = page_emits()
    await store.store_emits(investigation_id=None, module_id="web_spider", run_id=None, target=TARGET, emits=emits)
    found = ExtractorPipeline(registry).run(emits)
    await store.store_emits(
        investigation_id=None, module_id="email_extractor", run_id=None, target=TARGET, emits=found["email_extractor"]
    )
    ids = session.entities
    edges = {(a, b, rel) for a, b, rel in session.relations}
    assert (ids[("domain", "example.com")], ids[("url", PAGE)], "links_to") in edges
    assert (ids[("url", PAGE)], ids[("raw_content", PAGE)], "content_of") in edges
    assert (ids[("raw_content", PAGE)], ids[("email", "press@example.com")], "mentioned_in") in edges
    # the page text is evidence (observation), not entity meta
    meta = session.metas[("raw_content", PAGE)]
    assert "text" not in meta and meta["chars"] == len(HTML) and meta["excerpt"].startswith("<html>")
    assert entity_meta(emits[0]) is emits[0].meta
