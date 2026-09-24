from __future__ import annotations

from datetime import UTC, datetime

from osint_board.entities.types import EntityType
from osint_board.search.parser import parse_near, parse_query, parse_time

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def test_plain_identifier_is_a_pivot():
    plan = parse_query("203.0.113.7")
    assert plan.primary and plan.primary.type is EntityType.IP
    assert "pivot" in plan.intents
    assert plan.text == ""


def test_coordinates_are_a_locate_intent():
    plan = parse_query("48.8566, 2.3522")
    assert plan.primary.type is EntityType.GEO_POINT
    assert plan.intents == ["locate", "pivot"]
    assert plan.primary.meta["lat"] == 48.8566


def test_typed_prefixes_and_filters():
    plan = parse_query(
        'mmsi:366999999 layer:maritime,aviation since:24h near:48.85,2.35,50km "north sea" -tanker', now=NOW
    )
    assert plan.primary.type is EntityType.VESSEL and plan.primary.confidence == 1.0
    assert plan.layers == ["maritime", "aviation"]
    assert plan.since == datetime(2026, 9, 23, 12, 0, tzinfo=UTC)
    assert plan.near and plan.near.radius_m == 50_000
    assert plan.phrases == ["north sea"]
    assert plan.negated_terms == ["tanker"]
    assert "locate" in plan.intents and "layer" in plan.intents and "nearby" in plan.intents


def test_free_text_with_embedded_identifier():
    plan = parse_query("acme corp example.com breach")
    assert plan.terms == ["acme", "corp", "breach"]
    assert plan.primary.type is EntityType.DOMAIN
    assert "fulltext" in plan.intents and "pivot" in plan.intents


def test_low_confidence_guess_is_kept_as_suggestion_not_pivot():
    plan = parse_query("25544")
    assert plan.terms == ["25544"]
    assert plan.primary and plan.primary.type is EntityType.SATELLITE and plan.primary.confidence < 0.6
    assert "pivot" not in plan.intents


def test_type_filter_accepts_aliases_and_ids():
    plan = parse_query("type:ip,vessel,hostname bob")
    assert plan.types == [EntityType.IP, EntityType.VESSEL, EntityType.HOSTNAME]


def test_time_parsing():
    assert parse_time("7d", NOW) == datetime(2026, 9, 17, 12, 0, tzinfo=UTC)
    assert parse_time("2026-09-01", NOW) == datetime(2026, 9, 1, tzinfo=UTC)
    assert parse_time("garbage", NOW) is None


def test_near_parsing_units():
    assert parse_near("10,20").radius_m == 10_000
    assert parse_near("10,20,5mi").radius_m == 5 * 1609.344
    assert parse_near("10 20 3nm").radius_m == 3 * 1852
    assert parse_near("x") is None


def test_to_dict_is_json_ready():
    d = parse_query("ip:1.1.1.1 since:1h").to_dict()
    assert d["detections"][0]["type"] == "ip"
    assert d["intents"] == ["pivot", "time"]
