"""People, social, e-mail and breach modules."""

from __future__ import annotations

import hashlib

import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.impl.flickr import accuracy_precision
from osint_board.modules.impl.venmo import parse_profile
from osint_board.modules.types import EntityRef


def _by_type(emits):
    out: dict[EntityType, list[str]] = {}
    for e in emits:
        out.setdefault(e.type, []).append(e.value)
    return out


async def test_gravatar_v3_and_legacy(fake_http, run_lookup):
    sha = hashlib.sha256(b"jane@example.com").hexdigest()
    fake_http.route(f"api.gravatar.com/v3/profiles/{sha}", file="people/gravatar_v3.json")
    emits = await run_lookup("gravatar", "email", "Jane@Example.com ", config={"api_key": "g"})
    by = _by_type(emits)
    assert by[EntityType.SOCIAL_PROFILE] == [
        "https://gravatar.com/jdoe",
        "https://github.com/jdoe",
        "https://mastodon.example/@jdoe",
    ]
    assert (
        by[EntityType.PERSON] == ["Jane Doe"]
        and by[EntityType.USERNAME] == ["jdoe"]
        and by[EntityType.URL] == ["https://blog.example.com"]
    )
    assert emits[0].meta["location"] == "Anytown, CA" and EntityType.BTC_ADDRESS not in by
    assert fake_http.calls[-1][2]["headers"]["Authorization"] == "Bearer g"
    fake_http.routes.clear()
    fake_http.route("api.gravatar.com", "", status=404).route("www.gravatar.com", file="people/gravatar_legacy.json")
    by = _by_type(await run_lookup("gravatar", "email", "jane@example.com"))
    assert by[EntityType.SOCIAL_PROFILE] == ["https://gravatar.com/jdoe", "https://twitter.com/jdoe"] and by[
        EntityType.USERNAME
    ] == ["jdoe"]
    fake_http.routes.clear()
    fake_http.route("gravatar.com", "", status=404)
    assert await run_lookup("gravatar", "email", "nobody@example.com") == []


async def test_keybase(fake_http, run_lookup):
    fake_http.route("keybase.io/_/api/1.0/user/lookup.json", file="people/keybase_lookup.json")
    emits = await run_lookup("keybase", "username", "jdoe")
    by = _by_type(emits)
    assert by[EntityType.SOCIAL_PROFILE] == [
        "https://keybase.io/jdoe",
        "https://twitter.com/jdoe",
        "https://github.com/jdoe",
    ]
    assert by[EntityType.PGP_KEY] == ["0123456789ABCDEF0123456789ABCDEF01234567"] and by[EntityType.PERSON] == [
        "Jane Doe"
    ]
    assert by[EntityType.BTC_ADDRESS] == ["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"] and EntityType.USERNAME not in by
    assert fake_http.calls[-1][2]["params"] == {"usernames": "jdoe"}
    await run_lookup("keybase", "domain", "example.com")
    assert fake_http.calls[-1][2]["params"] == {"domain": "example.com"}


async def test_flickr(fake_http, run_lookup, monkeypatch):
    assert [accuracy_precision(a) for a in (16, 12, 9, 5, 1, None)] == [
        "exact",
        "street",
        "city",
        "region",
        "country",
        "city",
    ]
    monkeypatch.setenv("OSINT_MODULE_FLICKR_API_KEY", "fk")
    fake_http.route("flickr.people.findByEmail", file="people/flickr_find.json").route(
        "flickr.people.getInfo", file="people/flickr_info.json"
    )
    fake_http.route("flickr.photos.search", file="people/flickr_photos.json")
    emits = await run_lookup("flickr", "email", "jane@example.com")
    by = _by_type(emits)
    assert by[EntityType.SOCIAL_PROFILE] == ["https://www.flickr.com/people/jdoe/"] and EntityType.USERNAME not in by
    assert by[EntityType.URL] == [f"https://www.flickr.com/photos/12345678@N00/{i}" for i in (1001, 1002, 1003)]
    points = [e for e in emits if e.type is EntityType.GEO_POINT]
    assert (
        [p.geo.precision for p in points] == ["exact", "city"]
        and points[0].layer == "media"
        and points[0].observed_at.year == 2026
    )
    assert points[0].geo.lat == 52.520008 and points[0].meta["photo"].endswith("/1001")
    fake_http.routes.clear()
    fake_http.route("flickr.people.findByUsername", file="people/flickr_fail.json")
    assert await run_lookup("flickr", "username", "nobody") == []


async def test_myspace_and_slideshare(fake_http, run_lookup):
    fake_http.route("myspace.com/jdoe", file="people/myspace_profile.html").route("myspace.com/nobody", "", status=404)
    by = _by_type(await run_lookup("myspace", "username", "jdoe"))
    assert by[EntityType.PERSON] == ["Jane Doe"] and by[EntityType.PHYSICAL_ADDRESS] == ["Anytown, California"]
    assert by[EntityType.SOCIAL_PROFILE] == ["https://myspace.com/jdoe"]
    assert await run_lookup("myspace", "username", "nobody") == []
    fake_http.route("slideshare.net/janedoe", file="people/slideshare_profile.html")
    by = _by_type(await run_lookup("slideshare", "person", "Jane Doe"))
    assert by[EntityType.PERSON] == ["Jane Doe"] and by[EntityType.PHYSICAL_ADDRESS] == ["Anytown, United States"]


async def test_callername(fake_http, run_lookup):
    fake_http.route("callername.com/4155552671", file="people/callername.html")
    emits = await run_lookup("callername", "phone", "+14155552671")
    by = _by_type(emits)
    assert by[EntityType.PHONE_INFO] == ["+14155552671: Mobile, Example Wireless LLC, Anytown, CA"] and by[
        EntityType.COUNTRY
    ] == ["US"]
    assert emits[0].meta["reputation"] == "telemarketer"
    assert await run_lookup("callername", "phone", "+442071838750") == [] and len(fake_http.calls) == 1


async def test_emailformat_and_skymem(fake_http, run_lookup):
    fake_http.route("email-format.com/d/example.com", file="people/emailformat.html").route(
        "skymem.info", file="people/skymem.html"
    )
    by = _by_type(await run_lookup("emailformat", "domain", "example.com"))
    assert by[EntityType.EMAIL] == ["jane.doe@example.com", "jdoe@example.com"]
    assert by[EntityType.EMAIL_PATTERN] == ["{first}.{last}@example.com", "{f}{last}@example.com"]
    by = _by_type(await run_lookup("skymem", "domain", "example.com"))
    assert by[EntityType.EMAIL] == ["jane.doe@example.com", "sales@example.com"]
    by = _by_type(await run_lookup("skymem", "email", "sales@example.com"))
    assert by[EntityType.EMAIL] == ["jane.doe@example.com"]


async def test_reversewhois_psbdmp_leaklookup(fake_http, run_lookup, monkeypatch):
    fake_http.route("reversewhois.io", file="people/reversewhois.html").route(
        "psbdmp.cc/api/v3/search/example.com", file="people/psbdmp_search.json"
    )
    emits = await run_lookup("reversewhois_io", "company", "Example Networks")
    assert [(e.value, e.meta["registered"], e.meta["registrar"]) for e in emits] == [
        ("example-shop.com", "2021-03-04", "example registrar inc"),
        ("example-labs.net", "2019-11-30", "other registrar"),
    ]
    by = _by_type(await run_lookup("psbdmp", "domain", "example.com"))
    assert by[EntityType.PASTE] == ["pastebin:AbCdEf12", "pastebin:ZyXwVu98"] and by[EntityType.URL] == [
        "https://pastebin.com/AbCdEf12",
        "https://pastebin.com/ZyXwVu98",
    ]
    with pytest.raises(RuntimeError):
        await run_lookup("leak_lookup", "email", "jane@example.com")
    monkeypatch.setenv("OSINT_MODULE_LEAK_LOOKUP_API_KEY", "ll")
    fake_http.route("leak-lookup.com/api/search", file="people/leaklookup.json")
    emits = await run_lookup("leak_lookup", "email", "jane@example.com")
    assert [e.value for e in emits] == ["jane@example.com in linkedin.com", "jane@example.com in adobe.com"]
    assert emits[1].meta["fields"] == ["email_address", "password_hint", "username"]
    assert fake_http.calls[-1][2]["data"] == {"key": "ll", "type": "email_address", "query": "jane@example.com"}
    fake_http.routes.clear()
    fake_http.route("leak-lookup.com/api/search", file="people/leaklookup_error.json")
    with pytest.raises(RuntimeError, match="Invalid API key"):
        await run_lookup("leak_lookup", "username", "@jdoe")


async def test_debounce(fake_http, run_lookup):
    fake_http.route("disposable.debounce.io", file="people/debounce_disposable.json")
    emits = await run_lookup("debounce", "email", "throwaway@mailinator.com")
    assert [(e.type, e.value) for e in emits] == [
        (EntityType.EMAIL_VERDICT, "debounce: throwaway@mailinator.com disposable")
    ]
    assert emits[0].meta["disposable"] is True and emits[0].meta["domain"] == "mailinator.com"
    assert fake_http.calls[0][2]["params"] == {"email": "throwaway@mailinator.com"}

    fake_http.route("api.debounce.io/v1/", file="people/debounce_validate.json")
    emits = await run_lookup("debounce", "email", "info@example.com", config={"api_key": "db"})
    assert emits[0].value == "debounce: info@example.com role"
    assert (
        emits[0].meta["role"] is True and emits[0].meta["free_email"] is False and "did_you_mean" not in emits[0].meta
    )
    assert fake_http.calls[-1][2]["params"] == {"api": "db", "email": "info@example.com"}

    fake_http.routes.clear()
    fake_http.route("api.debounce.io/v1/", file="people/debounce_error.json")
    with pytest.raises(RuntimeError, match="Wrong API"):
        await run_lookup("debounce", "email", "info@example.com", config={"api_key": "bad"})


async def test_venmo(fake_http, run_lookup, fixtures_dir):
    fake_http.route("account.venmo.com/u/jane-doe", file="people/venmo_profile.html")
    emits = await run_lookup("venmo", "username", "@jane-doe")
    profile = emits[0]
    assert profile.type is EntityType.SOCIAL_PROFILE and profile.value == "https://account.venmo.com/u/jane-doe"
    assert profile.meta["name"] == "Jane Doe" and profile.meta["user_id"] == "2051234567890123456"
    assert profile.meta["joined"] == "2016-05-02T18:25:43"
    assert [(e.type, e.value) for e in emits[1:]] == [(EntityType.PERSON, "Jane Doe")]  # not the friend's name

    fake_http.route("account.venmo.com/u/john-roe", file="people/venmo_og_only.html")
    emits = await run_lookup("venmo", "username", "john-roe")
    assert emits[0].meta["name"] == "John Roe" and emits[0].meta["about"] == "Pay John Roe on Venmo"

    # a user called "login" is a profile, not the sign-in wall
    page = (fixtures_dir / "people/venmo_og_only.html").read_text()
    login = parse_profile(page, "https://account.venmo.com/u/login", EntityRef(EntityType.USERNAME, "login"))
    assert login[0].value == "https://account.venmo.com/u/login"
    with pytest.raises(RuntimeError, match="sign-in"):
        parse_profile(page, "https://account.venmo.com/sign-in?next=/u/jane", EntityRef(EntityType.USERNAME, "jane"))

    fake_http.route("account.venmo.com/u/nobody", "", status=404)
    assert await run_lookup("venmo", "username", "nobody") == []
    fake_http.route("account.venmo.com/u/changed", file="people/venmo_generic.html")
    with pytest.raises(RuntimeError, match="not recognised"):
        await run_lookup("venmo", "username", "changed")
