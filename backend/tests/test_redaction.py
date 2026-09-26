from osint_board.redaction import MASK, redact, register_secret


def test_redacts_env_secrets_and_query_params(monkeypatch):
    monkeypatch.setenv("OSINT_MODULE_NASA_FIRMS_API_KEY", "abcdef0123456789")
    monkeypatch.setenv("OSINT_MODULE_OPENSKY_CONFIG", '{"receivers": []}')
    url = "https://firms.modaps.eosdis.nasa.gov/api/area/csv/abcdef0123456789/VIIRS_SNPP_NRT/world/1"
    assert redact(url) == f"https://firms.modaps.eosdis.nasa.gov/api/area/csv/{MASK}/VIIRS_SNPP_NRT/world/1"
    assert redact("GET https://x.test/dl?token=zz99&type=diff") == f"GET https://x.test/dl?token={MASK}&type=diff"
    assert redact("https://x.test/?a=1&api_key=q") == f"https://x.test/?a=1&api_key={MASK}"
    assert "receivers" in redact('{"receivers": []}')  # _CONFIG values are not secrets


def test_registered_secrets_and_short_values():
    register_secret("runtime-token-42")
    register_secret("abc")  # too short to mask safely
    assert redact(RuntimeError("401 for runtime-token-42")) == f"401 for {MASK}"
    assert redact("abc") == "abc"
