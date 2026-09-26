"""Settings: module secrets and per-module config from the environment or `.env`, the module context built on
them, and the logging tap. Every dotenv file here lives in tmp_path; the repo's own `.env` is never touched."""

from __future__ import annotations

import logging
import pickle
from pathlib import Path

import pytest
import structlog
from structlog.testing import capture_logs

from osint_board import config as config_mod
from osint_board.config import ENV_FILES, REPO_ROOT, Settings
from osint_board.modules.base import FeedModule, MissingSecret
from osint_board.modules.registry import Registry
from osint_board.redaction import MASK, redact


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("ZZTEST_API_KEY", "ZZTEST_TOKEN", "ZZTEST_CONFIG", "USGS_CONFIG", "USGS_API_KEY"):
        monkeypatch.delenv(f"OSINT_MODULE_{name}", raising=False)
    monkeypatch.setattr(config_mod, "_warned_config", set())


def _dotenv(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_module_secret_reads_the_dotenv_file_and_the_environment_wins(tmp_path, monkeypatch):
    env = _dotenv(tmp_path / ".env", "OSINT_LOG_LEVEL=DEBUG\nOSINT_MODULE_ZZTEST_API_KEY=from-dotenv-123\n")
    settings = Settings(_env_file=env)
    assert settings.log_level == "DEBUG"  # the file pydantic-settings reads ...
    assert settings.module_secret("zztest") == "from-dotenv-123"  # ... is also where module secrets come from
    assert settings.module_secret("zztest", "token") is None

    monkeypatch.setenv("OSINT_MODULE_ZZTEST_API_KEY", "from-environ-456")
    assert settings.module_secret("zztest") == "from-environ-456"
    monkeypatch.setenv("OSINT_MODULE_ZZTEST_API_KEY", "")  # an empty variable counts as unset
    assert settings.module_secret("zztest") == "from-dotenv-123"
    assert Settings(_env_file=None).module_secret("zztest") is None


def test_later_dotenv_files_win(tmp_path):
    repo = _dotenv(
        tmp_path / "repo.env", "OSINT_MODULE_ZZTEST_API_KEY=repo-root-key\nOSINT_MODULE_ZZTEST_TOKEN=tok-repo\n"
    )
    cwd = _dotenv(tmp_path / "cwd.env", "osint_module_zztest_api_key=cwd-key-789\n")
    settings = Settings(_env_file=(repo, cwd, tmp_path / "missing.env"))
    assert settings.module_secret("zztest") == "cwd-key-789"
    assert settings.module_secret("ZZTEST", "TOKEN") == "tok-repo"


def test_default_env_files_are_the_repo_root_and_the_cwd(tmp_path, monkeypatch):
    assert REPO_ROOT is not None and (REPO_ROOT / "catalog" / "modules.yaml").is_file()
    assert (str(REPO_ROOT / ".env"), ".env") == ENV_FILES
    assert Settings.model_config["env_file"] == ENV_FILES

    monkeypatch.chdir(tmp_path)  # e.g. `cd backend && osint-board feeds`
    _dotenv(tmp_path / ".env", "OSINT_MODULE_ZZTEST_TOKEN=cwd-relative-token\n")
    assert Settings().module_secret("zztest", "TOKEN") == "cwd-relative-token"


def test_module_config_parses_json_objects(tmp_path, monkeypatch):
    env = _dotenv(
        tmp_path / ".env",
        'OSINT_MODULE_ZZTEST_CONFIG=\'{"poll_timeout": 900, "receivers": [{"name": "roof", "url": "http://r/a.json"}]}\'\n',
    )
    settings = Settings(_env_file=env)
    assert settings.module_config("zztest") == {
        "poll_timeout": 900,
        "receivers": [{"name": "roof", "url": "http://r/a.json"}],
    }
    assert settings.module_config("usgs") == {}
    monkeypatch.setenv("OSINT_MODULE_ZZTEST_CONFIG", '{"poll_timeout": 30}')
    assert settings.module_config("zztest") == {"poll_timeout": 30}


@pytest.mark.parametrize(
    ("raw", "problem"), [("{not json", "invalid JSON"), ("[1, 2]", "expected a JSON object"), ('"x"', "got str")]
)
def test_module_config_invalid_values_warn_once_and_yield_empty(monkeypatch, raw, problem):
    monkeypatch.setenv("OSINT_MODULE_ZZTEST_CONFIG", raw)
    settings = Settings(_env_file=None)
    with capture_logs() as logs:
        assert settings.module_config("zztest") == {}
        assert settings.module_config("zztest") == {}
    warnings = [e for e in logs if e["event"] == "config.module_config_invalid"]
    assert len(warnings) == 1 and warnings[0]["log_level"] == "warning"
    assert warnings[0]["variable"] == "OSINT_MODULE_ZZTEST_CONFIG" and problem in warnings[0]["problem"]


def test_registry_merges_deployment_config_under_run_config(catalog, tmp_path):
    class Feed(FeedModule):
        pass

    env = _dotenv(tmp_path / ".env", 'OSINT_MODULE_USGS_CONFIG={"window": "all_day", "min_mag": 2}\n')
    registry = Registry(catalog, {"usgs": Feed}, settings=Settings(_env_file=env))
    assert registry.module_config("usgs") == {"window": "all_day", "min_mag": 2}
    assert registry.instantiate("usgs").ctx.config == {"window": "all_day", "min_mag": 2}
    mod = registry.instantiate("usgs", config={"min_mag": 4, "extra": True})
    assert mod.ctx.config == {"window": "all_day", "min_mag": 4, "extra": True}
    assert mod.ctx.settings is registry.settings


def test_context_secrets_come_from_dotenv_and_are_redacted(catalog, tmp_path):
    class Feed(FeedModule):
        pass

    env = _dotenv(tmp_path / ".env", "OSINT_MODULE_USGS_API_KEY=dotenv-only-secret-42\n")
    ctx = Registry(catalog, {"usgs": Feed}, settings=Settings(_env_file=env)).instantiate("usgs").ctx
    assert ctx.require_secret() == "dotenv-only-secret-42"
    # not in os.environ, but masked anyway because the context registered it when handing it out
    assert redact("GET https://api.test/v1/dotenv-only-secret-42/data") == f"GET https://api.test/v1/{MASK}/data"

    with pytest.raises(MissingSecret) as info:
        ctx.require_secret("TOKEN")
    assert isinstance(info.value, RuntimeError)
    assert info.value.env_var == "OSINT_MODULE_USGS_TOKEN" and "OSINT_MODULE_USGS_TOKEN" in str(info.value)
    clone = pickle.loads(pickle.dumps(info.value))
    assert isinstance(clone, MissingSecret) and clone.env_var == info.value.env_var and str(clone) == str(info.value)


def test_configure_logging_tap_redaction_and_quiet_http_loggers(monkeypatch):
    from osint_board import logging as log_mod

    saved = structlog.get_config()
    saved_levels = {name: logging.getLogger(name).level for name in ("httpx", "httpcore")}
    monkeypatch.setenv("OSINT_MODULE_ZZTEST_API_KEY", "tap-secret-value-1")
    seen: list[tuple[str, str, dict]] = []
    try:
        log_mod.configure_logging(tap=lambda level, event, fields: seen.append((level, event, fields)))
        assert logging.getLogger("httpx").level >= logging.WARNING
        assert logging.getLogger("httpcore").level >= logging.WARNING

        log_mod.get_logger("tests.tap").warning("thing.failed", url="https://x.test/a/tap-secret-value-1?token=abc")
        assert len(seen) == 1
        level, event, fields = seen[0]
        assert (level, event) == ("warning", "thing.failed")
        assert fields["logger"] == "tests.tap" and fields["url"] == f"https://x.test/a/{MASK}?token={MASK}"

        def broken_tap(level: str, event: str, fields: dict) -> None:
            raise RuntimeError("tap bug")

        log_mod.configure_logging(tap=broken_tap)
        log_mod.get_logger("tests.tap2").error("still.logged")  # must not raise
        log_mod.configure_logging()
        log_mod.get_logger("tests.tap3").warning("untapped")
        assert len(seen) == 1
    finally:
        log_mod._tap = None
        structlog.configure(**saved)
        for name, lvl in saved_levels.items():
            logging.getLogger(name).setLevel(lvl)
