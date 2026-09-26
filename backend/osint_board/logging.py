"""structlog configuration shared by every process.

Every event carries the name of the logger that emitted it (``logger``), has known secrets masked in its string
values (:func:`osint_board.redaction.redact`, which also covers formatted exceptions) and can be copied to a *tap*
before it is rendered — the soak harness journals warnings and ``*.stats`` metrics that way.
"""

from __future__ import annotations

import contextlib
import logging
import sys
from collections.abc import Callable
from typing import Any

import structlog

from osint_board.config import get_settings
from osint_board.redaction import redact

#: ``tap(level, event, event_dict)`` — receives a shallow copy of every rendered event (after redaction)
LogTap = Callable[[str, str, dict[str, Any]], None]

# Loggers that log full request URLs (API keys included for FIRMS and OpenCellID) at INFO.
_NOISY_LOGGERS = ("httpx", "httpcore")

_tap: LogTap | None = None


class _NamedPrintLogger(structlog.PrintLogger):
    """A ``PrintLogger`` that remembers the name it was requested with, for :func:`_add_logger_name`."""

    def __init__(self, name: str | None) -> None:
        super().__init__()  # structlog's stdout, like PrintLoggerFactory
        self.name = name


def _logger_factory(*args: Any) -> _NamedPrintLogger:
    return _NamedPrintLogger(str(args[0]) if args else None)


def _add_logger_name(logger: Any, _method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    name = getattr(logger, "name", None)
    if name and "logger" not in event_dict:
        event_dict["logger"] = name
    return event_dict


def _redact_strings(_logger: Any, _method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    for key, value in event_dict.items():
        if isinstance(value, str):
            event_dict[key] = redact(value)
    return event_dict


def _call_tap(_logger: Any, method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    tap = _tap  # read per event so loggers cached before configure_logging(tap=...) still reach the tap
    if tap is not None:
        with contextlib.suppress(Exception):  # a broken tap must never break logging
            tap(str(event_dict.get("level", method)), str(event_dict.get("event", "")), dict(event_dict))
    return event_dict


def configure_logging(*, tap: LogTap | None = None) -> None:
    """Configure structlog (and the stdlib root logger) for this process; ``tap`` replaces any earlier tap."""
    global _tap
    _tap = tap
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(max(level, logging.WARNING))
    renderer = structlog.processors.JSONRenderer() if settings.log_json else structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            _add_logger_name,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            _redact_strings,
            _call_tap,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=_logger_factory,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
