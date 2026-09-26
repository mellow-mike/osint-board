"""Error String Extractor — verbose error/debug output leaked into a page.

Catalog: error_string_extractor · internal · extract · access=local · phase 2
Consumes: raw_content
Produces: error_message

Stack traces, SQL errors and framework debug pages leak the stack a site runs on and sometimes filesystem
paths or credentials. This extractor matches known error signatures (PHP warnings, Python/Java tracebacks,
ODBC/MySQL/PostgreSQL driver errors, ASP.NET yellow-screens, `.env`/config dumps) and emits one
``error_message`` per distinct signature, tagged with the technology it points at.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.helpers import strip_tags
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit

#: (technology, category, compiled signature). Database-specific signatures come before the generic Java/CLR
#: traceback patterns so an ``org.postgresql...`` exception is labelled PostgreSQL, not Java. ``leak`` matches
#: (filesystem paths, config keys) are always kept even inside a larger error (see :func:`find_errors`).
SIGNATURES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("PHP", "runtime", re.compile(
        r"(?:Fatal error|Warning|Parse error|Notice|Deprecated)\s*:.*?(?:in|on line)\s+.*?(?:\.php|line \d+)", re.I)),
    ("PHP", "runtime", re.compile(r"Stack trace:\s*#0\s")),
    ("Python", "traceback", re.compile(r"Traceback \(most recent call last\):")),
    ("MySQL", "sql", re.compile(r"(?:You have an error in your SQL syntax|Warning: mysql_|"
                                r"supplied argument is not a valid MySQL|com\.mysql\.jdbc)", re.I)),
    ("PostgreSQL", "sql", re.compile(r"(?:PostgreSQL query failed|pg_query\(\)|"
                                     r"org\.postgresql\.util\.\w+|ERROR:\s+syntax error at or near)", re.I)),
    ("Microsoft SQL Server", "sql", re.compile(
        r"(?:Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after|"
        r"\[SQL Server\]|System\.Data\.SqlClient)", re.I)),
    ("Oracle", "sql", re.compile(r"\bORA-\d{5}\b")),
    ("SQLite", "sql", re.compile(r"SQLite3?::|sqlite3\.OperationalError", re.I)),
    ("ODBC", "sql", re.compile(r"\[Microsoft\]\[ODBC|ODBC Driver", re.I)),
    ("ASP.NET", "runtime", re.compile(r"Server Error in '.*?' Application|System\.[\w.]+Exception", re.I)),
    ("Ruby", "traceback", re.compile(r"\(NoMethodError\)|\.rb:\d+:in `")),
    ("Node.js", "traceback", re.compile(r"at\s+[\w.]+\s+\(?/[\w./-]+\.js:\d+:\d+\)?")),
    ("Java", "traceback", re.compile(r"\b(?:java|javax|org|com)\.(?!postgresql|mysql)[\w.]+(?:Exception|Error)\b"
                                      r"(?::.*)?(?:\s+at\s+[\w.$]+\([\w.]+:\d+\))?")),
    ("Java", "traceback", re.compile(r"\bat\s+[\w.$]+\([\w.]+\.java:\d+\)")),
    ("filesystem path", "leak", re.compile(r"(?:/(?:var|home|usr|opt|srv)/[\w./-]+|[A-Za-z]:\\[\w\\.-]+)")),
    ("config dump", "leak", re.compile(r"(?m)^\s*(?:DB_PASSWORD|SECRET_KEY|API_KEY|AWS_SECRET)\s*[:=]", re.I)),
)

_LEAK_CATEGORIES = frozenset({"leak"})

# Trim a matched region to a single readable line/sentence for the entity value.
_WS = re.compile(r"\s+")
MAX_LEN = 300


def find_errors(text: str) -> list[tuple[str, str, str, int]]:
    """``(message, technology, category, offset)`` for each distinct error signature found.

    Overlapping signatures for one error (a PHP warning that mentions MySQL) collapse to the widest match, so a
    single leaked error is one finding, not three."""
    plain = strip_tags(text) if "<" in text and ">" in text else text
    raw: list[tuple[int, int, str, str, str]] = []
    for tech, category, rx in SIGNATURES:
        for m in rx.finditer(plain):
            snippet = _WS.sub(" ", m.group(0)).strip()[:MAX_LEN]
            if snippet:
                raw.append((m.start(), m.end(), snippet, tech, category))
    # Widest first at each start so a contained match is dropped in favour of the span that encloses it.
    raw.sort(key=lambda t: (t[0], -(t[1] - t[0])))
    out: list[tuple[str, str, str, int]] = []
    claimed: list[tuple[int, int]] = []
    seen: set[str] = set()
    for start, end, snippet, tech, category in raw:
        # Info-leak matches (paths, secret keys) are independently valuable, so a containing error never hides
        # them; every other signature yields to a wider match that already encloses it.
        if category not in _LEAK_CATEGORIES and any(cs <= start and end <= ce for cs, ce in claimed):
            continue
        key = snippet.lower()
        if key in seen:
            continue
        seen.add(key)
        if category not in _LEAK_CATEGORIES:
            claimed.append((start, end))
        out.append((snippet, tech, category, start))
    out.sort(key=lambda t: t[3])
    return out


@module("error_string_extractor")
class ErrorStringExtractor(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        for message, tech, category, offset in find_errors(content.text):
            yield Emit(
                EntityType.ERROR_MESSAGE,
                message,
                confidence=0.7 if category == "leak" else 0.85,
                relation="mentioned_in",
                parent=content.parent,
                meta={
                    "technology": tech,
                    "category": category,
                    "offset": offset,
                    "source_url": content.source_url,
                },
            )
