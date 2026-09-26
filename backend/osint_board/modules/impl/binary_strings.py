"""Binary Strings — the ``strings(1)`` of a binary file, re-fed as content.

Catalog: binary_strings · internal · extract · access=local · phase 2
Consumes: raw_file
Produces: raw_content

A downloaded binary (an executable, a firmware image, an office document's embedded stream) hides URLs,
e-mails, paths and keys as printable runs. This extractor pulls the printable ASCII and UTF-16LE runs out of
the bytes and emits them as a single ``raw_content`` document, so the extractor pipeline runs every other
extractor (URLs, e-mails, crypto addresses, errors ...) over the recovered text on its next round.

The framework hands content as text, so a caller passes the file's bytes as a byte-preserving latin-1 string in
``Content.text`` (``raw.decode("latin-1")``); the string extraction is over those code points.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit

MIN_RUN = 4  # shortest printable run to keep (matches `strings -n 4`)
MAX_OUTPUT = 1_000_000  # cap the recovered text handed back to the pipeline

# Printable ASCII including tab; runs shorter than MIN_RUN are dropped.
_ASCII_RUN = re.compile(rf"[\x20-\x7e\t]{{{MIN_RUN},}}")
# UTF-16LE: a printable byte followed by NUL, repeated — recovered by matching "(ch\x00){n}".
_UTF16_RUN = re.compile(rf"(?:[\x20-\x7e]\x00){{{MIN_RUN},}}")


def extract_strings(data: str) -> list[str]:
    """Printable ASCII and UTF-16LE runs of at least ``MIN_RUN`` chars, in file order, deduped preserving order.

    ``data`` is the file's bytes as a latin-1 string (one char per byte)."""
    runs: list[tuple[int, str]] = []
    for m in _ASCII_RUN.finditer(data):
        runs.append((m.start(), m.group(0)))
    for m in _UTF16_RUN.finditer(data):
        runs.append((m.start(), m.group(0).replace("\x00", "")))
    runs.sort(key=lambda t: t[0])
    out: list[str] = []
    seen: set[str] = set()
    for _, run in runs:
        run = run.strip()
        if len(run) < MIN_RUN or run in seen:
            continue
        seen.add(run)
        out.append(run)
    return out


@module("binary_strings")
class BinaryStrings(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        strings = extract_strings(content.text)
        if not strings:
            return
        recovered = "\n".join(strings)[:MAX_OUTPUT]
        identity = content.source_url or (content.parent.value if content.parent else "binary")
        yield Emit(
            EntityType.RAW_CONTENT,
            identity,
            confidence=1.0,
            relation="strings_of",
            parent=content.parent,
            meta={
                "text": recovered,
                "content_type": "text/plain",
                "url": content.source_url,
                "count": len(strings),
                "source": "binary_strings",
            },
        )
