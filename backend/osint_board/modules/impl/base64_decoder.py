"""Base64 Decoder — decode base64 blobs found in content or a URL and re-feed the plaintext.

Catalog: base64_decoder · internal · extract · access=local · phase 2
Consumes: raw_content, url
Produces: base64_string

Base64 hides indicators from a naive scan: an exfiltration URL, an e-mail, a config blob. This extractor finds
substantial base64 substrings (including URL-safe and data: URIs), decodes the ones that come out as printable
text, and emits a ``base64_string`` whose ``meta["text"]`` is the decoded plaintext — so the extractor pipeline
runs every other extractor over the decoded content on its next round.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit

# A run of base64 characters (standard or URL-safe alphabet) long enough to be worth decoding. The boundary
# excludes payload characters but not "=", so a blob after an assignment (``key=QWJj...``) still matches.
_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{20,}={0,2})(?![A-Za-z0-9+/_-])")
_DATA_URI = re.compile(r"data:[\w.+-]+/[\w.+-]+;base64,([A-Za-z0-9+/=]+)", re.I)

MIN_DECODED = 8  # ignore anything that decodes to fewer than this many bytes
MAX_BLOBS = 200


def _decode(blob: str) -> bytes | None:
    """Decode a base64 candidate (standard or URL-safe), tolerating missing padding; ``None`` if it is not b64."""
    s = blob.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _printable(data: bytes) -> str | None:
    """UTF-8/ASCII text of ``data`` when it is overwhelmingly printable, else ``None`` (binary blob)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return text if printable / len(text) >= 0.9 else None


def find_base64(text: str) -> list[tuple[str, str, int]]:
    """``(encoded, decoded_text, offset)`` for each base64 blob that decodes to printable text."""
    out: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    candidates = [(m.group(1), m.start(1)) for m in _DATA_URI.finditer(text)]
    candidates += [(m.group(1), m.start(1)) for m in _B64.finditer(text)]
    for blob, offset in candidates:
        if len(blob) > 100_000 or blob in seen:
            continue
        seen.add(blob)
        data = _decode(blob)
        if data is None or len(data) < MIN_DECODED:
            continue
        decoded = _printable(data)
        # A decoded value that just re-encodes the source (e.g. plain ascii mistaken for b64) adds nothing.
        if decoded is None or decoded == blob:
            continue
        out.append((blob, decoded, offset))
        if len(out) >= MAX_BLOBS:
            break
    out.sort(key=lambda t: t[2])
    return out


@module("base64_decoder")
class Base64Decoder(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        for encoded, decoded, offset in find_base64(content.text):
            yield Emit(
                EntityType.BASE64_STRING,
                encoded[:200],
                confidence=0.8,
                relation="decodes_to",
                parent=content.parent,
                meta={
                    "decoded": decoded[:2000],
                    "text": decoded,  # let the pipeline scan the plaintext on its next round
                    "encoded_length": len(encoded),
                    "offset": offset,
                    "source_url": content.source_url,
                },
            )
