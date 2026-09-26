"""Company Name Extractor — organisation names from copyright lines and legal suffixes.

Catalog: company_name_extractor · internal · extract · access=local · phase 2
Produces: company
Consumes: raw_content

Two high-signal patterns name the operator of a site without any dictionary: a copyright notice
(``© 2024 Acme Corporation``) and a legal-entity suffix (``Example Holdings Ltd``, ``Beispiel GmbH``,
``Société Exemple SA``). This extractor pulls the name out of each and emits it as a ``company`` entity.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.helpers import strip_tags
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit

# Legal-entity designators (word-boundary, case-sensitive-ish via IGNORECASE but kept in the value verbatim).
LEGAL_SUFFIXES = (
    "Inc",
    "Incorporated",
    "LLC",
    "L.L.C.",
    "Ltd",
    "Limited",
    "LLP",
    "LP",
    "PLC",
    "Corp",
    "Corporation",
    "Co",
    "Company",
    "GmbH",
    "AG",
    "KG",
    "SA",
    "S.A.",
    "S.L.",
    "SARL",
    "S.A.S.",
    "SAS",
    "B.V.",
    "BV",
    "N.V.",
    "NV",
    "Pty",
    "Pvt",
    "OY",
    "AB",
    "AS",
    "ApS",
    "S.p.A.",
    "SpA",
    "S.r.l.",
    "Srl",
    "Sdn Bhd",
)
_SUFFIX_ALT = "|".join(re.escape(s).replace(r"\ ", r"\s+") for s in sorted(LEGAL_SUFFIXES, key=len, reverse=True))

# A name is 1-5 capitalised words (allowing &, ., -) immediately before a legal suffix.
_ENTITY = re.compile(
    r"\b((?:[A-Z][\w&.\-]*(?:\s+(?:of|and|the|de|du|van|von|&)\s+)?\s*){1,5}?)"
    rf"[,\s]+({_SUFFIX_ALT})\.?(?=\s|$|[.,;)])"
)

# Copyright line: © / (c) / Copyright  [YYYY[-YYYY]]  Name  up to the next sentence break. The name class
# excludes the terminators (``. , |``) so it stops at "Acme Widgets Inc." rather than running into the next
# sentence.
_COPYRIGHT = re.compile(
    r"(?:©|\(c\)|&copy;|Copyright)\s*(?:©|\(c\))?\s*"
    r"(?:\d{4}(?:\s*[-–]\s*\d{4})?(?:,\s*)?\s*)?"
    r"([A-Z][^.,|\n©]{1,60}?)"
    r"\s*(?=\.|,|\||\n|$|All rights|All Rights|\d{4})",
    re.I,
)

_WS = re.compile(r"\s+")
_TRAILING = re.compile(r"\s+(?:all rights reserved|inc|ltd|llc)\.?$", re.I)
_STOP = {"the", "a", "an", "all", "rights", "reserved", "copyright", "home", "page", "website", "site"}


def _clean(name: str) -> str:
    return _WS.sub(" ", name).strip(" .,-&|")


def find_companies(text: str) -> list[tuple[str, str, int]]:
    """``(name, via, offset)`` for each company named by a legal suffix or a copyright line."""
    plain = strip_tags(text) if "<" in text and ">" in text else text
    out: list[tuple[str, str, int]] = []
    seen: set[str] = set()

    def push(name: str, via: str, offset: int) -> None:
        name = _clean(name)
        words = [w for w in re.split(r"\s+", name) if w]
        if len(name) < 2 or not words or all(w.lower() in _STOP for w in words):
            return
        key = name.lower()
        if key in seen:
            return
        seen.add(key)
        out.append((name, via, offset))

    for m in _ENTITY.finditer(plain):
        push(f"{_clean(m.group(1))} {m.group(2)}", "legal_suffix", m.start())
    for m in _COPYRIGHT.finditer(plain):
        push(_TRAILING.sub("", m.group(1)), "copyright", m.start())

    out.sort(key=lambda t: t[2])
    return out


@module("company_name_extractor")
class CompanyNameExtractor(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        for name, via, offset in find_companies(content.text):
            yield Emit(
                EntityType.COMPANY,
                name,
                confidence=0.8 if via == "legal_suffix" else 0.6,
                relation="mentioned_in",
                parent=content.parent,
                meta={"via": via, "offset": offset, "source_url": content.source_url},
            )
