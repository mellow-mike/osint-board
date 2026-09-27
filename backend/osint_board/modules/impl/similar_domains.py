"""Similar Domain Finder — squatted / look-alike domains around a target.

Catalog: similar_domains · internal · lookup · access=local · phase 2
Consumes: domain
Produces: similar_domain, domain

A dnstwist-compatible permutation engine expands the target's registrable name into the look-alikes an attacker
would register — additions, omissions, repetitions, transpositions, keyboard-adjacent replacements and
insertions, bitsquats, homoglyphs, hyphenation, vowel swaps, a doubled/plural name and the same name under other
TLDs. The permutation engine (:func:`permutations`) is pure. The lookup then resolves each candidate through the
system resolver and reports the ones that exist (an ``A``/``AAAA`` record, or an ``NS`` delegation for a parked
name): reading public DNS for third-party names is passive, so the module is not authorisation-gated. Set
``emit_all: true`` to also surface unregistered candidates (e.g. for defensive pre-registration).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable, Iterator
from dataclasses import dataclass

import tldextract

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.dnsutil import make_resolver, query
from osint_board.modules.helpers import host_of
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

_tld = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

#: QWERTY neighbours used by the insertion/replacement fuzzers (dnstwist's keyboard maps, merged).
_KEYBOARD: dict[str, str] = {
    "1": "2q", "2": "1qw3", "3": "2we4", "4": "3er5", "5": "4rt6", "6": "5ty7", "7": "6yu8", "8": "7ui9",
    "9": "8io0", "0": "9op",
    "q": "12wa", "w": "3qeasd2", "e": "4wrsdf3", "r": "5etdfg4", "t": "6ryfgh5", "y": "7tughj6", "u": "8yihjk7",
    "i": "9uojkl8", "o": "0ipkl9", "p": "olo0",
    "a": "qwsz", "s": "edxzaw", "d": "rfcxse", "f": "tgvcdr", "g": "yhbvft", "h": "ujnbgy", "j": "ikmnhu",
    "k": "olmji", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}  # fmt: skip

#: Confusable characters — the ASCII look-alikes a Latin reader skims past (dnstwist's glyph table, trimmed to
#: substitutions that stay inside the LDH set so the candidate is still a resolvable hostname label).
_HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "0": ("o",), "1": ("l", "i"), "2": ("z",), "5": ("s",), "6": ("b",), "8": ("b",), "9": ("g", "q"),
    "b": ("d", "lb", "6"), "c": ("e",), "d": ("b", "cl", "dl"), "e": ("c",), "g": ("q", "9"), "h": ("lh",),
    "i": ("1", "l"), "l": ("1", "i"), "m": ("n", "nn", "rn"), "n": ("m", "r"), "o": ("0",), "q": ("g", "9"),
    "s": ("5",), "u": ("v",), "v": ("u",), "w": ("vv",), "z": ("2",),
}  # fmt: skip

#: TLDs a squatter reaches for when the name is taken on the target's own suffix.
_COMMON_TLDS: tuple[str, ...] = (
    "com", "net", "org", "info", "biz", "co", "io", "app", "dev", "xyz", "online", "site", "shop", "store",
    "us", "uk", "eu", "de", "cn", "ru", "top", "live", "cc", "me",
)  # fmt: skip

_VOWELS = "aeiou"
_LDH = set("abcdefghijklmnopqrstuvwxyz0123456789-")


@dataclass(frozen=True, slots=True)
class Permutation:
    """One candidate look-alike domain and the fuzzer that produced it."""

    fuzzer: str
    domain: str


def _clean_label(label: str) -> str | None:
    """A permuted name label is usable only if it is non-empty, LDH and does not start/end with a hyphen."""
    label = label.lower()
    if not label or len(label) > 63 or set(label) - _LDH or label.startswith("-") or label.endswith("-"):
        return None
    if ".." in label:
        return None
    return label


def _label_fuzzers(name: str) -> Iterator[tuple[str, str]]:
    """Yield ``(fuzzer, permuted_name)`` for every mutation of the bare name label."""
    chars = "abcdefghijklmnopqrstuvwxyz"
    n = len(name)

    for c in chars:  # addition: trailing character
        yield "addition", name + c

    if n > 1:
        for i in range(n):  # omission: drop one character
            yield "omission", name[:i] + name[i + 1 :]
        for i in range(n - 1):  # transposition: swap adjacent characters
            if name[i] != name[i + 1]:
                yield "transposition", name[:i] + name[i + 1] + name[i] + name[i + 2 :]

    for i, ch in enumerate(name):  # repetition: double a character
        yield "repetition", name[:i] + ch + name[i:]

    for i, ch in enumerate(name):  # keyboard-adjacent replacement and insertion
        for near in _KEYBOARD.get(ch, ""):
            yield "replacement", name[:i] + near + name[i + 1 :]
            yield "insertion", name[:i] + near + name[i:]

    for i, ch in enumerate(name):  # homoglyph substitution
        for glyph in _HOMOGLYPHS.get(ch, ()):
            yield "homoglyph", name[:i] + glyph + name[i + 1 :]

    for i in range(len(name.encode())):  # bitsquatting: a single flipped bit in the byte stream
        byte = name.encode()
        flipped = byte[i] ^ (1 << (i % 7))  # low 7 bits keep us in ASCII
        try:
            ch = bytes([flipped]).decode("ascii")
        except UnicodeDecodeError:
            continue
        if ch in _LDH:
            yield "bitsquatting", name[:i] + ch + name[i + 1 :]

    for i in range(1, n):  # hyphenation and subdomain split between characters
        yield "hyphenation", name[:i] + "-" + name[i:]
        yield "subdomain", name[:i] + "." + name[i:]

    for i, ch in enumerate(name):  # vowel swap
        if ch in _VOWELS:
            for v in _VOWELS:
                if v != ch:
                    yield "vowel-swap", name[:i] + v + name[i + 1 :]


def split_domain(domain: str) -> tuple[str, str] | None:
    """``mail.example.co.uk`` → ``("example", "co.uk")``; ``None`` when there is no registrable name."""
    ext = _tld(host_of(domain))
    if ext.domain and ext.suffix:
        return ext.domain.lower(), ext.suffix.lower()
    return None


def permutations(domain: str, *, tlds: Iterable[str] = _COMMON_TLDS) -> list[Permutation]:
    """Every distinct look-alike of ``domain``'s registrable name, plus the same name under other TLDs.

    The input domain itself is never returned. Candidates are deduplicated across fuzzers (the first fuzzer to
    reach a given domain keeps it), in a stable order.
    """
    split = split_domain(domain)
    if split is None:
        return []
    name, suffix = split
    original = f"{name}.{suffix}"

    out: list[Permutation] = []
    seen: set[str] = {original}

    def add(fuzzer: str, candidate_name: str, candidate_suffix: str) -> None:
        label_ok = all(_clean_label(part) for part in candidate_name.split("."))
        if not label_ok:
            return
        fqdn = f"{candidate_name}.{candidate_suffix}"
        if fqdn in seen:
            return
        seen.add(fqdn)
        out.append(Permutation(fuzzer, fqdn))

    for fuzzer, permuted in _label_fuzzers(name):
        add(fuzzer, permuted, suffix)

    for tld in tlds:  # same name, different suffix
        if tld != suffix:
            add("tld-swap", name, tld)

    return out


@module("similar_domains")
class SimilarDomains(LookupModule):
    rate_per_sec = 20.0

    async def _registered(self, resolver, domain: str) -> tuple[bool, tuple[str, ...]]:  # noqa: ANN001
        """A domain exists if it has an address, or a nameserver delegation (parked names have only ``NS``)."""
        for rtype in ("A", "AAAA"):
            answer = await query(resolver, domain, rtype)
            if answer.ok and answer.records:
                return True, answer.records
        ns = await query(resolver, domain, "NS")
        if ns.ok and ns.records:
            return True, ()
        return False, ()

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        cfg = self.ctx.config
        max_candidates = int(cfg.get("max_candidates", 600))
        emit_all = bool(cfg.get("emit_all", False))
        concurrency = max(1, int(cfg.get("concurrency", 20)))

        candidates = permutations(host_of(target))[:max_candidates]
        if not candidates:
            return

        resolver = make_resolver(cfg.get("nameservers"))
        sem = asyncio.Semaphore(concurrency)

        async def resolve(perm: Permutation) -> tuple[Permutation, bool, tuple[str, ...]]:
            async with sem:
                registered, ips = await self._registered(resolver, perm.domain)
            return perm, registered, ips

        for coro in asyncio.as_completed([resolve(p) for p in candidates]):
            perm, registered, ips = await coro
            if not registered and not emit_all:
                continue
            yield Emit(
                EntityType.SIMILAR_DOMAIN,
                perm.domain,
                confidence=0.9 if registered else 0.4,
                relation="looks_like",
                parent=target,
                meta={
                    "fuzzer": perm.fuzzer,
                    "registered": registered,
                    "addresses": list(ips),
                    "target": host_of(target),
                    "source": "similar_domains",
                },
            )
            if registered and ips:  # a resolvable look-alike is also a domain worth pivoting on
                yield Emit(
                    EntityType.DOMAIN,
                    perm.domain,
                    confidence=0.9,
                    relation="looks_like",
                    parent=target,
                    meta={"fuzzer": perm.fuzzer, "via": "similar_domains"},
                )
