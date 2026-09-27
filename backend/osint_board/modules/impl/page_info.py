"""Page Information — what a web page *does* (forms, password fields, uploads, redirects, embeds).

Catalog: page_info · internal · lookup · access=local · phase 2
Consumes: url, raw_content
Produces: page_info

Reads a page's markup and reports the security-relevant facts an analyst wants without opening it: does it take
a password, does it have a login or file-upload form, does a form post credentials to another host or over plain
HTTP, does it redirect via ``<meta refresh>``, does it embed third-party frames or legacy plugins. The analysis
(:func:`analyze_page`) is a pure function over the markup, so it is exercised offline against a fixture; the
lookup only fetches the page first when handed a bare ``url``. When the web spider already collected the page it
arrives as ``raw_content`` (markup in ``meta["text"]``) and nothing is fetched.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import host_of
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

_SENSITIVE_INPUTS = frozenset({"password", "email", "tel", "file"})


@dataclass(slots=True)
class Form:
    method: str = "get"
    action: str = ""
    inputs: list[str] = field(default_factory=list)
    has_password: bool = False
    has_upload: bool = False
    has_hidden_token: bool = False

    @property
    def is_login(self) -> bool:
        return self.has_password and any(t in ("text", "email", "tel", "") for t in self.inputs)


@dataclass(slots=True)
class PageInfo:
    url: str
    title: str | None = None
    forms: list[Form] = field(default_factory=list)
    takes_passwords: bool = False
    has_login_form: bool = False
    has_upload_form: bool = False
    external_form_hosts: list[str] = field(default_factory=list)
    insecure_password_form: bool = False
    meta_refresh: str | None = None
    generator: str | None = None
    frame_hosts: list[str] = field(default_factory=list)
    legacy_plugins: list[str] = field(default_factory=list)
    external_scripts: int = 0
    comment_count: int = 0

    def summary(self) -> dict[str, object]:
        flags = []
        if self.takes_passwords:
            flags.append("password")
        if self.has_login_form:
            flags.append("login")
        if self.has_upload_form:
            flags.append("upload")
        if self.insecure_password_form:
            flags.append("insecure-credentials")
        if self.external_form_hosts:
            flags.append("external-form")
        if self.meta_refresh:
            flags.append("meta-refresh")
        if self.legacy_plugins:
            flags.append("legacy-plugin")
        return {
            "url": self.url,
            "title": self.title,
            "forms": len(self.forms),
            "takes_passwords": self.takes_passwords,
            "has_login_form": self.has_login_form,
            "has_upload_form": self.has_upload_form,
            "insecure_password_form": self.insecure_password_form,
            "external_form_hosts": self.external_form_hosts,
            "meta_refresh": self.meta_refresh,
            "generator": self.generator,
            "frame_hosts": self.frame_hosts,
            "legacy_plugins": self.legacy_plugins,
            "external_scripts": self.external_scripts,
            "comment_count": self.comment_count,
            "flags": flags,
        }


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.forms: list[Form] = []
        self.meta_refresh: str | None = None
        self.generator: str | None = None
        self.frame_srcs: list[str] = []
        self.legacy: list[str] = []
        self.external_scripts: list[str] = []
        self.comments = 0
        self._form: Form | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self._form = Form(method=(a.get("method", "get") or "get").lower(), action=a.get("action", ""))
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea", "button"):
            itype = a.get("type", "").lower() if tag == "input" else tag
            form = self._form
            if form is not None:
                form.inputs.append(itype)
                if itype == "password":
                    form.has_password = True
                elif itype == "file":
                    form.has_upload = True
                elif itype == "hidden" and _looks_like_token(a.get("name", "")):
                    form.has_hidden_token = True
        elif tag in ("iframe", "frame") and a.get("src"):
            self.frame_srcs.append(a["src"])
        elif tag in ("embed", "object", "applet"):
            self.legacy.append(tag)
        elif tag == "script" and a.get("src"):
            self.external_scripts.append(a["src"])
        elif tag == "meta":
            if a.get("http-equiv", "").lower() == "refresh":
                m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
                if m:
                    self.meta_refresh = m.group(1).strip()
            elif a.get("name", "").lower() == "generator" and a.get("content"):
                self.generator = a["content"].strip()[:200]

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)

    def handle_comment(self, data: str) -> None:
        self.comments += 1


_TOKEN_RE = re.compile(r"csrf|xsrf|token|nonce|authenticity", re.I)


def _looks_like_token(name: str) -> bool:
    return bool(name) and bool(_TOKEN_RE.search(name))


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def analyze_page(html: str, url: str) -> PageInfo:
    """Pure page analysis: parse ``html`` (fetched from ``url``) into a :class:`PageInfo`."""
    parser = _Parser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - html.parser is lenient; keep whatever was collected
        pass

    page_host = _host(url)
    page_insecure = urlsplit(url).scheme == "http"
    info = PageInfo(url=url)
    info.title = re.sub(r"\s+", " ", "".join(parser.title_parts)).strip() or None
    if info.title:
        info.title = info.title[:300]
    info.forms = parser.forms
    info.meta_refresh = parser.meta_refresh
    info.generator = parser.generator
    info.external_scripts = sum(1 for s in parser.external_scripts if _is_external(s, page_host))
    info.comment_count = parser.comments
    info.legacy_plugins = sorted(set(parser.legacy))

    frame_hosts: list[str] = []
    for src in parser.frame_srcs:
        h = _host(urljoin(url, src))
        if h and h != page_host and h not in frame_hosts:
            frame_hosts.append(h)
    info.frame_hosts = frame_hosts

    external_hosts: list[str] = []
    for form in parser.forms:
        if form.has_password:
            info.takes_passwords = True
        if form.is_login:
            info.has_login_form = True
        if form.has_upload:
            info.has_upload_form = True
        action_url = urljoin(url, form.action) if form.action else url
        action_scheme = urlsplit(action_url).scheme
        action_host = _host(action_url)
        if action_host and action_host != page_host and action_host not in external_hosts:
            external_hosts.append(action_host)
        if form.has_password and (action_scheme == "http" or (page_insecure and not form.action)):
            info.insecure_password_form = True
    info.external_form_hosts = external_hosts
    return info


def _is_external(src: str, page_host: str) -> bool:
    h = _host(src) if "//" in src else ""
    return bool(h) and h != page_host


@module("page_info")
class PageInformation(LookupModule):
    rate_per_sec = 5.0

    async def _fetch(self, url: str) -> tuple[str, str] | None:
        try:
            resp = await self.ctx.http.get(url, retries=1, timeout=20)
        except Exception as exc:  # noqa: BLE001 - a dead page is a non-result, not a crash
            self.log.info("page_info.fetch_failed", url=url, error=str(exc))
            return None
        ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype and not ctype.startswith(("text/html", "application/xhtml+xml", "text/plain")):
            return None
        return str(resp.url), resp.text

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        if target.type is EntityType.RAW_CONTENT:
            html = target.meta.get("text")
            url = target.meta.get("url") or target.value
            if not html:
                return
        else:
            url = target.value if "://" in target.value else f"https://{host_of(target)}/"
            fetched = await self._fetch(url)
            if fetched is None:
                return
            url, html = fetched

        info = analyze_page(html, url)
        summary = info.summary()
        yield Emit(
            EntityType.PAGE_INFO,
            url,
            relation="describes",
            parent=target,
            meta={**summary, "source": "page_info"},
        )
