"""OpenCellID — cell tower positions from the daily diff (default) or the full monthly dump (free key).

Catalog: opencellid · free_api · feed · access=key_free · cadence=daily · phase 1
Needs ``OSINT_MODULE_OPENCELLID_API_KEY`` (the OpenCellID access token). ``config.mode`` is ``diff``
(the daily delta, small; every day missed since the last success is fetched, up to a week) or ``full``
(~40M rows, streamed, at most once a calendar month). ``config.date`` pins one diff day. Tower positions are
estimates, reported at street precision when well sampled and city precision otherwise.

OpenCellID answers errors (bad token, exhausted quota, missing file) with HTTP 200 and a JSON body; those raise
:class:`DownloadRefused` with the upstream message instead of a zlib error, and a rejected token raises
:class:`TokenRejected` (a :class:`~osint_board.modules.base.MissingSecret`, so the runner disables the feed).
"""

from __future__ import annotations

import csv
import io
import json
import zlib
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta
from typing import Any

import httpx

from osint_board.entities.types import EntityType
from osint_board.modules.base import FeedModule, MissingSecret
from osint_board.modules.helpers import to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, GeoPoint

DOWNLOAD_URL = "https://opencellid.org/ocid/downloads?token={token}&type={kind}&file={file}"
FULL_FILE = "cell_towers.csv.gz"
DIFF_FILE = "OCID-diff-cell-export-{date}-T000000.csv.gz"
GZIP_MAGIC = b"\x1f\x8b"
#: most daily diffs fetched in one poll when catching up after downtime
MAX_CATCHUP_DAYS = 7
COLUMNS = (
    "radio",
    "mcc",
    "net",
    "area",
    "cell",
    "unit",
    "lon",
    "lat",
    "range",
    "samples",
    "changeable",
    "created",
    "updated",
    "averageSignal",
)


def _optional_int(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def parse_row(row: dict[str, str]) -> Emit | None:
    """One CSV row → a tower (``None`` when the identity or position is malformed; bad optional fields → ``None``)."""
    try:
        lat, lon = float(row["lat"]), float(row["lon"])
        mcc, mnc, lac, cid = int(row["mcc"]), int(row["net"]), int(row["area"]), int(row["cell"])
    except (KeyError, TypeError, ValueError):
        return None
    rng = _optional_int(row.get("range")) or 0
    samples = _optional_int(row.get("samples")) or 0
    precision = "street" if samples >= 5 and 0 < rng <= 1000 else "city"
    try:
        geo = GeoPoint(lat=lat, lon=lon, precision=precision, source="opencellid")
    except ValueError:
        return None
    ident = f"{mcc}-{mnc}-{lac}-{cid}"
    return Emit(
        type=EntityType.CELL_TOWER,
        value=ident,
        key=f"cell:{ident}",
        layer="cell_towers",
        geo=geo,
        observed_at=to_datetime(row.get("updated")),
        meta={
            "radio": row.get("radio"),
            "mcc": mcc,
            "mnc": mnc,
            "lac": lac,
            "cid": cid,
            "range_m": rng,
            "samples": samples,
            "signal": _optional_int(row.get("averageSignal")),
            "created": to_datetime(row.get("created")),
            "updated": to_datetime(row.get("updated")),
        },
    )


def parse_csv(text: str) -> list[Emit]:
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames and "lat" not in reader.fieldnames:  # header-less export
        reader = csv.DictReader(io.StringIO(text), fieldnames=COLUMNS)
    return [e for e in (parse_row(r) for r in reader) if e is not None]


class DownloadRefused(RuntimeError):
    """OpenCellID answered a download with an error document (HTTP 200, JSON) instead of a gzip file."""

    def __init__(self, message: str, *, file: str = "") -> None:
        self.message = message
        where = f" for {file}" if file else ""
        super().__init__(f"opencellid: download refused{where}: {message}")

    @property
    def affects_every_file(self) -> bool:
        """Quota problems: trying other files (or soon) only burns more of the download allowance."""
        return "LIMIT" in self.message.upper()


class TokenRejected(MissingSecret):
    """OpenCellID refused the configured token (``INVALID_TOKEN``).

    A configuration problem, not an outage: as a :class:`MissingSecret` it makes the feed runner disable the feed
    once instead of retrying it (every retry would count against the token's download allowance).
    """

    def __init__(self, message: str) -> None:
        super().__init__("opencellid", "API_KEY")
        self.message = message
        self.args = (f"opencellid rejected the token in {self.env_var}: {message}",)

    def __reduce__(self) -> tuple[Any, ...]:
        return type(self), (self.message,)


def refusal(message: str, *, file: str = "") -> RuntimeError:
    """The exception for an error document: :class:`TokenRejected` for token errors, else :class:`DownloadRefused`."""
    return TokenRejected(message) if "TOKEN" in message.upper() else DownloadRefused(message, file=file)


def download_error(body: bytes) -> str:
    """The message in a non-gzip download body: ``{"status":"error","message":"INVALID_TOKEN"}`` → ``INVALID_TOKEN``."""
    text = body[:4096].decode("utf-8", errors="replace").strip()
    if not text:
        return "empty response"
    try:
        doc = json.loads(text)
    except ValueError:
        return text[:200]
    if isinstance(doc, dict):
        return str(doc.get("message") or doc.get("error") or doc.get("status") or text)[:200]
    return text[:200]


async def ensure_gzip(chunks: AsyncIterator[bytes], *, file: str = "") -> AsyncIterator[bytes]:
    """Pass a gzip body through unchanged, or raise :func:`refusal` with the upstream message.

    OpenCellID reports a bad token, an exhausted quota or a missing file as HTTP 200 with a small JSON body, which
    would otherwise surface as a zlib "incorrect header check".
    """
    it = aiter(chunks)
    head = b""
    try:
        async for chunk in it:
            head += chunk
            if len(head) >= len(GZIP_MAGIC):
                break
        if head[: len(GZIP_MAGIC)] != GZIP_MAGIC:
            async for chunk in it:  # an error document is small; read a bounded amount of it
                head += chunk
                if len(head) >= 65_536:
                    break
            raise refusal(download_error(head), file=file)
        yield head
        async for chunk in it:
            yield chunk
    finally:
        aclose = getattr(it, "aclose", None)
        if aclose is not None:  # release the HTTP stream even when we stop early
            await aclose()


async def gunzip_lines(chunks: AsyncIterator[bytes]) -> AsyncIterator[str]:
    """Incrementally decompress a gzip body into text lines (memory stays flat for multi-GB dumps)."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    buf = b""
    async for chunk in chunks:
        buf += d.decompress(chunk)
        *lines, buf = buf.split(b"\n")
        for line in lines:
            yield line.decode("utf-8", errors="replace")
    buf += d.flush()
    if not d.eof:
        raise ValueError("opencellid: truncated gzip download")
    for line in buf.split(b"\n"):
        if line:
            yield line.decode("utf-8", errors="replace")


def pending_diffs(last: str | None, target: date, *, limit: int = MAX_CATCHUP_DAYS) -> tuple[list[str], int]:
    """Diff dates (``YYYY-MM-DD``) to ingest, oldest first, and how many older ones ``limit`` dropped.

    Every day after ``last`` (the last diff ingested) up to ``target``; only ``target`` when nothing was ingested
    yet; nothing when ``target`` is already done.
    """
    try:
        done = date.fromisoformat(last) if last else None
    except ValueError:
        done = None
    if done is None:
        return [target.isoformat()], 0
    missing = (target - done).days
    if missing <= 0:
        return [], 0
    keep = min(missing, limit)
    return [(target - timedelta(days=n)).isoformat() for n in range(keep - 1, -1, -1)], missing - keep


@module("opencellid")
class OpenCellIdFeed(FeedModule):
    rate_per_sec = 0.2

    def download_url(self, day: str | None = None) -> str:
        token = self.ctx.require_secret("API_KEY")
        if self.ctx.config.get("mode", "diff") == "full":
            return DOWNLOAD_URL.format(token=token, kind="full", file=FULL_FILE)
        day = day or self.ctx.config.get("date") or (datetime.now(tz=UTC) - timedelta(days=1)).strftime("%Y-%m-%d")
        return DOWNLOAD_URL.format(token=token, kind="diff", file=DIFF_FILE.format(date=day))

    async def poll(self) -> AsyncIterator[Emit]:
        if self.ctx.config.get("mode", "diff") == "full":
            month = datetime.now(tz=UTC).strftime("%Y-%m")
            if self.ctx.config.get("_last_full") == month:
                return  # the ~40M-row dump is ingested once a month even though the feed polls daily
            async for emit in self._ingest(self.download_url(), FULL_FILE):
                yield emit
            self.ctx.config["_last_full"] = month
            return
        explicit = self.ctx.config.get("date")
        target = date.fromisoformat(explicit) if explicit else datetime.now(tz=UTC).date() - timedelta(days=1)
        days, dropped = pending_diffs(self.ctx.config.get("_last_diff"), target)
        if dropped:
            self.log.warning("opencellid.catchup_capped", missed=dropped + len(days), fetching=len(days), first=days[0])
        for day in days:
            # A missed older diff that is gone upstream is skipped with a warning. The newest one (maybe not
            # published yet), quota errors, a rejected token and transport errors propagate: the runner backs off
            # (or disables the feed) and the next poll resumes after the last day ingested.
            try:
                async for emit in self._ingest(self.download_url(day), DIFF_FILE.format(date=day)):
                    yield emit
            except DownloadRefused as exc:
                if exc.affects_every_file or day == days[-1]:
                    raise
                self.log.warning("opencellid.diff_missing", day=day, error=exc.message)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 404 or day == days[-1]:
                    raise
                self.log.warning("opencellid.diff_missing", day=day, error="HTTP 404")
            self.ctx.config["_last_diff"] = day

    async def _ingest(self, url: str, file: str) -> AsyncIterator[Emit]:
        header: list[str] | None = None
        async for line in gunzip_lines(ensure_gzip(self.ctx.http.stream_bytes(url), file=file)):
            if not line.strip():
                continue
            fields = next(csv.reader([line]))
            if header is None:
                header = fields if "lat" in fields else list(COLUMNS)
                if header is fields:
                    continue
            emit = parse_row(dict(zip(header, fields, strict=False)))
            if emit is not None:
                yield emit
