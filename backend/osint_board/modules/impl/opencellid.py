"""OpenCellID — cell tower positions from the daily diff (default) or the full monthly dump (free key).

Catalog: opencellid · free_api · feed · access=key_free · cadence=monthly · phase 1
Needs ``OSINT_MODULE_OPENCELLID_API_KEY`` (the OpenCellID access token). ``config.mode`` is ``diff``
(yesterday's delta, small) or ``full`` (~40M rows, streamed). Tower positions are estimates, reported at
street precision when well sampled and city precision otherwise.
"""

from __future__ import annotations

import csv
import io
import zlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

from osint_board.entities.types import EntityType
from osint_board.modules.base import FeedModule
from osint_board.modules.helpers import to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, GeoPoint

DOWNLOAD_URL = "https://opencellid.org/ocid/downloads?token={token}&type={kind}&file={file}"
FULL_FILE = "cell_towers.csv.gz"
DIFF_FILE = "OCID-diff-cell-export-{date}-T000000.csv.gz"
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


def parse_row(row: dict[str, str]) -> Emit | None:
    try:
        lat, lon = float(row["lat"]), float(row["lon"])
        mcc, mnc, lac, cid = int(row["mcc"]), int(row["net"]), int(row["area"]), int(row["cell"])
    except (KeyError, TypeError, ValueError):
        return None
    rng = int(row.get("range") or 0)
    samples = int(row.get("samples") or 0)
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
            "signal": int(row["averageSignal"]) if row.get("averageSignal") not in (None, "") else None,
            "created": to_datetime(row.get("created")),
            "updated": to_datetime(row.get("updated")),
        },
    )


def parse_csv(text: str) -> list[Emit]:
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames and "lat" not in reader.fieldnames:  # header-less export
        reader = csv.DictReader(io.StringIO(text), fieldnames=COLUMNS)
    return [e for e in (parse_row(r) for r in reader) if e is not None]


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
    for line in buf.split(b"\n"):
        if line:
            yield line.decode("utf-8", errors="replace")


@module("opencellid")
class OpenCellIdFeed(FeedModule):
    rate_per_sec = 0.2

    def download_url(self) -> str:
        token = self.ctx.require_secret("API_KEY")
        if self.ctx.config.get("mode", "diff") == "full":
            return DOWNLOAD_URL.format(token=token, kind="full", file=FULL_FILE)
        day = self.ctx.config.get("date") or (datetime.now(tz=UTC) - timedelta(days=1)).strftime("%Y-%m-%d")
        return DOWNLOAD_URL.format(token=token, kind="diff", file=DIFF_FILE.format(date=day))

    async def poll(self) -> AsyncIterator[Emit]:
        header: list[str] | None = None
        async for line in gunzip_lines(self.ctx.http.stream_bytes(self.download_url())):
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
