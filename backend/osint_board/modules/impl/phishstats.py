"""PhishStats — scored phishing URLs with their hosting IPs (free, no key).

Catalog: phishstats · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

import csv
import io

from osint_board.modules.lists import IndicatorList, ListLookupModule, ListSource
from osint_board.modules.registry import module

URL = "https://phishstats.info/phish_score.csv"


def parse_phish_score(text: str) -> IndicatorList:
    """``"Date","Score","URL","IP"`` rows (comment lines start with ``#``); URL and IP both become indicators."""
    out = IndicatorList()
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 4 or row[0].startswith("#"):
            continue
        date, score, url, ip = (c.strip() for c in row[:4])
        note = f"score {score} ({date})"
        out.add(url, note)
        if ip:
            out.add(ip, note)
    return out


@module("phishstats")
class PhishStats(ListLookupModule):
    SOURCE = "PhishStats"
    LISTS = (ListSource(URL, "phish_score", parse_phish_score, ttl=3600, category="phishing"),)
