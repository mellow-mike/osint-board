"""OpenSky Network — live aircraft for the ``aviation`` layer, keyless by default through ``adsb_network``.

Catalog: opensky · tiered_api (replacement: adsb_network) · feed · access=account · cadence=5s · phase 2

Without any configuration this module never calls OpenSky. Each poll is one round of the in-process
``adsb_network`` seed (:mod:`osint_board.modules.adsb`): the community aggregators adsb.lol (ODbL 1.0) and adsb.fi
(open data, personal/non-commercial use, attribution required) are asked for the most overdue 250 nm tiles of a
world grid (up to three requests per provider per round, spaced to at most 0.5 req/s each by default and never
above 1 req/s; a provider answering 429 is slowed down and recovers gradually), any own readsb/dump1090 receivers
are read every round, and the answers are merged per ICAO address, newest position first. Busy airspace
refreshes every 2-5 minutes, quiet regions every 15 min to 3 h; after a restart the first world sweep takes most of
an hour, though tiles found busy during it are kept fresh. A round in which every request failed raises, so the
runner backs off; single failed requests are logged (``adsb.request_failed``) and the provider's breaker backs off.

OpenSky itself is an optional accelerator and OFF by default: its terms of use appear to require a written licence
for operational use of the REST API (review them before enabling it). It is enabled by
``OSINT_MODULE_OPENSKY_CLIENT_ID`` + ``OSINT_MODULE_OPENSKY_CLIENT_SECRET`` (an API client from the OpenSky account
page; OAuth2 client credentials, 4,000 credits/day → one global snapshot every 86 s) or by config
``{"opensky": {"anonymous": true}}`` (400 credits/day → every 14.4 min). Its snapshot is emitted and also tells the
tile scheduler where traffic is.

Config (``OSINT_MODULE_OPENSKY_CONFIG``, a JSON object):

* ``receivers``: ``[{"name": "home", "url": "http://pi.local/tar1090/data/aircraft.json"}]``
* ``providers``: ``{"adsb.fi": {"enabled": false}, "adsb.lol": {"rate": 1.0}}`` (rates are capped at 1 req/s,
  adsb.fi's published limit); a new name with a ``url``
  template (``{lat}``, ``{lon}``, ``{nm}``) adds a readsb-compatible aggregator you have an arrangement with
* ``opensky``: ``{"anonymous": true, "daily_credits": 8000, "interval_s": 120}``
* ``exclude_flags``: any of ``military``, ``interesting``, ``pia``, ``ladd`` — aircraft carrying them are dropped.
  The flags come from the aggregators' aircraft database (readsb ``dbFlags``); OpenSky and receivers without a
  ``--db-file`` report none, so flags seen once are remembered per address and applied to every later sighting.
* ``exclude_hex``: ICAO addresses never to emit
* ``round_s`` (default 5): sizes each round's per-provider budget, ``ceil(rate * round_s)`` requests
* ``radius_nm`` (default and maximum 250): tile query radius; smaller radii mean more tiles
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import AsyncIterator
from dataclasses import replace
from typing import Any

from osint_board.modules.adsb import DB_FLAGS, AdsbNetwork, AircraftState, to_emit
from osint_board.modules.base import FeedModule, ModuleContext
from osint_board.modules.registry import module
from osint_board.modules.types import Emit


class AdsbUnavailable(RuntimeError):
    """Every ADS-B request of a round failed (or every source needed is backing off)."""


@module("opensky")
class OpenSkyFeed(FeedModule):
    rate_per_sec = 1.0
    #: aircraft keys whose last emitted position time is remembered (least recently updated evicted first)
    max_tracked = 50_000
    #: addresses whose database flags (military/interesting/PIA/LADD) are remembered for sources without them
    max_flagged = 50_000
    #: seconds between ``opensky.stats`` log lines
    stats_every_s = 60.0

    def __init__(self, ctx: ModuleContext) -> None:
        super().__init__(ctx)
        self.clock = time.monotonic
        self.wall = time.time
        self.network: AdsbNetwork | None = None
        self._last_pos: OrderedDict[str, float] = OrderedDict()
        self._flags: OrderedDict[str, int] = OrderedDict()
        self._emitted_total = 0
        self._last_round = 0
        self._stats_at: float | None = None
        self._stats_prev: dict[str, float] = {}
        self._exclude_flags, self._exclude_hex = self._policy(ctx.config)

    def _policy(self, config: dict[str, Any]) -> tuple[int, frozenset[str]]:
        mask = 0
        for flag in config.get("exclude_flags") or []:
            bit = DB_FLAGS.get(str(flag).lower())
            if bit is None:
                self.log.warning("opensky.config_invalid", exclude_flag=flag, allowed=sorted(DB_FLAGS))
                continue
            mask |= bit
        hexes = frozenset(str(h).strip().lower() for h in config.get("exclude_hex") or [] if str(h).strip())
        return mask, hexes

    async def setup(self) -> None:
        net = self._net()
        osky = net.opensky
        self.log.info(
            "opensky.sources",
            providers=[f"{p.name}@{p.provider.rate_per_sec:g}/s" for p in net.providers],
            receivers=[r.receiver.name for r in net.receivers],
            opensky="off" if osky is None else ("oauth2" if osky.auth else "anonymous"),
            opensky_interval_s=round(osky.base_interval, 1) if osky is not None else None,
            tiles=len(net.scheduler.grid),
        )

    def _net(self) -> AdsbNetwork:
        if self.network is None:
            self.network = AdsbNetwork.from_config(
                self.ctx.config,
                settings=self.ctx.settings,
                client_id=self.ctx.secret("CLIENT_ID"),
                client_secret=self.ctx.secret("CLIENT_SECRET"),
                clock=self.clock,
                wall=self.wall,
                logger=self.log,
            )
        return self.network

    def _with_known_flags(self, state: AircraftState) -> AircraftState:
        """Remember an address's database flags and add earlier ones to a sighting that lacks them."""
        known = self._flags.get(state.hex, 0)
        if state.db_flags:
            self._flags[state.hex] = known | state.db_flags
            self._flags.move_to_end(state.hex)
            while len(self._flags) > self.max_flagged:
                self._flags.popitem(last=False)
        if known & ~state.db_flags:
            return replace(state, db_flags=state.db_flags | known)
        return state

    def _excluded(self, state: AircraftState) -> bool:
        return bool(state.db_flags & self._exclude_flags) or state.hex in self._exclude_hex

    def _advanced(self, state: AircraftState) -> bool:
        """Emit only when the position time moved on since the last emission for this key."""
        last = self._last_pos.get(state.key)
        if last is not None and state.pos_time <= last:
            return False
        self._last_pos[state.key] = state.pos_time
        self._last_pos.move_to_end(state.key)
        while len(self._last_pos) > self.max_tracked:
            self._last_pos.popitem(last=False)
        return True

    async def poll(self) -> AsyncIterator[Emit]:
        result = await self._net().round()
        states = [self._with_known_flags(s) for s in result.states]
        emits = [to_emit(s) for s in states if not self._excluded(s) and self._advanced(s)]
        self._last_round = len(result.states)
        self._emitted_total += len(emits)
        self._log_stats()
        if result.all_failed:
            raise AdsbUnavailable(result.summary())
        for emit in emits:
            yield emit

    def _log_stats(self) -> None:
        now = self.clock()
        if self._stats_at is not None and now - self._stats_at < self.stats_every_s:
            return
        totals = self._net().stats()
        # request counters are per stats window (since the previous line); everything else is a gauge
        fields = {k: (v - self._stats_prev.get(k, 0) if k.startswith("requests_") else v) for k, v in totals.items()}
        fields["window_s"] = round(now - self._stats_at, 1) if self._stats_at is not None else 0.0
        fields["aircraft_last_round"] = self._last_round
        fields["aircraft_emitted_total"] = self._emitted_total
        fields["tracked_aircraft"] = len(self._last_pos)
        self._stats_at, self._stats_prev = now, totals
        self.log.info("opensky.stats", **fields)
