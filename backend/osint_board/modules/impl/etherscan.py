"""Etherscan (API v2) — ETH balance and recent transactions of an address (free key).

Catalog: etherscan · free_api · lookup · access=key_free · phase 1
Needs ``OSINT_MODULE_ETHERSCAN_API_KEY``; ``config.chainid`` selects another EVM chain (default 1, mainnet).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://api.etherscan.io/v2/api"
WEI = 10**18


def parse_balance(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    if str(payload.get("status")) != "1":
        return []
    try:
        eth = int(payload.get("result") or 0) / WEI
    except (TypeError, ValueError):
        return []
    return [
        Emit(
            EntityType.CRYPTO_BALANCE,
            f"{target.value.lower()}: {eth:.6f} ETH",
            relation="balance_of",
            parent=target,
            meta={"currency": "ETH", "balance": eth, "wei": payload.get("result"), "source": "etherscan"},
        )
    ]


def parse_txlist(payload: dict[str, Any], target: EntityRef, limit: int = 50) -> list[Emit]:
    if str(payload.get("status")) != "1" or not isinstance(payload.get("result"), list):
        return []
    me = target.value.lower()
    out: list[Emit] = []
    for tx in payload["result"][:limit]:
        h = tx.get("hash")
        if not h:
            continue
        try:
            value = int(tx.get("value") or 0) / WEI
        except (TypeError, ValueError):
            value = 0.0
        sender, receiver = (tx.get("from") or "").lower(), (tx.get("to") or "").lower()
        out.append(
            Emit(
                EntityType.CRYPTO_TRANSACTION,
                h,
                relation="received" if receiver == me else "sent",
                parent=target,
                observed_at=to_datetime(tx.get("timeStamp")),
                meta={
                    "currency": "ETH",
                    "amount": value,
                    "from": sender,
                    "to": receiver,
                    "block": tx.get("blockNumber"),
                    "error": tx.get("isError") == "1",
                    "url": f"https://etherscan.io/tx/{h}",
                    "source": "etherscan",
                },
            )
        )
    return out


@module("etherscan")
class Etherscan(LookupModule):
    rate_per_sec = 4.0

    async def _call(self, **params: Any) -> dict[str, Any]:
        params.update({"chainid": int(self.ctx.config.get("chainid", 1)), "apikey": self.ctx.require_secret("API_KEY")})
        return await self.ctx.http.get_json(URL, params=params)

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        limit = int(self.ctx.config.get("limit", 50))
        for e in parse_balance(
            await self._call(module="account", action="balance", address=target.value, tag="latest"), target
        ):
            yield e
        txs = await self._call(
            module="account",
            action="txlist",
            address=target.value,
            startblock=0,
            endblock=99999999,
            page=1,
            offset=limit,
            sort="desc",
        )
        for e in parse_txlist(txs, target, limit):
            yield e
