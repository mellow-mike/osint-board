"""blockchain.com — balance and recent transactions of a Bitcoin address (free, no key).

Catalog: blockchain_com · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://blockchain.info/rawaddr/{address}"
SATOSHI = 100_000_000


def parse_rawaddr(payload: dict[str, Any], target: EntityRef, limit: int = 50) -> list[Emit]:
    address = payload.get("address") or target.value
    if "final_balance" not in payload:
        return []
    balance = int(payload.get("final_balance") or 0) / SATOSHI
    out = [
        Emit(
            EntityType.CRYPTO_BALANCE,
            f"{address}: {balance:.8f} BTC",
            relation="balance_of",
            parent=target,
            meta={
                "currency": "BTC",
                "balance": balance,
                "total_received": int(payload.get("total_received") or 0) / SATOSHI,
                "total_sent": int(payload.get("total_sent") or 0) / SATOSHI,
                "tx_count": payload.get("n_tx"),
                "source": "blockchain.com",
            },
        )
    ]
    for tx in (payload.get("txs") or [])[:limit]:
        h = tx.get("hash")
        if not h:
            continue
        inputs = [(i.get("prev_out") or {}).get("addr") for i in tx.get("inputs") or []]
        outputs = [o.get("addr") for o in tx.get("out") or []]
        result = int(tx.get("result") or 0) / SATOSHI
        out.append(
            Emit(
                EntityType.CRYPTO_TRANSACTION,
                h,
                relation="received" if result > 0 else "sent",
                parent=target,
                observed_at=to_datetime(tx.get("time")),
                meta={
                    "currency": "BTC",
                    "amount": result,
                    "inputs": [a for a in inputs if a][:20],
                    "outputs": [a for a in outputs if a][:20],
                    "block": tx.get("block_height"),
                    "url": f"https://www.blockchain.com/btc/tx/{h}",
                    "source": "blockchain.com",
                },
            )
        )
    return out


@module("blockchain_com")
class BlockchainCom(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        limit = int(self.ctx.config.get("limit", 50))
        payload = await self.ctx.http.get_json_or_none(URL.format(address=target.value), params={"limit": limit})
        for e in parse_rawaddr(payload or {}, target, limit):
            yield e
