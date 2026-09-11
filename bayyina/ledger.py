"""Hash-chained, append-only evidence ledger.

Why a government procurement tool needs this
--------------------------------------------
UAE Federal Law No. 11 of 2023 on Procurement in the Federal Government
requires (Art. 22(3)) that non-financial evaluation criteria be objective and
quantifiable, (Art. 22(4)) that the weight of each criterion be published, and
(Art. 29) that an unsuccessful bidder may request the strengths and weaknesses
of its bid. Together those imply that an award decision must still be
explainable *after* the fact, to a party with an incentive to challenge it.

A hash chain gives us that: each record commits to its predecessor, so the
evidence set that produced a score cannot be quietly edited afterwards without
the chain failing to verify. This is tamper-*evidence*, not tamper-proofing —
anyone holding the file can rewrite the whole chain. It defends against silent
mutation of a stored assessment, which is the realistic procurement risk; it
does not defend against a malicious operator, which needs a countersignature
from a party who does not control the file.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from .util import canonical, sha256_hex

GENESIS = "0" * 64


@dataclass
class LedgerRecord:
    seq: int
    kind: str
    ts: str
    payload_hash: str
    prev_hash: str
    entry_hash: str
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "ts": self.ts,
            "payload_hash": self.payload_hash,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "payload": self.payload,
        }


def _entry_hash(seq: int, kind: str, ts: str, payload_hash: str, prev_hash: str) -> str:
    header = {
        "seq": seq,
        "kind": kind,
        "ts": ts,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
    }
    return sha256_hex(canonical(header))


class EvidenceLedger:
    """An in-memory chain that can be flushed to newline-delimited JSON.

    Timestamps come from the *evidence*, never from the wall clock, so a replay
    of a recorded assessment produces a byte-identical ledger. That is what
    makes the determinism claim testable.
    """

    def __init__(self) -> None:
        self._records: List[LedgerRecord] = []

    # -- writing ---------------------------------------------------------

    def append(self, kind: str, payload: Dict[str, Any], ts: str = "") -> LedgerRecord:
        seq = len(self._records)
        prev = self._records[-1].entry_hash if self._records else GENESIS
        payload_hash = sha256_hex(canonical(payload))
        ts = ts or payload.get("observed_at") or ""
        rec = LedgerRecord(
            seq=seq,
            kind=kind,
            ts=ts,
            payload_hash=payload_hash,
            prev_hash=prev,
            entry_hash=_entry_hash(seq, kind, ts, payload_hash, prev),
            payload=payload,
        )
        self._records.append(rec)
        return rec

    def extend(self, kind: str, payloads: Iterable[Dict[str, Any]]) -> None:
        for payload in payloads:
            self.append(kind, payload)

    # -- reading ---------------------------------------------------------

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[LedgerRecord]:
        return iter(self._records)

    @property
    def head(self) -> str:
        return self._records[-1].entry_hash if self._records else GENESIS

    def records(self) -> List[LedgerRecord]:
        return list(self._records)

    # -- persistence -----------------------------------------------------

    def write(self, path: str) -> str:
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            for rec in self._records:
                handle.write(json.dumps(rec.to_dict(), sort_keys=True, ensure_ascii=False))
                handle.write("\n")
        return self.head

    @classmethod
    def read(cls, path: str) -> "EvidenceLedger":
        ledger = cls()
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                ledger._records.append(
                    LedgerRecord(
                        seq=raw["seq"],
                        kind=raw["kind"],
                        ts=raw.get("ts", ""),
                        payload_hash=raw["payload_hash"],
                        prev_hash=raw["prev_hash"],
                        entry_hash=raw["entry_hash"],
                        payload=raw.get("payload", {}),
                    )
                )
        return ledger

    # -- verification ----------------------------------------------------

    def verify(self) -> Tuple[bool, List[str]]:
        """Recompute the whole chain. Returns (ok, list of human-readable problems)."""
        problems: List[str] = []
        prev = GENESIS
        for index, rec in enumerate(self._records):
            if rec.seq != index:
                problems.append(f"record {index}: sequence number is {rec.seq}, expected {index}")
            if rec.prev_hash != prev:
                problems.append(
                    f"record {index}: prev_hash {rec.prev_hash[:12]} does not chain to "
                    f"{prev[:12]} — a record was inserted, removed or reordered"
                )
            recomputed_payload = sha256_hex(canonical(rec.payload))
            if recomputed_payload != rec.payload_hash:
                problems.append(
                    f"record {index} ({rec.kind}): payload does not match its hash — "
                    "the stored evidence was modified after it was recorded"
                )
            recomputed_entry = _entry_hash(
                rec.seq, rec.kind, rec.ts, rec.payload_hash, rec.prev_hash
            )
            if recomputed_entry != rec.entry_hash:
                problems.append(f"record {index} ({rec.kind}): entry hash does not verify")
            prev = rec.entry_hash
        return (not problems), problems

    def find(self, digest: str) -> Optional[LedgerRecord]:
        for rec in self._records:
            if rec.payload_hash == digest:
                return rec
        return None
