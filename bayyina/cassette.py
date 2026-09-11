"""Evidence cassettes — the record/replay layer.

The problem this solves
-----------------------
An assessment that reaches out to the internet is (a) not reproducible, because
the internet changes between runs, and (b) not demonstrable, because the demo
fails when the venue wifi does. An assessment that never reaches out is not
evidence of anything.

A cassette is a recorded set of raw observations with the timestamp at which
each was taken. ``record`` mode performs live collection and writes a cassette.
``replay`` mode reads the cassette and performs no network activity at all.
``auto`` replays what is on disk and records only what is missing.

The scoring pipeline cannot tell the difference: it consumes ``Evidence``
objects either way. So the run a juror reproduces offline executes exactly the
same check, scoring, divergence and reporting code as a live run — only the
transport differs. Nothing in the analysis path is stubbed for the demo.

Cassettes are the same idea as HTTP interaction recording in test suites
(VCR/Betamax), applied to security evidence rather than to HTTP alone.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, List, Optional

from .models import Evidence, EvidenceStatus
from .util import content_hash

MODE_REPLAY = "replay"
MODE_RECORD = "record"
MODE_AUTO = "auto"
MODES = (MODE_REPLAY, MODE_RECORD, MODE_AUTO)


class CassetteError(RuntimeError):
    pass


class Cassette:
    """A keyed store of raw observations."""

    def __init__(self, path: str, mode: str = MODE_REPLAY) -> None:
        if mode not in MODES:
            raise CassetteError(f"unknown cassette mode {mode!r}; expected one of {MODES}")
        self.path = path
        self.mode = mode
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._recorded = 0
        self._replayed = 0
        self._misses: List[str] = []
        if os.path.exists(path):
            self._load()
        elif mode == MODE_REPLAY:
            raise CassetteError(
                f"cassette not found: {path}\n"
                "Replay mode performs no network activity, so it needs a recorded "
                "cassette. Record one with --mode record, or point --tender at a "
                "scenario that ships with one."
            )

    # -- persistence -----------------------------------------------------

    def _load(self) -> None:
        with open(self.path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        if not isinstance(raw, dict) or "entries" not in raw:
            raise CassetteError(
                f"{self.path} is not a Bayyina cassette (missing 'entries' key)"
            )
        for key, value in raw["entries"].items():
            if not isinstance(value, dict):
                continue
            self._entries[key] = value
        self.meta = raw.get("meta", {})

    def save(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        payload = {
            "meta": {
                "format": "bayyina-cassette/1",
                "note": (
                    "Recorded raw observations. Replaying this file performs no "
                    "network activity and reproduces the assessment exactly."
                ),
            },
            "entries": self._entries,
        }
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")

    # -- keying ----------------------------------------------------------

    @staticmethod
    def make_key(collector: str, kind: str, target: str, params: Optional[Dict] = None) -> str:
        base = {"collector": collector, "kind": kind, "target": target, "params": params or {}}
        return f"{collector}/{kind}/{target}/{content_hash(base)[:10]}"

    # -- the one method collectors call ----------------------------------

    def obtain(
        self,
        collector: str,
        kind: str,
        target: str,
        live_fn: Callable[[], Evidence],
        params: Optional[Dict] = None,
    ) -> Evidence:
        """Return evidence for (collector, kind, target), replaying if possible.

        ``live_fn`` is only invoked in record/auto mode when there is no
        recorded entry. In replay mode a miss becomes an UNOBSERVABLE evidence
        record rather than an exception, because a missing observation is a
        legitimate state of the world that the scoring model already handles —
        it lowers coverage and widens the score interval.
        """
        key = self.make_key(collector, kind, target, params)

        if key in self._entries:
            self._replayed += 1
            return Evidence.from_dict(self._entries[key])

        if self.mode == MODE_REPLAY:
            self._misses.append(key)
            return Evidence(
                collector=collector,
                kind=kind,
                target=target,
                status=EvidenceStatus.UNOBSERVABLE,
                observed_at="",
                source="cassette-miss",
                note=(
                    "No recorded observation for this check in replay mode. "
                    "Scored as unknown, not as a pass or a failure."
                ),
            )

        try:
            evidence = live_fn()
        except Exception as exc:  # noqa: BLE001 - a collector must never abort a run
            evidence = Evidence(
                collector=collector,
                kind=kind,
                target=target,
                status=EvidenceStatus.ERROR,
                source="live",
                note=f"{type(exc).__name__}: {exc}",
            )
        self._entries[key] = evidence.to_dict()
        self._recorded += 1
        return evidence

    # -- diagnostics -----------------------------------------------------

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "path": self.path,
            "entries": len(self._entries),
            "replayed": self._replayed,
            "recorded": self._recorded,
            "misses": len(self._misses),
        }

    def all_evidence(self) -> List[Evidence]:
        return [Evidence.from_dict(v) for v in self._entries.values()]
