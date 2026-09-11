"""Deterministic serialisation, hashing and small helpers.

Everything that ends up in the evidence ledger passes through ``canonical``
so that the same evidence always produces byte-identical bytes and therefore
byte-identical hashes. This is what makes "run it twice, get the same answer"
a property we can prove rather than a claim we make.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable

__all__ = [
    "canonical",
    "sha256_hex",
    "content_hash",
    "short_hash",
    "clamp",
    "slugify",
    "registrable_domain",
    "host_suffix_match",
    "dedupe",
]


def canonical(obj: Any) -> bytes:
    """RFC 8785-style canonical JSON (sorted keys, no insignificant space).

    We do not use RFC 8785 proper because it mandates a specific float
    serialisation we do not need; every numeric value we hash is either an
    int or a float rounded to 6 dp by the callers. Keys are sorted, so the
    output is independent of dict insertion order.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_default,
    ).encode("utf-8")


def _default(o: Any) -> Any:
    # dataclasses and enums serialise through their own to_dict/value.
    if hasattr(o, "to_dict"):
        return o.to_dict()
    if hasattr(o, "value"):
        return o.value
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    if isinstance(o, bytes):
        return o.hex()
    raise TypeError(f"not JSON-serialisable: {type(o).__name__}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_hash(obj: Any) -> str:
    """Stable hash of any JSON-able structure."""
    return sha256_hex(canonical(obj))


def short_hash(value: str, length: int = 12) -> str:
    return value[:length]


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    return _SLUG_RE.sub("-", text.strip().lower()).strip("-") or "item"


# A deliberately small public-suffix table. A full PSL would be more accurate
# but would add a dependency and a data file that drifts; for the suffixes a
# GCC government tender actually encounters this is sufficient, and anything
# it gets wrong degrades to "treat the last two labels as registrable", which
# is safe for our purposes (we only use this for grouping, never for scoring).
_MULTI_LABEL_SUFFIXES = {
    "ae": {"co", "net", "org", "gov", "ac", "sch", "mil"},
    "uk": {"co", "org", "gov", "ac", "net", "sch", "police", "nhs"},
    "sa": {"com", "net", "org", "gov", "edu", "sch", "med", "pub"},
    "qa": {"com", "net", "org", "gov", "edu", "mil", "sch"},
    "om": {"com", "net", "org", "gov", "edu", "med", "pro", "museum"},
    "bh": {"com", "net", "org", "gov", "edu", "biz", "info"},
    "kw": {"com", "net", "org", "gov", "edu"},
    "in": {"co", "net", "org", "gen", "firm", "ind", "gov", "ac", "edu", "res"},
    "au": {"com", "net", "org", "gov", "edu", "asn", "id"},
    "br": {"com", "net", "org", "gov", "edu"},
    "za": {"co", "net", "org", "gov", "ac", "web"},
    "jp": {"co", "ne", "or", "go", "ac", "ad", "ed", "gr", "lg"},
}


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1. Used only for grouping evidence, never for scoring."""
    host = (host or "").strip().strip(".").lower()
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    tld = labels[-1]
    second = labels[-2]
    if tld in _MULTI_LABEL_SUFFIXES and second in _MULTI_LABEL_SUFFIXES[tld]:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def host_suffix_match(host: str, suffix: str) -> bool:
    """True when ``host`` is ``suffix`` or a subdomain of it.

    Written explicitly rather than as ``host.endswith(suffix)`` because the
    naive version matches ``evil-google.com`` against ``google.com``.
    """
    host = (host or "").strip().strip(".").lower()
    suffix = (suffix or "").strip().strip(".").lower()
    if not host or not suffix:
        return False
    return host == suffix or host.endswith("." + suffix)


def dedupe(items: Iterable[str]) -> list:
    """Order-preserving de-duplication."""
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
