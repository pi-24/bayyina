"""The check registry.

A *check* is a pure function from evidence to a finding. It has a stable id, a
fixed weight, a severity, and a list of external references justifying why the
control is a control at all. Purity matters: given the same evidence a check
must always produce the same finding, which is what makes a replayed
assessment byte-identical to the run it replays.

A check may return ``UNKNOWN``. That is not a failure of the check, it is a
statement about the evidence, and the scoring model treats it as such: the
check drops out of the point estimate and widens the score interval instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..models import CheckOutcome, Evidence, EvidenceStatus, Finding, Severity, Vendor

__all__ = [
    "CheckContext",
    "CheckResult",
    "CheckSpec",
    "register",
    "REGISTRY",
    "run_checks",
    "EvidenceIndex",
]


class EvidenceIndex:
    """Lookup over one vendor's evidence, keyed by (kind, target)."""

    def __init__(self, evidence: List[Evidence], primary_domain: str) -> None:
        self.primary_domain = primary_domain
        self._by_kind: Dict[str, List[Evidence]] = {}
        for item in evidence:
            self._by_kind.setdefault(item.kind, []).append(item)

    def get(self, kind: str, target: Optional[str] = None) -> Optional[Evidence]:
        items = self._by_kind.get(kind, [])
        target = target or self.primary_domain
        for item in items:
            if item.target == target or item.target.endswith("." + target):
                return item
        return items[0] if items else None

    def all(self, kind: str) -> List[Evidence]:
        return list(self._by_kind.get(kind, []))

    @staticmethod
    def usable(evidence: Optional[Evidence]) -> bool:
        """True only when we actually observed something we can stand behind."""
        return bool(evidence) and evidence.status == EvidenceStatus.OBSERVED

    def data(self, kind: str, target: Optional[str] = None) -> Optional[Dict[str, Any]]:
        item = self.get(kind, target)
        return item.data if self.usable(item) else None


@dataclass
class CheckContext:
    vendor: Vendor
    index: EvidenceIndex
    tender: Any = None
    extras: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckResult:
    outcome: str
    score: Optional[float] = None
    observation: str = ""
    remediation: str = ""
    evidence_digests: List[str] = field(default_factory=list)
    severity_override: Optional[str] = None


@dataclass
class CheckSpec:
    check_id: str
    title: str
    category: str
    weight: float
    severity: str
    references: List[str]
    fn: Callable[[CheckContext], CheckResult]


REGISTRY: Dict[str, CheckSpec] = {}


def register(
    check_id: str,
    title: str,
    category: str,
    weight: float,
    severity: str = Severity.MEDIUM,
    references: Optional[List[str]] = None,
):
    def decorator(fn: Callable[[CheckContext], CheckResult]) -> Callable:
        if check_id in REGISTRY:
            raise ValueError(f"duplicate check id: {check_id}")
        REGISTRY[check_id] = CheckSpec(
            check_id=check_id,
            title=title,
            category=category,
            weight=weight,
            severity=severity,
            references=references or [],
            fn=fn,
        )
        return fn

    return decorator


def unknown(reason: str) -> CheckResult:
    """The control applies but we could not observe it. Widens the interval."""
    return CheckResult(outcome=CheckOutcome.UNKNOWN, score=None, observation=reason)


def not_applicable(reason: str) -> CheckResult:
    """The control has nothing to bite on. Leaves the denominator entirely."""
    return CheckResult(outcome=CheckOutcome.NOT_APPLICABLE, score=None, observation=reason)


def run_checks(context: CheckContext) -> List[Finding]:
    """Execute every registered check against one vendor's evidence."""
    findings: List[Finding] = []
    for check_id in sorted(REGISTRY):
        spec = REGISTRY[check_id]
        try:
            result = spec.fn(context)
        except Exception as exc:  # noqa: BLE001 - one broken check must not void a run
            result = CheckResult(
                outcome=CheckOutcome.UNKNOWN,
                score=None,
                observation=f"check raised {type(exc).__name__}: {exc}",
            )
        findings.append(
            Finding(
                check_id=spec.check_id,
                title=spec.title,
                category=spec.category,
                weight=spec.weight,
                outcome=result.outcome,
                severity=result.severity_override or spec.severity,
                score=result.score,
                observation=result.observation,
                remediation=result.remediation,
                references=spec.references,
                evidence_digests=result.evidence_digests,
            )
        )
    return findings


# Importing the rules module populates REGISTRY as a side effect.
from . import rules  # noqa: E402,F401  isort:skip
