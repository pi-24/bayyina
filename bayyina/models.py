"""Core data model.

The central design commitment is the three-state epistemics: every check is
either OBSERVED (we have evidence and can score it), UNOBSERVABLE (we tried
and could not see it — scored as *unknown*, never as a pass or a fail), or
NEEDS_HUMAN (machine cannot decide; a named human must). Nothing in this
codebase is permitted to silently convert an unknown into a number.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .util import content_hash

# --------------------------------------------------------------------------
# Enumerations (plain string constants — they serialise cleanly and read well
# in the JSON evidence bundle a bidder may be handed during an appeal)
# --------------------------------------------------------------------------


class EvidenceStatus:
    OBSERVED = "OBSERVED"
    UNOBSERVABLE = "UNOBSERVABLE"
    INTERCEPTED = "INTERCEPTED"  # a TLS-terminating middlebox invalidated the observation
    ERROR = "ERROR"

    ALL = (OBSERVED, UNOBSERVABLE, INTERCEPTED, ERROR)


class CheckOutcome:
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    # UNKNOWN and NOT_APPLICABLE are both unscored, and the difference between
    # them matters. UNKNOWN means the control applies but we could not observe
    # it, so it lowers coverage and widens the score interval. NOT_APPLICABLE
    # means there is nothing for the control to bite on — assessing incident
    # disclosure timeliness for a vendor with no incidents, say — so it leaves
    # the denominator entirely. Conflating the two would penalise a clean
    # vendor with uncertainty it did not earn.
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NEEDS_HUMAN = "NEEDS_HUMAN"

    ALL = (PASS, FAIL, PARTIAL, UNKNOWN, NOT_APPLICABLE, NEEDS_HUMAN)


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
    # Remediation windows used to generate contract conditions (calendar days).
    REMEDIATION_DAYS = {CRITICAL: 14, HIGH: 30, MEDIUM: 90, LOW: 180, INFO: 180}


class DivergenceVerdict:
    CORROBORATED = "CORROBORATED"   # the claim is supported by what we observed
    CONTRADICTED = "CONTRADICTED"   # the claim is refuted by what we observed
    UNTESTABLE = "UNTESTABLE"       # no externally observable evidence bears on it


class Category:
    DIVERGENCE = "attestation_divergence"
    HYGIENE = "technical_hygiene"
    BREACH = "breach_history"
    ATTESTATION = "attestation_integrity"
    SURFACE = "attack_surface"

    ALL = (DIVERGENCE, HYGIENE, BREACH, ATTESTATION, SURFACE)

    LABELS = {
        DIVERGENCE: "Attestation divergence",
        HYGIENE: "Technical hygiene",
        BREACH: "Breach & incident history",
        ATTESTATION: "Attestation integrity",
        SURFACE: "Attack surface & exposure",
    }


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------


@dataclass
class Evidence:
    """A single raw observation.

    ``data`` holds the unmodified observation (the DNS record, the response
    header block, the certificate fields). We keep it because UAE Federal Law
    11/2023 Art. 29 gives an unsuccessful bidder the right to be told the
    weaknesses of its bid, and a finding a bidder cannot inspect is a finding
    a bidder cannot rebut.
    """

    collector: str
    target: str
    kind: str
    status: str = EvidenceStatus.OBSERVED
    observed_at: str = ""          # ISO-8601 UTC; supplied by cassette, never by now()
    source: str = ""               # how it was obtained (URL, protocol, dataset id)
    data: Dict[str, Any] = field(default_factory=dict)
    note: str = ""

    @property
    def key(self) -> str:
        return f"{self.collector}:{self.kind}:{self.target}"

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Evidence":
        allowed = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in raw.items() if k in allowed})


@dataclass
class Finding:
    """The result of applying one check to the evidence for one vendor."""

    check_id: str
    title: str
    category: str
    weight: float
    outcome: str
    severity: str = Severity.INFO
    score: Optional[float] = None      # None means "not scored" — unknown, not zero
    observation: str = ""              # plain-language statement of what was seen
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    evidence_digests: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.score is not None:
            self.score = round(float(self.score), 6)
        self.weight = round(float(self.weight), 6)

    @property
    def is_scored(self) -> bool:
        return self.score is not None

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Claim:
    """A machine-testable assertion extracted from a vendor questionnaire.

    ``control_ref`` points at the questionnaire control the vendor answered
    (e.g. a CAIQ v4 control id) so that a divergence can be traced back to the
    exact line of the document the vendor signed.
    """

    claim_id: str
    control_ref: str
    text: str
    assertion: Dict[str, Any]        # structured predicate, e.g. {"no_legacy_tls": True}
    source_document: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Divergence:
    claim_id: str
    control_ref: str
    claim_text: str
    verdict: str
    expected: str
    observed: str
    severity: str = Severity.MEDIUM
    check_ids: List[str] = field(default_factory=list)
    evidence_digests: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Vendor:
    vendor_id: str
    legal_name: str
    primary_domain: str
    additional_domains: List[str] = field(default_factory=list)
    country: str = ""
    bid_reference: str = ""
    questionnaire: str = ""          # path, relative to the tender directory
    claimed_certifications: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def domains(self) -> List[str]:
        out = [self.primary_domain] + list(self.additional_domains)
        return [d for d in out if d]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Vendor":
        allowed = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in raw.items() if k in allowed})


@dataclass
class Tender:
    tender_id: str
    title: str
    buyer: str
    criticality: str = "HIGH"         # HIGH | MEDIUM | LOW — drives contract windows
    data_classification: str = ""
    description: str = ""
    vendors: List[Vendor] = field(default_factory=list)
    weights: Dict[str, float] = field(default_factory=dict)
    published_on: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out = dataclasses.asdict(self)
        return out

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Tender":
        vendors = [Vendor.from_dict(v) for v in raw.get("vendors", [])]
        allowed = {f.name for f in dataclasses.fields(cls)} - {"vendors"}
        kwargs = {k: v for k, v in raw.items() if k in allowed}
        return cls(vendors=vendors, **kwargs)


@dataclass
class CategoryScore:
    category: str
    weight: float
    point: Optional[float]   # mean over observed evidence only
    lower: float             # every unobserved check assumed worst case
    upper: float             # every unobserved check assumed best case
    coverage: float          # share of category weight actually observed
    scored_checks: int
    total_checks: int

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class VendorAssessment:
    vendor: Vendor
    findings: List[Finding] = field(default_factory=list)
    divergences: List[Divergence] = field(default_factory=list)
    categories: List[CategoryScore] = field(default_factory=list)
    point: Optional[float] = None
    lower: float = 0.0
    upper: float = 100.0
    coverage: float = 0.0
    evidence_count: int = 0
    intercepted: bool = False
    dependencies: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def interval_width(self) -> float:
        return round(self.upper - self.lower, 3)

    def findings_by_category(self, category: str) -> List[Finding]:
        return [f for f in self.findings if f.category == category]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vendor": self.vendor.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "divergences": [d.to_dict() for d in self.divergences],
            "categories": [c.to_dict() for c in self.categories],
            "point": self.point,
            "lower": self.lower,
            "upper": self.upper,
            "coverage": self.coverage,
            "evidence_count": self.evidence_count,
            "intercepted": self.intercepted,
            "dependencies": self.dependencies,
        }
