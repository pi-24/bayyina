"""The assessment pipeline.

One entry point, ``assess_tender``, which does the whole thing:

    load tender -> collect evidence (live or replayed) -> run checks
      -> test attestations against evidence -> score with bounds
      -> rank under uncertainty -> analyse the bid field -> draft conditions
      -> write an evidence ledger that verifies

The pipeline is identical in live and replay mode. Only the transport differs,
which is what makes the offline demonstration honest: the jury reproduces the
same analysis code that a live run executes.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import concentration as concentration_mod
from . import contract as contract_mod
from . import divergence as divergence_mod
from . import scoring
from .cassette import Cassette
from .checks import CheckContext, EvidenceIndex, run_checks
from .collectors import detect_shared_interception, gather
from .ledger import EvidenceLedger
from .models import DivergenceVerdict, Evidence, EvidenceStatus, Tender, Vendor, VendorAssessment
from .util import content_hash

# Below this share of observed weighted evidence, the point estimate is not
# worth reading and the report says so.
COVERAGE_WARNING_THRESHOLD = 2 / 3


@dataclass
class AssessmentRun:
    tender: Tender
    assessments: List[VendorAssessment] = field(default_factory=list)
    ranking: Dict[str, Any] = field(default_factory=dict)
    concentration: Dict[str, Any] = field(default_factory=dict)
    sensitivity: Dict[str, Any] = field(default_factory=dict)
    leave_one_out: List[Dict[str, Any]] = field(default_factory=list)
    reliability: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    conditions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    ledger: Optional[EvidenceLedger] = None
    cassette_stats: Dict[str, Any] = field(default_factory=dict)
    interception_detected: bool = False
    weights: Dict[str, float] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def vendor(self, vendor_id: str) -> Optional[VendorAssessment]:
        for assessment in self.assessments:
            if assessment.vendor.vendor_id == vendor_id:
                return assessment
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tender": self.tender.to_dict(),
            "weights": self.weights,
            "assessments": [a.to_dict() for a in self.assessments],
            "ranking": self.ranking,
            "concentration": self.concentration,
            "sensitivity": self.sensitivity,
            "leave_one_category_out": self.leave_one_out,
            "attestation_reliability": self.reliability,
            "contract_conditions": self.conditions,
            "evidence_ledger_head": self.ledger.head if self.ledger else "",
            "evidence_records": len(self.ledger) if self.ledger else 0,
            "cassette": self.cassette_stats,
            "interception_detected": self.interception_detected,
            "warnings": self.warnings,
        }


def load_tender(path: str) -> Tender:
    """Load a tender definition from a directory or a tender.json path."""
    if os.path.isdir(path):
        path = os.path.join(path, "tender.json")
    if not os.path.exists(path):
        raise FileNotFoundError(f"tender definition not found: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict) or "vendors" not in raw:
        raise ValueError(f"{path} is not a tender definition (no 'vendors' key)")
    return Tender.from_dict(raw)


def assess_tender(
    tender_path: str,
    mode: str = "replay",
    samples: int = 2000,
    seed: int = 20260911,
) -> AssessmentRun:
    tender_dir = tender_path if os.path.isdir(tender_path) else os.path.dirname(tender_path)
    tender = load_tender(tender_path)
    weight_problems = scoring.validate_weights(tender.weights)
    weights = scoring.normalise_weights(tender.weights)

    cassette = Cassette(os.path.join(tender_dir, "cassette.json"), mode=mode)
    breach_corpus = _optional(tender_dir, "breach_corpus.json")
    registry = _optional(tender_dir, "attestation_registry.json")
    exposure = _optional(tender_dir, "exposure_corpus.json")

    ledger = EvidenceLedger()
    raw_evidence: Dict[str, List[Evidence]] = {}
    assessments: List[VendorAssessment] = []
    warnings: List[str] = [f"tender weights: {problem}" for problem in weight_problems]

    seen_ids: Dict[str, int] = {}
    for vendor in tender.vendors:
        seen_ids[vendor.vendor_id] = seen_ids.get(vendor.vendor_id, 0) + 1
    for vendor_id, count in sorted(seen_ids.items()):
        if count > 1:
            # Two bidders sharing an id silently overwrite each other's
            # report file and appear twice in every table.
            warnings.append(
                f"vendor_id '{vendor_id}' appears {count} times in the tender; each bidder needs a "
                "unique id or their reports will overwrite one another"
            )

    for vendor in tender.vendors:
        if not vendor.primary_domain:
            warnings.append(
                f"{vendor.vendor_id}: no primary domain supplied; only submitted attestations "
                "can be assessed and no external evidence can be gathered."
            )

    for vendor in tender.vendors:
        evidence = gather(vendor, cassette, breach_corpus, registry, exposure)
        raw_evidence[vendor.vendor_id] = evidence

    interception = detect_shared_interception(raw_evidence)

    for vendor in tender.vendors:
        evidence = raw_evidence[vendor.vendor_id]
        if interception:
            evidence = [_mark_intercepted(e) for e in evidence]

        # The ledger is written in a deterministic order so that two runs over
        # the same cassette produce the same chain head.
        for item in sorted(evidence, key=lambda e: (e.collector, e.kind, e.target)):
            ledger.append("evidence", {"vendor": vendor.vendor_id, **item.to_dict()})

        index = EvidenceIndex(evidence, vendor.primary_domain)
        findings = run_checks(CheckContext(vendor=vendor, index=index, tender=tender))

        claims, claim_warnings = divergence_mod.load_questionnaire(
            os.path.join(tender_dir, vendor.questionnaire) if vendor.questionnaire else ""
        )
        warnings.extend(f"{vendor.vendor_id}: {w}" for w in claim_warnings)
        divergences = divergence_mod.evaluate(claims, index)
        findings.extend(divergence_mod.to_findings(divergences))

        if vendor.questionnaire and not any(
            d.verdict != DivergenceVerdict.UNTESTABLE for d in divergences
        ):
            # A questionnaire was required and none of it could be tested. That
            # is a defect in the submission, not an absence of evidence about
            # the world, and it is scored as a failure so that an unreadable
            # submission cannot buy a wider interval.
            reason = "; ".join(claim_warnings) or "No response carried a testable assertion."
            findings.append(divergence_mod.unusable_submission_finding(vendor.vendor_id, reason))
            warnings.append(
                f"{vendor.vendor_id}: the declared questionnaire produced no testable attestation; "
                "scored as a submission defect (DIV-SUBMISSION)."
            )
        elif not vendor.questionnaire:
            warnings.append(
                f"{vendor.vendor_id}: no questionnaire was submitted, so no attestation could be tested "
                "and this bidder's score interval is correspondingly wide."
            )

        categories, point, lower, upper, coverage = scoring.score_vendor(findings, weights)
        assessment = VendorAssessment(
            vendor=vendor,
            findings=sorted(findings, key=lambda f: f.check_id),
            divergences=divergences,
            categories=categories,
            point=point,
            lower=lower,
            upper=upper,
            coverage=coverage,
            evidence_count=len([e for e in evidence if e.status == EvidenceStatus.OBSERVED]),
            intercepted=interception,
            dependencies=concentration_mod.extract_dependencies(index),
        )
        # Two thirds is the line at which the point estimate stops resting on
        # most of the evidence. Below it, the number in the leftmost column is
        # the thing a reader will take away and the thing least supported, so
        # it is called out rather than left for them to notice.
        if assessment.coverage < COVERAGE_WARNING_THRESHOLD:
            warnings.append(
                f"{vendor.vendor_id}: only {assessment.coverage * 100:.0f}% of the weighted checks could be "
                f"observed, below the {COVERAGE_WARNING_THRESHOLD * 100:.0f}% threshold at which a point "
                "estimate is worth reading. Use the supported range and the information requests instead of "
                "the point score for this bidder."
            )
        assessments.append(assessment)

    run = AssessmentRun(
        tender=tender,
        assessments=assessments,
        weights=weights,
        ledger=ledger,
        cassette_stats=cassette.stats,
        interception_detected=interception,
        warnings=warnings,
    )
    run.ranking = scoring.rank(assessments)
    run.concentration = concentration_mod.analyse(assessments)
    run.sensitivity = scoring.weight_sensitivity(assessments, weights, samples=samples, seed=seed)
    run.leave_one_out = scoring.leave_one_category_out(assessments, weights)
    run.reliability = {
        a.vendor.vendor_id: divergence_mod.reliability(a.divergences) for a in assessments
    }
    run.conditions = {
        a.vendor.vendor_id: contract_mod.build(a, tender.criticality, run.concentration)
        for a in assessments
    }

    if mode in ("record", "auto"):
        cassette.save()
        run.cassette_stats = cassette.stats

    return run


def _optional(directory: str, filename: str) -> Optional[str]:
    path = os.path.join(directory, filename)
    return path if os.path.exists(path) else None


def _mark_intercepted(evidence: Evidence) -> Evidence:
    """Downgrade TLS evidence when the run detected a TLS-terminating middlebox."""
    if evidence.kind != "tls_config" or evidence.status != EvidenceStatus.OBSERVED:
        return evidence
    evidence.status = EvidenceStatus.INTERCEPTED
    evidence.note = (
        (evidence.note + " ") if evidence.note else ""
    ) + (
        "One certificate issuer was observed across three or more unrelated vendors in this run, "
        "which indicates the assessing network terminates TLS. Certificate and protocol findings "
        "are withheld rather than reported against the vendor."
    )
    return evidence


def write_outputs(run: AssessmentRun, out_dir: str) -> Dict[str, str]:
    """Persist the machine-readable bundle. Reports are written separately."""
    os.makedirs(out_dir, exist_ok=True)
    paths: Dict[str, str] = {}

    assessment_path = os.path.join(out_dir, "assessment.json")
    with open(assessment_path, "w", encoding="utf-8") as handle:
        json.dump(run.to_dict(), handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    paths["assessment"] = assessment_path

    if run.ledger:
        ledger_path = os.path.join(out_dir, "evidence-ledger.jsonl")
        run.ledger.write(ledger_path)
        paths["ledger"] = ledger_path

    # A short manifest is what a second run is compared against: same cassette
    # in, same digest out.
    manifest = {
        "tender_id": run.tender.tender_id,
        "weights": run.weights,
        "ledger_head": run.ledger.head if run.ledger else "",
        "evidence_records": len(run.ledger) if run.ledger else 0,
        "result_digest": content_hash(
            {
                "assessments": [
                    {
                        "vendor": a.vendor.vendor_id,
                        "point": a.point,
                        "lower": a.lower,
                        "upper": a.upper,
                        "coverage": a.coverage,
                        "findings": [(f.check_id, f.outcome, f.score) for f in a.findings],
                    }
                    for a in run.assessments
                ],
                "ranking": run.ranking,
            }
        ),
    }
    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    paths["manifest"] = manifest_path
    return paths
