"""Turning findings into contract conditions.

An assessment that ends in a score changes nothing. An assessment that ends in
drafted contract language changes what the supplier is obliged to do, and gives
the buyer a defined acceptance test for each obligation.

Three output classes, because they attach at different points in the process:

  * **Conditions precedent** — must be satisfied before award. Reserved for
    findings that go to the integrity of the bid itself: an expired or
    mis-scoped certificate, or an attestation the evidence contradicts.
  * **Contract conditions** — remediation obligations with a deadline and a
    named verification method, sized by severity.
  * **Information requests** — where the tool honestly cannot decide and a
    named human must, or where evidence coverage was too thin to conclude.

Every condition names the check that produced it, so re-running that check is
the acceptance test. That closes the loop that questionnaire-based assurance
leaves open: the answer becomes a testable obligation instead of a filed PDF.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

from .models import (
    Category,
    CheckOutcome,
    Divergence,
    DivergenceVerdict,
    Finding,
    Severity,
    VendorAssessment,
)

# Criticality of the contract shortens the remediation window.
CRITICALITY_FACTOR = {"HIGH": 0.5, "MEDIUM": 0.75, "LOW": 1.0}

CONDITION_PRECEDENT = "condition_precedent"
CONTRACT_CONDITION = "contract_condition"
INFORMATION_REQUEST = "information_request"


def _deadline_days(severity: str, criticality: str) -> int:
    base = Severity.REMEDIATION_DAYS.get(severity, 90)
    factor = CRITICALITY_FACTOR.get((criticality or "HIGH").upper(), 0.5)
    return max(7, int(round(base * factor)))


def _clause(finding: Finding, days: int) -> str:
    action = finding.remediation or "remediate the deficiency identified"
    action = action[0].lower() + action[1:] if action else action
    return (
        f"The Supplier shall, within {days} calendar days of the Commencement Date, {action} "
        f"The Authority shall verify closure by re-executing assessment check {finding.check_id}; "
        f"the check returning PASS against the Supplier's production endpoints is the acceptance criterion."
    )


def build(
    assessment: VendorAssessment,
    criticality: str = "HIGH",
    concentration: Dict[str, Any] | None = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Generate the condition set for one vendor."""
    precedents: List[Dict[str, Any]] = []
    conditions: List[Dict[str, Any]] = []
    requests: List[Dict[str, Any]] = []

    contradicted = [
        d for d in assessment.divergences if d.verdict == DivergenceVerdict.CONTRADICTED
    ]

    # 1. Contradicted attestations are conditions precedent. The issue is not
    #    only the control — it is that the buyer is relying on a document that
    #    the evidence shows to be inaccurate.
    for item in contradicted:
        precedents.append(
            {
                "id": f"CP-{item.claim_id}",
                "type": CONDITION_PRECEDENT,
                "severity": item.severity,
                "source_check": item.claim_id,
                "control_ref": item.control_ref,
                "title": f"Correct or remediate contradicted attestation {item.control_ref or item.claim_id}",
                "clause": (
                    f"Prior to award, the Supplier shall either (a) remediate the deficiency such that the "
                    f"attestation it submitted becomes accurate, or (b) submit a corrected response to "
                    f"{item.control_ref or 'the questionnaire item'} and confirm in writing that its remaining "
                    f"responses have been re-verified. The Supplier attested: {item.expected}. The Authority "
                    f"observed: {item.observed}."
                ),
                "verification": f"Re-execution of predicate {', '.join(item.check_ids) or item.claim_id}",
            }
        )

    # 2. Failed and partial checks become dated remediation obligations.
    for finding in assessment.findings:
        if finding.category == Category.DIVERGENCE:
            continue  # handled above, to avoid duplicating the same obligation
        if finding.outcome in (CheckOutcome.FAIL, CheckOutcome.PARTIAL) and finding.remediation:
            severity = finding.severity
            days = _deadline_days(severity, criticality)
            target = precedents if severity == Severity.CRITICAL else conditions
            target.append(
                {
                    "id": f"CC-{finding.check_id}",
                    "type": CONDITION_PRECEDENT if severity == Severity.CRITICAL else CONTRACT_CONDITION,
                    "severity": severity,
                    "source_check": finding.check_id,
                    "title": finding.title,
                    "finding": finding.observation,
                    "deadline_days": days,
                    "clause": _clause(finding, days),
                    "verification": f"Re-execution of check {finding.check_id}",
                    "references": finding.references,
                }
            )

    # 3. Anything the tool refused to decide becomes an information request
    #    with a named human owner, not a silent pass.
    for finding in assessment.findings:
        if finding.outcome == CheckOutcome.NEEDS_HUMAN:
            requests.append(
                {
                    "id": f"IR-{finding.check_id}",
                    "type": INFORMATION_REQUEST,
                    "severity": finding.severity,
                    "source_check": finding.check_id,
                    "title": finding.title,
                    "reason": finding.observation,
                    "request": finding.remediation
                    or "Provide the supporting documentation required to close this item.",
                    "owner": "Named technical evaluator (to be assigned by the Authority)",
                    "stage": "Pre-award",
                }
            )
        elif finding.outcome == CheckOutcome.UNKNOWN:
            requests.append(
                {
                    "id": f"IR-{finding.check_id}",
                    "type": INFORMATION_REQUEST,
                    "severity": Severity.LOW,
                    "source_check": finding.check_id,
                    "title": finding.title,
                    "reason": finding.observation
                    or "No evidence was observable for this control.",
                    "request": (
                        "Supplier to provide evidence for this control, or to confirm the in-scope endpoints "
                        "against which the Authority may re-run the check."
                    ),
                    "owner": "Procurement technical evaluator",
                    "stage": "Pre-award",
                }
            )

    # 4. Sub-processor transparency. External assessment cannot see contractual
    #    sub-processors, so we ask for them rather than implying we found them.
    conditions.append(
        {
            "id": "CC-SUBPROC",
            "type": CONTRACT_CONDITION,
            "severity": Severity.HIGH,
            "source_check": "BRE-003",
            "title": "Sub-processor register and flow-down obligations",
            "finding": (
                "External assessment observes only the Supplier's own public estate. Sub-processors are "
                "visible contractually, not externally, and third-party involvement is the dominant breach "
                "archetype in DBIR 2026."
            ),
            "deadline_days": _deadline_days(Severity.HIGH, criticality),
            "clause": (
                "The Supplier shall maintain and provide to the Authority a register of all sub-processors "
                "and sub-contractors involved in delivering the Services, identifying the function supported "
                "and the processing location for each; shall flow down to each the security obligations of "
                "this Agreement; shall obtain the Authority's prior written approval before appointing any "
                "new sub-processor; and shall notify the Authority of any security incident affecting a "
                "sub-processor within the notification period specified in this Agreement."
            ),
            "verification": "Register delivered and reviewed; annual re-attestation",
            "references": [
                "DORA Art. 28 (register of information, sub-outsourcing chain)",
                "ISO/IEC 27001:2022 A.5.21",
                "UAE Federal Decree-Law 45/2021 Art. 8(10)",
            ],
        }
    )

    # 5. Concentration findings attach to the award decision, not to one vendor.
    if concentration:
        for warning in concentration.get("diversification_warnings", []):
            if assessment.vendor.vendor_id not in (warning["a"], warning["b"]):
                continue
            other = warning["b"] if warning["a"] == assessment.vendor.vendor_id else warning["a"]
            conditions.append(
                {
                    "id": f"CC-CONC-{other}",
                    "type": CONTRACT_CONDITION,
                    "severity": Severity.MEDIUM,
                    "source_check": "CONCENTRATION",
                    "title": f"Shared upstream dependency with {other}",
                    "finding": (
                        f"This bidder and {other} share {len(warning['shared_types'])} categories of upstream "
                        "dependency, so a split award between them would not create independent failure domains."
                    ),
                    "deadline_days": _deadline_days(Severity.MEDIUM, criticality),
                    "clause": (
                        "The Supplier shall disclose its material upstream service dependencies and shall notify "
                        "the Authority before making any change to them. Where the Authority has awarded related "
                        "contracts in reliance on supplier diversity, the Supplier shall maintain a documented "
                        "exit and migration plan with a transition assistance period of not less than 12 months."
                    ),
                    "verification": "Dependency disclosure and exit plan reviewed at contract signature and annually",
                    "references": ["DORA Art. 29 (ICT concentration risk)", "DORA Art. 30(3) (exit strategies)"],
                }
            )

    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    for bucket in (precedents, conditions, requests):
        bucket.sort(key=lambda c: (order.get(c.get("severity", Severity.INFO), 5), c["id"]))

    return {
        "conditions_precedent": precedents,
        "contract_conditions": conditions,
        "information_requests": requests,
    }


def summarise(conditions: Dict[str, List[Dict[str, Any]]]) -> str:
    counts = {k: len(v) for k, v in conditions.items()}
    parts = []
    if counts.get("conditions_precedent"):
        parts.append(f"{counts['conditions_precedent']} condition(s) precedent to award")
    if counts.get("contract_conditions"):
        parts.append(f"{counts['contract_conditions']} dated contract condition(s)")
    if counts.get("information_requests"):
        parts.append(f"{counts['information_requests']} information request(s)")
    return "; ".join(parts) if parts else "No conditions generated."
