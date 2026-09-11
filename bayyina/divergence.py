"""Attestation divergence — testing what a vendor claimed against what we observed.

The idea
--------
A security questionnaire is a set of assertions about the world, signed by the
bidder. Most procurement treats it as a document to be filed. Treat it instead
as a set of hypotheses, and a subset of them become externally testable: a
vendor that answered "we enforce DMARC" has made a claim that a single DNS
lookup can refute.

That reframing does two things.

First, a contradiction is a more serious finding than the underlying control
gap. A missing DMARC record is a hygiene weakness. A *claim* of DMARC
enforcement with no DMARC record published is an accuracy failure in a document
the bidder signed and the buyer is relying on — and it is evidence about the
bidder's assurance process, not just about its mail configuration.

Second, and this is the part that carries the whole method: the testable claims
are a *sample*. Most of a questionnaire cannot be checked from outside — you
cannot externally observe background screening, or key management, or whether
backups are actually restored. But if a bidder's externally testable claims are
corroborated 8 times out of 10, that is a measurement of how much weight the
buyer should place on the 200 claims that cannot be tested. Bayyina reports
that as an interval, with its assumptions stated, rather than as a score.

The honest limitation, stated in the output as well as here: the testable
claims are not a random sample of all claims. They are the ones that happen to
be externally observable, which skews toward network and email configuration.
A vendor could be scrupulous about the testable set and careless elsewhere, or
the reverse. The reliability estimate is evidence for a reviewer to weigh, not
a substitute for one.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, List, Optional, Tuple

from .checks import EvidenceIndex
from .collectors.dns_email import parse_dmarc, parse_spf
from .collectors.tls_web import parse_cookies, parse_hsts, weak_protocols_offered
from .models import (
    Category,
    CheckOutcome,
    Claim,
    Divergence,
    DivergenceVerdict,
    Finding,
    Severity,
)
from .stats import wilson_interval

# A predicate returns (observed_value, human_readable_observation, digests),
# or None when nothing we observed bears on the claim.
PredicateResult = Optional[Tuple[bool, str, List[str]]]
Predicate = Callable[[EvidenceIndex], PredicateResult]

PREDICATES: Dict[str, Predicate] = {}


def predicate(name: str, description: str, severity: str = Severity.HIGH):
    def decorator(fn: Predicate) -> Predicate:
        fn.description = description  # type: ignore[attr-defined]
        fn.severity = severity        # type: ignore[attr-defined]
        PREDICATES[name] = fn
        return fn

    return decorator


def _clip(text: str, limit: int = 190) -> str:
    """Truncate on a word boundary. A scope statement cut mid-word reads as a bug."""
    text = " ".join(str(text or "").split())
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0].rstrip(",;:") + "\u2026"


def _digest(index: EvidenceIndex, kind: str) -> List[str]:
    evidence = index.get(kind)
    return [evidence.digest] if evidence and index.usable(evidence) else []


# ---------------------------------------------------------------------------
# Predicates: each is one externally testable assertion
# ---------------------------------------------------------------------------


@predicate("no_legacy_tls", "Deprecated TLS versions are disabled", Severity.HIGH)
def _no_legacy_tls(index: EvidenceIndex) -> PredicateResult:
    data = index.data("tls_config")
    if not data or not data.get("connected"):
        return None
    weak = weak_protocols_offered(data)
    if weak:
        return (False, f"{', '.join(weak)} accepted on {index.primary_domain}", _digest(index, "tls_config"))
    return (True, "only TLS 1.2+ accepted", _digest(index, "tls_config"))


@predicate("tls13_supported", "TLS 1.3 is supported", Severity.LOW)
def _tls13(index: EvidenceIndex) -> PredicateResult:
    data = index.data("tls_config")
    if not data or not data.get("connected"):
        return None
    offered = bool(((data.get("protocols") or {}).get("TLSv1.3") or {}).get("offered"))
    return (offered, "TLS 1.3 offered" if offered else "TLS 1.3 not offered", _digest(index, "tls_config"))


@predicate("dmarc_enforced", "DMARC is published at an enforcing policy", Severity.HIGH)
def _dmarc(index: EvidenceIndex) -> PredicateResult:
    data = index.data("dmarc")
    if data is None:
        return None
    records = data.get("records") or []
    if not records:
        return (False, "no DMARC record published", _digest(index, "dmarc"))
    parsed = parse_dmarc(records[0])
    if parsed["enforcing"]:
        return (True, f"DMARC p={parsed['policy']} at pct=100", _digest(index, "dmarc"))
    return (
        False,
        f"DMARC published at p={parsed['policy'] or 'none'}"
        + (f" pct={parsed['pct']}" if parsed["pct"] != 100 else "")
        + " — monitoring only, blocks nothing",
        _digest(index, "dmarc"),
    )


@predicate("spf_enforced", "SPF is published and enforcing", Severity.MEDIUM)
def _spf(index: EvidenceIndex) -> PredicateResult:
    data = index.data("spf")
    if data is None:
        return None
    records = data.get("records") or []
    if not records:
        return (False, "no SPF record published", _digest(index, "spf"))
    parsed = parse_spf(records[0])
    if parsed["over_lookup_limit"]:
        return (False, f"SPF exceeds the RFC 7208 10-lookup limit ({parsed['dns_lookups']}); receivers ignore it",
                _digest(index, "spf"))
    return (parsed["enforcing"], f"SPF terminates in {parsed['terminator'] or 'no all mechanism'}", _digest(index, "spf"))


@predicate("hsts_enforced", "HSTS is enforced", Severity.MEDIUM)
def _hsts(index: EvidenceIndex) -> PredicateResult:
    data = index.data("headers")
    if data is None:
        return None
    hsts = parse_hsts((data.get("security_headers") or {}).get("strict-transport-security", ""))
    if not hsts["present"]:
        return (False, "no Strict-Transport-Security header served", _digest(index, "headers"))
    return (hsts["adequate"], f"HSTS max-age={hsts['max_age']}", _digest(index, "headers"))


@predicate("csp_deployed", "A Content-Security-Policy is enforced", Severity.MEDIUM)
def _csp(index: EvidenceIndex) -> PredicateResult:
    data = index.data("headers")
    if data is None:
        return None
    csp = (data.get("security_headers") or {}).get("content-security-policy", "")
    if not csp:
        return (False, "no Content-Security-Policy header served", _digest(index, "headers"))
    weak = "unsafe-inline" in csp or "unsafe-eval" in csp
    return (not weak, "CSP served" + (" but permits unsafe-inline/unsafe-eval" if weak else ""), _digest(index, "headers"))


@predicate("dnssec_enabled", "The DNS zone is DNSSEC-signed", Severity.LOW)
def _dnssec(index: EvidenceIndex) -> PredicateResult:
    data = index.data("dnssec")
    if data is None:
        return None
    signed = bool(data.get("records"))
    return (signed, "DS record present" if signed else "no DS record at the parent zone", _digest(index, "dnssec"))


@predicate("caa_published", "CAA records restrict certificate issuance", Severity.LOW)
def _caa(index: EvidenceIndex) -> PredicateResult:
    data = index.data("caa")
    if data is None:
        return None
    present = bool(data.get("records"))
    return (present, "CAA records published" if present else "no CAA records", _digest(index, "caa"))


@predicate("mta_sts_enabled", "MTA-STS protects inbound mail", Severity.LOW)
def _mta_sts(index: EvidenceIndex) -> PredicateResult:
    data = index.data("mta_sts")
    if data is None:
        return None
    present = bool(data.get("records"))
    return (present, "MTA-STS policy published" if present else "no MTA-STS policy", _digest(index, "mta_sts"))


@predicate("cookies_hardened", "Session cookies carry protective attributes", Severity.MEDIUM)
def _cookies(index: EvidenceIndex) -> PredicateResult:
    data = index.data("headers")
    if data is None:
        return None
    cookies = parse_cookies(data.get("set_cookie", ""))
    if cookies["count"] == 0:
        return None
    if cookies["all_secure"]:
        return (True, "all observed cookies carry Secure, HttpOnly and SameSite", _digest(index, "headers"))
    names = ", ".join(c["name"] for c in cookies["insecure"][:3])
    return (False, f"cookies missing protective attributes: {names}", _digest(index, "headers"))


@predicate("no_version_disclosure", "Software versions are not disclosed in responses", Severity.MEDIUM)
def _version_disclosure(index: EvidenceIndex) -> PredicateResult:
    data = index.data("headers")
    if data is None:
        return None
    disclosed = data.get("disclosure_headers") or {}
    versioned = {k: v for k, v in disclosed.items() if any(ch.isdigit() for ch in str(v))}
    if versioned:
        detail = ", ".join(f"{k}: {v}" for k, v in list(versioned.items())[:2])
        return (False, f"version disclosed in response headers ({detail})", _digest(index, "headers"))
    return (True, "no version disclosure in response headers", _digest(index, "headers"))


@predicate("vuln_disclosure_published", "A vulnerability disclosure contact is published", Severity.MEDIUM)
def _vdp(index: EvidenceIndex) -> PredicateResult:
    data = index.data("security_txt")
    if data is None:
        return None
    present = bool(data.get("present"))
    return (present, "security.txt published" if present else "no security.txt published", _digest(index, "security_txt"))


@predicate("no_public_breach_36m", "No security incident disclosed in the last 36 months", Severity.HIGH)
def _no_breach(index: EvidenceIndex) -> PredicateResult:
    import datetime as dt

    evidence = index.get("history")
    data = index.data("history")
    if data is None or not evidence:
        return None
    as_of = evidence.observed_at[:10]
    if not as_of:
        return None
    recent = []
    for entry in data.get("incidents", []):
        raw = str(entry.get("date") or "")[:10]
        try:
            age = (dt.date.fromisoformat(as_of) - dt.date.fromisoformat(raw)).days
        except ValueError:
            continue
        if age <= 1095:
            recent.append(entry)
    if recent:
        titles = ", ".join(str(e.get("title", "incident")) for e in recent[:2])
        return (False, f"{len(recent)} disclosed incident(s) in the last 36 months ({titles})", _digest(index, "history"))
    return (True, "no disclosed incident in the last 36 months", _digest(index, "history"))


@predicate("no_subprocessor_incident", "No incident originated with a sub-processor", Severity.HIGH)
def _no_subprocessor_incident(index: EvidenceIndex) -> PredicateResult:
    data = index.data("history")
    if data is None:
        return None
    incidents = data.get("incidents", [])
    if not incidents:
        return None
    downstream = [i for i in incidents if i.get("third_party_origin")]
    if downstream:
        names = ", ".join(str(i.get("third_party_name", "a supplier")) for i in downstream[:2])
        return (False, f"{len(downstream)} incident(s) originated with a sub-processor ({names})", _digest(index, "history"))
    return (True, "no recorded incident originated with a sub-processor", _digest(index, "history"))


@predicate("no_admin_services_exposed", "No administrative or database service is internet-facing", Severity.HIGH)
def _no_admin_services(index: EvidenceIndex) -> PredicateResult:
    data = index.data("exposed_services")
    if data is None:
        return None
    high_risk = data.get("high_risk") or []
    if high_risk:
        detail = ", ".join(
            f"{s.get('port')} {s.get('risk_label') or s.get('service', '')}".strip()
            for s in high_risk[:3]
        )
        return (False, f"reachable from the public internet: {detail}", _digest(index, "exposed_services"))
    return (True, "no administrative or database service reachable from the public internet",
            _digest(index, "exposed_services"))


@predicate("certification_scope_covers_delivery", "Certification scope covers the delivering entity", Severity.HIGH)
def _cert_scope(index: EvidenceIndex) -> PredicateResult:
    data = index.data("certifications")
    if data is None:
        return None
    claims = data.get("claims") or []
    flagged = [c for c in claims if c.get("covers_delivery_entity") is False]
    # Scope adequacy is not machine-derivable and this tool does not pretend
    # otherwise. What is recorded here is a *reviewer's determination*, supplied
    # by the buyer in the tender file. The value of testing it is that the
    # bidder also asserted something about its own scope, and the two can
    # disagree. The wording below says whose judgement this is, because a
    # report that renders it as "observed" would imply the tool parsed the
    # certificate, which it did not.
    if flagged:
        scopes = "; ".join(_clip(c.get("scope_statement")) for c in flagged[:1])
        return (False,
                "reviewer determination recorded in the tender file: certification scope excludes the "
                f"delivering entity — the scope statement reads: \"{scopes}\"",
                _digest(index, "certifications"))
    stated = [c for c in claims if c.get("covers_delivery_entity") is True]
    if stated:
        return (True,
                "reviewer determination recorded in the tender file: scope covers the delivering entity",
                _digest(index, "certifications"))
    return None


# ---------------------------------------------------------------------------
# Questionnaire loading
# ---------------------------------------------------------------------------


def load_questionnaire(path: str) -> Tuple[List[Claim], List[str]]:
    """Load a questionnaire into structured claims.

    The format is intentionally close to a CAIQ export: a control reference,
    the question text, the vendor's answer, and — the part that makes it
    testable — a named predicate plus the value the vendor asserted.

    Malformed input degrades safely rather than aborting the run, and the
    failure is returned as a warning rather than swallowed. The safe direction
    is important: a bidder whose questionnaire cannot be parsed ends up with no
    testable claims, which collapses its evidence coverage and makes it
    unrankable. Failing to parse a submission must never look like passing it.
    """
    warnings: List[str] = []
    if not path:
        return [], warnings
    if not os.path.exists(path):
        return [], [f"questionnaire not found: {os.path.basename(path)}"]
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        return [], [f"questionnaire {os.path.basename(path)} could not be parsed ({type(exc).__name__}); "
                    "no attestation could be tested for this bidder"]
    if not isinstance(raw, dict):
        return [], [f"questionnaire {os.path.basename(path)} is not an object"]
    responses = raw.get("responses")
    if not isinstance(responses, list):
        return [], [f"questionnaire {os.path.basename(path)} has no 'responses' list"]

    claims: List[Claim] = []
    for index, entry in enumerate(responses):
        if not isinstance(entry, dict):
            warnings.append(f"questionnaire response {index + 1} is not an object; skipped")
            continue
        assertion = entry.get("assertion")
        if not isinstance(assertion, dict):
            assertion = {}
        claims.append(
            Claim(
                claim_id=entry.get("id") or f"Q{index + 1:03d}",
                control_ref=entry.get("control_ref", ""),
                text=entry.get("question", ""),
                assertion={
                    "predicate": assertion.get("predicate", ""),
                    "value": assertion.get("value"),
                    "answer": entry.get("answer", ""),
                },
                source_document=str(raw.get("document", os.path.basename(path))),
            )
        )
    return claims, warnings


# ---------------------------------------------------------------------------
# The divergence engine
# ---------------------------------------------------------------------------


def evaluate(claims: List[Claim], index: EvidenceIndex) -> List[Divergence]:
    """Test every claim that has a registered predicate against the evidence."""
    results: List[Divergence] = []
    for claim in claims:
        name = claim.assertion.get("predicate", "")
        asserted = claim.assertion.get("value")
        fn = PREDICATES.get(name)
        if fn is None or asserted is None:
            results.append(
                Divergence(
                    claim_id=claim.claim_id,
                    control_ref=claim.control_ref,
                    claim_text=claim.text,
                    verdict=DivergenceVerdict.UNTESTABLE,
                    expected=str(claim.assertion.get("answer", "")),
                    observed="no externally observable evidence bears on this claim",
                    severity=Severity.INFO,
                )
            )
            continue
        outcome = fn(index)
        if outcome is None:
            results.append(
                Divergence(
                    claim_id=claim.claim_id,
                    control_ref=claim.control_ref,
                    claim_text=claim.text,
                    verdict=DivergenceVerdict.UNTESTABLE,
                    expected=f"{name} = {asserted}",
                    observed="the relevant evidence could not be observed in this assessment",
                    severity=Severity.INFO,
                    check_ids=[name],
                )
            )
            continue
        observed_value, description, digests = outcome
        contradicted = bool(asserted) != bool(observed_value)
        # A claimed control that is absent is a contradiction. A control the
        # vendor did *not* claim but which we observed working is not a
        # problem — we record it as corroborating, noting the understatement.
        if contradicted and not asserted and observed_value:
            contradicted = False
            description += " (vendor understated its own posture)"
        results.append(
            Divergence(
                claim_id=claim.claim_id,
                control_ref=claim.control_ref,
                claim_text=claim.text,
                verdict=DivergenceVerdict.CONTRADICTED if contradicted else DivergenceVerdict.CORROBORATED,
                expected=f"{getattr(fn, 'description', name)} = {asserted}",
                observed=description,
                severity=getattr(fn, "severity", Severity.MEDIUM) if contradicted else Severity.INFO,
                check_ids=[name],
                evidence_digests=digests,
            )
        )
    return results


# Contradicting a signed attestation is weighted above the underlying control
# gap: it is evidence about the reliability of the bidder's whole submission.
_DIVERGENCE_WEIGHT = {
    Severity.CRITICAL: 4.0,
    Severity.HIGH: 3.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 1.0,
    Severity.INFO: 1.0,
}


def to_findings(divergences: List[Divergence]) -> List[Finding]:
    """Turn divergences into scored findings in the divergence category."""
    findings: List[Finding] = []
    for item in divergences:
        if item.verdict == DivergenceVerdict.UNTESTABLE:
            # Untestable claims are not scored. They are the population the
            # reliability estimate below is *about*, and scoring them would
            # double-count the same uncertainty.
            continue
        contradicted = item.verdict == DivergenceVerdict.CONTRADICTED
        findings.append(
            Finding(
                check_id=f"DIV-{item.claim_id}",
                title=f"Attestation {item.control_ref or item.claim_id}: {item.claim_text[:90]}",
                category=Category.DIVERGENCE,
                weight=_DIVERGENCE_WEIGHT.get(item.severity, 2.0) if contradicted else 2.0,
                outcome=CheckOutcome.FAIL if contradicted else CheckOutcome.PASS,
                severity=item.severity,
                score=0.0 if contradicted else 1.0,
                observation=(
                    f"Bidder attested: {item.expected}. Observed: {item.observed}."
                    if contradicted
                    else f"Attestation corroborated by observation: {item.observed}."
                ),
                remediation=(
                    "Require the bidder to correct the questionnaire response or remediate the control "
                    "before award, and re-run this check as the acceptance test."
                    if contradicted
                    else ""
                ),
                references=["CSA CAIQ v4", "ISO/IEC 27001:2022 A.5.19", "UAE National Cloud Security Policy"],
                evidence_digests=item.evidence_digests,
            )
        )
    return findings


def unusable_submission_finding(vendor_id: str, reason: str) -> Finding:
    """A declared questionnaire that yielded no testable claim is a bid defect.

    This closes a hole that inverted the tool's safety property. Previously an
    unparseable questionnaire simply produced no divergence findings, which
    left the divergence category empty — and an empty category is scored as
    *unknown*, so the bidder's upper bound rose and its adverse findings
    disappeared. Submitting a corrupt questionnaire was therefore a dominant
    strategy for a bidder facing demotion: it bought a wider interval and, under
    a dominance rule, a wider interval is exactly what defeats being outranked.

    A submission that cannot be read is not missing evidence about the world.
    It is a defect in the bid, and it is scored as one.
    """
    return Finding(
        check_id="DIV-SUBMISSION",
        title="The submitted questionnaire could not be used",
        category=Category.DIVERGENCE,
        weight=8.0,
        outcome=CheckOutcome.FAIL,
        severity=Severity.HIGH,
        score=0.0,
        observation=(
            f"A questionnaire was declared for this bidder but yielded no testable attestation. {reason} "
            "This is scored as a failure rather than as missing evidence: an unreadable submission is a "
            "defect in the bid, and treating it as an unknown would reward it with a wider score interval."
        ),
        remediation=(
            "Require the bidder to resubmit a readable questionnaire before award, and re-run the "
            "assessment against it."
        ),
        references=["UAE Federal Law No. 11 of 2023 Art. 24(1) (exclusion for failure to meet minimum requirements)"],
    )


def reliability(divergences: List[Divergence]) -> Dict[str, Any]:
    """Estimate how far a bidder's untestable attestations can be relied on.

    The estimator is the proportion of *testable* claims that survived contact
    with evidence, reported as a Wilson score interval. The interval is what
    makes it honest: with 11 testable claims, a single contradiction moves the
    point estimate a lot and the interval barely at all, and the reader can see
    that.
    """
    testable = [d for d in divergences if d.verdict != DivergenceVerdict.UNTESTABLE]
    corroborated = [d for d in testable if d.verdict == DivergenceVerdict.CORROBORATED]
    contradicted = [d for d in testable if d.verdict == DivergenceVerdict.CONTRADICTED]
    untestable = [d for d in divergences if d.verdict == DivergenceVerdict.UNTESTABLE]

    # The claims are NOT independent trials, and pretending otherwise would
    # understate the very uncertainty this tool exists to report honestly.
    # Three of a bidder's contradictions can be read out of a single HTTP
    # response; SPF and DMARC reflect one mail-configuration decision. So we
    # cluster the claims by the evidence record each was tested against and
    # report a second, conservative interval over clusters, where a cluster
    # counts as corroborated only if every claim resting on it survived.
    #
    # Cluster-level is the interval we lead with. It is wider, and it is the
    # one that survives the obvious statistical objection.
    clusters: Dict[str, List[Divergence]] = {}
    for item in testable:
        key = "|".join(sorted(item.evidence_digests)) or f"unclustered:{item.claim_id}"
        clusters.setdefault(key, []).append(item)
    clean_clusters = [
        k for k, items in clusters.items()
        if all(i.verdict == DivergenceVerdict.CORROBORATED for i in items)
    ]

    claim_point, claim_lower, claim_upper = wilson_interval(len(corroborated), len(testable))
    point, lower, upper = wilson_interval(len(clean_clusters), len(clusters))
    sizes = sorted((len(v) for v in clusters.values()), reverse=True)
    return {
        "claims_total": len(divergences),
        "claims_testable": len(testable),
        "claims_untestable": len(untestable),
        "corroborated": len(corroborated),
        "contradicted": len(contradicted),
        # Headline figures are cluster-level.
        "point": point,
        "ci_lower": lower,
        "ci_upper": upper,
        "evidence_clusters": len(clusters),
        "clusters_corroborated": len(clean_clusters),
        "largest_cluster": sizes[0] if sizes else 0,
        # Retained for comparison, and clearly labelled as the optimistic view.
        "claim_level_point": claim_point,
        "claim_level_ci_lower": claim_lower,
        "claim_level_ci_upper": claim_upper,
        "confidence": 0.95,
        "method": (
            "Wilson score interval on the proportion of independent evidence sources whose attestations "
            "were all corroborated. Claims are clustered by the evidence record they were tested against, "
            "because several claims can rest on one observation and treating them as independent trials "
            "would report an interval narrower than the evidence supports. The claim-level interval is "
            "reported alongside as the optimistic bound."
        ),
        "caveat": (
            "Two limitations, both material. Testable claims are not a random sample of all claims — they "
            "skew toward network and email configuration. And clustering by evidence record is a "
            "conservative approximation of the real dependence structure, not a measurement of it. This "
            "estimates the reliability of the bidder's attestation process, and is evidence for a reviewer "
            "to weigh, not a substitute for one."
        ),
    }
