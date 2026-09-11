"""Bid-field concentration analysis.

The gap this fills
------------------
DORA Article 29 requires a financial entity to assess, before contracting for a
critical function, whether the arrangement creates non-substitutable dependence
on one provider or on several interconnected ones. That is a *portfolio*
question asked by one buyer about its own suppliers.

Government procurement has a question no regulator has systematised and no
commercial rating service answers: when several vendors bid for the same
contract, do they share upstream dependencies? A buyer that splits an award
across two bidders to avoid single-supplier risk, where both terminate TLS at
the same CDN and route mail through the same provider, has bought two invoices
and one failure domain. That correlation is invisible to any per-vendor
assessment, including every commercial security rating, because each is scored
alone.

Bayyina computes it across the bid field. Stated honestly: this is our
operationalisation of a qualitative regulatory concept, not compliance with a
standard. No regulator mandates a concentration metric and no threshold here
is normative — the numbers are there to make a pattern visible to a human, who
decides what it means for this contract.

What we can and cannot see: dependencies are inferred from name-server, mail
exchanger, edge/CDN fingerprints and certificate authority. That reaches the
providers a vendor's public service visibly depends on. It does not reach
sub-processors disclosed only contractually, which is why the generated
contract conditions ask for a sub-processor register rather than pretending we
derived one.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple

from .checks import EvidenceIndex
from .collectors.dns_email import mx_providers
from .models import EvidenceStatus, VendorAssessment
from .util import registrable_domain

# Response-header fingerprints for the major edge and CDN providers. These are
# the vendor-set headers those services add; they identify the edge, not the
# origin, which is the correct level for a shared-failure-domain question.
EDGE_FINGERPRINTS: Sequence[Tuple[str, str]] = (
    ("cf-ray", "Cloudflare"),
    ("cf-cache-status", "Cloudflare"),
    ("x-amz-cf-id", "Amazon CloudFront"),
    ("x-amz-cf-pop", "Amazon CloudFront"),
    ("x-azure-ref", "Azure Front Door"),
    ("x-msedge-ref", "Azure Front Door"),
    ("x-akamai-transformed", "Akamai"),
    ("akamai-grn", "Akamai"),
    ("x-served-by", "Fastly"),
    ("fastly-io-info", "Fastly"),
    ("x-goog-generation", "Google Cloud"),
    ("x-guploader-uploadid", "Google Cloud"),
)

SERVER_FINGERPRINTS: Sequence[Tuple[str, str]] = (
    ("cloudflare", "Cloudflare"),
    ("akamaighost", "Akamai"),
    ("awselb", "AWS Elastic Load Balancing"),
    ("amazons3", "Amazon S3"),
    ("microsoft-iis", "Microsoft IIS"),
    ("gws", "Google Web Server"),
)

DEPENDENCY_LABELS = {
    "dns_provider": "Authoritative DNS",
    "mail_provider": "Mail exchange",
    "edge_provider": "Edge / CDN",
    "certificate_authority": "Certificate authority",
}


def extract_dependencies(index: EvidenceIndex) -> Dict[str, List[str]]:
    """Derive one vendor's visible upstream dependencies from its evidence."""
    dependencies: Dict[str, List[str]] = {
        "dns_provider": [],
        "mail_provider": [],
        "edge_provider": [],
        "certificate_authority": [],
    }

    ns = index.data("ns")
    if ns:
        providers = set()
        for record in ns.get("records", []):
            host = str(record).strip().strip(".").lower()
            if host:
                providers.add(registrable_domain(host))
        dependencies["dns_provider"] = sorted(providers)

    mx = index.data("mx")
    if mx:
        dependencies["mail_provider"] = mx_providers(mx.get("records", []))

    headers_evidence = index.get("headers")
    headers = index.data("headers")
    if headers:
        found = set()
        raw = headers.get("disclosure_headers") or {}
        server = str(raw.get("server", "")).lower()
        # Edge fingerprints are recorded by the collector under edge_headers
        # when present; fall back to the server banner.
        edge_headers = {k.lower() for k in (headers.get("edge_headers") or [])}
        for header, provider in EDGE_FINGERPRINTS:
            if header in edge_headers:
                found.add(provider)
        for needle, provider in SERVER_FINGERPRINTS:
            if needle in server.replace(" ", ""):
                found.add(provider)
        dependencies["edge_provider"] = sorted(found)

    tls_evidence = index.get("tls_config")
    tls = index.data("tls_config")
    if tls and tls_evidence and tls_evidence.status == EvidenceStatus.OBSERVED:
        issuer = (tls.get("certificate") or {}).get("issuer") or {}
        name = issuer.get("organizationName") or issuer.get("commonName")
        if name:
            dependencies["certificate_authority"] = [str(name)]

    return dependencies


def _herfindahl(shares: Sequence[float]) -> float:
    """Herfindahl-Hirschman index on provider shares within one dependency type.

    Reported on the 0-1 scale (1 = every bidder on one provider). Borrowed from
    competition economics because it rises faster when one provider dominates
    than a simple count of distinct providers does.

    The share denominator is *bidders*, not (provider, bidder) incidences. That
    distinction is not pedantic: a bidder listing four name servers across two
    registrable domains would otherwise be counted four times and would inflate
    the index on its own. Used descriptively; no threshold in this file is
    normative.
    """
    return round(sum(s * s for s in shares), 4)


def analyse(assessments: Sequence[VendorAssessment]) -> Dict[str, Any]:
    """Cross-vendor concentration analysis for one bid field."""
    vendors = [a.vendor.vendor_id for a in assessments]
    by_type: Dict[str, Dict[str, List[str]]] = {}

    for assessment in assessments:
        for dep_type, providers in (assessment.dependencies or {}).items():
            bucket = by_type.setdefault(dep_type, {})
            for provider in providers:
                bucket.setdefault(provider, []).append(assessment.vendor.vendor_id)

    shared: List[Dict[str, Any]] = []
    indices: Dict[str, Any] = {}
    for dep_type, providers in sorted(by_type.items()):
        uses = sum(len(set(v)) for v in providers.values())
        if uses:
            shares = [len(set(v)) / uses for v in providers.values()]
            indices[dep_type] = {
                "label": DEPENDENCY_LABELS.get(dep_type, dep_type),
                "distinct_providers": len(providers),
                "hhi": _herfindahl(shares),
                "vendors_covered": len({v for lst in providers.values() for v in lst}),
            }
        for provider, users in sorted(providers.items()):
            if len(set(users)) > 1:
                shared.append(
                    {
                        "dependency_type": dep_type,
                        "label": DEPENDENCY_LABELS.get(dep_type, dep_type),
                        "provider": provider,
                        "vendors": sorted(set(users)),
                        "share_of_field": round(len(set(users)) / max(len(vendors), 1), 4),
                    }
                )

    # Pairwise overlap: how much of two bidders' visible dependency sets is the
    # same, as a Jaccard index. Jaccard is bounded, symmetric in its arguments,
    # and penalises non-overlap on both sides — which is what we want when the
    # question is "would splitting the award between these two produce
    # independent failure domains?".
    #
    # It is NOT insensitive to set-size asymmetry, and that matters here: a
    # bidder whose TLS we could not observe contributes no certificate-authority
    # entry, which shrinks every union it appears in and moves its Jaccard
    # scores relative to a fully-observed bidder. So the coefficient is reported
    # alongside the explicit list of shared dependency *types*, and it is the
    # type count — not the coefficient — that triggers the warning below.
    pairs: List[Dict[str, Any]] = []
    for i, a in enumerate(assessments):
        set_a = {f"{t}:{p}" for t, ps in (a.dependencies or {}).items() for p in ps}
        for b in assessments[i + 1:]:
            set_b = {f"{t}:{p}" for t, ps in (b.dependencies or {}).items() for p in ps}
            union = set_a | set_b
            overlap = set_a & set_b
            jaccard = round(len(overlap) / len(union), 4) if union else 0.0
            shared_types = sorted({item.split(":", 1)[0] for item in overlap})
            pairs.append(
                {
                    "a": a.vendor.vendor_id,
                    "b": b.vendor.vendor_id,
                    "jaccard": jaccard,
                    "shared": sorted(overlap),
                    "shared_types": shared_types,
                    # A reporting trigger, not a norm: two or more shared
                    # dependency types is the pattern that defeats a split
                    # award, so it is surfaced to a human. No regulator
                    # prescribes a threshold and this one claims no authority.
                    "diversification_warning": len(shared_types) >= 2,
                    "warning_basis": "two or more shared dependency types (reporting trigger, not a standard)",
                }
            )

    warnings = [p for p in pairs if p["diversification_warning"]]
    return {
        "vendors": vendors,
        "shared_dependencies": shared,
        "indices": indices,
        "pairs": pairs,
        "diversification_warnings": warnings,
        "summary": _summarise(shared, warnings, len(vendors)),
        "method": (
            "Upstream dependencies inferred from NS, MX, edge/CDN response fingerprints and certificate "
            "issuer. HHI is computed per dependency type over provider shares across the bid field. "
            "Descriptive only: no regulator mandates a concentration metric, and no threshold here is normative. "
            "Contractual sub-processors are not visible externally and are requested as a contract condition."
        ),
        "basis": "Operationalises the DORA Article 29 concentration concept across a bid field rather than a portfolio.",
    }


def _summarise(shared: List[Dict], warnings: List[Dict], vendor_count: int) -> str:
    if not shared:
        return (
            f"No upstream provider is shared between the {vendor_count} bidders on the evidence available. "
            "A split award would not obviously concentrate risk."
        )
    lines = []
    universal = [s for s in shared if s["share_of_field"] >= 0.999]
    if universal:
        names = ", ".join(f"{s['provider']} ({s['label'].lower()})" for s in universal[:3])
        lines.append(
            f"All {vendor_count} bidders depend on the same provider for at least one function: {names}. "
            "No award allocation among these bidders removes that dependency."
        )
    if warnings:
        for warning in warnings[:3]:
            types = ", ".join(DEPENDENCY_LABELS.get(t, t).lower() for t in warning["shared_types"])
            lines.append(
                f"{warning['a']} and {warning['b']} share {types}. Splitting the award between these two "
                "would not produce independent failure domains."
            )
    if not lines:
        lines.append(
            f"{len(shared)} upstream provider(s) are shared between some bidders, but no pair shares two or "
            "more dependency types."
        )
    return " ".join(lines)
