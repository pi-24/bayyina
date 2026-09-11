"""Collector orchestration.

``gather`` runs every collector for one vendor and returns the raw evidence.
It never scores anything — turning observations into findings is the job of
``bayyina.checks``, and keeping the two apart is what lets a bidder dispute a
*finding* while the underlying *observation* stays fixed.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..models import Evidence, EvidenceStatus, Vendor
from .dns_email import DnsEmailCollector
from .public_data import (
    AttestationCollector,
    BreachCollector,
    CertificateTransparencyCollector,
    ExposureCollector,
)
from .tls_web import HttpCollector, TlsCollector

__all__ = [
    "gather",
    "detect_shared_interception",
    "DnsEmailCollector",
    "TlsCollector",
    "HttpCollector",
    "CertificateTransparencyCollector",
    "BreachCollector",
    "ExposureCollector",
    "AttestationCollector",
]


def gather(
    vendor: Vendor,
    cassette,
    breach_corpus: Optional[str] = None,
    attestation_registry: Optional[str] = None,
    exposure_corpus: Optional[str] = None,
) -> List[Evidence]:
    """Collect all evidence for one vendor across all of its domains."""
    evidence: List[Evidence] = []
    dns = DnsEmailCollector()
    tls = TlsCollector()
    http = HttpCollector()
    ct = CertificateTransparencyCollector()
    breach = BreachCollector(breach_corpus)
    exposure = ExposureCollector(exposure_corpus)
    attestation = AttestationCollector(attestation_registry)

    for domain in vendor.domains:
        evidence.extend(dns.collect(domain, cassette))
        evidence.extend(tls.collect(domain, cassette))
        evidence.extend(http.collect(domain, cassette))
        evidence.extend(ct.collect(domain, cassette))
        evidence.extend(breach.collect(domain, cassette))
        evidence.extend(exposure.collect(domain, cassette))

    evidence.extend(
        attestation.collect(vendor.primary_domain, cassette, vendor.claimed_certifications)
    )
    return evidence


def detect_shared_interception(all_evidence: Dict[str, List[Evidence]], threshold: int = 3) -> bool:
    """Structural detection of a TLS-terminating middlebox across the run.

    Independent organisations do not share a certificate issuer. If one issuer
    signs the certificates presented by three or more unrelated vendors, the
    assessing network is almost certainly intercepting TLS, and every
    certificate observation in the run describes the middlebox rather than the
    vendors.

    This catches interception that the issuer-name pattern list misses, which
    matters because a false "certificate is valid" is the most damaging error
    this tool could make: it would tell a buyer we verified something we never
    saw.
    """
    # Two independent signals, and the run flag must fire on either. They used
    # to disagree: a collector could mark a single observation INTERCEPTED on a
    # known-middlebox issuer pattern while this function, which needs three
    # unrelated vendors sharing one issuer, returned False — so the banner
    # never appeared in exactly the environment the banner exists for.
    if any(
        item.kind == "tls_config" and item.status == EvidenceStatus.INTERCEPTED
        for items in all_evidence.values()
        for item in items
    ):
        return True

    issuers: Dict[str, set] = {}
    for vendor_id, items in all_evidence.items():
        for item in items:
            if item.kind != "tls_config" or item.status == EvidenceStatus.UNOBSERVABLE:
                continue
            issuer = ((item.data or {}).get("certificate") or {}).get("issuer") or {}
            label = issuer.get("organizationName") or issuer.get("commonName")
            if label:
                issuers.setdefault(label, set()).add(vendor_id)
    return any(len(vendors) >= threshold for vendors in issuers.values())
