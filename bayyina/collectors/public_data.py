"""Zero-contact evidence: certificate transparency, breach corpora, attestation registries.

Nothing in this module sends a single packet to the vendor. Every observation
comes from a public third-party dataset, which is why these checks can be run
across an entire bid field before a tender even closes.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from typing import Any, Dict, List, Optional

from ..models import Evidence, EvidenceStatus
from ..util import registrable_domain
from . import net


class CertificateTransparencyCollector:
    """Attack-surface discovery from CT logs.

    Every publicly-trusted certificate issued since Chrome's 2018 enforcement
    is in a public log by design (RFC 9162). Reading the log tells us which
    hostnames a vendor has certificates for — i.e. the shape of their public
    estate — with zero packets sent to them. It also shows CA choice, key
    strength and issuance cadence.

    The honest limitation, which we surface rather than hide: CT shows what was
    *issued*, not what is *live*. A hostname in CT may be decommissioned. We
    therefore treat CT-derived surface as an indicator to investigate, never as
    a confirmed exposure.
    """

    name = "ct"

    def collect(self, domain: str, cassette) -> List[Evidence]:
        return [
            cassette.obtain(
                self.name, "certificates", domain, lambda d=domain: self._live(d)
            )
        ]

    def _live(self, domain: str) -> Evidence:
        query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json", "exclude": "expired"})
        rows = net.http_json(f"https://crt.sh/?{query}", timeout=45)
        names: set = set()
        issuers: Dict[str, int] = {}
        for row in rows if isinstance(rows, list) else []:
            for name in str(row.get("name_value", "")).split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and name.endswith(domain):
                    names.add(name)
            issuer = str(row.get("issuer_name", ""))
            if issuer:
                issuers[issuer] = issuers.get(issuer, 0) + 1
        return Evidence(
            collector=self.name,
            kind="certificates",
            target=domain,
            status=EvidenceStatus.OBSERVED,
            observed_at=net.utcnow(),
            source="https://crt.sh certificate transparency search",
            data={
                "hostnames": sorted(names),
                "hostname_count": len(names),
                "issuers": issuers,
                "distinct_issuers": len(issuers),
            },
        )


class BreachCollector:
    """Public breach and incident history.

    Two sources, kept separate because they have very different evidentiary
    weight:

      * a local corpus file supplied with the tender (regulator notices, the
        buyer's own incident records, VERIS Community Database extracts). This
        is the authoritative one.
      * Have I Been Pwned's public breach index, when reachable, which covers
        credential-exposure events by domain.

    A structural bias worth stating out loud, because it bounds what any breach
    signal can mean: this measures *disclosed* breaches. Sarabi et al. (2016)
    showed that public breach disclosure is predictable from firmographics
    alone, so absence of disclosed breaches is weak evidence of safety and is
    partly a proxy for size, sector and jurisdiction. We therefore weight
    breach history for *handling and recency*, not merely for occurrence, and
    we never let a clean history alone lift a vendor's score.
    """

    name = "breach"

    def __init__(self, corpus_path: Optional[str] = None) -> None:
        self.corpus_path = corpus_path
        self._corpus: Optional[Dict[str, Any]] = None

    def _load_corpus(self) -> Dict[str, Any]:
        if self._corpus is not None:
            return self._corpus
        self._corpus = {}
        if self.corpus_path and os.path.exists(self.corpus_path):
            with open(self.corpus_path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
            for entry in raw.get("incidents", []):
                domain = str(entry.get("domain", "")).lower()
                self._corpus.setdefault(domain, []).append(entry)
        return self._corpus

    def collect(self, domain: str, cassette) -> List[Evidence]:
        return [
            cassette.obtain(
                self.name, "history", domain, lambda d=domain: self._live(d)
            )
        ]

    def _live(self, domain: str) -> Evidence:
        corpus = self._load_corpus()
        incidents = list(corpus.get(domain, []))
        sources = ["local incident corpus"]
        try:
            rows = net.http_json(
                f"https://haveibeenpwned.com/api/v3/breaches?Domain={urllib.parse.quote(domain)}"
            )
            for row in rows if isinstance(rows, list) else []:
                incidents.append(
                    {
                        "domain": domain,
                        "title": row.get("Title") or row.get("Name"),
                        "date": row.get("BreachDate", ""),
                        "disclosed": row.get("AddedDate", "")[:10],
                        "records": row.get("PwnCount", 0),
                        "classes": row.get("DataClasses", []),
                        "source": "haveibeenpwned.com",
                        "verified": bool(row.get("IsVerified")),
                    }
                )
            sources.append("haveibeenpwned.com/api/v3/breaches")
        except net.TransportError:
            pass
        return Evidence(
            collector=self.name,
            kind="history",
            target=domain,
            status=EvidenceStatus.OBSERVED,
            observed_at=net.utcnow(),
            source="; ".join(sources),
            data={"incidents": incidents, "incident_count": len(incidents)},
        )


class AttestationCollector:
    """Verification of claimed certifications, with honest verdicts.

    What can genuinely be machine-verified, and what cannot, is the whole point
    of this collector:

      * FedRAMP authorisation, CSA STAR entries and UK Cyber Essentials are
        public and machine-checkable — a real yes/no.
      * An ISO 27001 certificate can sometimes be found in IAF CertSearch, but
        coverage is materially incomplete: DAkkS, Germany's national
        accreditation body, publicly stated on 15 November 2024 that it does
        not apply IAF MD 28:2023 in its accreditation procedure. So "not found"
        is *not* evidence of a forged certificate, and this tool never says it
        is. What is reliably checkable is whether the issuing certification
        body is itself accredited — which catches certification mills, the
        largest real fraud class.
      * ISO 27001 *scope adequacy* cannot be automated at all. A certificate
        can legitimately cover one office or one product line while the bid
        implies enterprise coverage. This is routed to a human as
        NEEDS_HUMAN — never quietly passed.
      * SOC 2 cannot be verified at all: it is a private attestation delivered
        under NDA with no registry. Only the CPA firm is checkable.

    Encoding that trichotomy — verified / unverifiable / requires human review
    — instead of a single green tick is the design position of this module.
    """

    name = "attestation"

    def __init__(self, registry_path: Optional[str] = None) -> None:
        self.registry_path = registry_path
        self._registry: Optional[Dict[str, Any]] = None

    def _load_registry(self) -> Dict[str, Any]:
        if self._registry is not None:
            return self._registry
        self._registry = {"accredited_bodies": [], "public_authorisations": {}}
        if self.registry_path and os.path.exists(self.registry_path):
            with open(self.registry_path, "r", encoding="utf-8") as handle:
                self._registry = json.load(handle)
        return self._registry

    def collect(self, domain: str, cassette, claims: Optional[List[Dict]] = None) -> List[Evidence]:
        return [
            cassette.obtain(
                self.name,
                "certifications",
                domain,
                lambda d=domain, c=claims: self._live(d, c or []),
                params={"claims": [c.get("standard") for c in (claims or [])]},
            )
        ]

    def _live(self, domain: str, claims: List[Dict]) -> Evidence:
        registry = self._load_registry()
        accredited = {b.lower() for b in registry.get("accredited_bodies", [])}
        public = registry.get("public_authorisations", {}).get(domain, [])
        results = []
        for claim in claims:
            standard = str(claim.get("standard", "")).upper()
            body = str(claim.get("certification_body", ""))
            entry = {
                "standard": standard,
                "certificate_id": claim.get("certificate_id", ""),
                "certification_body": body,
                "accreditation_body": claim.get("accreditation_body", ""),
                "scope_statement": claim.get("scope_statement", ""),
                "valid_until": claim.get("valid_until", ""),
                "covers_delivery_entity": claim.get("covers_delivery_entity"),
            }
            if standard.startswith("ISO"):
                entry["issuer_accredited"] = body.lower() in accredited if body else None
                entry["registry_lookup"] = "iaf_certsearch_not_queried"
                entry["verdict"] = "ISSUER_CHECKED"
            elif standard.startswith("SOC"):
                entry["verdict"] = "NOT_MACHINE_VERIFIABLE"
                entry["reason"] = (
                    "SOC 2 is a private AICPA attestation report delivered under NDA. "
                    "No public registry exists; only the CPA firm can be checked."
                )
            elif standard in {s.upper() for s in public}:
                entry["verdict"] = "PUBLICLY_VERIFIED"
            else:
                entry["verdict"] = "UNVERIFIED"
            results.append(entry)
        return Evidence(
            collector=self.name,
            kind="certifications",
            target=domain,
            status=EvidenceStatus.OBSERVED,
            observed_at=net.utcnow(),
            source="claimed certifications cross-checked against accreditation registry",
            data={"claims": results, "public_authorisations": public},
        )


class ExposureCollector:
    """Internet-exposed services, from a passive dataset — zero packets sent.

    The case brief asks for exposed services alongside TLS, headers and DNS
    hygiene. Enumerating them ourselves would mean port scanning, which this
    tool does not do and will not do: under the UK Computer Misuse Act 1990
    s.1 the status of port scanning is unresolved, and running it across a bid
    field without each bidder's written authorisation is not a defensible
    position for a buyer.

    The resolution is that the enumeration has already been done, publicly and
    continuously, by internet-wide measurement projects. A buyer supplies a
    passive export — Censys, Shodan, Rapid7 Open Data, or its own
    attack-surface inventory — as ``exposure_corpus.json`` in the tender
    directory, and Bayyina reads the observation rather than making it. Zero
    packets reach the bidder, and the finding still carries a timestamp, a
    named source and a raw record the bidder can dispute.

    When no corpus is supplied the check returns UNKNOWN, which lowers coverage
    and widens the interval. That is the honest outcome and it is visible in
    the report, rather than the requirement quietly going unmet.
    """

    name = "exposure"

    # Services that should not be reachable from the public internet on a
    # system delivering a government contract. Administrative access, database
    # engines, and cleartext protocols.
    HIGH_RISK_PORTS: Dict[int, str] = {
        21: "FTP (cleartext)",
        23: "Telnet (cleartext)",
        135: "MSRPC",
        139: "NetBIOS session",
        445: "SMB",
        1433: "Microsoft SQL Server",
        1521: "Oracle DB",
        2375: "Docker API (unauthenticated by default)",
        2379: "etcd",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        5984: "CouchDB",
        6379: "Redis",
        9200: "Elasticsearch HTTP",
        9300: "Elasticsearch transport",
        11211: "Memcached",
        27017: "MongoDB",
        161: "SNMP",
    }

    EXPECTED_PORTS = {25, 53, 80, 110, 143, 443, 465, 587, 993, 995}

    def __init__(self, corpus_path: Optional[str] = None) -> None:
        self.corpus_path = corpus_path
        self._corpus: Optional[Dict[str, Any]] = None

    def _load(self) -> Dict[str, Any]:
        if self._corpus is not None:
            return self._corpus
        self._corpus = {"hosts": {}, "sources": []}
        if self.corpus_path and os.path.exists(self.corpus_path):
            try:
                with open(self.corpus_path, "r", encoding="utf-8") as handle:
                    raw = json.load(handle)
                if isinstance(raw, dict):
                    self._corpus = {
                        "hosts": raw.get("hosts") or {},
                        "sources": raw.get("sources") or [],
                        "as_of": raw.get("as_of", ""),
                    }
            except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                pass  # a corrupt corpus must leave the check UNKNOWN, never PASS
        return self._corpus

    def collect(self, domain: str, cassette) -> List[Evidence]:
        return [cassette.obtain(self.name, "exposed_services", domain, lambda d=domain: self._live(d))]

    def _live(self, domain: str) -> Evidence:
        corpus = self._load()
        hosts = corpus.get("hosts") or {}
        services = hosts.get(domain)
        if services is None:
            return Evidence(
                collector=self.name,
                kind="exposed_services",
                target=domain,
                status=EvidenceStatus.ERROR,
                observed_at=net.utcnow(),
                source="passive exposure corpus",
                note=(
                    "No passive exposure record for this domain. Bayyina does not port scan, so with no "
                    "supplied dataset the exposed-service posture is genuinely unobserved."
                ),
            )
        annotated = []
        for entry in services:
            try:
                port = int(entry.get("port", 0))
            except (TypeError, ValueError):
                port = 0
            annotated.append(
                {
                    **entry,
                    "port": port,
                    "high_risk": port in self.HIGH_RISK_PORTS,
                    "risk_label": self.HIGH_RISK_PORTS.get(port, ""),
                    "expected": port in self.EXPECTED_PORTS,
                }
            )
        return Evidence(
            collector=self.name,
            kind="exposed_services",
            target=domain,
            status=EvidenceStatus.OBSERVED,
            observed_at=net.utcnow(),
            source="; ".join(corpus.get("sources") or ["passive exposure corpus"]),
            data={
                "services": annotated,
                "service_count": len(annotated),
                "high_risk": [s for s in annotated if s["high_risk"]],
                "as_of": corpus.get("as_of", ""),
            },
        )
