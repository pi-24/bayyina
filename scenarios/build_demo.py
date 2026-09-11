#!/usr/bin/env python3
"""Build the bundled demonstration tender.

Why the demo tender is synthetic, stated plainly
------------------------------------------------
The bidders in this scenario do not exist. Their domains are under .example
(RFC 2606, reserved and unresolvable) and every observation in the cassette was
constructed by this script.

That is a deliberate choice, not a shortcut. A demonstration that published
real security findings about real named companies would be asserting things
about third parties that they have no opportunity to rebut, in a context where
the finding could affect their commercial standing — which is precisely the
harm the dispute-and-correction principle in this field exists to prevent. And
a live run against real infrastructure cannot be reproduced by a juror later,
because the internet will have changed.

So the bundled scenario is synthetic and reproducible, and the tool also runs
live against real infrastructure with `bayyina live --domain <domain>`. The
analysis code is identical in both paths; only the transport differs.

The observations here are structurally real: real record syntax, real header
strings, real certificate field shapes, real RFC-conformant SPF and DMARC. They
are constructed to exercise the three outcomes the tool is built to
distinguish — a polished bidder whose attestations do not survive contact with
evidence, a modest bidder whose do, and a bidder about whom too little is
observable to rank at all.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bayyina.cassette import Cassette  # noqa: E402
from bayyina.collectors.public_data import AttestationCollector, ExposureCollector  # noqa: E402
from bayyina.models import Evidence, EvidenceStatus  # noqa: E402

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "MDG-2026-114")
OBSERVED_AT = "2026-09-05T09:00:00+00:00"

entries = {}


def add(collector, kind, target, data, params=None, status=EvidenceStatus.OBSERVED, source="", note=""):
    evidence = Evidence(
        collector=collector,
        kind=kind,
        target=target,
        status=status,
        observed_at=OBSERVED_AT,
        source=source or _default_source(collector, target),
        data=data,
        note=note,
    )
    key = Cassette.make_key(collector, kind, target, params)
    entries[key] = evidence.to_dict()


def _default_source(collector, target):
    return {
        "dns_email": "dns-over-https (cloudflare-dns.com)",
        "tls": "tls handshake (client-conformant, no application data sent)",
        "http": f"HTTPS GET https://{target}/",
        "ct": "https://crt.sh certificate transparency search",
        "breach": "local incident corpus",
        "attestation": "claimed certifications cross-checked against accreditation registry",
    }.get(collector, "synthetic demonstration evidence")


def dns(domain, kind, rtype, records, ad=False):
    add("dns_email", kind, domain if kind != "dmarc" else f"_dmarc.{domain}",
        {"query_type": rtype, "records": records, "dnssec_ad_flag": ad, "rcode": 0},
        params={"rtype": rtype})


def dns_target(target, kind, rtype, records, ad=False):
    add("dns_email", kind, target,
        {"query_type": rtype, "records": records, "dnssec_ad_flag": ad, "rcode": 0},
        params={"rtype": rtype})


def tls(domain, negotiated, offered, issuer_o, issuer_cn, not_after, san):
    protocols = {
        label: {"offered": label in offered, "detail": "" if label in offered else "SSLError"}
        for label in ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
    }
    add("tls", "tls_config", domain, {
        "host": domain,
        "port": 443,
        "connected": True,
        "negotiated": negotiated,
        "cipher": {"name": "TLS_AES_256_GCM_SHA384" if negotiated == "TLSv1.3" else "ECDHE-RSA-AES256-GCM-SHA384",
                   "protocol": negotiated, "bits": 256},
        "certificate": {
            "subject": {"commonName": domain},
            "issuer": {"organizationName": issuer_o, "commonName": issuer_cn, "countryName": "US"},
            "not_before": "Jun  8 00:00:00 2026 GMT",
            "not_after": not_after,
            "serial": "0" + str(abs(hash(domain)) % 10**28),
            "san": san,
            "version": 3,
        },
        "protocols": protocols,
        "interception_suspected": False,
        "errors": [],
    }, params={"port": 443})


def headers(domain, security, disclosure, cookie, edge):
    add("http", "headers", domain, {
        "status": 200,
        "final_url": f"https://{domain}/",
        "security_headers": {
            h: security.get(h, "") for h in (
                "strict-transport-security", "content-security-policy", "x-content-type-options",
                "x-frame-options", "referrer-policy", "permissions-policy",
                "cross-origin-opener-policy", "cross-origin-resource-policy",
            )
        },
        "disclosure_headers": disclosure,
        "set_cookie": cookie,
        "server_header_present": bool(disclosure.get("server")),
        "edge_headers": edge,
    })


def security_txt(domain, present, body=""):
    data = {"present": present}
    if present:
        data.update({"path": "/.well-known/security.txt", "body": body})
    add("http", "security_txt", domain, data)


def ct(domain, hostnames, issuers):
    add("ct", "certificates", domain, {
        "hostnames": sorted(hostnames),
        "hostname_count": len(hostnames),
        "issuers": issuers,
        "distinct_issuers": len(issuers),
    })


def breach(domain, incidents):
    add("breach", "history", domain, {"incidents": incidents, "incident_count": len(incidents)})


def certifications(domain, claims, public=None):
    """Produce attestation evidence using the real collector.

    Rather than hand-writing the verdicts, we run the actual
    AttestationCollector against the actual accreditation registry. That means
    the synthetic evidence cannot drift away from what a live run would
    produce — if the verification logic changes, the demo changes with it.
    """
    collector = AttestationCollector(os.path.join(HERE, "attestation_registry.json"))
    evidence = collector._live(domain, claims)
    evidence.observed_at = OBSERVED_AT
    entries[Cassette.make_key("attestation", "certifications", domain,
                              {"claims": [c["standard"] for c in claims]})] = evidence.to_dict()


def exposure(domain):
    """Exposed-service evidence, produced by the real collector reading the real corpus."""
    collector = ExposureCollector(os.path.join(HERE, "exposure_corpus.json"))
    evidence = collector._live(domain)
    evidence.observed_at = OBSERVED_AT
    entries[Cassette.make_key("exposure", "exposed_services", domain)] = evidence.to_dict()


def missing(collector, kind, target, reason, params=None):
    """Record an explicit non-observation, so the tool reports it as unknown."""
    evidence = Evidence(
        collector=collector, kind=kind, target=target,
        status=EvidenceStatus.ERROR, observed_at=OBSERVED_AT,
        source="live attempt", data={}, note=reason,
    )
    entries[Cassette.make_key(collector, kind, target, params)] = evidence.to_dict()


# ===========================================================================
# Bidder A — Meridian Gov Solutions FZ-LLC
# The polished incumbent. Strong paper submission, ISO 27001 and SOC 2 Type II,
# lowest technical risk on the questionnaire. The evidence disagrees.
# ===========================================================================
M = "meridiangov.example"
dns_target(M, "a", "A", ["203.0.113.20"])
dns_target(M, "ns", "NS", ["ns1.cloudsecure-dns.example.", "ns2.cloudsecure-dns.example."])
dns_target(M, "mx", "MX", ["10 mx1.mailguard-cloud.example.", "20 mx2.mailguard-cloud.example."])
dns_target(M, "spf", "TXT", [
    "v=spf1 include:_spf.mailguard-cloud.example include:sendgrid.net include:_spf.crm-suite.example "
    "include:mail.zendesk.com include:_spf.marketo.example include:spf.protection.outlook.com "
    "include:_spf.eventbrite.example include:mailer.hrsuite.example include:_spf.docsign.example "
    "include:relay.partner-a.example include:relay.partner-b.example ~all"
])
dns_target(f"_dmarc.{M}", "dmarc", "TXT", ["v=DMARC1; p=none; rua=mailto:dmarc-reports@meridiangov.example"])
dns_target(M, "caa", "CAA", [])
dns_target(M, "dnssec", "DS", [])
dns_target(f"_mta-sts.{M}", "mta_sts", "TXT", [])
tls(M, "TLSv1.2", {"TLSv1", "TLSv1.1", "TLSv1.2"}, "DigiCert Inc",
    "DigiCert TLS RSA SHA256 2020 CA1", "Mar 14 23:59:59 2027 GMT",
    [M, f"www.{M}", f"portal.{M}"])
headers(M,
        security={"x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN"},
        disclosure={"server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3"},
        cookie="MERIDIANSESS=8f2a1c; Path=/; Secure",
        edge=["x-amz-cf-id", "x-amz-cf-pop"])
security_txt(M, False)
exposure(M)
ct(M, [f"{p}.{M}" for p in (
    "www", "portal", "vpn", "mail", "webmail", "autodiscover", "sso", "api", "api-uat", "api-dev",
    "legacy-portal", "crm", "hr", "intranet", "files", "sharepoint", "citrix", "remote", "test",
    "staging", "uat", "demo", "old", "backup", "archive", "reports", "analytics", "partner",
    "supplier", "billing", "invoice", "helpdesk", "support", "kb", "wiki", "git", "jenkins",
    "sonar", "nexus", "docker", "k8s", "monitor", "grafana", "kibana", "elastic", "db-admin",
)] + [M], {"C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1": 118,
           "C=US, O=Let's Encrypt, CN=R11": 46,
           "C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018": 17,
           "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV Secure Server CA": 9})
breach(M, [
    {
        "domain": M,
        "title": "Customer support platform compromise via third-party CRM integration",
        "date": "2024-11-03",
        "disclosed": "2025-02-18",
        "records": 44000,
        "classes": ["Email addresses", "Names", "Support ticket contents"],
        "source": "regulator notification register (synthetic)",
        "third_party_origin": True,
        "third_party_name": "CRM Suite (sub-processor)",
        "remediation_evidence": False,
    },
    {
        "domain": M,
        "title": "Exposed development database snapshot",
        "date": "2023-04-21",
        "disclosed": "2023-05-09",
        "records": 2100,
        "classes": ["Email addresses", "Hashed passwords"],
        "source": "public disclosure (synthetic)",
        "third_party_origin": False,
        "remediation_evidence": True,
    },
])
certifications(M, [
    {
        "standard": "ISO/IEC 27001:2022",
        "certificate_id": "IS-774213",
        "certification_body": "BSI Group",
        "accreditation_body": "UKAS",
        "scope_statement": (
            "The provision of managed IT support services and service desk operations "
            "delivered from the Meridian Dubai office, in accordance with the Statement "
            "of Applicability version 4.2."
        ),
        "valid_until": "2027-03-31",
        "covers_delivery_entity": False,
    },
    {
        "standard": "SOC 2 Type II",
        "certificate_id": "n/a",
        "certification_body": "Independent CPA firm",
        "accreditation_body": "AICPA",
        "scope_statement": "Security trust services criterion only; report provided under NDA.",
        "valid_until": "2027-01-31",
        "covers_delivery_entity": None,
    },
])

# ===========================================================================
# Bidder B — Nawras Digital DMCC
# Smaller, thinner paper submission, no SOC 2. Every claim it makes survives
# contact with evidence.
# ===========================================================================
N = "nawrasdigital.example"
dns_target(N, "a", "A", ["198.51.100.44"])
dns_target(N, "ns", "NS", ["ns1.emirates-dns.example.", "ns2.emirates-dns.example."])
dns_target(N, "mx", "MX", ["10 mx.mailfortress.example."])
dns_target(N, "spf", "TXT", ["v=spf1 include:_spf.mailfortress.example -all"])
dns_target(f"_dmarc.{N}", "dmarc", "TXT",
           ["v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:dmarc@nawrasdigital.example"])
dns_target(N, "caa", "CAA", ['0 issue "letsencrypt.org"', '0 iodef "mailto:security@nawrasdigital.example"'])
dns_target(N, "dnssec", "DS", ["12345 13 2 9F3A2B1C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8"], ad=True)
dns_target(f"_mta-sts.{N}", "mta_sts", "TXT", ["v=STSv1; id=20260401120000"])
tls(N, "TLSv1.3", {"TLSv1.2", "TLSv1.3"}, "Let's Encrypt", "R11", "Nov 12 12:00:00 2026 GMT",
    [N, f"www.{N}", f"app.{N}"])
headers(N,
        security={
            "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
            "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=(), camera=(), microphone=()",
        },
        disclosure={},
        cookie="nd_session=a91f; Path=/; Secure; HttpOnly; SameSite=Strict",
        edge=["x-served-by"])
exposure(N)
security_txt(N, True, "Contact: mailto:security@nawrasdigital.example\nExpires: 2027-01-01T00:00:00Z\nPreferred-Languages: en, ar\n")
ct(N, [f"{p}.{N}" for p in ("www", "app", "api", "status", "docs", "id", "cdn", "mail",
                           "staging", "vpn", "git", "monitor", "backup", "reports", "admin",
                           "sso", "files")] + [N],
   {"C=US, O=Let's Encrypt, CN=R11": 31})
breach(N, [])
certifications(N, [
    {
        "standard": "ISO/IEC 27001:2022",
        "certificate_id": "IS-902551",
        "certification_body": "TUV Rheinland",
        "accreditation_body": "DAkkS",
        "scope_statement": (
            "Design, development, hosting and operation of cloud-based case management "
            "and workflow software, including all delivery and support functions of "
            "Nawras Digital DMCC."
        ),
        "valid_until": "2028-06-30",
        "covers_delivery_entity": True,
    },
    {
        "standard": "CSA STAR LEVEL 1",
        "certificate_id": "STAR-L1-NWD-2026",
        "certification_body": "Cloud Security Alliance (self-assessment)",
        "accreditation_body": "n/a",
        "scope_statement": "CAIQ v4 self-assessment published to the public CSA STAR registry.",
        "valid_until": "2027-05-14",
        "covers_delivery_entity": True,
    },
], public=["CSA STAR LEVEL 1"])

# ===========================================================================
# Bidder C — Orion Systems Integration LLC
# Reasonable where we can see it, but too much is unobservable to rank.
# Shares three dependency categories with Meridian.
# ===========================================================================
O = "orionsys.example"
dns_target(O, "a", "A", ["203.0.113.88"])
dns_target(O, "ns", "NS", ["ns1.cloudsecure-dns.example.", "ns2.cloudsecure-dns.example."])
dns_target(O, "mx", "MX", ["10 mx1.mailguard-cloud.example."])
dns_target(O, "spf", "TXT", ["v=spf1 include:_spf.mailguard-cloud.example include:spf.protection.outlook.com -all"])
dns_target(f"_dmarc.{O}", "dmarc", "TXT", ["v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@orionsys.example"])
dns_target(O, "caa", "CAA", [])
dns_target(O, "dnssec", "DS", [])
dns_target(f"_mta-sts.{O}", "mta_sts", "TXT", [])
headers(O,
        security={
            "strict-transport-security": "max-age=15768000",
            "content-security-policy": "default-src 'self' 'unsafe-inline'; img-src *",
            "x-content-type-options": "nosniff",
            "x-frame-options": "SAMEORIGIN",
        },
        disclosure={"server": "nginx"},
        cookie="ORIONID=7c31; Path=/; Secure; HttpOnly",
        edge=["x-amz-cf-id"])
# Deliberate non-observations. These are the point of this bidder: the tool
# must report low coverage and refuse to rank, rather than filling the gaps.
#
# The TLS endpoint requires client-certificate authentication, so a normal
# client cannot complete a handshake. That is not a weakness — it is arguably
# good practice — but it means the protocol set and certificate are genuinely
# unobservable from outside. Three TLS checks therefore return UNKNOWN, which
# is the honest result and the reason this bidder cannot be ranked.
missing("tls", "tls_config", O,
        "Handshake rejected: the endpoint requires client-certificate authentication "
        "(SSLV3_ALERT_HANDSHAKE_FAILURE after certificate request). Protocol versions and "
        "server certificate are not observable by an unauthenticated client.",
        params={"port": 443})
missing("http", "security_txt", O, "Connection timed out after 10s on two attempts.")
missing("exposure", "exposed_services", O,
        "No passive exposure dataset covers this domain in the supplied corpus. Bayyina does not "
        "port scan, so the exposed-service posture is genuinely unobserved.")
missing("ct", "certificates", O, "crt.sh query exceeded the 45s timeout; not retried within the assessment window.")
missing("breach", "history", O, "No incident corpus entry and the public breach index returned no result for this domain; "
                                "absence of a record is not evidence of absence of an incident.")
certifications(O, [
    {
        "standard": "ISO/IEC 27001:2022",
        "certificate_id": "IS-661044",
        "certification_body": "TUV Rheinland",
        "accreditation_body": "DAkkS",
        "scope_statement": "Systems integration and application managed services.",
        "valid_until": "2028-02-28",
        "covers_delivery_entity": None,
    },
])


def main() -> None:
    os.makedirs(HERE, exist_ok=True)
    payload = {
        "meta": {
            "format": "bayyina-cassette/1",
            "note": (
                "SYNTHETIC demonstration evidence for a fictional tender. Bidder domains are "
                "under .example (RFC 2606) and do not resolve. Generated by scenarios/build_demo.py. "
                "Replaying this cassette performs no network activity and reproduces the assessment exactly."
            ),
            "observed_at": OBSERVED_AT,
            "generator": "scenarios/build_demo.py",
        },
        "entries": entries,
    }
    path = os.path.join(HERE, "cassette.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    print(f"wrote {path} with {len(entries)} recorded observations")


if __name__ == "__main__":
    main()
