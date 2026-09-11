"""The check rules.

Every check carries the external authority it derives from. That is not
decoration: a bidder challenging a finding under UAE Federal Law 11/2023
Art. 29 is entitled to know why the buyer treated the control as a control,
and "our tool said so" is not an answer.

Weights are *within-category* and are normalised by the scoring model, so the
absolute numbers here only express relative importance inside their category.
The category weights themselves live in the tender configuration, because
Art. 22(4) requires the buyer to publish the weighting of each criterion in
advance — so it must be the buyer's setting, not ours.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Dict, List, Optional

from ..collectors.dns_email import mx_providers, parse_dmarc, parse_spf
from ..collectors.tls_web import (
    certificate_days_remaining,
    parse_cookies,
    parse_hsts,
    weak_protocols_offered,
)
from ..models import Category, CheckOutcome, EvidenceStatus, Severity
from . import CheckContext, CheckResult, not_applicable, register, unknown

PASS = CheckOutcome.PASS
FAIL = CheckOutcome.FAIL
PARTIAL = CheckOutcome.PARTIAL
NEEDS_HUMAN = CheckOutcome.NEEDS_HUMAN


# ==========================================================================
# Technical hygiene — TLS
# ==========================================================================


@register(
    "TLS-001",
    "Deprecated TLS versions are not accepted",
    Category.HYGIENE,
    weight=3.0,
    severity=Severity.HIGH,
    references=[
        "RFC 8996 (Deprecating TLS 1.0 and TLS 1.1, March 2021)",
        "NIST SP 800-52 Rev. 2",
        "CISA BOD 18-01",
    ],
)
def tls_legacy(ctx: CheckContext) -> CheckResult:
    evidence = ctx.index.get("tls_config")
    if evidence and evidence.status == EvidenceStatus.INTERCEPTED:
        return unknown(
            "TLS observation withheld: the assessing network terminated the "
            "connection, so the certificate and protocol set observed were the "
            "middlebox's, not the vendor's."
        )
    data = ctx.index.data("tls_config")
    if not data or not data.get("connected"):
        return unknown("No successful TLS handshake was observed for this host.")
    weak = weak_protocols_offered(data)
    digests = [evidence.digest] if evidence else []
    if weak:
        return CheckResult(
            FAIL,
            0.0,
            f"Server accepts {', '.join(weak)}, deprecated by RFC 8996 and prohibited "
            f"for federal systems by NIST SP 800-52 Rev. 2.",
            "Disable TLS 1.0 and TLS 1.1 on all Internet-facing endpoints; serve TLS 1.2 as a minimum.",
            digests,
        )
    return CheckResult(
        PASS,
        1.0,
        "Only TLS 1.2 and above are accepted; TLS 1.0 and 1.1 are refused.",
        "",
        digests,
    )


@register(
    "TLS-002",
    "Certificate is valid and not close to expiry",
    Category.HYGIENE,
    weight=2.0,
    severity=Severity.MEDIUM,
    references=["CA/Browser Forum Baseline Requirements", "NIST SP 800-52 Rev. 2 §3.3"],
)
def tls_certificate(ctx: CheckContext) -> CheckResult:
    evidence = ctx.index.get("tls_config")
    if evidence and evidence.status == EvidenceStatus.INTERCEPTED:
        return unknown("Certificate observation withheld: TLS interception detected on the assessing network.")
    data = ctx.index.data("tls_config")
    if not data or not data.get("connected"):
        return unknown("No certificate was observed.")
    days = certificate_days_remaining(data, evidence.observed_at if evidence else "")
    digests = [evidence.digest] if evidence else []
    if days is None:
        return unknown("Certificate validity dates could not be parsed from the observation.")
    if days < 0:
        return CheckResult(FAIL, 0.0, f"Certificate expired {abs(days)} days before the observation date.",
                           "Renew the certificate and add automated renewal monitoring.", digests)
    if days < 30:
        return CheckResult(PARTIAL, 0.4, f"Certificate expires in {days} days.",
                           "Renew now and automate renewal at least 30 days ahead of expiry.", digests)
    return CheckResult(PASS, 1.0, f"Certificate valid, {days} days remaining at the observation date.", "", digests)


@register(
    "TLS-003",
    "TLS 1.3 is supported",
    Category.HYGIENE,
    weight=1.0,
    severity=Severity.LOW,
    references=["RFC 8446", "Mozilla Server Side TLS — Intermediate configuration"],
)
def tls_modern(ctx: CheckContext) -> CheckResult:
    evidence = ctx.index.get("tls_config")
    if evidence and evidence.status == EvidenceStatus.INTERCEPTED:
        return unknown("Protocol observation withheld: TLS interception detected.")
    data = ctx.index.data("tls_config")
    if not data or not data.get("connected"):
        return unknown("No TLS handshake observed.")
    offered = ((data.get("protocols") or {}).get("TLSv1.3") or {}).get("offered")
    digests = [evidence.digest] if evidence else []
    if offered:
        return CheckResult(PASS, 1.0, "TLS 1.3 is offered.", "", digests)
    return CheckResult(PARTIAL, 0.5, "TLS 1.3 is not offered; the endpoint tops out at TLS 1.2.",
                       "Enable TLS 1.3 to obtain forward secrecy by default and a reduced handshake surface.", digests)


# ==========================================================================
# Technical hygiene — web
# ==========================================================================


@register(
    "WEB-001",
    "HSTS is enforced with an adequate max-age",
    Category.HYGIENE,
    weight=2.0,
    severity=Severity.MEDIUM,
    references=["RFC 6797", "CISA BOD 18-01", "OWASP Secure Headers Project"],
)
def web_hsts(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("headers")
    evidence = ctx.index.get("headers")
    if not data:
        return unknown("No HTTP response was observed for this host.")
    hsts = parse_hsts((data.get("security_headers") or {}).get("strict-transport-security", ""))
    digests = [evidence.digest] if evidence else []
    if not hsts["present"]:
        return CheckResult(FAIL, 0.0, "No Strict-Transport-Security header is served.",
                           "Serve HSTS with max-age of at least 31536000 and includeSubDomains.", digests)
    if not hsts["adequate"]:
        return CheckResult(PARTIAL, 0.5,
                           f"HSTS present but max-age is {hsts['max_age']}s, below the one-year baseline.",
                           "Raise max-age to at least 31536000 seconds.", digests)
    if not hsts["include_subdomains"]:
        return CheckResult(PARTIAL, 0.75, "HSTS max-age adequate but includeSubDomains is absent.",
                           "Add includeSubDomains so subdomains cannot be downgraded.", digests)
    return CheckResult(PASS, 1.0,
                       f"HSTS enforced (max-age {hsts['max_age']}s, includeSubDomains"
                       f"{', preload' if hsts['preload'] else ''}).", "", digests)


@register(
    "WEB-002",
    "A Content-Security-Policy is served",
    Category.HYGIENE,
    weight=2.0,
    severity=Severity.MEDIUM,
    references=["OWASP Secure Headers Project", "MDN Observatory scoring"],
)
def web_csp(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("headers")
    evidence = ctx.index.get("headers")
    if not data:
        return unknown("No HTTP response was observed for this host.")
    csp = (data.get("security_headers") or {}).get("content-security-policy", "")
    digests = [evidence.digest] if evidence else []
    if not csp:
        return CheckResult(FAIL, 0.0, "No Content-Security-Policy header is served.",
                           "Deploy a CSP starting in report-only mode, then enforce.", digests)
    weak = "unsafe-inline" in csp or "unsafe-eval" in csp or "default-src *" in csp
    if weak:
        return CheckResult(PARTIAL, 0.5,
                           "CSP is present but permits unsafe-inline/unsafe-eval or a wildcard default-src, "
                           "which removes most of its value against injection.",
                           "Remove unsafe-inline/unsafe-eval; adopt nonces or hashes.", digests)
    return CheckResult(PASS, 1.0, "A restrictive Content-Security-Policy is served.", "", digests)


@register(
    "WEB-003",
    "Core response-hardening headers are present",
    Category.HYGIENE,
    weight=2.0,
    severity=Severity.MEDIUM,
    references=["OWASP HTTP Headers Cheat Sheet"],
)
def web_headers(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("headers")
    evidence = ctx.index.get("headers")
    if not data:
        return unknown("No HTTP response was observed for this host.")
    headers = data.get("security_headers") or {}
    csp = headers.get("content-security-policy", "")
    required = {
        "x-content-type-options": bool(headers.get("x-content-type-options")),
        "frame protection": bool(headers.get("x-frame-options")) or "frame-ancestors" in csp,
        "referrer-policy": bool(headers.get("referrer-policy")),
    }
    present = sum(1 for v in required.values() if v)
    missing = [k for k, v in required.items() if not v]
    digests = [evidence.digest] if evidence else []
    score = present / len(required)
    if present == len(required):
        return CheckResult(PASS, 1.0, "X-Content-Type-Options, frame protection and Referrer-Policy are all set.", "", digests)
    return CheckResult(
        FAIL if present == 0 else PARTIAL,
        score,
        f"Missing: {', '.join(missing)}.",
        "Add the missing response headers at the edge; none require application changes.",
        digests,
    )


@register(
    "WEB-004",
    "Session cookies carry Secure, HttpOnly and SameSite",
    Category.HYGIENE,
    weight=1.5,
    severity=Severity.MEDIUM,
    references=["OWASP Session Management Cheat Sheet", "RFC 6265bis"],
)
def web_cookies(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("headers")
    evidence = ctx.index.get("headers")
    if not data:
        return unknown("No HTTP response was observed for this host.")
    cookies = parse_cookies(data.get("set_cookie", ""))
    digests = [evidence.digest] if evidence else []
    if cookies["count"] == 0:
        return unknown("The observed response set no cookies, so cookie flags could not be assessed.")
    if cookies["all_secure"]:
        return CheckResult(PASS, 1.0, f"All {cookies['count']} observed cookies carry Secure, HttpOnly and SameSite.", "", digests)
    names = ", ".join(f"{c['name']} (missing {'/'.join(c['missing'])})" for c in cookies["insecure"][:3])
    score = 1 - (len(cookies["insecure"]) / max(cookies["count"], 1))
    return CheckResult(PARTIAL if score > 0 else FAIL, round(score, 4),
                       f"Cookies missing protective attributes: {names}.",
                       "Set Secure, HttpOnly and SameSite on all session cookies.", digests)


# ==========================================================================
# Technical hygiene — DNS and email authentication
# ==========================================================================


@register(
    "DNS-001",
    "SPF is published and enforcing",
    Category.HYGIENE,
    weight=2.0,
    severity=Severity.MEDIUM,
    references=["RFC 7208", "CISA BOD 18-01", "NIST SP 800-177 Rev. 1"],
)
def dns_spf(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("spf")
    evidence = ctx.index.get("spf")
    if data is None:
        return unknown("SPF record could not be retrieved.")
    records = data.get("records") or []
    digests = [evidence.digest] if evidence else []
    if not records:
        return CheckResult(FAIL, 0.0, "No SPF record is published; any host may send mail claiming this domain.",
                           "Publish an SPF record terminating in -all.", digests)
    parsed = parse_spf(records[0])
    if parsed["over_lookup_limit"]:
        return CheckResult(FAIL, 0.2,
                           f"SPF record requires {parsed['dns_lookups']} DNS lookups, above the RFC 7208 limit of 10; "
                           "receivers will treat it as permerror and ignore it.",
                           "Flatten includes to bring the lookup count to 10 or fewer.", digests)
    if parsed["enforcing"]:
        return CheckResult(PASS, 1.0, f"SPF published and enforcing ({parsed['terminator']}).", "", digests)
    if parsed["softfail"]:
        return CheckResult(PARTIAL, 0.6, f"SPF terminates in {parsed['terminator']} (softfail), which most receivers do not reject on.",
                           "Move to -all once the sending inventory is confirmed.", digests)
    return CheckResult(FAIL, 0.2, f"SPF terminates in '{parsed['terminator'] or 'nothing'}', which enforces nothing.",
                       "Terminate the SPF record in -all.", digests)


@register(
    "DNS-002",
    "DMARC is published at an enforcing policy",
    Category.HYGIENE,
    weight=3.0,
    severity=Severity.HIGH,
    references=["RFC 7489", "CISA BOD 18-01 (p=reject mandated for US federal agencies)"],
)
def dns_dmarc(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("dmarc")
    evidence = ctx.index.get("dmarc")
    if data is None:
        return unknown("DMARC record could not be retrieved.")
    records = data.get("records") or []
    digests = [evidence.digest] if evidence else []
    if not records:
        return CheckResult(FAIL, 0.0, "No DMARC record is published; the domain is spoofable in phishing against the buyer.",
                           "Publish DMARC, move to p=quarantine then p=reject.", digests)
    parsed = parse_dmarc(records[0])
    if parsed["reject"]:
        return CheckResult(PASS, 1.0, "DMARC published at p=reject with pct=100.", "", digests)
    if parsed["enforcing"]:
        return CheckResult(PASS, 0.85, "DMARC published at p=quarantine with pct=100.",
                           "Move to p=reject once report analysis is clean.", digests)
    if parsed["monitor_only"]:
        return CheckResult(FAIL, 0.25,
                           "DMARC is published at p=none — it collects reports but blocks nothing. "
                           "The domain remains spoofable.",
                           "Move to p=quarantine, then p=reject.", digests)
    if parsed["pct"] < 100:
        return CheckResult(PARTIAL, 0.55, f"DMARC policy is {parsed['policy']} but applied to only {parsed['pct']}% of mail.",
                           "Raise pct to 100.", digests)
    return CheckResult(PARTIAL, 0.4, f"DMARC present with policy '{parsed['policy']}'.", "Move to an enforcing policy.", digests)


@register(
    "DNS-003",
    "The zone is DNSSEC-signed",
    Category.HYGIENE,
    weight=1.0,
    severity=Severity.LOW,
    references=["RFC 4033–4035", "internet.nl test suite"],
)
def dns_dnssec(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("dnssec")
    evidence = ctx.index.get("dnssec")
    if data is None:
        return unknown("DNSSEC delegation could not be checked.")
    digests = [evidence.digest] if evidence else []
    if data.get("records"):
        return CheckResult(PASS, 1.0, "A DS record is published at the parent; the zone is signed.", "", digests)
    return CheckResult(PARTIAL, 0.3, "No DS record at the parent zone; DNSSEC is not enabled.",
                       "Sign the zone and publish a DS record with the registrar.", digests)


@register(
    "DNS-004",
    "CAA records constrain certificate issuance",
    Category.HYGIENE,
    weight=1.0,
    severity=Severity.LOW,
    references=["RFC 8659"],
)
def dns_caa(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("caa")
    evidence = ctx.index.get("caa")
    if data is None:
        return unknown("CAA records could not be checked.")
    digests = [evidence.digest] if evidence else []
    if data.get("records"):
        return CheckResult(PASS, 1.0, "CAA records restrict which CAs may issue for this domain.", "", digests)
    return CheckResult(PARTIAL, 0.4, "No CAA records; any public CA may issue certificates for this domain.",
                       "Publish CAA records naming the approved CAs.", digests)


@register(
    "DNS-005",
    "MTA-STS is published for inbound mail",
    Category.HYGIENE,
    weight=1.0,
    severity=Severity.LOW,
    references=["RFC 8461", "RFC 8460 (TLS-RPT)"],
)
def dns_mta_sts(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("mta_sts")
    evidence = ctx.index.get("mta_sts")
    if data is None:
        return unknown("MTA-STS policy record could not be checked.")
    digests = [evidence.digest] if evidence else []
    if data.get("records"):
        return CheckResult(PASS, 1.0, "An MTA-STS policy is published; inbound mail is protected against downgrade.", "", digests)
    return CheckResult(PARTIAL, 0.4, "No MTA-STS policy; inbound mail can be stripped to cleartext by an on-path attacker.",
                       "Publish an MTA-STS policy and TLS-RPT reporting address.", digests)


# ==========================================================================
# Attack surface and exposure
# ==========================================================================


@register(
    "SUR-001",
    "Public certificate surface is proportionate and declared",
    Category.SURFACE,
    weight=2.0,
    severity=Severity.MEDIUM,
    references=["RFC 9162 (Certificate Transparency v2)"],
)
def surface_breadth(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("certificates")
    evidence = ctx.index.get("certificates")
    if data is None:
        return unknown("Certificate transparency logs could not be queried for this domain.")
    count = int(data.get("hostname_count", 0))
    digests = [evidence.digest] if evidence else []
    # CT shows what was issued, not what is live. So this is deliberately a
    # coarse band and is framed as "investigate", never as "exposed".
    if count <= 25:
        return CheckResult(PASS, 1.0, f"{count} hostnames appear in certificate transparency logs — a compact public estate.", "", digests)
    if count <= 120:
        return CheckResult(PARTIAL, 0.6,
                           f"{count} hostnames appear in CT logs. Confirm each is still in service and in scope for the contract.",
                           "Provide an inventory of Internet-facing hostnames and decommission stale entries.", digests)
    return CheckResult(FAIL, 0.25,
                       f"{count} hostnames appear in CT logs, indicating a broad and possibly unmanaged public estate.",
                       "Inventory and reduce the Internet-facing estate; retire unused hostnames and their certificates.",
                       digests)


@register(
    "SUR-002",
    "Responses do not disclose software versions",
    Category.SURFACE,
    weight=2.0,
    severity=Severity.MEDIUM,
    references=["OWASP Secure Headers Project", "OWASP ASVS v4 §14.3"],
)
def surface_disclosure(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("headers")
    evidence = ctx.index.get("headers")
    if data is None:
        return unknown("No HTTP response was observed for this host.")
    disclosed = data.get("disclosure_headers") or {}
    digests = [evidence.digest] if evidence else []
    versioned = {k: v for k, v in disclosed.items() if any(ch.isdigit() for ch in str(v))}
    if versioned:
        detail = ", ".join(f"{k}: {v}" for k, v in list(versioned.items())[:3])
        return CheckResult(FAIL, 0.0,
                           f"Response headers disclose software versions ({detail}), letting an attacker select an exploit "
                           "without touching the service.",
                           "Suppress Server, X-Powered-By and framework version headers at the edge.", digests)
    if disclosed:
        return CheckResult(PARTIAL, 0.6, f"Product headers present without version detail ({', '.join(disclosed)}).",
                           "Suppress product identification headers.", digests)
    return CheckResult(PASS, 1.0, "No product or version disclosure in response headers.", "", digests)


@register(
    "SUR-003",
    "A vulnerability disclosure contact is published",
    Category.SURFACE,
    weight=2.0,
    severity=Severity.MEDIUM,
    references=["RFC 9116 (security.txt)", "ISO/IEC 29147"],
)
def surface_disclosure_policy(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("security_txt")
    evidence = ctx.index.get("security_txt")
    if data is None:
        return unknown("security.txt could not be checked.")
    digests = [evidence.digest] if evidence else []
    if data.get("present"):
        return CheckResult(PASS, 1.0, "An RFC 9116 security.txt publishes a vulnerability disclosure contact.", "", digests)
    return CheckResult(PARTIAL, 0.3,
                       "No security.txt is published, so a researcher or the buyer's own SOC has no documented route to "
                       "report a vulnerability.",
                       "Publish /.well-known/security.txt with a monitored contact and disclosure policy.", digests)


@register(
    "SUR-004",
    "Certificate issuance is consolidated across few CAs",
    Category.SURFACE,
    weight=1.0,
    severity=Severity.LOW,
    references=["CA/Browser Forum Baseline Requirements", "RFC 8659 (CAA)"],
)
def surface_issuer_sprawl(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("certificates")
    evidence = ctx.index.get("certificates")
    if data is None:
        return unknown("Certificate transparency logs could not be queried.")
    distinct = int(data.get("distinct_issuers", 0))
    digests = [evidence.digest] if evidence else []
    if distinct == 0:
        return unknown("No issuers observed in CT logs.")
    if distinct <= 3:
        return CheckResult(PASS, 1.0, f"Certificates issued by {distinct} distinct CA(s) — consistent with central control.", "", digests)
    return CheckResult(PARTIAL, 0.5,
                       f"Certificates issued by {distinct} distinct CAs, which often indicates decentralised or shadow "
                       "certificate procurement.",
                       "Consolidate issuance and enforce it with CAA records.", digests)


# ==========================================================================
# Breach and incident history
# ==========================================================================


def _incident_age_days(entry: Dict[str, Any], as_of: str) -> Optional[int]:
    raw = str(entry.get("date") or "")[:10]
    if not raw or not as_of:
        return None
    try:
        when = dt.date.fromisoformat(raw)
        ref = dt.datetime.fromisoformat(as_of.replace("Z", "+00:00")).date()
    except ValueError:
        return None
    return (ref - when).days


@register(
    "BRE-001",
    "No disclosed security incident in the trailing 36 months",
    Category.BREACH,
    weight=3.0,
    severity=Severity.HIGH,
    references=["VERIS Community Database", "Verizon DBIR 2026 third-party archetypes"],
)
def breach_recent(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("history")
    evidence = ctx.index.get("history")
    if data is None:
        return unknown("No breach corpus was available for this domain.")
    digests = [evidence.digest] if evidence else []
    as_of = evidence.observed_at if evidence else ""
    recent = []
    for entry in data.get("incidents", []):
        age = _incident_age_days(entry, as_of)
        if age is not None and age <= 1095:
            recent.append((entry, age))
    if not recent:
        return CheckResult(PASS, 1.0,
                           "No disclosed incident in the trailing 36 months. Note this measures *disclosed* "
                           "incidents only and is therefore weak evidence of safety.", "", digests)
    worst = min(recent, key=lambda x: x[1])
    entry, age = worst
    score = 0.15 if age <= 365 else 0.45
    return CheckResult(FAIL, score,
                       f"{len(recent)} disclosed incident(s) in the trailing 36 months; most recent "
                       f"\"{entry.get('title', 'incident')}\" {age} days before assessment.",
                       "Provide the post-incident review, root cause and completed remediation evidence.",
                       digests)


@register(
    "BRE-002",
    "Incident disclosure was timely",
    Category.BREACH,
    weight=2.0,
    severity=Severity.HIGH,
    references=["UAE Federal Decree-Law 45/2021", "DORA Art. 19 incident reporting", "GDPR Art. 33 (72 hours)"],
)
def breach_disclosure_lag(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("history")
    evidence = ctx.index.get("history")
    if data is None:
        return unknown("No breach corpus was available for this domain.")
    incidents = data.get("incidents", [])
    digests = [evidence.digest] if evidence else []
    if not incidents:
        return not_applicable(
            "No incidents are on record, so there is no disclosure behaviour to assess. "
            "Recorded as not applicable rather than unknown: the vendor is not penalised with "
            "uncertainty for a control that has nothing to bite on."
        )
    lags = []
    for entry in incidents:
        try:
            occurred = dt.date.fromisoformat(str(entry.get("date"))[:10])
            disclosed = dt.date.fromisoformat(str(entry.get("disclosed"))[:10])
            lags.append((disclosed - occurred).days)
        except (ValueError, TypeError):
            continue
    if not lags:
        return unknown("Incident dates are on record but disclosure dates are not.")
    worst = max(lags)
    if worst <= 30:
        return CheckResult(PASS, 1.0, f"Longest disclosure lag on record is {worst} days.", "", digests)
    if worst <= 90:
        return CheckResult(PARTIAL, 0.5, f"Longest disclosure lag on record is {worst} days.",
                           "Commit contractually to a defined notification window.", digests)
    return CheckResult(FAIL, 0.1,
                       f"Longest disclosure lag on record is {worst} days, materially longer than any applicable "
                       "notification window.",
                       "Require a contractual incident notification window with liquidated remedies.", digests)


@register(
    "BRE-003",
    "No incident originated with the vendor's own suppliers",
    Category.BREACH,
    weight=2.0,
    severity=Severity.HIGH,
    references=["Verizon DBIR 2026 (48% of breaches involve a third party)", "DORA Art. 28 sub-outsourcing register"],
)
def breach_fourth_party(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("history")
    evidence = ctx.index.get("history")
    if data is None:
        return unknown("No breach corpus was available for this domain.")
    digests = [evidence.digest] if evidence else []
    downstream = [i for i in data.get("incidents", []) if i.get("third_party_origin")]
    if not data.get("incidents"):
        return not_applicable(
            "No incidents are on record, so none can be attributed to a sub-supplier. Sub-processor "
            "exposure is instead addressed as a contract condition, since it is not externally observable."
        )
    if not downstream:
        return CheckResult(PASS, 1.0, "No recorded incident originated with one of the vendor's own suppliers.", "", digests)
    names = ", ".join(str(i.get("third_party_name", "unnamed supplier")) for i in downstream[:2])
    return CheckResult(FAIL, 0.2,
                       f"{len(downstream)} incident(s) originated in the vendor's own supply chain ({names}). "
                       "This is the dominant breach archetype in DBIR 2026 and it transfers to the buyer.",
                       "Require a sub-processor register, flow-down security obligations and prior approval for new sub-processors.",
                       digests)


@register(
    "BRE-004",
    "Remediation of prior incidents is evidenced",
    Category.BREACH,
    weight=2.0,
    severity=Severity.MEDIUM,
    references=["ISO/IEC 27001:2022 A.5.20", "NIST SP 800-161r1"],
)
def breach_remediation(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("history")
    evidence = ctx.index.get("history")
    if data is None:
        return unknown("No breach corpus was available for this domain.")
    incidents = data.get("incidents", [])
    digests = [evidence.digest] if evidence else []
    if not incidents:
        return not_applicable("No incidents are on record, so there is no remediation to evidence.")
    unevidenced = [i for i in incidents if not i.get("remediation_evidence")]
    if not unevidenced:
        return CheckResult(PASS, 1.0, "Remediation evidence is on file for every recorded incident.", "", digests)
    return CheckResult(
        NEEDS_HUMAN,
        None,
        f"{len(unevidenced)} of {len(incidents)} recorded incident(s) have no remediation evidence on file. "
        "Whether the remediation was adequate is a judgement a named reviewer must make; the tool will not guess.",
        "Request the post-incident review and independent verification of closure before award.",
        digests,
    )


# ==========================================================================
# Attestation integrity
# ==========================================================================


@register(
    "ATT-001",
    "Claimed certifications are independently verifiable",
    Category.ATTESTATION,
    weight=3.0,
    severity=Severity.HIGH,
    references=["IAF MD 28:2023", "DAkkS statement of 15 Nov 2024 declining IAF CertSearch participation"],
)
def attestation_verifiable(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("certifications")
    evidence = ctx.index.get("certifications")
    if data is None:
        return unknown("No certification claims were supplied for this bidder.")
    claims = data.get("claims") or []
    digests = [evidence.digest] if evidence else []
    if not claims:
        return CheckResult(PARTIAL, 0.3, "The bidder claims no third-party certification.",
                           "Require at least one accredited certification or an equivalent independent assessment.", digests)
    verified = [c for c in claims if c.get("verdict") == "PUBLICLY_VERIFIED"]
    unverifiable = [c for c in claims if c.get("verdict") == "NOT_MACHINE_VERIFIABLE"]
    score = len(verified) / len(claims)
    detail = (
        f"{len(verified)} of {len(claims)} claimed attestations are publicly verifiable"
        + (f"; {len(unverifiable)} (SOC 2) cannot be verified from any registry by design" if unverifiable else "")
        + "."
    )
    if score >= 0.99:
        return CheckResult(PASS, 1.0, detail, "", digests)
    return CheckResult(PARTIAL, round(max(score, 0.35), 4), detail,
                       "Supply the certificate PDF, the certification body and the accreditation body for each claim; "
                       "absence from a registry is not itself evidence of a false claim.", digests)


@register(
    "ATT-002",
    "Certification body is accredited",
    Category.ATTESTATION,
    weight=2.0,
    severity=Severity.HIGH,
    references=["IAF Multilateral Recognition Arrangement", "UKAS / ANAB accredited body directories"],
)
def attestation_accredited(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("certifications")
    evidence = ctx.index.get("certifications")
    if data is None:
        return unknown("No certification claims were supplied.")
    iso_claims = [c for c in (data.get("claims") or []) if str(c.get("standard", "")).startswith("ISO")]
    digests = [evidence.digest] if evidence else []
    if not iso_claims:
        return unknown("No ISO management-system certificate was claimed, so issuer accreditation does not apply.")
    unaccredited = [c for c in iso_claims if c.get("issuer_accredited") is False]
    unknown_issuer = [c for c in iso_claims if c.get("issuer_accredited") is None]
    if unaccredited:
        names = ", ".join(str(c.get("certification_body")) for c in unaccredited)
        return CheckResult(FAIL, 0.0,
                           f"Certificate issued by a body not on any recognised accreditation register ({names}). "
                           "This is the signature of a certification mill.",
                           "Require certification from a body accredited by an IAF MLA signatory.", digests)
    if unknown_issuer:
        return CheckResult(NEEDS_HUMAN, None,
                           "The issuing certification body was not named, so its accreditation could not be checked.",
                           "Require the certificate PDF naming the certification body and its accreditation body.", digests)
    return CheckResult(PASS, 1.0, "All claimed ISO certificates were issued by accredited certification bodies.", "", digests)


@register(
    "ATT-003",
    "Certificates are in force at the bid date",
    Category.ATTESTATION,
    weight=2.0,
    severity=Severity.MEDIUM,
    references=["ISO/IEC 17021-1 three-year certification cycle with annual surveillance"],
)
def attestation_currency(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("certifications")
    evidence = ctx.index.get("certifications")
    if data is None:
        return unknown("No certification claims were supplied.")
    claims = data.get("claims") or []
    digests = [evidence.digest] if evidence else []
    if not claims:
        return unknown("No certification claims to date-check.")
    as_of = (evidence.observed_at or "")[:10]
    if not as_of:
        return unknown("No observation date available to compare certificate validity against.")
    expired = []
    for claim in claims:
        valid_until = str(claim.get("valid_until") or "")[:10]
        if valid_until and valid_until < as_of:
            expired.append(f"{claim.get('standard')} (expired {valid_until})")
    if expired:
        return CheckResult(FAIL, 0.0, f"Expired certification presented: {', '.join(expired)}.",
                           "Provide a current certificate, or withdraw the claim from the bid.", digests)
    return CheckResult(PASS, 1.0,
                       "All claimed certificates are in date. Note that suspension status is not published by any "
                       "registry, so 'in date' does not prove 'in good standing'.", "", digests)


@register(
    "ATT-004",
    "Certification scope covers the delivery entity and the tendered service",
    Category.ATTESTATION,
    weight=3.0,
    severity=Severity.HIGH,
    references=["ISO/IEC 27001:2022 §4.3 (scope of the ISMS)", "ISO/IEC 27001:2022 A.5.19"],
)
def attestation_scope(ctx: CheckContext) -> CheckResult:
    data = ctx.index.data("certifications")
    evidence = ctx.index.get("certifications")
    if data is None:
        return unknown("No certification claims were supplied.")
    claims = data.get("claims") or []
    digests = [evidence.digest] if evidence else []
    if not claims:
        return unknown("No certification claims to scope-check.")
    # Scope adequacy is the single most consequential and least detectable
    # attestation failure: a certificate can legitimately cover one office
    # while the bid implies enterprise coverage. No registry field encodes
    # this. It is routed to a human by design rather than guessed at.
    flagged = [c for c in claims if c.get("covers_delivery_entity") is False]
    unstated = [c for c in claims if c.get("covers_delivery_entity") is None]
    if flagged:
        from ..divergence import _clip  # local import: divergence imports checks
        detail = "; ".join(
            f"{c.get('standard')} scope: \"{_clip(c.get('scope_statement'))}\"" for c in flagged
        )
        return CheckResult(FAIL, 0.0,
                           f"Certification scope excludes the entity that would deliver this contract. {detail}",
                           "Require certification covering the delivering legal entity and the tendered service, "
                           "or a contractual commitment to extend scope before service commencement.", digests)
    if unstated:
        return CheckResult(NEEDS_HUMAN, None,
                           "Scope statements were supplied but no reviewer has confirmed they cover the delivering "
                           "entity and the tendered service. This cannot be determined mechanically.",
                           "Assign a named reviewer to compare each scope statement against the delivery model.", digests)
    return CheckResult(PASS, 1.0, "A reviewer has confirmed each certification scope covers the delivery entity.", "", digests)


@register(
    "SUR-005",
    "No high-risk services are exposed to the internet",
    Category.SURFACE,
    weight=3.0,
    severity=Severity.HIGH,
    references=[
        "CIS Controls v8 Control 4 (Secure Configuration)",
        "NIST SP 800-41 Rev. 1",
        "Observed from a passive internet-wide measurement dataset; Bayyina performs no port scanning",
    ],
)
def surface_exposed_services(ctx: CheckContext) -> CheckResult:
    """Administrative and database services reachable from the public internet.

    The observation comes from a buyer-supplied passive dataset (Censys,
    Shodan, Rapid7 Open Data, or the buyer's own inventory), not from any
    probe of our own. Without such a dataset the answer is UNKNOWN, which is
    the honest result: we decline to port scan, so we genuinely do not know.
    """
    data = ctx.index.data("exposed_services")
    evidence = ctx.index.get("exposed_services")
    if data is None:
        return unknown(
            "No passive exposure dataset covers this domain. Bayyina does not port scan, so the "
            "exposed-service posture is genuinely unobserved rather than assumed clean."
        )
    digests = [evidence.digest] if evidence else []
    services = data.get("services") or []
    if not services:
        return CheckResult(
            PASS, 1.0,
            "The passive exposure dataset records no reachable service on this estate.",
            "", digests,
        )
    high_risk = data.get("high_risk") or []
    if high_risk:
        detail = ", ".join(
            f"{s.get('port')}/{s.get('transport', 'tcp')} {s.get('risk_label') or s.get('service', '')}"
            f"{' on ' + str(s.get('ip')) if s.get('ip') else ''}"
            for s in high_risk[:4]
        )
        # Administrative access reachable from the internet is a different
        # class of problem from a missing header, so it fails outright rather
        # than degrading proportionally.
        return CheckResult(
            FAIL, 0.0,
            f"{len(high_risk)} high-risk service(s) reachable from the public internet: {detail}. "
            f"Observed in a passive measurement dataset as at {data.get('as_of') or 'the recorded date'}.",
            "Remove these services from the public internet; place administrative and database access "
            "behind the Authority-approved remote access path and restrict by source address.",
            digests,
        )
    unexpected = [s for s in services if not s.get("expected") and not s.get("high_risk")]
    if unexpected:
        detail = ", ".join(f"{s.get('port')} {s.get('service', '')}".strip() for s in unexpected[:4])
        return CheckResult(
            PARTIAL, 0.6,
            f"{len(services)} exposed service(s); none high-risk, but {len(unexpected)} are outside the "
            f"expected web and mail set ({detail}).",
            "Confirm each non-standard exposed service is required for the Services and is intended to be "
            "publicly reachable.",
            digests,
        )
    return CheckResult(
        PASS, 1.0,
        f"{len(services)} exposed service(s), all within the expected web and mail set.",
        "", digests,
    )
