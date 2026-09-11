"""TLS configuration and HTTP security-header evidence.

A note on interception, which is the reason this module is more careful than
it looks
------------------------------------------------------------------------------
This tool was built inside a network whose egress gateway terminates and
re-issues TLS. A naive collector running there reports a perfectly healthy
certificate for every host on the internet, because it is describing the
middlebox, not the vendor. Silently emitting those findings would have meant
telling a buyer that a bidder's certificate was fine when we never saw it.

So the collector detects the condition two ways — a known-middlebox issuer
pattern, and the structural giveaway that unrelated hosts share one issuer —
and marks the evidence INTERCEPTED. Intercepted evidence is not scored as a
pass or a failure; it lowers coverage and widens the score interval, exactly
like any other thing we could not see. Reporting "we could not observe this"
is always available to us; reporting a number we cannot stand behind is not.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..models import Evidence, EvidenceStatus
from . import net

# Headers we record. Authority: OWASP Secure Headers Project and the OWASP
# HTTP Headers cheat sheet.
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
)

# Headers whose *presence* leaks build/version detail an attacker uses to
# select an exploit without touching the target.
DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache")

# Vendor-set headers that identify the edge/CDN in front of a service. Recorded
# for concentration analysis, not scored — using a CDN is not a weakness, but
# three bidders behind the *same* CDN is a fact a buyer splitting an award
# needs to know.
EDGE_HEADER_NAMES = frozenset(
    {
        "cf-ray",
        "cf-cache-status",
        "x-amz-cf-id",
        "x-amz-cf-pop",
        "x-azure-ref",
        "x-msedge-ref",
        "x-akamai-transformed",
        "akamai-grn",
        "x-served-by",
        "fastly-io-info",
        "x-goog-generation",
        "x-guploader-uploadid",
    }
)


class TlsCollector:
    name = "tls"

    def collect(self, domain: str, cassette) -> List[Evidence]:
        return [
            cassette.obtain(
                self.name,
                "tls_config",
                domain,
                lambda d=domain: self._live(d),
                params={"port": 443},
            )
        ]

    def _live(self, domain: str) -> Evidence:
        probe = net.tls_probe(domain)
        status = EvidenceStatus.OBSERVED
        note = ""
        if probe.get("interception_suspected"):
            status = EvidenceStatus.INTERCEPTED
            note = (
                "The certificate presented was issued by what appears to be a "
                "TLS-terminating middlebox on the assessing network, not by the "
                "vendor's CA. Certificate and protocol findings are withheld."
            )
        elif not probe.get("connected"):
            status = EvidenceStatus.ERROR
            note = "; ".join(probe.get("errors", [])) or "handshake failed"
        return Evidence(
            collector=self.name,
            kind="tls_config",
            target=domain,
            status=status,
            observed_at=net.utcnow(),
            source="tls handshake (client-conformant, no application data sent)",
            data=probe,
            note=note,
        )


class HttpCollector:
    name = "http"

    def collect(self, domain: str, cassette) -> List[Evidence]:
        evidence = [
            cassette.obtain(
                self.name,
                "headers",
                domain,
                lambda d=domain: self._live_headers(d),
            ),
            cassette.obtain(
                self.name,
                "security_txt",
                domain,
                lambda d=domain: self._live_security_txt(d),
            ),
        ]
        return evidence

    def _live_headers(self, domain: str) -> Evidence:
        response = net.http_get(f"https://{domain}/")
        headers = response["headers"]
        data = {
            "status": response["status"],
            "final_url": response["url"],
            "security_headers": {h: headers.get(h, "") for h in SECURITY_HEADERS},
            "disclosure_headers": {h: headers.get(h, "") for h in DISCLOSURE_HEADERS if headers.get(h)},
            "set_cookie": headers.get("set-cookie", ""),
            "server_header_present": bool(headers.get("server")),
            # Vendor-set edge/CDN headers, kept so concentration analysis can
            # identify a shared failure domain across a bid field.
            "edge_headers": sorted(h for h in headers if h in EDGE_HEADER_NAMES),
        }
        return Evidence(
            collector=self.name,
            kind="headers",
            target=domain,
            status=EvidenceStatus.OBSERVED,
            observed_at=net.utcnow(),
            source=f"HTTPS GET https://{domain}/",
            data=data,
        )

    def _live_security_txt(self, domain: str) -> Evidence:
        for path in ("/.well-known/security.txt", "/security.txt"):
            try:
                response = net.http_get(f"https://{domain}{path}")
            except net.TransportError:
                continue
            if response["status"] == 200 and "contact" in response["body"].lower():
                return Evidence(
                    collector=self.name,
                    kind="security_txt",
                    target=domain,
                    status=EvidenceStatus.OBSERVED,
                    observed_at=net.utcnow(),
                    source=f"HTTPS GET https://{domain}{path}",
                    data={"present": True, "path": path, "body": response["body"][:2000]},
                )
        return Evidence(
            collector=self.name,
            kind="security_txt",
            target=domain,
            status=EvidenceStatus.OBSERVED,
            observed_at=net.utcnow(),
            source=f"HTTPS GET https://{domain}/.well-known/security.txt",
            data={"present": False},
        )


# ---------------------------------------------------------------------------
# Header parsing helpers, used by the checks
# ---------------------------------------------------------------------------


def parse_hsts(value: str) -> Dict[str, Any]:
    lowered = (value or "").lower()
    max_age = 0
    for chunk in lowered.split(";"):
        chunk = chunk.strip()
        if chunk.startswith("max-age="):
            try:
                max_age = int(chunk.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                max_age = 0
    return {
        "present": bool(lowered),
        "max_age": max_age,
        "include_subdomains": "includesubdomains" in lowered,
        "preload": "preload" in lowered,
        # 31536000 = one year, the value CISA BOD 18-01 and the HSTS preload
        # list both require.
        "adequate": max_age >= 31536000,
    }


def parse_cookies(set_cookie: str) -> Dict[str, Any]:
    if not set_cookie:
        return {"count": 0, "insecure": [], "all_secure": True}
    cookies = [c.strip() for c in set_cookie.split("\n") if c.strip()] or [set_cookie]
    insecure = []
    for cookie in cookies:
        lowered = cookie.lower()
        name = cookie.split("=", 1)[0].strip()
        missing = []
        if "secure" not in lowered:
            missing.append("Secure")
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if missing:
            insecure.append({"name": name, "missing": missing})
    return {"count": len(cookies), "insecure": insecure, "all_secure": not insecure}


def weak_protocols_offered(tls_data: Dict[str, Any]) -> List[str]:
    """Deprecated protocol versions the server still accepts.

    TLS 1.0 and 1.1 were deprecated by RFC 8996 (March 2021) and are
    prohibited for US federal systems by NIST SP 800-52 Rev. 2.
    """
    offered = []
    for label in ("TLSv1", "TLSv1.1"):
        entry = (tls_data.get("protocols") or {}).get(label) or {}
        if entry.get("offered"):
            offered.append(label)
    return offered


def certificate_days_remaining(tls_data: Dict[str, Any], as_of: str) -> Optional[int]:
    """Days until certificate expiry, measured against the observation date.

    Measured against ``as_of`` — the moment the evidence was captured — and not
    against the wall clock, so a replayed assessment gives the same answer
    today as it did when it was recorded.
    """
    import datetime as dt

    not_after = ((tls_data or {}).get("certificate") or {}).get("not_after")
    if not not_after or not as_of:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            expiry = dt.datetime.strptime(not_after, fmt).replace(tzinfo=dt.timezone.utc)
            break
        except ValueError:
            continue
    else:
        return None
    try:
        observed = dt.datetime.fromisoformat(as_of.replace("Z", "+00:00"))
    except ValueError:
        return None
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=dt.timezone.utc)
    return (expiry - observed).days
