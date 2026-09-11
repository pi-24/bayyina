"""Shared transport for live collection. Standard library only.

Scope policy (enforced here, not just documented)
-------------------------------------------------
Bayyina performs *normal-client protocol interaction and public-data retrieval
only*. Concretely, the transport layer in this file can:

  * resolve DNS over HTTPS (a DNS query, which is what any resolver does);
  * complete a TLS handshake (what any browser does);
  * issue a single HTTP GET/HEAD per endpoint (what any browser does);
  * read public third-party datasets (certificate transparency, breach corpora).

It deliberately provides no primitive for port scanning, vulnerability probing,
authentication attempts, fuzzing, or DNS zone transfer. That is a legal
position as much as an engineering one: under the UK Computer Misuse Act 1990
s.1 there is no statutory research defence and the status of port scanning is
unsettled, and the US DOJ's 2022 CFAA charging policy is prosecutorial policy
rather than statute and confers no civil immunity. Restricting the tool to
observations a bidder's own customers make every day is what allows a buyer to
run it across a bid field without per-bidder written authorisation.

Ethical practice follows the Menlo Report and the ZMap "good internet
citizenship" guidance: one request per endpoint per assessment cycle, an
identifying User-Agent that points at a page explaining the activity, and a
documented opt-out route.
"""

from __future__ import annotations

import datetime as _dt
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

USER_AGENT = (
    "Bayyina/0.9 (vendor assurance assessment; "
    "+https://example.org/bayyina/scope-policy; passive checks only)"
)

DEFAULT_TIMEOUT = 10.0

# Public DNS-over-HTTPS resolvers. DoH rather than UDP/53 is a deliberate
# choice: government and enterprise networks routinely block outbound 53, and a
# tool that only works from an unfiltered network is not deployable inside the
# buyer's own environment.
DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)


def utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


class TransportError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


def http_get(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    max_bytes: int = 512_000,
    method: str = "GET",
) -> Dict[str, Any]:
    """One request. Returns status, headers and a bounded body slice."""
    request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(max_bytes)
            return {
                "url": response.geturl(),
                "status": response.status,
                "headers": {k.lower(): v for k, v in response.headers.items()},
                "body": body.decode("utf-8", errors="replace"),
                "redirected": response.geturl() != url,
            }
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(max_bytes)
        except Exception:  # noqa: BLE001
            pass
        return {
            "url": url,
            "status": exc.code,
            "headers": {k.lower(): v for k, v in (exc.headers or {}).items()},
            "body": body.decode("utf-8", errors="replace"),
            "redirected": False,
        }
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
        raise TransportError(f"{type(exc).__name__}: {exc}") from exc


def http_json(url: str, timeout: float = DEFAULT_TIMEOUT, headers: Optional[Dict] = None) -> Any:
    response = http_get(url, timeout=timeout, headers=headers)
    if response["status"] >= 400:
        raise TransportError(f"HTTP {response['status']} from {url}")
    try:
        return json.loads(response["body"])
    except json.JSONDecodeError as exc:
        raise TransportError(f"non-JSON response from {url}: {exc}") from exc


# --------------------------------------------------------------------------
# DNS over HTTPS
# --------------------------------------------------------------------------

_RECORD_TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2, "TXT": 16, "CAA": 257,
                 "DS": 43, "DNSKEY": 48, "SOA": 6}


def resolve(name: str, rtype: str = "A", timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Resolve one record type via DoH, trying each resolver in turn.

    Returns a normalised dict:
        {"name":…, "type":…, "records":[str], "ad": bool, "status": int, "resolver": url}

    ``ad`` is the DNSSEC Authenticated Data flag as reported by the resolver.
    Note honestly what that means: it is the *resolver's* validation result,
    not our own chain validation. We report it as such and never claim to have
    validated the chain ourselves.
    """
    last_error = None
    for endpoint in DOH_ENDPOINTS:
        query = urllib.parse.urlencode({"name": name, "type": rtype})
        url = f"{endpoint}?{query}"
        try:
            payload = http_json(url, timeout=timeout, headers={"accept": "application/dns-json"})
        except TransportError as exc:
            last_error = exc
            continue
        answers = payload.get("Answer") or []
        records = []
        for answer in answers:
            if answer.get("type") != _RECORD_TYPES.get(rtype, -1):
                continue
            value = str(answer.get("data", "")).strip()
            if rtype == "TXT":
                value = value.strip('"').replace('" "', "")
            records.append(value)
        return {
            "name": name,
            "type": rtype,
            "records": records,
            "ad": bool(payload.get("AD", False)),
            "status": int(payload.get("Status", -1)),
            "resolver": endpoint,
        }
    raise TransportError(f"all DoH resolvers failed for {name}/{rtype}: {last_error}")


# --------------------------------------------------------------------------
# TLS
# --------------------------------------------------------------------------

# Issuer organisation fragments that indicate a TLS-terminating middlebox
# rather than the real server certificate. Interception is common in corporate
# and cloud build environments and it silently invalidates every certificate
# and protocol observation. See tls.py for how this is acted on.
_INTERCEPTION_MARKERS = (
    "egress gateway",
    "zscaler",
    "netskope",
    "bluecoat",
    "blue coat",
    "forcepoint",
    "fortinet",
    "fortigate",
    "palo alto",
    "mitmproxy",
    "charles proxy",
    "burp",
    "ssl inspection",
    "deep packet",
    "sophos",
    "mcafee web gateway",
    "cisco umbrella",
)

_PROTOCOLS: Tuple[Tuple[str, int], ...] = (
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
)


def _name_tuple_to_dict(pairs) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for rdn in pairs or ():
        for key, value in rdn:
            out[str(key)] = str(value)
    return out


def tls_probe(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """A verified handshake plus a per-protocol-version offer test.

    The offer test opens one connection per protocol version pinned to that
    version, which is how any TLS client determines what a server will accept.
    It sends no application data. Failures are recorded as "not offered",
    which is the desired result for the deprecated versions.
    """
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "connected": False,
        "negotiated": None,
        "cipher": None,
        "certificate": {},
        "protocols": {},
        "interception_suspected": False,
        "errors": [],
    }

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                result["connected"] = True
                result["negotiated"] = tls.version()
                cipher = tls.cipher()
                result["cipher"] = {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None
                peer = tls.getpeercert() or {}
                issuer = _name_tuple_to_dict(peer.get("issuer"))
                subject = _name_tuple_to_dict(peer.get("subject"))
                sans = [v for k, v in peer.get("subjectAltName", ()) if k == "DNS"]
                result["certificate"] = {
                    "subject": subject,
                    "issuer": issuer,
                    "not_before": peer.get("notBefore", ""),
                    "not_after": peer.get("notAfter", ""),
                    "serial": peer.get("serialNumber", ""),
                    "san": sorted(sans),
                    "version": peer.get("version"),
                }
                blob = " ".join(list(issuer.values())).lower()
                result["interception_suspected"] = any(m in blob for m in _INTERCEPTION_MARKERS)
    except Exception as exc:  # noqa: BLE001
        result["errors"].append(f"verified handshake: {type(exc).__name__}: {exc}")

    for label, version in _PROTOCOLS:
        offered = False
        detail = ""
        try:
            probe_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            probe_ctx.check_hostname = False
            probe_ctx.verify_mode = ssl.CERT_NONE
            probe_ctx.minimum_version = version
            probe_ctx.maximum_version = version
            # OpenSSL 3 refuses to even configure the legacy versions unless the
            # security level is lowered; a server that still accepts them is
            # exactly what we are looking for, so we lower it for the probe only.
            if label in ("TLSv1", "TLSv1.1"):
                try:
                    probe_ctx.set_ciphers("DEFAULT@SECLEVEL=0")
                except ssl.SSLError:
                    detail = "client library refuses to offer this version"
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with probe_ctx.wrap_socket(raw, server_hostname=host) as tls:
                    offered = tls.version() == label
        except Exception as exc:  # noqa: BLE001
            detail = detail or f"{type(exc).__name__}"
        result["protocols"][label] = {"offered": offered, "detail": detail}

    return result
