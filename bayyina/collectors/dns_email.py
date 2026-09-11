"""DNS and email-authentication evidence.

Every observation here is a DNS lookup. Nothing is sent to the vendor's own
infrastructure beyond what a resolver or a sending mail server does routinely.

The check set follows the same ground CISA Binding Operational Directive 18-01
made mandatory for US federal agencies in 2017 (SPF, DMARC at p=reject,
STARTTLS, no legacy ciphers) and that the Dutch government's internet.nl test
suite scores publicly — i.e. this is not a novel or contested set of controls,
it is the baseline a government already applies to itself.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..models import Evidence, EvidenceStatus
from ..util import registrable_domain
from . import net


class DnsEmailCollector:
    name = "dns_email"

    LOOKUPS = (
        ("a", "A", "{domain}"),
        ("ns", "NS", "{domain}"),
        ("mx", "MX", "{domain}"),
        ("spf", "TXT", "{domain}"),
        ("dmarc", "TXT", "_dmarc.{domain}"),
        ("caa", "CAA", "{domain}"),
        ("dnssec", "DS", "{domain}"),
        ("mta_sts", "TXT", "_mta-sts.{domain}"),
    )

    def collect(self, domain: str, cassette) -> List[Evidence]:
        evidence: List[Evidence] = []
        for kind, rtype, template in self.LOOKUPS:
            target = template.format(domain=domain)
            evidence.append(
                cassette.obtain(
                    self.name,
                    kind,
                    target,
                    lambda t=target, r=rtype, k=kind: self._live(t, r, k, domain),
                    params={"rtype": rtype},
                )
            )
        return evidence

    def _live(self, target: str, rtype: str, kind: str, domain: str) -> Evidence:
        try:
            answer = net.resolve(target, rtype)
        except net.TransportError as exc:
            return Evidence(
                collector=self.name,
                kind=kind,
                target=target,
                status=EvidenceStatus.ERROR,
                observed_at=net.utcnow(),
                source="dns-over-https",
                note=str(exc),
            )
        data: Dict[str, Any] = {
            "query_type": rtype,
            "records": answer["records"],
            "dnssec_ad_flag": answer["ad"],
            "rcode": answer["status"],
        }
        if kind == "spf":
            data["records"] = [r for r in answer["records"] if r.lower().startswith("v=spf1")]
        if kind == "dmarc":
            data["records"] = [r for r in answer["records"] if r.lower().startswith("v=dmarc1")]
        if kind == "mta_sts":
            data["records"] = [r for r in answer["records"] if r.lower().startswith("v=stsv1")]

        status = EvidenceStatus.OBSERVED
        return Evidence(
            collector=self.name,
            kind=kind,
            target=target,
            status=status,
            observed_at=net.utcnow(),
            source=answer["resolver"],
            data=data,
        )


# ---------------------------------------------------------------------------
# Parsers used by the checks. Kept here so the record syntax and the rules that
# read it live next to each other.
# ---------------------------------------------------------------------------


def parse_spf(record: str) -> Dict[str, Any]:
    """Parse an SPF record into its mechanisms and terminating qualifier.

    We report the *terminating* mechanism (``-all`` fail, ``~all`` softfail,
    ``?all`` neutral, ``+all`` pass-everything) and the DNS-lookup count, which
    RFC 7208 s.4.6.4 caps at 10 — exceeding it makes the record permerror and
    therefore unenforceable, a failure mode that is invisible unless counted.
    """
    tokens = (record or "").split()
    mechanisms = [t for t in tokens if not t.lower().startswith("v=")]
    terminator = ""
    for token in mechanisms:
        if token.lower().lstrip("+-~?") == "all":
            terminator = token
    lookup_mechanisms = ("include:", "a", "mx", "ptr", "exists:", "redirect=")
    lookups = 0
    for token in mechanisms:
        bare = token.lstrip("+-~?").lower()
        if bare.startswith(("include:", "exists:", "redirect=")):
            lookups += 1
        elif bare == "a" or bare.startswith("a:") or bare == "mx" or bare.startswith("mx:"):
            lookups += 1
        elif bare == "ptr" or bare.startswith("ptr:"):
            lookups += 1
    return {
        "terminator": terminator,
        "enforcing": terminator.startswith("-"),
        "softfail": terminator.startswith("~"),
        "permissive": terminator.startswith(("+", "?")) or terminator == "",
        "dns_lookups": lookups,
        "over_lookup_limit": lookups > 10,
        "mechanisms": mechanisms,
    }


def parse_dmarc(record: str) -> Dict[str, Any]:
    """Parse a DMARC record. Policy strength is the field that matters."""
    parts: Dict[str, str] = {}
    for chunk in (record or "").split(";"):
        chunk = chunk.strip()
        if "=" in chunk:
            key, _, value = chunk.partition("=")
            parts[key.strip().lower()] = value.strip()
    policy = parts.get("p", "").lower()
    try:
        percentage = int(parts.get("pct", "100"))
    except ValueError:
        percentage = 100
    return {
        "policy": policy,
        "subdomain_policy": parts.get("sp", "").lower(),
        "pct": percentage,
        "rua": parts.get("rua", ""),
        "ruf": parts.get("ruf", ""),
        "adkim": parts.get("adkim", "r"),
        "aspf": parts.get("aspf", "r"),
        # p=none collects reports but blocks nothing. It is the single most
        # common gap between "we enforce DMARC" on a questionnaire and reality.
        "enforcing": policy in ("quarantine", "reject") and percentage == 100,
        "reject": policy == "reject" and percentage == 100,
        "monitor_only": policy == "none",
    }


def mx_providers(records: List[str]) -> List[str]:
    """Reduce MX records to the provider that actually handles the mail.

    Used for concentration analysis: two bidders whose mail terminates at the
    same provider share that provider's failure and compromise modes.
    """
    providers = []
    for record in records or []:
        host = record.split()[-1] if record.split() else record
        host = host.strip().strip(".").lower()
        if not host:
            continue
        providers.append(registrable_domain(host))
    return sorted(set(providers))
