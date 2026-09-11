"""Adversarial and malformed input.

The rule these tests encode: bad input must degrade to *unknown*, never to a
pass. A parser that throws stops the run, which is annoying. A parser that
silently returns a clean result for garbage is dangerous, because it tells a
buyer a supplier is fine when nothing was actually checked.
"""

from __future__ import annotations

import json
import os

import pytest

from bayyina.cassette import Cassette, CassetteError
from bayyina.checks import CheckContext, EvidenceIndex, run_checks
from bayyina.collectors.dns_email import mx_providers, parse_dmarc, parse_spf
from bayyina.collectors.tls_web import certificate_days_remaining, parse_cookies, parse_hsts
from bayyina.divergence import evaluate, load_questionnaire
from bayyina.engine import assess_tender, load_tender
from bayyina.models import CheckOutcome, Evidence, EvidenceStatus, Vendor
from bayyina.util import canonical, content_hash, host_suffix_match, registrable_domain

GARBAGE = [
    "", "   ", None, "\x00\x01\x02", "v=spf1", "not a record at all",
    "v=DMARC1", ";;;;;;", "a" * 5000, "🙂🙂🙂", "v=spf1 " + "include:x.example " * 400,
    "<script>alert(1)</script>", "'; DROP TABLE vendors; --", "../../etc/passwd",
    "%s%s%s%n", "\r\n\r\nInjected: header",
]


@pytest.mark.parametrize("value", GARBAGE)
def test_record_parsers_never_raise(value):
    for parser in (parse_spf, parse_dmarc, parse_hsts, parse_cookies):
        result = parser(value)
        assert isinstance(result, dict)


@pytest.mark.parametrize("value", GARBAGE)
def test_garbage_is_never_read_as_a_passing_control(value):
    """The direction of failure matters more than the fact of it."""
    assert parse_dmarc(value)["enforcing"] is False
    assert parse_spf(value)["enforcing"] is False
    assert parse_hsts(value)["adequate"] is False


def test_spf_lookup_limit_is_counted_not_guessed():
    over = "v=spf1 " + " ".join(f"include:h{i}.example" for i in range(14)) + " -all"
    parsed = parse_spf(over)
    assert parsed["dns_lookups"] == 14
    assert parsed["over_lookup_limit"] is True
    # An over-limit record is permerror at the receiver, so a hard-fail
    # terminator on it must not be read as enforcement.
    under = "v=spf1 include:a.example -all"
    assert parse_spf(under)["over_lookup_limit"] is False
    assert parse_spf(under)["enforcing"] is True


def test_dmarc_pct_below_one_hundred_is_not_enforcement():
    assert parse_dmarc("v=DMARC1; p=reject; pct=20")["enforcing"] is False
    assert parse_dmarc("v=DMARC1; p=reject; pct=100")["enforcing"] is True
    assert parse_dmarc("v=DMARC1; p=none")["monitor_only"] is True
    assert parse_dmarc("v=DMARC1; p=reject; pct=notanumber")["pct"] == 100


def test_hsts_max_age_parses_hostile_values():
    assert parse_hsts("max-age=abc")["max_age"] == 0
    assert parse_hsts("max-age=")["max_age"] == 0
    assert parse_hsts('max-age="31536000"; includeSubDomains')["adequate"] is True
    assert parse_hsts("max-age=-5")["adequate"] is False


def test_domain_suffix_matching_rejects_lookalikes():
    """endswith() would match evil-google.com against google.com."""
    assert host_suffix_match("a.example.com", "example.com") is True
    assert host_suffix_match("example.com", "example.com") is True
    assert host_suffix_match("evil-example.com", "example.com") is False
    assert host_suffix_match("", "example.com") is False


def test_registrable_domain_handles_multi_label_suffixes():
    assert registrable_domain("mail.company.co.ae") == "company.co.ae"
    assert registrable_domain("company.ae") == "company.ae"
    assert registrable_domain("a.b.c.example.com") == "example.com"
    assert registrable_domain("") == ""


def test_mx_provider_extraction_survives_malformed_records():
    assert mx_providers(["10 mx.provider.example.", "garbage", "", "20"]) is not None
    assert "provider.example" in mx_providers(["10 mx.provider.example."])


def test_certificate_expiry_uses_observation_date_not_wall_clock():
    """Replaying an assessment must give the same answer next year."""
    data = {"certificate": {"not_after": "Mar 14 23:59:59 2027 GMT"}}
    assert certificate_days_remaining(data, "2026-09-05T09:00:00+00:00") == 190
    assert certificate_days_remaining(data, "2027-09-05T09:00:00+00:00") == -175
    assert certificate_days_remaining({}, "2026-09-05T09:00:00+00:00") is None
    assert certificate_days_remaining(data, "not-a-date") is None


def test_checks_return_unknown_when_all_evidence_is_missing():
    """No evidence at all must produce unknowns, never failures."""
    vendor = Vendor(vendor_id="v", legal_name="V", primary_domain="v.example")
    findings = run_checks(CheckContext(vendor=vendor, index=EvidenceIndex([], "v.example")))
    assert findings, "checks should still run"
    assert all(f.score is None for f in findings)
    assert all(
        f.outcome in (CheckOutcome.UNKNOWN, CheckOutcome.NOT_APPLICABLE, CheckOutcome.NEEDS_HUMAN)
        for f in findings
    )


def test_a_check_that_raises_does_not_abort_the_run():
    """One malformed evidence record must not void an entire assessment."""
    poisoned = Evidence(
        collector="tls", kind="tls_config", target="v.example",
        status=EvidenceStatus.OBSERVED, observed_at="2026-09-05T09:00:00+00:00",
        data={"connected": True, "protocols": "this should be a dict, not a string"},
    )
    vendor = Vendor(vendor_id="v", legal_name="V", primary_domain="v.example")
    findings = run_checks(CheckContext(vendor=vendor, index=EvidenceIndex([poisoned], "v.example")))
    assert len(findings) > 10
    tls_findings = [f for f in findings if f.check_id.startswith("TLS")]
    assert all(f.score is None or f.outcome != CheckOutcome.PASS for f in tls_findings)


def test_questionnaire_loader_degrades_safely(tmp_path):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not json at all")
    claims, warnings = load_questionnaire(str(bad_json))
    assert claims == []
    assert warnings and "could not be parsed" in warnings[0]

    wrong_shape = tmp_path / "wrong.json"
    wrong_shape.write_text(json.dumps(["a", "list", "not", "an", "object"]))
    claims, warnings = load_questionnaire(str(wrong_shape))
    assert claims == [] and warnings

    mixed = tmp_path / "mixed.json"
    mixed.write_text(json.dumps({"responses": [
        {"id": "Q1", "question": "ok", "assertion": {"predicate": "dmarc_enforced", "value": True}},
        "this response is a string",
        {"id": "Q3", "question": "no assertion", "assertion": "not a dict"},
    ]}))
    claims, warnings = load_questionnaire(str(mixed))
    assert len(claims) == 2
    assert any("not an object" in w for w in warnings)

    assert load_questionnaire("") == ([], [])
    assert load_questionnaire("/nonexistent/path.json")[0] == []


def test_unknown_predicate_is_untestable_not_a_failure():
    from bayyina.models import Claim, DivergenceVerdict

    claim = Claim(
        claim_id="Q1", control_ref="X-1", text="We do a thing",
        assertion={"predicate": "no_such_predicate_exists", "value": True},
    )
    result = evaluate([claim], EvidenceIndex([], "v.example"))
    assert result[0].verdict == DivergenceVerdict.UNTESTABLE


def test_tender_loader_rejects_files_that_are_not_tenders(tmp_path):
    not_a_tender = tmp_path / "tender.json"
    not_a_tender.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(ValueError, match="not a tender definition"):
        load_tender(str(tmp_path))

    with pytest.raises(FileNotFoundError):
        load_tender(str(tmp_path / "missing"))


def test_tender_loader_ignores_unexpected_extra_keys(tmp_path):
    (tmp_path / "tender.json").write_text(json.dumps({
        "tender_id": "T1", "title": "T", "buyer": "B",
        "unexpected_key": "should be ignored", "_note": "comments are fine",
        "vendors": [{"vendor_id": "v", "legal_name": "V", "primary_domain": "v.example",
                     "extra_vendor_key": 1}],
    }))
    tender = load_tender(str(tmp_path))
    assert tender.tender_id == "T1"
    assert tender.vendors[0].vendor_id == "v"


def test_missing_cassette_in_replay_mode_explains_itself(tmp_path):
    with pytest.raises(CassetteError, match="Replay mode performs no network activity"):
        Cassette(str(tmp_path / "cassette.json"), mode="replay")


def test_unknown_cassette_mode_is_rejected(tmp_path):
    with pytest.raises(CassetteError, match="unknown cassette mode"):
        Cassette(str(tmp_path / "cassette.json"), mode="pillage")


def test_corrupt_cassette_is_rejected_not_silently_emptied(tmp_path):
    path = tmp_path / "cassette.json"
    path.write_text(json.dumps({"something": "else"}))
    with pytest.raises(CassetteError, match="not a Bayyina cassette"):
        Cassette(str(path), mode="replay")


def test_cassette_miss_in_replay_returns_unobservable(tmp_path):
    path = tmp_path / "cassette.json"
    path.write_text(json.dumps({"meta": {}, "entries": {}}))
    cassette = Cassette(str(path), mode="replay")

    def should_not_run():
        raise AssertionError("replay mode must never perform live collection")

    evidence = cassette.obtain("dns_email", "dmarc", "x.example", should_not_run)
    assert evidence.status == EvidenceStatus.UNOBSERVABLE
    assert cassette.stats["misses"] == 1


def test_tender_with_no_bidders_produces_an_empty_but_valid_run(tmp_path):
    (tmp_path / "tender.json").write_text(json.dumps(
        {"tender_id": "EMPTY", "title": "Empty", "buyer": "B", "vendors": []}))
    (tmp_path / "cassette.json").write_text(json.dumps({"meta": {}, "entries": {}}))
    run = assess_tender(str(tmp_path), mode="replay", samples=10)
    assert run.assessments == []
    assert run.ranking["tiers"] == []
    assert run.concentration["shared_dependencies"] == []


def test_bidder_with_no_domain_is_warned_about_not_silently_passed(tmp_path):
    (tmp_path / "tender.json").write_text(json.dumps({
        "tender_id": "NODOM", "title": "T", "buyer": "B",
        "vendors": [{"vendor_id": "ghost", "legal_name": "Ghost", "primary_domain": ""}],
    }))
    (tmp_path / "cassette.json").write_text(json.dumps({"meta": {}, "entries": {}}))
    run = assess_tender(str(tmp_path), mode="replay", samples=10)
    assert any("no primary domain" in w for w in run.warnings)
    ghost = run.vendor("ghost")
    assert ghost.coverage == 0.0
    assert (ghost.lower, ghost.upper) == (0.0, 100.0)


def test_unicode_and_html_in_vendor_names_do_not_break_reporting(tmp_path):
    from bayyina.report import comparison, vendor_report

    (tmp_path / "tender.json").write_text(json.dumps({
        "tender_id": "UNI", "title": "Tender <script>alert(1)</script> مناقصة",
        "buyer": "وزارة", "description": "Test & <b>bold</b>",
        "vendors": [{"vendor_id": "u1", "legal_name": "شركة \"الاختبار\" <img src=x>",
                     "primary_domain": "u1.example"}],
    }, ensure_ascii=False), encoding="utf-8")
    (tmp_path / "cassette.json").write_text(json.dumps({"meta": {}, "entries": {}}))
    run = assess_tender(str(tmp_path), mode="replay", samples=10)

    html = comparison(run)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "مناقصة" in html

    per_vendor = vendor_report(run, run.assessments[0])
    assert "<img src=x>" not in per_vendor


def test_canonical_json_is_order_independent():
    assert canonical({"a": 1, "b": 2}) == canonical({"b": 2, "a": 1})
    assert content_hash({"x": [1, 2]}) == content_hash({"x": [1, 2]})
    assert content_hash({"x": [1, 2]}) != content_hash({"x": [2, 1]})
