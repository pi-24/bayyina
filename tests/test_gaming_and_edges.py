"""Adversarial-bidder and degenerate-input behaviour.

Every test here corresponds to a way the tool could be gamed or could crash,
found by attacking it rather than by using it. They are separated from the
other suites because they encode the property that matters most in a
procurement setting: **a defect in a bid must never improve the bidder's
position**, and the tool must never assert an ordering it cannot support.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from bayyina.checks import CheckContext, EvidenceIndex, run_checks
from bayyina.divergence import reliability
from bayyina.engine import assess_tender
from bayyina.models import (
    Category,
    CheckOutcome,
    Divergence,
    DivergenceVerdict,
    Evidence,
    EvidenceStatus,
    Finding,
    Vendor,
    VendorAssessment,
)
from bayyina.scoring import normalise_weights, rank, score_vendor, validate_weights, weight_sensitivity

SCENARIO = Path(__file__).resolve().parent.parent / "scenarios" / "MDG-2026-114"


@pytest.fixture
def tender_copy(tmp_path):
    """A writable copy of the bundled tender, for corrupting."""
    destination = tmp_path / "tender"
    shutil.copytree(SCENARIO, destination)
    return destination


# ==========================================================================
# Tier construction must not assert an ordering the pairwise table denies
# ==========================================================================


def _assessment(vendor_id, lower, upper, point):
    return VendorAssessment(
        vendor=Vendor(vendor_id=vendor_id, legal_name=vendor_id, primary_domain=f"{vendor_id}.example"),
        lower=lower, upper=upper, point=point,
    )


def test_tiers_never_contradict_the_pairwise_table():
    """Every member of a tier must dominate every member of the tier below it.

    The naive "repeatedly take the undominated" construction fails here: `wide`
    is undominated only because nothing can separate it, so it lands in tier 1
    while `mid` — which it cannot be separated from — lands in tier 2, and the
    output asserts an ordering its own pairwise table denies.
    """
    tight_high = _assessment("tight_high", 90.0, 92.0, 91.0)
    wide = _assessment("wide", 40.0, 95.0, 80.0)
    mid = _assessment("mid", 45.0, 55.0, 50.0)
    low = _assessment("low", 5.0, 10.0, 7.0)

    result = rank([tight_high, wide, mid, low])
    positions = {v: i for i, tier in enumerate(result["tiers"]) for v in tier}

    for pair in result["pairwise"]:
        if not pair["separable"]:
            assert positions[pair["a"]] == positions[pair["b"]], (
                f"{pair['a']} and {pair['b']} are in different tiers but the tool says "
                f"they are not separable: {pair['reason']}"
            )
    # And where it does order, the ordering must hold for every member.
    for upper_tier, lower_tier in zip(result["tiers"], result["tiers"][1:]):
        for a in upper_tier:
            for b in lower_tier:
                pair = next(p for p in result["pairwise"] if {p["a"], p["b"]} == {a, b})
                assert pair["separable"], f"tier boundary between {a} and {b} is not supported"


def test_a_field_nothing_separates_is_reported_as_unranked():
    overlapping = [_assessment(f"v{i}", 40.0, 60.0, 50.0) for i in range(3)]
    result = rank(overlapping)
    assert len(result["tiers"]) == 1
    assert result["ranked"] is False
    assert result["fully_separable"] is False


def test_a_single_bidder_is_flagged_rather_than_declared_the_winner():
    result = rank([_assessment("only", 10.0, 90.0, 50.0)])
    assert result["single_bidder"] is True
    assert result["ranked"] is False


def test_end_to_end_a_wide_interval_bidder_does_not_split_the_field(tender_copy):
    """The regression that motivated the fix, run through the real pipeline."""
    tender = json.loads((tender_copy / "tender.json").read_text())
    delta = dict(tender["vendors"][1])
    delta.update({"vendor_id": "delta", "legal_name": "Delta", "questionnaire": ""})
    tender["vendors"].append(delta)
    (tender_copy / "tender.json").write_text(json.dumps(tender))

    run = assess_tender(str(tender_copy), mode="replay", samples=50)
    positions = {v: i for i, tier in enumerate(run.ranking["tiers"]) for v in tier}
    for pair in run.ranking["pairwise"]:
        if not pair["separable"]:
            assert positions[pair["a"]] == positions[pair["b"]]


# ==========================================================================
# A defective submission must never improve the bidder's position
# ==========================================================================


def test_a_corrupt_questionnaire_makes_a_bidder_worse_off_not_better(tender_copy):
    """Closes a loophole that made corrupting your own submission rational.

    An unparseable questionnaire used to leave the divergence category empty.
    An empty category scores as *unknown*, which widened the interval and
    deleted every contradiction — and under a dominance rule a wider interval
    is precisely what defeats being outranked. Submitting a corrupt file was a
    dominant strategy for a bidder facing demotion.
    """
    before = assess_tender(str(tender_copy), mode="replay", samples=50).vendor("meridian")

    (tender_copy / "questionnaire-meridian.json").write_text("{ this is not json")
    after_run = assess_tender(str(tender_copy), mode="replay", samples=50)
    after = after_run.vendor("meridian")

    assert after.upper <= before.upper, "corrupting the submission must not raise the upper bound"
    assert after.point <= before.point, "corrupting the submission must not raise the score"
    assert any("DIV-SUBMISSION" in f.check_id for f in after.findings)
    defect = next(f for f in after.findings if f.check_id == "DIV-SUBMISSION")
    assert defect.outcome == CheckOutcome.FAIL and defect.score == 0.0
    assert any("DIV-SUBMISSION" in w for w in after_run.warnings)


def test_a_missing_questionnaire_is_warned_about_and_widens_the_interval(tender_copy):
    tender = json.loads((tender_copy / "tender.json").read_text())
    for vendor in tender["vendors"]:
        if vendor["vendor_id"] == "nawras":
            vendor["questionnaire"] = ""
    (tender_copy / "tender.json").write_text(json.dumps(tender))

    run = assess_tender(str(tender_copy), mode="replay", samples=50)
    nawras = run.vendor("nawras")
    assert nawras.upper - nawras.lower > 0
    assert any("no questionnaire was submitted" in w for w in run.warnings)
    # No questionnaire is not the same defect as an unreadable one.
    assert not any(f.check_id == "DIV-SUBMISSION" for f in nawras.findings)


# ==========================================================================
# Buyer-authored configuration must fail loudly
# ==========================================================================


def test_a_typo_in_a_weight_name_is_reported_not_silently_absorbed(tender_copy):
    tender = json.loads((tender_copy / "tender.json").read_text())
    tender["weights"] = {"technical_hygeine": 0.5, "breach_history": 0.5}  # deliberate typo
    (tender_copy / "tender.json").write_text(json.dumps(tender))

    run = assess_tender(str(tender_copy), mode="replay", samples=50)
    assert any("technical_hygeine" in w and "not an evaluation criterion" in w for w in run.warnings)
    # The surviving criterion is still applied rather than everything collapsing.
    assert run.weights == {"breach_history": 1.0}


def test_weights_naming_nothing_real_fall_back_loudly():
    problems = validate_weights({"nonsense": 1.0})
    assert any("not an evaluation criterion" in p for p in problems)
    assert any("default weighting was applied" in p for p in problems)
    assert normalise_weights({"nonsense": 1.0})  # falls back rather than producing an empty model


def test_zero_and_negative_weights_are_rejected():
    assert any("must be positive" in p for p in validate_weights({"technical_hygiene": 0}))
    assert any("must be positive" in p for p in validate_weights({"technical_hygiene": -2}))
    assert any("not a number" in p for p in validate_weights({"technical_hygiene": "high"}))


def test_zero_samples_does_not_divide_by_zero():
    a = _assessment("a", 10.0, 20.0, 15.0)
    result = weight_sensitivity([a], None, samples=0)
    assert result["top1_stability"] is None


def test_unrankable_bidders_are_excluded_from_stability_not_sorted_last():
    """A bidder with no point estimate cannot make a ranking look stable."""
    rankable = _assessment("rankable", 10.0, 20.0, 15.0)
    rankable.categories = score_vendor(
        [Finding(check_id="A", title="A", category=Category.HYGIENE, weight=1,
                 outcome=CheckOutcome.PASS, score=1.0)]
    )[0]
    unrankable = _assessment("unrankable", 0.0, 100.0, None)
    unrankable.categories = score_vendor([])[0]

    result = weight_sensitivity([rankable, unrankable], None, samples=50)
    assert "unrankable" not in (result.get("bidders_included") or [])


# ==========================================================================
# Statistics: the claims are clustered, and the report must say so
# ==========================================================================


def _divergence(claim_id, verdict, digest):
    return Divergence(
        claim_id=claim_id, control_ref=claim_id, claim_text=claim_id,
        verdict=verdict, expected="x", observed="y", evidence_digests=[digest],
    )


def test_reliability_clusters_claims_that_share_one_observation():
    """Three claims read out of one HTTP response are not three trials."""
    clustered = [
        _divergence("a", DivergenceVerdict.CONTRADICTED, "headers-digest"),
        _divergence("b", DivergenceVerdict.CONTRADICTED, "headers-digest"),
        _divergence("c", DivergenceVerdict.CONTRADICTED, "headers-digest"),
        _divergence("d", DivergenceVerdict.CORROBORATED, "dns-digest"),
    ]
    result = reliability(clustered)
    assert result["claims_testable"] == 4
    assert result["evidence_clusters"] == 2, "claims sharing an observation are one source"
    assert result["largest_cluster"] == 3
    assert result["clusters_corroborated"] == 1


def test_the_cluster_interval_is_never_narrower_than_the_claim_interval():
    """Clustering must be conservative — that is the whole reason for it."""
    items = [_divergence(f"c{i}", DivergenceVerdict.CORROBORATED, "one-source") for i in range(10)]
    result = reliability(items)
    cluster_width = result["ci_upper"] - result["ci_lower"]
    claim_width = result["claim_level_ci_upper"] - result["claim_level_ci_lower"]
    assert cluster_width >= claim_width


def test_a_cluster_counts_as_corroborated_only_if_every_claim_on_it_survived():
    mixed = [
        _divergence("a", DivergenceVerdict.CORROBORATED, "shared"),
        _divergence("b", DivergenceVerdict.CONTRADICTED, "shared"),
    ]
    assert reliability(mixed)["clusters_corroborated"] == 0


def test_no_testable_claim_reports_nothing_rather_than_zero_percent():
    result = reliability([_divergence("a", DivergenceVerdict.UNTESTABLE, "")])
    assert result["evidence_clusters"] == 0
    assert result["claims_testable"] == 0


# ==========================================================================
# Exposed services — the brief requirement, met without port scanning
# ==========================================================================


def test_exposed_services_are_unknown_without_a_dataset_never_assumed_clean():
    vendor = Vendor(vendor_id="v", legal_name="V", primary_domain="v.example")
    findings = run_checks(CheckContext(vendor=vendor, index=EvidenceIndex([], "v.example")))
    check = next(f for f in findings if f.check_id == "SUR-005")
    assert check.outcome == CheckOutcome.UNKNOWN
    assert check.score is None
    assert "does not port scan" in check.observation


def test_high_risk_exposed_services_fail_outright():
    evidence = Evidence(
        collector="exposure", kind="exposed_services", target="v.example",
        status=EvidenceStatus.OBSERVED, observed_at="2026-09-05T09:00:00+00:00",
        data={
            "services": [{"port": 3389, "high_risk": True, "risk_label": "RDP", "expected": False}],
            "high_risk": [{"port": 3389, "high_risk": True, "risk_label": "RDP", "expected": False}],
            "as_of": "2026-09-02",
        },
    )
    vendor = Vendor(vendor_id="v", legal_name="V", primary_domain="v.example")
    findings = run_checks(CheckContext(vendor=vendor, index=EvidenceIndex([evidence], "v.example")))
    check = next(f for f in findings if f.check_id == "SUR-005")
    assert check.outcome == CheckOutcome.FAIL and check.score == 0.0
    assert "RDP" in check.observation


def test_the_bundled_scenario_exercises_exposed_services():
    run = assess_tender(str(SCENARIO), mode="replay", samples=50)
    meridian = next(f for f in run.vendor("meridian").findings if f.check_id == "SUR-005")
    assert meridian.outcome == CheckOutcome.FAIL
    nawras = next(f for f in run.vendor("nawras").findings if f.check_id == "SUR-005")
    assert nawras.outcome == CheckOutcome.PASS
    # Orion has no exposure record, which must read as unknown rather than clean.
    orion = next(f for f in run.vendor("orion").findings if f.check_id == "SUR-005")
    assert orion.outcome == CheckOutcome.UNKNOWN


def test_a_corrupt_exposure_corpus_leaves_the_check_unknown(tmp_path):
    from bayyina.collectors.public_data import ExposureCollector

    corpus = tmp_path / "exposure_corpus.json"
    corpus.write_text("{not json at all")
    evidence = ExposureCollector(str(corpus))._live("v.example")
    assert evidence.status == EvidenceStatus.ERROR


# ==========================================================================
# Report generation must survive degenerate runs
# ==========================================================================


def test_reports_render_for_a_tender_with_no_bidders(tmp_path):
    from bayyina.report import comparison

    (tmp_path / "tender.json").write_text(json.dumps(
        {"tender_id": "EMPTY", "title": "Empty", "buyer": "B", "vendors": []}))
    (tmp_path / "cassette.json").write_text(json.dumps({"meta": {}, "entries": {}}))
    run = assess_tender(str(tmp_path), mode="replay", samples=10)
    html = comparison(run)          # used to raise IndexError
    assert "EMPTY" in html or "Empty" in html


def test_duplicate_vendor_ids_are_warned_about(tender_copy):
    tender = json.loads((tender_copy / "tender.json").read_text())
    tender["vendors"].append(dict(tender["vendors"][0]))
    (tender_copy / "tender.json").write_text(json.dumps(tender))
    run = assess_tender(str(tender_copy), mode="replay", samples=10)
    assert any("appears 2 times" in w for w in run.warnings)


def test_thin_evidence_produces_a_warning_not_a_confident_score(tender_copy):
    run = assess_tender(str(tender_copy), mode="replay", samples=10)
    orion = run.vendor("orion")
    assert orion.coverage < 0.7
    assert any(orion.vendor.vendor_id in w and "could be observed" in w for w in run.warnings)
