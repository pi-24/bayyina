"""End-to-end tests against the bundled demonstration tender.

These pin the behaviours the tool exists to demonstrate. If a refactor breaks
one of them, the tool has stopped doing the thing it claims to do.
"""

from __future__ import annotations

import os

import pytest

from bayyina.divergence import reliability
from bayyina.engine import assess_tender, write_outputs
from bayyina.models import CheckOutcome, DivergenceVerdict
from bayyina.report import comparison, vendor_report

TENDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "scenarios", "MDG-2026-114")


@pytest.fixture(scope="module")
def run():
    return assess_tender(TENDER, mode="replay", samples=500)


def test_the_assessment_runs_offline_with_no_network(run):
    assert run.cassette_stats["mode"] == "replay"
    assert run.cassette_stats["recorded"] == 0
    assert run.cassette_stats["misses"] == 0
    assert len(run.assessments) == 3


def test_running_twice_produces_an_identical_evidence_chain():
    first = assess_tender(TENDER, mode="replay", samples=200)
    second = assess_tender(TENDER, mode="replay", samples=200)
    assert first.ledger.head == second.ledger.head
    assert [a.point for a in first.assessments] == [a.point for a in second.assessments]
    assert first.ranking == second.ranking
    assert first.sensitivity == second.sensitivity


def test_the_evidence_ledger_verifies(run):
    ok, problems = run.ledger.verify()
    assert ok, problems


def test_the_paper_favourite_is_overturned_by_evidence(run):
    """The point of the whole tool, expressed as an assertion.

    Meridian submits the strongest paper bid — ISO 27001, SOC 2 Type II, a
    near-perfect questionnaire. Nawras submits less. On evidence the order
    reverses, and the tool can say exactly why.
    """
    meridian = run.vendor("meridian")
    nawras = run.vendor("nawras")
    assert nawras.point > meridian.point
    assert nawras.lower > meridian.upper, "the reversal must survive the uncertainty, not just the point estimate"
    assert run.ranking["tiers"][0] == ["nawras"]


def test_contradicted_attestations_are_found_and_attributed(run):
    meridian = run.vendor("meridian")
    contradicted = [d for d in meridian.divergences if d.verdict == DivergenceVerdict.CONTRADICTED]
    assert len(contradicted) >= 8

    by_predicate = {c.check_ids[0]: c for c in contradicted if c.check_ids}
    # The DMARC contradiction is the canonical example: the bidder claimed an
    # enforcing policy and publishes p=none.
    assert "dmarc_enforced" in by_predicate
    assert "p=none" in by_predicate["dmarc_enforced"].observed
    assert by_predicate["dmarc_enforced"].control_ref.startswith("CAIQ")
    # The certification scope contradiction is the one no external rating finds.
    assert "certification_scope_covers_delivery" in by_predicate


def test_a_clean_bidder_has_no_contradictions(run):
    nawras = run.vendor("nawras")
    assert not [d for d in nawras.divergences if d.verdict == DivergenceVerdict.CONTRADICTED]
    assert run.reliability["nawras"]["point"] == 1.0


def test_attestation_reliability_is_reported_as_an_interval(run):
    for vendor_id in ("meridian", "nawras", "orion"):
        rel = run.reliability[vendor_id]
        assert rel["ci_lower"] <= rel["point"] <= rel["ci_upper"]
        assert rel["claims_untestable"] > 0
        assert "not a random sample" in rel["caveat"]
    # A perfect but small sample must not be reported as certainty.
    assert run.reliability["nawras"]["ci_lower"] < 0.9


def test_the_tool_refuses_to_rank_bidders_it_cannot_separate(run):
    """Orion's evidence coverage is too thin to place it against Meridian."""
    orion = run.vendor("orion")
    assert orion.coverage < 0.7
    assert orion.upper - orion.lower > 30

    unseparable = [p for p in run.ranking["pairwise"] if not p["separable"]]
    assert unseparable, "the demo must exercise the refuse-to-rank behaviour"
    pair = {unseparable[0]["a"], unseparable[0]["b"]}
    assert pair == {"orion", "meridian"}
    assert any(len(tier) > 1 for tier in run.ranking["tiers"])


def test_unobservable_controls_become_unknowns_and_information_requests(run):
    orion = run.vendor("orion")
    unknowns = [f for f in orion.findings if f.outcome == CheckOutcome.UNKNOWN]
    assert len(unknowns) >= 5
    # A client-certificate-protected endpoint means TLS is genuinely unobservable.
    assert {"TLS-001", "TLS-002", "TLS-003"} <= {f.check_id for f in unknowns}
    assert all(f.score is None for f in unknowns)

    requests = run.conditions["orion"]["information_requests"]
    assert len(requests) >= len(unknowns)


def test_scope_mis_certification_is_caught_and_routed(run):
    meridian = run.vendor("meridian")
    scope = next(f for f in meridian.findings if f.check_id == "ATT-004")
    assert scope.outcome == CheckOutcome.FAIL
    assert "Dubai office" in scope.observation

    # Where scope is merely unstated, it must go to a human rather than pass.
    orion_scope = next(f for f in run.vendor("orion").findings if f.check_id == "ATT-004")
    assert orion_scope.outcome == CheckOutcome.NEEDS_HUMAN
    assert orion_scope.score is None


def test_soc2_is_reported_as_unverifiable_rather_than_verified(run):
    meridian = run.vendor("meridian")
    att = next(f for f in meridian.findings if f.check_id == "ATT-001")
    assert "cannot be verified" in att.observation


def test_bid_field_concentration_is_detected(run):
    conc = run.concentration
    shared = {(s["dependency_type"], tuple(s["vendors"])) for s in conc["shared_dependencies"]}
    assert ("mail_provider", ("meridian", "orion")) in shared
    assert ("dns_provider", ("meridian", "orion")) in shared
    assert ("edge_provider", ("meridian", "orion")) in shared

    warnings = conc["diversification_warnings"]
    assert warnings, "sharing three dependency categories must raise a diversification warning"
    assert {warnings[0]["a"], warnings[0]["b"]} == {"meridian", "orion"}
    assert "nawras" not in [v for w in warnings for v in (w["a"], w["b"])]


def test_the_result_does_not_depend_on_the_chosen_weights(run):
    assert run.sensitivity["top1_stability"] == 1.0
    assert all(l["leader"] == "nawras" for l in run.leave_one_out)


def test_contract_conditions_are_generated_and_traceable(run):
    conditions = run.conditions["meridian"]
    precedents = conditions["conditions_precedent"]
    assert precedents, "contradicted attestations must become conditions precedent"
    for condition in precedents:
        assert condition["clause"]
        assert condition["verification"]

    contract = conditions["contract_conditions"]
    assert any(c["id"] == "CC-SUBPROC" for c in contract), "sub-processor register is always required"
    for condition in contract:
        assert condition["deadline_days"] > 0
        # Every obligation must name the check that re-tests it.
        assert condition["source_check"]

    # A concentration condition must attach to both affected bidders only.
    assert any("CONC" in c["id"] for c in run.conditions["meridian"]["contract_conditions"])
    assert not any("CONC" in c["id"] for c in run.conditions["nawras"]["contract_conditions"])


def test_high_criticality_shortens_remediation_windows(run):
    """A HIGH-criticality contract must not inherit generic 90-day windows."""
    for condition in run.conditions["meridian"]["contract_conditions"]:
        if condition["severity"] == "HIGH":
            assert condition["deadline_days"] <= 15


def test_reports_render_and_are_self_contained(run, tmp_path):
    html = comparison(run)
    assert "<svg" in html and "Bayyina" in html
    assert "http://" not in html.replace("http://www.w3.org", "")
    assert "Demonstration scenario" in html, "the synthetic notice must be unmissable"

    for assessment in run.assessments:
        page = vendor_report(run, assessment)
        assert assessment.vendor.legal_name in page
        assert "Evidence integrity" in page
        assert run.ledger.head[:16] in page


def test_the_output_bundle_is_written(run, tmp_path):
    paths = write_outputs(run, str(tmp_path))
    assert os.path.exists(paths["assessment"])
    assert os.path.exists(paths["ledger"])
    assert os.path.exists(paths["manifest"])
