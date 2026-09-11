"""Scoring model properties.

These are the tests that matter most, because the scoring model is where a
tool like this usually goes wrong: by quietly converting an unknown into a
number, or by asserting a ranking the evidence does not support.
"""

from __future__ import annotations

import pytest

from bayyina.models import Category, CheckOutcome, Finding, Vendor, VendorAssessment
from bayyina.scoring import (
    DEFAULT_WEIGHTS,
    dominates,
    leave_one_category_out,
    normalise_weights,
    rank,
    score_category,
    score_vendor,
    weight_sensitivity,
)


def finding(check_id, category, weight, outcome, score):
    return Finding(
        check_id=check_id, title=check_id, category=category,
        weight=weight, outcome=outcome, score=score,
    )


def assessment(vendor_id, findings, weights=None):
    categories, point, lower, upper, coverage = score_vendor(findings, weights)
    return VendorAssessment(
        vendor=Vendor(vendor_id=vendor_id, legal_name=vendor_id, primary_domain=f"{vendor_id}.example"),
        findings=findings, categories=categories, point=point,
        lower=lower, upper=upper, coverage=coverage,
    )


# -- the central invariant -------------------------------------------------


def test_point_estimate_always_lies_within_the_supported_range():
    """The point estimate can never fall outside the bounds it is bracketed by.

    This is a proof obligation, not a nicety: the interval is what licenses the
    ranking, so a point outside it would make the ranking rule incoherent.
    """
    scenarios = [
        [finding("A", Category.HYGIENE, 3, CheckOutcome.PASS, 1.0)],
        [finding("A", Category.HYGIENE, 3, CheckOutcome.FAIL, 0.0)],
        [
            finding("A", Category.HYGIENE, 3, CheckOutcome.PASS, 1.0),
            finding("B", Category.HYGIENE, 2, CheckOutcome.UNKNOWN, None),
        ],
        [
            finding("A", Category.HYGIENE, 1, CheckOutcome.PARTIAL, 0.5),
            finding("B", Category.BREACH, 4, CheckOutcome.UNKNOWN, None),
            finding("C", Category.SURFACE, 2, CheckOutcome.FAIL, 0.0),
        ],
    ]
    for findings in scenarios:
        _, point, lower, upper, _ = score_vendor(findings)
        assert point is None or lower - 1e-6 <= point <= upper + 1e-6, (point, lower, upper)


def test_unknown_is_never_scored_as_pass_or_fail():
    """An unobserved check widens the interval; it does not move the estimate."""
    observed = [finding("A", Category.HYGIENE, 3, CheckOutcome.PASS, 1.0)]
    with_unknown = observed + [finding("B", Category.HYGIENE, 3, CheckOutcome.UNKNOWN, None)]

    _, point_a, low_a, high_a, cov_a = score_vendor(observed)
    _, point_b, low_b, high_b, cov_b = score_vendor(with_unknown)

    assert point_a == point_b, "an unknown check must not change the point estimate"
    assert high_b - low_b > high_a - low_a, "an unknown check must widen the interval"
    assert cov_b < cov_a, "an unknown check must reduce coverage"


def test_not_applicable_leaves_the_denominator_entirely():
    """A control with nothing to bite on must not cost the vendor certainty."""
    base = [finding("A", Category.BREACH, 3, CheckOutcome.PASS, 1.0)]
    with_na = base + [finding("B", Category.BREACH, 5, CheckOutcome.NOT_APPLICABLE, None)]
    with_unknown = base + [finding("B", Category.BREACH, 5, CheckOutcome.UNKNOWN, None)]

    na = score_category(Category.BREACH, with_na, 1.0)
    unknown = score_category(Category.BREACH, with_unknown, 1.0)
    plain = score_category(Category.BREACH, base, 1.0)

    assert (na.lower, na.upper, na.coverage) == (plain.lower, plain.upper, plain.coverage)
    assert unknown.coverage < na.coverage
    assert unknown.upper - unknown.lower > na.upper - na.lower


def test_zero_evidence_yields_the_widest_possible_interval():
    """Knowing nothing must produce the full range, not a middling score."""
    findings = [finding(f"C{i}", Category.HYGIENE, 1, CheckOutcome.UNKNOWN, None) for i in range(5)]
    _, point, lower, upper, coverage = score_vendor(findings)
    assert point is None
    assert (lower, upper) == (0.0, 100.0)
    assert coverage == 0.0


def test_a_category_with_no_checks_is_maximally_uncertain():
    """A bidder that submitted no questionnaire cannot be credited for it."""
    findings = [finding("A", Category.HYGIENE, 1, CheckOutcome.PASS, 1.0)]
    categories, _, lower, upper, _ = score_vendor(findings)
    divergence = next(c for c in categories if c.category == Category.DIVERGENCE)
    assert divergence.point is None
    assert (divergence.lower, divergence.upper) == (0.0, 1.0)
    assert upper > lower


# -- ranking ---------------------------------------------------------------


def fully_covered(vendor_id, score):
    """A vendor with one observed check in every category.

    Coverage has to be complete for a dominance test to mean anything: a
    bidder assessed on one category out of five has an interval so wide that
    refusing to rank it is the correct answer, which is what the two tests
    below would otherwise be measuring.
    """
    outcome = (CheckOutcome.PASS if score >= 1.0
               else CheckOutcome.FAIL if score <= 0.0 else CheckOutcome.PARTIAL)
    return assessment(vendor_id, [
        finding(f"{cat[:3].upper()}-1", cat, 1, outcome, score) for cat in Category.ALL
    ])


def test_ranking_requires_non_overlapping_intervals():
    strong = fully_covered("strong", 1.0)
    weak = fully_covered("weak", 0.0)
    assert strong.coverage == 1.0 and weak.coverage == 1.0
    assert dominates(strong, weak)
    assert not dominates(weak, strong)


def test_partial_coverage_defeats_dominance_against_a_middling_vendor():
    """A perfect score on a fifth of the evidence buys no ranking authority.

    The thin vendor's point estimate is 100 and the well-evidenced vendor's is
    50, so any point-estimate ranking would put the thin one first. It must
    not, because four fifths of its evidence is missing: its supported range
    reaches down to 25, which overlaps the other's. The comparison is refused.

    Note the boundary this test sits on. Dominance *can* legitimately hold on
    thin evidence — if the other vendor's best case is worse than the thin
    vendor's worst case, the ordering follows regardless of coverage. The rule
    is about disjoint intervals, not about coverage as such, and that is the
    correct rule.
    """
    perfect_but_thin = assessment("thin", [finding("A", Category.HYGIENE, 1, CheckOutcome.PASS, 1.0)])
    middling = fully_covered("middling", 0.5)

    assert perfect_but_thin.point == 100.0 and middling.point == 50.0
    assert perfect_but_thin.coverage < 0.3 and middling.coverage == 1.0
    assert not dominates(perfect_but_thin, middling), (
        "a high point estimate on thin evidence must not license a ranking"
    )
    assert not dominates(middling, perfect_but_thin)


def test_overlapping_intervals_are_reported_as_not_separable():
    """The behaviour the whole model exists for: refusing to invent a decision."""
    known_poor = assessment("known_poor", [
        finding("A", Category.HYGIENE, 3, CheckOutcome.FAIL, 0.0),
        finding("B", Category.HYGIENE, 3, CheckOutcome.PARTIAL, 0.5),
        finding("C", Category.BREACH, 3, CheckOutcome.PASS, 1.0),
    ])
    unknown_middle = assessment("unknown_middle", [
        finding("A", Category.HYGIENE, 3, CheckOutcome.PASS, 1.0),
        finding("B", Category.HYGIENE, 3, CheckOutcome.UNKNOWN, None),
        finding("C", Category.BREACH, 3, CheckOutcome.UNKNOWN, None),
    ])
    result = rank([known_poor, unknown_middle])
    assert not result["fully_separable"]
    assert any(len(tier) > 1 for tier in result["tiers"])
    pair = result["pairwise"][0]
    assert pair["separable"] is False
    assert "overlap" in pair["reason"]


def test_ranking_is_total_when_every_interval_is_disjoint():
    a = fully_covered("a", 1.0)
    b = fully_covered("b", 0.0)
    result = rank([a, b])
    assert result["fully_separable"]
    assert result["tiers"] == [["a"], ["b"]]


def test_ranking_handles_an_empty_field():
    result = rank([])
    assert result["tiers"] == []
    assert result["fully_separable"] is True


# -- weights ---------------------------------------------------------------


def test_weights_normalise_to_one():
    assert pytest.approx(sum(normalise_weights({"a": 2, "b": 2}).values()), abs=1e-6) == 1.0
    assert pytest.approx(sum(normalise_weights(None).values()), abs=1e-6) == 1.0
    assert pytest.approx(sum(normalise_weights({}).values()), abs=1e-6) == 1.0
    # Negative and zero weights are dropped rather than inverting a criterion.
    assert "bad" not in normalise_weights({"good": 1, "bad": -3})


def test_sensitivity_is_reproducible_for_a_given_seed():
    a = assessment("a", [finding("X", Category.HYGIENE, 1, CheckOutcome.PASS, 1.0)])
    b = assessment("b", [finding("X", Category.HYGIENE, 1, CheckOutcome.FAIL, 0.0)])
    first = weight_sensitivity([a, b], DEFAULT_WEIGHTS, samples=200, seed=7)
    second = weight_sensitivity([a, b], DEFAULT_WEIGHTS, samples=200, seed=7)
    assert first == second
    third = weight_sensitivity([a, b], DEFAULT_WEIGHTS, samples=200, seed=8)
    assert third["seed"] != first["seed"]


def test_sensitivity_survives_an_empty_field():
    result = weight_sensitivity([], DEFAULT_WEIGHTS, samples=10)
    assert result["top1_stability"] is None


def test_leave_one_out_covers_every_declared_category():
    a = assessment("a", [finding("X", Category.HYGIENE, 1, CheckOutcome.PASS, 1.0)])
    results = leave_one_category_out([a], DEFAULT_WEIGHTS)
    assert {r["dropped_category"] for r in results} == set(DEFAULT_WEIGHTS)
