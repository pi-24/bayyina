"""The scoring model.

Three commitments, each of which exists to survive a specific challenge.

1. Unknowns are bounded, never imputed.
   A check we could not observe is not scored 0 (which would punish a bidder
   for our blind spot) and not scored 1 (which would reward opacity). It is
   left out of the point estimate and instead widens an interval: the lower
   bound assumes every unobserved check would have failed, the upper bound
   assumes every one would have passed. The interval is therefore a statement
   about *our evidence*, not a confidence interval about the vendor, and we
   say so in the output. There is no distributional assumption to attack
   because we make none.

2. The composite is an ordinal triage device and is labelled as one.
   Jack Jones' critique of risk scoring is correct: multiplying ordinal
   severities by ordinal criticalities and calling the product "risk" is not
   quantification, because there is no unit. So Bayyina does not claim to
   measure risk. It produces a defensible ranking and a findings list. Where
   we do make a probabilistic statement — attestation reliability — it carries
   an explicit interval and a named estimator.

3. Ranking requires separation.
   A vendor is ranked above another only when its lower bound exceeds the
   other's upper bound. If the intervals overlap, the tool reports the pair as
   not separable on the available evidence and refuses to order them. This is
   the single most important behaviour in the system: the failure mode of every
   scoring tool is manufacturing a decision the evidence does not support, and
   in a procurement that is the failure that ends in a challenge.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

from .models import Category, CategoryScore, CheckOutcome, Finding, VendorAssessment
from .stats import perturb_weights

# Default category weights. These are a *default*, not a constant: UAE Federal
# Law 11/2023 Art. 22(4) requires the buyer to publish the weight of each
# evaluation criterion in advance, so the buyer sets them in the tender file
# and every report prints the set that was used.
DEFAULT_WEIGHTS: Dict[str, float] = {
    Category.DIVERGENCE: 0.25,
    Category.HYGIENE: 0.25,
    Category.BREACH: 0.20,
    Category.ATTESTATION: 0.15,
    Category.SURFACE: 0.15,
}


def validate_weights(weights: Optional[Dict[str, float]]) -> List[str]:
    """Return human-readable problems with a buyer-supplied weight set.

    A typo in a criterion name used to be silent and catastrophic: every
    finding was still computed and then discarded against a criterion that
    does not exist, and the tool reported a coverage of 0% with a straight
    face and exit code 0. The buyer hand-authors this file, so a typo is a
    realistic input, and it must be loud.
    """
    problems: List[str] = []
    if not weights:
        return problems
    for key, value in weights.items():
        if key not in Category.ALL:
            problems.append(
                f"weight '{key}' is not an evaluation criterion and was ignored "
                f"(valid criteria: {', '.join(sorted(Category.ALL))})"
            )
            continue
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            problems.append(f"weight '{key}' is not a number ({value!r}) and was ignored")
            continue
        if numeric <= 0:
            problems.append(f"weight '{key}' is {numeric} and was ignored; weights must be positive")
    known = {k: v for k, v in weights.items() if k in Category.ALL}
    if known and not any(_positive(v) for v in known.values()):
        problems.append("no usable weights were supplied; the default weighting was applied instead")
    elif weights and not known:
        problems.append("none of the supplied weights named a real criterion; the default weighting was applied instead")
    return problems


def _positive(value) -> bool:
    try:
        return float(value) > 0
    except (TypeError, ValueError):
        return False


def normalise_weights(weights: Optional[Dict[str, float]]) -> Dict[str, float]:
    """Normalise to sum 1, keeping only positive weights on real criteria."""
    source = weights if weights else DEFAULT_WEIGHTS
    cleaned = {k: float(v) for k, v in source.items() if k in Category.ALL and _positive(v)}
    if not cleaned:
        cleaned = dict(DEFAULT_WEIGHTS)
    total = sum(cleaned.values())
    return {k: round(v / total, 6) for k, v in cleaned.items()}


def score_category(category: str, findings: Sequence[Finding], weight: float) -> CategoryScore:
    # Checks that do not apply leave the denominator entirely; checks that
    # apply but could not be observed stay in it and widen the interval.
    relevant = [
        f for f in findings
        if f.category == category and f.outcome != CheckOutcome.NOT_APPLICABLE
    ]
    total_weight = sum(f.weight for f in relevant)
    scored = [f for f in relevant if f.is_scored]
    observed_weight = sum(f.weight for f in scored)
    weighted_sum = sum(f.weight * (f.score or 0.0) for f in scored)

    if total_weight <= 0:
        # The category has no checks at all for this vendor — most commonly
        # because no questionnaire was submitted. Coverage is zero and the
        # bounds are maximally wide, which is the correct statement.
        return CategoryScore(category, weight, None, 0.0, 1.0, 0.0, 0, 0)

    point = (weighted_sum / observed_weight) if observed_weight > 0 else None
    lower = weighted_sum / total_weight                       # unobserved assumed to fail
    upper = (weighted_sum + (total_weight - observed_weight)) / total_weight  # assumed to pass
    coverage = observed_weight / total_weight
    return CategoryScore(
        category=category,
        weight=weight,
        point=round(point, 6) if point is not None else None,
        lower=round(lower, 6),
        upper=round(upper, 6),
        coverage=round(coverage, 6),
        scored_checks=len(scored),
        total_checks=len(relevant),
    )


def score_vendor(
    findings: Sequence[Finding], weights: Optional[Dict[str, float]] = None
) -> Tuple[List[CategoryScore], Optional[float], float, float, float]:
    """Compute category scores and the composite interval, on a 0–100 scale."""
    weights = normalise_weights(weights)
    categories = [score_category(cat, findings, w) for cat, w in sorted(weights.items())]

    total_weight = sum(c.weight for c in categories) or 1.0
    lower = sum(c.weight * c.lower for c in categories) / total_weight
    upper = sum(c.weight * c.upper for c in categories) / total_weight
    coverage = sum(c.weight * c.coverage for c in categories) / total_weight

    scored = [c for c in categories if c.point is not None]
    if scored:
        scored_weight = sum(c.weight for c in scored)
        point = sum(c.weight * (c.point or 0.0) for c in scored) / scored_weight
    else:
        point = None

    return (
        categories,
        round(point * 100, 2) if point is not None else None,
        round(lower * 100, 2),
        round(upper * 100, 2),
        round(coverage, 4),
    )


def composite_point(
    categories: Sequence[CategoryScore], weights: Dict[str, float]
) -> Optional[float]:
    """Recompute only the point estimate under an alternative weight vector."""
    scored = [c for c in categories if c.point is not None and weights.get(c.category, 0) > 0]
    if not scored:
        return None
    total = sum(weights[c.category] for c in scored)
    if total <= 0:
        return None
    return sum(weights[c.category] * (c.point or 0.0) for c in scored) / total * 100


# ---------------------------------------------------------------------------
# Ranking under uncertainty
# ---------------------------------------------------------------------------


def dominates(a: VendorAssessment, b: VendorAssessment) -> bool:
    """A strictly outranks B only when their score intervals do not overlap."""
    return a.lower > b.upper


def rank(assessments: Sequence[VendorAssessment]) -> Dict[str, object]:
    """Produce tiers in which the ordering actually holds.

    The naive construction — repeatedly take the undominated vendors as the
    next tier — is wrong, and wrong in the direction that matters. Being
    *undominated* is not the same as *dominating everyone below you*: a vendor
    with a very wide interval is undominated simply because nothing can
    separate it, so it lands in tier 1 while a vendor it cannot be separated
    from lands in tier 2. The output then asserts an ordering that the pairwise
    table on the same page denies.

    So after the initial layering we merge downward until the tier structure is
    sound: every member of tier i must dominate every member of tier i+1. If a
    vendor in an upper tier cannot be separated from one below, the two tiers
    are not really ordered and are merged into one. In the limit this collapses
    to a single tier, which is the honest answer when nothing separates
    anything — the pairwise table then carries the detail.
    """
    remaining = list(assessments)
    tiers: List[List[VendorAssessment]] = []
    guard = 0
    while remaining and guard < 200:
        guard += 1
        top = [v for v in remaining if not any(dominates(o, v) for o in remaining if o is not v)]
        if not top:  # cycles are impossible under a strict interval order; be safe
            top = list(remaining)
        tiers.append(top)
        top_ids = {id(v) for v in top}
        remaining = [v for v in remaining if id(v) not in top_ids]

    # Merge downward until every tier dominates the whole of the next one.
    merged = True
    while merged and len(tiers) > 1:
        merged = False
        for i in range(len(tiers) - 1):
            upper, lower = tiers[i], tiers[i + 1]
            if not all(dominates(a, b) for a in upper for b in lower):
                tiers[i] = upper + lower
                del tiers[i + 1]
                merged = True
                break

    for tier in tiers:
        tier.sort(key=lambda v: (-(v.point if v.point is not None else -1), v.vendor.vendor_id))

    pairs = []
    ordered = sorted(assessments, key=lambda v: -(v.point if v.point is not None else -1))
    for i, a in enumerate(ordered):
        for b in ordered[i + 1:]:
            separable = dominates(a, b) or dominates(b, a)
            pairs.append(
                {
                    "a": a.vendor.vendor_id,
                    "b": b.vendor.vendor_id,
                    "separable": separable,
                    "reason": (
                        f"{a.vendor.vendor_id} lower bound {a.lower} > {b.vendor.vendor_id} upper bound {b.upper}"
                        if dominates(a, b)
                        else f"{b.vendor.vendor_id} lower bound {b.lower} > {a.vendor.vendor_id} upper bound {a.upper}"
                        if dominates(b, a)
                        else f"intervals overlap ([{a.lower}, {a.upper}] vs [{b.lower}, {b.upper}])"
                    ),
                }
            )

    tier_ids = [[v.vendor.vendor_id for v in tier] for tier in tiers]
    return {
        "tiers": tier_ids,
        "indicative_order": [v.vendor.vendor_id for v in ordered],
        "pairwise": pairs,
        "fully_separable": all(p["separable"] for p in pairs) if pairs else True,
        "ranked": len(tier_ids) > 1,
        "single_bidder": len(assessments) == 1,
    }


# ---------------------------------------------------------------------------
# Sensitivity analysis
# ---------------------------------------------------------------------------


def weight_sensitivity(
    assessments: Sequence[VendorAssessment],
    weights: Dict[str, float],
    samples: int = 2000,
    seed: int = 20260911,
) -> Dict[str, object]:
    """How much of the result is the evidence, and how much is our weighting?

    Draws weight vectors from a Dirichlet centred on the declared weights and
    re-ranks under each. Reports how often the leader stays the leader and how
    often the whole order is preserved. Deterministic for a given seed.
    """
    weights = normalise_weights(weights)
    samples = max(int(samples), 0)
    # A vendor with no point estimate has nothing to be stable about. Including
    # it (sorted last on a sentinel) would inflate "order unchanged" with a
    # position the tool never claimed in the first place.
    assessments = [a for a in assessments if a.point is not None]
    baseline = sorted(assessments, key=lambda v: -(v.point or 0.0))
    if not baseline or samples <= 0:
        return {
            "samples": samples,
            "seed": seed,
            "declared_weights": weights,
            "top1_stability": None,
            "order_stability": None,
            "excluded_unrankable": True if not baseline else False,
            "method": "No bidder had a point estimate to rank, or zero samples were requested.",
        }
    baseline_top = baseline[0].vendor.vendor_id
    baseline_order = [v.vendor.vendor_id for v in baseline]
    scored_ids = [a.vendor.vendor_id for a in assessments]

    top_hits = 0
    order_hits = 0
    leader_counts: Dict[str, int] = {}
    for vector in perturb_weights(weights, samples=samples, seed=seed):
        scored = []
        for assessment in assessments:
            point = composite_point(assessment.categories, vector)
            if point is None:
                continue
            scored.append((point, assessment.vendor.vendor_id))
        if not scored:
            continue
        scored.sort(key=lambda t: (-t[0], t[1]))
        order = [vid for _, vid in scored]
        leader_counts[order[0]] = leader_counts.get(order[0], 0) + 1
        if order[0] == baseline_top:
            top_hits += 1
        if order == baseline_order:
            order_hits += 1

    return {
        "samples": samples,
        "seed": seed,
        "declared_weights": weights,
        "baseline_leader": baseline_top,
        "top1_stability": round(top_hits / samples, 4),
        "order_stability": round(order_hits / samples, 4),
        "leader_distribution": {k: round(v / samples, 4) for k, v in sorted(leader_counts.items())},
        "bidders_included": scored_ids,
        "method": (
            "Dirichlet perturbation of the declared category weights (alpha = 40 x weight), "
            "re-ranking on the point estimate under each sample. This measures the stability of "
            "the *indicative* point order, not of the dominance tiers, which do not depend on "
            "the weighting in the same way. Bidders with no point estimate are excluded."
        ),
    }


def leave_one_category_out(
    assessments: Sequence[VendorAssessment], weights: Dict[str, float]
) -> List[Dict[str, object]]:
    """Recompute the ranking with each category removed in turn.

    Fully deterministic and easier to interpret than the Dirichlet analysis:
    it answers "would dropping this criterion entirely change who wins?".
    """
    weights = normalise_weights(weights)
    results = []
    for dropped in sorted(weights):
        reduced = {k: v for k, v in weights.items() if k != dropped}
        if not reduced:
            continue
        reduced = normalise_weights(reduced)
        scored = []
        for assessment in assessments:
            point = composite_point(assessment.categories, reduced)
            if point is None:
                continue
            scored.append((point, assessment.vendor.vendor_id))
        scored.sort(key=lambda t: (-t[0], t[1]))
        results.append(
            {
                "dropped_category": dropped,
                "label": Category.LABELS.get(dropped, dropped),
                "order": [vid for _, vid in scored],
                "leader": scored[0][1] if scored else None,
            }
        )
    return results
