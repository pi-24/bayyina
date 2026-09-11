"""Small statistical helpers, written out so the method is inspectable.

Deliberate position on modelling
--------------------------------
Bayyina contains no machine learning, and that is a decision rather than an
omission. Two reasons, both of which we would rather state than be asked:

1. There is no adequate labelled dataset. A model trained on public breach
   disclosures learns *disclosure*, not compromise. Sarabi, Naghizadeh, Liu &
   Liu (Journal of Cybersecurity, 2016) achieved roughly 90% TP / 11% FP
   predicting disclosed breaches from business profile data alone — industry,
   size and web traffic rank, with no security measurements at all. A
   technical rating that performs similarly may be reproducing firmographics.
   Fitting a model here would produce a number whose apparent accuracy came
   from the wrong variable.

2. It would be legally awkward. UAE Federal Law No. 11 of 2023 Art. 22(3)
   requires non-financial evaluation criteria to be objective and quantifiable,
   Art. 22(4) requires each criterion's weight to be published in advance, and
   Art. 29 entitles an unsuccessful bidder to the strengths and weaknesses of
   its bid. A fitted model with learned weights satisfies none of those
   comfortably.

So the scoring function is deterministic and published. Where we do make a
statistical statement — the reliability of a vendor's attestations — we use an
interval estimator with its assumptions stated, not a point estimate.
"""

from __future__ import annotations

import math
import random
from typing import Dict, List, Optional, Sequence, Tuple

# Two-sided normal quantiles, tabulated so no dependency is needed.
Z_SCORES = {0.90: 1.6448536270, 0.95: 1.9599639845, 0.99: 2.5758293035}


def wilson_interval(successes: int, trials: int, confidence: float = 0.95) -> Tuple[float, float, float]:
    """Wilson score interval for a binomial proportion.

    Chosen over the normal ("Wald") approximation because the samples here are
    small — a vendor may only have a dozen externally testable claims — and the
    Wald interval is badly behaved at small n and at proportions near 0 or 1,
    where it can produce bounds outside [0, 1]. Wilson does not.

    Returns (point, lower, upper). With zero trials the interval is the whole
    unit interval, which is the correct statement: we know nothing.
    """
    if trials <= 0:
        return (0.0, 0.0, 1.0)
    z = Z_SCORES.get(round(confidence, 2), Z_SCORES[0.95])
    p_hat = successes / trials
    denominator = 1 + (z * z) / trials
    centre = (p_hat + (z * z) / (2 * trials)) / denominator
    margin = (z / denominator) * math.sqrt(
        (p_hat * (1 - p_hat) / trials) + (z * z) / (4 * trials * trials)
    )
    return (
        round(p_hat, 6),
        round(max(0.0, centre - margin), 6),
        round(min(1.0, centre + margin), 6),
    )


def dirichlet_sample(alpha: Sequence[float], rng: random.Random) -> List[float]:
    """Draw one Dirichlet sample using the gamma construction.

    Uses the supplied seeded Random so weight-sensitivity analysis is
    reproducible: the same seed gives the same samples gives the same
    stability figure in every run.
    """
    draws = [rng.gammavariate(max(a, 1e-9), 1.0) for a in alpha]
    total = sum(draws) or 1.0
    return [d / total for d in draws]


def perturb_weights(
    weights: Dict[str, float],
    samples: int = 2000,
    concentration: float = 40.0,
    seed: int = 20260911,
) -> List[Dict[str, float]]:
    """Generate weight vectors around the declared weights.

    ``concentration`` controls how far the samples wander: the Dirichlet is
    centred on the declared weights with alpha = concentration * weight, so a
    higher value means tighter perturbation. 40 gives roughly +/- 7 percentage
    points on a 0.25 weight, which is the order of disagreement a real
    evaluation panel would have about a weighting.

    The purpose is to answer the obvious challenge to any weighted model —
    "you chose those weights, so you chose the winner" — with a measurement
    instead of an assertion.
    """
    keys = sorted(weights)
    alpha = [concentration * max(weights[k], 1e-6) for k in keys]
    rng = random.Random(seed)
    return [dict(zip(keys, dirichlet_sample(alpha, rng))) for _ in range(samples)]


def mean(values: Sequence[float]) -> Optional[float]:
    values = list(values)
    return sum(values) / len(values) if values else None
