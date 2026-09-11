"""Evidence ledger integrity and the statistical helpers."""

from __future__ import annotations

import json

import pytest

from bayyina.ledger import GENESIS, EvidenceLedger
from bayyina.stats import dirichlet_sample, perturb_weights, wilson_interval


# -- ledger ----------------------------------------------------------------


def build(n=5):
    ledger = EvidenceLedger()
    for i in range(n):
        ledger.append("evidence", {"i": i, "observed_at": f"2026-09-0{i + 1}T00:00:00+00:00"})
    return ledger


def test_a_clean_chain_verifies():
    ok, problems = build().verify()
    assert ok and problems == []


def test_empty_ledger_verifies_and_heads_at_genesis():
    ledger = EvidenceLedger()
    assert ledger.head == GENESIS
    assert ledger.verify() == (True, [])


def test_editing_a_payload_breaks_the_chain(tmp_path):
    """The realistic threat: a stored finding is quietly changed after the fact."""
    ledger = build()
    path = tmp_path / "ledger.jsonl"
    ledger.write(str(path))

    lines = path.read_text().splitlines()
    record = json.loads(lines[2])
    record["payload"]["i"] = 999
    lines[2] = json.dumps(record, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")

    ok, problems = EvidenceLedger.read(str(path)).verify()
    assert not ok
    assert any("modified after it was recorded" in p for p in problems)


def test_removing_a_record_breaks_the_chain(tmp_path):
    ledger = build()
    path = tmp_path / "ledger.jsonl"
    ledger.write(str(path))
    lines = path.read_text().splitlines()
    del lines[2]
    path.write_text("\n".join(lines) + "\n")
    ok, problems = EvidenceLedger.read(str(path)).verify()
    assert not ok
    assert any("chain" in p or "sequence" in p for p in problems)


def test_reordering_records_breaks_the_chain(tmp_path):
    ledger = build()
    path = tmp_path / "ledger.jsonl"
    ledger.write(str(path))
    lines = path.read_text().splitlines()
    lines[1], lines[3] = lines[3], lines[1]
    path.write_text("\n".join(lines) + "\n")
    ok, _ = EvidenceLedger.read(str(path)).verify()
    assert not ok


def test_the_head_changes_when_any_record_changes():
    a = build()
    b = EvidenceLedger()
    for i in range(5):
        b.append("evidence", {"i": i if i != 3 else 99, "observed_at": f"2026-09-0{i + 1}T00:00:00+00:00"})
    assert a.head != b.head


def test_the_ledger_round_trips_through_disk(tmp_path):
    ledger = build(8)
    path = tmp_path / "ledger.jsonl"
    head = ledger.write(str(path))
    reloaded = EvidenceLedger.read(str(path))
    assert reloaded.head == head
    assert len(reloaded) == 8
    assert reloaded.verify()[0]


def test_timestamps_come_from_the_evidence_not_the_clock():
    """Two ledgers built from identical evidence must have identical heads."""
    assert build().head == build().head


# -- Wilson interval -------------------------------------------------------


def test_wilson_matches_hand_computed_values():
    point, lower, upper = wilson_interval(6, 15)
    assert point == pytest.approx(0.4, abs=1e-9)
    assert lower == pytest.approx(0.1982, abs=5e-4)
    assert upper == pytest.approx(0.6425, abs=5e-4)


def test_wilson_stays_inside_the_unit_interval_at_the_extremes():
    """The reason Wilson is used instead of the normal approximation."""
    for successes, trials in ((0, 5), (5, 5), (0, 1), (1, 1), (1, 100), (99, 100)):
        _, lower, upper = wilson_interval(successes, trials)
        assert 0.0 <= lower <= upper <= 1.0, (successes, trials, lower, upper)


def test_wilson_with_no_trials_claims_nothing():
    assert wilson_interval(0, 0) == (0.0, 0.0, 1.0)


def test_wilson_interval_narrows_as_evidence_accumulates():
    _, low_small, high_small = wilson_interval(8, 10)
    _, low_large, high_large = wilson_interval(80, 100)
    assert (high_large - low_large) < (high_small - low_small)


def test_a_perfect_record_on_few_trials_is_still_uncertain():
    """14/14 must not be reported as certainty."""
    point, lower, upper = wilson_interval(14, 14)
    assert point == 1.0
    assert lower < 0.85, "a small perfect sample must not imply near-certainty"
    assert upper == 1.0


# -- weight perturbation ---------------------------------------------------


def test_dirichlet_samples_are_valid_distributions():
    import random

    rng = random.Random(1)
    for _ in range(50):
        sample = dirichlet_sample([2.0, 3.0, 5.0], rng)
        assert len(sample) == 3
        assert all(v >= 0 for v in sample)
        assert sum(sample) == pytest.approx(1.0, abs=1e-9)


def test_perturbation_is_seed_reproducible():
    weights = {"a": 0.5, "b": 0.3, "c": 0.2}
    assert perturb_weights(weights, samples=20, seed=3) == perturb_weights(weights, samples=20, seed=3)
    assert perturb_weights(weights, samples=20, seed=3) != perturb_weights(weights, samples=20, seed=4)


def test_perturbation_stays_centred_on_the_declared_weights():
    weights = {"a": 0.5, "b": 0.3, "c": 0.2}
    samples = perturb_weights(weights, samples=4000, seed=11)
    for key, declared in weights.items():
        observed = sum(s[key] for s in samples) / len(samples)
        assert observed == pytest.approx(declared, abs=0.02)
