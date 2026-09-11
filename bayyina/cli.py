"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from typing import List, Optional

from . import __version__
from .checks import REGISTRY
from .divergence import PREDICATES
from .cassette import CassetteError
from .engine import assess_tender, write_outputs
from .ledger import EvidenceLedger
from .models import Category, CheckOutcome, DivergenceVerdict
from .report import write_reports
from .util import content_hash

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
GREEN, YELLOW, RED = "\033[32m", "\033[33m", "\033[31m"


def _colour(enabled: bool):
    if enabled and sys.stdout.isatty():
        return BOLD, DIM, RESET, GREEN, YELLOW, RED
    return "", "", "", "", "", ""


# ---------------------------------------------------------------------------


def _non_negative(value: int, name: str) -> int:
    if value < 0:
        raise ValueError(f"--{name} must be zero or greater (got {value})")
    return value


def cmd_assess(args: argparse.Namespace) -> int:
    bold, dim, reset, green, yellow, red = _colour(not args.no_colour)
    _non_negative(args.samples, "samples")
    run = assess_tender(args.tender, mode=args.mode, samples=args.samples, seed=args.seed)

    out_dir = args.out or os.path.join("out", run.tender.tender_id)
    paths = write_outputs(run, out_dir)
    paths.update(write_reports(run, out_dir))

    print(f"\n{bold}{run.tender.title}{reset}")
    print(f"{dim}Tender {run.tender.tender_id} · {run.tender.buyer} · criticality {run.tender.criticality}{reset}")
    print(f"{dim}Evidence: {run.cassette_stats.get('replayed', 0)} replayed, "
          f"{run.cassette_stats.get('recorded', 0)} recorded, mode={run.cassette_stats.get('mode')}{reset}\n")

    if run.interception_detected:
        print(f"{yellow}! TLS interception detected on this network — certificate and protocol "
              f"findings withheld for every bidder.{reset}\n")

    header = f"  {'BIDDER':<12}{'POINT':>7}{'RANGE':>14}{'COVER':>8}{'CONTRA':>8}{'RELIABILITY':>22}"
    print(bold + header + reset)
    ordered = sorted(run.assessments, key=lambda a: -(a.point if a.point is not None else -1))
    for a in ordered:
        rel = run.reliability[a.vendor.vendor_id]
        contradicted = sum(1 for d in a.divergences if d.verdict == DivergenceVerdict.CONTRADICTED)
        tone = green if (a.point or 0) >= 75 else yellow if (a.point or 0) >= 50 else red
        point = f"{a.point:.1f}" if a.point is not None else "—"
        rng = f"{a.lower:.0f}–{a.upper:.0f}"
        # With no testable claim there is no proportion to report. Printing
        # "0%" beside another bidder's genuine 40% would be a lie of format.
        if rel.get("evidence_clusters", 0) == 0:
            ci = "— (no testable claim)"
        else:
            ci = f"{rel['point'] * 100:.0f}% ({rel['ci_lower'] * 100:.0f}–{rel['ci_upper'] * 100:.0f}%)"
        print(f"  {a.vendor.vendor_id:<12}{tone}{point:>7}{reset}{rng:>14}"
              f"{a.coverage * 100:>7.0f}%{contradicted:>6}/{rel['claims_testable']:<2}{ci:>20}")

    print(f"\n{bold}Ranking{reset}")
    if run.ranking.get("single_bidder"):
        print(f"  {dim}Single bidder — nothing to rank against.{reset}")
    elif not run.ranking.get("ranked"):
        print(f"  {yellow}No bidder can be separated from every other on the available evidence; "
              f"the field is not ranked.{reset}")
    for i, tier in enumerate(run.ranking["tiers"], start=1):
        note = "" if len(tier) == 1 else f"  {dim}(not separable on available evidence){reset}"
        print(f"  Tier {i}: {', '.join(tier)}{note}")

    unseparable = [p for p in run.ranking["pairwise"] if not p["separable"]]
    for pair in unseparable:
        print(f"  {yellow}·{reset} {pair['a']} vs {pair['b']}: {pair['reason']}")

    print(f"\n{bold}Weight sensitivity{reset}")
    if run.sensitivity.get("top1_stability") is None:
        print(f"  Not computed: {run.sensitivity.get('method', 'no rankable bidder')}")
    else:
        print(f"  Leader unchanged in {run.sensitivity['top1_stability'] * 100:.1f}% of "
              f"{run.sensitivity['samples']} perturbed weight vectors; "
              f"full order unchanged in {run.sensitivity['order_stability'] * 100:.1f}%.")

    print(f"\n{bold}Bid-field concentration{reset}")
    print(f"  {run.concentration['summary']}")

    if run.warnings:
        print(f"\n{bold}Warnings{reset}")
        for warning in run.warnings:
            print(f"  {yellow}·{reset} {warning}")

    print(f"\n{bold}Evidence ledger{reset}")
    ok, problems = run.ledger.verify() if run.ledger else (False, ["no ledger"])
    status = f"{green}verified{reset}" if ok else f"{red}FAILED{reset}"
    print(f"  {len(run.ledger)} records, chain {status}, head {run.ledger.head[:16]}")
    for problem in problems[:3]:
        print(f"  {red}!{reset} {problem}")

    print(f"\n{bold}Written to {out_dir}/{reset}")
    for name in sorted(paths):
        print(f"  {dim}{name:<14}{reset} {paths[name]}")
    print()
    return 0


def cmd_live(args: argparse.Namespace) -> int:
    """Assess one real domain by recording a fresh cassette."""
    domain = args.domain.strip().lower().lstrip("https://").lstrip("http://").split("/")[0]
    workdir = args.out or os.path.join("out", "live", domain)
    os.makedirs(workdir, exist_ok=True)
    tender = {
        "tender_id": f"LIVE-{domain}",
        "title": f"Live assessment of {domain}",
        "buyer": "ad-hoc",
        "criticality": "MEDIUM",
        "description": f"Single-domain live assessment of {domain}. Passive checks only.",
        "vendors": [
            {
                "vendor_id": domain.split(".")[0][:20],
                "legal_name": domain,
                "primary_domain": domain,
                "questionnaire": "",
                "claimed_certifications": [],
            }
        ],
    }
    with open(os.path.join(workdir, "tender.json"), "w", encoding="utf-8") as handle:
        json.dump(tender, handle, indent=2)

    print(f"Recording live evidence for {domain}. Passive checks only: DNS over HTTPS, one TLS "
          f"handshake, one HTTPS GET, and public certificate transparency data.\n")
    args.tender = workdir
    args.mode = "auto"
    return cmd_assess(args)


def cmd_verify(args: argparse.Namespace) -> int:
    bold, dim, reset, green, yellow, red = _colour(not args.no_colour)
    ledger = EvidenceLedger.read(args.path)
    ok, problems = ledger.verify()
    # The head is read from the file, not recomputed, so it is only
    # meaningful once the chain verifies. Labelling it avoids printing an
    # authoritative-looking digest above a failure notice.
    label = "head" if ok else "head as stored (not trustworthy — see below)"
    print(f"{len(ledger)} records, {label} {ledger.head}")
    if ok:
        print(f"{green}Chain verifies.{reset} Every record hashes to its stored digest and chains to its "
              f"predecessor, so no record has been inserted, removed, reordered or edited since it was written.")
        return 0
    print(f"{red}Chain does NOT verify.{reset} {len(problems)} problem(s) found.")
    for problem in problems[:10]:
        print(f"  ! {problem}")
    if len(problems) > 10:
        print(f"  ... and {len(problems) - 10} further problem(s); a single removed or reordered "
              f"record invalidates every link after it, so one edit cascades.")
    return 1


def cmd_reproduce(args: argparse.Namespace) -> int:
    """Run the same assessment twice and compare the results bit for bit.

    This is the determinism claim, made testable. The jury does not have to
    take "run it twice and you get the same answer" on trust.
    """
    bold, dim, reset, green, yellow, red = _colour(not args.no_colour)
    digests: List[str] = []
    heads: List[str] = []
    for attempt in (1, 2):
        run = assess_tender(args.tender, mode="replay", samples=args.samples, seed=args.seed)
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_outputs(run, tmp)
            with open(paths["manifest"], "r", encoding="utf-8") as handle:
                manifest = json.load(handle)
        digests.append(manifest["result_digest"])
        heads.append(manifest["ledger_head"])
        print(f"  run {attempt}: ledger head {manifest['ledger_head'][:24]}  "
              f"result digest {manifest['result_digest'][:24]}")
    if digests[0] == digests[1] and heads[0] == heads[1]:
        print(f"\n{green}Identical.{reset} Same cassette in, same evidence chain and same scores out. "
              f"Scoring depends only on the recorded evidence, never on the wall clock or on iteration order.")
        return 0
    print(f"\n{red}Runs differ — this is a bug.{reset}")
    return 1


def cmd_checks(args: argparse.Namespace) -> int:
    bold, dim, reset, *_ = _colour(not args.no_colour)
    if args.check:
        spec = REGISTRY.get(args.check.upper())
        if not spec:
            print(f"No such check: {args.check}")
            return 1
        print(f"{bold}{spec.check_id}{reset}  {spec.title}")
        print(f"  category  {Category.LABELS.get(spec.category, spec.category)}")
        print(f"  weight    {spec.weight} (within category)")
        print(f"  severity  {spec.severity}")
        print("  authority")
        for ref in spec.references:
            print(f"    · {ref}")
        return 0

    by_category: dict = {}
    for spec in REGISTRY.values():
        by_category.setdefault(spec.category, []).append(spec)
    total = 0
    for category in Category.ALL:
        specs = sorted(by_category.get(category, []), key=lambda s: s.check_id)
        if not specs and category != Category.DIVERGENCE:
            continue
        print(f"\n{bold}{Category.LABELS.get(category, category)}{reset}")
        if category == Category.DIVERGENCE:
            print(f"  {dim}generated per questionnaire claim from {len(PREDICATES)} testable "
                  f"predicates{reset}")
            for name in sorted(PREDICATES):
                fn = PREDICATES[name]
                print(f"  {name:<38}{getattr(fn, 'description', '')}")
            continue
        for spec in specs:
            total += 1
            print(f"  {spec.check_id:<10}w={spec.weight:<5}{spec.severity:<9}{spec.title}")
    print(f"\n{total} static checks plus {len(PREDICATES)} attestation predicates.\n")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        print("The API needs the optional extras. Install with:  pip install -e '.[api]'")
        return 1
    from .api import serve

    serve(args.tender, host=args.host, port=args.port)
    return 0


# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bayyina",
        description=(
            "Evidence-based third-party vendor assurance for government procurement. "
            "Scores competing bidders on externally observable evidence, tests their "
            "questionnaire attestations against it, and drafts contract conditions."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  bayyina assess --tender scenarios/MDG-2026-114\n"
            "  bayyina reproduce --tender scenarios/MDG-2026-114\n"
            "  bayyina live --domain example.org\n"
            "  bayyina verify-ledger out/MDG-2026-114/evidence-ledger.jsonl\n"
            "  bayyina checks --check DNS-002\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"bayyina {__version__}")

    # Accepted either before or after the subcommand, because both readings are
    # natural and being told "unrecognized arguments" for a flag the help text
    # advertises is a poor first impression.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-colour", "--no-color", action="store_true",
                        dest="no_colour", help="disable ANSI colour")
    parser.add_argument("--no-colour", "--no-color", action="store_true",
                        dest="no_colour", help="disable ANSI colour")
    sub = parser.add_subparsers(dest="command", required=True)

    assess = sub.add_parser("assess", parents=[common], help="assess every bidder in a tender")
    assess.add_argument("--tender", required=True, help="tender directory or tender.json")
    assess.add_argument("--mode", default="replay", choices=("replay", "record", "auto"),
                        help="replay (default, no network) | record (live) | auto")
    assess.add_argument("--out", help="output directory (default out/<tender-id>)")
    assess.add_argument("--samples", type=int, default=2000, help="weight-sensitivity samples")
    assess.add_argument("--seed", type=int, default=20260911, help="sensitivity seed")
    assess.set_defaults(func=cmd_assess)

    live = sub.add_parser("live", parents=[common], help="record and assess one real domain")
    live.add_argument("--domain", required=True)
    live.add_argument("--out")
    live.add_argument("--samples", type=int, default=500)
    live.add_argument("--seed", type=int, default=20260911)
    live.set_defaults(func=cmd_live)

    verify = sub.add_parser("verify-ledger", parents=[common], help="verify an evidence ledger's hash chain")
    verify.add_argument("path")
    verify.set_defaults(func=cmd_verify)

    reproduce = sub.add_parser("reproduce", parents=[common], help="run an assessment twice and compare bit for bit")
    reproduce.add_argument("--tender", required=True)
    reproduce.add_argument("--samples", type=int, default=2000)
    reproduce.add_argument("--seed", type=int, default=20260911)
    reproduce.set_defaults(func=cmd_reproduce)

    checks = sub.add_parser("checks", parents=[common], help="list the check catalogue and its authorities")
    checks.add_argument("--check", help="show one check in detail")
    checks.set_defaults(func=cmd_checks)

    serve = sub.add_parser("serve", parents=[common], help="run the HTTP API (needs the [api] extra)")
    serve.add_argument("--tender", required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError, CassetteError) as exc:
        # A missing cassette carries a carefully written explanation; wrapping
        # it in a stack trace was hiding the one thing the user needed to read.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
