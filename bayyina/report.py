"""HTML report generation.

Two documents, matching the two decisions a buyer actually makes:

  * a **comparison dashboard** for the award decision across the bid field,
    including the concentration analysis, which only exists at that level; and
  * a **one-page assessment per bidder**, which is the document handed to an
    unsuccessful bidder under UAE Federal Law 11/2023 Art. 29.

Both are self-contained: no external CSS, no fonts, no scripts, no network.
That is a requirement rather than a preference — these are evidence documents
that must render identically in five years from a file on disk, and one of
them may be an annex to a procurement challenge.
"""

from __future__ import annotations

import html
import os
from typing import Any, Dict, List, Optional, Sequence

from .contract import summarise as summarise_conditions
from .models import Category, CheckOutcome, DivergenceVerdict, Severity, VendorAssessment

CSS = """
:root{
  --ink:#12203a; --muted:#5b6b86; --faint:#8493aa; --line:#dde3ec; --panel:#f6f8fb;
  --accent:#1f4e8c; --accent-soft:#e8eff8;
  --pass:#1a7f5a; --partial:#b2760a; --fail:#b3261e; --unknown:#7a869a; --na:#9aa6b8;
}
*{box-sizing:border-box}
body{margin:0;background:#eef1f6;color:var(--ink);
  font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
.page{max-width:1080px;margin:0 auto;background:#fff;padding:44px 52px 56px}
h1{font-size:25px;line-height:1.2;margin:0 0 6px;letter-spacing:-.015em}
h2{font-size:15px;margin:34px 0 12px;padding-bottom:7px;border-bottom:2px solid var(--ink);
  letter-spacing:.055em;text-transform:uppercase}
h3{font-size:13.5px;margin:20px 0 8px;letter-spacing:.03em;text-transform:uppercase;color:var(--muted)}
p{margin:0 0 11px}
.masthead{display:flex;justify-content:space-between;align-items:flex-start;gap:26px;
  border-bottom:3px solid var(--ink);padding-bottom:16px;margin-bottom:22px}
.brand{font-size:11px;letter-spacing:.24em;text-transform:uppercase;color:var(--accent);font-weight:700}
.sub{color:var(--muted);font-size:13px;margin-top:3px}
.stamp{text-align:right;font-size:11px;color:var(--muted);line-height:1.7;white-space:nowrap}
.notice{background:#fff8e6;border:1px solid #e8d9a8;border-left:4px solid #c9a227;
  padding:11px 14px;font-size:12.5px;color:#5c4a10;margin:0 0 20px;border-radius:3px}
.lede{font-size:15.5px;line-height:1.6;color:var(--ink);margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:12.8px;margin:10px 0 4px}
th{text-align:left;font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);
  border-bottom:1.5px solid var(--line);padding:0 10px 7px 0;font-weight:700;vertical-align:bottom}
td{padding:9px 10px 9px 0;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:none}
.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11.5px}
.tag{display:inline-block;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:700;
  letter-spacing:.06em;text-transform:uppercase;white-space:nowrap}
.t-pass{background:#e4f3ec;color:var(--pass)} .t-fail{background:#fbe9e7;color:var(--fail)}
.t-partial{background:#fdf1dd;color:var(--partial)} .t-unknown{background:#eef1f5;color:var(--unknown)}
.t-na{background:#f2f4f7;color:var(--na)} .t-human{background:#ede9f7;color:#5b3fa8}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:5px;padding:15px 18px;margin:12px 0}
.panel h3{margin-top:0}
.grid{display:grid;gap:13px}
.g3{grid-template-columns:repeat(3,1fr)} .g2{grid-template-columns:repeat(2,1fr)}
.card{border:1px solid var(--line);border-radius:5px;padding:14px 16px;background:#fff}
.card .name{font-weight:700;font-size:14px;margin-bottom:2px}
.card .meta{font-size:11.5px;color:var(--muted)}
.kpi{font-size:27px;font-weight:700;font-variant-numeric:tabular-nums;letter-spacing:-.02em;line-height:1.1}
.kpi-sub{font-size:11.5px;color:var(--muted);margin-top:2px}
.rule{height:1px;background:var(--line);margin:26px 0}
.foot{margin-top:34px;padding-top:14px;border-top:1px solid var(--line);font-size:11px;color:var(--faint);line-height:1.7}
.tier{display:flex;gap:10px;align-items:baseline;padding:9px 0;border-bottom:1px solid var(--line)}
.tier:last-child{border-bottom:none}
.tier .n{font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);min-width:72px}
.tier .v{font-weight:600}
.warn{background:#fbe9e7;border-left:4px solid var(--fail);padding:11px 14px;font-size:12.8px;
  border-radius:3px;margin:11px 0}
.good{background:#e4f3ec;border-left:4px solid var(--pass);padding:11px 14px;font-size:12.8px;
  border-radius:3px;margin:11px 0}
.info{background:var(--accent-soft);border-left:4px solid var(--accent);padding:11px 14px;
  font-size:12.8px;border-radius:3px;margin:11px 0}
.small{font-size:11.5px;color:var(--muted)}
.obs{color:var(--muted);font-size:12px;margin-top:3px}
.clause{font-size:12.3px;line-height:1.6}
ul{margin:6px 0 11px;padding-left:19px} li{margin-bottom:5px}
@media print{
  body{background:#fff} .page{max-width:none;padding:0;margin:0}
  h2{page-break-after:avoid} table{page-break-inside:auto} tr{page-break-inside:avoid}
  .card,.panel{page-break-inside:avoid}
  @page{size:A4;margin:15mm}
}
"""


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _tag(outcome: str) -> str:
    mapping = {
        CheckOutcome.PASS: ("t-pass", "Pass"),
        CheckOutcome.FAIL: ("t-fail", "Fail"),
        CheckOutcome.PARTIAL: ("t-partial", "Partial"),
        CheckOutcome.UNKNOWN: ("t-unknown", "Unknown"),
        CheckOutcome.NOT_APPLICABLE: ("t-na", "N/A"),
        CheckOutcome.NEEDS_HUMAN: ("t-human", "Human review"),
    }
    cls, label = mapping.get(outcome, ("t-unknown", outcome))
    return f'<span class="tag {cls}">{label}</span>'


def _pct(value: Optional[float]) -> str:
    return f"{value * 100:.0f}%" if value is not None else "—"


def _reliability_pct(rel: Dict[str, Any], key: str = "point") -> str:
    """A bidder with no testable claim has no proportion — a dash, not 0%.

    ``wilson_interval(0, 0)`` returns a point of 0.0 meaning "we know nothing",
    which is correct arithmetic and a disastrous thing to print in a column
    beside another bidder's genuine 40%.
    """
    if not rel or rel.get("evidence_clusters", 0) == 0:
        return "—"
    return _pct(rel.get(key))


# ---------------------------------------------------------------------------
# Inline SVG: the score interval chart
# ---------------------------------------------------------------------------


def interval_chart(assessments: Sequence[VendorAssessment], width: int = 700) -> str:
    """Horizontal interval bars — the visual that carries the whole argument.

    The bar is the range the evidence supports; the tick is the point estimate
    over observed evidence only. Where two bars overlap horizontally, the tool
    will not rank those two bidders. Reading that off the picture is the point.
    """
    if not assessments:
        return ""
    # `right` reserves room for the value label printed after each bar; too
    # small and a bar reaching 100 pushes its own label outside the viewBox.
    row_h, top, left, right = 46, 34, 132, 68
    height = top + row_h * len(assessments) + 34
    plot_w = width - left - right

    def x(value: float) -> float:
        return left + (max(0.0, min(100.0, value)) / 100.0) * plot_w

    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" '
        f'aria-label="Assessment score intervals by bidder" style="max-width:{width}px">',
        '<style>.ax{font:10px -apple-system,sans-serif;fill:#8493aa}'
        '.lb{font:600 12.5px -apple-system,sans-serif;fill:#12203a}'
        '.vl{font:600 11px ui-monospace,monospace;fill:#5b6b86}</style>',
    ]
    for gridline in (0, 25, 50, 75, 100):
        gx = x(gridline)
        parts.append(f'<line x1="{gx:.1f}" y1="{top - 12}" x2="{gx:.1f}" y2="{height - 30}" '
                     f'stroke="#e6eaf1" stroke-width="1"/>')
        parts.append(f'<text class="ax" x="{gx:.1f}" y="{height - 14}" text-anchor="middle">{gridline}</text>')

    for i, a in enumerate(assessments):
        cy = top + row_h * i + 12
        x0, x1 = x(a.lower), x(a.upper)
        colour = "#1a7f5a" if (a.point or 0) >= 75 else "#b2760a" if (a.point or 0) >= 50 else "#b3261e"
        parts.append(f'<text class="lb" x="0" y="{cy + 4:.0f}">{_esc(a.vendor.vendor_id)}</text>')
        parts.append(f'<rect x="{x0:.1f}" y="{cy - 9:.0f}" width="{max(x1 - x0, 2):.1f}" height="18" '
                     f'rx="3" fill="{colour}" fill-opacity="0.17" stroke="{colour}" stroke-opacity="0.45"/>')
        if a.point is not None:
            px = x(a.point)
            parts.append(f'<line x1="{px:.1f}" y1="{cy - 13:.0f}" x2="{px:.1f}" y2="{cy + 13:.0f}" '
                         f'stroke="{colour}" stroke-width="2.5" stroke-linecap="round"/>')
        label_x = min(x1 + 8, width - right + 6)
        parts.append(f'<text class="vl" x="{label_x:.1f}" y="{cy + 4:.0f}">'
                     f'{a.lower:.0f}–{a.upper:.0f}</text>')
        parts.append(f'<text class="ax" x="0" y="{cy + 19:.0f}">coverage {a.coverage * 100:.0f}%</text>')
    parts.append("</svg>")
    return "".join(parts)


def _shell(title: str, body: str) -> str:
    return (
        f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{_esc(title)}</title><style>{CSS}</style></head>"
        f'<body><div class="page">{body}</div></body></html>'
    )


def _masthead(run, subtitle: str, right_lines: Sequence[str]) -> str:
    stamp = "<br>".join(_esc(line) for line in right_lines)
    return (
        '<div class="masthead"><div>'
        '<div class="brand">Bayyina &middot; evidence-based vendor assurance</div>'
        f"<h1>{_esc(run.tender.title)}</h1>"
        f'<div class="sub">{_esc(subtitle)}</div>'
        f'</div><div class="stamp">{stamp}</div></div>'
    )


def _synthetic_notice(run) -> str:
    # A tender with no bidders is unusual but legal, and indexing [0] here used
    # to take the whole report generator down with an IndexError.
    if not run.tender.vendors:
        return ""
    if not any("example" in (v.primary_domain or "") for v in run.tender.vendors):
        return ""
    return (
        '<div class="notice"><strong>Demonstration scenario.</strong> The bidders in this document '
        "are fictional and their domains are reserved under RFC 2606. Every observation was generated "
        "by <span class=\"mono\">scenarios/build_demo.py</span>. Nothing here describes any real "
        "organisation. The tool runs identically against live infrastructure.</div>"
    )


def _weights_panel(run) -> str:
    rows = "".join(
        f"<tr><td>{_esc(Category.LABELS.get(k, k))}</td>"
        f'<td class="num" style="text-align:right;width:80px">{v * 100:.0f}%</td></tr>'
        for k, v in sorted(run.weights.items(), key=lambda kv: -kv[1])
    )
    return (
        '<div class="panel"><h3>Published evaluation weights</h3>'
        f"<table>{rows}</table>"
        '<p class="small" style="margin-top:9px">Set by the buyer in the tender definition, not by the tool. '
        "UAE Federal Law No. 11 of 2023 Art. 22(4) requires the weight assigned to each evaluation "
        "criterion to be published in advance; the sensitivity analysis below measures how far the "
        "outcome actually depends on these particular values.</p></div>"
    )


# ---------------------------------------------------------------------------
# Comparison dashboard
# ---------------------------------------------------------------------------


def comparison(run) -> str:
    ordered = sorted(run.assessments, key=lambda a: -(a.point if a.point is not None else -1))
    ranking = run.ranking
    conc = run.concentration
    sens = run.sensitivity

    tiers_html = ""
    for i, tier in enumerate(ranking.get("tiers", []), start=1):
        names = ", ".join(
            _esc(run.vendor(v).vendor.legal_name) if run.vendor(v) else _esc(v) for v in tier
        )
        note = "" if len(tier) == 1 else ' <span class="small">— not separable on the available evidence</span>'
        tiers_html += f'<div class="tier"><span class="n">Tier {i}</span><span class="v">{names}{note}</span></div>'

    unseparable = [p for p in ranking.get("pairwise", []) if not p["separable"]]
    if unseparable:
        pair_note = (
            '<div class="warn"><strong>The tool will not rank every pair.</strong> '
            + " ".join(
                f"{_esc(p['a'])} and {_esc(p['b'])} cannot be separated: {_esc(p['reason'])}."
                for p in unseparable
            )
            + " Ranking these bidders against each other would assert a difference the evidence does not "
            "support. The information requests in each bidder's assessment set out what would resolve it.</div>"
        )
    else:
        pair_note = (
            '<div class="good"><strong>All pairs are separable.</strong> Every bidder\'s score interval '
            "is disjoint from every other's, so the ranking is supported by the evidence rather than by "
            "the choice of weights.</div>"
        )

    summary_rows = ""
    for a in ordered:
        rel = run.reliability.get(a.vendor.vendor_id, {})
        cond = run.conditions.get(a.vendor.vendor_id, {})
        contradicted = sum(
            1 for d in a.divergences if d.verdict == DivergenceVerdict.CONTRADICTED
        )
        summary_rows += (
            f"<tr><td><strong>{_esc(a.vendor.legal_name)}</strong>"
            f'<div class="small mono">{_esc(a.vendor.primary_domain)} &middot; {_esc(a.vendor.bid_reference)}</div></td>'
            f'<td class="num">{a.point if a.point is not None else "—"}</td>'
            f'<td class="num">{a.lower:.0f} – {a.upper:.0f}</td>'
            f'<td class="num">{a.coverage * 100:.0f}%</td>'
            f'<td class="num">{contradicted} / {rel.get("claims_testable", 0)}</td>'
            f'<td class="num">{_reliability_pct(rel)} '
            f'<span class="small">({_reliability_pct(rel, "ci_lower")}–{_reliability_pct(rel, "ci_upper")})'
            f'<br>{_esc(rel.get("clusters_corroborated", 0))} of {_esc(rel.get("evidence_clusters", 0))} '
            f'evidence sources</span></td>'
            f'<td class="num">{len(cond.get("conditions_precedent", []))}</td></tr>'
        )

    shared_rows = "".join(
        f"<tr><td>{_esc(s['label'])}</td><td class=\"mono\">{_esc(s['provider'])}</td>"
        f"<td>{_esc(', '.join(s['vendors']))}</td>"
        f'<td class="num">{s["share_of_field"] * 100:.0f}% of field</td></tr>'
        for s in conc.get("shared_dependencies", [])
    ) or '<tr><td colspan="4" class="small">No upstream provider is shared between bidders.</td></tr>'

    loco_rows = "".join(
        f"<tr><td>{_esc(l['label'])}</td><td>{_esc(' &rsaquo; '.join(l['order']))}</td>"
        f"<td><strong>{_esc(l['leader'])}</strong></td></tr>"
        for l in run.leave_one_out
    )

    leaders = sens.get("leader_distribution", {}) or {}
    leader_rows = "".join(
        f'<tr><td>{_esc(k)}</td><td class="num">{v * 100:.1f}%</td></tr>'
        for k, v in sorted(leaders.items(), key=lambda kv: -kv[1])
    )

    body = (
        _masthead(
            run,
            f"Bid-field comparison \u00b7 tender {run.tender.tender_id} \u00b7 {run.tender.buyer}",
            [
                f"Criticality: {run.tender.criticality}",
                f"Bidders assessed: {len(run.assessments)}",
                f"Evidence records: {len(run.ledger) if run.ledger else 0}",
                f"Ledger head: {run.ledger.head[:16] if run.ledger else '—'}",
            ],
        )
        + _synthetic_notice(run)
        + f'<p class="lede">{_esc(run.tender.description)}</p>'
        + "<h2>Result</h2>"
        + tiers_html
        + pair_note
        + '<h3 style="margin-top:22px">Score intervals</h3>'
        + '<p class="small">The bar is the range the evidence supports: its lower end assumes every '
        "unobserved check would have failed, its upper end assumes every one would have passed. The tick "
        "is the point estimate over observed evidence only. This is a statement about the evidence, not a "
        "confidence interval about the bidder. Where two bars overlap, the bidders are not ranked against "
        "each other.</p>"
        + interval_chart(ordered)
        + "<table><thead><tr><th>Bidder</th><th>Point</th><th>Supported range</th><th>Evidence coverage</th>"
        "<th>Attestations contradicted</th><th>Attestation reliability (95% CI)</th>"
        "<th>Conditions precedent</th></tr></thead><tbody>"
        + summary_rows
        + "</tbody></table>"
        + '<p class="small">The composite is an ordinal triage and ranking device, not a measurement of '
        "risk. It has no unit, and a 20-point gap does not mean twice the risk. What carries decision "
        "weight is the findings list and the conditions, not the number.</p>"
        + _weights_panel(run)
        + "<h2>Bid-field concentration</h2>"
        + f'<div class="{"warn" if conc.get("diversification_warnings") else "info"}">{_esc(conc.get("summary", ""))}</div>'
        + "<table><thead><tr><th>Dependency</th><th>Provider</th><th>Bidders</th><th>Share</th></tr></thead>"
        f"<tbody>{shared_rows}</tbody></table>"
        + f'<p class="small">{_esc(conc.get("basis", ""))} {_esc(conc.get("method", ""))}</p>'
        + "<h2>How much of this result is the weighting?</h2>"
        + (
            '<div class="grid g2">'
            f'<div class="card"><div class="kpi">{sens["top1_stability"] * 100:.1f}%</div>'
            f'<div class="kpi-sub">of {sens.get("samples", 0):,} perturbed weight vectors keep the same '
            "leader</div></div>"
            f'<div class="card"><div class="kpi">{sens["order_stability"] * 100:.1f}%</div>'
            '<div class="kpi-sub">keep the entire indicative order unchanged</div></div></div>'
            if sens.get("top1_stability") is not None
            else '<div class="info">Not computed &mdash; no bidder had a point estimate to rank, or zero '
                 "samples were requested.</div>"
        )
        + f'<p class="small">{_esc(sens.get("method", ""))} Seed {_esc(sens.get("seed"))}, so the figure '
        "reproduces exactly on re-run.</p>"
        + (f"<table><thead><tr><th>Leader under perturbation</th><th>Share of samples</th></tr></thead>"
           f"<tbody>{leader_rows}</tbody></table>" if len(leaders) > 1 else "")
        + "<h3>Leave-one-criterion-out</h3>"
        + '<p class="small">The ranking recomputed with each criterion removed entirely — a blunter and more '
        "interpretable test than the perturbation above.</p>"
        + "<table><thead><tr><th>Criterion removed</th><th>Resulting order</th><th>Leader</th></tr></thead>"
        f"<tbody>{loco_rows}</tbody></table>"
        + _footer(run)
    )
    return _shell(f"{run.tender.tender_id} — bid-field comparison", body)


# ---------------------------------------------------------------------------
# Per-vendor assessment
# ---------------------------------------------------------------------------


def vendor_report(run, assessment: VendorAssessment) -> str:
    rel = run.reliability.get(assessment.vendor.vendor_id, {})
    conditions = run.conditions.get(assessment.vendor.vendor_id, {})

    contradicted = [d for d in assessment.divergences if d.verdict == DivergenceVerdict.CONTRADICTED]
    div_rows = "".join(
        f'<tr><td class="mono">{_esc(d.control_ref or d.claim_id)}</td>'
        f"<td>{_esc(d.claim_text)}<div class=\"obs\"><strong>Attested:</strong> {_esc(d.expected)}</div></td>"
        f"<td>{_esc(d.observed)}</td>"
        f'<td><span class="tag t-fail">{_esc(d.severity)}</span></td></tr>'
        for d in contradicted
    ) or '<tr><td colspan="4" class="small">No attestation was contradicted by observed evidence.</td></tr>'

    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    material = sorted(
        [f for f in assessment.findings
         if f.outcome in (CheckOutcome.FAIL, CheckOutcome.PARTIAL, CheckOutcome.NEEDS_HUMAN)
         and not f.check_id.startswith("DIV-")],
        key=lambda f: (order.get(f.severity, 5), f.check_id),
    )
    finding_rows = "".join(
        f'<tr><td class="mono">{_esc(f.check_id)}</td>'
        f"<td>{_esc(f.title)}<div class=\"obs\">{_esc(f.observation)}</div></td>"
        f"<td>{_tag(f.outcome)}</td><td>{_esc(f.severity)}</td>"
        f'<td class="small">{_esc("; ".join(f.references[:2]))}</td></tr>'
        for f in material
    ) or '<tr><td colspan="5" class="small">No failed or partial checks.</td></tr>'

    unknowns = [f for f in assessment.findings if f.outcome == CheckOutcome.UNKNOWN]
    unknown_html = ""
    if unknowns:
        items = "".join(
            f'<li><span class="mono">{_esc(f.check_id)}</span> — {_esc(f.title)}. {_esc(f.observation)}</li>'
            for f in unknowns
        )
        unknown_html = (
            "<h3>Controls that could not be observed</h3>"
            '<p class="small">These are scored as unknown, not as failures. They widen the supported range '
            "above and are the reason for the information requests below.</p>"
            f"<ul>{items}</ul>"
        )

    cat_rows = "".join(
        f"<tr><td>{_esc(Category.LABELS.get(c.category, c.category))}</td>"
        f'<td class="num">{c.weight * 100:.0f}%</td>'
        f'<td class="num">{_pct(c.point)}</td>'
        f'<td class="num">{c.lower * 100:.0f}–{c.upper * 100:.0f}</td>'
        f'<td class="num">{c.coverage * 100:.0f}%</td>'
        f'<td class="num">{c.scored_checks}/{c.total_checks}</td></tr>'
        for c in sorted(assessment.categories, key=lambda c: -c.weight)
    )

    def condition_block(title: str, key: str, note: str) -> str:
        items = conditions.get(key, [])
        if not items:
            return ""
        rows = "".join(
            f'<tr><td class="mono">{_esc(c["id"])}</td>'
            f"<td><strong>{_esc(c.get('title', ''))}</strong>"
            f"<div class=\"clause\" style=\"margin-top:5px\">{_esc(c.get('clause') or c.get('request', ''))}</div>"
            + (f"<div class=\"obs\">Verification: {_esc(c['verification'])}</div>" if c.get("verification") else "")
            + (f"<div class=\"obs\">Owner: {_esc(c['owner'])}</div>" if c.get("owner") else "")
            + "</td>"
            f'<td class="num">{_esc(c.get("deadline_days", "—"))}{" days" if c.get("deadline_days") else ""}</td>'
            f"<td>{_esc(c.get('severity', ''))}</td></tr>"
            for c in items
        )
        return (
            f"<h3>{_esc(title)} ({len(items)})</h3>"
            f'<p class="small">{_esc(note)}</p>'
            "<table><thead><tr><th>Ref</th><th>Obligation</th><th>Window</th><th>Severity</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )

    rank_position = None
    for i, tier in enumerate(run.ranking.get("tiers", []), start=1):
        if assessment.vendor.vendor_id in tier:
            rank_position = (i, len(tier))
            break
    rank_text = (
        f"Tier {rank_position[0]}"
        + (f" (shared with {rank_position[1] - 1} other bidder(s) — not separable)" if rank_position[1] > 1 else "")
        if rank_position
        else "—"
    )

    body = (
        _masthead(
            run,
            f"Supplier security assessment \u00b7 {assessment.vendor.legal_name}",
            [
                f"Tender: {run.tender.tender_id}",
                f"Bid: {assessment.vendor.bid_reference}",
                f"Domain: {assessment.vendor.primary_domain}",
                f"Evidence records: {assessment.evidence_count}",
            ],
        )
        + _synthetic_notice(run)
        + '<div class="grid g3">'
        + f'<div class="card"><div class="kpi">{assessment.point if assessment.point is not None else "—"}'
        f'<span style="font-size:14px;color:var(--muted)">/100</span></div>'
        f'<div class="kpi-sub">point estimate; supported range {assessment.lower:.0f}–{assessment.upper:.0f}</div></div>'
        + f'<div class="card"><div class="kpi">{assessment.coverage * 100:.0f}%</div>'
        '<div class="kpi-sub">of weighted checks actually observed</div></div>'
        + f'<div class="card"><div class="kpi">{_reliability_pct(rel)}</div>'
        f'<div class="kpi-sub">attestation reliability across {_esc(rel.get("evidence_clusters", 0))} independent '
        f'evidence sources, 95% CI {_reliability_pct(rel, "ci_lower")}–{_reliability_pct(rel, "ci_upper")}</div></div>'
        + "</div>"
        + f'<div class="info" style="margin-top:14px"><strong>Award position: {_esc(rank_text)}.</strong> '
        f"{_esc(summarise_conditions(conditions))}</div>"
        + "<h2>Attestation divergence</h2>"
        + '<p class="small">Each row is a claim the bidder made in its questionnaire that externally '
        "observable evidence contradicts. A contradiction is treated as more serious than the underlying "
        "control gap: it is evidence about the reliability of the whole submission, including the parts "
        "that cannot be checked.</p>"
        + "<table><thead><tr><th>Control</th><th>Claim</th><th>Observed</th><th>Severity</th></tr></thead>"
        f"<tbody>{div_rows}</tbody></table>"
        + '<div class="panel"><h3>What this implies for the untestable claims</h3>'
        + f"<p>Of {_esc(rel.get('claims_total', 0))} questionnaire responses, "
        f"{_esc(rel.get('claims_testable', 0))} carried an assertion that could be tested against external "
        f"evidence. {_esc(rel.get('corroborated', 0))} survived and {_esc(rel.get('contradicted', 0))} did not. "
        f"Those claims rest on {_esc(rel.get('evidence_clusters', 0))} <em>independent</em> evidence sources "
        f"(the largest single source carries {_esc(rel.get('largest_cluster', 0))} of them), and "
        f"{_esc(rel.get('clusters_corroborated', 0))} of those sources corroborated every claim resting on it — "
        f"an estimated attestation reliability of <strong>{_reliability_pct(rel)}</strong> "
        f"(95% CI {_reliability_pct(rel, 'ci_lower')}–{_reliability_pct(rel, 'ci_upper')}, Wilson score interval). "
        f"The remaining {_esc(rel.get('claims_untestable', 0))} responses could not be tested from outside.</p>"
        + '<p class="small"><strong>Why sources rather than claims.</strong> Several attestations can rest on a '
        "single observation — three of them can come out of one HTTP response — so treating each claim as an "
        "independent trial would report an interval narrower than the evidence supports. Clustering by evidence "
        "source is the conservative reading. For comparison, the claim-level figure is "
        f"{_pct(rel.get('claim_level_point'))} (95% CI {_pct(rel.get('claim_level_ci_lower'))}–"
        f"{_pct(rel.get('claim_level_ci_upper'))}).</p>"
        + f'<p class="small">{_esc(rel.get("caveat", ""))}</p></div>'
        + "<h2>Findings</h2>"
        + "<table><thead><tr><th>Check</th><th>Finding</th><th>Outcome</th><th>Severity</th><th>Authority</th></tr></thead>"
        f"<tbody>{finding_rows}</tbody></table>"
        + unknown_html
        + "<h2>Score composition</h2>"
        + "<table><thead><tr><th>Criterion</th><th>Weight</th><th>Point</th><th>Range</th>"
        "<th>Coverage</th><th>Checks scored</th></tr></thead>"
        f"<tbody>{cat_rows}</tbody></table>"
        + "<h2>Recommended contract conditions</h2>"
        + condition_block(
            "Conditions precedent to award", "conditions_precedent",
            "To be satisfied before award. These go to the integrity of the bid itself rather than to "
            "ordinary remediation.",
        )
        + condition_block(
            "Contract conditions", "contract_conditions",
            "Drafted obligations with a remediation window sized by severity and contract criticality. "
            "Each names the check that produced it, so re-running that check is the acceptance test.",
        )
        + condition_block(
            "Information requests", "information_requests",
            "Where the tool could not observe a control, or declined to decide one that requires human "
            "judgement. Each is assigned to a named reviewer rather than silently passed.",
        )
        + _footer(run, assessment)
    )
    return _shell(f"{run.tender.tender_id} — {assessment.vendor.legal_name}", body)


def _footer(run, assessment: Optional[VendorAssessment] = None) -> str:
    ledger_head = run.ledger.head if run.ledger else "—"
    lines = [
        "<strong>Evidence integrity.</strong> Every observation behind this document is recorded in a "
        f"hash-chained ledger; head <span class=\"mono\">{_esc(ledger_head[:32])}</span> over "
        f"{len(run.ledger) if run.ledger else 0} records. Verify with "
        '<span class="mono">bayyina verify-ledger &lt;out&gt;/evidence-ledger.jsonl</span>. '
        "The chain makes silent modification of stored evidence detectable; it is tamper-evidence, "
        "not tamper-proofing.",
        "<strong>Method.</strong> Assessment is passive: public datasets and normal-client protocol "
        "interaction only. No port scanning, vulnerability probing, authentication attempts, fuzzing or "
        "zone transfer. Findings are point-in-time as at the observation date recorded with each "
        "evidence item.",
        "<strong>Right of reply.</strong> Every finding carries the raw observation that produced it. A "
        "bidder disputing a finding should be given the evidence record and the check identifier, and "
        "the check re-run against endpoints it nominates.",
    ]
    if run.warnings:
        shown = run.warnings[:8]
        items = "".join(f"<br>&nbsp;&nbsp;&middot; {_esc(w)}" for w in shown)
        if len(run.warnings) > len(shown):
            items += (f"<br>&nbsp;&nbsp;&middot; and {len(run.warnings) - len(shown)} further warning(s) "
                      "— see the warnings list in assessment.json")
        lines.insert(0, f"<strong>Run warnings.</strong>{items}")
    if run.interception_detected:
        lines.insert(
            0,
            "<strong>TLS interception detected on the assessing network.</strong> Certificate and "
            "protocol findings were withheld for this run rather than reported against the bidders.",
        )
    return '<div class="foot">' + "<br><br>".join(lines) + "</div>"


# ---------------------------------------------------------------------------


def write_reports(run, out_dir: str) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    paths: Dict[str, str] = {}
    comparison_path = os.path.join(out_dir, "comparison.html")
    with open(comparison_path, "w", encoding="utf-8") as handle:
        handle.write(comparison(run))
    paths["comparison"] = comparison_path
    for assessment in run.assessments:
        path = os.path.join(out_dir, f"assessment-{assessment.vendor.vendor_id}.html")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(vendor_report(run, assessment))
        paths[assessment.vendor.vendor_id] = path
    return paths
