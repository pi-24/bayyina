#!/usr/bin/env python3
"""Build the five-page submission PDF.

Page order is fixed by the submission requirements:
  1 Title  2 Project objective  3 Proposed solution  4 Solution validation  5 Results and conclusions
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

TEAM = os.environ.get("BAYYINA_TEAM", "Team name")
CAPTAIN = os.environ.get("BAYYINA_CAPTAIN", "Piyush Goel")


def img(name: str) -> str:
    path = os.path.join(HERE, "figs", name)
    with open(path, "rb") as handle:
        return "data:image/png;base64," + base64.b64encode(handle.read()).decode()


CSS = """
@page { size: A4 landscape; margin: 0; }
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --ink:#101d33; --body:#2c3c56; --muted:#5f7089; --faint:#8a99ad;
  --line:#dbe2ec; --panel:#f5f8fc; --accent:#1d4e89; --accent2:#0f7b63;
  --pass:#177a55; --fail:#b3261e; --warn:#b2760a;
}
body{font:9.6px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  color:var(--body);-webkit-font-smoothing:antialiased;background:#7a8699}
.pg{width:297mm;height:210mm;background:#fff;padding:12mm 13mm 9mm;position:relative;
  page-break-after:always;overflow:hidden;display:flex;flex-direction:column}
.pg:last-child{page-break-after:auto}
.hdr{display:flex;justify-content:space-between;align-items:baseline;
  border-bottom:2.5px solid var(--ink);padding-bottom:5px;margin-bottom:11px;flex:none}
.hdr .t{font-size:15.5px;font-weight:750;color:var(--ink);letter-spacing:-.01em}
.hdr .n{font-size:8.6px;letter-spacing:.2em;text-transform:uppercase;color:var(--accent);font-weight:700}
.ftr{position:absolute;left:13mm;right:13mm;bottom:5mm;display:flex;justify-content:space-between;
  border-top:1px solid var(--line);padding-top:4px;font-size:7.6px;color:var(--faint);letter-spacing:.02em}
h3{font-size:8.8px;letter-spacing:.11em;text-transform:uppercase;color:var(--accent);
  font-weight:750;margin-bottom:5px}
h4{font-size:10.2px;color:var(--ink);font-weight:700;margin-bottom:3px}
p{margin-bottom:6px}
b,strong{color:var(--ink);font-weight:700}
.cols{display:grid;gap:9px;flex:1;min-height:0}
.c2{grid-template-columns:1fr 1fr} .c3{grid-template-columns:1fr 1fr 1fr}
.c4{grid-template-columns:repeat(4,1fr)}
.c23{grid-template-columns:1.35fr 1fr} .c32{grid-template-columns:1fr 1.5fr}
.box{border:1px solid var(--line);border-radius:4px;padding:9px 11px;background:#fff}
.box.tint{background:var(--panel)}
.box.acc{border-left:3px solid var(--accent)}
.box.red{border-left:3px solid var(--fail);background:#fdf1f0}
.box.grn{border-left:3px solid var(--pass);background:#eef7f2}
.box.amb{border-left:3px solid var(--warn);background:#fdf7ea}
ul{list-style:none}
li{padding-left:11px;position:relative;margin-bottom:4px}
li:before{content:"";position:absolute;left:0;top:5.5px;width:4px;height:4px;border-radius:1px;
  background:var(--accent);opacity:.5}
ol{counter-reset:n;list-style:none}
ol li{padding-left:17px;margin-bottom:5px}
ol li:before{counter-increment:n;content:counter(n);position:absolute;left:0;top:1px;width:12px;height:12px;
  border-radius:2px;background:var(--accent);color:#fff;font-size:7.6px;font-weight:800;
  text-align:center;line-height:12px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:8.4px}
.term{background:#101d33;color:#d6e2f0;border-radius:4px;padding:8px 10px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:8px;line-height:1.62;
  white-space:pre;overflow:hidden}
.term .g{color:#68d9a7} .term .y{color:#f0c46a} .term .r{color:#f2a09a} .term .d{color:#7f92ab}
table{width:100%;border-collapse:collapse;font-size:8.6px}
th{text-align:left;font-size:7.4px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);
  border-bottom:1.2px solid var(--line);padding:0 6px 4px 0;font-weight:750}
td{padding:4.5px 6px 4.5px 0;border-bottom:1px solid #edf1f6;vertical-align:top}
tr:last-child td{border-bottom:none}
.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.kpi{display:flex;gap:9px}
.kpi .k{flex:1;border:1px solid var(--line);border-radius:4px;padding:9px 11px;background:var(--panel)}
.kpi .v{font-size:26px;font-weight:800;color:var(--ink);letter-spacing:-.025em;line-height:1.05;
  font-variant-numeric:tabular-nums}
.kpi .l{font-size:8.6px;color:var(--body);margin-top:3px;line-height:1.42}
.kpi .s{font-size:7.4px;color:var(--faint);margin-top:4px}
.src{font-size:7.4px;color:var(--faint);margin-top:4px;line-height:1.45}
img.fig{width:100%;border:1px solid var(--line);border-radius:3px;display:block}
.tag{display:inline-block;padding:1px 5px;border-radius:2px;font-size:7.2px;font-weight:800;
  letter-spacing:.05em;text-transform:uppercase}
.tg-f{background:#fbe4e2;color:var(--fail)} .tg-p{background:#e2f2ea;color:var(--pass)}
.tg-n{background:#ece7f8;color:#5b3fa8} .tg-u{background:#eceff4;color:var(--muted)}
.lead{font-size:11.4px;line-height:1.55;color:var(--ink)}
.rule{height:1px;background:var(--line);margin:8px 0}
.mini{font-size:8.2px;line-height:1.45;color:var(--muted)}
.stack{display:flex;flex-direction:column;gap:9px;min-height:0}
table.tight td{padding:2.7px 6px 2.7px 0}
.grow{flex:1;min-height:0}
"""


def page(number: int, title: str, kicker: str, body: str, foot_left: str) -> str:
    return f"""
<div class="pg">
  <div class="hdr">
    <div><div class="n">{kicker}</div><div class="t">{title}</div></div>
    <div class="n" style="color:var(--faint)">Bayyina &nbsp;·&nbsp; {number} / 5</div>
  </div>
  {body}
  <div class="ftr"><span>{foot_left}</span>
    <span>School of Cyber Defense &nbsp;·&nbsp; Stage 2 &nbsp;·&nbsp; {TEAM}</span></div>
</div>"""


# --------------------------------------------------------------------------
# Pipeline diagram
# --------------------------------------------------------------------------

PIPELINE = """
<svg viewBox="0 0 1240 176" width="100%" style="display:block">
<style>
 .bx{fill:#f5f8fc;stroke:#c8d5e6;stroke-width:1.1;rx:4}
 .bxa{fill:#e9f0f9;stroke:#1d4e89;stroke-width:1.2;rx:4}
 .bxg{fill:#eaf6f1;stroke:#0f7b63;stroke-width:1.2;rx:4}
 .h{font:700 10px -apple-system,sans-serif;fill:#101d33}
 .s{font:8.4px -apple-system,sans-serif;fill:#5f7089}
 .lb{font:700 7.4px -apple-system,sans-serif;fill:#1d4e89;letter-spacing:.09em}
 .ar{stroke:#9db0c8;stroke-width:1.3;fill:none;marker-end:url(#a)}
</style>
<defs><marker id="a" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
<path d="M0 0 L8 4 L0 8 z" fill="#9db0c8"/></marker></defs>

<rect class="bx" x="0" y="20" width="150" height="58"/>
<text class="h" x="12" y="42">Bid field</text>
<text class="s" x="12" y="58">N bidders, one contract</text>
<text class="s" x="12" y="70">domains + questionnaires</text>

<path class="ar" d="M154 49 H196"/>

<rect class="bxa" x="200" y="4" width="176" height="102"/>
<text class="lb" x="212" y="21">PASSIVE COLLECTION</text>
<text class="s" x="212" y="37">DNS · SPF/DMARC/DNSSEC</text>
<text class="s" x="212" y="51">TLS handshake · headers</text>
<text class="s" x="212" y="65">CT logs · breach corpora</text>
<text class="s" x="212" y="79">attestation registries</text>
<text class="s" x="212" y="93">passive exposure datasets</text>

<rect class="bx" x="200" y="112" width="176" height="52"/>
<text class="lb" x="212" y="128">EVIDENCE CASSETTE</text>
<text class="s" x="212" y="144">record once, replay offline</text>
<text class="s" x="212" y="157">deterministic re-runs</text>
<path d="M288 106 V112" stroke="#9db0c8" stroke-width="1.2" stroke-dasharray="2.5 2.5"/>

<path class="ar" d="M380 49 H422"/>

<rect class="bx" x="426" y="4" width="168" height="62"/>
<text class="lb" x="438" y="21">25 CHECKS</text>
<text class="s" x="438" y="37">each with its authority:</text>
<text class="s" x="438" y="51">RFC · NIST · CISA · ISO · OWASP</text>

<rect class="bxg" x="426" y="76" width="168" height="84"/>
<text class="lb" x="438" y="93" style="fill:#0f7b63">ATTESTATION DIVERGENCE</text>
<text class="s" x="438" y="109">questionnaire answers as</text>
<text class="s" x="438" y="123">testable hypotheses; each</text>
<text class="s" x="438" y="137">claim vs what we observed</text>
<text class="s" x="438" y="151">+ reliability of the remainder</text>

<path class="ar" d="M598 35 H638 V60"/>
<path class="ar" d="M598 118 H638 V88"/>

<rect class="bxa" x="642" y="34" width="176" height="80"/>
<text class="lb" x="654" y="51">BOUNDED SCORING</text>
<text class="s" x="654" y="67">unknowns bound the interval,</text>
<text class="s" x="654" y="81">they are never imputed</text>
<text class="s" x="654" y="95">rank only when intervals</text>
<text class="s" x="654" y="109">are disjoint</text>

<path class="ar" d="M822 74 H864"/>

<rect class="bx" x="868" y="4" width="176" height="62"/>
<text class="lb" x="880" y="21">BID-FIELD CONCENTRATION</text>
<text class="s" x="880" y="37">shared upstream providers</text>
<text class="s" x="880" y="51">across competing bidders</text>

<rect class="bx" x="868" y="86" width="176" height="74"/>
<text class="lb" x="880" y="103">CONTRACT CONDITIONS</text>
<text class="s" x="880" y="119">conditions precedent, dated</text>
<text class="s" x="880" y="133">obligations, information</text>
<text class="s" x="880" y="147">requests — each re-testable</text>

<path class="ar" d="M1048 35 H1082 V64"/>
<path class="ar" d="M1048 122 H1082 V86"/>

<rect class="bxa" x="1086" y="40" width="152" height="70"/>
<text class="lb" x="1098" y="57">OUTPUT</text>
<text class="s" x="1098" y="73">award dashboard</text>
<text class="s" x="1098" y="87">per-bidder assessment</text>
<text class="s" x="1098" y="101">verifiable evidence ledger</text>
</svg>
"""


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------


def page1() -> str:
    body = f"""
<div class="stack grow">
  <div class="lead" style="max-width:none">
    A government buyer decides which supplier to trust using a document the supplier wrote about itself.
    <b>Bayyina treats that document as a set of hypotheses rather than a filing.</b> It tests every questionnaire
    answer that can be tested against externally observable evidence, estimates how far the untestable
    remainder can be relied on, refuses to rank bidders whose evidence cannot separate them, detects upstream
    dependencies shared across the bid field, and ends in drafted contract conditions with named acceptance tests.
  </div>

  <div class="kpi">
    <div class="k"><div class="v">48%</div>
      <div class="l">of breaches now involve a third party — up from 30% in 2025 and 15% in 2024</div>
      <div class="s">Verizon DBIR 2026, n &gt; 22,000 breaches across 145 countries</div></div>
    <div class="k"><div class="v">$8.45M</div>
      <div class="l">average cost of a supply-chain-compromise breach in the Middle East, against a $4.99M global
        all-breach average</div>
      <div class="s">IBM Cost of a Data Breach, Middle East findings, 3 August 2026</div></div>
    <div class="k"><div class="v">14%</div>
      <div class="l">of third-party risk professionals are highly confident that vendor questionnaire answers
        are accurate — while 84% rely on them</div>
      <div class="s">Cyentia Institute / RiskRecon, State of Third-Party Risk Management</div></div>
  </div>

  <div class="cols c23" style="flex:none">
    <div class="box acc">
      <h3>What is in this submission</h3>
      <ul style="columns:2;column-gap:16px">
        <li><b>A working prototype.</b> Python, <b>zero runtime dependencies</b>, standard library only.</li>
        <li><b>One command to reproduce.</b> <span class="mono">pip install -e . &amp;&amp; bayyina assess --tender scenarios/MDG-2026-114</span></li>
        <li><b>A complete demonstration tender.</b> Three bidders, 45 recorded observations, runs fully offline.</li>
        <li><b>122 tests</b> in 0.3 s, including a suite dedicated to <i>gaming</i> the tool — adversarial input, and every way a bidder could profit from a defective submission.</li>
        <li><b>A verifiable evidence ledger.</b> Hash-chained; editing one stored record is detected and named.</li>
        <li><b>Reports</b> — an award dashboard and a one-page assessment per bidder, self-contained HTML.</li>
        <li><b><span class="mono">docs/EVIDENCE.md</span></b> — every external claim in this deck with its source and
          how far we verified it.</li>
        <li><b>A live mode.</b> <span class="mono">bayyina live --domain &lt;domain&gt;</span> runs the identical
          pipeline against real infrastructure.</li>
      </ul>
    </div>
    <div class="box tint">
      <h3>The name</h3>
      <p><b>Bayyina</b> (بيّنة) is the Arabic legal term for clear, produced evidence — the standard a claim must
      meet before it is relied on. That is the design brief in one word: an assertion is not evidence until
      something tests it.</p>
      <div class="rule"></div>
      <h3 style="margin-top:0">Two things we will not do</h3>
      <p style="margin-bottom:4px"><b>We do not fit a model.</b> A model trained on public breach disclosures learns
      disclosure, not compromise. There is no training set here, and therefore no leakage.</p>
      <p style="margin-bottom:0"><b>We do not call the output a risk measure.</b> It is an ordinal ranking and triage
      device, and every report says so.</p>
    </div>
  </div>


  <div class="box acc" style="flex:none;padding:8px 12px;background:#eef4fb">
    <div style="display:flex;align-items:center;gap:18px">
      <div style="flex:none">
        <div class="n" style="font-size:8.2px;letter-spacing:.16em;text-transform:uppercase;
             color:var(--accent);font-weight:750">Run the prototype yourself</div>
        <div class="mono" style="font-size:11.6px;color:var(--ink);font-weight:700;margin-top:2px">
          github.com/pi-24/bayyina</div>
      </div>
      <div style="flex:1;border-left:1px solid #c6d5e8;padding-left:16px">
        <div class="mono" style="font-size:8.6px;line-height:1.65;color:var(--body)">
          git clone https://github.com/pi-24/bayyina.git &amp;&amp; cd bayyina<br>
          pip install -e .&nbsp;&nbsp;&nbsp;<span style="color:var(--faint)"># no dependencies, Python 3.9+</span><br>
          bayyina assess --tender scenarios/MDG-2026-114&nbsp;&nbsp;&nbsp;<span style="color:var(--faint)"># runs offline</span>
        </div>
      </div>
      <div style="flex:none;max-width:270px">
        <p class="mini" style="margin-bottom:0">Apache-2.0, ~5,900 lines, <b>no third-party dependencies</b>.
        A clean clone runs the full assessment offline and passes <b>122 tests in 0.3 s</b>. Every figure in this
        deck is a screenshot of that command's real output &mdash; nothing here is a mockup.</p>
      </div>
    </div>
  </div>
  <div class="box" style="flex:none;padding:7px 11px 5px">
    <h3 style="margin-bottom:3px">Where to find each thing the jury scores</h3>
    <table class="tight" style="font-size:8.3px">
      <thead><tr><th style="width:19%">Criterion</th><th style="width:8%">Weight</th>
        <th style="width:40%">Where it is addressed in this deck</th>
        <th>What to run or read in the repository</th></tr></thead>
      <tr><td><b>Fit to the brief and the business problem</b></td><td class="num">20%</td>
          <td>Page 2 &mdash; who buys it, what it replaces, and the three UAE procurement-law obligations
              behind the design</td>
          <td class="mono">README.md &middot; docs/EVIDENCE.md &sect;1, &sect;5</td></tr>
      <tr><td><b>Relevance of the proposed solution</b></td><td class="num">15%</td>
          <td>Page 2 (why questionnaires fail, what a rating costs) and page 3 (FedRAMP 20x, the CMMC
              suspension)</td>
          <td class="mono">docs/EVIDENCE.md &sect;2, &sect;3, &sect;4</td></tr>
      <tr><td><b>Does the prototype work</b></td><td class="num">25%</td>
          <td>Page 4 &mdash; reproducibility, the offline demonstration, 122 tests, and the ledger tamper
              test</td>
          <td class="mono">bayyina assess &middot; bayyina reproduce &middot; pytest -q</td></tr>
      <tr><td><b>Technical depth and correctness</b></td><td class="num">25%</td>
          <td>Page 3 (scoring model, three-state epistemics) and page 4 (no fitted model, Wilson, sensitivity)</td>
          <td class="mono">bayyina/scoring.py &middot; stats.py &middot; divergence.py</td></tr>
      <tr><td><b>Innovation</b></td><td class="num">15%</td>
          <td>Page 3, contributions 1&ndash;5 &mdash; divergence, the reliability estimator, refusing to rank,
              concentration, contract conditions</td>
          <td class="mono">bayyina/divergence.py &middot; concentration.py &middot; contract.py</td></tr>
    </table>
  </div>
</div>"""
    header = f"""
<div class="pg">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;
       border-bottom:3px solid var(--ink);padding-bottom:9px;margin-bottom:13px;flex:none">
    <div>
      <div style="font-size:8.8px;letter-spacing:.22em;text-transform:uppercase;color:var(--accent);font-weight:750">
        School of Cyber Defense &nbsp;·&nbsp; Stage 2 &nbsp;·&nbsp; Case submission</div>
      <div style="font-size:36px;font-weight:800;color:var(--ink);letter-spacing:-.03em;line-height:1.05;margin-top:4px">
        Bayyina <span style="font-size:24px;font-weight:600;color:var(--muted)">بيّنة</span></div>
      <div style="font-size:14.5px;color:var(--body);margin-top:3px">
        Evidence-based third-party vendor assurance for government contracts</div>
    </div>
    <div style="text-align:right;font-size:8.8px;color:var(--muted);line-height:1.85;padding-top:4px">
      <b style="color:var(--ink)">Topic</b><br>Third-Party / Vendor Risk Assessment<br>Automation for Government Contracts
      <div style="height:7px"></div>
      <b style="color:var(--ink)">Team</b> {TEAM}<br><b style="color:var(--ink)">Captain</b> {CAPTAIN}
    </div>
  </div>
  {body}
  <div class="ftr"><span>Title</span>
    <span>School of Cyber Defense &nbsp;·&nbsp; Stage 2 &nbsp;·&nbsp; {TEAM}</span></div>
</div>"""
    return header


def page2() -> str:
    body = """
<div class="cols c3" style="flex:none">
  <div class="stack">
    <div class="box red">
      <h4 style="color:var(--fail)">The problem</h4>
      <p>Security due diligence in public procurement is a document exchange. The buyer sends a questionnaire,
      the supplier answers it about itself, an evaluator files it. Nothing in that loop tests whether any answer
      is true, and the supplier that writes the best document wins.</p>
      <p style="margin-bottom:0">Meanwhile the supplier is now the way in. Third-party involvement in breaches went
      <b>15% → 30% → 48%</b> across three consecutive Verizon DBIRs. Government suppliers are worse than average:
      <b>58% of breaches at the top 100 US federal contractors involved a third-party vector, against the ~29%
      global figure in the same study — roughly double.</b></p>
      <div class="src">DBIR 2024/25/26 · SecurityScorecard, 22 Jan 2025</div>
    </div>
    <div class="box grow">
      <h3>The regional shape of it</h3>
      <p>Of the <b>30 largest UAE companies by revenue, 90% score A or B on their own security posture — and 73%
      have a supplier that has been breached.</b> The same study found 73% also have a breached fourth party.</p>
      <p style="margin-bottom:0"><b>Own-posture assurance is not supply-chain assurance.</b> An organisation can be
      in excellent shape and still be reached through a supplier it assessed with a PDF. That gap is the product.</p>
      <div class="src">SecurityScorecard UAE supply chain study, 11 Feb 2024 · IBM MEA, Aug 2026:
      supply chain compromise was 16% of Middle East breaches at $8.45M average cost</div>
    </div>
    <div class="box tint" style="flex:none">
      <h3>Who buys it, who runs it</h3>
      <p style="margin-bottom:0"><b>Buyer:</b> the procurement and information-security functions of a government
      entity. <b>Operator:</b> the technical evaluator on a tender panel. <b>Deployment:</b> a Python package the
      entity runs inside its own environment — no data leaves, no subscription, no per-vendor fee. <b>When:</b> at
      bid evaluation, and again as the acceptance test for each contract condition.</p>
    </div>
  </div>

  <div class="stack">
    <div class="box amb">
      <h4 style="color:var(--warn)">Why the current control does not work</h4>
      <table style="margin-top:5px">
        <tr><td class="num" style="font-size:17px;font-weight:800;color:var(--ink);width:44px">84%</td>
            <td>of firms use questionnaires to assess vendor security</td></tr>
        <tr><td class="num" style="font-size:17px;font-weight:800;color:var(--ink)">81%</td>
            <td>report that most vendors claim <i>perfect</i> compliance</td></tr>
        <tr><td class="num" style="font-size:17px;font-weight:800;color:var(--fail)">14%</td>
            <td>are highly confident those answers are accurate</td></tr>
      </table>
      <p style="margin-top:6px;margin-bottom:0">Near-universal use. Near-universal passing. Near-zero belief.
      The Cloud Security Alliance — which authors the CAIQ questionnaire — publishes the same critique itself:
      responses <i>"only represent a single point in time"</i> and <i>"are rarely evaluated."</i></p>
      <div class="src">Cyentia/RiskRecon (n=154, 2020 — old and small, and we say so) · CSA, 2 Apr 2025</div>
    </div>
    <div class="box grow">
      <h3>What Bayyina replaces</h3>
      <ul>
        <li><b>Manual questionnaire triage.</b> 5–15 hours to complete one, and often nobody reads it. Bayyina
          tests the testable subset in seconds and puts a named human only where judgement is genuinely required.</li>
        <li><b>The external-signal half of a commercial security rating.</b> Roughly 71.5% of a Bitsight rating
          is externally observable configuration; UpGuard's is explicitly 50% automated scanning. Reported market
          price is <b>$150–400 per vendor per year with a $12–25k floor</b> — economically absurd for a buyer
          assessing three bidders on one contract.</li>
        <li><b>The gap nothing currently fills:</b> comparing bidders against <i>each other</i>, and testing what
          each one claimed.</li>
      </ul>
      <div class="src">Bitsight and UpGuard published methodologies · pricing from Vendr negotiated-deal
      aggregation, not vendor list prices</div>
    </div>
  </div>

  <div class="stack">
    <div class="box acc">
      <h4>What UAE law already requires — and a questionnaire cannot deliver</h4>
      <p><b>Federal Law No. 11 of 2023 on Procurement in the Federal Government</b></p>
      <ul style="margin-top:2px">
        <li><b>Art. 22(3)</b> — non-financial evaluation criteria must be <i>"objective … and quantifiable as much
          as possible."</i> A questionnaire yes/no is neither.</li>
        <li><b>Art. 22(4)</b> — the tender must publish <i>"the weight assigned to each criterion"</i> in advance.
          So in Bayyina weights live in the buyer's tender file, never in the tool, and every report prints the
          set that was used.</li>
        <li><b>Art. 29</b> — a failed bidder may request <i>"the weaknesses and strengths of its bid."</i> So every
          finding keeps the raw observation that produced it, and the per-bidder report is written to be handed over.</li>
      </ul>
      <div class="rule"></div>
      <p style="margin-bottom:3px"><b>UAE National Cloud Security Policy</b> requires organisations to
      <i>"identify security risks from third-party suppliers and require independent security testing rather than
      relying solely on provider assertions."</i></p>
      <p style="margin-bottom:0"><b>Dubai DESC ISR v3</b> extends obligations to <i>"consultants, contractors"</i>
      and to <i>"external party and managed services"</i>, with Third Party Management as a named domain. The UAE
      Information Assurance Standard carries a Third Party Security control family.</p>
      <div class="src">Ministry of Finance PDF · Pinsent Masons analysis of the Cloud Security Policy ·
      DESC ISR v3.0 announcement. Full sourcing and confidence levels in docs/EVIDENCE.md</div>
    </div>
  </div>

</div>
<div class="box" style="margin-top:7px;flex:1;min-height:0;padding:6px 11px 4px">
  <h3 style="margin-bottom:3px">Against the two things a government buyer uses today</h3>
  <table class="tight" style="font-size:8.4px">
    <thead><tr><th style="width:34%">Capability</th><th style="width:20%">Security questionnaire</th>
      <th style="width:23%">Commercial security rating</th><th>Bayyina</th></tr></thead>
    <tr><td>Tests whether the supplier&rsquo;s answers are true</td>
        <td><span class="tag tg-u">No</span> <span class="mini">it <i>is</i> the answer</span></td>
        <td><span class="tag tg-u">No</span> <span class="mini">never sees the questionnaire</span></td>
        <td><span class="tag tg-p">Yes</span> <span class="mini">15 predicates, claim by claim</span></td></tr>
    <tr><td>Declines to rank when the evidence cannot separate two bidders</td>
        <td><span class="tag tg-u">n/a</span></td>
        <td><span class="tag tg-u">No</span> <span class="mini">always emits a number</span></td>
        <td><span class="tag tg-p">Yes</span> <span class="mini">disjoint-interval rule; unobserved checks widen it</span></td></tr>
    <tr><td>Compares bidders against <i>each other</i>, and finds shared upstream providers</td>
        <td><span class="tag tg-u">No</span></td>
        <td><span class="tag tg-u">No</span> <span class="mini">rates one company at a time</span></td>
        <td><span class="tag tg-p">Yes</span> <span class="mini">DNS, mail, edge and CA across the field</span></td></tr>
    <tr><td><b>Sees active compromise &mdash; botnet, C2 and sinkhole telemetry</b></td>
        <td><span class="tag tg-u">No</span></td>
        <td><span class="tag tg-p">Yes</span> <span class="mini">~26% of a Bitsight rating</span></td>
        <td><span class="tag tg-f">No</span> <span class="mini">no sensor network &mdash; and we say so</span></td></tr>
    <tr><td>Cost to assess three bidders on one contract</td>
        <td class="mini">5&ndash;15 analyst hours per questionnaire, often unread</td>
        <td class="mini">$12&ndash;25k floor; $150&ndash;400 per vendor per year at volume</td>
        <td class="mini">Free, self-hosted; no data leaves the buyer</td></tr>
  </table>
</div>"""
    return page(2, "Project objective", "Fit to the brief and the business problem",
                body, "Project objective")


def page3() -> str:
    body = f"""
<div class="stack grow">
  <div class="box" style="padding:7px 9px;flex:none">{PIPELINE}</div>

  <div class="cols c3" style="flex:none">
    <div class="box grn">
      <h4><span style="color:var(--pass)">1.</span> The questionnaire becomes testable</h4>
      <p style="margin-bottom:0">Each answer carries a named predicate. A bidder that answered <i>"we enforce DMARC"</i>
      has made a claim one DNS lookup refutes. <b>A contradiction is weighted above the underlying control gap:</b>
      a missing DMARC record is a hygiene weakness, but a <i>claim</i> of enforcement with <span class="mono">p=none</span>
      published is an accuracy failure in a document the bidder signed and the buyer is relying on.</p>
    </div>
    <div class="box grn">
      <h4><span style="color:var(--pass)">2.</span> The untestable remainder gets a number</h4>
      <p style="margin-bottom:0">Most of a questionnaire cannot be checked from outside — background screening, key
      management, backup restoration. But the testable claims are a <b>sample</b>, and how they fare
      measures how far to trust the rest. Reported as a <b>Wilson score interval</b> over <i>independent evidence
      sources</i>, not over claims — three attestations can be tested against one HTTP response, and counting
      those as three trials would report an interval narrower than the evidence supports.</p>
    </div>
    <div class="box grn">
      <h4><span style="color:var(--pass)">3.</span> Unknowns bound the score; they are never imputed</h4>
      <p style="margin-bottom:0">Every score is an interval: the lower bound assumes every unobserved check
      would have failed, the upper that every one would have passed. <b>A bidder is ranked above another only
      when its lower bound exceeds the other's upper bound</b>, and a tier boundary holds only if <i>every</i>
      member of a tier dominates <i>every</i> member below — otherwise the tiers merge. No prior, no
      distribution, nothing to attack.</p>
    </div>
  </div>

  <div class="cols c3" style="flex:none">
    <div class="box grn">
      <h4><span style="color:var(--pass)">4.</span> The bid field, not just the bidder</h4>
      <p style="margin-bottom:0">DORA Art. 29 asks one buyer about concentration across <i>its own</i> portfolio.
      Nobody asks it across a <i>tender</i>. A buyer splitting an award between two bidders that terminate TLS at the
      same CDN and route mail through the same provider has bought two invoices and one failure domain — invisible to
      every commercial rating, because each rates one company alone.</p>
    </div>
    <div class="box grn">
      <h4><span style="color:var(--pass)">5.</span> It ends in contract language</h4>
      <p style="margin-bottom:0">An assessment ending in a score changes nothing. Each finding becomes a drafted
      obligation with a window sized by severity and contract criticality, and <b>a named acceptance test — re-running
      the check that produced it.</b> Three classes: conditions precedent to award, dated contract conditions, and
      information requests routed to a named reviewer.</p>
    </div>
    <div class="box acc">
      <h4>Why this, why now</h4>
      <p style="margin-bottom:0"><b>FedRAMP 20x</b> is replacing static narrative assessment with Key Security
      Indicators — machine-readable, continuously validated assertions; Phase 3 began April 2026. In the other
      direction, <b>CMMC Phase II was suspended in July 2026</b>, with the cost and burden of mandatory third-party
      certification on small suppliers given as the reason. Government assurance is moving from attestation documents
      to machine-checkable evidence, and it has to get cheaper while doing it.</p>
    </div>
  </div>

  <div class="cols c3" style="flex:none">
    <div class="box tint">
      <h3>Scope policy — enforced in the transport layer, not just documented</h3>
      <p style="margin-bottom:0">DNS over HTTPS, one TLS handshake, one HTTPS GET per endpoint, and public datasets.
      <b>There is no primitive in this codebase for port scanning, vulnerability probing, authentication attempts,
      fuzzing or zone transfer.</b> That is a legal position as much as an engineering one: the UK Computer Misuse Act
      1990 s.1 has no statutory research defence and the status of port scanning is unresolved, and the US DOJ's 2022
      CFAA charging policy is prosecutorial policy rather than statute and confers no civil immunity. Restricting the
      tool to observations a bidder's own customers make every day is what lets a buyer run it across a bid field
      without per-bidder authorisation.</p>
    </div>
    <div class="box tint">
      <h3>Exposed services, read rather than scanned</h3>
      <p style="margin-bottom:0">The brief asks for exposed services, and enumerating them ourselves would
      mean port scanning. That enumeration has already been done, publicly and continuously, by
      internet-wide measurement projects — so the buyer supplies a passive export (Censys, Shodan, Rapid7
      Open Data, or its own attack-surface inventory) and Bayyina <b>reads the observation rather than
      making it</b>. Zero packets reach the bidder, and the finding still carries a timestamp, a named
      source and a raw record the bidder can dispute. With no dataset supplied the check returns
      <b>unknown</b>, never clean — the requirement visibly unmet rather than quietly assumed away.</p>
    </div>
    <div class="box tint">
      <h3>Three states, not two</h3>
      <p style="margin-bottom:0">Most tools have pass and fail. Bayyina distinguishes <b>unknown</b> (the control
      applies, we could not observe it — widens the interval), <b>not applicable</b> (nothing for the control to bite
      on, such as disclosure timeliness for a vendor with no incidents — leaves the denominator, so a clean vendor is
      not punished with uncertainty it did not earn), and <b>needs human</b> (no machine can decide whether an ISO 27001
      scope statement covers the delivering entity — so it goes to a named reviewer, never to a silent pass).
      Conflating any two of these is how a scoring tool quietly tells a buyer something it does not know.</p>
    </div>
  </div>
</div>"""
    return page(3, "Proposed solution", "Architecture and the five contributions",
                body, "Proposed solution")


def page4() -> str:
    body = f"""
<div class="cols c3">
  <div class="stack">
    <div class="box" style="flex:none">
      <h3>Does it run, and does it run twice?</h3>
      <div class="term"><span class="d">$</span> bayyina reproduce --tender scenarios/MDG-2026-114
  run 1: ledger head <span class="y">142e94cca9a8…</span>  digest <span class="y">08e678bb…</span>
  run 2: ledger head <span class="y">142e94cca9a8…</span>  digest <span class="y">08e678bb…</span>

<span class="g">Identical.</span> Same cassette in, same evidence
chain and same scores out.</div>
      <p style="margin-top:6px;margin-bottom:0">Determinism is <b>proved, not claimed</b>. Timestamps come from the
      evidence rather than the wall clock, evidence is hashed through canonical JSON, and the ledger is written in
      sorted order. Certificate expiry is measured against the observation date, so a replay gives the same answer
      next year as it did today.</p>
    </div>
    <div class="box tint" style="flex:none">
      <h3>Reproduce it yourself, in this order</h3>
      <div class="term"><span class="d">$</span> git clone https://github.com/pi-24/bayyina.git
<span class="d">$</span> pip install -e .          <span class="d"># no dependencies</span>
<span class="d">$</span> bayyina assess    --tender scenarios/MDG-2026-114
<span class="d">$</span> bayyina reproduce --tender scenarios/MDG-2026-114
<span class="d">$</span> bayyina verify-ledger out/&hellip;/evidence-ledger.jsonl
<span class="d">$</span> bayyina checks --check DNS-002
<span class="d">$</span> python -m pytest -q
<span class="d">$</span> bayyina live --domain &lt;a-real-domain&gt;</div>
      <p class="mini" style="margin-top:6px;margin-bottom:0">Python 3.9+. Nothing to configure, no API key, no
      network needed for anything except the last line.</p>
    </div>
    <div class="box grow">
      <h3>Record / replay — why the offline demo is honest</h3>
      <p>Evidence collection and evidence <i>use</i> are separate layers. A <b>cassette</b> is a recorded set of raw
      observations with the timestamp each was taken at. <span class="mono">--mode replay</span> performs no network
      activity; <span class="mono">--mode record</span> collects live.</p>
      <p style="margin-bottom:0"><b>The scoring pipeline cannot tell the difference.</b> The run reproduced offline
      executes exactly the same check, scoring, divergence, concentration and reporting code as a live run — only the
      transport differs. Nothing in the analysis path is stubbed for the demonstration.</p>
    </div>
  </div>

  <div class="stack">
    <div class="box" style="flex:none">
      <h3>Tests — 122, in 0.3 seconds</h3>
      <table>
        <tr><td><b>Scoring invariants</b></td><td class="mini">the point estimate can never fall outside its bounds;
          an unknown widens the interval without moving the estimate; zero evidence yields the full range</td></tr>
        <tr><td><b>Adversarial input</b></td><td class="mini">null bytes, 5,000-character records, emoji, SQL and path
          traversal strings, HTML injection, Arabic text — every parser is asserted to <b>never read garbage as a
          passing control</b></td></tr>
        <tr><td><b>Failure direction</b></td><td class="mini">a check that raises must not abort the run, and must not
          produce a PASS; a questionnaire that will not parse must leave the bidder unrankable, never approved</td></tr>
        <tr><td><b>Ledger integrity</b></td><td class="mini">edit, delete or reorder a record — each is detected
          separately and named</td></tr>
        <tr><td><b>Statistics</b></td><td class="mini">Wilson checked against hand-computed values; bounds stay
          inside [0,1] at the extremes where the normal approximation fails; a perfect small sample must not
          read as certainty; clustering must never <i>narrow</i> an interval</td></tr>
    <tr><td><b>Anti-gaming</b></td><td class="mini">a corrupt questionnaire must lower a bidder's upper bound,
          never raise it; a wide-interval bidder must not split the field into tiers its own pairwise table
          denies; a typo in a weight name must be reported, not silently absorbed</td></tr>
      </table>
    </div>
    <div class="box red grow">
      <h4 style="color:var(--fail)">Tamper test</h4>
      <p class="mini" style="margin-bottom:5px">One stored DMARC record edited to claim an enforcing policy:</p>
      <div class="term"><span class="r">Chain does NOT verify.</span>
  ! record 6 (evidence): payload does not
    match its hash — the stored evidence was
    modified after it was recorded</div>
      <p style="margin-top:6px;margin-bottom:0">Stated precisely: this is tamper-<b>evidence</b>, not tamper-proofing.
      Anyone holding the file can rewrite the whole chain. It defends against silent mutation of a stored assessment,
      which is the realistic procurement risk; defending against a malicious operator needs a countersignature from a
      party who does not control the file.</p>
    </div>
  </div>

  <div class="stack">
    <div class="box acc" style="flex:none">
      <h3>Is the method correct?</h3>
      <p><b>No machine learning, deliberately.</b> There is no adequate labelled dataset: a model trained on public
      breach disclosures learns <i>disclosure</i>, not compromise. Sarabi et al. (<i>Journal of Cybersecurity</i>, 2016)
      predicted disclosed breaches at ~90% TP / 11% FP from <b>business-profile data alone</b> — industry, size, traffic
      rank, no security measurements at all. A technical rating performing similarly may be reproducing firmographics.
      <b>Nothing here is fitted, so there is no train/test split and no leakage.</b></p>
      <p><b>The composite is declared ordinal.</b> Multiplying ordinal severities and calling the product "risk" is not
      quantification — there is no unit. Bayyina claims a ranking and triage device and says so in every report. The one
      probabilistic statement it makes carries an interval and a named estimator.</p>
      <p style="margin-bottom:0"><b>The weights are not load-bearing, and we measure it.</b> 2,000 Dirichlet-perturbed
      weight vectors (α = 40 × weight, seeded so the figure reproduces) plus a leave-one-criterion-out analysis: the
      leader is unchanged in <b>100%</b> of samples and under every single criterion removal. This measures the
      stability of the <i>indicative point order</i> — the dominance tiers do not turn on the weighting in the same
      way — and bidders with no point estimate are excluded rather than sorted last on a sentinel.</p>
    </div>
    <div class="box amb" style="flex:none">
      <h4 style="color:var(--warn)">What it cannot do</h4>
      <p style="margin-bottom:0" class="mini">No sinkhole or darknet telemetry, so <b>no visibility of active
      compromise</b> — roughly a quarter of a commercial rating that we do not have. <b>ISO 27001 scope adequacy cannot
      be automated</b>, and is routed to a human. <b>SOC 2 cannot be verified at all</b> beyond the CPA firm: it is a
      private attestation with no registry. <b>Absence from IAF CertSearch is not evidence of a false certificate</b> —
      DAkkS, Germany's national accreditation body, publicly declined to apply IAF MD 28:2023 on 15 Nov 2024. Breach
      history measures <i>disclosed</i> breaches, so a clean record is weak evidence of safety. Every one of these is
      printed in the output rather than hidden.</p>
    </div>
    <div class="box tint" style="flex:none">
      <h3>A bug the build environment taught us</h3>
      <p style="margin-bottom:0" class="mini">This tool was built inside a network whose egress gateway terminates and
      re-issues TLS. A naive collector there reports a <b>perfectly healthy certificate for every host on the
      internet</b> — because it is describing the middlebox. Bayyina now detects that two ways, including the structural
      giveaway that unrelated bidders share one certificate issuer, and <b>withholds the finding rather than reporting
      a number it cannot stand behind.</b></p>
    </div>
  </div>
</div>"""
    return page(4, "Solution validation", "Reproducibility, testing and method correctness",
                body, "Solution validation")


def page5() -> str:
    body = f"""
<div class="cols c32">
  <div class="stack">
    <div class="box" style="flex:none">
      <h3>The demonstration tender — MDG-2026-114</h3>
      <p class="mini" style="margin-bottom:6px">Three bidders for a citizen case-management platform.
      <b>Meridian</b> submits the strongest paper bid: ISO 27001, SOC 2 Type II, a near-perfect questionnaire.
      <b>Nawras</b> submits less. <b>Orion</b> is barely observable from outside.</p>
      <img class="fig" src="{img('intervals.png')}" alt="Score intervals by bidder">
      <p class="mini" style="margin-top:6px;margin-bottom:0">The bar is the range the evidence supports; the tick is
      the point estimate over observed evidence only. <b>Where two bars overlap, the tool does not rank those bidders
      against each other.</b></p>
    </div>
    <div class="box" style="flex:none;padding-top:7px">
      <img class="fig" src="{img('summary.png')}" alt="Bid field summary table" style="border:none">
    </div>
    <div class="box red" style="flex:none">
      <h4 style="color:var(--fail)">Result: the paper favourite is overturned, and the tool can say exactly why</h4>
      <p style="margin-bottom:4px"><b>10 of Meridian's 16 externally testable attestations are contradicted by
      evidence</b> — a claimed enforcing DMARC policy published at <span class="mono">p=none</span>; claimed
      TLS 1.0/1.1 removal on endpoints that still accept both; a claim that no administrative service is
      internet-facing, against RDP and an unauthenticated Elasticsearch 6.8 in the passive exposure data; a
      claimed absence of sub-processor incidents against a 2024 compromise through a third-party CRM; and an
      ISO 27001 certificate whose scope covers <i>"managed IT support services … from the Dubai office"</i> —
      not the entity that would deliver the contract.</p>
      <p style="margin-bottom:0">Those 16 claims rest on <b>11 independent evidence sources</b>, of which 3
      corroborated everything resting on them — an estimated attestation reliability of <b>27% (95% CI
      10–57%)</b>. Twenty further responses could not be tested externally, and nothing here supports treating
      them as more reliable.</p>
    </div>
    <div class="box tint grow" style="padding:7px 11px 5px">
      <h3 style="margin-bottom:3px">Provenance and honesty</h3>
      <p class="mini" style="margin-bottom:0;font-size:7.8px;line-height:1.36">The three bidders are fictional; their domains are reserved under
      RFC 2606 and all 45 observations were generated by
      <span class="mono">scenarios/build_demo.py</span>. Real findings about real named companies would
      assert things they cannot rebut, and a live run cannot be reproduced later. The scenario
      deliberately exercises three distinct outcomes, so the contrast is sharper than a typical bid field; its
      attestation evidence comes from the real collector and registry.
      Sources: <span class="mono">docs/EVIDENCE.md</span>.</p>
    </div>
  </div>

  <div class="stack">
    <div class="box" style="flex:none;padding-top:7px">
      <img class="fig" src="{img('divergence.png')}" alt="Attestation divergence ledger" style="border:none">
    </div>

    <div class="cols c3" style="flex:none;display:grid">
      <div class="box grn" style="padding:8px 10px">
        <h4 style="color:var(--pass);font-size:9.4px">Nawras — ranked first, defensibly</h4>
        <p class="mini" style="margin-bottom:0">Interval <b>98–98</b>, coverage 100%, <b>zero contradictions in 15 testable
        claims across 11 evidence sources</b>. Reliability 100% (95% CI 74–100%) — a small perfect sample is
        still reported as an interval, not as certainty. Leader in 100% of 2,000 perturbed weightings and under
        every criterion removal.</p>
      </div>
      <div class="box amb" style="padding:8px 10px">
        <h4 style="color:var(--warn);font-size:9.4px">Orion — not ranked</h4>
        <p class="mini" style="margin-bottom:0">Its endpoint requires client-certificate authentication, so three TLS
        checks are genuinely unobservable; the CT query timed out; there is no incident record and no exposure data.
        Coverage <b>57%</b> — below the two-thirds threshold at which the tool considers a point estimate worth
        reading, and it says so. Interval <b>32–76</b>. Rather than invent a ranking, it emits <b>12 information
        requests</b> naming what would resolve it.</p>
      </div>
      <div class="box red" style="padding:8px 10px">
        <h4 style="color:var(--fail);font-size:9.4px">Concentration</h4>
        <p class="mini" style="margin-bottom:0">Meridian and Orion share <b>authoritative DNS, edge/CDN and mail
        exchange</b>. A split award between them would not create independent failure domains — a fact no per-vendor
        rating can surface, because each rates one company alone.</p>
      </div>
    </div>

    <div class="box acc" style="flex:none">
      <h3>What the buyer does differently on Monday</h3>
      <ul style="columns:2;column-gap:14px">
        <li><b>The award is defensible.</b> One bidder is ranked first and the evidence separates it; two are
          declared inseparable rather than ordered on noise.</li>
        <li><b>Each bidder can be handed a report</b> carrying the raw observation behind every finding — which
          is what Art. 29 asks for.</li>
        <li><b>Ten conditions precedent</b> attach to the favourite before any award, each naming the attestation
          it corrects and the check that re-tests it.</li>
        <li><b>Thirteen conditions precedent and thirty-six contract conditions</b> across the field, each with a
          severity-sized window and a machine-checkable acceptance test.</li>
        <li><b>The split-award plan changes</b>, because two of the three bidders are not independent.</li>
        <li><b>Re-running the same checks</b> after award turns each condition into continuous monitoring rather
          than a one-off gate.</li>
      </ul>
    </div>

    <div class="box tint" style="flex:none;padding:8px 11px">
      <h3 style="margin-bottom:4px">Next</h3>
      <p class="mini" style="margin-bottom:7px"><b>Bidder self-service</b> — let a supplier run the assessment on
      itself before bidding, so the tool reduces the compliance burden it inspects rather than adding to it.
      <b>Arabic reporting</b>, and mapping the catalogue to UAE IAS and DESC ISR control identifiers so a finding
      cites the control a Dubai evaluator already works to.</p>
    </div>
  </div>
</div>"""
    return page(5, "Results and conclusions", "What the tool found, and what a buyer does with it",
                body, "Results and conclusions")


def main() -> None:
    html = (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f"<title>Bayyina — Stage 2 submission</title><style>{CSS}</style></head><body>"
            + page1() + page2() + page3() + page4() + page5()
            + "</body></html>")
    html_path = os.path.join(HERE, "deck.html")
    with open(html_path, "w", encoding="utf-8") as handle:
        handle.write(html)

    from playwright.sync_api import sync_playwright

    pdf_path = os.path.join(ROOT, "Bayyina-Stage2-Submission.pdf")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page_ = browser.new_page()
        page_.goto("file://" + html_path)
        page_.wait_for_timeout(700)
        page_.pdf(path=pdf_path, format="A4", landscape=True, print_background=True,
                  margin={"top": "0", "right": "0", "bottom": "0", "left": "0"})
        browser.close()
    size = os.path.getsize(pdf_path)
    print(f"wrote {pdf_path}  ({size/1024/1024:.2f} MB)")


if __name__ == "__main__":
    main()
