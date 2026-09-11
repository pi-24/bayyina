#!/usr/bin/env python3
"""Build the five-page submission PDF.

Page order is fixed by the submission requirements:
  1 Title  2 Project objective  3 Proposed solution  4 Solution validation  5 Results and conclusions

Deliberately spare. This is three days of one person's work and the deck should
read like it — a handful of claims, each carrying its weight, with the detail
left in the repository rather than crammed into the margins.
"""

from __future__ import annotations

import base64
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

TEAM = os.environ.get("BAYYINA_TEAM", "Team name")
CAPTAIN = os.environ.get("BAYYINA_CAPTAIN", "Piyush Goel")
REPO = os.environ.get("BAYYINA_REPO", "github.com/pi-24/bayyina")


def img(name: str) -> str:
    with open(os.path.join(HERE, "figs", name), "rb") as handle:
        return "data:image/png;base64," + base64.b64encode(handle.read()).decode()


CSS = """
@page { size: A4 landscape; margin: 0; }
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --ink:#101d33; --body:#31415c; --muted:#64758e; --faint:#93a2b6;
  --line:#dde4ee; --panel:#f6f9fc; --accent:#1d4e89;
  --pass:#177a55; --fail:#b3261e; --warn:#b2760a;
}
body{font:10.6px/1.62 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  color:var(--body);-webkit-font-smoothing:antialiased;background:#7a8699}
.pg{width:297mm;height:210mm;background:#fff;padding:15mm 16mm 11mm;position:relative;
  page-break-after:always;overflow:hidden;display:flex;flex-direction:column}
.pg:last-child{page-break-after:auto}
.hdr{display:flex;justify-content:space-between;align-items:baseline;
  border-bottom:2.5px solid var(--ink);padding-bottom:7px;margin-bottom:18px;flex:none}
.hdr .t{font-size:19px;font-weight:750;color:var(--ink);letter-spacing:-.015em}
.hdr .n{font-size:9px;letter-spacing:.2em;text-transform:uppercase;color:var(--accent);font-weight:700}
.ftr{position:absolute;left:16mm;right:16mm;bottom:6mm;display:flex;justify-content:space-between;
  border-top:1px solid var(--line);padding-top:5px;font-size:8px;color:var(--faint);letter-spacing:.02em}
h3{font-size:9.4px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);
  font-weight:750;margin-bottom:7px}
h4{font-size:12px;color:var(--ink);font-weight:700;margin-bottom:5px}
p{margin-bottom:9px}
p:last-child{margin-bottom:0}
b,strong{color:var(--ink);font-weight:700}
.cols{display:grid;gap:16px;flex:1;min-height:0}
.c2{grid-template-columns:1fr 1fr} .c3{grid-template-columns:1fr 1fr 1fr}
.c32{grid-template-columns:1fr 1.18fr}
.box{border:1px solid var(--line);border-radius:5px;padding:14px 16px;background:#fff}
.box.tint{background:var(--panel)}
.box.acc{border-left:3px solid var(--accent)}
.box.red{border-left:3px solid var(--fail);background:#fdf2f1}
.box.grn{border-left:3px solid var(--pass);background:#eff8f3}
.box.amb{border-left:3px solid var(--warn);background:#fdf8ec}
ul{list-style:none}
li{padding-left:14px;position:relative;margin-bottom:7px}
li:last-child{margin-bottom:0}
li:before{content:"";position:absolute;left:0;top:6.5px;width:4px;height:4px;border-radius:1px;
  background:var(--accent);opacity:.55}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:9.4px}
.term{background:#101d33;color:#d6e2f0;border-radius:5px;padding:11px 13px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:9px;line-height:1.72;
  white-space:pre;overflow:hidden}
.term .g{color:#68d9a7} .term .y{color:#f0c46a} .term .r{color:#f2a09a} .term .d{color:#8497ae}
.kpi{display:flex;gap:16px}
.kpi .k{flex:1;border:1px solid var(--line);border-radius:5px;padding:14px 16px;background:var(--panel)}
.kpi .v{font-size:34px;font-weight:800;color:var(--ink);letter-spacing:-.03em;line-height:1;
  font-variant-numeric:tabular-nums}
.kpi .l{font-size:10px;color:var(--body);margin-top:7px;line-height:1.5}
.kpi .s{font-size:8.2px;color:var(--faint);margin-top:6px}
img.fig{width:100%;border-radius:4px;display:block}
.lead{font-size:13.6px;line-height:1.6;color:var(--ink)}
.rule{height:1px;background:var(--line);margin:12px 0}
.mini{font-size:9.3px;line-height:1.55;color:var(--muted)}
.stack{display:flex;flex-direction:column;gap:16px;min-height:0;justify-content:flex-start}
.grow{flex:1;min-height:0}
.vc{display:flex;flex-direction:column;justify-content:center}
.stat{display:flex;align-items:baseline;gap:10px;margin-bottom:7px}
.stat .n{font-size:21px;font-weight:800;color:var(--ink);font-variant-numeric:tabular-nums;
  min-width:46px;line-height:1.2}
.stat .t{font-size:10.2px;line-height:1.45}
"""


def page(number, title, kicker, body, foot_left):
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


PIPELINE = """
<svg viewBox="0 0 1180 132" width="100%" style="display:block">
<style>
 .bx{fill:#f6f9fc;stroke:#ccd9e9;stroke-width:1.1;rx:5}
 .bxa{fill:#e9f1f9;stroke:#1d4e89;stroke-width:1.3;rx:5}
 .bxg{fill:#eef8f2;stroke:#177a55;stroke-width:1.3;rx:5}
 .h{font:700 11px -apple-system,sans-serif;fill:#101d33}
 .s{font:9.4px -apple-system,sans-serif;fill:#64758e}
 .ar{stroke:#a6b7cd;stroke-width:1.4;fill:none;marker-end:url(#a)}
</style>
<defs><marker id="a" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
<path d="M0 0 L8 4 L0 8 z" fill="#a6b7cd"/></marker></defs>

<rect class="bx" x="0" y="34" width="176" height="64"/>
<text class="h" x="16" y="60">The bid field</text>
<text class="s" x="16" y="80">domains + questionnaires</text>

<path class="ar" d="M180 66 H222"/>

<rect class="bxa" x="226" y="34" width="196" height="64"/>
<text class="h" x="242" y="60">Passive evidence</text>
<text class="s" x="242" y="80">DNS · TLS · headers · public data</text>

<path class="ar" d="M426 66 H468"/>

<rect class="bxg" x="472" y="8" width="196" height="52"/>
<text class="h" x="488" y="32">Test every claim</text>
<text class="s" x="488" y="50">questionnaire vs observation</text>

<rect class="bx" x="472" y="72" width="196" height="52"/>
<text class="h" x="488" y="96">25 control checks</text>
<text class="s" x="488" y="114">RFC · NIST · CISA · ISO · OWASP</text>

<path class="ar" d="M672 34 H710 V58"/>
<path class="ar" d="M672 98 H710 V74"/>

<rect class="bxa" x="714" y="34" width="196" height="64"/>
<text class="h" x="730" y="60">Score as a range</text>
<text class="s" x="730" y="80">rank only when ranges are disjoint</text>

<path class="ar" d="M914 66 H956"/>

<rect class="bx" x="960" y="34" width="220" height="64"/>
<text class="h" x="976" y="60">Report + contract clauses</text>
<text class="s" x="976" y="80">each with a re-runnable test</text>
</svg>
"""


def page1():
    return f"""
<div class="pg">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;
       border-bottom:3px solid var(--ink);padding-bottom:13px;margin-bottom:22px;flex:none">
    <div>
      <div style="font-size:9.4px;letter-spacing:.22em;text-transform:uppercase;color:var(--accent);font-weight:750">
        School of Cyber Defense &nbsp;·&nbsp; Stage 2 &nbsp;·&nbsp; Case submission</div>
      <div style="font-size:44px;font-weight:800;color:var(--ink);letter-spacing:-.035em;line-height:1.05;margin-top:7px">
        Bayyina <span style="font-size:29px;font-weight:600;color:var(--muted)">بيّنة</span></div>
      <div style="font-size:16.5px;color:var(--body);margin-top:5px">
        Evidence-based vendor assurance for government contracts</div>
    </div>
    <div style="text-align:right;font-size:9.6px;color:var(--muted);line-height:2;padding-top:6px">
      <b style="color:var(--ink)">Topic</b><br>Third-Party / Vendor Risk Assessment<br>Automation for Government Contracts
      <div style="height:9px"></div>
      <b style="color:var(--ink)">Team</b> {TEAM} &nbsp;·&nbsp; <b style="color:var(--ink)">Captain</b> {CAPTAIN}
    </div>
  </div>

  <div class="stack grow">
    <div class="lead">
      A government buyer decides which supplier to trust by reading a document the supplier wrote about itself.
      <b>Bayyina treats that document as a set of claims to be tested, not a form to be filed.</b> It checks every
      questionnaire answer that can be checked against evidence a buyer can gather without permission, and it
      refuses to rank bidders when the evidence cannot separate them.
    </div>

    <div class="kpi">
      <div class="k"><div class="v">48%</div>
        <div class="l">of breaches now involve a third party — 15% two years ago</div>
        <div class="s">Verizon DBIR 2026</div></div>
      <div class="k"><div class="v">$8.45M</div>
        <div class="l">average cost of a supply-chain breach in the Middle East</div>
        <div class="s">IBM Cost of a Data Breach, August 2026</div></div>
      <div class="k"><div class="v">14%</div>
        <div class="l">of risk professionals believe vendor questionnaire answers — 84% rely on them anyway</div>
        <div class="s">Cyentia Institute / RiskRecon</div></div>
    </div>

    <div class="box acc" style="flex:none;background:#eff4fb">
      <div style="display:flex;align-items:center;gap:26px">
        <div style="flex:none">
          <h3 style="margin-bottom:3px">Run it yourself</h3>
          <div class="mono" style="font-size:13px;color:var(--ink);font-weight:700">{REPO}</div>
        </div>
        <div style="flex:1;border-left:1px solid #ccdaeb;padding-left:24px">
          <div class="mono" style="font-size:9.6px;line-height:1.8;color:var(--body)">
            git clone https://{REPO}.git &amp;&amp; cd bayyina<br>
            pip install -e .<br>
            bayyina assess --tender scenarios/MDG-2026-114
          </div>
        </div>
        <div style="flex:none;max-width:290px">
          <p class="mini">Python, <b>no third-party dependencies</b>. Runs offline in about a second and passes
          122 tests. Every figure in this deck is a screenshot of that command's output.</p>
        </div>
      </div>
    </div>

    <div class="box grow" style="display:flex;flex-direction:column">
      <h3>That command, on the demonstration tender</h3>
      <div class="term" style="flex:1;font-size:10.4px;line-height:1.85">  BIDDER        POINT         RANGE   COVER  CONTRA           RELIABILITY
  <span class="g">nawras         97.8         98–98    100%     0/15      100% (74–100%)</span>
  <span class="y">orion          58.5         32–76     57%     3/6         75% (30–95%)</span>
  <span class="r">meridian       31.8         31–35     96%    10/16        27% (10–57%)</span>

  Ranking
    Tier 1: nawras
    Tier 2: orion, meridian  <span class="d">(not separable on available evidence)</span></div>
      <p class="mini" style="margin-top:11px;margin-bottom:0">Meridian submitted the strongest paperwork of the
      three and finishes last, because ten of its sixteen checkable claims are contradicted by evidence. Orion is
      not ranked at all — too little of it is observable to place it honestly.</p>
    </div>
  </div>

  <div class="ftr"><span>Title</span>
    <span>School of Cyber Defense &nbsp;·&nbsp; Stage 2 &nbsp;·&nbsp; {TEAM}</span></div>
</div>"""


def page2():
    body = """
<div class="cols c3" style="flex:none">
  <div class="box red">
    <h4 style="color:var(--fail)">The problem</h4>
    <p>Security due diligence in public procurement is a document exchange. The buyer sends a questionnaire, the
    supplier answers it about itself, an evaluator files it. Nothing in that loop tests whether any answer is true,
    so the supplier that writes the best document wins.</p>
    <p style="margin-bottom:0">Meanwhile the supplier has become the way in. Third-party involvement in breaches
    went <b>15% &rarr; 30% &rarr; 48%</b> across three consecutive Verizon reports, and government suppliers are
    breached that way at roughly twice the global rate.</p>
  </div>

  <div class="box amb">
    <h4 style="color:var(--warn)">Why the current control fails</h4>
    <div class="stat"><span class="n">84%</span><span class="t">of buyers use security questionnaires</span></div>
    <div class="stat"><span class="n">81%</span><span class="t">say vendors claim near-perfect compliance</span></div>
    <div class="stat" style="margin-bottom:12px"><span class="n" style="color:var(--fail)">14%</span>
      <span class="t">believe the answers are accurate</span></div>
    <p style="margin-bottom:0">Near-universal use, near-universal passing, near-zero belief. The Cloud Security
    Alliance — the body that writes the standard questionnaire — publishes the same criticism itself.</p>
  </div>

  <div class="box acc">
    <h4>What UAE law already asks for</h4>
    <p><b>Federal Law No. 11 of 2023</b> on federal procurement:</p>
    <ul>
      <li><b>Art. 22(3)</b> — non-financial evaluation criteria must be <i>"objective … and quantifiable as much as
        possible."</i> A questionnaire yes/no is neither.</li>
      <li><b>Art. 29</b> — a losing bidder may demand the <i>"weaknesses and strengths"</i> of its bid, so every
        finding has to keep the raw observation behind it.</li>
    </ul>
    <div class="rule"></div>
    <p class="mini" style="margin-bottom:0"><b>Who runs it.</b> The technical evaluator on a tender panel, inside
    the buyer's own environment. No subscription, no per-vendor fee, no data leaves.</p>
  </div>
</div>

<div class="box" style="flex:1;min-height:0;margin-top:16px;display:flex;flex-direction:column">
  <h3 style="flex:none">Against the two things a buyer uses today</h3>
  <table style="width:100%;height:100%;border-collapse:collapse;font-size:10px">
    <thead><tr>
      <th style="text-align:left;width:38%;font-size:8.4px;letter-spacing:.1em;text-transform:uppercase;
          color:var(--muted);padding-bottom:7px;border-bottom:1.2px solid var(--line)"></th>
      <th style="text-align:left;width:21%;font-size:8.4px;letter-spacing:.1em;text-transform:uppercase;
          color:var(--muted);padding-bottom:7px;border-bottom:1.2px solid var(--line)">Questionnaire</th>
      <th style="text-align:left;width:23%;font-size:8.4px;letter-spacing:.1em;text-transform:uppercase;
          color:var(--muted);padding-bottom:7px;border-bottom:1.2px solid var(--line)">Commercial rating</th>
      <th style="text-align:left;font-size:8.4px;letter-spacing:.1em;text-transform:uppercase;
          color:var(--accent);padding-bottom:7px;border-bottom:1.2px solid var(--line)">Bayyina</th>
    </tr></thead>
    <tr><td style="padding:7px 0;border-bottom:1px solid #eef2f7">Tests whether the supplier's answers are true</td>
        <td style="padding:7px 0;border-bottom:1px solid #eef2f7;color:var(--muted)">No — it <i>is</i> the answer</td>
        <td style="padding:7px 0;border-bottom:1px solid #eef2f7;color:var(--muted)">No — never sees it</td>
        <td style="padding:7px 0;border-bottom:1px solid #eef2f7;color:var(--pass)"><b>Yes</b></td></tr>
    <tr><td style="padding:7px 0;border-bottom:1px solid #eef2f7">Says what it could <i>not</i> observe</td>
        <td style="padding:7px 0;border-bottom:1px solid #eef2f7;color:var(--muted)">No</td>
        <td style="padding:7px 0;border-bottom:1px solid #eef2f7;color:var(--muted)">No — gaps vanish into the grade</td>
        <td style="padding:7px 0;border-bottom:1px solid #eef2f7;color:var(--pass)"><b>Yes</b></td></tr>
    <tr><td style="padding:7px 0;border-bottom:1px solid #eef2f7">Compares bidders against <i>each other</i></td>
        <td style="padding:7px 0;border-bottom:1px solid #eef2f7;color:var(--muted)">No</td>
        <td style="padding:7px 0;border-bottom:1px solid #eef2f7;color:var(--muted)">No — one company at a time</td>
        <td style="padding:7px 0;border-bottom:1px solid #eef2f7;color:var(--pass)"><b>Yes</b></td></tr>
    <tr><td style="padding:7px 0;border-bottom:1px solid #eef2f7"><b>Sees active compromise (botnet, C2 traffic)</b></td>
        <td style="padding:7px 0;border-bottom:1px solid #eef2f7;color:var(--muted)">No</td>
        <td style="padding:7px 0;border-bottom:1px solid #eef2f7;color:var(--pass)"><b>Yes</b></td>
        <td style="padding:7px 0;border-bottom:1px solid #eef2f7;color:var(--fail)"><b>No</b> — I have no sensor network</td></tr>
    <tr><td style="padding:7px 0">Cost to assess three bidders on one contract</td>
        <td style="padding:7px 0;color:var(--muted)">5–15 analyst hours each</td>
        <td style="padding:7px 0;color:var(--muted)">$12–25k a year to start</td>
        <td style="padding:7px 0;color:var(--pass)"><b>Free, self-hosted</b></td></tr>
  </table>
</div>"""
    return page(2, "Project objective", "The problem, and whose it is", body, "Project objective")


def page3():
    body = f"""
<div class="stack grow">
  <div class="box" style="flex:none;padding:14px 18px">{PIPELINE}</div>

  <div class="cols c2" style="flex:1;min-height:0">
    <div class="box grn vc">
      <h4><span style="color:var(--pass)">1.</span> Mark the homework</h4>
      <p style="margin-bottom:0">Each questionnaire answer carries a machine-testable predicate. A bidder that
      answered <i>"we enforce DMARC"</i> has made a claim one DNS lookup can refute. <b>A contradiction counts for
      more than the flaw behind it:</b> a missing DMARC record is a config gap, but claiming it while publishing
      nothing is a false statement in a document the bidder signed — and evidence about every answer nobody can
      check.</p>
    </div>
    <div class="box grn vc">
      <h4><span style="color:var(--pass)">2.</span> Put a number on the part you cannot check</h4>
      <p style="margin-bottom:0">Most of a questionnaire is invisible from outside — background screening, key
      management, backup testing. But the checkable answers are a <b>sample</b>, and how they fare measures how far
      to trust the rest. Reported as a confidence interval over <i>independent evidence sources</i>, because three
      answers tested against a single web request are not three independent trials.</p>
    </div>
  </div>

  <div class="cols c2" style="flex:1;min-height:0">
    <div class="box grn vc">
      <h4><span style="color:var(--pass)">3.</span> Refuse to rank on noise</h4>
      <p style="margin-bottom:0">Every score is a range: the bottom assumes everything unobserved was broken, the top
      assumes it was fine. <b>One bidder outranks another only when its worst case beats the other's best case.</b>
      Otherwise the tool says they cannot be separated and lists exactly what would settle it. Nothing is guessed at,
      so there is no hidden assumption to attack.</p>
    </div>
    <div class="box grn vc">
      <h4><span style="color:var(--pass)">4.</span> Look at the whole competition</h4>
      <p style="margin-bottom:0">Split an award between two suppliers for resilience and you may have bought two
      invoices and one failure domain. Bayyina compares upstream dependencies <i>across bidders</i> — DNS, mail, CDN,
      certificate authority. No commercial rating service sees this, because each one rates a single company in
      isolation.</p>
    </div>
  </div>

  <div class="box tint" style="flex:none">
    <p style="margin-bottom:0"><b>It ends in contract language.</b> Each finding becomes a drafted clause with a
    deadline and a named acceptance test: re-running the check that produced it. &nbsp;&nbsp;·&nbsp;&nbsp;
    <b>Passive only.</b> DNS lookups, one TLS handshake, one page fetch, public datasets. No port scanning, no
    probing, nothing needing a bidder's permission — which is what lets a buyer run this across a whole bid field
    before the tender even closes.</p>
  </div>
</div>"""
    return page(3, "Proposed solution", "Four ideas, and the pipeline that runs them", body, "Proposed solution")


def page4():
    body = """
<div class="cols c3">
  <div class="stack">
    <div class="box" style="flex:none">
      <h3>Run it twice, get the same answer</h3>
      <div class="term"><span class="d">$</span> bayyina reproduce
  run 1: ledger <span class="y">142e94cca9a8…</span>  result <span class="y">08e678bb…</span>
  run 2: ledger <span class="y">142e94cca9a8…</span>  result <span class="y">08e678bb…</span>

<span class="g">Identical.</span></div>
      <p style="margin-top:11px;margin-bottom:0">Timestamps come from the evidence rather than the clock, so a replay
      next year gives today's answer. Evidence is recorded once and replayed offline, and the analysis code is the
      same either way — nothing is stubbed for the demo.</p>
    </div>
    <div class="box">
      <h3>122 tests, 0.3 seconds</h3>
      <p style="margin-bottom:0">They cover the scoring rules, deliberately hostile input — null bytes, huge strings,
      injection attempts — and a suite dedicated to <b>gaming the tool</b>. That last one exists because an early
      version rewarded a bidder for submitting a corrupt questionnaire. It no longer does.</p>
    </div>
  </div>

  <div class="stack">
    <div class="box red" style="flex:none">
      <h3 style="color:var(--fail)">Evidence you cannot quietly edit</h3>
      <p class="mini" style="margin-bottom:9px">Every observation goes into a hash chain. Here is one stored DMARC
      record altered to look compliant:</p>
      <div class="term"><span class="r">Chain does NOT verify.</span>
  ! record 6: payload does not match
    its hash — the stored evidence was
    modified after it was recorded</div>
    </div>
    <div class="box">
      <h3>Said plainly</h3>
      <p style="margin-bottom:0">That is tamper-<b>evidence</b>, not tamper-proofing. Anyone holding the file could
      rewrite the whole chain. It catches silent edits to a stored assessment, which is the realistic procurement
      risk; stopping a malicious operator would need a signature from someone who does not control the file.</p>
    </div>
  </div>

  <div class="stack">
    <div class="box acc" style="flex:none">
      <h3>Is the method sound?</h3>
      <p><b>No machine learning, on purpose.</b> There is no honest training set: a model fitted to public breach
      reports learns which companies <i>get reported</i>, not which are insecure. Published work predicts disclosed
      breaches from company size and sector alone, with no security data at all. Nothing here is fitted, so there is
      no train/test split and no leakage.</p>
      <p style="margin-bottom:0"><b>The weights belong to the buyer, and they are not load-bearing.</b> They sit in
      the tender file because the law requires them published in advance, and re-ranking under 2,000 perturbed
      weightings leaves the winner unchanged every time.</p>
    </div>
    <div class="box amb">
      <h3 style="color:var(--warn)">What it cannot do</h3>
      <p style="margin-bottom:0">No sensor network, so no view of active compromise. ISO 27001 scope adequacy cannot
      be automated and goes to a named human. SOC 2 cannot be verified at all — a private report with no registry.
      Breach history only counts <i>disclosed</i> breaches, so a clean record is weak evidence. All of it is printed
      in the output rather than hidden.</p>
    </div>
  </div>
</div>

<div class="box" style="flex:none;margin-top:16px">
  <h3>Every check cites the standard it comes from, and the tests prove it runs</h3>
  <div style="display:flex;gap:20px;align-items:stretch">
    <div style="flex:1.25">
      <div class="term"><span class="d">$</span> bayyina checks --check DNS-002
DNS-002  DMARC is published at an enforcing policy
  category  Technical hygiene
  weight    3.0 <span class="d">(within category)</span>
  severity  HIGH
  authority
    · RFC 7489
    · CISA BOD 18-01 <span class="d">(p=reject mandated for US federal agencies)</span></div>
    </div>
    <div style="flex:1">
      <div class="term"><span class="d">$</span> python -m pytest -q
..............................................  [100%]
<span class="g">122 passed in 0.53s</span></div>
      <p class="mini" style="margin-top:11px;margin-bottom:0">No check is a number I invented. Each one names the
      RFC, NIST publication, CISA directive or OWASP guidance it enforces, so a bidder disputing a finding can argue
      with the standard rather than with me.</p>
    </div>
  </div>
</div>"""
    return page(4, "Solution validation", "How I know it works", body, "Solution validation")


def page5():
    body = f"""
<div class="cols c32">
  <div class="stack">
    <div class="box" style="flex:none">
      <h3>Three bidders, one contract</h3>
      <p class="mini" style="margin-bottom:12px"><b>Meridian</b> has the best paperwork — ISO 27001, SOC 2, a
      near-perfect questionnaire. <b>Nawras</b> has less. <b>Orion</b> is barely visible from outside.</p>
      <img class="fig" src="{img('intervals.png')}" alt="Score ranges by bidder">
      <p class="mini" style="margin-top:11px;margin-bottom:0">The bar is the range the evidence supports.
      <b>Where two bars overlap, the tool will not rank those bidders.</b></p>
    </div>

    <div class="box red" style="flex:none">
      <h4 style="color:var(--fail)">The paper favourite loses</h4>
      <p><b>10 of Meridian's 16 checkable claims are contradicted by evidence.</b> It claims an enforcing DMARC
      policy and publishes one that blocks nothing. It claims no admin service is internet-facing; Remote Desktop and
      an open Elasticsearch say otherwise. Its ISO 27001 certificate covers <i>"the Dubai office"</i> — not the
      entity that would build the system.</p>
      <p style="margin-bottom:0">Estimated reliability of its 20 untestable answers: <b>27%</b>, reported with the
      interval that says how little that is worth.</p>
    </div>

    <div class="box" style="flex:1;min-height:0">
      <h3>Every finding leaves as a contract clause</h3>
      <p class="mini" style="margin-bottom:8px">One of Meridian's ten conditions precedent, as emitted:</p>
      <div class="term" style="font-size:8.4px;line-height:1.62;padding:9px 12px;white-space:pre-wrap">CP-Q001  HIGH  ·  CAIQ v4 IVS-09
<span class="d">Prior to award, the Supplier shall remediate the deficiency or submit
a corrected response to CAIQ v4 IVS-09 …</span>
<span class="y">Attested:</span>     Deprecated TLS versions are disabled = True
<span class="r">Observed:</span>     TLSv1, TLSv1.1 accepted on meridiangov.example
<span class="g">Verification:</span> re-execution of predicate no_legacy_tls</div>
    </div>
  </div>

  <div class="stack">
    <div class="box" style="flex:none;padding:12px 14px">
      <img class="fig" src="{img('divergence.png')}" alt="Attestation divergence"
           style="border:1px solid var(--line)">
    </div>

    <div class="cols c3" style="flex:none;display:grid;gap:12px">
      <div class="box grn" style="padding:12px 13px">
        <h4 style="color:var(--pass);font-size:10.6px">Nawras wins</h4>
        <p class="mini" style="margin-bottom:0">Zero contradictions in 15 claims, full evidence coverage, and it stays
        ahead under every weighting tried.</p>
      </div>
      <div class="box amb" style="padding:12px 13px">
        <h4 style="color:var(--warn);font-size:10.6px">Orion is not ranked</h4>
        <p class="mini" style="margin-bottom:0">Only 57% of checks were observable, so the tool declines to place it
        and issues 12 document requests instead.</p>
      </div>
      <div class="box red" style="padding:12px 13px">
        <h4 style="color:var(--fail);font-size:10.6px">One failure domain</h4>
        <p class="mini" style="margin-bottom:0">Meridian and Orion share DNS, CDN and mail. Splitting the award
        between them buys no resilience.</p>
      </div>
    </div>

    <div class="box acc" style="flex:none">
      <h3>What changes for the buyer</h3>
      <ul>
        <li>An award that can be defended line by line, with the raw observation behind every finding.</li>
        <li><b>13 conditions precedent and 36 drafted contract clauses</b>, each with a deadline and a test that
          re-runs automatically.</li>
        <li>The split-award plan changes, because two of the three bidders are not independent.</li>
      </ul>
      <div class="rule"></div>
      <p class="mini" style="margin-bottom:0"><b>Honesty note.</b> The three bidders are invented and their domains
      are reserved test names; the evidence was generated by a script in the repository, and the scenario is built to
      show three different outcomes, so the contrast is sharper than a real tender would be. The same code runs live
      against real infrastructure, and sources for every figure are in the repo.</p>
    </div>
  </div>
</div>"""
    return page(5, "Results and conclusions", "What it found, and what a buyer does with it",
                body, "Results and conclusions")


def main():
    html = (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f"<title>Bayyina — Stage 2 submission</title><style>{CSS}</style></head><body>"
            + page1() + page2() + page3() + page4() + page5() + "</body></html>")
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
    print(f"wrote {pdf_path}  ({os.path.getsize(pdf_path)/1024/1024:.2f} MB)")


if __name__ == "__main__":
    main()
