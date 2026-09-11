# Bayyina

**Evidence-based third-party vendor assurance for government procurement.**

*Bayyina* (بيّنة) is the Arabic legal term for clear, produced evidence — the standard a claim must meet before it is relied on. That is the whole idea: a supplier's security questionnaire is an *assertion*, and an assertion is not evidence until something tests it.

Bayyina assesses every bidder for one contract from externally observable evidence, **tests each questionnaire answer against what it actually observed**, refuses to rank bidders it cannot separate, finds shared upstream dependencies across the bid field, and drafts the contract conditions that follow.

---

## Run it in 30 seconds

No dependencies, no network, no API keys. Python 3.9+.

```bash
git clone <this-repo> && cd bayyina
pip install -e .

bayyina assess --tender scenarios/MDG-2026-114
```

That runs the bundled tender offline against recorded evidence and writes an HTML dashboard, three one-page bidder assessments, a JSON bundle and a verifiable evidence ledger into `out/MDG-2026-114/`.

Then, in order of what is worth seeing:

```bash
bayyina reproduce --tender scenarios/MDG-2026-114     # run twice, compare bit for bit
bayyina verify-ledger out/MDG-2026-114/evidence-ledger.jsonl
bayyina checks                                         # the full check catalogue and its authorities
bayyina checks --check DNS-002                         # one check, its weight and its source
python -m pytest -q                                    # 122 tests, ~0.3s

bayyina live --domain <a-real-domain>                  # the same pipeline, live
bayyina serve --tender scenarios/MDG-2026-114          # HTTP API (needs pip install -e '.[api]')
```

Open `out/MDG-2026-114/comparison.html` in a browser.

---

## What it does that a questionnaire does not

### 1. It tests the questionnaire

Most procurement treats a security questionnaire as a document to be filed. Bayyina treats it as a set of hypotheses. A bidder that answered *"we enforce DMARC"* has made a claim one DNS lookup can refute.

In the bundled tender, the bidder with the strongest paper submission — ISO 27001, SOC 2 Type II, near-perfect questionnaire — has **10 of its 16 externally testable attestations contradicted by evidence**:

| Control | Bidder attested | Observed |
|---|---|---|
| CAIQ v4 SEF-08 | DMARC set to an enforcing policy | `p=none` — monitoring only, blocks nothing |
| CAIQ v4 IVS-09 | TLS 1.0/1.1 disabled | TLS 1.0 and 1.1 both accepted |
| CAIQ v4 IVS-06 | No admin or database service internet-facing | RDP on 3389 and Elasticsearch 6.8 on 9200, both reachable |
| CAIQ v4 A&A-03 | ISO 27001 scope covers the delivering entity | reviewer determination: scope reads *"managed IT support services … from the Dubai office"* |
| CAIQ v4 STA-09 | No incident originating with a sub-processor | 2024 compromise via a third-party CRM integration |

A contradiction is treated as **more serious than the underlying control gap**. A missing DMARC record is a hygiene weakness. A *claim* of DMARC enforcement with no DMARC record published is an accuracy failure in a document the bidder signed and the buyer is relying on.

### 2. It estimates how far the *untestable* claims can be trusted

This is the part that carries the method. Most of a questionnaire cannot be checked from outside — you cannot externally observe background screening, key management, or whether backups are actually restored. But the testable claims are a sample. How they fare is a measurement of how much weight to place on the rest.

Bayyina reports it as a **Wilson score interval**, not a point estimate:

```
meridian   attestation reliability  27%  (95% CI 10–57%)    3 of 11 evidence sources fully corroborated
nawras     attestation reliability 100%  (95% CI 74–100%)  11 of 11
orion      attestation reliability  75%  (95% CI 30–95%)    3 of 4
```

Two deliberate choices here, and the second is the one a statistician will ask about.

**Wilson rather than the normal approximation**, because *n* is small and the Wald interval misbehaves near 0 and 1, where it can produce bounds outside [0,1]. Note that 11 of 11 is reported as **74–100%**, not as certainty — a small perfect sample is still a small sample.

**Evidence sources rather than claims**, because the claims are not independent trials. Three of Meridian's contradictions — HSTS, cookie attributes, version disclosure — are read out of a *single HTTP response*; SPF and DMARC reflect one mail-configuration decision. Treating 16 claims as 16 Bernoulli trials would report an interval narrower than the evidence supports, in a tool whose whole argument is not overstating what it knows. So claims are clustered by the evidence record each was tested against, a cluster counts as corroborated only if every claim resting on it survived, and the interval is computed over clusters. The claim-level figure is printed alongside as the optimistic bound (Meridian: 38%).

Clustering by evidence record is a conservative approximation of the real dependence structure, not a measurement of it — and that, with the sampling bias below, is printed in every report. Testable claims are not a random sample of all claims: they skew toward network and email configuration. This estimates the reliability of the bidder's attestation *process*; it is evidence for a reviewer to weigh, not a substitute for one.

### 3. It refuses to rank bidders it cannot separate

Every score is an interval. The lower bound assumes every unobserved check would have failed; the upper bound assumes every one would have passed. Nothing is imputed — there is no distributional assumption to attack, because none is made.

**A bidder is ranked above another only when its lower bound exceeds the other's upper bound.** Otherwise the tool says so and stops:

```
Tier 1: nawras
Tier 2: orion, meridian   (not separable on available evidence)
  · orion vs meridian: intervals overlap ([32.32, 75.8] vs [30.54, 34.98])
```

Orion's public endpoint requires client-certificate authentication, so three TLS checks are genuinely unobservable; its certificate transparency query timed out; it has no incident record and no exposure data. Coverage is 57%, below the two-thirds threshold at which the tool considers a point estimate worth reading, and it says so. Rather than manufacture a ranking, Bayyina emits **12 information requests** naming exactly what would resolve it.

Tiers are built so the ordering they assert actually holds: **every member of a tier must dominate every member of the tier below**. The obvious construction — repeatedly take the undominated bidders as the next tier — quietly fails this, because a bidder with a very wide interval is undominated merely by being unseparable, and lands a tier above someone it cannot be separated from. Bayyina merges tiers downward until the property holds, collapsing to a single unranked tier when nothing separates anything.

This is the single most important behaviour in the system. The failure mode of every scoring tool is producing a decision the evidence does not support, and in a procurement that is the failure that ends in a challenge.

### 4. It sees the bid field, not just each bidder

DORA Article 29 asks one buyer to assess concentration across *its own* portfolio. Government procurement has a question no regulator has systematised and no commercial rating service answers: **when several vendors bid for the same contract, do they share upstream dependencies?**

```
meridian and orion share authoritative DNS, edge/CDN, and mail exchange.
Splitting the award between these two would not produce independent failure domains.
```

A buyer that splits an award across two bidders to avoid single-supplier risk, where both terminate TLS at the same CDN and route mail through the same provider, has bought two invoices and one failure domain. That correlation is invisible to any per-vendor assessment — including every commercial security rating, because each rates one company alone.

Stated honestly: this is our operationalisation of a qualitative regulatory concept, not compliance with a standard. No regulator mandates a concentration metric and no threshold here is normative.

### 5. It ends in contract language, not a score

An assessment that ends in a number changes nothing. Each finding becomes a drafted obligation with a deadline sized by severity and contract criticality, and **a named verification method** — re-running the check that produced it:

> The Supplier shall, within 15 calendar days of the Commencement Date, disable TLS 1.0 and TLS 1.1 on all Internet-facing endpoints; serve TLS 1.2 as a minimum. The Authority shall verify closure by re-executing assessment check TLS-001; the check returning PASS against the Supplier's production endpoints is the acceptance criterion.

Three classes, because they attach at different points: **conditions precedent** (contradicted attestations, expired or mis-scoped certificates — before award), **contract conditions** (dated remediation), and **information requests** (what the tool could not observe, or declined to decide, assigned to a named human). Across the bundled bid field: 13 conditions precedent, 36 contract conditions, 13 information requests.

---

## Design decisions we would rather state than be asked

**There is no machine learning, deliberately.** There is no adequate labelled dataset: a model trained on public breach disclosures learns *disclosure*, not compromise. Sarabi et al. (*Journal of Cybersecurity*, 2016) predicted disclosed breaches at ~90% TP / 11% FP from business-profile data alone — industry, size, web traffic rank, with no security measurements at all. A technical rating that performs similarly may be reproducing firmographics. Fitting a model here would produce a number whose accuracy came from the wrong variable. A transparent deterministic function is also what UAE Federal Law 11/2023 Art. 22(3)–(4) requires: criteria that are objective, quantifiable, and published in advance.

**The composite is an ordinal triage device and is labelled as one.** Jack Jones' critique is correct: multiplying ordinal severities and calling the product "risk" is not quantification, because there is no unit. Bayyina does not claim to measure risk. Where it does make a probabilistic statement — attestation reliability — that statement carries an interval and a named estimator.

**Unknown, not applicable, and needs-human are three different things.** An unobserved check widens the interval. A control with nothing to bite on (incident disclosure timeliness for a vendor with no incidents) leaves the denominator entirely, so a clean vendor is not punished with uncertainty it did not earn. A control no machine can decide (whether an ISO 27001 scope statement covers the delivering entity) goes to a named reviewer, never to a silent pass.

**Passive only, and enforced in the transport layer.** DNS over HTTPS, one TLS handshake, one HTTPS GET per endpoint, and public datasets. There is no primitive in this codebase for port scanning, vulnerability probing, authentication attempts, fuzzing or zone transfer. Exposed services — which the brief asks for — are read from a buyer-supplied passive measurement export (Censys, Shodan, Rapid7 Open Data, or the buyer's own attack-surface inventory) rather than enumerated by us: the scan has already been done publicly and continuously, so we read the observation instead of making it. With no such dataset the check returns **unknown**, not clean. That is a legal position as much as an engineering one — under the UK Computer Misuse Act 1990 s.1 there is no statutory research defence and the status of port scanning is unsettled, and the US DOJ's 2022 CFAA charging policy is prosecutorial policy, not statute, and confers no civil immunity. Restricting the tool to observations a bidder's own customers make every day is what lets a buyer run it across a bid field without per-bidder authorisation.

**TLS interception is detected, and findings are withheld rather than faked.** This tool was built inside a network whose egress gateway terminates and re-issues TLS. A naive collector there reports a perfectly healthy certificate for every host on the internet, because it is describing the middlebox. Bayyina detects that two ways — a known-middlebox issuer pattern, and the structural giveaway that unrelated hosts share one issuer — and marks the evidence `INTERCEPTED`, which scores as unknown. Reporting "we could not observe this" is always available; reporting a number we cannot stand behind is not.

**A defect in a bid must never improve the bidder's position.** An unparseable questionnaire used to leave the divergence category empty — and an empty category scores as *unknown*, which widened the score interval and deleted every adverse finding with it. Under a dominance rule a wider interval is precisely what defeats being outranked, so corrupting your own submission was a dominant strategy for a bidder facing demotion. An unreadable submission is now scored as a defect in the bid rather than as missing evidence about the world: a `FAIL`, with a condition precedent attached. `tests/test_gaming_and_edges.py` asserts the direction end to end.

**What it cannot do, said plainly.** No sinkhole or darknet telemetry, so no visibility of active compromise — that is roughly a quarter of a commercial rating and we do not have it. ISO 27001 scope adequacy cannot be automated. SOC 2 cannot be verified at all beyond the CPA firm, because it is a private attestation with no registry. Absence from IAF CertSearch is *not* evidence of a false certificate — DAkkS, Germany's national accreditation body, publicly declined to apply IAF MD 28:2023 on 15 November 2024. Every one of these is surfaced in the output rather than hidden.

---

## Reproducibility

Evidence collection and evidence *use* are separate layers. A **cassette** is a recorded set of raw observations with the timestamp each was taken at.

- `--mode replay` (default) reads the cassette and performs no network activity at all.
- `--mode record` collects live and writes a cassette.
- `--mode auto` replays what exists and records what is missing.

The scoring pipeline cannot tell the difference. The run a juror reproduces offline executes exactly the same check, scoring, divergence, concentration and reporting code as a live run — only the transport differs. Nothing in the analysis path is stubbed for the demo.

Determinism is a property we prove rather than claim. Timestamps come from the evidence, never from the wall clock; evidence is hashed through canonical JSON; the ledger is written in sorted order:

```
$ bayyina reproduce --tender scenarios/MDG-2026-114
  run 1: ledger head 142e94cca9a838b985d4fadc  result digest 08e678bb3de59181a2fc3f2f
  run 2: ledger head 142e94cca9a838b985d4fadc  result digest 08e678bb3de59181a2fc3f2f
  Identical.
```

### Evidence ledger

Every observation is recorded in a hash chain: each record commits to its predecessor, so evidence cannot be edited after the fact without the chain failing to verify.

```
$ bayyina verify-ledger out/MDG-2026-114/evidence-ledger.jsonl
45 records, head 142e94cca9a838b9…
Chain verifies.
```

Change one byte of one stored DMARC record and it says so, naming the record:

```
Chain does NOT verify. 1 problem(s) found.
  ! record 6 (evidence): payload does not match its hash — the stored evidence was modified after it was recorded
```

This is tamper-**evidence**, not tamper-proofing: anyone holding the file can rewrite the whole chain. It defends against silent mutation of a stored assessment, which is the realistic procurement risk. Defending against a malicious operator needs a countersignature from a party who does not control the file.

---

## Why this shape, for a government buyer

UAE Federal Law No. 11 of 2023 on Procurement in the Federal Government sets three requirements that a PDF questionnaire cannot satisfy together, and that shaped this design:

- **Art. 22(3)** — non-financial evaluation criteria must be *"objective … and quantifiable as much as possible"*. A questionnaire yes/no is neither.
- **Art. 22(4)** — the tender must publish *"the weight assigned to each criterion"* in advance. So weights live in the buyer's tender file, not in the tool, and every report prints the set that was used alongside a sensitivity analysis showing how far the result actually depends on them.
- **Art. 29** — an unsuccessful bidder may request *"the weaknesses and strengths of its bid"*. So every finding keeps the raw observation that produced it, and the per-bidder report is written to be handed over.

The UAE **National Cloud Security Policy** already requires organisations to *"identify security risks from third-party suppliers and require independent security testing rather than relying solely on provider assertions"*. Dubai's **DESC ISR v3** extends obligations to *"consultants, contractors"* and to *"external party and managed services"*. The UAE Information Assurance Standard carries a Third Party Security control family.

The evidence that this is the right thing to spend effort on:

- **Verizon DBIR: 15% → 30% → 48%.** The share of breaches involving a third party, 2024 → 2025 → 2026.
- **IBM, August 2026:** in the Middle East, supply-chain-compromise breaches averaged **$8.45M**, against a $4.99M global average across all breach types.
- **SecurityScorecard, Feb 2024:** of the top 30 UAE companies by revenue, **90% score A or B on their own posture — and 73% have a supplier that has been breached.** Own-posture assurance is not supply-chain assurance.
- **Cyentia / RiskRecon:** 84% of firms use questionnaires; 81% report that vendors claim near-perfect compliance; **14% are highly confident the answers are accurate.**

Every figure above is sourced in `docs/EVIDENCE.md`, with the ones we could not verify to a primary source marked as such.

---

## Repository layout

```
bayyina/
  models.py            data model — the three-state epistemics live here
  cassette.py          record/replay evidence layer
  ledger.py            hash-chained evidence ledger
  collectors/
    net.py             transport; the passive-only scope policy is enforced here
    dns_email.py       DNS, SPF, DMARC, DNSSEC, CAA, MTA-STS
    tls_web.py         TLS configuration, security headers, interception detection
    public_data.py     certificate transparency, breach corpora, attestation
                       registries, passive exposed-service datasets
  checks/rules.py      25 checks, each carrying the authority it derives from
  divergence.py        attestation testing + the clustered reliability estimator
  scoring.py           bounded intervals, dominance ranking, sensitivity analysis
  concentration.py     bid-field shared-dependency analysis
  contract.py          findings → drafted contract conditions
  report.py            self-contained HTML, inline SVG, no external assets
  cli.py  api.py  stats.py  engine.py
scenarios/
  build_demo.py        generates the demo cassette — all synthetic evidence is here
  MDG-2026-114/        the bundled tender: 3 bidders, 3 questionnaires, 45 observations
tests/                 122 tests, including a suite dedicated to gaming the tool
docs/EVIDENCE.md       every external claim, with sources and confidence
```

## The bundled scenario is synthetic, and labelled as such everywhere

The three bidders are invented. Their domains are under `.example` (RFC 2606, reserved and non-resolvable). Every observation in `cassette.json` was generated by `scenarios/build_demo.py`, which is in the repository and readable.

That is deliberate. Publishing real security findings about real named companies would assert things about third parties who have no opportunity to rebut them, in a context where the finding could affect their commercial standing. And a live run against real infrastructure cannot be reproduced by anyone later, because the internet will have changed by then.

The observations are structurally real — real record syntax, real header strings, real certificate field shapes, RFC-conformant SPF and DMARC — and are constructed to exercise the three outcomes the tool exists to distinguish: a polished bidder whose attestations do not survive contact with evidence, a modest bidder whose do, and a bidder about whom too little is observable to rank at all. The attestation evidence is generated by running the *real* collector against the *real* registry, so the synthetic data cannot drift from what a live run would produce.

For a live demonstration, `bayyina live --domain <domain>` runs the identical pipeline against real infrastructure.

## Licence

Apache-2.0.
