# Evidence register

Every external claim Bayyina makes — in this repository, in its reports, or in
the submission deck — with its source and how far we verified it.

**Confidence key**
`[PRIMARY]` fetched from the issuing body or the report publisher ·
`[SECONDARY]` a reputable third party citing the primary ·
`[UNVERIFIED]` we could not confirm it, and it is therefore **not** asserted anywhere in this project.

---

## 1. The problem is real and growing

| Claim | Source | Confidence |
|---|---|---|
| Breaches involving a third party: **15% (2024) → 30% (2025) → 48% (2026)**. DBIR 2026: *"breaches with third-party involvement have increased by 60% from last year's dataset, reaching 48% of total breaches."* DBIR 2025: *"the percentages of breaches where a third party was involved doubled, going from 15% to 30%."* | Verizon DBIR 2026 (19 May 2026), [report PDF](https://www.verizon.com/business/resources/T161/reports/2026-dbir-data-breach-investigations-report.pdf); DBIR 2025 (23 Apr 2025), [executive summary](https://www.verizon.com/business/resources/reports/2025-dbir-executive-summary.pdf) | **[PRIMARY]** |
| DBIR 2026 dataset: >22,000 breaches, 145 countries, drawn from >31,000 real-world incidents. Software flaws (31%) overtook stolen credentials as the top entry point for the first time. | As above | **[PRIMARY]** |
| Middle East: average breach cost **$8M**; **supply chain compromise accounted for 16% of breaches at an average cost of $8.45M**; one in four malicious breaches in the region was AI-enabled. | IBM, [Cost of a Data Breach — Middle East findings, 3 Aug 2026](https://mea.newsroom.ibm.com/codb-me-findings-2026) | **[PRIMARY]** |
| Global average breach cost **$4.99M**, up 12% YoY; supply chain compromise the **#2 initial attack vector** globally. | IBM Cost of a Data Breach 2026, reported [here](https://www.infosecurity-magazine.com/news/cost-of-a-data-breach-5m-ibm/) and [here](https://databreachcost.com/report/2026) | **[PRIMARY-adjacent]** |
| **Of the top 30 UAE companies by revenue, 90% score A or B on their own security posture — and 73% have a third-party supplier that experienced a breach**; 73% also have a breached fourth party. Period 20 Jan 2023 – 20 Jan 2024. | SecurityScorecard, [11 Feb 2024](https://securityscorecard.com/company/press/uae-cybersecurity-supply-chain/) | **[PRIMARY]** |
| **58% of breaches at the top 100 US federal contractors involved third-party attack vectors — double the ~29% global average.** | SecurityScorecard, [22 Jan 2025](https://securityscorecard.com/company/press/58-percent-of-breaches-impacting-leading-us-federal-contractors-caused-by-third-party-attack-vectors/) | **[PRIMARY]** |
| Supply chain attacks named the top global cyber threat of 2026; 100+ ransomware incidents across the GCC, government and healthcare 21 each; five GCC organisations identified as supply chain attack victims. | Group-IB via Gulf News, [26 Feb 2026](https://gulfnews.com/technology/supply-chain-attacks-emerge-as-top-global-cyber-threat-in-2026-1.500456194) | **[SECONDARY]** |
| The UAE blocks ~600,000 cyberattacks daily; Dr. Mohamed Al Kuwaiti, Head of the UAE Cyber Security Council, names attacks on digital supply chains as an emerging threat. | Gulf News, [11 Aug 2026](https://gulfnews.com/technology/uae-thwarts-416-cyberattacks-every-second-with-advanced-cyber-defences-1.500637752) | **[SECONDARY]** |

**Not asserted anywhere:** the "634 UAE entities affected by the Oracle Cloud incident" figure (single unverified source); any Middle East year-on-year breach-cost percentage (IBM reported 2025 in SAR and 2026 in USD, so no comparable change can be stated).

---

## 2. Questionnaire-based assurance is known to be unreliable

| Claim | Source | Confidence |
|---|---|---|
| **84%** of firms use questionnaires to assess vendor security; **81%** report that at least three quarters of vendors claim perfect compliance; **only 14% are highly confident** the responses are accurate. n = 154 TPRM professionals. | Cyentia Institute / RiskRecon, *State of Third-Party Risk Management*, [23 Nov 2020](https://www.businesswire.com/news/home/20201123005473/en/Joint-CyentiaRiskRecon-Research-Reveals-the-Need-for-Third-Party-Risk-Management-Programs-to-Move-Beyond-Questionnaire-Based-Assessments) | **[PRIMARY]** |
| Questionnaire responses *"only represent a single point in time"* and *"are rarely evaluated"*; completing one takes **5–15 hours**. Published by the Cloud Security Alliance — the body that authors the CAIQ. | CSA, [2 Apr 2025](https://cloudsecurityalliance.org/blog/2025/04/02/why-security-questionnaires-are-a-familiar-but-ineffective-norm-for-assessing-risk) | **[PRIMARY]** |

**Stated caveat we volunteer rather than wait to be asked:** the Cyentia/RiskRecon study is from 2020 with n=154. No later study contradicts it, and DBIR's 15→30→48% trajectory is consistent with it, but it is old and small and we say so.

**Not asserted anywhere:** "manual vendor risk assessment takes 3–6 months per vendor" — vendor marketing with no original source.

---

## 3. Security ratings services: what they measure, and the criticism

| Claim | Source | Confidence |
|---|---|---|
| **~71.5% of a Bitsight rating is "Diligence"** — externally observable configuration (SPF, DKIM, TLS/SSL, DNSSEC, open ports, server software), the same class of signal Bayyina measures. Compromised Systems 26%, User Behavior 2.5%. | [Bitsight KB](https://help.bitsighttech.com/hc/en-us/articles/231950968-How-are-Bitsight-Security-Ratings-Calculated) | **[PRIMARY]** — vendor-published and subject to change |
| UpGuard's rating is **50% automated external scanning + 50% questionnaire responses**. | [UpGuard help](https://help.upguard.com/en/articles/3765184-how-are-upguard-s-security-ratings-calculated) | **[PRIMARY]** |
| **Commercial raters disagree with each other on identical evidence.** FICO, BitSight, RiskRecon and ComplyScore were asked to rate the *same* institution: *"the provided security scores do not entirely converge."* BitSight flagged poor web headers and outdated SSL as significant problems while **RiskRecon scored Web Encryption 8.6/10** for the same organisation. | Keskin, Caramancion, Tatar, Raza & Tatar (2021), *Electronics* 10(10):1168, [DOI 10.3390/electronics10101168](https://www.mdpi.com/2079-9292/10/10/1168) | **[PRIMARY, peer-reviewed]** |
| **Business-profile data alone predicts disclosed breaches about as well as 258 technical features do** (~90% TP / 11% FP), suggesting technical ratings may partly reproduce firmographics. Authors state the work is correlational and subject to disclosure bias. | Sarabi, Naghizadeh, Liu & Liu (2016), *Journal of Cybersecurity* 2(1):15–28, [link](https://academic.oup.com/cybersecurity/article/2/1/15/2629555) | **[PRIMARY, peer-reviewed]** |
| IP-scan-based rating has three documented weaknesses: low feature utilisation, a cloud gap that disproportionately hides SMEs, and *"IP address ownership can be fluid … and obscure"*. | Sarabi, Karir & Liu (2025), [arXiv:2506.06604](https://arxiv.org/html/2506.06604v1) | **[PRIMARY, preprint]** |
| Ratings carry a **real but modest** signal: a one-unit rating increase associated with a **0.6% decrease in the odds of breach** (P = .015), 3,528 hospital-year observations. | Choi & Johnson (2021), *JAMIA* 28(10):2085–2092, [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC8449620/) | **[PRIMARY, peer-reviewed, independent]** |
| *"These security ratings don't measure risk and may be misleading: a score of 742 implies less risk than a score of 581 but we don't know how much less."* And on scoring generally: *"It might be numeric but it's not quantitative because there is no unit of measurement."* | FAIR Institute — [buyer's guide](https://www.fairinstitute.org/blog/crq-buyers-guide-cyber-risk-security-ratings-maturity-models-threat-analysis) and [Jack Jones on risk scores](https://www.fairinstitute.org/blog/jack-jones-problem-with-risk-scores) | **[PRIMARY]** |
| The industry wrote itself a transparency, dispute and appeal code — *Principles for Fair and Accurate Security Ratings* (2017, revised 2022), endorsed by 44 organisations including BitSight, SecurityScorecard and RiskRecon. Its existence is the industry's own acknowledgement that customers disputed rating accuracy. | [US Chamber of Commerce](https://www.uschamber.com/security/cybersecurity/principles-for-fair-and-accurate-security-ratings) | **[PRIMARY]** |
| Reported market pricing: **$150–400 per vendor per year at volume, with a $12–25k floor.** Median reported ACV: Bitsight $23,639; SecurityScorecard $23,618; UpGuard $34,868. | [Vendr marketplace](https://www.vendr.com/marketplace/bitsight) — negotiated-deal aggregation, **not vendor list prices** | **[SECONDARY]** — presented as reported market ranges only |

**Fair characterisation we hold to:** ratings are *weakly predictive, opaque and mutually inconsistent* — not worthless. The Choi & Johnson result is statistically significant and practically small.

---

## 4. Frameworks Bayyina maps to

| Claim | Source | Confidence |
|---|---|---|
| NIST SP 800-161r1 **does not prescribe a normative scoring algorithm**. Appendix C offers a Risk Exposure Framework and Appendix D example likelihood/impact templates — a method to be tailored, not a required scale. | [NIST SP 800-161r1 Upd.1](https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final) | **[PRIMARY]** |
| ISO/IEC 27001:2022 Annex A supplier controls: **A.5.19** information security in supplier relationships, **A.5.20** addressing security within supplier agreements, **A.5.21** managing security in the ICT supply chain, **A.5.22** monitoring/review/change management of supplier services, **A.5.23** security for use of cloud services. | ISO/IEC 27001:2022 (control numbering confirmed; wording paraphrased, as the standard text is copyright) | **[SECONDARY]** |
| ISO/IEC 27036 has **four parts, not five**; Part 2 (2022) is the only requirements part. | [ISO](https://www.iso.org/standard/82905.html) | **[PRIMARY]** |
| **DORA Art. 29** requires a preliminary assessment of ICT concentration risk before contracting for a critical or important function, considering non-substitutable dependence on one provider *or on multiple interconnected providers*. Art. 28 requires a register of information covering sub-outsourcing chains. Art. 30 mandates exit rights with ≥12 months transition assistance. | Regulation (EU) 2022/2554 | **[SECONDARY]** |
| **No regulator mandates a numeric concentration metric**, and no threshold is prescribed anywhere. Bayyina's bid-field index is therefore presented as our operationalisation of a qualitative concept, never as compliance. | Analysis of DORA, UK CTP regime (PS16/24, SS6/24), FSB Toolkit (Dec 2023), BCBS d605 (Dec 2025) | **[PRIMARY analysis]** |
| **NIS2 Art. 21(2)(d) is scoped to *direct* suppliers.** We do not claim NIS2 requires nth-party analysis; that would be an overreach. | Directive (EU) 2022/2555 | **[SECONDARY]** |
| **FedRAMP 20x** replaces static narrative assessment with **Key Security Indicators** — machine-readable, continuously and automatically validated assertions. Phase 3 (wide-scale adoption) began April 2026. The strongest precedent that government assurance is moving from attestation documents to machine-checkable evidence. | [fedramp.gov/20x](https://www.fedramp.gov/20x/) | **[PRIMARY]** |
| **CMMC Phase II was suspended on 13 July 2026** — the mandatory independent C3PAO assessment as a condition of award — with cost and barriers to entry for small suppliers cited as the reason, pending a 60-day reform review. | [Holland & Knight](https://www.hklaw.com/en/insights/publications/2026/07/dow-suspends-cmmc-phase-ii-requirements), [Federal News Network](https://federalnewsnetwork.com/cybersecurity/2026/07/pentagon-suspends-cmmc-phase-two-requirements-launches-review-of-program/) | **[SECONDARY, law firm + trade press]** |

---

## 5. UAE regulatory grounding

| Claim | Source | Confidence |
|---|---|---|
| **Federal Law No. 11 of 2023 on Procurement in the Federal Government**, issued 27 Nov 2023. **Art. 22(3):** non-financial evaluation criteria *"must be objective and commensurate with the nature of the Procurements … and be quantifiable as much as possible."* **Art. 22(4):** the announcement must give *"a clear breakdown of the used evaluation criteria, the evaluation mechanism, and the weight assigned to each criterion."* **Art. 29:** a failed bidder may request *"the weaknesses and strengths of its bid."* **Art. 16(4):** entities may pre-qualify suppliers. | [UAE Ministry of Finance PDF](https://mof.gov.ae/wp-content/uploads/2024/01/Federal-Law-No.-11-of-2023-on-Procurements-in-the-Federal-Government.pdf); implemented by Cabinet Resolution No. 122 of 2024 | **[PRIMARY]** |
| **UAE National Cloud Security Policy** (UAE Cyber Security Council, issued 6 Feb 2023; v2.0 Sept 2025) requires organisations to *"identify security risks from third-party suppliers and require independent security testing rather than relying solely on provider assertions."* | Legal analysis: [Pinsent Masons](https://www.pinsentmasons.com/out-law/news/security-policy-supports-shift-cloud-uae); official page: [u.ae](https://u.ae/en/about-the-uae/digital-uae/digital-transformation/strategies-policies-and-initiatives/National-Cloud-Security-Policy) | **[SECONDARY]** for the quoted clause; **[PRIMARY]** for the policy's existence and scope |
| **Dubai DESC Information Security Regulation v3** applies to *"all Dubai Government Entities, including employees, consultants, contractors, and visitors who are not government employees but are engaged with the government"*, and v3.0 introduced *"minimum security and compliance requirements for external party and managed services"*. **Domain 12 is Third Party Management.** Critical information may not be stored or processed outside the UAE. | DESC announcement coverage: [menews.ae](https://menews.ae/news/dubai-electronic-security-center-part-of-digital-dubai-to-launch-information-security-regulation-isr-version-3-0), [Zawya](https://www.zawya.com/en/legal/regulations/dubai-electronic-security-centre-to-launch-information-security-regulation-version-30-agaf4j9a); AWS holds a [DESC CSP Tier 1 License](https://aws.amazon.com/compliance/desc_csp_security_standard/) requiring ISR compliance | **[SECONDARY]** — DESC's own ISR page is not publicly indexed and the document is not publicly downloadable. We say so rather than implying we read it. |
| The **UAE Information Assurance Standard** (UAE Cyber Security Council; historically NESA, implemented via the Information Assurance Regulation) carries a **Third Party Security** control family and retains priority levels P1–P4. | [csc.gov.ae](https://csc.gov.ae/en/w/uae-information-assurance-standard); [AWS UAE IAR](https://aws.amazon.com/compliance/UAE_IAR/) | **[SECONDARY]** — csc.gov.ae was not directly retrievable from our build network |
| **UAE Federal Decree-Law No. 45 of 2021 (PDPL): the Executive Regulations have still not been issued** as of March 2026, and the Emirates Data Office is not yet fully operational. Art. 8 obliges processors to act on controller instructions, maintain a processing record, and use written agreements where multiple processors are involved. | [Chambers Data Protection & Privacy 2026 — UAE, 10 Mar 2026](https://practiceguides.chambers.com/practice-guides/data-protection-privacy-2026/uae/trends-and-developments) | **[PRIMARY-adjacent, authoritative legal guide]** |

**Not asserted anywhere:** a release date for IAS V2 (sources conflict); the existence of IAS V2.1 (single unverified source); that the PDPL Executive Regulations are in force (they are not); an Abu Dhabi ADSIC version number; that NCAP is mandatory; that the National Cybersecurity Strategy *mandates* SBOMs (reported, not confirmed against the strategy document).

---

## 6. Technical control authorities cited by individual checks

| Check | Authority |
|---|---|
| TLS-001 | RFC 8996 (deprecating TLS 1.0/1.1, March 2021); NIST SP 800-52 Rev. 2; CISA BOD 18-01 |
| TLS-002 | CA/Browser Forum Baseline Requirements; NIST SP 800-52r2 §3.3 |
| TLS-003 | RFC 8446; Mozilla Server Side TLS |
| WEB-001 | RFC 6797; CISA BOD 18-01; OWASP Secure Headers Project |
| WEB-002/003 | OWASP Secure Headers Project; OWASP HTTP Headers Cheat Sheet; MDN Observatory |
| WEB-004 | OWASP Session Management Cheat Sheet; RFC 6265bis |
| DNS-001 | RFC 7208 (including the 10-lookup limit, §4.6.4); CISA BOD 18-01 |
| DNS-002 | RFC 7489; CISA BOD 18-01 (p=reject mandated for US federal agencies) |
| DNS-003 | RFC 4033–4035; internet.nl test suite |
| DNS-004 | RFC 8659 |
| DNS-005 | RFC 8461; RFC 8460 |
| SUR-001/004 | RFC 9162 (Certificate Transparency v2) |
| SUR-002 | OWASP Secure Headers Project; OWASP ASVS v4 §14.3 |
| SUR-003 | RFC 9116 (security.txt); ISO/IEC 29147 |
| ATT-001 | IAF MD 28:2023; [DAkkS statement of 15 Nov 2024 declining to apply it](https://www.dakks.de/en/news/no-obligation-to-use-the-iaf-certsearch-database.html) |
| ATT-002 | IAF Multilateral Recognition Arrangement; UKAS / ANAB accredited body directories |
| ATT-003 | ISO/IEC 17021-1 three-year cycle with annual surveillance |
| ATT-004 | ISO/IEC 27001:2022 §4.3 (scope of the ISMS); A.5.19 |

**Prior art we build on rather than claim to have invented:** the Dutch government's [internet.nl](https://internet.nl/) runs a public, open-source, transparently-scored version of the technical-hygiene layer, and the UK NCSC operates [Web Check](https://checkcybersecurity.service.ncsc.gov.uk/) for public sector bodies. A national government already scores these exact controls in public. Bayyina's contribution is not the checks — it is testing attestations against them, bounding the unknowns, and analysing the bid field.

---

## 7. Assessment ethics and legality

| Position | Basis |
|---|---|
| Passive only: public datasets and normal-client protocol interaction. No port scanning, vulnerability probing, authentication attempts, fuzzing or AXFR. Enforced in the transport layer — there is no primitive for any of it in the codebase. | UK Computer Misuse Act 1990 s.1 has **no statutory research defence**, and the status of port scanning is unresolved; reform was announced 13 May 2026 but is not yet drafted. The US DOJ CFAA charging policy (19 May 2022) is **prosecutorial policy, not statute**, does not bind courts, and confers no civil immunity. |
| One request per endpoint per assessment cycle; identifying User-Agent pointing at a scope-policy page; documented opt-out. | The Menlo Report (DHS, 2012); ZMap "good internet citizenship" practices (Durumeric et al., USENIX Security 2013; *Ten Years of ZMap*, arXiv:2406.15585) |
| Every finding stores the raw observation and is disclosed with its check identifier, so a bidder can rebut it. | US Chamber *Principles for Fair and Accurate Security Ratings* — Transparency, and Dispute/Correction/Appeal; UAE Federal Law 11/2023 Art. 29 |
| Bidders are told that passive assessment forms part of evaluation, in the tender documentation, before it runs. | The cheapest and strongest available control: in a procurement context it removes the authorisation question almost entirely. |

---

## 8. Statistical method

| Choice | Justification |
|---|---|
| **Wilson score interval** for attestation reliability | The sample is small (often 4–16 units). The Wald/normal interval misbehaves at small *n* and near p = 0 or 1, where it can produce bounds outside [0,1]. Wilson does not. Verified against hand-computed values in `tests/test_ledger_and_stats.py`. |
| **The interval is computed over independent evidence sources, not over claims** | The claims are not independent Bernoulli trials: three of a bidder's attestations can be tested against a single HTTP response, and SPF and DMARC reflect one mail-configuration decision. Treating *n* claims as *n* trials would report an interval narrower than the evidence supports — the exact failure this tool exists to avoid. Claims are therefore clustered by the evidence record each was tested against, a cluster counts as corroborated only if every claim resting on it survived, and the claim-level figure is reported alongside as the optimistic bound. Clustering by evidence record is a conservative approximation of the real dependence structure, not a measurement of it, and the reports say so. |
| **Bounded intervals rather than imputation** for unobserved checks | Imputing an unobserved check requires a prior we have no basis for. Bounding requires none: the lower bound assumes every unknown fails, the upper assumes every one passes. There is no distributional assumption to attack. |
| **Dominance ranking** (rank only when intervals are disjoint) | A strict partial order. Avoids asserting an ordering the evidence does not support — the failure that ends in a procurement challenge. |
| **Dirichlet weight perturbation** (α = 40 × weight, seeded) | Answers "you chose the weights, so you chose the winner" with a measurement rather than an assertion. Seeded, so the figure reproduces exactly. |
| **Leave-one-criterion-out** | A blunter and more interpretable companion to the above: would dropping this criterion entirely change who wins? |
| **No machine learning** | No adequate labelled dataset exists; a model trained on public breach disclosures learns disclosure bias (Sarabi et al. 2016). A fitted model would also sit awkwardly with UAE Federal Law 11/2023 Art. 22(3)–(4), which require objective, quantifiable, pre-published criteria. There is consequently **no train/test split in this project, and no leakage risk, because nothing is fitted.** |
| **The composite is declared ordinal** | Per the FAIR critique: arithmetic on ordinals does not produce a risk measure. Bayyina claims a ranking and triage device, and says so in every report. |
