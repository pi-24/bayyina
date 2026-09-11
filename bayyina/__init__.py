"""Bayyina — evidence-based third-party vendor assurance for government procurement.

*Bayyina* (بيّنة) is the Arabic legal term for clear, produced evidence — the
standard a claim has to meet before it is relied on. That is the whole idea of
this tool: a supplier's security questionnaire is an assertion, and an
assertion is not evidence until something tests it.

Entry points:
    bayyina.engine.assess_tender  — the whole pipeline
    bayyina.cli.main              — command line
    bayyina.api.build_app         — HTTP API (optional extra)
"""

__version__ = "0.9.0"
__all__ = ["__version__"]
