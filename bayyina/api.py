"""Optional HTTP API.

Kept deliberately thin. The API exists because a procurement system needs to
call the assessment as a service, not because the analysis lives here — every
endpoint is a wrapper over the same ``assess_tender`` the CLI uses, so there is
no second implementation to drift out of step with the first.

Install the extra and run:
    pip install -e '.[api]'
    bayyina serve --tender scenarios/MDG-2026-114
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .engine import AssessmentRun, assess_tender
from .report import comparison, vendor_report


def build_app(tender_path: str, mode: str = "replay"):
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse

    app = FastAPI(
        title="Bayyina",
        version="0.9.0",
        description=(
            "Evidence-based third-party vendor assurance for government procurement. "
            "Passive assessment only: public datasets and normal-client protocol interaction."
        ),
    )

    cache: Dict[str, AssessmentRun] = {}

    def current() -> AssessmentRun:
        if "run" not in cache:
            cache["run"] = assess_tender(tender_path, mode=mode)
        return cache["run"]

    @app.get("/health")
    def health() -> Dict[str, Any]:
        return {"status": "ok", "tender": tender_path, "mode": mode}

    @app.post("/refresh")
    def refresh() -> Dict[str, Any]:
        cache.pop("run", None)
        run = current()
        return {"reassessed": True, "ledger_head": run.ledger.head if run.ledger else None}

    @app.get("/tender")
    def tender() -> Dict[str, Any]:
        run = current()
        return {
            "tender": run.tender.to_dict(),
            "weights": run.weights,
            "ranking": run.ranking,
            "concentration": run.concentration,
            "sensitivity": run.sensitivity,
            "leave_one_category_out": run.leave_one_out,
        }

    @app.get("/vendors")
    def vendors() -> Dict[str, Any]:
        run = current()
        return {
            "vendors": [
                {
                    "vendor_id": a.vendor.vendor_id,
                    "legal_name": a.vendor.legal_name,
                    "point": a.point,
                    "lower": a.lower,
                    "upper": a.upper,
                    "coverage": a.coverage,
                    "attestation_reliability": run.reliability.get(a.vendor.vendor_id),
                }
                for a in run.assessments
            ]
        }

    @app.get("/vendors/{vendor_id}")
    def vendor(vendor_id: str) -> Dict[str, Any]:
        run = current()
        assessment = run.vendor(vendor_id)
        if not assessment:
            raise HTTPException(status_code=404, detail=f"no such bidder: {vendor_id}")
        return {
            **assessment.to_dict(),
            "attestation_reliability": run.reliability.get(vendor_id),
            "contract_conditions": run.conditions.get(vendor_id),
        }

    @app.get("/vendors/{vendor_id}/report", response_class=HTMLResponse)
    def vendor_html(vendor_id: str) -> str:
        run = current()
        assessment = run.vendor(vendor_id)
        if not assessment:
            raise HTTPException(status_code=404, detail=f"no such bidder: {vendor_id}")
        return vendor_report(run, assessment)

    @app.get("/", response_class=HTMLResponse)
    @app.get("/report", response_class=HTMLResponse)
    def dashboard() -> str:
        return comparison(current())

    @app.get("/ledger")
    def ledger() -> Dict[str, Any]:
        run = current()
        ok, problems = run.ledger.verify() if run.ledger else (False, ["no ledger"])
        return {
            "records": len(run.ledger) if run.ledger else 0,
            "head": run.ledger.head if run.ledger else None,
            "verified": ok,
            "problems": problems,
        }

    return app


def serve(tender_path: str, host: str = "127.0.0.1", port: int = 8000, mode: str = "replay") -> None:
    import uvicorn

    uvicorn.run(build_app(tender_path, mode=mode), host=host, port=port)
