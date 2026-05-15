"""FastAPI 기반 LLM Report API Server.

엔드포인트
─────────
  GET  /api/llm/health
  GET  /api/llm/providers
  POST /api/llm/report/vulnerability
  POST /api/llm/report/asset
  POST /api/llm/report/summary

실행
────
  cd "LLM Report Module"
  cp .env.example .env       # 또는 환경변수 직접 설정
  pip install -r requirements.txt
  uvicorn api_server:app --host 0.0.0.0 --port 8000
"""
import os
from typing import Any, Optional

from dotenv import load_dotenv
load_dotenv()  # .env 우선 로드

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from llm_report_generator import LLMReportGenerator
from risk_data_adapter import build_llm_input, load_record_from_opensearch


app = FastAPI(
    title="Attack Surface LLM Report API",
    description=(
        "이미 산출된 위험 분석 결과(张正秀 + 李元吉 加权)를 "
        "자연어 보고서(JSON)로 변환하는 보조 모듈."
    ),
    version="0.1.0",
)

# Dashboard 호출을 위한 CORS 허용 (운영 시 도메인 제한 권장)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ───────────────────────────────────────────────
# Pydantic 모델
# ───────────────────────────────────────────────

class VulnReportRequest(BaseModel):
    asset_id: Optional[str] = None
    domain: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    service_name: Optional[str] = None
    technology_stack: Optional[Any] = None

    cve_id: str

    # 다음 점수 필드들은 옵션:
    # - 모두 제공 → 그대로 LLM에 전달
    # - 일부만 제공 → risk_data_adapter 로 점수 산출 후 LLM에 전달
    # - fetch_from_opensearch=True → DB 조회 후 점수 산출
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev_status: Optional[bool] = None
    poc_status: Optional[bool] = None
    cwe_id: Optional[Any] = None
    final_risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    priority: Optional[str] = None
    ranking_reason: Optional[str] = None
    weight_detail: Optional[dict] = None

    fetch_from_opensearch: bool = False
    language: Optional[str] = None  # ko | en | zh


class AssetReportRequest(BaseModel):
    asset: dict
    vulnerabilities: list
    language: Optional[str] = None


class SummaryReportRequest(BaseModel):
    scan_meta: dict
    top_vulnerabilities: list
    language: Optional[str] = None


# ───────────────────────────────────────────────
# 헬스체크 / Provider 조회
# ───────────────────────────────────────────────

@app.get("/api/llm/health")
def health():
    return {
        "status": "ok",
        "provider": os.getenv("LLM_PROVIDER", "mock"),
        "language": os.getenv("REPORT_LANGUAGE", "ko"),
    }


@app.get("/api/llm/providers")
def list_providers():
    return {
        "active": os.getenv("LLM_PROVIDER", "mock"),
        "available": ["mock", "openai", "gemini", "claude"],
    }


# ───────────────────────────────────────────────
# 핵심 엔드포인트
# ───────────────────────────────────────────────

@app.post("/api/llm/report/vulnerability")
def report_vulnerability(req: VulnReportRequest):
    """단일 자산-CVE 쌍에 대한 AI 위험 보고서."""
    try:
        payload = req.model_dump()
        lang = payload.pop("language", None)
        fetch_db = payload.pop("fetch_from_opensearch", False)

        if fetch_db:
            record = load_record_from_opensearch(req.cve_id, asset_info=payload)
            input_data = build_llm_input(record)
        elif req.final_risk_score is None or req.risk_level is None or req.priority is None:
            # 점수 일부 누락 → adapter로 보강 (李 + 张 식 적용)
            input_data = build_llm_input(_map_request_to_record(payload))
        else:
            # 호출자가 점수까지 모두 들고 있다면 그대로 사용
            input_data = payload

        gen = LLMReportGenerator(lang=lang or "")
        return gen.generate_vulnerability_report(input_data)
    except (LookupError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM 호출 실패: {e}")


@app.post("/api/llm/report/asset")
def report_asset(req: AssetReportRequest):
    """단일 자산에 식별된 다수 취약점 종합 보고서."""
    try:
        gen = LLMReportGenerator(lang=req.language or "")
        return gen.generate_asset_report(req.asset, req.vulnerabilities)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM 호출 실패: {e}")


@app.post("/api/llm/report/summary")
def report_summary(req: SummaryReportRequest):
    """전체 스캔 결과의 임원 요약 보고서."""
    try:
        gen = LLMReportGenerator(lang=req.language or "")
        return gen.generate_summary_report(req.scan_meta, req.top_vulnerabilities)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM 호출 실패: {e}")


# ───────────────────────────────────────────────
# Helpers
# ───────────────────────────────────────────────

def _map_request_to_record(payload: dict) -> dict:
    """API 요청 payload를 risk_data_adapter 의 record 형식으로 매핑."""
    rec = dict(payload)
    # adapter는 in_kev / cwe_ids / has_poc 키를 우선 사용
    if "kev_status" in rec and "in_kev" not in rec:
        rec["in_kev"] = rec["kev_status"]
    if "cwe_id" in rec and "cwe_ids" not in rec:
        rec["cwe_ids"] = rec["cwe_id"]
    if "poc_status" in rec and "has_poc" not in rec and rec["poc_status"] is not None:
        rec["has_poc"] = rec["poc_status"]
    if "service_name" in rec and "service" not in rec:
        rec["service"] = rec["service_name"]
    if "technology_stack" in rec and "technologies" not in rec:
        rec["technologies"] = rec["technology_stack"]
    if "ip" in rec and "host" not in rec:
        rec["host"] = rec["ip"]
    return rec


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api_server:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", "8000")),
        reload=False,
    )
