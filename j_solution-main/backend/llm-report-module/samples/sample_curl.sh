#!/bin/bash
# LLM Report API 호출 예시
# 사전 조건: api_server.py 가 http://localhost:8000 에서 실행 중

BASE=http://localhost:8000

# 1) 헬스 체크
echo "=== Health ==="
curl -s $BASE/api/llm/health | python -m json.tool

# 2) 단일 취약점 보고서
echo
echo "=== Vulnerability Report ==="
curl -s -X POST $BASE/api/llm/report/vulnerability \
  -H "Content-Type: application/json" \
  -d @sample_input.json | python -m json.tool

# 3) 자산 보고서
echo
echo "=== Asset Report ==="
curl -s -X POST $BASE/api/llm/report/asset \
  -H "Content-Type: application/json" \
  -d '{
    "asset": {"asset_id": "asset-001", "host": "localhost", "port": 8080},
    "vulnerabilities": [
      {"cve_id": "CVE-2021-44228", "final_risk_score": 22.93, "risk_level": "Immediate", "priority": "Immediate"}
    ],
    "language": "ko"
  }' | python -m json.tool

# 4) 요약 보고서
echo
echo "=== Summary Report ==="
curl -s -X POST $BASE/api/llm/report/summary \
  -H "Content-Type: application/json" \
  -d '{
    "scan_meta": {"root_domain": "localhost", "scan_time": "2026-04-09", "total_assets": 1, "total_vulns": 1},
    "top_vulnerabilities": [
      {"cve_id": "CVE-2021-44228", "final_risk_score": 22.93, "priority": "Immediate"}
    ],
    "language": "ko"
  }' | python -m json.tool
