import json
import os
import numpy as np
from opensearchpy import OpenSearch
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ══════════════════════════════════════════════════════════════
# 1. 설정 및 글로벌 상수
# ══════════════════════════════════════════════════════════════
BANK_CRITICAL_CWES = [
    "CWE-89", "CWE-78", "CWE-287", "CWE-306", "CWE-502",
    "CWE-269", "CWE-284", "CWE-285", "CWE-639", "CWE-327",
    "CWE-326", "CWE-311", "CWE-918", "CWE-611", "CWE-434",
    "CWE-1104", "CWE-494"
]


class AssetRiskAnalyzer:
    def __init__(self):
        # OpenSearch 연결
        self.client = OpenSearch(
            hosts=[{"host": "localhost", "port": 9200}],
            http_auth=("admin", "VulnScanner_2026!@#"),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False,
        )
        self.index_name = "vulnerability_cve"

    # ══════════════════════════════════════════════════════════════
    # 2. ML 기반 위험도 계산 (학습된 CWE 계수 포함)
    # ══════════════════════════════════════════════════════════════
    def calculate_ml_risk_score(self, cvss, epss, has_poc, cwes):
        base_cvss = float(cvss) if cvss is not None else 0.0
        base_epss = float(epss) if epss is not None else 0.0
        flag_poc = 1 if has_poc else 0

        flag_cwe = 0
        if isinstance(cwes, list) and any(cwe in BANK_CRITICAL_CWES for cwe in cwes):
            flag_cwe = 1

        # 업데이트된 Logistic Regression 공식 (CWE가 수식 안으로 들어옴)
        #z = -7.8119 + (0.1985 * base_cvss) + (5.7956 * base_epss) + (1.0100 * flag_poc) + (0.0649 * flag_cwe)
        z = -5.9571 + (0.1744 * base_cvss) + (5.6841 * base_epss) + (0.7553 * flag_poc) + (0.2420 * flag_cwe)

        # 외부 보정 없이 순수 Sigmoid 함수만 적용
        final_prob = 1 / (1 + np.exp(-z))

        return round(final_prob * 100, 2)

    # ══════════════════════════════════════════════════════════════
    # 3. OpenSearch에서 기술 스택(CPE) 기반 취약점 검색
    # ══════════════════════════════════════════════════════════════
    def fetch_cves_for_tech(self, tech_string):
        parts = tech_string.lower().split(':')
        if len(parts) < 2:
            return []

        vendor = parts[0]
        product_raw = parts[1]

        product = product_raw.replace("-core", "").replace("_suite", "").replace("_adc", "").replace("_mft", "")
        version = parts[2] if len(parts) > 2 and parts[2] != "*" else ""

        if version:
            search_term = f"*{vendor}*{product}*{version}*"
        else:
            search_term = f"*{vendor}*{product}*"

        query = {
            "size": 1000,
            "query": {
                "wildcard": {
                    "cpes": {"value": search_term}
                }
            },
            "sort": [
                {"in_kev": {"order": "desc"}},
                {"cvss_score": {"order": "desc"}}
            ]
        }

        try:
            res = self.client.search(index=self.index_name, body=query)
            return [hit['_source'] for hit in res['hits']['hits']]
        except Exception as e:
            print(f"[!] OpenSearch 검색 오류 ({tech_string}): {e}")
            return []

    # ══════════════════════════════════════════════════════════════
    # 4. 스캔 파일 분석 및 리포트 생성
    # ══════════════════════════════════════════════════════════════
    def analyze_scan_file(self, json_file_path):
        if not os.path.exists(json_file_path):
            print(f"[!] 에러: {json_file_path} 파일이 없습니다. 스캐너를 먼저 돌려주세요.")
            return

        print(f"[*] 스캔 결과 로드 중: {json_file_path}")
        with open(json_file_path, 'r', encoding='utf-8') as f:
            scan_data = json.load(f)

        analyzed_results = []
        seen_cves = set()  # 중복 CVE 출력 방지용

        root_domain = scan_data.get("root_domain", "Unknown")
        print(f"[*] 분석 대상 호스트: {root_domain}\n")

        # 스캐너의 JSON 구조 파싱: subdomains -> open_ports -> technologies
        for sub in scan_data.get("subdomains", []):
            host = sub.get("host", root_domain)

            for port_info in sub.get("open_ports", []):
                port = port_info.get("port")
                techs = port_info.get("technologies", [])

                for tech in techs:
                    print(f" [🔍] OpenSearch 검색 중... (기술: {tech})")
                    cve_list = self.fetch_cves_for_tech(tech)

                    for cve in cve_list:
                        cve_id = cve.get("cve_id")

                        # 이미 분석한 CVE면 패스 (동일 호스트/포트 중복 제거)
                        if cve_id in seen_cves:
                            continue
                        seen_cves.add(cve_id)

                        # ML 엔진을 통한 점수 계산
                        cvss = cve.get("cvss_score", 0.0)
                        epss = cve.get("epss_percentile", 0.0)
                        has_poc = cve.get("has_poc", False)
                        cwes = cve.get("cwes", [])
                        in_kev = cve.get("in_kev", False)

                        risk_score = self.calculate_ml_risk_score(cvss, epss, has_poc, cwes)

                        # KEV는 무조건 최우선 처리 (100점 오버라이드)
                        if in_kev:
                            risk_score = 100.0

                        analyzed_results.append({
                            "target": f"{host}:{port}",
                            "tech": tech,
                            "cve_id": cve_id,
                            "cvss": cvss,
                            "epss": epss,
                            "has_poc": has_poc,
                            "in_kev": in_kev,
                            "risk_score": risk_score
                        })

        # 위험도 점수 기준 내림차순 정렬
        analyzed_results.sort(key=lambda x: x["risk_score"], reverse=True)
        self._print_report(analyzed_results)

    def _print_report(self, results):
        print("\n" + "=" * 90)
        print(" 🤖 [ML 기반 자산 취약점 분석 리포트 (Threshold: 25.7 적용)]")
        print("=" * 90)
        print(f" {'Target':<18} | {'Technology':<25} | {'CVE ID':<15} | {'PoC/KEV':<7} | {'Risk Score'}")
        print("-" * 90)

        if not results:
            print("  발견된 취약점이 없습니다! 안전합니다. 🎉")

        # 통계 카운트용 변수
        emergency_cnt = 0
        critical_cnt = 0
        managed_cnt = 0
        low_cnt = 0

        for res in results:
            score = res['risk_score']

            # 💡 위험도 라벨링 (ML Threshold 및 실무 기준 적용)
            if res['in_kev']:
                alert = "☠️ (Emergency)"
                emergency_cnt += 1
            elif score >= 84.4:
                alert = "🚨 (Critical)"
                critical_cnt += 1
            elif score >= 24.3:
                alert = "⚠️ (High/Med)"
                managed_cnt += 1
            else:
                alert = "✅ (Low)"
                low_cnt += 1

            poc_str = "O" if res['has_poc'] else "X"
            kev_str = "O" if res['in_kev'] else "X"
            threat_badge = f"{poc_str}/{kev_str}"

            # 기술 이름이 너무 길면 자름
            tech_short = res['tech'][:23] + ".." if len(res['tech']) > 25 else res['tech']

            print(
                f" {res['target']:<18} | {tech_short:<25} | {res['cve_id']:<15} | {threat_badge:<7} | {score:>5.1f}점 {alert}")

        print("=" * 90)
        print(f"[*] 총 {len(results)}개의 취약점 매핑 및 AI 리스크 평가 완료.")
        print(f"  - ☠️ 즉각 조치 (KEV 100점)          : {emergency_cnt}건")
        print(f"  - 🚨 긴급 패치 (85.0점 이상)        : {critical_cnt}건")
        print(f"  - ⚠️ 잠재 위험 (ML 임계치 73.3 이상): {managed_cnt}건 (정기 패치 대상)")
        print(f"  - ✅ 수용 가능 (안전함)             : {low_cnt}건")
        print("=" * 90)


if __name__ == "__main__":
    analyzer = AssetRiskAnalyzer()
    target_file = "scan_report_simulated.json"
    analyzer.analyze_scan_file(target_file)
