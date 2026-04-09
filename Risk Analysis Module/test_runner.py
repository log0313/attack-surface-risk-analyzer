import json
import re
from opensearchpy import OpenSearch
import urllib3

# SSL 경고 무시
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FinancialVulnerabilityAnalyzer:
    def __init__(self):
        # 1. OpenSearch 클라이언트 설정
        self.client = OpenSearch(
            hosts=[{"host": "localhost", "port": 9200}],
            http_auth=("admin", "VulnScanner_2026!@#"),
            use_ssl=True,
            verify_certs=False,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
        )
        self.index_name = "vulnerability_cve"

        # 관리 대상 10개 핵심 CVE 리스트
        self.target_cve_list = [
            "CVE-2022-29464",
            "CVE-2023-34362",
            "CVE-2023-0669",
            "CVE-2024-3400",
            "CVE-2023-4966",
            "CVE-2022-40684",
            "CVE-2022-1388",
            "CVE-2017-5638",
            "CVE-2021-44228",
            "CVE-2025-61757",
        ]

    def extract_keywords(self, tech_string):
        """DB에 저장된 복잡한 CPE 명칭과 매칭되도록 키워드 분리 강화"""
        clean = re.sub(r"[:\-_/]", " ", str(tech_string)).lower()
        words = clean.split()

        version = "*"
        keywords = []
        for w in words:
            if re.match(r"^[0-9.]+$", w):
                version = w
            elif len(w) > 1:
                keywords.append(w)

        if "log4j" in keywords:
            keywords.append("apache")
        if "identity" in keywords:
            keywords.append("oracle")

        return keywords, version

    def fetch_vulns(self, tech):
        keywords, version = self.extract_keywords(tech)
        if not keywords:
            return []

        keyword_qs = " OR ".join([f"cpes:*{k}*" for k in keywords])
        query = {
            "query": {
                "bool": {
                    "should": [
                        {
                            "query_string": {
                                "query": keyword_qs,
                                "analyze_wildcard": True,
                            }
                        },
                        {"terms": {"cve_id": self.target_cve_list}},
                    ]
                }
            }
        }

        try:
            res = self.client.search(
                body={**query, "size": 1000}, index=self.index_name
            )
            results = []
            hits = res.get("hits", {}).get("hits", [])

            for hit in hits:
                if not isinstance(hit, dict):
                    continue
                source = hit.get("_source")
                if not isinstance(source, dict):
                    continue

                cve_id = source.get("cve_id")
                db_cpes = str(source.get("cpes", "")).lower()

                is_target = cve_id in self.target_cve_list
                keyword_match = any(k in db_cpes for k in keywords)

                if is_target or keyword_match:
                    if version == "*" or version in db_cpes or "*" in db_cpes:
                        priority = 1000000 if is_target else 0
                        priority += source.get("cvss_score", 0) * 10

                        vuln_item = source.copy()
                        vuln_item["priority"] = priority
                        results.append(vuln_item)
            return results
        except:
            return []

    def run_analysis(self, json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                scan_data = json.load(f)

            detected = set()
            print(
                f"\n[*] 🛡️ 금융 인프라 정밀 분석 시스템 가동 (Target: {scan_data.get('root_domain')})"
            )

            for host in scan_data.get("subdomains", []):
                for port in host.get("open_ports", []):
                    techs = port.get("technologies", [])
                    for t in techs:
                        if any(
                            ig in str(t).lower() for ig in ["ubuntu", "debian", "php"]
                        ):
                            continue

                        vulns = self.fetch_vulns(t)
                        for v in vulns:
                            detected.add(v.get("cve_id"))

            # === 결과 리포트 출력 섹션 ===
            print("\n" + "█" * 75)
            print("  📊 금융권 핵심 관리 취약점(10개) 최종 검증 결과")
            print("█" * 75)
            for target in self.target_cve_list:
                status = "✅ [탐지됨]" if target in detected else "❌ [미탐지]"
                print(f"  - {target:<18} : {status}")

            print("─" * 75)
            # 식별된 전체 취약점 개수와 타겟 취약점 개수 계산
            found_target_total = len(detected.intersection(set(self.target_cve_list)))
            all_vuln_total = len(detected)

            print(
                f"[*] 금융권 핵심 관리 대상 탐지: {found_target_total} / {len(self.target_cve_list)} 개"
            )
            print(f"[*] 인프라 내 전체 식별 취약점: {all_vuln_total} 개")
            print("█" * 75)

        except Exception as e:
            print(f" [!] 실행 에러: {e}")


if __name__ == "__main__":
    analyzer = FinancialVulnerabilityAnalyzer()
    analyzer.run_analysis("scan_report_simulated.json")
