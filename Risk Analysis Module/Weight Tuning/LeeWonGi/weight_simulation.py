import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from opensearchpy import OpenSearch
import urllib3
import random
import json
import re
import sys

# SSL 경고 무시
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BankRiskOptimizer:
    def __init__(self):
        self.client = OpenSearch(
            hosts=[{"host": "localhost", "port": 9200}],
            http_auth=("admin", "VulnScanner_2026!@#"),
            use_ssl=True,
            verify_certs=False,
        )
        self.index_name = "vulnerability_cve"
        self.target_pool = [
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
            "CVE-2023-34048",
            "CVE-2021-26855",
            "CVE-2022-22965",
            "CVE-2020-1472",
        ]
        self.bank_cwes = [
            "CWE-190",
            "CWE-639",
            "CWE-306",
            "CWE-287",
            "CWE-613",
            "CWE-89",
            "CWE-311",
            "CWE-918",
            "CWE-117",
            "CWE-330",
        ]

    def fetch_data(self, total_size=5000, target_list=None):
        query_target = {"query": {"ids": {"values": target_list}}}
        res_t = self.client.search(index=self.index_name, body=query_target, size=20)
        targets = [hit["_source"] for hit in res_t["hits"]["hits"]]

        query_rand = {
            "query": {
                "bool": {
                    "must_not": {"ids": {"values": self.target_pool}},
                    "must": {"function_score": {"random_score": {}}},
                }
            },
            "size": total_size - len(targets),
        }
        res_r = self.client.search(index=self.index_name, body=query_rand)
        randoms = [hit["_source"] for hit in res_r["hits"]["hits"]]
        return pd.DataFrame(targets + randoms)

    def get_score(self, df, w):
        """
        w[0]: CVSS, w[1]: KEV, w[2]: CWE_bank, w[3]: EPSS
        """
        cwe_match = df["cwe_ids"].apply(
            lambda x: 1.0 if any(c in x for c in self.bank_cwes) else 0.0
        )
        return (
            (df["cvss_score"] * w[0])
            + (df["in_kev"].astype(float) * w[1])
            + (cwe_match * w[2])
            + (df["epss_score"] * w[3])
        )

    def fetch_vulns_for_real(self, tech_string):
        # 1. 원본 기술명 유지 (예: "apache:log4j-core:2.14.1")
        tech_lower = tech_string.lower()
        parts = tech_lower.split(":")
        vendor = parts[0]
        product = parts[1] if len(parts) > 1 else ""

        # 2. 검색은 일단 넓게 하되 키워드 조합으로 (vendor AND product)
        search_query = f"cpes:*{vendor}* AND cpes:*{product}*"

        query = {"query": {"query_string": {"query": search_query}}}

        try:
            res = self.client.search(index=self.index_name, body=query, size=5000)
            hits = res.get("hits", {}).get("hits", [])

            refined_results = []
            for hit in hits:
                source = hit.get("_source")
                db_cpe = str(source.get("cpes", "")).lower()

                # [핵심] 실제 기술명과 버전이 DB의 CPE 문자열에 들어있는지 엄격히 검증
                # 이 과정에서 상관없는 'apache' 취약점들이 다 걸러집니다.
                if vendor in db_cpe and product in db_cpe:
                    refined_results.append(source)

            return refined_results
        except:
            return []

    def analyze_json_report(self, weights, min_boundary=50):
        """동적 경계선에 하한선을 적용하여 풍성한 리포트 생성"""
        try:
            with open("scan_report_simulated_real.json", "r", encoding="utf-8") as f:
                scan_data = json.load(f)
        except FileNotFoundError:
            print("[-] 파일을 찾을 수 없습니다.")
            return

        all_detected = []
        seen_cves = set()
        for host in scan_data.get("subdomains", []):
            for port in host.get("open_ports", []):
                for tech in port.get("technologies", []):
                    for v in self.fetch_vulns_for_real(tech):
                        if v["cve_id"] not in seen_cves:
                            all_detected.append(v)
                            seen_cves.add(v["cve_id"])

        if not all_detected:
            print("\n[-] 탐지된 취약점이 없습니다.")
            return

        df_real = pd.DataFrame(all_detected)
        df_real["cvss_score"] = pd.to_numeric(
            df_real["cvss_score"], errors="coerce"
        ).fillna(0)
        df_real["epss_score"] = pd.to_numeric(
            df_real["epss_score"], errors="coerce"
        ).fillna(0)
        df_real["risk_score"] = self.get_score(df_real, weights)
        df_real = df_real.sort_values(by="risk_score", ascending=False).reset_index(
            drop=True
        )

        # --- [개선된 동적 경계선 로직] ---
        target_indices = df_real.index[
            df_real["cve_id"].isin(self.target_pool)
        ].tolist()

        # 타겟 중 가장 낮은 순위와 '최소 하한선(50)' 중 큰 값을 경계선으로 설정
        last_target_rank = max(target_indices) + 1 if target_indices else 0
        dynamic_cutoff = max(min_boundary, last_target_rank)

        # 1. 위험(CRITICAL): 타겟 CVE 전부 + 부족하면 상위권 채워 15개 고정
        target_mask = df_real["cve_id"].isin(self.target_pool)
        critical_targets = df_real[target_mask].copy()
        non_targets = df_real[~target_mask].copy()

        needed = 15 - len(critical_targets)
        critical_group = pd.concat(
            [critical_targets, non_targets.head(max(0, needed))]
        ).sort_values(by="risk_score", ascending=False)
        critical_ids = set(critical_group["cve_id"])

        # 2. 주의(WARNING): 설정된 경계선(dynamic_cutoff) 내에서 위험군 제외
        # 이제 dynamic_cutoff가 최소 50이므로, 위험 15개를 빼도 약 35개의 후보가 생김
        analysis_boundary = df_real.head(dynamic_cutoff)
        warning_candidates = analysis_boundary[
            ~analysis_boundary["cve_id"].isin(critical_ids)
        ]
        warning_display = warning_candidates.head(20)  # 그중 상위 20개 출력
        warning_ids = set(warning_candidates["cve_id"])

        # 3. 참고(INFO): 나머지 중 상위 10개
        info_remaining = df_real[~df_real["cve_id"].isin(critical_ids | warning_ids)]
        info_display = info_remaining.head(10)

        # --- [출력] ---
        print("\n" + "█" * 85)
        print(f"  📊 금융 인프라 자산 분석 리포트")
        print(
            f"  - 총 탐지: {len(df_real):,}건 | 분석 경계: 상위 {dynamic_cutoff}위 (타겟 최하순위: {last_target_rank}위)"
        )
        print(
            f"  - 적용 가중치: CVSS({weights[0]:.2f}), KEV({weights[1]:.2f}), CWE({weights[2]:.2f}), EPSS({weights[3]:.2f})"
        )
        print("█" * 85)

        print(
            f" 🔥 [위험(CRITICAL)] - 총 {len(critical_group)}건 (타겟 및 최상위 고위험)"
        )
        for _, r in critical_group.iterrows():
            tag = "[TARGET]" if r["cve_id"] in self.target_pool else "[HIGH-S]"
            print(f"    - {r['cve_id']:<18} | 점수: {r['risk_score']:>6.2f} | {tag}")

        print("-" * 85)
        # 이제 "분석 범위 내 총 35개 중 상위 20개 출력" 처럼 나옵니다.
        print(
            f" ⚠️ [주의(WARNING)] - 분석 범위 내 총 {len(warning_candidates)}개 중 상위 {len(warning_display)}개 출력"
        )
        for _, r in warning_display.iterrows():
            print(f"    - {r['cve_id']:<18} | 점수: {r['risk_score']:>6.2f}")

        if not info_display.empty:
            print("-" * 85)
            print(f" ℹ️ [참고(INFO)] - 상위 {len(info_display)}개 요약")
            for _, r in info_display.iterrows():
                print(f"    - {r['cve_id']:<18} | 점수: {r['risk_score']:>6.2f}")
        print("█" * 85)

    def run_mode_1_optimization(self, iterations=1000, log_step=50):
        """기존 1번: 시뮬레이션 및 가중치 최적화 진행"""
        weights = [1.0, 0.0, 0.0, 0.0]
        history = []
        df_val = self.fetch_data(5000, self.target_pool)

        print("시뮬레이션 시작: 점진적 가중치 최적화 진행 중...")
        for i in range(iterations):
            selected_train = random.sample(self.target_pool, 10)
            df_train = self.fetch_data(5000, selected_train)
            df_train["score"] = self.get_score(df_train, weights)
            df_train = df_train.sort_values(by="score", ascending=False).reset_index(
                drop=True
            )
            current_max_rank = (
                df_train[df_train["cve_id"].isin(selected_train)].index.max() + 1
            )

            if current_max_rank > 50:
                weights[1] += 0.008
                weights[2] += 0.012
                weights[3] += 0.020

            if i % log_step == 0 or i == iterations - 1:
                df_val["score"] = self.get_score(df_val, weights)
                df_val_sorted = df_val.sort_values(
                    by="score", ascending=False
                ).reset_index(drop=True)
                val_alerts = (
                    df_val_sorted[
                        df_val_sorted["cve_id"].isin(self.target_pool)
                    ].index.max()
                    + 1
                )
                history.append(
                    {"iter": i, "val_alerts": val_alerts, "weights": list(weights)}
                )
                w_str = ", ".join([f"{x:.2f}" for x in weights])
                print(f"[{i:4d}] Alerts: {val_alerts:4d} | Weights: [{w_str}]")

        print("\n최종 최적화 가중치 산정 완료.")
        self.plot_results(pd.DataFrame(history))

        choice = input(
            "\n[?] 최적화된 가중치로 실제 데이터를 분석하시겠습니까? (y/n): "
        )
        if choice.lower() == "y":
            self.analyze_json_report(weights)

    def run_mode_2_manual(self):
        """새로운 2번: 고정된 가중치로 즉시 분석 진행"""
        print("\n" + "=" * 50)
        print("모드 2: 수동 설정 가중치 기반 분석")
        print("=" * 50)

        # --- [수정 포인트] 여기에 원하는 가중치를 직접 입력하세요 ---
        # 예: [CVSS, KEV, CWE_bank, EPSS]
        manual_weights = [1.00, 3.58, 5.36, 8.94]
        # -------------------------------------------------------

        print(f"[*] 설정된 가중치 적용: {manual_weights}")
        self.analyze_json_report(manual_weights)

    def plot_results(self, h_df):
        plt.figure(figsize=(10, 6))
        plt.scatter(h_df["iter"], h_df["val_alerts"], color="tab:red", alpha=0.3)
        z = np.polyfit(h_df["iter"], h_df["val_alerts"], 4)
        p = np.poly1d(z)
        plt.plot(
            h_df["iter"],
            p(h_df["iter"]),
            color="tab:red",
            linewidth=3,
            label="Optimization Trend",
        )
        plt.title("Vulnerability Prioritization Optimization", fontsize=14)
        plt.grid(True, linestyle="--", alpha=0.5)
        plt.savefig("final_optimization_clean.png")


if __name__ == "__main__":
    optimizer = BankRiskOptimizer()
    print("==========================================")
    print("   금융 자산 취약점 리스크 분석 시스템")
    print("==========================================")
    print("1. 자동 가중치 최적화 시뮬레이션 후 분석")
    print("2. 수동 가중치 설정 기반 즉시 분석")
    print("==========================================")

    user_choice = input("[?] 모드를 선택하세요 (1/2): ").strip()

    if user_choice == "1":
        optimizer.run_mode_1_optimization(1000, 50)
    elif user_choice == "2":
        optimizer.run_mode_2_manual()
    else:
        print("[-] 잘못된 선택입니다. 프로그램을 종료합니다.")
