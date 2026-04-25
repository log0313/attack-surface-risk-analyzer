"""
EPSS-KEV Gap Based Early Warning Model
EPSS-KEV 갭 기반 금융권 선제 대응 모델

작성자: WangJinling
경로: Risk Analysis Module/Weight Tuning/WangJinling/epss_kev_gap_early_warning.py

실행 방법:
    cd "Risk Analysis Module"
    python "Weight Tuning/WangJinling/epss_kev_gap_early_warning.py"
"""

import json
import os
import re
import sys

try:
    from opensearchpy import OpenSearch
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    OPENSEARCH_AVAILABLE = True
except ImportError:
    OPENSEARCH_AVAILABLE = False
    print("[!] opensearch-py 미설치. OpenSearch 연결 없이 샘플 데이터로 실행합니다.")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("[!] pandas 미설치. CSV만 출력합니다.")

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False


# ──────────────────────────────────────────────
# 설정값
# ──────────────────────────────────────────────

OPENSEARCH_CONFIG = {
    "host": "localhost",
    "port": 9200,
    "username": "admin",
    "password": "VulnScanner_2026!@#",
    "index_name": "vulnerability_cve",
}

TOP_N = 30

# 금융 핵심 자산 식별 키워드
CRITICAL_ASSET_KEYWORDS = [
    "api gateway", "managed file transfer", "mft", "vpn", "adc",
    "network firewall", "iam", "identity", "internet banking",
    "core framework", "wso2", "moveit", "goanywhere", "citrix",
    "netscaler", "palo alto", "pan-os", "fortinet", "fortios",
    "f5", "big-ip", "oracle", "struts", "log4j",
]

# 인증 우회 / RCE 관련 키워드 및 CWE
AUTH_RCE_KEYWORDS = [
    "rce", "remote code execution", "auth bypass", "authentication bypass",
    "pre-auth", "sql injection", "os command injection",
    "cwe-287", "cwe-306", "cwe-89", "cwe-78", "cwe-502", "cwe-918",
]

# 인터넷 노출 포트
EXPOSED_PORTS = {80, 443, 8080, 8081, 8443, 9443, 14000}

# Priority Category 라벨
CAT_IMMEDIATE   = "Immediate Watchlist"
CAT_CONFIRMED   = "Confirmed Exploited"
CAT_HIGH        = "High Probability"
CAT_STANDARD    = "Standard Monitoring"


# ──────────────────────────────────────────────
# 유틸 함수
# ──────────────────────────────────────────────

def _contains_any(text: str, keywords: list) -> bool:
    """대소문자 무관 키워드 포함 여부"""
    t = text.lower()
    return any(k.lower() in t for k in keywords)


def compute_critical_asset_flag(asset_type="", technology="", web_title="", cpe_23="") -> int:
    combined = " ".join([asset_type, technology, web_title, cpe_23])
    return 1 if _contains_any(combined, CRITICAL_ASSET_KEYWORDS) else 0


def compute_auth_rce_flag(vuln_type="", description="", cwe_ids="") -> int:
    combined = " ".join([str(vuln_type), str(description), str(cwe_ids)])
    return 1 if _contains_any(combined, AUTH_RCE_KEYWORDS) else 0


def compute_internet_exposed_flag(service="", port=0) -> int:
    if str(service).lower() in ("http", "https"):
        return 1
    if int(port) in EXPOSED_PORTS:
        return 1
    return 0


def compute_ransomware_flag(value) -> int:
    """knownRansomwareCampaignUse 필드가 'known'이면 1, 그 외 0"""
    return 1 if str(value).lower() == "known" else 0


def compute_kev_gap_bonus(epss_percentile: float, in_kev: bool) -> float:
    if in_kev:
        return 0
    if epss_percentile >= 0.95:
        return 20
    elif epss_percentile >= 0.90:
        return 15
    elif epss_percentile >= 0.80:
        return 10
    return 0


def compute_scores(cvss_score, epss_percentile, in_kev,
                   critical_asset_flag, auth_or_rce_flag,
                   internet_exposed_flag, ransomware_flag):
    cvss_norm = cvss_score / 10.0
    kev_flag  = 1 if in_kev else 0

    base = cvss_norm * 25 + epss_percentile * 35 + kev_flag * 15
    kev_gap_bonus = compute_kev_gap_bonus(epss_percentile, in_kev)
    financial = (
        critical_asset_flag    * 10
        + auth_or_rce_flag     * 8
        + internet_exposed_flag * 7
        + ransomware_flag      * 5   # 소폭 가산
    )
    final = min(100.0, base + kev_gap_bonus + financial)

    return round(cvss_norm, 4), round(base, 2), round(kev_gap_bonus, 2), round(financial, 2), round(final, 2)


def determine_priority_category(epss_percentile, in_kev, critical_asset_flag) -> str:
    if not in_kev and epss_percentile >= 0.90 and critical_asset_flag == 1:
        return CAT_IMMEDIATE
    if in_kev:
        return CAT_CONFIRMED
    if not in_kev and epss_percentile >= 0.80:
        return CAT_HIGH
    return CAT_STANDARD


CATEGORY_ORDER = {CAT_IMMEDIATE: 0, CAT_CONFIRMED: 1, CAT_HIGH: 2, CAT_STANDARD: 3}


def determine_action_plan(category: str) -> str:
    plans = {
        CAT_IMMEDIATE: (
            "KEV 등재 전 선제 대응 필요\n"
            "24~72시간 내 영향도 확인\n"
            "임시 차단, WAF rule, 접근제어 적용 검토\n"
            "KEV 등재 여부 지속 모니터링"
        ),
        CAT_CONFIRMED: (
            "긴급 패치 또는 서비스 격리\n"
            "침해 여부 조사\n"
            "로그 분석 및 계정/토큰 재발급 검토"
        ),
        CAT_HIGH: (
            "3~7일 내 패치 계획 수립\n"
            "외부 노출 여부 재검토\n"
            "임시 완화 조치 적용"
        ),
        CAT_STANDARD: (
            "정기 점검 항목으로 관리\n"
            "EPSS percentile 상승 또는 KEV 등재 시 재평가"
        ),
    }
    return plans.get(category, "")


def build_reason(epss_percentile, in_kev, critical_asset_flag,
                 auth_or_rce_flag, internet_exposed_flag,
                 kev_gap_bonus, cvss_score=0.0) -> str:
    reasons = []
    if kev_gap_bonus > 0:
        reasons.append("High EPSS but not yet listed in KEV")
        reasons.append("Possible KEV delay risk")
    if in_kev:
        reasons.append("Already listed in KEV")
    if critical_asset_flag:
        reasons.append("Critical financial asset")
    if internet_exposed_flag:
        reasons.append("Internet-exposed service")
    if auth_or_rce_flag:
        reasons.append("Authentication bypass or RCE pattern")
    if epss_percentile >= 0.90:
        reasons.append("High exploitation probability based on EPSS")
    if cvss_score >= 9.0:
        reasons.append("High CVSS severity")
    if not reasons:
        reasons.append("Monitored for potential escalation")
    return " | ".join(reasons)


# ──────────────────────────────────────────────
# OpenSearch 질의
# ──────────────────────────────────────────────

def build_opensearch_client():
    if not OPENSEARCH_AVAILABLE:
        return None
    try:
        client = OpenSearch(
            hosts=[{"host": OPENSEARCH_CONFIG["host"], "port": OPENSEARCH_CONFIG["port"]}],
            http_auth=(OPENSEARCH_CONFIG["username"], OPENSEARCH_CONFIG["password"]),
            use_ssl=True,
            verify_certs=False,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
        )
        # 연결 확인
        client.info()
        return client
    except Exception as e:
        print(f"[!] OpenSearch 연결 실패: {e}")
        return None


def extract_keywords_from_text(text: str) -> list:
    """임의 문자열에서 검색용 키워드 추출 (버전 숫자 제외)"""
    clean = re.sub(r"[:\-_/]", " ", str(text)).lower()
    words = [w for w in clean.split() if len(w) > 1 and not re.match(r"^[0-9.]+$", w)]
    return words


def extract_keywords_from_cpe23(cpe_23: str) -> list:
    """cpe_23에서 vendor/product 핵심 키워드 우선 추출
    예: 'cpe:2.3:a:apache:log4j-core:2.14.1:...' → ['apache', 'log4j', 'core']
    """
    if not cpe_23:
        return []
    # cpe:2.3:a: 또는 cpe:/a: 접두사 제거 후 파트 분리
    stripped = re.sub(r"^cpe:/?(?:2\.3:)?[aoh]:", "", cpe_23.lower())
    parts = stripped.split(":")
    # vendor(0), product(1) 파트만 사용 (version 이후는 제외)
    core_parts = parts[:2] if len(parts) >= 2 else parts
    keywords = []
    for part in core_parts:
        # 하이픈/언더스코어로 분리된 토큰도 개별 추가
        sub = re.sub(r"[_\-]", " ", part).split()
        keywords.extend([w for w in sub if len(w) > 1 and not re.match(r"^[0-9.]+$", w)])
    return list(set(keywords))


def query_cves_for_asset(client, technology: str, cpe_23: str,
                         web_title: str, index_name: str) -> list:
    """OpenSearch에서 technology / cpe_23 / web_title을 모두 활용해 CVE 조회.

    우선순위:
      1) cpe_23의 vendor/product 키워드 (가장 정밀)
      2) technology 키워드
      3) web_title 키워드 (보조)
    세 소스의 키워드를 합집합으로 구성해 OR 질의를 전송합니다.
    """
    if client is None:
        return []

    # 키워드 수집
    cpe_kws  = extract_keywords_from_cpe23(cpe_23)
    tech_kws = extract_keywords_from_text(technology)
    title_kws = extract_keywords_from_text(web_title) if web_title else []

    # log4j 보완
    combined = list(set(cpe_kws + tech_kws + title_kws))
    if "log4j" in combined and "apache" not in combined:
        combined.append("apache")

    if not combined:
        return []

    # cpe_23 키워드를 앞에 배치해 검색 정밀도 향상
    ordered = cpe_kws + [k for k in (tech_kws + title_kws) if k not in cpe_kws]
    ordered = list(dict.fromkeys(ordered))   # 중복 제거, 순서 유지

    keyword_qs = " OR ".join([f"cpes:*{k}*" for k in ordered])
    query = {
        "query": {
            "query_string": {
                "query": keyword_qs,
                "analyze_wildcard": True,
            }
        },
        "size": 200,
    }

    label = (cpe_23 or technology)[:40]
    try:
        res = client.search(body=query, index=index_name)
        hits = res.get("hits", {}).get("hits", [])
        results = []
        for hit in hits:
            src = hit.get("_source")
            if isinstance(src, dict) and src.get("cve_id"):
                results.append(src)
        return results
    except Exception as e:
        print(f"   [!] OpenSearch 질의 오류 ({label}): {e}")
        return []


# ──────────────────────────────────────────────
# 자산 유형 추론
# ──────────────────────────────────────────────

ASSET_TYPE_MAP = {
    "wso2":       "API Gateway",
    "oracle":     "IAM / Identity Management",
    "log4j":      "Core Framework (Log4j)",
    "struts":     "Core Framework (Struts)",
    "goanywhere": "Managed File Transfer",
    "moveit":     "Managed File Transfer",
    "pan-os":     "Network Firewall / VPN",
    "paloalto":   "Network Firewall / VPN",
    "netscaler":  "ADC",
    "citrix":     "ADC",
    "fortios":    "Network Firewall",
    "fortinet":   "Network Firewall",
    "f5":         "ADC / Load Balancer",
    "big-ip":     "ADC / Load Balancer",
}

def infer_asset_type(technology: str) -> str:
    t = technology.lower()
    for k, v in ASSET_TYPE_MAP.items():
        if k in t:
            return v
    return "Web Service"


# ──────────────────────────────────────────────
# 메인 분석 로직
# ──────────────────────────────────────────────

def load_scan_report() -> dict:
    candidates = [
        "scan_report_simulated_real.json",
        os.path.join(os.path.dirname(__file__), "../../scan_report_simulated_real.json"),
    ]
    for path in candidates:
        norm = os.path.normpath(path)
        if os.path.exists(norm):
            with open(norm, "r", encoding="utf-8") as f:
                print(f"[*] 스캔 리포트 로드: {norm}")
                return json.load(f)
    print("[!] scan_report_simulated_real.json 파일을 찾을 수 없습니다.")
    sys.exit(1)


def run_analysis():
    print("=" * 65)
    print("  EPSS-KEV Gap Based Early Warning Model")
    print("  EPSS-KEV 갭 기반 금융권 선제 대응 모델")
    print("=" * 65)

    scan_data = load_scan_report()
    client    = build_opensearch_client()
    index     = OPENSEARCH_CONFIG["index_name"]

    all_results = []
    seen_cve_per_tech = {}   # (technology, cve_id) 중복 방지

    for host_data in scan_data.get("subdomains", []):
        host = host_data.get("host", "unknown")
        for port_info in host_data.get("open_ports", []):
            port    = port_info.get("port", 0)
            service = port_info.get("service", "")
            cpe_23  = port_info.get("cpe_23", "")
            web_title = port_info.get("web_title", "")
            techs   = port_info.get("technologies", [])

            internet_exposed = compute_internet_exposed_flag(service, port)

            for tech in techs:
                # 1) JSON에 asset_type 필드가 있으면 우선 사용, 없으면 기술 스택에서 추론
                asset_type = host_data.get("asset_type") or infer_asset_type(tech)
                critical_asset = compute_critical_asset_flag(
                    asset_type=asset_type,
                    technology=tech,
                    web_title=web_title,
                    cpe_23=cpe_23,
                )

                print(f"\n[>] {host}:{port} | {tech} | Critical={critical_asset}")
                # 2) technology + cpe_23 + web_title 통합 질의
                cve_list = query_cves_for_asset(client, tech, cpe_23, web_title, index)

                if not cve_list:
                    print(f"   [-] 매칭 CVE 없음 (OpenSearch 연결 여부 확인 필요)")
                    continue

                print(f"   [+] {len(cve_list)}개 CVE 후보 발견")

                for cve_src in cve_list:
                    cve_id = cve_src.get("cve_id", "")
                    dedup_key = (tech, cve_id)
                    if dedup_key in seen_cve_per_tech:
                        continue
                    seen_cve_per_tech[dedup_key] = True

                    cvss_score      = float(cve_src.get("cvss_score", 0.0))
                    epss_percentile = float(cve_src.get("epss_percentile", 0.0))
                    in_kev          = bool(cve_src.get("in_kev", False))
                    epss_score      = float(cve_src.get("epss_score", 0.0))
                    cpes_raw        = cve_src.get("cpes", [])
                    cpes_str        = ", ".join(cpes_raw) if isinstance(cpes_raw, list) else str(cpes_raw)

                    # Auth/RCE 판단 (DB에 description/cwe 필드가 있으면 사용)
                    description = cve_src.get("description", "")
                    cwe_ids     = cve_src.get("cwe_ids", "")
                    vuln_type   = cve_src.get("vuln_type", "")
                    auth_or_rce = compute_auth_rce_flag(vuln_type, description, str(cwe_ids))

                    # 3) Ransomware flag
                    ransomware_raw  = cve_src.get("knownRansomwareCampaignUse", False)
                    ransomware_flag = compute_ransomware_flag(ransomware_raw)

                    # 점수 계산
                    cvss_norm, base_score, kev_gap_bonus, financial_score, final_score = compute_scores(
                        cvss_score, epss_percentile, in_kev,
                        critical_asset, auth_or_rce, internet_exposed, ransomware_flag
                    )

                    category    = determine_priority_category(epss_percentile, in_kev, critical_asset)
                    action_plan = determine_action_plan(category)
                    reason      = build_reason(epss_percentile, in_kev, critical_asset,
                                               auth_or_rce, internet_exposed,
                                               kev_gap_bonus, cvss_score)

                    all_results.append({
                        "host":                     host,
                        "asset_type":               asset_type,
                        "port":                     port,
                        "service":                  service,
                        "matched_technology":       tech,
                        "cpe_23":                   cpe_23 or cpes_str[:80],
                        "cve_id":                   cve_id,
                        "cvss_score":               cvss_score,
                        "cvss_norm":                cvss_norm,
                        "epss_percentile":          epss_percentile,
                        "in_kev":                   in_kev,
                        "knownRansomwareCampaignUse": ransomware_raw,
                        "ransomware_flag":          ransomware_flag,
                        "cwe_ids":                  str(cwe_ids),
                        "critical_asset_flag":      critical_asset,
                        "auth_or_rce_flag":         auth_or_rce,
                        "internet_exposed_flag":    internet_exposed,
                        "base_exploitability_score": base_score,
                        "kev_gap_bonus":            kev_gap_bonus,
                        "financial_impact_score":   financial_score,
                        "final_score":              final_score,
                        "priority_category":        category,
                        "action_plan":              action_plan,
                        "reason":                   reason,
                    })

    # ── 정렬 ──
    all_results.sort(
        key=lambda x: (CATEGORY_ORDER[x["priority_category"]], -x["final_score"])
    )

    # ── 통계 출력 ──
    print("\n" + "█" * 65)
    print("  📊 Priority Category 집계")
    print("█" * 65)
    from collections import Counter
    cat_counts = Counter(r["priority_category"] for r in all_results)
    for cat in [CAT_IMMEDIATE, CAT_CONFIRMED, CAT_HIGH, CAT_STANDARD]:
        print(f"  {cat:<28}: {cat_counts.get(cat, 0):>4} 건")
    print(f"  {'전체 식별 취약점':<28}: {len(all_results):>4} 건")
    print("█" * 65)

    # ── Top 30 콘솔 출력 ──
    top = all_results[:TOP_N]
    print(f"\n[*] Top {TOP_N} 결과")
    print("─" * 65)
    for i, r in enumerate(top, 1):
        kev_badge = "🔴KEV" if r["in_kev"] else "🟡   "
        gap_badge = f"+{int(r['kev_gap_bonus'])}gap" if r["kev_gap_bonus"] > 0 else "     "
        print(
            f"  {i:>2}. [{r['priority_category'][:14]:<14}] {r['cve_id']:<18} "
            f"Score={r['final_score']:>5.1f} | {kev_badge} | {gap_badge} | "
            f"EPSS={r['epss_percentile']:.2f} | {r['matched_technology'][:25]}"
        )

    # ── 파일 출력 ──
    output_csv  = "wangjinling_epss_kev_gap_result.csv"
    output_xlsx = "wangjinling_epss_kev_gap_result.xlsx"

    if PANDAS_AVAILABLE:
        df = pd.DataFrame(all_results)
        df.to_csv(output_csv, index=False, encoding="utf-8-sig")
        print(f"\n[*] CSV 저장 완료: {output_csv}")

        if OPENPYXL_AVAILABLE:
            with pd.ExcelWriter(output_xlsx, engine="openpyxl") as writer:
                df.to_excel(writer, index=False, sheet_name="EPSS_KEV_Gap_Result")
                ws = writer.sheets["EPSS_KEV_Gap_Result"]
                # 컬럼 너비 자동 조정
                for col in ws.columns:
                    max_len = max((len(str(cell.value)) for cell in col if cell.value), default=10)
                    ws.column_dimensions[col[0].column_letter].width = min(max_len + 2, 50)
            print(f"[*] XLSX 저장 완료: {output_xlsx}")
        else:
            print("[!] openpyxl 미설치 → XLSX 생략")
    else:
        # pandas 없이 직접 CSV 쓰기
        import csv
        if all_results:
            with open(output_csv, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
                writer.writeheader()
                writer.writerows(all_results)
            print(f"\n[*] CSV 저장 완료 (pandas 없이): {output_csv}")

    print("\n[*] 분석 완료.")


if __name__ == "__main__":
    run_analysis()
