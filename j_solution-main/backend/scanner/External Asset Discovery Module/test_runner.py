import json
import re
from cpe_matcher import check_cpe_similarity
from opensearchpy import OpenSearch
from urllib3.exceptions import InsecureRequestWarning
import urllib3

# SSL 경고 무시
urllib3.disable_warnings(InsecureRequestWarning)

# OpenSearch 클라이언트 설정
client = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_auth=('admin', 'VulnScanner_2026!@#'),
    use_ssl=True,
    verify_certs=False,
    ssl_assert_hostname=False,
    ssl_show_warn=False,
)
INDEX_NAME = 'vulnerability_cve'


def extract_core_cpe(full_cpe):
    """핵심 키워드 추출 브릿지 함수"""
    if not full_cpe:
        return ""
    core = re.sub(r'^cpe:/?(?:2\.3:)?(?:a|o|h):', '', full_cpe)
    core = core.split(':*')[0]
    return core.strip()


def tech_to_cpe_keyword(tech_string):
    """HTTPX 기술 스택을 OpenSearch 검색용 뼈대 CPE로 변환"""
    if ":" not in tech_string:
        return ""
    parts = tech_string.split(":")
    name = parts[0].lower()
    version = parts[1]

    if "apache" in name:
        return f"apache:http_server:{version}"
    elif "php" in name:
        return f"php:php:{version}"
    elif "iis" in name:
        return f"microsoft:internet_information_services:{version}"
    else:
        name_clean = name.replace(" ", "_")
        return f"{name_clean}:{name_clean}:{version}"


def find_threat_prioritized_vulns(scanned_cpe):
    """[핵심] CPE 매칭률 60% 이상인 것들을 찾아 KEV/EPSS 위협 순으로 정렬합니다."""
    if not scanned_cpe:
        return []

    core_keyword = extract_core_cpe(scanned_cpe)
    if not core_keyword:
        return []

    # 1. OpenSearch 1차 검색
    search_query = {
        "query": {
            "wildcard": {"cpes": {"value": f"*{core_keyword}*"}}
        },
        "size": 100
    }

    try:
        response = client.search(body=search_query, index=INDEX_NAME)
        hits = response['hits']['hits']
    except Exception as e:
        print(f"[!] OpenSearch 검색 에러: {e}")
        return []

    results = []
    # 2. cpe_matcher를 활용한 정밀 분석
    for hit in hits:
        source = hit['_source']
        cve_id = source.get('cve_id')
        cvss = source.get('cvss_score', 0.0)
        in_kev = source.get('in_kev', False)
        epss = source.get('epss_score', 0.0)
        percentile = source.get('epss_percentile', 0.0)
        nvd_cpes = source.get('cpes', [])

        best_match_score = 0.0
        best_match_cpe = ""
        for n_cpe in nvd_cpes:
            score = check_cpe_similarity(scanned_cpe, n_cpe)
            if score > best_match_score:
                best_match_score = score
                best_match_cpe = n_cpe

        # 3. 유사도 60% 이상인 유효 취약점만 수집
        if best_match_score >= 0.6:
            results.append({
                "cve_id": cve_id,
                "cvss_score": cvss,
                "in_kev": in_kev,
                "epss": epss,
                "percentile": percentile,
                "similarity": round(best_match_score, 2),
                "cpe": best_match_cpe
            })

    # 4. [정렬] 1순위: KEV, 2순위: EPSS 점수, 3순위: CVSS 점수, 4순위: 유사도
    results = sorted(results, key=lambda x: (x['in_kev'], x['epss'], x['cvss_score'], x['similarity']), reverse=True)
    return results


if __name__ == "__main__":
    report_file = "scan_report_vulnweb.com.json"

    try:
        with open(report_file, "r", encoding="utf-8") as f:
            scan_data = json.load(f)

        print(f"[*] 🚀 {scan_data['root_domain']} 위협 기반 + 정밀 매칭 취약점 분석 시작...\n")

        for host_data in scan_data.get("subdomains", []):
            host = host_data.get("host")
            ports_info = host_data.get("open_ports", [])

            if not ports_info:
                continue

            print(f"=======================================")
            print(f"🎯 Target: {host}")
            print(f"=======================================")

            for port_info in ports_info:
                port = port_info.get("port")
                service = port_info.get("service")
                cpe_23 = port_info.get("cpe_23")
                technologies = port_info.get("technologies", [])

                search_targets = set()

                # cpe_23이나 converted를 셋에 넣기 전에, 미리 '핵심 단어'로 변환해서 중복을 원천 차단합니다.
                if cpe_23:
                    core = extract_core_cpe(cpe_23)
                    if core: search_targets.add(core)

                if technologies:
                    for tech in technologies:
                        converted = tech_to_cpe_keyword(tech)
                        if converted:
                            core = extract_core_cpe(converted)
                            if core: search_targets.add(core)

                print(f"\n[Port {port}] Service: {service}")

                if search_targets:
                    for target_cpe in search_targets:
                        print(f"  🔍 분석 키워드: {target_cpe}")
                        vulns = find_threat_prioritized_vulns(target_cpe)

                        if vulns:
                            print(f"  🚨 발견된 유효 취약점 ({len(vulns)}건 중 상위 {min(len(vulns), 5)}건):")
                            for v in vulns[:5]:
                                badge = "[CVE in KEV]" if v['in_kev'] else "[Warning]"
                                epss_pct = v['epss'] * 100
                                percentile_pct = v['percentile'] * 100

                                print(
                                    f"     - {badge} {v['cve_id']} (CVSS: {v['cvss_score']}) | 매칭률: {int(v['similarity'] * 100)}% | EPSS: {epss_pct:.2f}% | CPE: {v['cpe']}" )
                        else:
                            print("  ✅ 매칭되는 주요 취약점 없음.")
                else:
                    print("  ⚠️ 버전 정보 식별 불가")

    except FileNotFoundError:
        print(f"에러: {report_file} 파일을 찾을 수 없습니다.")
