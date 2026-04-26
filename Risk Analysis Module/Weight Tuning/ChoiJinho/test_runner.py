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


# [개선 3] 자산 키워드에 따른 자동 가중치 할당 함수
def get_automatic_asset_weight(host):
    host_lower = host.lower()
    if any(kw in host_lower for kw in ['iam', 'vpn', 'gw', 'auth']):
        return 1.5  # 인증 및 관문 자산 (최우선)
    elif any(kw in host_lower for kw in ['mft', 'db', 'core', 'bank']):
        return 1.3  # 데이터 및 코어 업무 자산 (고중요)
    elif any(kw in host_lower for kw in ['test', 'dev', 'sandbox']):
        return 0.7  # 개발 및 테스트 환경 (낮음)
    return 1.0      # 일반 자산

def calculate_advanced_financial_risk(cvss_score, epss_percentile, in_kev, 
                                      cwe_ids=None, known_ransomware=False, 
                                      port=0, cpe_string="", asset_weight=1.0):
    if cwe_ids is None:
        cwe_ids = []

    # 기본 점수 계산 (CVSS 0.3 + EPSS 0.3 + KEV 0.4)
    kev_score = 10.0 if in_kev else 0.0
    epss_score_scaled = epss_percentile * 10.0
    raw_risk = (cvss_score * 0.3) + (epss_score_scaled * 0.3) + (kev_score * 0.4)
    
    # 가중치(Multiplier) 계산
    multiplier = 1.0

    # ① 인증 우회 계열 (CWE-287, 306) -> x1.5
    auth_bypass_cwes = {"CWE-287", "CWE-306"}
    if any(cwe in auth_bypass_cwes for cwe in cwe_ids):
        multiplier *= 1.5

    # ② 랜섬웨어 캠페인 사용 이력 -> x1.3
    if known_ransomware:
        multiplier *= 1.3

    # ③ 웹 서비스 노출 (포트 + CPE) -> x1.2
    web_ports = {80, 443, 8080, 8443}
    web_server_keywords = ['http_server', 'nginx', 'iis', 'tomcat']
    if port in web_ports and any(kw in cpe_string.lower() for kw in web_server_keywords):
        multiplier *= 1.2

    # [개선 4] DB 서비스 민감도 가중치 추가 -> x1.3
    # 금융권 핵심 데이터가 저장된 포트(MSSQL, Oracle, MySQL 등) 탐지 시 증폭
    db_ports = {1433, 1521, 3306, 5432, 1522}
    if port in db_ports:
        multiplier *= 1.3

    # ④ 공급망 컴포넌트 (오픈소스 Vendor) -> x1.2
    opensource_vendors = {"apache", "log4j", "openssl", "spring", "nginx", "struts"}
    cpe_parts = cpe_string.split(':')
    vendor = cpe_parts[3].lower() if len(cpe_parts) >= 4 else ""
    if vendor in opensource_vendors:
        multiplier *= 1.2

    # 최종 리스크 산출 (자산 가중치 적용)
    total_risk = raw_risk * multiplier * asset_weight

    # KEV/Ransomware 최소 보장 점수(Floor)
    if known_ransomware:
        total_risk = max(9.5, total_risk)
    elif in_kev:
        total_risk = max(8.5, total_risk)

    return total_risk # [개선 1] 정렬을 위해 10.0 캡핑 전 원본 점수 반환

def calculate_optimized_financial_risk(cvss_score, epss_percentile, in_kev, cwe_ids, cpe_string, known_ransomware, port=0, asset_weight=1.0):
    """
    [고도화 버전] 점수 포화를 방지하고 변별력을 극대화한 리스크 산출 로직
    """
    if cwe_ids is None: cwe_ids = []
    cpe_lower = cpe_string.lower()

    # 1. 머신러닝 최적화 가중치 (이전 도출 값)
    W_CVSS, W_EPSS, W_KEV = 0.150, 0.450, 0.400
    M_AUTH, M_RCE = 2.0, 2.0

    # 2. Raw Score 계산 (0~10점 사이)
    kev_score = 10.0 if in_kev else 0.0
    base_risk = (cvss_score * W_CVSS) + (epss_percentile * 10.0 * W_EPSS) + (kev_score * W_KEV)
    
    # 3. 증폭 배수 계산 (Multiplier)
    multiplier = 1.0
    if any(cwe in ["CWE-287", "CWE-306"] for cwe in cwe_ids): multiplier *= M_AUTH
    elif any(cwe in ["CWE-77", "CWE-78", "CWE-89", "CWE-502", "CWE-125"] for cwe in cwe_ids): multiplier *= M_RCE

    # 자산 및 환경 가중치 결합 (최대 약 3.0~4.0배까지 증폭 가능)
    if any(asset in cpe_lower for asset in ['vpn', 'firewall', 'gateway', 'mft']): multiplier *= 1.4
    if port in {80, 443, 8080}: multiplier *= 1.2
    if known_ransomware: multiplier *= 1.3

    # 4. [핵심 개선] 비선형 스케일링 (Saturation Curve)
    # 단순히 10점에서 자르는 대신, 점수가 높을수록 10점에 '수렴'하게 만듦
    # 이론적 최대치(약 30~40점)가 들어와야 비로소 10점에 도달함
    raw_total = base_risk * multiplier * asset_weight
    
    # 수식: 10 * (score / (score + 5)) -> 5점일 때 5점, 15점일 때 7.5점, 45점일 때 9점...
    # 이 수식은 점수 간의 '상대적 차이'를 상단에서도 유지해줍니다.
    refined_score = 10 * (raw_total / (raw_total + 3.5)) # 3.5는 변별력 조절 상수
    
    # 5. [수정] 강제 하한선 제거 (변별력을 위해 삭제)
    # 대신 KEV 보너스 점수만 살짝 부여 (0.5점)
    if in_kev:
        refined_score = min(10.0, refined_score + 0.5)

    return refined_score

def calculate_risk_score(cvss_score, epss_percentile, in_kev, asset_weight=1.0):
    """
    CVSS, EPSS_percentile, KEV_flag, Asset_Weight를 기반으로 리스크 점수를 계산합니다.
    Risk = min(10, (CVSS * 0.4 + EPSS_percentile * 0.3 + KEV_flag * 0.3) * Asset_Weight)
    """
    # KEV 등재 여부 및 EPSS Percentile을 10점 만점 스케일로 변환
    kev_flag_score = 10.0 if in_kev else 0.0
    epss_score_scaled = epss_percentile * 10.0

    # 수식 적용
    raw_risk = (
        (cvss_score * 0.4) + 
        (epss_score_scaled * 0.3) + 
        (kev_flag_score * 0.3)
    ) * asset_weight

    return round(min(10.0, raw_risk), 2)


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

def extract_vendor_product(full_cpe):
    """DB 검색 시 버전 불일치로 누락되는 것을 막기 위해 vendor:product까지만 추출"""
    if not full_cpe:
        return ""
    core = re.sub(r'^cpe:/?(?:2\.3:)?(?:a|o|h):', '', full_cpe)
    parts = core.split(':')
    if len(parts) >= 2:
        return f"{parts[0]}:{parts[1]}"
    return core.split(':*')[0]

# 🎯 [수정됨] port 파라미터 추가
# ---------------------------------------------------------
# [Main Function] 취약점 검색 및 우선순위 정렬 (생략 없음)
# ---------------------------------------------------------
def find_threat_prioritized_vulns(host, scanned_cpe, port=0):
    """
    [최종 통합 버전]
    CPE 매칭률 60% 이상인 취약점을 찾아 금융 리스크 점수를 산출하고,
    KEV 여부와 리스크 점수를 기준으로 정렬합니다.
    """
    if not scanned_cpe:
        return []

    # 1. 자산 가중치 자동 할당
    asset_weight = get_automatic_asset_weight(host)
    
    # 2. 검색을 위한 벤더:제품 키워드 추출
    vp_keyword = extract_vendor_product(scanned_cpe)
    if not vp_keyword:
        return []

    # 3. OpenSearch 1차 검색 쿼리 (충분한 노이즈 데이터 확보를 위해 size 확대)
    search_query = {
        "query": {
            "wildcard": {"cpes": {"value": f"*{vp_keyword}*"}}
        },
        "size": 1000 
    }

    try:
        response = client.search(body=search_query, index=INDEX_NAME)
        hits = response['hits']['hits']
    except Exception as e:
        print(f"[!] OpenSearch 검색 에러: {e}")
        return []

    results = []
    
    # 4. 2차 정밀 분석 및 리스크 산출 루프
    for hit in hits:
        source = hit['_source']
        
        # 데이터 추출
        cve_id = source.get('cve_id')
        cvss = source.get('cvss_score', 0.0)
        in_kev = source.get('in_kev', False)
        epss_score = source.get('epss_score', 0.0)
        percentile = source.get('epss_percentile', 0.0)
        nvd_cpes = source.get('cpes', [])
        cwe_ids = source.get('cwe_ids', [])
        known_ransomware = source.get('knownRansomwareCampaignUse', 'Unknown') == 'Known'

        # CPE 매칭 유사도 검사
        best_match_score = 0.0
        best_match_cpe = ""
        for n_cpe in nvd_cpes:
            score = check_cpe_similarity(scanned_cpe, n_cpe)
            if score > best_match_score:
                best_match_score = score
                best_match_cpe = n_cpe

        # 유사도 60% 이상인 경우에만 결과에 포함
        if best_match_score >= 0.6:
            # [핵심] 최적화된 리스크 산출 로직 호출
            # calculate_optimized_financial_risk 함수 내부에 비선형 스케일링이 포함되어야 함
            risk_score = calculate_optimized_financial_risk(
                cvss_score=cvss, 
                epss_percentile=percentile, 
                in_kev=in_kev,
                cwe_ids=cwe_ids,
                known_ransomware=known_ransomware,
                port=port, 
                cpe_string=best_match_cpe, 
                asset_weight=asset_weight
            )
            
            # 최종 정렬 및 출력용 데이터 구성
            results.append({
                "cve_id": cve_id,
                "risk_score": round(risk_score, 2), # 스케일링된 0~10점 사이의 값
                "in_kev": in_kev,                   # 정렬 1순위용
                "similarity": round(best_match_score, 2),
                "cvss_score": cvss,
                "epss": epss_score,
                "percentile": percentile,
                "cpe": best_match_cpe
            })

    # 5. [정렬 로직] 
    # 1순위: KEV 여부 (False보다 True가 먼저)
    # 2순위: 계산된 리스크 점수 (risk_score)
    # 3순위: 유사도 (similarity)
    results = sorted(
        results, 
        key=lambda x: (x['in_kev'], x['risk_score'], x['similarity']), 
        reverse=True
    )
    
    return results

if __name__ == "__main__":
    # 분석할 타겟 리포트 JSON 파일 경로 (실제 파일명에 맞게 수정)
    report_file = "scan_report_vulnweb.com.json"

    try:
        with open(report_file, "r", encoding="utf-8") as f:
            scan_data = json.load(f)

        print(f"[*] 🚀 {scan_data.get('root_domain', 'Unknown')} 위협 기반 + 정밀 매칭 취약점 분석 시작...\n")

        for host_data in scan_data.get("subdomains", []):
            host = host_data.get("host") # <-- 여기서 host 이름을 가져옴
            ports_info = host_data.get("open_ports", [])

            if not ports_info:
                continue

            print(f"=======================================")
            print(f"🎯 Target: {host}")
            print(f"=======================================")

            for port_info in ports_info:
                port = port_info.get("port") # <-- 여기서 port 번호를 가져옴
                service = port_info.get("service")
                cpe_23 = port_info.get("cpe_23")
                technologies = port_info.get("technologies", [])

                search_targets = set()

                # CPE 및 기술 스택 키워드 추출 로직
                if cpe_23:
                    core = extract_vendor_product(cpe_23)
                    if core: search_targets.add(cpe_23)

                if technologies:
                    # 기술 스택이 있을 경우 기존 tech_to_cpe_keyword 등의 변환 로직이 있다면 적용
                    pass 

                print(f"\n[Port {port}] Service: {service}")

                if search_targets:
                    for target_cpe in search_targets:
                        print(f"  🔍 분석 키워드: {target_cpe}")
                        
                        # 🎯 [핵심 수정 부분] host, target_cpe, port 3가지를 모두 넘겨줍니다!
                        vulns = find_threat_prioritized_vulns(host=host, scanned_cpe=target_cpe, port=port)

                        if vulns:
                            print(f"  🚨 발견된 유효 취약점 ({len(vulns)}건 중 상위 {min(len(vulns), 20)}건):")
                            for v in vulns[:20]:
                                badge = "[CVE in KEV]" if v['in_kev'] else "[Warning]"
                                epss_pct = v['epss'] * 100
                                # 화면 출력은 risk_score(10.0 만점 캡핑된 값) 사용
                                print(
                                    f"     - {badge} {v['cve_id']} (Risk: {v['risk_score']}) | "
                                    f"매칭률: {int(v['similarity'] * 100)}% | CVSS: {v['cvss_score']} | "
                                    f"EPSS: {epss_pct:.2f}% | CPE: {v['cpe']}" 
                                )
                        else:
                            print("  ✅ 매칭되는 주요 취약점 없음.")
                else:
                    print("  ⚠️ 버전 정보 식별 불가")

    except FileNotFoundError:
        print(f"에러: {report_file} 파일을 찾을 수 없습니다.")

