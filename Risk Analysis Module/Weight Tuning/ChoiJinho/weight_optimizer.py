import json
import re
import random
import copy
from opensearchpy import OpenSearch
import urllib3
from urllib3.exceptions import InsecureRequestWarning

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

def extract_vendor_product(full_cpe):
    """DB 검색 시 버전 불일치 누락을 막기 위해 vendor:product 추출"""
    if not full_cpe: return ""
    core = re.sub(r'^cpe:/?(?:2\.3:)?(?:a|o|h):', '', full_cpe)
    parts = core.split(':')
    if len(parts) >= 2: return f"{parts[0]}:{parts[1]}"
    return core.split(':*')[0]

def build_dataset_from_report(report_path):
    """
    스캔 리포트를 읽어 OpenSearch에서 실제 CVE 데이터를 수집합니다.
    - 리포트의 'expected_cve' -> 타겟 (is_target=True)
    - 같이 검색된 나머지 일반 CVE들 -> 노이즈 (is_target=False)
    """
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            scan_data = json.load(f)
    except FileNotFoundError:
        print(f"[!] 에러: '{report_path}' 파일을 찾을 수 없습니다.")
        return []

    target_cves = set()
    cpe_keywords = set()

    # 1. 정답지(expected_cve)와 검색할 자산(CPE) 키워드 파싱
    for host_data in scan_data.get("subdomains", []):
        for port_info in host_data.get("open_ports", []):
            tv = port_info.get("target_vulnerability", {})
            if "expected_cve" in tv:
                target_cves.add(tv["expected_cve"])
            
            cpe_23 = port_info.get("cpe_23")
            if cpe_23:
                core = extract_vendor_product(cpe_23)
                if core: cpe_keywords.add(core)

    dataset = []
    seen_cves = set()

    print(f"[*] 🔍 리포트에서 {len(target_cves)}개의 핵심 타겟을 발견했습니다: {target_cves}")
    print(f"[*] 📥 OpenSearch에서 노이즈(일반 취약점) 데이터를 수집합니다...")

    # 2. OpenSearch에서 자산별 취약점 대량 검색 (노이즈 풀 생성)
    for vp_keyword in cpe_keywords:
        search_query = {
            "query": {"wildcard": {"cpes": {"value": f"*{vp_keyword}*"}}},
            "size": 100  # 성능을 위해 자산당 100개씩만 추출
        }
        try:
            response = client.search(body=search_query, index=INDEX_NAME)
            for hit in response['hits']['hits']:
                src = hit['_source']
                cve_id = src.get('cve_id')
                
                if cve_id in seen_cves: continue
                seen_cves.add(cve_id)
                
                dataset.append({
                    "cve_id": cve_id,
                    "cvss": src.get('cvss_score', 0.0),
                    "epss": src.get('epss_percentile', 0.0),
                    "in_kev": src.get('in_kev', False),
                    "cwe_ids": src.get('cwe_ids', []),
                    "is_target": cve_id in target_cves
                })
        except Exception as e:
            print(f"[!] DB 검색 중 에러 발생: {e}")

    # 3. 만약 검색 제한으로 타겟 CVE가 누락되었다면 강제로 채워넣음
    for t_cve in target_cves:
        if t_cve not in seen_cves:
            search_query = {"query": {"match": {"cve_id": t_cve}}}
            try:
                response = client.search(body=search_query, index=INDEX_NAME)
                if response['hits']['hits']:
                    src = response['hits']['hits'][0]['_source']
                    dataset.append({
                        "cve_id": t_cve,
                        "cvss": src.get('cvss_score', 0.0),
                        "epss": src.get('epss_percentile', 0.0),
                        "in_kev": src.get('in_kev', False),
                        "cwe_ids": src.get('cwe_ids', []),
                        "is_target": True
                    })
            except:
                pass

    target_count = sum(1 for d in dataset if d['is_target'])
    noise_count = len(dataset) - target_count
    print(f"[*] ✅ 데이터셋 구축 완료! (타겟: {target_count}개 / 노이즈: {noise_count}개)\n")
    return dataset

# -------------------------------------------------------------
# 머신러닝 최적화 (Optimization) 핵심 로직
# -------------------------------------------------------------

def calculate_risk(cve, weights):
    """주어진 가중치로 단일 취약점의 리스크를 계산"""
    cvss_weighted = cve['cvss'] * weights['w_cvss']
    epss_weighted = (cve['epss'] * 10.0) * weights['w_epss']
    kev_weighted = (10.0 if cve['in_kev'] else 0.0) * weights['w_kev']
    
    raw_risk = cvss_weighted + epss_weighted + kev_weighted
    
    multiplier = 1.0
    cwe_ids = cve.get('cwe_ids', [])
    
    if any(cwe in ["CWE-287", "CWE-306"] for cwe in cwe_ids):
        multiplier *= weights['m_auth']
    if any(cwe in ["CWE-77", "CWE-89", "CWE-502", "CWE-125"] for cwe in cwe_ids):
        multiplier *= weights['m_rce']
        
    return raw_risk * multiplier

def objective_function(weights, data):
    """
    [목적 함수] 타겟(핵심 취약점)과 노이즈(일반 취약점)의 점수 차이를 반환
    """
    target_scores = [calculate_risk(cve, weights) for cve in data if cve['is_target']]
    normal_scores = [calculate_risk(cve, weights) for cve in data if not cve['is_target']]
            
    avg_target = sum(target_scores) / len(target_scores) if target_scores else 0
    avg_normal = sum(normal_scores) / len(normal_scores) if normal_scores else 0
    
    return avg_target - avg_normal

def optimize_weights(data, iterations=10000):
    """
    학습률 감소(Learning Rate Decay) 및 전문가 제약 조건을 포함한 고도화된 탐색
    """
    print(f"[*] 🧠 인공지능 기반 가중치 최적화 시작 (반복 횟수: {iterations}회)...\n")
    
    # 초기 가중치 시작점
    best_weights = {
        'w_cvss': 0.33, 'w_epss': 0.33, 'w_kev': 0.34,
        'm_auth': 1.3, 'm_rce': 1.3 
    }
    best_fitness = objective_function(best_weights, data)
    
    # 초기 탐색 보폭(Step Size)
    initial_base_step = 0.05
    initial_mult_step = 0.10
    
    for i in range(1, iterations + 1):
        # 진행률에 따라 보폭을 서서히 줄여 미세 튜닝
        progress = i / iterations
        current_base_step = initial_base_step * (1.0 - progress) + 0.001
        current_mult_step = initial_mult_step * (1.0 - progress) + 0.005

        if i % 1000 == 0:
            print(f"[{i}/{iterations}] 현재 최고 점수 격차: {best_fitness:.4f}점 (보폭: {current_base_step:.4f})")
            print(f"  > CVSS: {best_weights['w_cvss']:.4f} | EPSS: {best_weights['w_epss']:.4f} | KEV: {best_weights['w_kev']:.4f}")
            print(f"  > 인증 배수: x{best_weights['m_auth']:.4f} | RCE 배수: x{best_weights['m_rce']:.4f}\n")

        new_weights = copy.deepcopy(best_weights)
        
        # 보폭을 적용하여 가중치 변경
        new_weights['w_cvss'] += random.uniform(-current_base_step, current_base_step)
        new_weights['w_epss'] += random.uniform(-current_base_step, current_base_step)
        new_weights['w_kev'] = 1.0 - (new_weights['w_cvss'] + new_weights['w_epss'])
        
        # 전문가 제약 조건 (Domain Regularization)
        if not (0.15 <= new_weights['w_cvss'] <= 0.40 and 
                0.30 <= new_weights['w_epss'] <= 0.60 and 
                0.15 <= new_weights['w_kev'] <= 0.40):
            continue
            
        # 증폭 배수 최소 1.2 보장
        new_weights['m_auth'] = max(1.2, min(2.0, new_weights['m_auth'] + random.uniform(-current_mult_step, current_mult_step)))
        new_weights['m_rce'] = max(1.2, min(2.0, new_weights['m_rce'] + random.uniform(-current_mult_step, current_mult_step)))
        
        new_fitness = objective_function(new_weights, data)
        
        # 이전보다 점수 격차가 더 벌어졌다면 업데이트
        if new_fitness > best_fitness:
            best_fitness = new_fitness
            best_weights = new_weights

    return best_weights, best_fitness

if __name__ == "__main__":
    report_file = "scan_report_vulnweb.com.json"
    
    # 1. 스캔 리포트 기반 데이터셋 생성
    dataset = build_dataset_from_report(report_file)
    
    # ==============================================================
    # 🚨 [데이터 검증 (디버깅) 구역]
    # 타겟 데이터가 정상적으로 수집되었는지, 점수가 0은 아닌지 확인합니다.
    # ==============================================================
    print("="*60)
    print("🔍 [데이터 검증] 수집된 핵심 타겟(Target) 상세 정보")
    print("="*60)
    
    target_count = 0
    for d in dataset:
        if d['is_target']:
            target_count += 1
            print(f" - CVE ID: {d['cve_id']}")
            print(f"   * CVSS: {d['cvss']} | EPSS: {d['epss']} | KEV: {d['in_kev']}")
            print(f"   * CWEs: {d['cwe_ids']}")
            print("-" * 40)
            
    if target_count == 0:
        print("[!] 타겟 데이터가 아예 수집되지 않았습니다. 리포트의 expected_cve를 확인하세요.")
    # ==============================================================
    
    elif len(dataset) < 5:
        print("[!] 충분한 데이터가 수집되지 않았습니다. 파일 경로 및 OpenSearch 연동 상태를 확인하세요.")
    else:
        # 2. 최적화 알고리즘 10000회 실행
        optimized_weights, final_fitness = optimize_weights(dataset, iterations=10000)
        
        # 3. 최종 도출된 결과 출력
        print("="*60)
        print("🏆 [실제 스캔 데이터 기반] 최종 최적화 가중치 탐색 완료 🏆")
        print("="*60)
        print(f" [Base Score 비율]")
        print(f"  - CVSS 가중치 : {optimized_weights['w_cvss']:.3f}")
        print(f"  - EPSS 가중치 : {optimized_weights['w_epss']:.3f}")
        print(f"  - KEV  가중치 : {optimized_weights['w_kev']:.3f}")
        print(f" [도메인 특화 증폭 배수]")
        print(f"  - 인증 우회(CWE-287/306) 증폭률 : x{optimized_weights['m_auth']:.2f}")
        print(f"  - 핵심 탈취(CWE-502/125 등) 증폭률: x{optimized_weights['m_rce']:.2f}")
        print(f" \n 📊 타겟과 노이즈의 최종 점수 격차 : {final_fitness:.2f}점")
        print("="*60)
        print("💡 제안: 위 도출된 수치를 test_runner.py의 calculate_optimized_financial_risk 함수에 적용하세요.")