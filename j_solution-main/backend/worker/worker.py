"""
Redis 큐에서 스캔 작업을 꺼내 실행하는 Python Worker
- Next.js 대시보드에서 LPUSH된 작업을 BLPOP으로 수신
- AssetScanner로 외부 도메인 스캔
- CVE 매칭 후 scan_results 인덱스에 저장
- Redis에 작업 상태 업데이트
"""

import json
import sys
import os
import re
from datetime import datetime

import redis
from opensearchpy import OpenSearch, helpers
import urllib3

# 경로 추가
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "External Asset Discovery Module"))
from AssetScanner import IntegratedScanner

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── 설정 ──────────────────────────────────────────────
REDIS_HOST  = "localhost"
REDIS_PORT  = 6400
QUEUE_NAME  = "scan_jobs"

OS_HOST     = "localhost"
OS_PORT     = 9200
OS_USER     = "admin"
OS_PASS     = "VulnScanner_2026!@#"

CVE_INDEX    = "vulnerability_cve"
RESULT_INDEX = "scan_results"
ASSET_INDEX  = "scan_assets"

TARGET_CVES = [
    "CVE-2022-29464","CVE-2023-34362","CVE-2023-0669","CVE-2024-3400",
    "CVE-2023-4966","CVE-2022-40684","CVE-2022-1388","CVE-2017-5638",
    "CVE-2021-44228","CVE-2025-61757",
]
# ──────────────────────────────────────────────────────


def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def get_opensearch():
    return OpenSearch(
        hosts=[{"host": OS_HOST, "port": OS_PORT}],
        http_auth=(OS_USER, OS_PASS),
        use_ssl=True,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
    )


def update_job(r: redis.Redis, job: dict, status: str, phase: str = "", error: str = ""):
    job["status"] = status
    if phase:
        job["phase"] = phase
    if error:
        job["error"] = error
    if status in ("done", "error"):
        job["finishedAt"] = datetime.now().isoformat()
    r.set(f"job:{job['jobId']}", json.dumps(job), ex=86400)
    print(f"[job:{job['jobId']}] {status} {phase}")


def extract_keywords(tech_string):
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


def fetch_vulns(os_client, tech):
    keywords, version = extract_keywords(tech)
    if not keywords:
        return []
    keyword_qs = " OR ".join([f"cpes:*{k}*" for k in keywords])
    query = {
        "query": {
            "bool": {
                "should": [
                    {"query_string": {"query": keyword_qs, "analyze_wildcard": True}},
                    {"terms": {"cve_id": TARGET_CVES}},
                ]
            }
        }
    }
    try:
        res = os_client.search(body={**query, "size": 500}, index=CVE_INDEX)
        results = []
        for hit in res.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            cve_id  = src.get("cve_id")
            db_cpes = str(src.get("cpes", "")).lower()
            is_target   = cve_id in TARGET_CVES
            kw_match    = any(k in db_cpes for k in keywords)
            if (is_target or kw_match) and (version == "*" or version in db_cpes or "*" in db_cpes):
                results.append(src)
        return results
    except Exception as e:
        print(f"[!] CVE 검색 오류: {e}")
        return []


def ensure_asset_index(os_client):
    mapping = {
        "mappings": {
            "properties": {
                "subdomain":  {"type": "keyword"},
                "ip":         {"type": "keyword"},
                "port":       {"type": "integer"},
                "service":    {"type": "keyword"},
                "version":    {"type": "keyword"},
                "cvss":       {"type": "float"},
                "status":     {"type": "keyword"},
                "scanned_at": {"type": "date"},
                "job_id":     {"type": "keyword"},
            }
        }
    }
    if not os_client.indices.exists(index=ASSET_INDEX):
        os_client.indices.create(index=ASSET_INDEX, body=mapping)


def save_assets(os_client, scan_report: dict, job_id: str, scanned_at: str, top_cvss: dict):
    """스캔된 자산을 scan_assets 인덱스에 저장"""
    ensure_asset_index(os_client)

    # 이전 동일 job 자산 삭제
    os_client.delete_by_query(
        index=ASSET_INDEX,
        body={"query": {"term": {"job_id": job_id}}},
        conflicts="proceed",
    )

    actions = []
    for host_info in scan_report.get("subdomains", []):
        asset = host_info.get("host", "")
        ip    = host_info.get("ip", asset)
        for port_info in host_info.get("open_ports", []):
            port    = port_info.get("port", 0)
            service = port_info.get("service", "unknown")
            version = port_info.get("version", "")
            doc_id  = f"{job_id}_{asset}_{port}"
            cvss    = top_cvss.get(f"{asset}_{port}", 0)
            actions.append({
                "_index": ASSET_INDEX,
                "_id":    doc_id,
                "_source": {
                    "subdomain":  asset,
                    "ip":         ip,
                    "port":       port,
                    "service":    f"{service} {version}".strip(),
                    "version":    version,
                    "cvss":       cvss,
                    "status":     "open",
                    "scanned_at": scanned_at,
                    "job_id":     job_id,
                },
            })

    if actions:
        success, _ = helpers.bulk(os_client, actions, chunk_size=500)
        print(f"[*] {success}건 scan_assets 저장 완료")


def ensure_result_index(os_client):
    mapping = {
        "mappings": {
            "properties": {
                "asset":      {"type": "keyword"},
                "ip":         {"type": "keyword"},
                "port":       {"type": "integer"},
                "service":    {"type": "keyword"},
                "technology": {"type": "keyword"},
                "cve_id":     {"type": "keyword"},
                "cvss_score": {"type": "float"},
                "epss_score": {"type": "float"},
                "in_kev":     {"type": "boolean"},
                "scanned_at": {"type": "date"},
                "job_id":     {"type": "keyword"},
            }
        }
    }
    if not os_client.indices.exists(index=RESULT_INDEX):
        os_client.indices.create(index=RESULT_INDEX, body=mapping)


def run_scan_and_match(job: dict, r: redis.Redis, os_client):
    target   = job["target"]
    job_id   = job["jobId"]
    scanned_at = datetime.now().isoformat()

    # ── Phase 1: 스캔 ──────────────────────────────────
    update_job(r, job, "running", phase="subfinder")
    scanner = IntegratedScanner(target)
    scan_report = scanner.start_full_scan()

    # ── Phase 2: CVE 매칭 ──────────────────────────────
    update_job(r, job, "running", phase="cve_match")
    ensure_result_index(os_client)

    # 이전 동일 job 결과 삭제
    os_client.delete_by_query(
        index=RESULT_INDEX,
        body={"query": {"term": {"job_id": job_id}}},
        conflicts="proceed",
    )

    bulk_actions = []
    top_cvss: dict = {}  # {asset_port: max_cvss}

    for host_info in scan_report.get("subdomains", []):
        asset = host_info.get("host", target)
        ip    = host_info.get("ip", asset)
        for port_info in host_info.get("open_ports", []):
            port    = port_info.get("port", 0)
            service = port_info.get("service", "unknown")
            version = port_info.get("version", "")
            techs   = port_info.get("technologies", [])

            cpe = port_info.get("cpe_23", "")
            if cpe:
                techs = [cpe] + techs
            if service and service != "unknown":
                techs.append(f"{service}:{version}" if version else service)

            seen_cves = set()
            for t in techs:
                if any(ig in str(t).lower() for ig in ["ubuntu","debian","php","generic"]):
                    continue
                for v in fetch_vulns(os_client, t):
                    cve_id = v.get("cve_id")
                    if not cve_id or cve_id in seen_cves:
                        continue
                    seen_cves.add(cve_id)
                    cvss = v.get("cvss_score", 0)
                    key  = f"{asset}_{port}"
                    top_cvss[key] = max(top_cvss.get(key, 0), cvss)
                    doc_id = f"{job_id}_{asset}_{port}_{cve_id}"
                    bulk_actions.append({
                        "_index": RESULT_INDEX,
                        "_id":    doc_id,
                        "_source": {
                            "asset":      asset,
                            "ip":         ip,
                            "port":       port,
                            "service":    f"{service} {version}".strip(),
                            "technology": str(t),
                            "cve_id":     cve_id,
                            "cvss_score": cvss,
                            "epss_score": v.get("epss_score", 0),
                            "in_kev":     v.get("in_kev", False),
                            "scanned_at": scanned_at,
                            "job_id":     job_id,
                        },
                    })

    if bulk_actions:
        success, _ = helpers.bulk(os_client, bulk_actions, chunk_size=500)
        print(f"[*] {success}건 scan_results 저장 완료")
    else:
        print("[!] 매칭된 CVE 없음")

    # 자산 목록 저장
    save_assets(os_client, scan_report, job_id, scanned_at, top_cvss)

    update_job(r, job, "done")


def main():
    r         = get_redis()
    os_client = get_opensearch()
    print(f"[Worker] 시작 — Redis {REDIS_HOST}:{REDIS_PORT} / 큐: {QUEUE_NAME}")

    while True:
        print("[Worker] 작업 대기 중...")
        # BLPOP: 작업이 올 때까지 블로킹 대기 (timeout=0 = 무제한)
        result = r.blpop(QUEUE_NAME, timeout=0)
        if not result:
            continue

        _, raw = result
        try:
            job = json.loads(raw)
            print(f"[Worker] 작업 수신: {job['jobId']} — {job['target']}")
            run_scan_and_match(job, r, os_client)
        except Exception as e:
            print(f"[Worker] 오류: {e}")
            try:
                update_job(r, job, "error", error=str(e))
            except:
                pass


if __name__ == "__main__":
    main()
