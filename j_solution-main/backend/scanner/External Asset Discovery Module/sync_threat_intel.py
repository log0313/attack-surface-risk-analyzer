import requests
import gzip
import csv
import io
from opensearchpy import OpenSearch, helpers
import urllib3

# SSL 경고 무시 (로컬 환경용)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ThreatIntelSynchronizer:
    def __init__(self):
        self.client = OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            http_auth=('admin', 'VulnScanner_2026!@#'),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )
        self.index_name = "vulnerability_cve"
        self.kev_data = set()
        self.epss_data = {}

    def fetch_kev(self):
        print("1/2. 최신 CISA KEV 다운로드 중...")
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        resp = requests.get(url, timeout=10)
        for item in resp.json().get('vulnerabilities', []):
            self.kev_data.add(item['cveID'])
        print(f"KEV 다운로드 완료 ({len(self.kev_data)}건)")

    def fetch_epss(self):
        print("2/2. 최신 FIRST EPSS 다운로드 중...")
        url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
        resp = requests.get(url, timeout=30)
        with gzip.open(io.BytesIO(resp.content), 'rt', encoding='utf-8') as f:
            next(f);
            next(csv.reader(f))  # 주석, 헤더 스킵
            for row in csv.reader(f):
                self.epss_data[row[0]] = {"epss": float(row[1]), "pct": float(row[2])}
        print(f"EPSS 다운로드 완료 ({len(self.epss_data):,}건)")

    def sync_to_db(self):
        print("DB에 위협 인텔리전스(KEV/EPSS) 부분 업데이트(Partial Update) 진행 중...")
        actions = []

        # EPSS 데이터의 Key(CVE ID)와 KEV 데이터(Set)를 합집합(Union) 처리
        # 이렇게 해야 EPSS에는 없지만 KEV에는 있는 케이스(EPSS에 등재되기 전에 악용되는 경우)도 대응 가능
        all_target_cves = set(self.epss_data.keys()).union(self.kev_data)

        for cve_id in all_target_cves:
            # EPSS에 데이터가 없으면 기본값(0.0)을 부여
            epss_info = self.epss_data.get(cve_id, {"epss": 0.0, "pct": 0.0})
            in_kev = cve_id in self.kev_data

            action = {
                "_op_type": "update",
                "_index": self.index_name,
                "_id": cve_id,
                "doc": {
                    "in_kev": in_kev,
                    "epss_score": epss_info["epss"],
                    "epss_percentile": epss_info["pct"]
                }
            }
            actions.append(action)

        success, failed = helpers.bulk(
            self.client, actions, chunk_size=2000, raise_on_error=False, yield_ok=False
        )
        print(f"KEV/EPSS 업데이트 완료. {success}개의 데이터가 최신으로 업데이트되었습니다.")


if __name__ == "__main__":
    sync = ThreatIntelSynchronizer()
    sync.fetch_kev()
    sync.fetch_epss()
    sync.sync_to_db()
