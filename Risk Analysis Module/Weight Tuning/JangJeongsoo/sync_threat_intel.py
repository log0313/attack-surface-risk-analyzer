import requests
import gzip
import csv
import io
import json
import zipfile
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
        self.kev_data = {}
        self.epss_data = {}
        self.github_pocs = set()
        self.exploitdb_pocs = set()
        self.nuclei_pocs = set()

        self.vulncheck_api_key = "vulncheck_0a2dd4cae5f79f51b183c61a7b66fd6c10a2659e6e999658f3c3edf8e29c6b0d"

    def fetch_kev(self):
        print("1/5. 최신 VulnCheck KEV 다운로드 중...")
        headers = {
            "Authorization": f"Bearer {self.vulncheck_api_key}",
            "Accept": "application/json"
        }

        try:
            url = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
            resp = requests.get(url, headers=headers, timeout=10)
            resp.raise_for_status()

            download_url = resp.json().get('data', [])[0].get('url')

            print("   - 백업 URL 확보 완료, 실제 KEV 데이터(ZIP) 다운로드 중...")
            zip_resp = requests.get(download_url, timeout=30)
            zip_resp.raise_for_status()

            with zipfile.ZipFile(io.BytesIO(zip_resp.content)) as thezip:
                json_filename = thezip.namelist()[0]
                with thezip.open(json_filename) as f:
                    kev_json = json.load(f)

            kev_items = kev_json if isinstance(kev_json, list) else kev_json.get('data', [])

            for item in kev_items:
                is_ransomware = item.get('knownRansomwareCampaignUse') == "Known"
                has_poc = len(item.get('vulncheck_xdb', [])) > 0

                # cve 필드는 ["CVE-2021-44228"] 형태의 배열
                for cve_id in item.get('cve', []):
                    self.kev_data[cve_id] = {
                        "is_ransomware": is_ransomware,
                        "has_poc": has_poc
                    }

            print(f"VulnCheck KEV 다운로드 완료 ({len(self.kev_data):,}건)")

        except Exception as e:
            print(f"[!] VulnCheck KEV 다운로드 중 오류 발생: {e}")

    def fetch_epss(self):
        print("2/5. 최신 FIRST EPSS 다운로드 중...")
        url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
        resp = requests.get(url, timeout=30)
        with gzip.open(io.BytesIO(resp.content), 'rt', encoding='utf-8') as f:
            next(f)
            next(csv.reader(f))  # 주석, 헤더 스킵
            for row in csv.reader(f):
                self.epss_data[row[0]] = {"epss": float(row[1]), "pct": float(row[2])}
        print(f"EPSS 다운로드 완료 ({len(self.epss_data):,}건)")

    def fetch_github_pocs(self):
        print("3/5. 최신 GitHub PoC 데이터베이스(nomi-sec) 동기화 중...")
        # GitHub Tree API를 사용하여 레포지토리의 모든 파일 트리(경로)를 한 번에 가져옵니다.
        url = "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/git/trees/master?recursive=1"
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            tree_data = resp.json()

            # 경로가 '20'으로 시작(연도 폴더)하고 '.json'으로 끝나는 파일명에서 CVE 추출
            for item in tree_data.get('tree', []):
                path = item.get('path', '')
                if path.startswith('20') and path.endswith('.json'):
                    # 예: '2021/CVE-2021-44228.json' -> 'CVE-2021-44228'
                    cve_id = path.split('/')[-1].replace('.json', '')
                    self.github_pocs.add(cve_id)

            print(f"GitHub PoC 동기화 완료 ({len(self.github_pocs):,}건의 CVE 확보)")
        except Exception as e:
            print(f"[!] GitHub PoC 동기화 중 오류 발생: {e}")

    def fetch_exploitdb_pocs(self):
        print("4/5. 최신 Exploit-DB 데이터베이스 다운로드 중...")
        url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()

            import re
            cves_found = re.findall(r"CVE-\d{4}-\d{4,7}", resp.text, re.IGNORECASE)

            # 대문자로 통일하고 중복 제거
            self.exploitdb_pocs = set([cve.upper() for cve in cves_found])

            print(f"Exploit-DB 동기화 완료 ({len(self.exploitdb_pocs):,}건의 CVE 확보)")
        except Exception as e:
            print(f"[!] Exploit-DB 동기화 중 오류 발생: {e}")

    def fetch_nuclei_pocs(self):
        print("5/5. 최신 Nuclei Templates(ProjectDiscovery) 동기화 중...")
        # GitHub Tree API 활용 (http/cves/ 등 특정 경로에 모여있음)
        url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            tree_data = resp.json()

            for item in tree_data.get('tree', []):
                path = item.get('path', '')
                # CVE 번호가 포함된 YAML 파일만 쏙쏙 추출
                if "CVE-" in path and path.endswith('.yaml'):
                    # 파일명에서 정규식이나 문자열 파싱으로 CVE만 추출
                    # 예: "http/cves/2021/CVE-2021-44228.yaml"
                    cve_part = path.split('/')[-1].replace('.yaml', '')
                    if cve_part.startswith("CVE-"):
                        self.nuclei_pocs.add(cve_part)

            print(f"Nuclei Templates 동기화 완료 ({len(self.nuclei_pocs):,}건의 CVE 확보)")
        except Exception as e:
            print(f"[!] Nuclei 동기화 중 오류 발생: {e}")

    def sync_to_db(self):
        print("DB에 위협 인텔리전스(KEV/EPSS/PoC) 부분 업데이트 진행 중...")
        actions = []

        all_target_cves = (
            set(self.epss_data.keys())
            .union(self.kev_data.keys())
            .union(self.github_pocs)
            .union(self.exploitdb_pocs)
            .union(self.nuclei_pocs)
        )

        for cve_id in all_target_cves:
            epss_info = self.epss_data.get(cve_id, {"epss": 0.0, "pct": 0.0})
            kev_info = self.kev_data.get(cve_id, {"is_ransomware": False, "has_poc": False})

            in_kev = cve_id in self.kev_data

            # 4군데 소스(kev, github, exploit-db, nuclei templates) 중 어디서라도 PoC가 발견되면 True
            has_poc_external = (
                    kev_info["has_poc"] or
                    (cve_id in self.github_pocs) or
                    (cve_id in self.exploitdb_pocs) or
                    (cve_id in self.nuclei_pocs)
            )

            # 기본적으로 업데이트할 문서 내용
            doc_update = {
                "in_kev": in_kev,
                "is_ransomware": kev_info["is_ransomware"],
                "epss_score": epss_info["epss"],
                "epss_percentile": epss_info["pct"]
            }

            # 외부 데이터에서 PoC가 '있다고(True)' 한 경우에만 업데이트 항목에 추가합니다.
            # 만약 False라면 아예 업데이트 항목에서 빼버려서, NVD가 찾은 기존 True 값을 보존합니다.
            if has_poc_external:
                doc_update["has_poc"] = True

            action = {
                "_op_type": "update",
                "_index": self.index_name,
                "_id": cve_id,
                "doc": doc_update
            }
            actions.append(action)

        success, failed = helpers.bulk(
            self.client, actions, chunk_size=2000, raise_on_error=False, yield_ok=False
        )
        print(f"업데이트 완료. {success}개의 데이터가 최신으로 반영되었습니다.")


if __name__ == "__main__":
    sync = ThreatIntelSynchronizer()
    sync.fetch_kev()
    sync.fetch_epss()
    sync.fetch_github_pocs()
    sync.fetch_exploitdb_pocs()
    sync.fetch_nuclei_pocs()
    sync.sync_to_db()
