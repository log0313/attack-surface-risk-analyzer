import json
from opensearchpy import OpenSearch, helpers
import urllib3

# SSL 경고 무시 (로컬 환경용)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NVDLoader:
    def __init__(self):
        # OpenSearch 연결 설정
        self.client = OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            http_auth=('admin', 'VulnScanner_2026!@#'),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )
        self.index_name = "vulnerability_cve"

    def setup_index(self):
        mapping = {
            "mappings": {
                "properties": {
                    "cve_id": {"type": "keyword"},
                    "cvss_score": {"type": "float"},
                    "severity": {"type": "keyword"},
                    "cvss_vector": {"type": "keyword"}, # AV:N, PR:N 등 분석용
                    "cpes": {"type": "keyword"},
                    "cwes": {"type": "keyword"},        # 취약점 종류 (CWE-79 등)

                    # 이하 필드들은 ThreatIntelSynchronizer(VulnCheck/EPSS)에서 업데이트할 예약 공간
                    "in_kev": {"type": "boolean"},
                    "is_ransomware": {"type": "boolean"}, #
                    "has_poc": {"type": "boolean"},       # GitHub, Exploited-DB, Nuclei templates, NVD exploited 종합
                    "epss_score": {"type": "float"},
                    "epss_percentile": {"type": "float"}
                }
            }
        }

        # 인덱스가 이미 있어도 매핑이 다르면 꼬일 수 있으므로 주의가 필요합니다.
        # 테스트 단계라면 기존 인덱스를 지우고 다시 만드는 것도 방법입니다.
        if not self.client.indices.exists(index=self.index_name):
            self.client.indices.create(index=self.index_name, body=mapping)
            print(f"새로운 '{self.index_name}' 인덱스를 생성했습니다.")
        else:
            print(f"'{self.index_name}' 인덱스가 이미 존재합니다. 스키마를 유지하며 적재를 시작합니다.")

    def _extract_cpes(self, cve_item):
        cpe_list = []
        configurations = cve_item.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get('vulnerable', True):
                        cpe23 = match.get("criteria", "")
                        if cpe23:
                            parts = cpe23.split(":")
                            if len(parts) >= 6:
                                core_cpe = f"{parts[3]}:{parts[4]}:{parts[5]}"
                                cpe_list.append(core_cpe)
        return list(set(cpe_list))

    def _extract_cwes(self, cve_item):
        cwe_list = []
        weaknesses = cve_item.get("weaknesses", [])
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwe_list.append(desc.get("value"))
        return list(set(cwe_list))

    def load_nvd_json(self, json_file):
        print(f"'{json_file}' 파일을 읽는 중...")

        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            vulnerabilities = data.get("vulnerabilities", [])
            actions = []

            print(f"파싱 시작 (총 {len(vulnerabilities):,}건)...")

            for item in vulnerabilities:
                cve_info = item.get("cve", {})
                cve_id = cve_info.get("id")
                if not cve_id: continue

                cpes = self._extract_cpes(cve_info)
                if not cpes: continue

                cwes = self._extract_cwes(cve_info)

                # CVSS v3.1/3.0 파싱 (Vector String 포함)
                cvss_score = 0.0
                severity = "UNKNOWN"
                cvss_vector = "UNKNOWN"
                metrics = cve_info.get("metrics", {})

                if "cvssMetricV31" in metrics:
                    m = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score = m.get("baseScore", 0.0)
                    severity = m.get("baseSeverity", "UNKNOWN")
                    cvss_vector = m.get("vectorString", "UNKNOWN")
                elif "cvssMetricV30" in metrics:
                    m = metrics["cvssMetricV30"][0]["cvssData"]
                    cvss_score = m.get("baseScore", 0.0)
                    severity = m.get("baseSeverity", "UNKNOWN")
                    cvss_vector = m.get("vectorString", "UNKNOWN")

                # NVD 레퍼런스에서 Exploited 태그 찾기
                has_poc_in_nvd = False
                for ref in cve_info.get("references", []):
                    if "Exploit" in ref.get("tags", []):
                        has_poc_in_nvd = True
                        break

                # Upsert 액션 구성
                action = {
                    "_index": self.index_name,
                    "_id": cve_id,
                    "_source": {
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "cvss_vector": cvss_vector,
                        "cpes": cpes,
                        "cwes": cwes,
                        "in_kev": False,
                        "is_ransomware": False,
                        "has_poc": has_poc_in_nvd,
                        "epss_score": 0.0,
                        "epss_percentile": 0.0
                    }
                }
                actions.append(action)

            if actions:
                print(f"DB 적재 시작 (Bulk Insert)...")
                success, failed = helpers.bulk(self.client, actions, chunk_size=1000)
                print(f"완료: 성공 {success}건 / 실패 {len(failed) if isinstance(failed, list) else failed}건")

        except FileNotFoundError:
            print(f"에러: {json_file} 파일을 찾을 수 없습니다.")
        except Exception as e:
            print(f"적재 중 예외 발생: {e}")


if __name__ == "__main__":
    loader = NVDLoader()

    # 기존 인덱스의 스키마가 충돌할 수 있다면,
    # OpenSearch 대시보드나 Dev Tools에서 기존 'vulnerability_cve' 인덱스를 삭제 후 실행하시길 권장합니다.
    loader.setup_index()

    TARGET_FILE = "cve_data_update.json"
    loader.load_nvd_json(TARGET_FILE)
