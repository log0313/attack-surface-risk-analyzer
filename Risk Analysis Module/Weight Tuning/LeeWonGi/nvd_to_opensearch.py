import json
from opensearchpy import OpenSearch, helpers
import urllib3

# SSL 경고 무시 (로컬 환경용)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NVDLoader:
    def __init__(self):
        # OpenSearch 연결 설정
        self.client = OpenSearch(
            hosts=[{"host": "localhost", "port": 9200}],
            http_auth=("admin", "VulnScanner_2026!@#"),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False,
        )
        self.index_name = "vulnerability_cve"

    def setup_index(self):
        # CWE ID 저장을 위해 'cwe_ids' 필드 추가 (keyword 타입의 배열 지원)
        mapping = {
            "mappings": {
                "properties": {
                    "cve_id": {"type": "keyword"},
                    "cwe_ids": {"type": "keyword"},  # 추가: CWE 분류 정보
                    "cvss_score": {"type": "float"},
                    "severity": {"type": "keyword"},
                    "cpes": {"type": "keyword"},
                    "in_kev": {"type": "boolean"},
                    "epss_score": {"type": "float"},
                    "epss_percentile": {"type": "float"},
                }
            }
        }

        if not self.client.indices.exists(index=self.index_name):
            self.client.indices.create(index=self.index_name, body=mapping)
            print(f"새로운 '{self.index_name}' 인덱스를 생성했습니다.")
        else:
            print(
                f"'{self.index_name}' 인덱스가 이미 존재합니다. 스키마를 최신화하려면 인덱스 삭제 후 재실행을 권장합니다."
            )

    def _extract_cpes(self, cve_item):
        cpe_list = []
        configurations = cve_item.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable", True):
                        cpe23 = match.get("criteria", "")
                        if cpe23:
                            parts = cpe23.split(":")
                            if len(parts) >= 6:
                                core_cpe = f"{parts[3]}:{parts[4]}:{parts[5]}"
                                cpe_list.append(core_cpe)
        return list(set(cpe_list))

    def _extract_cwes(self, cve_info):
        """NVD JSON 구조에서 CWE-ID를 추출하는 헬퍼 함수"""
        cwe_list = []
        weaknesses = cve_info.get("weaknesses", [])
        for weakness in weaknesses:
            description = weakness.get("description", [])
            for desc in description:
                value = desc.get("value", "")
                # 'CWE-89'와 같은 형식만 추출하고 'NVD-CWE-noinfo' 등은 제외하려면 조건 강화 가능
                if value.startswith("CWE-"):
                    cwe_list.append(value)
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
                if not cve_id:
                    continue

                cpes = self._extract_cpes(cve_info)
                if not cpes:
                    continue

                # CWE 추출 적용
                cwes = self._extract_cwes(cve_info)

                # CVSS v3.x 추출
                cvss_score = 0.0
                severity = "UNKNOWN"
                metrics = cve_info.get("metrics", {})

                if "cvssMetricV31" in metrics:
                    m = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score = m.get("baseScore", 0.0)
                    severity = m.get("baseSeverity", "UNKNOWN")
                elif "cvssMetricV30" in metrics:
                    m = metrics["cvssMetricV30"][0]["cvssData"]
                    cvss_score = m.get("baseScore", 0.0)
                    severity = m.get("baseSeverity", "UNKNOWN")

                # Upsert 액션 구성
                action = {
                    "_index": self.index_name,
                    "_id": cve_id,
                    "_source": {
                        "cve_id": cve_id,
                        "cwe_ids": cwes,  # 추가된 필드
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "cpes": cpes,
                        "in_kev": False,
                        "epss_score": 0.0,
                        "epss_percentile": 0.0,
                    },
                }
                actions.append(action)

            if actions:
                print(f"DB 적재 시작 (Bulk Insert)...")
                success, failed = helpers.bulk(self.client, actions, chunk_size=1000)
                print(
                    f"완료: 성공 {success}건 / 실패 {len(failed) if isinstance(failed, list) else failed}건"
                )

        except FileNotFoundError:
            print(f"에러: {json_file} 파일을 찾을 수 없습니다.")
        except Exception as e:
            print(f"적재 중 예외 발생: {e}")


if __name__ == "__main__":
    loader = NVDLoader()

    # 주의: 필드가 추가되었으므로 기존 인덱스가 있다면 삭제 후 실행하는 것이 깔끔합니다.
    # loader.client.indices.delete(index="vulnerability_cve", ignore=[400, 404])

    loader.setup_index()

    TARGET_FILE = "cve_data_full.json"
    loader.load_nvd_json(TARGET_FILE)
