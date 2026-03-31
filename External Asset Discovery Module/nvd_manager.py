import requests
import json
import time
from datetime import datetime, timedelta, timezone


class NVDManager:
    def __init__(self, api_key=None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        # API 키가 없으면 6초 대기(필수), 있으면 0.6초 대기
        self.delay = 6.0 if not api_key else 0.6

    def _fetch_pages(self, params, output_file="cve_data.json"):
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        all_vulnerabilities = []
        start_index = 0
        results_per_page = 2000
        total_results = 1  # 최초 진입을 위한 더미 값

        print(f"NVD API 호출 시작... (호출간 대기 시간: {self.delay}초)")

        while start_index < total_results:
            params["startIndex"] = start_index
            params["resultsPerPage"] = results_per_page

            try:
                response = requests.get(self.base_url, headers=headers, params=params, timeout=30)

                # 속도 제한(403)이나 서버 에러 시 재시도 로직
                if response.status_code != 200:
                    print(f"서버 응답 에러 ({response.status_code}). 10초 후 재시도합니다...")
                    time.sleep(10)
                    continue

                data = response.json()
                total_results = data.get("totalResults", 0)
                vulnerabilities = data.get("vulnerabilities", [])
                all_vulnerabilities.extend(vulnerabilities)

                print(f"진행률: {len(all_vulnerabilities):,} / {total_results:,} 건 다운로드 완료")

                start_index += results_per_page
                time.sleep(self.delay)  # NVD 서버 차단 방지용 딜레이

            except requests.exceptions.RequestException as e:
                print(f"네트워크 에러: {e}. 10초 후 재시도...")
                time.sleep(10)

        # 결과 저장
        final_data = {
            "timestamp": datetime.now().isoformat(),
            "resultsPerPage": len(all_vulnerabilities),
            "startIndex": 0,
            "totalResults": len(all_vulnerabilities),
            "format": "NVD_CVE",
            "version": "2.0",
            "vulnerabilities": all_vulnerabilities
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(final_data, f, ensure_ascii=False)

        print(f"다운로드 완료: '{output_file}'에 저장되었습니다.")

    def download_all(self): # 전체 취약점 다운로드(최초 실행시)
        print("\n=== [전체 데이터 다운로드 모드] ===")
        if not self.api_key:
            print("warning: api키가 없으면 다운로드 시간이 오래 걸릴 수 있습니다.")
        params = {}  # 아무 조건이 없으면 전체 다운로드
        self._fetch_pages(params, "cve_data_full.json")

    def update_recent(self, days=7): # 최근 취약점 다운로드(기본 7일)
        print(f"\n=== [업데이트 모드: 최근 {days}일] ===")

        # NVD API 시간에 맞게 UTC 기준으로 계산
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        # NVD API v2.0 날짜 포맷 (YYYY-MM-DDTHH:MM:SS.000%2B00:00 -> requests가 인코딩해줌)
        date_format = "%Y-%m-%dT%H:%M:%S.000"

        params = {
            "lastModStartDate": start_date.strftime(date_format),
            "lastModEndDate": end_date.strftime(date_format)
        }
        self._fetch_pages(params, "cve_data_update.json")


if __name__ == "__main__":
    # API 키가 있다면 삽입 (예: "your-api-key-here")
    manager = NVDManager(api_key="bddf393b-475c-454f-9bc7-2ed2d32ceadb")

    # [1] 최초 구축 시 (전체 다운로드 - 시간이 오래 걸림. 1GB 이상)
    # manager.download_all()

    # [2] 주기적 업데이트 시 (최근 7일치만 빠르게 다운로드)
    manager.update_recent(days=7)
