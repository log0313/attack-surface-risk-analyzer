import json
import requests  # 터미널에서 'pip install requests' 필수!
from datetime import datetime


class IntegratedScanner:
    def __init__(self, domain):
        self.domain = domain.strip().lower()

    def _analyze_target(self, target, port):
        """httpx 대신 requests를 사용하여 헤더에서 기술 스택 추출"""
        url = f"http://{target}:{port}"
        h_info = {"tech": [], "status_code": 0}

        # 원하는 결과 포맷 매핑
        target_map = {
            "WSO2": "WSO2:api_manager:*",
            "Oracle": "oracle:identity_management_suite:12.2.1.4.0",
            "log4j": "apache:log4j-core:2.14.1",
            "Struts": "Apache:struts:2.3.15.1",
            "GoAnywhere": "Fortra:goanywhere_mft:*",
            "MOVEit": "Progress:moveit_transfer:*",
            "Palo Alto": "Paloaltonetworks:pan-os:10.2.0",
            "NetScaler": "Citrix:netscaler_adc:*",
            "FortiOS": "Fortinet:fortios:*",
            "F5": "F5:big-ip:*",
        }

        try:
            # 도커 서버에 요청 (timeout을 줘서 멈춤 방지)
            response = requests.get(url, timeout=3)
            h_info["status_code"] = response.status_code

            # 모든 헤더 정보를 하나의 문자열로 합침
            header_dump = ""
            for k, v in response.headers.items():
                header_dump += f"{k}: {v}\n"

            # 키워드 매칭 로직
            for key, val in target_map.items():
                if key.lower() in header_dump.lower():
                    h_info["tech"].append(val)

            if h_info["tech"]:
                print(f" [OK] Port {port}: {len(h_info['tech'])}개 기술 탐색 성공!")
            else:
                print(f" [?] Port {port}: 응답은 왔으나 매칭되는 기술이 없음.")

        except Exception as e:
            print(f" [!] Port {port} 연결 실패 (도커가 켜져 있나요?): {e}")

        return h_info

    def scan_target(self, target):
        print(f"[*] Starting Security Scan for {target}...")
        ports = ["8080", "8081", "8443"]
        asset_data = {"host": target, "open_ports": []}

        for port in ports:
            print(f" [>] Analyzing Port {port}...")
            h_info = self._analyze_target(target, port)

            port_result = {
                "port": int(port),
                "service": "https" if port == "8443" else "http",
                "technologies": h_info["tech"],
            }
            asset_data["open_ports"].append(port_result)

        return asset_data


if __name__ == "__main__":
    TARGET = "localhost"
    scanner = IntegratedScanner(TARGET)

    # 실제 스캔 실행
    final_result = scanner.scan_target(TARGET)

    # 보고서 구조화
    report = {
        "root_domain": TARGET,
        "scan_time": datetime.now().isoformat(),
        "subdomains": [final_result],
    }

    # JSON 파일 저장
    filename = "scan_report_simulated.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    print(f"\n[*] 스캔 완료! 결과 파일 확인: {filename}")
