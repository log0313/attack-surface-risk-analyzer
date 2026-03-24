import subprocess
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime


class IntegratedScanner:
    def __init__(self, domain):
        # 도메인 양 끝의 공백이나 특수문자 제거
        self.domain = domain.strip().lower()
        self.final_report = {
            "root_domain": self.domain,
            "scan_time": datetime.now().isoformat(),
            "subdomains": [],
        }

    def _run_command(self, cmd):
        """외부 명령어를 실행하고 결과를 반환"""
        try:
            # 윈도우 환경에서 도구들이 설치된 PATH를 인식하지 못할 경우를 대비
            # 결과물에서 불필요한 공백 제거
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            return result.decode("utf-8", errors="ignore").strip()
        except Exception as e:
            # 에러 발생 시 로그 출력 후 빈 문자열 반환
            return ""

    def _clean_text(self, text):
        """u003e 같은 유니코드 깨짐 및 특수문자 제거"""
        # 알파벳, 숫자, 점, 하이픈만 남기고 모두 제거
        cleaned = re.sub(r"[^\w\.\-]", "", text)
        return cleaned.strip()

    def _enumerate_subdomains(self):
        """Phase 0: Subfinder를 이용한 서브도메인 수집 및 정제"""
        print(f"[+] Phase 0: Enumerating subdomains for {self.domain}...")
        sub_out = self._run_command(f"subfinder -d {self.domain} -silent")

        raw_subs = sub_out.split("\n")
        sub_set = set()  # 중복 제거를 위해 set 사용

        for line in raw_subs:
            clean_sub = self._clean_text(line)
            # 유효한 도메인 형태인지 체크 (글자가 있고 점이 포함됨)
            if clean_sub and "." in clean_sub:
                sub_set.add(clean_sub)

        # 최종적으로 리스트로 변환하여 반환
        final_subs = list(sub_set)
        print(f"[*] Found {len(final_subs)} valid subdomains.")
        return final_subs

    def _parse_nmap_xml(self, xml_str):
        """Nmap XML 파싱 (예외 처리 강화)"""
        services = {}
        if not xml_str or "<?xml" not in xml_str:
            return services
        try:
            root = ET.fromstring(xml_str)
            for port in root.findall(".//port"):
                port_id = port.get("portid")
                state = (
                    port.find("state").get("state")
                    if port.find("state") is not None
                    else ""
                )

                # 열린 포트만 처리
                if state != "open":
                    continue

                service_tag = port.find("service")
                cpe_val = ""
                cpe_tag = service_tag.find("cpe") if service_tag is not None else None
                if cpe_tag is not None:
                    cpe_val = cpe_tag.text

                services[port_id] = {
                    "service_name": (
                        service_tag.get("name", "unknown")
                        if service_tag is not None
                        else "unknown"
                    ),
                    "product": service_tag.get("product", ""),
                    "version": service_tag.get("version", ""),
                    "cpe": cpe_val,
                }
        except Exception as e:
            print(f"[!] XML Parsing Error: {e}")
        return services

    def _generate_fallback_cpe(self, n_info):
        """CPE 생성 (표준 포맷 준수)"""
        if not n_info["product"]:
            return ""
        vendor = n_info["product"].lower().replace(" ", "_")
        product = vendor
        version = n_info["version"] or "*"
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    def scan_target(self, target_host):
        """개별 호스트 상세 스캔"""
        print(f"\n>>> Scanning Target: {target_host}")
        asset_data = {"host": target_host, "open_ports": []}

        # 1. Naabu: 포트 스캔
        naabu_out = self._run_command(f"naabu -host {target_host} -silent")
        ports = [
            line.split(":")[-1]
            for line in naabu_out.split("\n")
            if line and ":" in line
        ]

        if not ports:
            print(f"[-] No open ports found on {target_host}")
            return asset_data

        # 2. Nmap: 서비스 탐지
        port_arg = ",".join(ports)
        nmap_xml = self._run_command(f"nmap -sV -p{port_arg} {target_host} -oX -")
        nmap_data = self._parse_nmap_xml(nmap_xml)

        # 3. HTTPX: 기술 스택 분석 (성공률을 위해 -u 대신 URL 직접 생성 시도 가능)
        # 포트별로 더 상세히 찌르기 위해 옵션 보강
        httpx_out = self._run_command(
            f"httpx -u {target_host} -silent -json -td -title -status-code"
        )

        httpx_map = {}
        for line in httpx_out.split("\n"):
            if line.strip().startswith("{"):
                try:
                    data = json.loads(line)
                    port = str(data.get("port", ""))
                    httpx_map[port] = data
                except:
                    continue

        # 4. 결과 통합
        for port, n_info in nmap_data.items():
            h_info = httpx_map.get(port, {})
            port_result = {
                "port": int(port),
                "service": n_info["service_name"],
                "version": n_info["version"],
                "technologies": h_info.get("tech", []),
                "web_title": h_info.get("title", ""),
                "status_code": h_info.get("status_code"),  # httpx json 키값 확인
                "cpe_23": (
                    n_info["cpe"]
                    if n_info["cpe"]
                    else self._generate_fallback_cpe(n_info)
                ),
            }
            asset_data["open_ports"].append(port_result)

        return asset_data

    def start_full_scan(self):
        """전체 프로세스 시작"""
        subdomains = self._enumerate_subdomains()

        # 루트 도메인이 결과에 없으면 추가
        if self.domain not in subdomains:
            subdomains.append(self.domain)

        for sub in subdomains:
            result = self.scan_target(sub)
            # 열린 포트가 있는 자산만 리포트에 의미 있게 기록 (선택 사항)
            self.final_report["subdomains"].append(result)

        return self.final_report


# 실행
if __name__ == "__main__":
    DOMAIN = "vulnweb.com"  # 타겟 도메인
    scanner = IntegratedScanner(DOMAIN)
    final_results = scanner.start_full_scan()

    filename = f"scan_report_{DOMAIN}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(final_results, f, indent=4, ensure_ascii=False)

    print(f"\n[*] All scans complete. Report saved to '{filename}'")
6
