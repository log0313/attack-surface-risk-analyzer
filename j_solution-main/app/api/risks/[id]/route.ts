import { NextRequest, NextResponse } from "next/server";
import { getOpenSearch, INDICES } from "@/lib/opensearch";
import { Risk } from "@/lib/types";

const MOCK_DETAIL: Record<string, Risk> = {
  "1":  { id: "1",  asset: "api.example.com",    ip: "203.0.113.10", cvss: 9.8, epss: 0.92, kev: true,  cve: "CVE-2024-21762", service: "FortiOS SSL-VPN",
    description: "FortiOS 및 FortiProxy의 웹 관리 인터페이스에서 인증 없이 임의 코드를 실행할 수 있는 원격 코드 실행(RCE) 취약점. CISA KEV에 등재되어 현재 실제 공격에 악용 중.",
    ports: [{ port: 443, protocol: "TCP", service: "HTTPS", version: "FortiOS 7.2.4", state: "open" }, { port: 8443, protocol: "TCP", service: "HTTPS", version: "FortiOS MGMT", state: "open" }, { port: 22, protocol: "TCP", service: "SSH", version: "OpenSSH 8.2", state: "open" }],
    cveList: [{ id: "CVE-2024-21762", cvss: 9.8, epss: 0.92, kev: true, summary: "FortiOS Out-of-bounds Write leads to RCE via crafted HTTP request" }, { id: "CVE-2023-27997", cvss: 9.8, epss: 0.87, kev: true, summary: "FortiOS SSL-VPN heap buffer overflow — pre-auth RCE" }] },
  "2":  { id: "2",  asset: "vpn.example.com",    ip: "203.0.113.22", cvss: 9.1, epss: 0.76, kev: true,  cve: "CVE-2024-3400",  service: "PAN-OS",
    description: "Palo Alto Networks PAN-OS GlobalProtect 기능에서 OS Command Injection이 가능한 취약점. 인증 없이 root 권한으로 임의 명령 실행 가능.",
    ports: [{ port: 443, protocol: "TCP", service: "GlobalProtect", version: "PAN-OS 11.0.2", state: "open" }, { port: 4443, protocol: "TCP", service: "SSL-VPN", version: "PAN-OS 11.0.2", state: "open" }],
    cveList: [{ id: "CVE-2024-3400", cvss: 9.1, epss: 0.76, kev: true, summary: "OS Command Injection in PAN-OS GlobalProtect — unauthenticated RCE" }] },
  "3":  { id: "3",  asset: "gitlab.example.com", ip: "203.0.113.45", cvss: 8.7, epss: 0.41, kev: false, cve: "CVE-2023-7028",  service: "GitLab CE",
    description: "GitLab 환경에서 사용자의 비밀번호 변경 메일이 인증되지 않은 주소로 발송될 수 있는 취약점(계정 탈취 가능성).",
    ports: [{ port: 80, protocol: "TCP", service: "HTTP", version: "Nginx", state: "open" }],
    cveList: [{ id: "CVE-2023-7028", cvss: 8.7, epss: 0.41, kev: false, summary: "Account Takeover via Password Reset without user interaction" }] },
  "4":  { id: "4",  asset: "smtp.example.com",   ip: "203.0.113.67", cvss: 7.5, epss: 0.29, kev: false, cve: "CVE-2024-1234",  service: "Exim SMTP",
    description: "Exim 메일 서버에서 메시지 검사 중 발생할 수 있는 메모리 손상 버그.",
    ports: [{ port: 25, protocol: "TCP", service: "SMTP", version: "Exim 4.96", state: "open" }],
    cveList: [{ id: "CVE-2024-1234", cvss: 7.5, epss: 0.29, kev: false, summary: "Memory corruption in message parsing" }] },
  "5":  { id: "5",  asset: "dev.example.com",    ip: "10.0.1.15",    cvss: 7.2, epss: 0.18, kev: false, cve: "CVE-2023-5678",  service: "Apache HTTP",
    description: "오래된 버전의 Apache 서버에서 발견된 로컬 권한 상승(LPE) 및 DoS 취약점.",
    ports: [{ port: 8080, protocol: "TCP", service: "HTTP-Alt", version: "Apache 2.4.40", state: "open" }],
    cveList: [{ id: "CVE-2023-5678", cvss: 7.2, epss: 0.18, kev: false, summary: "Local privilege escalation possible via symlinks" }] },
  "6":  { id: "6",  asset: "mail.example.com",   ip: "203.0.113.80", cvss: 5.3, epss: 0.08, kev: false, cve: "CVE-2023-9012",  service: "Dovecot IMAP",
    description: "IMAP 서버의 자원 소모성(Denial of Service) 취약점.",
    ports: [{ port: 993, protocol: "TCP", service: "IMAPS", version: "Dovecot", state: "open" }],
    cveList: [{ id: "CVE-2023-9012", cvss: 5.3, epss: 0.08, kev: false, summary: "Resource exhaustion via multiple concurrent IMAP sessions" }] },
  "7":  { id: "7",  asset: "stage.example.com",  ip: "10.0.1.20",    cvss: 4.9, epss: 0.05, kev: false, cve: "CVE-2023-3456",  service: "Nginx",
    description: "Nginx 설정의 미스컨피규레이션으로 인한 정보 노출(Information Disclosure) 위험.",
    ports: [{ port: 443, protocol: "TCP", service: "HTTPS", version: "Nginx 1.22.0", state: "filtered" }],
    cveList: [{ id: "CVE-2023-3456", cvss: 4.9, epss: 0.05, kev: false, summary: "Information disclosure via detailed error messages" }] },
  "8":  { id: "8",  asset: "cdn.example.com",    ip: "203.0.113.99", cvss: 3.2, epss: 0.02, kev: false, cve: "CVE-2023-2345",  service: "Cloudflare Worker",
    description: "서드파티 워커 로직의 캐싱 이슈로 인한 단순 캐시 교란.",
    ports: [{ port: 80, protocol: "TCP", service: "HTTP", version: "Cloudflare", state: "open" }],
    cveList: [{ id: "CVE-2023-2345", cvss: 3.2, epss: 0.02, kev: false, summary: "Low-impact cache poisoning vulnerability" }] },
  "9":  { id: "9",  asset: "auth.example.com",   ip: "10.0.1.22",    cvss: 3.1, epss: 0.01, kev: false, cve: "CVE-2023-1212",  service: "OAuth Proxy",
    description: "OAuth 인증 프록시에서 만료된 토큰이 리다이렉트되는 중 리퍼러 정보에 유출되는 현상.",
    ports: [{ port: 443, protocol: "TCP", service: "HTTPS", version: "OAuth2 Proxy", state: "open" }],
    cveList: [{ id: "CVE-2023-1212", cvss: 3.1, epss: 0.01, kev: false, summary: "Information exposure via HTTP Referer header" }] },
  "10": { id: "10", asset: "files.example.com",  ip: "203.0.113.11", cvss: 2.1, epss: 0.01, kev: false, cve: "CVE-2023-0001",  service: "Samba",
    description: "매우 한정된 환경에서의 Samba 경로 오류. 실질적인 외부 타격 가능성은 희박함.",
    ports: [{ port: 445, protocol: "TCP", service: "SMB", version: "Samba 4.10", state: "open" }],
    cveList: [{ id: "CVE-2023-0001", cvss: 2.1, epss: 0.01, kev: false, summary: "Minor edge case in parsing symbolic links" }] },
  "11": { id: "11", asset: "proxy.example.com",  ip: "203.0.113.19", cvss: 8.2, epss: 0.65, kev: true,  cve: "CVE-2024-5555",  service: "HAProxy",
    description: "HTTP Request Smuggling 취약점으로, 악의적인 페이로드를 숨겨 내부 망의 다른 서버를 우회 타격할 수 있음. CISA KEV 등재됨.",
    ports: [{ port: 443, protocol: "TCP", service: "HTTPS", version: "HAProxy 2.4", state: "open" }, { port: 80, protocol: "TCP", service: "HTTP", version: "HAProxy 2.4", state: "open" }],
    cveList: [{ id: "CVE-2024-5555", cvss: 8.2, epss: 0.65, kev: true, summary: "HTTP Request Smuggling leading to internal service bypass" }] },
  "12": { id: "12", asset: "backup.example.com", ip: "10.0.1.66",    cvss: 6.8, epss: 0.12, kev: false, cve: "CVE-2023-4444",  service: "Rsync",
    description: "잘못된 권한 설정으로 인해 익명 유저가 백업 모듈 리스트를 열람할 수 있는 상태.",
    ports: [{ port: 873, protocol: "TCP", service: "Rsync", version: "Rsync 3.1", state: "open" }],
    cveList: [{ id: "CVE-2023-4444", cvss: 6.8, epss: 0.12, kev: false, summary: "Insecure module configuration exposing backup lists" }] },
  "13": { id: "13", asset: "test.example.com",   ip: "203.0.113.88", cvss: 4.5, epss: 0.04, kev: false, cve: "CVE-2023-8888",  service: "Node.js",
    description: "개발용 Node.js 환경에서 디버깅 포트가 외부에 노출되어 있어 코드 주입 등 2차 타격 위험 존재.",
    ports: [{ port: 9229, protocol: "TCP", service: "Node Debug", version: "V8 Inspector", state: "open" }],
    cveList: [{ id: "CVE-2023-8888", cvss: 4.5, epss: 0.04, kev: false, summary: "V8 Inspector protocol exposed leading to code injection vectors" }] },
};

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  try {
    const os = getOpenSearch();
    type OsSource    = { asset?: string; ip?: string; port?: number; cvss_score?: number; epss_score?: number; in_kev?: boolean; cve_id?: string; service?: string; description?: string };
    type AssetSource = { subdomain?: string; ip?: string; port?: number; service?: string; cvss?: number; status?: string; job_id?: string };
    type CveHit      = { _id: string; _source: OsSource };

    // 1) scan_results 직접 조회 (Risk Analysis 목록에서 넘어온 경우)
    let src: OsSource | null = null;
    try {
      const res = await os.get({ index: INDICES.SCAN_RESULTS, id });
      if (res.body.found) src = res.body._source as OsSource;
    } catch { /* not in scan_results */ }

    if (src) {
      return NextResponse.json({
        risk: {
          id,
          asset:   src.asset       ?? "",
          ip:      src.ip          ?? "",
          cvss:    src.cvss_score  ?? 0,
          epss:    src.epss_score  ?? 0,
          kev:     src.in_kev      ?? false,
          cve:     src.cve_id      ?? id,
          service: src.service     ?? "",
          description: src.description,
        } satisfies Risk,
        source: "opensearch",
      });
    }

    // 2) scan_assets 조회 (Asset Discovery 목록에서 넘어온 경우)
    //    → 해당 자산+포트의 모든 CVE를 scan_results에서 조회
    try {
      const assetRes = await os.get({ index: INDICES.ASSETS, id });
      if (assetRes.body.found) {
        const a = assetRes.body._source as AssetSource;
        const cveRes = await os.search({
          index: INDICES.SCAN_RESULTS,
          body: {
            query: { bool: { must: [
              { term: { asset: a.subdomain ?? "" } },
              { term: { port:  a.port ?? 0 } },
              { term: { job_id: a.job_id ?? "" } },
            ]}},
            sort: [{ cvss_score: { order: "desc" } }],
            size: 200,
          },
        });
        const cveHits = (cveRes.body.hits.hits as unknown) as CveHit[];
        const top = cveHits[0]?._source;
        const risk: Risk = {
          id,
          asset:   a.subdomain ?? "",
          ip:      a.ip        ?? "",
          cvss:    top?.cvss_score  ?? a.cvss ?? 0,
          epss:    top?.epss_score  ?? 0,
          kev:     top?.in_kev      ?? false,
          cve:     top?.cve_id      ?? "",
          service: a.service        ?? "",
          description: cveHits.length > 0
            ? `${a.subdomain}:${a.port} (${a.service}) 에서 ${cveHits.length}개의 CVE가 탐지되었습니다.`
            : `${a.service} 서비스가 탐지되었으나 매칭된 CVE가 없습니다.`,
          ports: [{ port: a.port ?? 0, protocol: "TCP", service: a.service ?? "", version: "", state: "open" }],
          cveList: cveHits.map((h) => ({
            id:      h._source.cve_id ?? h._id,
            cvss:    h._source.cvss_score ?? 0,
            epss:    h._source.epss_score ?? 0,
            kev:     h._source.in_kev    ?? false,
            summary: h._source.service   ?? "",
          })),
        };
        return NextResponse.json({ risk, source: "opensearch" });
      }
    } catch { /* not in scan_assets */ }

    // 3) CVE DB 직접 조회 (fallback)
    try {
      const res = await os.get({ index: INDICES.CVE, id });
      if (!res.body.found) throw new Error("not found");
      const s = res.body._source as OsSource;
      return NextResponse.json({
        risk: {
          id, asset: "", ip: "",
          cvss: s.cvss_score ?? 0, epss: s.epss_score ?? 0,
          kev: s.in_kev ?? false, cve: s.cve_id ?? id, service: "",
        } satisfies Risk,
        source: "opensearch",
      });
    } catch { throw new Error("not found"); }

  } catch {
    const risk = MOCK_DETAIL[id];
    if (!risk) return NextResponse.json({ error: "Not found" }, { status: 404 });
    return NextResponse.json({ risk, source: "mock" });
  }
}
