import { NextRequest, NextResponse } from "next/server";
import { getOpenSearch, INDICES } from "@/lib/opensearch";
import { Risk } from "@/lib/types";

const MOCK_RISKS: Risk[] = [
  { id: "1",  asset: "api.example.com",    ip: "203.0.113.10", cvss: 9.8, epss: 0.92, kev: true,  cve: "CVE-2024-21762", service: "FortiOS SSL-VPN" },
  { id: "2",  asset: "vpn.example.com",    ip: "203.0.113.22", cvss: 9.1, epss: 0.76, kev: true,  cve: "CVE-2024-3400",  service: "PAN-OS" },
  { id: "3",  asset: "gitlab.example.com", ip: "203.0.113.45", cvss: 8.7, epss: 0.41, kev: false, cve: "CVE-2023-7028",  service: "GitLab CE" },
  { id: "4",  asset: "smtp.example.com",   ip: "203.0.113.67", cvss: 7.5, epss: 0.29, kev: false, cve: "CVE-2024-1234",  service: "Exim SMTP" },
  { id: "5",  asset: "dev.example.com",    ip: "10.0.1.15",    cvss: 7.2, epss: 0.18, kev: false, cve: "CVE-2023-5678",  service: "Apache HTTP" },
  { id: "6",  asset: "mail.example.com",   ip: "203.0.113.80", cvss: 5.3, epss: 0.08, kev: false, cve: "CVE-2023-9012",  service: "Dovecot IMAP" },
  { id: "7",  asset: "stage.example.com",  ip: "10.0.1.20",    cvss: 4.9, epss: 0.05, kev: false, cve: "CVE-2023-3456",  service: "Nginx" },
  { id: "8",  asset: "cdn.example.com",    ip: "203.0.113.99", cvss: 3.2, epss: 0.02, kev: false, cve: "CVE-2023-2345",  service: "Cloudflare Worker" },
  { id: "9",  asset: "auth.example.com",   ip: "10.0.1.22",    cvss: 3.1, epss: 0.01, kev: false, cve: "CVE-2023-1212",  service: "OAuth Proxy" },
  { id: "10", asset: "files.example.com",  ip: "203.0.113.11", cvss: 2.1, epss: 0.01, kev: false, cve: "CVE-2023-0001",  service: "Samba" },
  { id: "11", asset: "proxy.example.com",  ip: "203.0.113.19", cvss: 8.2, epss: 0.65, kev: true,  cve: "CVE-2024-5555",  service: "HAProxy" },
  { id: "12", asset: "backup.example.com", ip: "10.0.1.66",    cvss: 6.8, epss: 0.12, kev: false, cve: "CVE-2023-4444",  service: "Rsync" },
  { id: "13", asset: "test.example.com",   ip: "203.0.113.88", cvss: 4.5, epss: 0.04, kev: false, cve: "CVE-2023-8888",  service: "Node.js" },
];

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const size = parseInt(searchParams.get("size") ?? "100");
  const from = parseInt(searchParams.get("from") ?? "0");
  const topN = searchParams.get("top") ? parseInt(searchParams.get("top")!) : null;

  type OsHit = { _id: string; _source: { asset?: string; ip?: string; port?: number; cvss_score?: number; epss_score?: number; in_kev?: boolean; cve_id?: string; service?: string; scanned_at?: string } };

  try {
    const os = getOpenSearch();

    // scan_results 인덱스 우선 조회 (스캔된 자산 + 매칭된 CVE)
    const scanRes = await os.search({
      index: INDICES.SCAN_RESULTS,
      body: {
        query: { match_all: {} },
        from,
        size: topN ?? size,
        sort: [{ cvss_score: { order: "desc" } }],
      },
    });

    const hits = (scanRes.body.hits.hits as unknown) as OsHit[];
    const risks: Risk[] = hits.map((h) => ({
      id: h._id,
      asset:     h._source.asset      ?? "",
      ip:        h._source.ip         ?? "",
      cvss:      h._source.cvss_score ?? 0,
      epss:      h._source.epss_score ?? 0,
      kev:       h._source.in_kev     ?? false,
      cve:       h._source.cve_id     ?? h._id,
      service:   h._source.service    ?? "",
      scannedAt: h._source.scanned_at ?? "",
    }));
    const total = typeof scanRes.body.hits.total === "number" ? scanRes.body.hits.total : (scanRes.body.hits.total?.value ?? 0);
    // OpenSearch 연결 성공 시 결과가 0개여도 그대로 반환 (초기화 상태 유지)
    return NextResponse.json({ risks, total, source: "opensearch" });
  } catch {
    // OpenSearch 연결 자체가 실패한 경우에만 mock 데이터 반환
    const risks = topN ? MOCK_RISKS.slice(0, topN) : MOCK_RISKS.slice(from, from + size);
    return NextResponse.json({ risks, total: MOCK_RISKS.length, source: "mock" });
  }
}
