import { NextRequest, NextResponse } from "next/server";
import { getOpenSearch, INDICES } from "@/lib/opensearch";
import { getRedis } from "@/lib/redis";
import { Asset } from "@/lib/types";

const MOCK_ASSETS: Asset[] = [
  { id: "1",  subdomain: "api.example.com",     ip: "203.0.113.10", port: 443,  service: "HTTPS",      cvss: 9.8, status: "open" },
  { id: "2",  subdomain: "vpn.example.com",     ip: "203.0.113.22", port: 4443, service: "SSL-VPN",    cvss: 9.1, status: "open" },
  { id: "3",  subdomain: "gitlab.example.com",  ip: "203.0.113.45", port: 80,   service: "HTTP",       cvss: 8.7, status: "open" },
  { id: "4",  subdomain: "smtp.example.com",    ip: "203.0.113.67", port: 25,   service: "SMTP",       cvss: 7.5, status: "open" },
  { id: "5",  subdomain: "dev.example.com",     ip: "10.0.1.15",    port: 8080, service: "HTTP-Alt",   cvss: 7.2, status: "open" },
  { id: "6",  subdomain: "mail.example.com",    ip: "203.0.113.80", port: 993,  service: "IMAPS",      cvss: 5.3, status: "open" },
  { id: "7",  subdomain: "stage.example.com",   ip: "10.0.1.20",    port: 443,  service: "HTTPS",      cvss: 4.9, status: "filtered" },
  { id: "8",  subdomain: "cdn.example.com",     ip: "203.0.113.99", port: 80,   service: "HTTP",       cvss: 3.2, status: "open" },
  { id: "9",  subdomain: "auth.example.com",    ip: "10.0.1.22",    port: 443,  service: "OAuth Proxy",cvss: 3.1, status: "open" },
  { id: "10", subdomain: "files.example.com",   ip: "203.0.113.11", port: 445,  service: "SMB",        cvss: 2.1, status: "open" },
  { id: "11", subdomain: "proxy.example.com",   ip: "203.0.113.19", port: 80,   service: "HAProxy",    cvss: 8.2, status: "open" },
  { id: "12", subdomain: "backup.example.com",  ip: "10.0.1.66",    port: 873,  service: "Rsync",      cvss: 6.8, status: "open" },
  { id: "13", subdomain: "test.example.com",    ip: "203.0.113.88", port: 9229, service: "Node.js",    cvss: 4.5, status: "open" },
  { id: "14", subdomain: "portal.example.com",  ip: "203.0.113.44", port: 443,  service: "HTTPS",      cvss: 0,   status: "open" },
  { id: "15", subdomain: "static.example.com",  ip: "203.0.113.15", port: 443,  service: "HTTPS",      cvss: 0,   status: "open" },
];

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const search = searchParams.get("search") ?? "";
  const size = parseInt(searchParams.get("size") ?? "50");
  const from = parseInt(searchParams.get("from") ?? "0");

  try {
    const os = getOpenSearch();
    const query = search
      ? { bool: { should: [
          { wildcard: { subdomain: `*${search}*` } },
          { wildcard: { ip: `*${search}*` } },
          { wildcard: { service: `*${search}*` } },
        ], minimum_should_match: 1 }}
      : { match_all: {} };

    const res = await os.search({
      index: INDICES.ASSETS,
      body: { query, from, size, sort: [{ cvss: { order: "desc" } }] },
    });

    type OsHit = { _id: string; _source: { subdomain?: string; ip?: string; port?: number; service?: string; cvss?: number; status?: string } };
    const hits = (res.body.hits.hits as unknown) as OsHit[];
    const assets: Asset[] = hits.map((h) => ({
      id:       h._id,
      subdomain: h._source.subdomain ?? "",
      ip:       h._source.ip      ?? "",
      port:     h._source.port    ?? 0,
      service:  h._source.service ?? "",
      cvss:     h._source.cvss    ?? 0,
      status:   (h._source.status as Asset["status"]) ?? "open",
    }));
    const total = typeof res.body.hits.total === "number" ? res.body.hits.total : (res.body.hits.total?.value ?? 0);

    // OpenSearch 연결 성공 시 결과가 0개여도 그대로 반환 (초기화 상태 유지)
    return NextResponse.json({ assets, total, source: "opensearch" });
  } catch {
    // OpenSearch 연결 자체가 실패한 경우에만 mock 데이터 반환
    let assets = MOCK_ASSETS;
    if (search) {
      const q = search.toLowerCase();
      assets = MOCK_ASSETS.filter(
        (a) =>
          a.subdomain.toLowerCase().includes(q) ||
          a.ip.includes(q) ||
          a.service.toLowerCase().includes(q)
      );
    }
    return NextResponse.json({
      assets: assets.slice(from, from + size),
      total: assets.length,
      source: "mock",
    });
  }
}

export async function DELETE() {
  try {
    const os = getOpenSearch();
    const matchAll = { body: { query: { match_all: {} } } };

    await Promise.allSettled([
      os.deleteByQuery({ index: INDICES.ASSETS,        ...matchAll, conflicts: "proceed" }),
      os.deleteByQuery({ index: INDICES.SCAN_RESULTS,  ...matchAll, conflicts: "proceed" }),
    ]);

    // Redis job:* 키 전체 삭제
    try {
      const redis = getRedis();
      const keys = await redis.keys("job:*");
      if (keys.length > 0) await redis.del(...keys);
    } catch { /* Redis 연결 실패 시 무시 */ }

    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: "초기화 실패" }, { status: 500 });
  }
}
