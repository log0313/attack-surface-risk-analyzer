import { Client } from "@opensearch-project/opensearch";

let client: Client | null = null;

export function getOpenSearch(): Client {
  if (!client) {
    client = new Client({
      node: process.env.OPENSEARCH_URL ?? "https://localhost:9200",
      auth: {
        username: process.env.OPENSEARCH_USERNAME ?? "admin",
        password: process.env.OPENSEARCH_PASSWORD ?? "",
      },
      ssl: {
        rejectUnauthorized: false,
        secureProtocol: "TLSv1_2_method",
      },
      requestTimeout: 8000,
    });
  }
  return client;
}

export const INDICES = {
  CVE: "vulnerability_cve",
  SCAN_RESULTS: "scan_results",
  ASSETS: "scan_assets",
  JOBS: "scan_jobs",
} as const;
