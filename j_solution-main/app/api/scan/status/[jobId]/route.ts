import { NextRequest, NextResponse } from "next/server";
import { getRedis } from "@/lib/redis";
import { ScanJob } from "@/lib/types";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ jobId: string }> }
) {
  const { jobId } = await params;

  try {
    const redis = getRedis();
    const raw = await redis.get(`job:${jobId}`);
    if (!raw) {
      return NextResponse.json({ error: "Job not found" }, { status: 404 });
    }
    const job: ScanJob = JSON.parse(raw);
    return NextResponse.json(job);
  } catch {
    return NextResponse.json({ error: "Redis unavailable" }, { status: 503 });
  }
}
