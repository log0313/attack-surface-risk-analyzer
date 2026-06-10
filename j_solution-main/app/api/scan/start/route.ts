import { NextRequest, NextResponse } from "next/server";
import { getRedis } from "@/lib/redis";
import { ScanJob } from "@/lib/types";

export async function POST(req: NextRequest) {
  const { target } = await req.json();
  if (!target || typeof target !== "string") {
    return NextResponse.json({ error: "target is required" }, { status: 400 });
  }

  const jobId = `job_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const job: ScanJob = {
    jobId,
    target: target.trim(),
    status: "queued",
    createdAt: new Date().toISOString(),
  };

  try {
    const redis = getRedis();
    const queueName = process.env.SCAN_QUEUE_NAME ?? "scan_jobs";
    await redis.lpush(queueName, JSON.stringify(job));
    await redis.set(`job:${jobId}`, JSON.stringify(job), "EX", 86400);
    return NextResponse.json({ jobId, status: "queued" });
  } catch {
    return NextResponse.json({ error: "Redis unavailable" }, { status: 503 });
  }
}
