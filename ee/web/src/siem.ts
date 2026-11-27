import { queryOptions } from "@tanstack/react-query";
import { apiFetch } from "@/api/client";
import type { Retention, SinkBody, SinkKind, SinkView } from "@/api/gen/types.gen";

const BASE = "/api/v1/ee/audit";
const json = (method: string, body: unknown) => ({ method, body: JSON.stringify(body), contentType: "application/json" });

export const siemKeys = { all: ["ee", "audit-forwarding"] as const };

export const sinksQuery = queryOptions({
  queryKey: [...siemKeys.all, "sinks"] as const,
  queryFn: () => apiFetch<SinkView[]>(`${BASE}/sinks`),
  refetchInterval: 15_000,
});
export const retentionQuery = queryOptions({
  queryKey: [...siemKeys.all, "retention"] as const,
  queryFn: () => apiFetch<Retention>(`${BASE}/retention`),
});

export const createSink = (b: SinkBody) => apiFetch<SinkView>(`${BASE}/sinks`, json("POST", b));
export const updateSink = (id: number, b: SinkBody) => apiFetch<SinkView>(`${BASE}/sinks/${id}`, json("PUT", b));
export const deleteSink = (id: number) => apiFetch<void>(`${BASE}/sinks/${id}`, { method: "DELETE" });
export const testSink = (id: number) => apiFetch<void>(`${BASE}/sinks/${id}/test`, { method: "POST" });
export const putRetention = (days: number) => apiFetch<Retention>(`${BASE}/retention`, json("PUT", { days }));

export const SINK_LABEL: Record<SinkKind, string> = {
  syslog: "Syslog",
  splunk_hec: "Splunk HEC",
  http: "HTTPS (JSON)",
};

/** "Up to date", "N behind" or "Paused": how far a sink has got. */
export function progress(s: SinkView): string {
  if (!s.enabled) return "Paused";
  return s.behind > 0 ? `${s.behind} behind` : "Up to date";
}
