import { queryOptions } from "@tanstack/react-query";
import { apiFetch } from "@/api/client";
import type { CreatedToken, NewToken, TokenInfo } from "@/api/gen/types.gen";

const BASE = "/api/v1/ee/tokens";

export const tokenKeys = { all: ["ee", "tokens"] as const };

export const myTokensQuery = queryOptions({
  queryKey: [...tokenKeys.all, "mine"] as const,
  queryFn: () => apiFetch<TokenInfo[]>(BASE),
});
export const allTokensQuery = queryOptions({
  queryKey: [...tokenKeys.all, "all"] as const,
  queryFn: () => apiFetch<TokenInfo[]>(`${BASE}/all`),
});

export const createToken = (b: NewToken) =>
  apiFetch<CreatedToken>(BASE, { method: "POST", body: JSON.stringify(b), contentType: "application/json" });
export const revokeToken = (id: number) => apiFetch<void>(`${BASE}/${id}`, { method: "DELETE" });

/** Expiry choices, in days; "" is never. */
export const EXPIRY_CHOICES = [
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year" },
  { value: "", label: "Never" },
];
