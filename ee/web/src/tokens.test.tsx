import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { TokenInfo } from "@/api/gen/types.gen";
import { mockFetch } from "@/test/fetch";
import { loggedIn, renderApp } from "@/test/app";

const TOKEN: TokenInfo = {
  id: 3,
  user_id: 1,
  username: "admin",
  name: "deploy",
  prefix: "fo_abc123",
  read_only: true,
  created_at: 1_790_000_000,
  expires_at: null,
  last_used_at: null,
  last_used_ip: null,
};

const SECRET = `fo_abc123${"0".repeat(58)}`;

const routes = (extra: Record<string, unknown> = {}) => ({
  ...loggedIn,
  "GET /api/v1/edition": { json: { edition: "enterprise", features: ["api_tokens"] } },
  "GET /api/v1/auth/sessions": { json: [] },
  "GET /api/v1/ee/tokens": { json: [TOKEN] },
  "GET /api/v1/ee/tokens/all": { json: [TOKEN, { ...TOKEN, id: 4, user_id: 2, username: "bob", name: "bob-ci" }] },
  ...extra,
});

const section = async () => screen.findByRole("region", { name: "API tokens" });

describe("API tokens", () => {
  it("lists tokens with prefix, scope and last use", async () => {
    mockFetch(routes());
    renderApp("/account");
    const s = await section();
    const row = await within(s).findByRole("row", { name: /deploy/ });
    expect(row).toHaveTextContent("fo_abc123…");
    expect(row).toHaveTextContent("Read-only");
    expect(row).toHaveTextContent("Never used");
  });

  it("shows a new token's secret once", async () => {
    const calls = mockFetch(
      routes({ "POST /api/v1/ee/tokens": { status: 201, json: { token: { ...TOKEN, id: 5, name: "ci", read_only: false }, secret: SECRET } } }),
    );
    renderApp("/account");
    const s = await section();
    await userEvent.click(within(s).getByRole("button", { name: "Create token" }));
    const d = await screen.findByRole("dialog", { name: "Create API token" });
    await userEvent.type(within(d).getByLabelText("Name"), "ci");
    await userEvent.selectOptions(within(d).getByLabelText("Expires"), "90");
    await userEvent.click(within(d).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "ci", read_only: false, expires_in_days: 90 }),
    );
    const shown = await screen.findByRole("dialog", { name: "Copy your token" });
    expect(within(shown).getByText(SECRET)).toBeInTheDocument();
    expect(within(shown).getByRole("button", { name: "Copy" })).toBeInTheDocument();
    await userEvent.click(within(shown).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByText(SECRET)).toBeNull());
    await userEvent.click(within(s).getByRole("button", { name: "Create token" }));
    await screen.findByRole("dialog", { name: "Create API token" });
    expect(screen.queryByText(SECRET)).toBeNull();
  });

  it("asks before revoking", async () => {
    const calls = mockFetch(routes({ "DELETE /api/v1/ee/tokens/3": { status: 204 } }));
    renderApp("/account");
    const s = await section();
    const row = await within(s).findByRole("row", { name: /deploy/ });
    await userEvent.click(within(row).getByRole("button", { name: "Revoke" }));
    const d = await screen.findByRole("dialog", { name: "Revoke token deploy?" });
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    await userEvent.click(within(d).getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.path === "/api/v1/ee/tokens/3")).toBe(true));
  });

  it("lists every user's tokens for admins", async () => {
    mockFetch(routes());
    renderApp("/admin/tokens");
    const table = await screen.findByRole("table", { name: "API tokens" });
    const bob = await within(table).findByRole("row", { name: /bob-ci/ });
    expect(bob).toHaveTextContent("bob");
  });
});
