import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { SinkView } from "@/api/gen/types.gen";
import { mockFetch } from "@/test/fetch";
import { loggedIn, renderApp } from "@/test/app";

const BASE = "/api/v1/ee/audit/sinks";

const sink = (over: Partial<SinkView> = {}): SinkView => ({
  id: 1,
  name: "splunk",
  kind: "splunk_hec",
  enabled: true,
  target: "splunk.example",
  transport: null,
  url: "https://splunk.example:8088/services/collector/event",
  header_names: [],
  token_set: true,
  ca_set: false,
  cursor: 10,
  behind: 0,
  gap_rows: 0,
  last_sent_at: 1_790_000_000,
  last_error: null,
  last_error_at: null,
  ...over,
});

const routes = (sinks: SinkView[], extra: Record<string, unknown> = {}) => ({
  ...loggedIn,
  "GET /api/v1/edition": { json: { edition: "enterprise", features: ["audit_sinks"] } },
  [`GET ${BASE}`]: { json: sinks },
  "GET /api/v1/ee/audit/retention": { json: { days: 90, default_days: 90 } },
  ...extra,
});

const table = () => screen.findByRole("table", { name: "Audit sinks" });

describe("audit forwarding", () => {
  it("lists sinks with their status", async () => {
    mockFetch(
      routes([
        sink(),
        sink({ id: 2, name: "dd", kind: "http", target: "http-intake.logs.datadoghq.com", behind: 120 }),
        sink({ id: 3, name: "rsyslog", kind: "syslog", target: "siem.lan:6514", last_error: "could not connect (siem.lan:6514): refused", last_error_at: 1_790_000_100 }),
        sink({ id: 4, name: "old", gap_rows: 42 }),
      ]),
    );
    renderApp("/admin/audit-forwarding");
    const t = await table();
    expect(within(t).getByRole("row", { name: /^splunk/ })).toHaveTextContent("Up to date");
    expect(within(t).getByRole("row", { name: /dd/ })).toHaveTextContent("120 behind");
    expect(within(t).getByRole("row", { name: /rsyslog/ })).toHaveTextContent("could not connect (siem.lan:6514): refused");
    expect(within(t).getByRole("row", { name: /old/ })).toHaveTextContent("42 rows were removed by retention before they were sent");
  });

  it("adds a Splunk sink", async () => {
    const calls = mockFetch(routes([], { [`POST ${BASE}`]: { status: 201, json: sink() } }));
    renderApp("/admin/audit-forwarding");
    await userEvent.click(await screen.findByRole("button", { name: "Add sink" }));
    const d = await screen.findByRole("dialog", { name: "Add sink" });
    await userEvent.selectOptions(within(d).getByLabelText("Kind"), "splunk_hec");
    expect(within(d).queryByLabelText("Host")).toBeNull();
    await userEvent.type(within(d).getByLabelText("Name"), "splunk");
    await userEvent.type(within(d).getByLabelText("HEC URL"), "https://splunk.example:8088/services/collector/event");
    const token = within(d).getByLabelText("HEC token");
    expect(token).toHaveAttribute("type", "password");
    await userEvent.type(token, "t0ken");
    await userEvent.selectOptions(within(d).getByLabelText("Start from"), "all");
    await userEvent.click(within(d).getByRole("button", { name: "Add" }));
    await waitFor(() =>
      expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({
        name: "splunk",
        kind: "splunk_hec",
        url: "https://splunk.example:8088/services/collector/event",
        token: "t0ken",
        start: "all",
        enabled: true,
      }),
    );
  });

  it("adds a syslog sink over TLS", async () => {
    const calls = mockFetch(routes([], { [`POST ${BASE}`]: { status: 201, json: sink({ kind: "syslog" }) } }));
    renderApp("/admin/audit-forwarding");
    await userEvent.click(await screen.findByRole("button", { name: "Add sink" }));
    const d = await screen.findByRole("dialog", { name: "Add sink" });
    await userEvent.type(within(d).getByLabelText("Name"), "rsyslog");
    await userEvent.type(within(d).getByLabelText("Host"), "siem.lan");
    await userEvent.clear(within(d).getByLabelText("Port"));
    await userEvent.type(within(d).getByLabelText("Port"), "6514");
    await userEvent.selectOptions(within(d).getByLabelText("Transport"), "tls");
    await userEvent.click(within(d).getByRole("button", { name: "Add" }));
    await waitFor(() =>
      expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({ kind: "syslog", host: "siem.lan", port: 6514, transport: "tls" }),
    );
  });

  it("leaves secrets blank when editing and says so", async () => {
    const calls = mockFetch(routes([sink()], { [`PUT ${BASE}/1`]: { json: sink() } }));
    renderApp("/admin/audit-forwarding");
    const t = await table();
    await userEvent.click(within(within(t).getByRole("row", { name: /splunk/ })).getByRole("button", { name: "Edit splunk" }));
    const d = await screen.findByRole("dialog", { name: "Edit splunk" });
    const token = within(d).getByLabelText("HEC token");
    expect(token).toHaveValue("");
    expect(token).toHaveAttribute("placeholder", "Leave blank to keep the current token");
    expect(within(d).queryByLabelText("Start from")).toBeNull();
    await userEvent.click(within(d).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toMatchObject({ name: "splunk", token: "" }));
  });

  it("sends a test", async () => {
    const calls = mockFetch(routes([sink()], { [`POST ${BASE}/1/test`]: { status: 204 } }));
    renderApp("/admin/audit-forwarding");
    const t = await table();
    await userEvent.click(within(t).getByRole("button", { name: "Send test to splunk" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === `${BASE}/1/test`)).toBe(true));
  });

  it("saves retention", async () => {
    const calls = mockFetch(routes([], { "PUT /api/v1/ee/audit/retention": { json: { days: 365, default_days: 90 } } }));
    renderApp("/admin/audit-forwarding");
    const days = await screen.findByLabelText("Keep audit entries for (days)");
    await waitFor(() => expect(days).toHaveValue("90"));
    await userEvent.clear(days);
    await userEvent.type(days, "365");
    await userEvent.click(screen.getByRole("button", { name: "Save retention" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ days: 365 }));
  });
});
