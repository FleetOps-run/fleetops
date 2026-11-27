import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { ENVS, KUBE_ENV, kubeRoutes, loggedIn, renderApp } from "@/test/app";
import { mockFetch } from "@/test/fetch";

const pod = (yaml: string) => ({
  row: { name: "postgres-0", namespace: "db", created: 1, status: "Running", health: "ok", columns: {} },
  yaml,
  conditions: [],
  owners: [],
  containers: ["postgres"],
});
const YAML = "kind: Pod\nspec:\n  containers:\n  - name: postgres\n    ports:\n    - containerPort: 5432\n      name: pg\n";
const MINT = "/api/v1/envs/k/k8s/pods/db/postgres-0/port-forward";

const routes = (extra: Record<string, unknown> = {}) => ({
  ...loggedIn,
  ...kubeRoutes,
  "GET /api/v1/envs/k/k8s/pods/db/postgres-0": { json: pod(YAML) },
  "GET /api/v1/envs/k/k8s/pods/db/postgres-0/events": { json: [] },
  ...extra,
});

describe("port-forward", () => {
  it("is offered only with Shell on pods", async () => {
    mockFetch(routes({ "GET /api/v1/envs": { json: [...ENVS, { ...KUBE_ENV, access: { role: "viewer", namespaces: null } }] } }));
    renderApp("/envs/k/k8s/pods/db/postgres-0");
    await screen.findByRole("heading", { name: "postgres-0" });
    expect(screen.queryByRole("button", { name: "Port-forward" })).toBeNull();
  });

  it("prefills the container port", async () => {
    mockFetch(routes());
    renderApp("/envs/k/k8s/pods/db/postgres-0");
    await userEvent.click(await screen.findByRole("button", { name: "Port-forward" }));
    const d = await screen.findByRole("dialog", { name: "Port-forward to postgres-0" });
    expect(within(d).getByLabelText("Pod port")).toHaveValue("5432");
  });

  it("creates a link and shows the command", async () => {
    const calls = mockFetch(
      routes({ [`POST ${MINT}`]: { status: 201, json: { ticket: "fpt_abc", expires_at: 1_790_000_300, server: null } } }),
    );
    renderApp("/envs/k/k8s/pods/db/postgres-0");
    await userEvent.click(await screen.findByRole("button", { name: "Port-forward" }));
    const d = await screen.findByRole("dialog", { name: "Port-forward to postgres-0" });
    await userEvent.click(within(d).getByRole("button", { name: "Create link" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST" && c.path === MINT)?.body).toEqual({ port: 5432 }));
    expect(
      await within(d).findByText(`fleetops-cli forward --server ${window.location.origin} fpt_abc --local 5432`),
    ).toBeInTheDocument();
    expect(within(d).getByRole("button", { name: "Copy" })).toBeInTheDocument();
    expect(d).toHaveTextContent("5 minutes");
    expect(within(d).getByRole("link", { name: /Download fleetops-cli/ })).toHaveAttribute(
      "href",
      "https://github.com/FleetOps-run/fleetops/releases/latest",
    );
  });

  it("uses the server's public URL when it has one", async () => {
    mockFetch(
      routes({ [`POST ${MINT}`]: { status: 201, json: { ticket: "fpt_abc", expires_at: 1, server: "https://fleet.example.com" } } }),
    );
    renderApp("/envs/k/k8s/pods/db/postgres-0");
    await userEvent.click(await screen.findByRole("button", { name: "Port-forward" }));
    const d = await screen.findByRole("dialog", { name: "Port-forward to postgres-0" });
    await userEvent.click(within(d).getByRole("button", { name: "Create link" }));
    expect(await within(d).findByText("fleetops-cli forward --server https://fleet.example.com fpt_abc --local 5432")).toBeInTheDocument();
  });
});
