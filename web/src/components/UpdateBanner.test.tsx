import { waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { mockFetch } from "@/test/fetch";
import { ADMIN, loggedIn, renderApp } from "@/test/app";

const version = (latest: string | null, update_available: boolean) => ({
  json: {
    current: "1.5.0",
    latest,
    update_available,
    release_url: latest && `https://github.com/FleetOps-run/fleetops/releases/tag/${latest}`,
    checked_at: latest ? 1 : null,
    check_enabled: true,
  },
});

describe("update banner", () => {
  it("shows when a newer release exists", async () => {
    mockFetch({ ...loggedIn, "GET /api/v1/system/version": version("v1.6.0", true) });
    const { screen } = renderApp("/envs/local");
    expect(await screen.findByText(/FleetOps v1\.6\.0 is available/)).toBeInTheDocument();
    expect(screen.getByText(/you're on v1\.5\.0/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Release notes/ })).toHaveAttribute(
      "href",
      "https://github.com/FleetOps-run/fleetops/releases/tag/v1.6.0",
    );
  });

  it("is hidden when up to date", async () => {
    const calls = mockFetch({ ...loggedIn, "GET /api/v1/system/version": version("v1.5.0", false) });
    const { screen } = renderApp("/envs/local");
    await screen.findByRole("heading", { name: "local" });
    await waitFor(() => expect(calls.some((c) => c.path === "/api/v1/system/version")).toBe(true));
    expect(screen.queryByText(/is available/)).toBeNull();
  });

  it("dismissing hides it and remembers the version", async () => {
    mockFetch({ ...loggedIn, "GET /api/v1/system/version": version("v1.6.0", true) });
    const { screen } = renderApp("/envs/local");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Dismiss update notice" }));
    expect(screen.queryByText(/is available/)).toBeNull();
    expect(localStorage.getItem("fleetops.update.dismissed")).toBe("v1.6.0");
  });

  it("stays hidden for a dismissed version", async () => {
    localStorage.setItem("fleetops.update.dismissed", "v1.6.0");
    const calls = mockFetch({ ...loggedIn, "GET /api/v1/system/version": version("v1.6.0", true) });
    const { screen } = renderApp("/envs/local");
    await screen.findByRole("heading", { name: "local" });
    await waitFor(() => expect(calls.some((c) => c.path === "/api/v1/system/version")).toBe(true));
    expect(screen.queryByText(/is available/)).toBeNull();
  });

  it("comes back for a release newer than the dismissed one", async () => {
    localStorage.setItem("fleetops.update.dismissed", "v1.6.0");
    mockFetch({ ...loggedIn, "GET /api/v1/system/version": version("v1.7.0", true) });
    const { screen } = renderApp("/envs/local");
    expect(await screen.findByText(/FleetOps v1\.7\.0 is available/)).toBeInTheDocument();
  });

  it("never asks for non-admins", async () => {
    const calls = mockFetch({
      ...loggedIn,
      "GET /api/v1/auth/me": { json: { ...ADMIN, user: { ...ADMIN.user, username: "bob", role: "user" } } },
      "GET /api/v1/system/version": version("v1.6.0", true),
    });
    const { screen } = renderApp("/envs/local");
    await screen.findByRole("heading", { name: "local" });
    expect(screen.queryByText(/is available/)).toBeNull();
    expect(calls.some((c) => c.path === "/api/v1/system/version")).toBe(false);
  });
});
