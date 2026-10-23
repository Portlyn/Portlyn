import { describe, expect, it } from "vitest";

import { hostMatches, servicePublicURL } from "./service-host";
import type { Service } from "./types";

function service(overrides: Partial<Service>): Partial<Service> {
  return { hostname: "app.example.com", path: "/", ...overrides };
}

describe("servicePublicURL", () => {
  it("drops the root path", () => {
    expect(servicePublicURL(service({ path: "/" }))).toBe("http://app.example.com");
  });

  it("keeps a sub path", () => {
    expect(servicePublicURL(service({ path: "/grafana" }))).toBe("http://app.example.com/grafana");
  });

  it("adds the missing separator when a path was stored without one", () => {
    expect(servicePublicURL(service({ path: "grafana" }))).toBe("http://app.example.com/grafana");
  });

  it("falls back to the domain when no subdomain is set", () => {
    expect(servicePublicURL({ domain: { name: "example.com" } as Service["domain"], path: "/" })).toBe(
      "http://example.com"
    );
  });

  it("returns nothing without a host", () => {
    expect(servicePublicURL({ path: "/" })).toBe("");
    expect(servicePublicURL(null)).toBe("");
  });
});

describe("hostMatches", () => {
  it("matches exact hosts", () => {
    expect(hostMatches("app.example.com", "APP.example.com")).toBe(true);
    expect(hostMatches("app.example.com", "other.example.com")).toBe(false);
  });

  it("matches one label under a wildcard", () => {
    expect(hostMatches("*.example.com", "app.example.com")).toBe(true);
    expect(hostMatches("*.example.com", "a.b.example.com")).toBe(false);
    expect(hostMatches("*.example.com", "example.com")).toBe(false);
  });

  it("has no public url for wildcard services", () => {
    expect(servicePublicURL(service({ hostname: "*.example.com" }))).toBe("");
  });
});
