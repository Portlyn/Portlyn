import { describe, expect, it } from "vitest";

import { servicePublicURL } from "./service-host";
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
