import { describe, expect, it } from "vitest";

import { isSafeRelativePath, sanitizeReturnTo } from "@/lib/safe-redirect";

describe("isSafeRelativePath", () => {
  it("accepts plain relative paths", () => {
    expect(isSafeRelativePath("/services")).toBe(true);
    expect(isSafeRelativePath("/services?tab=1#anchor")).toBe(true);
  });

  it("rejects protocol-relative and backslash tricks", () => {
    expect(isSafeRelativePath("//evil.example")).toBe(false);
    expect(isSafeRelativePath("/\\evil.example")).toBe(false);
  });

  it("rejects anything that is not rooted", () => {
    expect(isSafeRelativePath("services")).toBe(false);
    expect(isSafeRelativePath("https://evil.example/")).toBe(false);
    expect(isSafeRelativePath("")).toBe(false);
  });
});

describe("sanitizeReturnTo", () => {
  it("passes relative paths through", () => {
    expect(sanitizeReturnTo("/services")).toBe("/services");
  });

  it("drops empty and missing values", () => {
    expect(sanitizeReturnTo(null)).toBeNull();
    expect(sanitizeReturnTo(undefined)).toBeNull();
    expect(sanitizeReturnTo("   ")).toBeNull();
  });

  it("keeps absolute URLs only for the expected host", () => {
    expect(sanitizeReturnTo("https://app.example.com/dash", "app.example.com")).toBe("https://app.example.com/dash");
    expect(sanitizeReturnTo("https://app.example.com/dash", "APP.EXAMPLE.COM")).toBe("https://app.example.com/dash");
    expect(sanitizeReturnTo("https://evil.example/dash", "app.example.com")).toBeNull();
  });

  it("rejects absolute URLs when no host is expected", () => {
    expect(sanitizeReturnTo("https://app.example.com/dash")).toBeNull();
  });

  it("rejects non-http schemes", () => {
    expect(sanitizeReturnTo("javascript:alert(1)", "app.example.com")).toBeNull();
    expect(sanitizeReturnTo("data:text/html,<script>", "app.example.com")).toBeNull();
    expect(sanitizeReturnTo("ftp://app.example.com/x", "app.example.com")).toBeNull();
  });

  it("rejects a host that only looks like the expected one", () => {
    expect(sanitizeReturnTo("https://app.example.com.evil.test/x", "app.example.com")).toBeNull();
    expect(sanitizeReturnTo("https://evil.test/?x=app.example.com", "app.example.com")).toBeNull();
  });

  it("treats userinfo tricks as a foreign host", () => {
    expect(sanitizeReturnTo("https://app.example.com@evil.test/x", "app.example.com")).toBeNull();
  });
});
