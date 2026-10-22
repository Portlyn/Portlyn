import { describe, expect, it } from "vitest";

import { parsePath, parseSource } from "./access-rules";

describe("parseSource", () => {
  it.each([
    ["8.8.8.8", "8.8.8.8"],
    [" 8.8.8.0/24 ", "8.8.8.0/24"],
    ["!8.8.8.8", "!8.8.8.8"],
    ["! 10.0.0.0/8", "!10.0.0.0/8"],
    ["2001:DB8::1", "2001:db8::1"],
    ["2001:db8::/32", "2001:db8::/32"]
  ])("accepts %s", (raw, value) => {
    expect(parseSource(raw)).toEqual({ value });
  });

  it.each(["8.8.8", "8.8.8.256", "8.8.8.0/33", "2001:db8::/129", "example.com", "!", "1.2.3.4/24/1", "8.8.8.8/"])("rejects %s", (raw) => {
    expect(parseSource(raw)).toHaveProperty("error");
  });
});

describe("parsePath", () => {
  it.each([
    ["/admin", "/admin"],
    ["admin", "/admin"],
    ["/api/*/export/", "/api/*/export"],
    ["/", "/"]
  ])("normalizes %s", (raw, value) => {
    expect(parsePath(raw)).toEqual({ value });
  });

  it.each(["/a b", "/a?x=1", "/a#top", ""])("rejects %s", (raw) => {
    expect(parsePath(raw)).toHaveProperty("error");
  });
});
