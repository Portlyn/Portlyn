const UNSAFE_URL_CHARS = /[\u0000- \u007f\\]/;
const RELATIVE_BASE = "http://portlyn.invalid";

function currentOrigin(): string {
  if (typeof window !== "undefined" && window.location?.origin && window.location.origin !== "null") {
    return window.location.origin;
  }
  return RELATIVE_BASE;
}

export function isSafeRelativePath(value: string, origin: string = currentOrigin()): boolean {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) {
    return false;
  }
  if (UNSAFE_URL_CHARS.test(value)) {
    return false;
  }
  let base: URL;
  let parsed: URL;
  try {
    base = new URL(origin);
    parsed = new URL(value, base);
  } catch {
    return false;
  }
  return parsed.origin === base.origin;
}

export function sanitizeReturnTo(raw: string | null | undefined, domainName?: string | null): string | null {
  if (!raw) {
    return null;
  }
  const value = raw.trim();
  if (value === "" || UNSAFE_URL_CHARS.test(value)) {
    return null;
  }
  if (isSafeRelativePath(value)) {
    return value;
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return null;
  }
  if (parsed.username || parsed.password) {
    return null;
  }
  const host = (domainName || "").trim().toLowerCase();
  if (host && parsed.host.toLowerCase() === host) {
    return parsed.toString();
  }
  return null;
}
