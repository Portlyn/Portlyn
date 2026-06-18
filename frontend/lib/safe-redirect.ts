export function isSafeRelativePath(value: string): boolean {
  if (!value.startsWith("/")) {
    return false;
  }
  if (value.startsWith("//") || value.startsWith("/\\")) {
    return false;
  }
  return true;
}

export function sanitizeReturnTo(raw: string | null | undefined, domainName?: string | null): string | null {
  if (!raw) {
    return null;
  }
  const value = raw.trim();
  if (value === "") {
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
  const host = (domainName || "").trim().toLowerCase();
  if (host && parsed.host.toLowerCase() === host) {
    return value;
  }
  return null;
}
