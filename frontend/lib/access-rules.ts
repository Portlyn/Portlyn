export type TagParseResult = { value: string } | { error: string };

function isIPv4(value: string) {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function isIPv6(value: string) {
  if (!value.includes(":") || /[^0-9a-f:.]/i.test(value)) {
    return false;
  }
  try {
    new URL(`http://[${value}]/`);
    return true;
  } catch {
    return false;
  }
}

export function parseSource(raw: string): TagParseResult {
  const trimmed = raw.trim();
  const negated = trimmed.startsWith("!");
  const body = (negated ? trimmed.slice(1) : trimmed).trim();
  if (!body) {
    return { error: "Enter an IP address or CIDR range" };
  }
  const [address, prefix, ...rest] = body.split("/");
  const v4 = isIPv4(address);
  const v6 = !v4 && isIPv6(address);
  if (rest.length > 0 || (!v4 && !v6)) {
    return { error: `${trimmed} is not a valid IP address or CIDR range` };
  }
  if (prefix !== undefined) {
    const bits = Number(prefix);
    if (!/^\d{1,3}$/.test(prefix) || bits > (v4 ? 32 : 128)) {
      return { error: `${trimmed} has an invalid prefix length` };
    }
  }
  return { value: `${negated ? "!" : ""}${body.toLowerCase()}` };
}

export function parsePath(raw: string): TagParseResult {
  let value = raw.trim();
  if (!value) {
    return { error: "Enter a path" };
  }
  if (/[\s?#]/.test(value)) {
    return { error: `${value} must not contain spaces, ? or #` };
  }
  if (!value.startsWith("/")) {
    value = `/${value}`;
  }
  if (value.length > 1) {
    value = value.replace(/\/+$/, "");
  }
  return { value };
}
