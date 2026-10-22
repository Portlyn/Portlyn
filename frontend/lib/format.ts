export function hasDate(value?: string | null): value is string {
  if (!value) {
    return false;
  }
  const time = new Date(value).getTime();
  return Number.isFinite(time) && time > 0;
}

export function formatDateTime(value?: string | null, empty = "Never") {
  if (!hasDate(value)) {
    return empty;
  }

  return new Intl.DateTimeFormat("de-DE", {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}

export function formatNumber(value: number, digits = 2) {
  return new Intl.NumberFormat("de-DE", {
    maximumFractionDigits: digits
  }).format(value);
}
