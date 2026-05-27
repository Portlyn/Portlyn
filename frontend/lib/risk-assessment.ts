import type { Service, ServicePayload } from "@/lib/types";

export type RiskLevel = "none" | "low" | "medium" | "high";

export interface RiskChange {
  field: string;
  label: string;
  before: string;
  after: string;
  level: RiskLevel;
  reason?: string;
}

export interface RiskAssessment {
  level: RiskLevel;
  changes: RiskChange[];
  requiresConfirmation: boolean;
}

const accessModeRank: Record<string, number> = {
  public: 0,
  authenticated: 1,
  restricted: 2,
};

function formatList(value: ReadonlyArray<unknown> | undefined | null): string {
  if (!value || value.length === 0) return "(none)";
  return value.map((item) => String(item)).join(", ");
}

function joinIPList(value: ReadonlyArray<string> | undefined | null): string {
  if (!value || value.length === 0) return "(none)";
  return value.join(", ");
}

export function assessServiceChange(before: Partial<Service> | undefined, after: ServicePayload): RiskAssessment {
  const changes: RiskChange[] = [];

  const beforeMode = (before?.access_mode ?? "authenticated") as string;
  const afterMode = after.access_policy.access_mode;
  if (beforeMode !== afterMode) {
    const beforeRank = accessModeRank[beforeMode] ?? 1;
    const afterRank = accessModeRank[afterMode] ?? 1;
    const stricter = afterRank > beforeRank;
    changes.push({
      field: "access_mode",
      label: "Access mode",
      before: beforeMode,
      after: afterMode,
      level: stricter ? "low" : afterMode === "public" ? "high" : "medium",
      reason: stricter
        ? "Making access stricter is generally safe."
        : afterMode === "public"
        ? "Exposing a service publicly removes authentication entirely."
        : "Loosening the access mode lets more identities reach the upstream.",
    });
  }

  const beforeMethod = (before?.access_method ?? "") || "session";
  const afterMethod = after.access_method || "session";
  if (beforeMethod !== afterMethod) {
    let level: RiskLevel = "low";
    if (beforeMethod === "oidc_only" && afterMethod === "session") {
      level = "medium";
    }
    if (beforeMethod === "pin" && afterMethod === "session") {
      level = "low";
    }
    changes.push({
      field: "access_method",
      label: "Access method",
      before: beforeMethod,
      after: afterMethod,
      level,
      reason: "Switching authentication flow can lock out existing users.",
    });
  }

  const beforeAllowedRoles = (before?.allowed_roles ?? []) as string[];
  const afterAllowedRoles = after.access_policy.allowed_roles;
  if (JSON.stringify(beforeAllowedRoles.slice().sort()) !== JSON.stringify(afterAllowedRoles.slice().sort())) {
    const expanded = afterAllowedRoles.some((role) => !beforeAllowedRoles.includes(role));
    changes.push({
      field: "allowed_roles",
      label: "Allowed roles",
      before: formatList(beforeAllowedRoles),
      after: formatList(afterAllowedRoles),
      level: expanded ? "medium" : "low",
      reason: expanded ? "Granting access to additional roles." : "Removing role access.",
    });
  }

  const beforeAllowedGroups = (before?.allowed_groups ?? []) as number[];
  const afterAllowedGroups = after.access_policy.allowed_groups;
  if (JSON.stringify([...beforeAllowedGroups].sort()) !== JSON.stringify([...afterAllowedGroups].sort())) {
    const expanded = afterAllowedGroups.some((group) => !beforeAllowedGroups.includes(group));
    changes.push({
      field: "allowed_groups",
      label: "Allowed groups",
      before: formatList(beforeAllowedGroups.map((id) => `#${id}`)),
      after: formatList(afterAllowedGroups.map((id) => `#${id}`)),
      level: expanded ? "medium" : "low",
      reason: expanded ? "Granting access to additional groups." : "Removing group access.",
    });
  }

  const beforeAllowlist = (before?.ip_allowlist ?? []) as string[];
  const afterAllowlist = after.ip_allowlist;
  if (JSON.stringify([...beforeAllowlist].sort()) !== JSON.stringify([...afterAllowlist].sort())) {
    const removedAll = beforeAllowlist.length > 0 && afterAllowlist.length === 0;
    changes.push({
      field: "ip_allowlist",
      label: "IP allowlist",
      before: joinIPList(beforeAllowlist),
      after: joinIPList(afterAllowlist),
      level: removedAll ? "high" : "low",
      reason: removedAll
        ? "Removing an existing IP allowlist exposes the service to every network."
        : "Allowlist updated.",
    });
  }

  const beforeBlocklist = (before?.ip_blocklist ?? []) as string[];
  const afterBlocklist = after.ip_blocklist;
  if (JSON.stringify([...beforeBlocklist].sort()) !== JSON.stringify([...afterBlocklist].sort())) {
    changes.push({
      field: "ip_blocklist",
      label: "IP blocklist",
      before: joinIPList(beforeBlocklist),
      after: joinIPList(afterBlocklist),
      level: "low",
    });
  }

  const beforeWindowsCount = (before?.access_windows ?? []).length;
  const afterWindowsCount = after.access_windows.length;
  if (beforeWindowsCount !== afterWindowsCount) {
    const removedAll = beforeWindowsCount > 0 && afterWindowsCount === 0;
    changes.push({
      field: "access_windows",
      label: "Access windows",
      before: `${beforeWindowsCount} window(s)`,
      after: `${afterWindowsCount} window(s)`,
      level: removedAll ? "medium" : "low",
      reason: removedAll ? "Removing all time windows allows access 24/7." : undefined,
    });
  }

  const beforeTarget = before?.target_url ?? "";
  if (beforeTarget && beforeTarget !== after.target_url) {
    changes.push({
      field: "target_url",
      label: "Upstream target",
      before: beforeTarget,
      after: after.target_url,
      level: "medium",
      reason: "Redirecting traffic to a different upstream is a sensitive change — verify the target.",
    });
  }

  const highest: RiskLevel = changes.reduce<RiskLevel>((acc, change) => {
    const order: RiskLevel[] = ["none", "low", "medium", "high"];
    return order.indexOf(change.level) > order.indexOf(acc) ? change.level : acc;
  }, "none");

  return {
    level: highest,
    changes,
    requiresConfirmation: highest === "high",
  };
}

export function riskLevelColor(level: RiskLevel): string {
  switch (level) {
    case "high":
      return "red";
    case "medium":
      return "orange";
    case "low":
      return "yellow";
    case "none":
    default:
      return "gray";
  }
}

export function riskLevelLabel(level: RiskLevel): string {
  switch (level) {
    case "high":
      return "High risk";
    case "medium":
      return "Medium risk";
    case "low":
      return "Low risk";
    case "none":
    default:
      return "No risk";
  }
}
