"use client";

import { Badge, Tooltip } from "@mantine/core";

import { accessMethodLabel } from "@/lib/access-control";
import type { AccessMethod, AccessMode, AuthPolicy } from "@/lib/types";

export function StatusBadge({ status }: { status: string }) {
  const normalized = status.toLowerCase();
  let color: string;
  if (normalized === "online" || normalized === "healthy" || normalized === "active" || normalized === "ok" || normalized === "mfa") {
    color = "success";
  } else if (normalized === "unhealthy" || normalized === "error" || normalized === "revoked") {
    color = "danger";
  } else if (normalized === "offline" || normalized === "inactive") {
    color = "gray";
  } else if (normalized === "warning" || normalized === "warn" || normalized === "pending" || normalized === "degraded") {
    color = "warning";
  } else {
    color = "gray";
  }
  return (
    <Badge color={color}>
      {status.replace("_", " ")}
    </Badge>
  );
}

export function AuthPolicyBadge({ value }: { value: AuthPolicy }) {
  const color = value === "public" ? "info" : value === "authenticated" ? "brand" : "warning";
  return <Badge color={color}>{value}</Badge>;
}

export function AccessModeBadge({ value }: { value: AccessMode }) {
  const color = value === "public" ? "info" : value === "authenticated" ? "brand" : "warning";
  return <Badge color={color}>{value}</Badge>;
}

export function AccessMethodBadge({ value }: { value: AccessMethod | undefined }) {
  const normalized = value || "session";
  const color =
    normalized === "oidc_only" ? "brand" : normalized === "pin" ? "warning" : normalized === "email_code" ? "accent" : "gray";
  return <Badge color={color}>{accessMethodLabel(normalized)}</Badge>;
}

export function RiskBadge({ value }: { value: string | undefined }) {
  const normalized = (value || "low").toLowerCase();
  const color = normalized === "high" ? "danger" : normalized === "medium" ? "warning" : "success";
  return (
    <Tooltip label="Exposure risk based on access mode, method and network rules" withArrow>
      <Badge color={color}>{normalized} risk</Badge>
    </Tooltip>
  );
}
