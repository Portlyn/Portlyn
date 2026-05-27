import type { AccessMethod, AccessPolicy, AccessWindow, Service, ServiceGroup, ServiceGroupPayload, ServicePayload } from "@/lib/types";

export const defaultAccessPolicy: AccessPolicy = {
  access_mode: "authenticated",
  allowed_roles: [],
  allowed_groups: [],
  allowed_service_groups: []
};

export function legacyAuthPolicyFromAccessMode(policy: AccessPolicy): ServicePayload["auth_policy"] {
  if (policy.access_mode === "public") {
    return "public";
  }
  if (policy.access_mode === "restricted" && policy.allowed_roles.includes("admin") && policy.allowed_roles.length === 1 && policy.allowed_groups.length === 0) {
    return "admin_only";
  }
  return "authenticated";
}

export function accessPolicyFromService(service?: Partial<Service>): AccessPolicy {
  return {
    access_mode: service?.access_mode || "authenticated",
    allowed_roles: [...(service?.allowed_roles || [])],
    allowed_groups: [...(service?.allowed_groups || [])],
    allowed_service_groups: [...(service?.allowed_service_groups || [])]
  };
}

export function defaultServicePayload(service?: Partial<Service>): ServicePayload {
  const accessPolicy = accessPolicyFromService(service);
  return {
    name: service?.name || "",
    domain_id: service?.domain_id || 0,
    subdomain: service?.subdomain || "",
    path: service?.path || "/",
    target_url: service?.target_url || "",
    tls_mode: service?.tls_mode || "offload",
    auth_policy: service?.auth_policy || legacyAuthPolicyFromAccessMode(accessPolicy),
    access_policy: accessPolicy,
    use_group_policy: Boolean(service?.use_group_policy),
    access_method: service?.access_method || "",
    access_method_config: {
      hint: service?.access_method_config?.hint || "",
      allowed_email_domain: service?.access_method_config?.allowed_email_domain || "",
      allowed_emails: [...(service?.access_method_config?.allowed_emails || [])]
    },
    access_message: service?.access_message || "",
    service_group_ids: service?.service_groups?.map((group) => group.id) || [],
    ip_allowlist: [...(service?.ip_allowlist || [])],
    ip_blocklist: [...(service?.ip_blocklist || [])],
    allowed_countries: [...(service?.allowed_countries || [])],
    blocked_countries: [...(service?.blocked_countries || [])],
    access_windows: [...(service?.access_windows || [])],
    node_id: service?.node_id ?? null
  };
}

export function defaultServiceGroupPolicy(group?: Partial<ServiceGroup>): AccessPolicy {
  return {
    access_mode: group?.default_access_policy?.access_mode || "authenticated",
    allowed_roles: [...(group?.default_access_policy?.allowed_roles || [])],
    allowed_groups: [...(group?.default_access_policy?.allowed_groups || [])],
    allowed_service_groups: [...(group?.default_access_policy?.allowed_service_groups || [])]
  };
}

export function defaultServiceGroupPayload(group?: Partial<ServiceGroup>): ServiceGroupPayload {
  return {
    name: group?.name || "",
    description: group?.description || "",
    default_access_policy: defaultServiceGroupPolicy(group),
    access_method: group?.access_method || "",
    access_method_config: {
      hint: group?.access_method_config?.hint || "",
      allowed_email_domain: group?.access_method_config?.allowed_email_domain || "",
      allowed_emails: [...(group?.access_method_config?.allowed_emails || [])]
    },
    service_ids: group?.services?.map((service) => service.id) || []
  };
}

export function accessMethodLabel(value: AccessMethod | undefined) {
  switch (value) {
    case "oidc_only":
      return "SSO required";
    case "pin":
      return "PIN protected";
    case "email_code":
      return "Email code required";
    case "session":
    case "":
    case undefined:
    default:
      return "Session-based";
  }
}

export function linesToList(value: string): string[] {
  return value
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function listToLines(values: string[] | undefined): string {
  return (values || []).join("\n");
}

export function accessWindowLabel(window: AccessWindow) {
  const name = window.name || "Window";
  const days = window.days_of_week.length > 0 ? window.days_of_week.join(", ") : "all days";
  return `${name}: ${days} ${window.start_time}-${window.end_time} ${window.timezone || "UTC"}`;
}

export function buildServiceRequestPayload(values: ServicePayload, options?: { omitEmptyAccessMethod?: boolean }) {
  const payload: Record<string, unknown> = {
    ...values,
    access_method_config: sanitizeAccessMethodConfig(values.access_method, values.access_method_config)
  };
  if (options?.omitEmptyAccessMethod && !values.access_method) {
    delete payload.access_method;
    delete payload.access_method_config;
  }
  if (values.node_id == null) {
    delete payload.node_id;
    payload.clear_node_id = true;
  }
  return payload;
}

export function buildServiceGroupRequestPayload(values: ServiceGroupPayload, options?: { omitEmptyAccessMethod?: boolean }) {
  const payload: Record<string, unknown> = {
    ...values,
    access_method_config: sanitizeAccessMethodConfig(values.access_method, values.access_method_config)
  };
  if (options?.omitEmptyAccessMethod && !values.access_method) {
    delete payload.access_method;
    delete payload.access_method_config;
  }
  return payload;
}

function sanitizeAccessMethodConfig(
  accessMethod: AccessMethod,
  config: { pin?: string; hint?: string; allowed_email_domain?: string; allowed_emails?: string[] }
) {
  const hint = config.hint?.trim() || "";
  const pin = config.pin?.trim() || "";
  const allowedEmailDomain = config.allowed_email_domain?.trim() || "";
  const allowedEmails = (config.allowed_emails || [])
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);

  switch (accessMethod) {
    case "pin":
      return {
        ...(hint ? { hint } : {}),
        ...(pin ? { pin } : {})
      };
    case "email_code":
      return {
        ...(hint ? { hint } : {}),
        ...(allowedEmailDomain ? { allowed_email_domain: allowedEmailDomain } : {}),
        ...(allowedEmails.length > 0 ? { allowed_emails: allowedEmails } : {})
      };
    default:
      return {};
  }
}
