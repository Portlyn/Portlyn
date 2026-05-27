"use client";

import {
  Alert,
  Button,
  Card,
  Checkbox,
  Divider,
  Group,
  NumberInput,
  Select,
  Stack,
  Tabs,
  Text,
  TextInput,
  Textarea,
  Title
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useEffect, useState } from "react";

import { AdminOnly } from "@/components/admin-only";
import { useAuth } from "@/components/providers";
import { ApiError, apiFetch } from "@/lib/api";
import type { AuthSettings, SystemOverview } from "@/lib/types";

type AuthSettingsForm = {
  frontend_base_url: string;
  auth_brand_name: string;
  auth_logo_url: string;
  auth_background_color: string;
  auth_background_accent: string;
  auth_panel_color: string;
  auth_button_color: string;
  auth_text_color: string;
  auth_muted_text_color: string;
  auth_login_title: string;
  auth_login_subtitle: string;
  auth_route_login_title: string;
  auth_route_login_subtitle: string;
  auth_forbidden_title: string;
  auth_forbidden_subtitle: string;
  auth_login_password_label: string;
  auth_login_oidc_label: string;
  auth_login_otp_request_label: string;
  auth_login_otp_verify_label: string;
  auth_route_continue_label: string;
  auth_route_oidc_label: string;
  auth_route_pin_label: string;
  auth_route_email_send_label: string;
  auth_route_email_verify_label: string;
  auth_forbidden_retry_label: string;
  oidc_enabled: boolean;
  oidc_issuer_url: string;
  oidc_client_id: string;
  oidc_client_secret: string;
  oidc_redirect_url: string;
  oidc_allowed_email_domains: string;
  oidc_admin_role_claim_path: string;
  oidc_admin_role_value: string;
  oidc_provider_label: string;
  oidc_allow_email_linking: boolean;
  oidc_require_verified_email: boolean;
  otp_enabled: boolean;
  otp_token_ttl_seconds: number;
  otp_request_limit: number;
  otp_request_window_seconds: number;
  require_mfa_for_admins: boolean;
  smtp_enabled: boolean;
  smtp_host: string;
  smtp_port: number;
  smtp_username: string;
  smtp_password: string;
  smtp_from_email: string;
  smtp_from_name: string;
  smtp_encryption: "none" | "starttls" | "implicit_tls";
  smtp_insecure_skip_verify: boolean;
};

function toForm(settings: AuthSettings): AuthSettingsForm {
  return {
    frontend_base_url: settings.frontend_base_url || "",
    auth_brand_name: settings.auth_brand_name || "Portlyn",
    auth_logo_url: settings.auth_logo_url || "/logo.png",
    auth_background_color: settings.auth_background_color || "#0d0e11",
    auth_background_accent: settings.auth_background_accent || "#1f232b",
    auth_panel_color: settings.auth_panel_color || "#181b20",
    auth_button_color: settings.auth_button_color || "#654c96",
    auth_text_color: settings.auth_text_color || "#f4f7fb",
    auth_muted_text_color: settings.auth_muted_text_color || "#9aa3b2",
    auth_login_title: settings.auth_login_title || "Login",
    auth_login_subtitle: settings.auth_login_subtitle || "",
    auth_route_login_title: settings.auth_route_login_title || "Login",
    auth_route_login_subtitle: settings.auth_route_login_subtitle || "",
    auth_forbidden_title: settings.auth_forbidden_title || "Access denied",
    auth_forbidden_subtitle: settings.auth_forbidden_subtitle || "You do not have permission to access this route.",
    auth_login_password_label: settings.auth_login_password_label || "Login",
    auth_login_oidc_label: settings.auth_login_oidc_label || "Continue with SSO",
    auth_login_otp_request_label: settings.auth_login_otp_request_label || "Request code",
    auth_login_otp_verify_label: settings.auth_login_otp_verify_label || "Verify code",
    auth_route_continue_label: settings.auth_route_continue_label || "Continue",
    auth_route_oidc_label: settings.auth_route_oidc_label || "Continue with SSO",
    auth_route_pin_label: settings.auth_route_pin_label || "Unlock",
    auth_route_email_send_label: settings.auth_route_email_send_label || "Send code",
    auth_route_email_verify_label: settings.auth_route_email_verify_label || "Verify code",
    auth_forbidden_retry_label: settings.auth_forbidden_retry_label || "Try again",
    oidc_enabled: settings.oidc_enabled,
    oidc_issuer_url: settings.oidc_issuer_url || "",
    oidc_client_id: settings.oidc_client_id || "",
    oidc_client_secret: "",
    oidc_redirect_url: settings.oidc_redirect_url || "",
    oidc_allowed_email_domains: (settings.oidc_allowed_email_domains || []).join(", "),
    oidc_admin_role_claim_path: settings.oidc_admin_role_claim_path || "realm_access.roles",
    oidc_admin_role_value: settings.oidc_admin_role_value || "",
    oidc_provider_label: settings.oidc_provider_label || "SSO",
    oidc_allow_email_linking: settings.oidc_allow_email_linking,
    oidc_require_verified_email: settings.oidc_require_verified_email,
    otp_enabled: settings.otp_enabled,
    otp_token_ttl_seconds: settings.otp_token_ttl_seconds || 600,
    otp_request_limit: settings.otp_request_limit || 5,
    otp_request_window_seconds: settings.otp_request_window_seconds || 900,
    require_mfa_for_admins: settings.require_mfa_for_admins,
    smtp_enabled: settings.smtp_enabled,
    smtp_host: settings.smtp_host || "",
    smtp_port: settings.smtp_port || 587,
    smtp_username: settings.smtp_username || "",
    smtp_password: "",
    smtp_from_email: settings.smtp_from_email || "",
    smtp_from_name: settings.smtp_from_name || "",
    smtp_encryption: settings.smtp_encryption || "starttls",
    smtp_insecure_skip_verify: settings.smtp_insecure_skip_verify
  };
}

export default function SettingsPage() {
  const { user } = useAuth();
  const [settings, setSettings] = useState<AuthSettings | null>(null);
  const [form, setForm] = useState<AuthSettingsForm | null>(null);
  const [testEmail, setTestEmail] = useState("");
  const [overview, setOverview] = useState<SystemOverview | null>(null);
  const [activeTab, setActiveTab] = useState<string>("general");
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await apiFetch<AuthSettings>("/api/v1/settings/auth");
      const systemOverview = await apiFetch<SystemOverview>("/api/v1/system/overview");
      setSettings(response);
      setOverview(systemOverview);
      setForm(toForm(response));
      setTestEmail(user?.email || "");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load settings.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, [user?.email]);

  const update = <K extends keyof AuthSettingsForm>(key: K, value: AuthSettingsForm[K]) => {
    setForm((current) => (current ? { ...current, [key]: value } : current));
  };

  const handleSave = async () => {
    if (!form) return;
    setIsSaving(true);
    try {
      const payload = {
        ...form,
        oidc_allowed_email_domains: form.oidc_allowed_email_domains
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean)
      };
      const response = await apiFetch<AuthSettings>("/api/v1/settings/auth", {
        method: "PATCH",
        body: JSON.stringify(payload)
      });
      setSettings(response);
      setForm(toForm(response));
      notifications.show({ color: "success", message: "Authentication settings updated" });
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to save settings." });
    } finally {
      setIsSaving(false);
    }
  };

  const handleSendTest = async () => {
    setIsSending(true);
    try {
      await apiFetch<{ ok: boolean }>("/api/v1/settings/auth/test-email", {
        method: "POST",
        body: JSON.stringify({ email: testEmail })
      });
      notifications.show({ color: "success", message: "Test email sent" });
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to send test email." });
    } finally {
      setIsSending(false);
    }
  };

  return (
    <AdminOnly>
      <Stack gap="lg">
        <div>
          <Title order={2}>Authentication & Mail</Title>
        </div>

        {error ? <Alert color="danger" variant="light">{error}</Alert> : null}
        {isLoading || !form ? <Text c="dimmed">Loading settings...</Text> : (
          <>
            <Tabs value={activeTab} onChange={(value) => setActiveTab(value || "general")}>
              <Tabs.List>
                <Tabs.Tab value="general">General</Tabs.Tab>
                <Tabs.Tab value="auth-ui">Auth UI</Tabs.Tab>
                <Tabs.Tab value="oidc">OIDC</Tabs.Tab>
                <Tabs.Tab value="otp">OTP</Tabs.Tab>
                <Tabs.Tab value="smtp">SMTP</Tabs.Tab>
                <Tabs.Tab value="proxy">Proxy</Tabs.Tab>
                <Tabs.Tab value="security">Security</Tabs.Tab>
              </Tabs.List>
            </Tabs>

            {activeTab === "general" ? (
            <Card withBorder>
              <Stack gap="md">
                <Text fw={600}>General / Runtime</Text>
                <TextInput
                  label="Frontend base URL"
                  description="Used for route-login redirects and OIDC flow handoff."
                  value={form.frontend_base_url}
                  onChange={(event) => update("frontend_base_url", event.currentTarget.value)}
                />
                {overview ? (
                  <Stack gap="sm">
                    <Alert color="brand" variant="light">
                      API {overview.runtime.http_addr} | Proxy HTTP {overview.runtime.proxy_http_addr} | Proxy HTTPS {overview.runtime.proxy_https_addr || "disabled"} | Version {overview.runtime.version}
                    </Alert>
                    <Alert color="gray" variant="light">
                      ACME {overview.runtime.acme_enabled ? "enabled" : "disabled"} | Challenge types {overview.runtime.acme_challenge_types.join(", ")} | DNS providers {overview.counts.dns_providers} | Supported issuers {overview.certificates.supported_issuers.join(", ")}
                    </Alert>
                  </Stack>
                ) : null}
              </Stack>
            </Card>
            ) : null}

            {activeTab === "auth-ui" ? (
            <Card withBorder>
              <Stack gap="md">
                <Text fw={600}>Auth pages</Text>
                <TextInput
                  label="Brand name"
                  value={form.auth_brand_name}
                  onChange={(event) => update("auth_brand_name", event.currentTarget.value)}
                />
                <TextInput
                  label="Logo URL"
                  value={form.auth_logo_url}
                  onChange={(event) => update("auth_logo_url", event.currentTarget.value)}
                />
                <Group grow>
                  <TextInput
                    label="Background"
                    value={form.auth_background_color}
                    onChange={(event) => update("auth_background_color", event.currentTarget.value)}
                  />
                  <TextInput
                    label="Background accent"
                    value={form.auth_background_accent}
                    onChange={(event) => update("auth_background_accent", event.currentTarget.value)}
                  />
                </Group>
                <Group grow>
                  <TextInput
                    label="Panel"
                    value={form.auth_panel_color}
                    onChange={(event) => update("auth_panel_color", event.currentTarget.value)}
                  />
                  <TextInput
                    label="Button"
                    value={form.auth_button_color}
                    onChange={(event) => update("auth_button_color", event.currentTarget.value)}
                  />
                </Group>
                <Group grow>
                  <TextInput
                    label="Text"
                    value={form.auth_text_color}
                    onChange={(event) => update("auth_text_color", event.currentTarget.value)}
                  />
                  <TextInput
                    label="Muted text"
                    value={form.auth_muted_text_color}
                    onChange={(event) => update("auth_muted_text_color", event.currentTarget.value)}
                  />
                </Group>

                <Divider />

                <Text fw={600}>Login page</Text>
                <TextInput
                  label="Title"
                  value={form.auth_login_title}
                  onChange={(event) => update("auth_login_title", event.currentTarget.value)}
                />
                <Textarea
                  label="Subtitle"
                  minRows={2}
                  value={form.auth_login_subtitle}
                  onChange={(event) => update("auth_login_subtitle", event.currentTarget.value)}
                />
                <Group grow>
                  <TextInput
                    label="Password button"
                    value={form.auth_login_password_label}
                    onChange={(event) => update("auth_login_password_label", event.currentTarget.value)}
                  />
                  <TextInput
                    label="OIDC button"
                    value={form.auth_login_oidc_label}
                    onChange={(event) => update("auth_login_oidc_label", event.currentTarget.value)}
                  />
                </Group>
                <Group grow>
                  <TextInput
                    label="OTP request button"
                    value={form.auth_login_otp_request_label}
                    onChange={(event) => update("auth_login_otp_request_label", event.currentTarget.value)}
                  />
                  <TextInput
                    label="OTP verify button"
                    value={form.auth_login_otp_verify_label}
                    onChange={(event) => update("auth_login_otp_verify_label", event.currentTarget.value)}
                  />
                </Group>

                <Divider />

                <Text fw={600}>Route login page</Text>
                <TextInput
                  label="Title"
                  value={form.auth_route_login_title}
                  onChange={(event) => update("auth_route_login_title", event.currentTarget.value)}
                />
                <Textarea
                  label="Subtitle"
                  minRows={2}
                  value={form.auth_route_login_subtitle}
                  onChange={(event) => update("auth_route_login_subtitle", event.currentTarget.value)}
                />
                <Group grow>
                  <TextInput
                    label="Continue button"
                    value={form.auth_route_continue_label}
                    onChange={(event) => update("auth_route_continue_label", event.currentTarget.value)}
                  />
                  <TextInput
                    label="OIDC button"
                    value={form.auth_route_oidc_label}
                    onChange={(event) => update("auth_route_oidc_label", event.currentTarget.value)}
                  />
                </Group>
                <Group grow>
                  <TextInput
                    label="PIN button"
                    value={form.auth_route_pin_label}
                    onChange={(event) => update("auth_route_pin_label", event.currentTarget.value)}
                  />
                  <TextInput
                    label="Email send button"
                    value={form.auth_route_email_send_label}
                    onChange={(event) => update("auth_route_email_send_label", event.currentTarget.value)}
                  />
                </Group>
                <TextInput
                  label="Email verify button"
                  value={form.auth_route_email_verify_label}
                  onChange={(event) => update("auth_route_email_verify_label", event.currentTarget.value)}
                />

                <Divider />

                <Text fw={600}>Access denied page</Text>
                <TextInput
                  label="Title"
                  value={form.auth_forbidden_title}
                  onChange={(event) => update("auth_forbidden_title", event.currentTarget.value)}
                />
                <Textarea
                  label="Subtitle"
                  minRows={2}
                  value={form.auth_forbidden_subtitle}
                  onChange={(event) => update("auth_forbidden_subtitle", event.currentTarget.value)}
                />
                <TextInput
                  label="Retry button"
                  value={form.auth_forbidden_retry_label}
                  onChange={(event) => update("auth_forbidden_retry_label", event.currentTarget.value)}
                />
              </Stack>
            </Card>
            ) : null}

            {activeTab === "oidc" ? (
            <Card withBorder>
              <Stack gap="md">
                <Group justify="space-between">
                  <Text fw={600}>OIDC / SSO</Text>
                  <Checkbox checked={form.oidc_enabled} onChange={(event) => update("oidc_enabled", event.currentTarget.checked)} label="Enabled" />
                </Group>
                <TextInput label="Issuer URL" value={form.oidc_issuer_url} onChange={(event) => update("oidc_issuer_url", event.currentTarget.value)} />
                <TextInput label="Client ID" value={form.oidc_client_id} onChange={(event) => update("oidc_client_id", event.currentTarget.value)} />
                <TextInput
                  label="Client Secret"
                  description={settings?.oidc_client_secret_configured ? "Leave blank to keep the existing secret." : undefined}
                  value={form.oidc_client_secret}
                  onChange={(event) => update("oidc_client_secret", event.currentTarget.value)}
                />
                <TextInput label="Redirect URL" value={form.oidc_redirect_url} onChange={(event) => update("oidc_redirect_url", event.currentTarget.value)} />
                <TextInput
                  label="Allowed email domains"
                  description="Comma-separated, optional."
                  value={form.oidc_allowed_email_domains}
                  onChange={(event) => update("oidc_allowed_email_domains", event.currentTarget.value)}
                />
                <TextInput label="Admin role claim path" value={form.oidc_admin_role_claim_path} onChange={(event) => update("oidc_admin_role_claim_path", event.currentTarget.value)} />
                <TextInput label="Admin role value" value={form.oidc_admin_role_value} onChange={(event) => update("oidc_admin_role_value", event.currentTarget.value)} />
                <TextInput label="Provider label" value={form.oidc_provider_label} onChange={(event) => update("oidc_provider_label", event.currentTarget.value)} />
                <Checkbox checked={form.oidc_allow_email_linking} onChange={(event) => update("oidc_allow_email_linking", event.currentTarget.checked)} label="Allow email linking" />
                <Checkbox checked={form.oidc_require_verified_email} onChange={(event) => update("oidc_require_verified_email", event.currentTarget.checked)} label="Require verified email" />
              </Stack>
            </Card>
            ) : null}

            {activeTab === "otp" ? (
            <Card withBorder>
              <Stack gap="md">
                <Group justify="space-between">
                  <Text fw={600}>OTP / Email</Text>
                  <Checkbox checked={form.otp_enabled} onChange={(event) => update("otp_enabled", event.currentTarget.checked)} label="Enabled" />
                </Group>
                <NumberInput label="Token TTL (seconds)" min={60} value={form.otp_token_ttl_seconds} onChange={(value) => update("otp_token_ttl_seconds", Number(value) || 600)} />
                <NumberInput label="Request limit" min={1} value={form.otp_request_limit} onChange={(value) => update("otp_request_limit", Number(value) || 5)} />
                <NumberInput label="Request window (seconds)" min={60} value={form.otp_request_window_seconds} onChange={(value) => update("otp_request_window_seconds", Number(value) || 900)} />
                <Checkbox checked={form.require_mfa_for_admins} onChange={(event) => update("require_mfa_for_admins", event.currentTarget.checked)} label="Require MFA for admin users" />
              </Stack>
            </Card>
            ) : null}

            {activeTab === "smtp" ? (
            <Card withBorder>
              <Stack gap="md">
                <Group justify="space-between">
                  <Text fw={600}>SMTP</Text>
                  <Checkbox checked={form.smtp_enabled} onChange={(event) => update("smtp_enabled", event.currentTarget.checked)} label="Enabled" />
                </Group>
                <TextInput label="Host" value={form.smtp_host} onChange={(event) => update("smtp_host", event.currentTarget.value)} />
                <NumberInput label="Port" min={1} value={form.smtp_port} onChange={(value) => update("smtp_port", Number(value) || 587)} />
                <TextInput label="Username" value={form.smtp_username} onChange={(event) => update("smtp_username", event.currentTarget.value)} />
                <TextInput
                  label="Password"
                  description={settings?.smtp_password_configured ? "Leave blank to keep the existing password." : undefined}
                  value={form.smtp_password}
                  onChange={(event) => update("smtp_password", event.currentTarget.value)}
                />
                <TextInput label="From email" value={form.smtp_from_email} onChange={(event) => update("smtp_from_email", event.currentTarget.value)} />
                <TextInput label="From name" value={form.smtp_from_name} onChange={(event) => update("smtp_from_name", event.currentTarget.value)} />
                <Select
                  label="Encryption"
                  data={[
                    { value: "starttls", label: "STARTTLS" },
                    { value: "implicit_tls", label: "Implicit TLS" },
                    { value: "none", label: "Plain" }
                  ]}
                  value={form.smtp_encryption}
                  onChange={(value) => update("smtp_encryption", (value || "starttls") as AuthSettingsForm["smtp_encryption"])}
                />
                <Checkbox checked={form.smtp_insecure_skip_verify} onChange={(event) => update("smtp_insecure_skip_verify", event.currentTarget.checked)} label="Skip TLS certificate verification" />
                <Group align="end">
                  <TextInput
                    label="Test email recipient"
                    value={testEmail}
                    onChange={(event) => setTestEmail(event.currentTarget.value)}
                    style={{ flex: 1 }}
                  />
                  <Button variant="default" loading={isSending} onClick={handleSendTest} disabled={!testEmail}>
                    Send test email
                  </Button>
                </Group>
              </Stack>
            </Card>
            ) : null}

            {activeTab === "proxy" ? (
            <Card withBorder>
              <Stack gap="md">
                <Text fw={600}>Proxy / TLS / ACME</Text>
                <Text size="sm" c="dimmed">Proxy HTTP address: {overview?.runtime.proxy_http_addr || "n/a"}</Text>
                <Text size="sm" c="dimmed">Proxy HTTPS address: {overview?.runtime.proxy_https_addr || "disabled"}</Text>
                <Text size="sm" c="dimmed">TLS enabled: {overview?.runtime.tls_enabled ? "yes" : "no"}</Text>
                <Text size="sm" c="dimmed">ACME enabled: {overview?.runtime.acme_enabled ? "yes" : "no"}</Text>
                <Text size="sm" c="dimmed">Redirect HTTP to HTTPS: {overview?.runtime.redirect_http_to_https ? "yes" : "no"}</Text>
              </Stack>
            </Card>
            ) : null}

            {activeTab === "security" ? (
            <Card withBorder>
              <Stack gap="md">
                <Text fw={600}>Security</Text>
                <Text size="sm" c="dimmed">JWT TTL: {settings?.jwt_ttl_seconds || 0} seconds</Text>
                <Text size="sm" c="dimmed">Refresh token TTL: {settings?.refresh_token_ttl_seconds || 0} seconds</Text>
                <Text size="sm" c="dimmed">Rate limit attempts: {settings?.auth_rate_limit_attempts || 0}</Text>
                <Text size="sm" c="dimmed">Rate limit window: {settings?.auth_rate_limit_window_seconds || 0} seconds</Text>
                <Text size="sm" c="dimmed">CSRF protection: {settings?.csrf_enabled ? "enabled" : "disabled"}</Text>
                <Text size="sm" c="dimmed">Session cookie: Secure={settings?.cookie_secure ? "yes" : "no"} HttpOnly={settings?.cookie_http_only ? "yes" : "no"} SameSite={settings?.cookie_same_site_session || "n/a"}</Text>
                <Text size="sm" c="dimmed">Refresh cookie SameSite: {settings?.cookie_same_site_refresh || "n/a"}</Text>
                <Text size="sm" c="dimmed">Admin MFA required: {settings?.require_mfa_for_admins ? "yes" : "no"}</Text>
                <Text size="sm" c="dimmed">Runtime cookies secure: {overview?.security.cookie_secure ? "yes" : "no"}</Text>
                <Text size="sm" c="dimmed">Runtime CSRF active: {overview?.security.csrf_enabled ? "yes" : "no"}</Text>
                <Text size="sm" c="dimmed">Security headers: {overview?.security.security_headers_enabled ? "enabled" : "disabled"}</Text>
                <Text size="sm" c="dimmed">Admins without MFA: {overview?.security.admins_without_mfa ?? 0}</Text>
                <Text size="sm" c="dimmed">Node heartbeat auth: {overview?.security.node_heartbeat_auth_mode} {overview?.security.node_mtls_enabled ? "+ mTLS" : "(mTLS pending)"}</Text>
              </Stack>
            </Card>
            ) : null}

            <Group justify="flex-end">
              <Button loading={isSaving} onClick={handleSave}>
                Save settings
              </Button>
            </Group>
          </>
        )}
      </Stack>
    </AdminOnly>
  );
}
