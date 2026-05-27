"use client";

import {
  Button,
  Checkbox,
  Divider,
  Grid,
  Group,
  MultiSelect,
  Paper,
  Select,
  Stack,
  Switch,
  Tabs,
  Text,
  TextInput,
  Textarea
} from "@mantine/core";
import { useEffect, useState } from "react";

import { AccessPolicyFields } from "@/components/access-policy-fields";
import { RiskyChangeModal } from "@/components/services/risky-change-modal";
import { accessWindowLabel, defaultServicePayload, linesToList, listToLines } from "@/lib/access-control";
import { countryOptions } from "@/lib/countries";
import { assessServiceChange, type RiskAssessment } from "@/lib/risk-assessment";
import { buildServiceHostname } from "@/lib/service-host";
import type {
  AccessWindow,
  Domain,
  Group as UserGroup,
  Node as PortlynNode,
  Service,
  ServiceGroup,
  ServicePayload,
  TLSMode
} from "@/lib/types";

const days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];

const blankWindow: AccessWindow = {
  name: "",
  days_of_week: ["monday", "tuesday", "wednesday", "thursday", "friday"],
  start_time: "09:00",
  end_time: "18:00",
  timezone: "UTC"
};

export function ServiceForm({
  domains,
  groups,
  serviceGroups,
  nodes,
  initialValues,
  onSubmit,
  submitLabel,
  isLoading,
  inheritedFrom,
  confirmRiskyChanges
}: {
  domains: Domain[];
  groups: UserGroup[];
  serviceGroups: ServiceGroup[];
  nodes?: PortlynNode[];
  initialValues?: Partial<Service>;
  onSubmit: (values: ServicePayload) => Promise<void>;
  submitLabel: string;
  isLoading?: boolean;
  inheritedFrom?: string | null;
  confirmRiskyChanges?: boolean;
}) {
  const [values, setValues] = useState<ServicePayload>(defaultServicePayload(initialValues));
  const [allowlistText, setAllowlistText] = useState(listToLines(initialValues?.ip_allowlist));
  const [blocklistText, setBlocklistText] = useState(listToLines(initialValues?.ip_blocklist));
  const [emailWhitelistText, setEmailWhitelistText] = useState(listToLines(initialValues?.access_method_config?.allowed_emails));
  const [windowDraft, setWindowDraft] = useState<AccessWindow>(blankWindow);
  const [riskAssessment, setRiskAssessment] = useState<RiskAssessment | null>(null);
  const [pendingValues, setPendingValues] = useState<ServicePayload | null>(null);

  useEffect(() => {
    const next = defaultServicePayload(initialValues);
    setValues(next);
    setAllowlistText(listToLines(next.ip_allowlist));
    setBlocklistText(listToLines(next.ip_blocklist));
    setEmailWhitelistText(listToLines(next.access_method_config.allowed_emails));
  }, [initialValues]);

  const update = <K extends keyof ServicePayload>(key: K, value: ServicePayload[K]) => {
    setValues((current) => ({ ...current, [key]: value }));
  };

  const selectedDomain = domains.find((domain) => domain.id === values.domain_id);
  const hostnamePreview = buildServiceHostname(selectedDomain?.name, values.subdomain);

  const buildSubmitPayload = (): ServicePayload => ({
    ...values,
    auth_policy: values.use_group_policy ? "authenticated" : values.auth_policy,
    access_method_config: {
      ...values.access_method_config,
      allowed_emails: linesToList(emailWhitelistText)
    },
    ip_allowlist: linesToList(allowlistText),
    ip_blocklist: linesToList(blocklistText)
  });

  const handleSubmit = async () => {
    const payload = buildSubmitPayload();
    if (confirmRiskyChanges && initialValues) {
      const assessment = assessServiceChange(initialValues, payload);
      if (assessment.changes.length > 0) {
        setRiskAssessment(assessment);
        setPendingValues(payload);
        return;
      }
    }
    await onSubmit(payload);
  };

  const handleConfirmPending = async () => {
    if (!pendingValues) return;
    await onSubmit(pendingValues);
    setPendingValues(null);
    setRiskAssessment(null);
  };

  const handleCancelPending = () => {
    setPendingValues(null);
    setRiskAssessment(null);
  };

  return (
    <Stack gap="lg">
      <Tabs defaultValue="general">
        <Tabs.List>
          <Tabs.Tab value="general">General</Tabs.Tab>
          <Tabs.Tab value="access">Access</Tabs.Tab>
          <Tabs.Tab value="network">Network</Tabs.Tab>
          <Tabs.Tab value="windows">Windows</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="general" pt="md">
          <Paper withBorder radius="md" p="md">
            <Grid>
              <Grid.Col span={{ base: 12, md: 6 }}>
                <TextInput label="Name" value={values.name} onChange={(event) => update("name", event.currentTarget.value)} />
              </Grid.Col>
              <Grid.Col span={{ base: 12, md: 6 }}>
                <Select
                  label="Root domain"
                  data={domains.map((domain) => ({ value: String(domain.id), label: domain.name }))}
                  value={values.domain_id ? String(values.domain_id) : null}
                  onChange={(value) => update("domain_id", Number(value || 0))}
                  disabled={domains.length === 0}
                />
              </Grid.Col>
              <Grid.Col span={{ base: 12, md: 6 }}>
                <TextInput
                  label="Subdomain"
                  value={values.subdomain}
                  onChange={(event) => update("subdomain", event.currentTarget.value)}
                />
              </Grid.Col>
              <Grid.Col span={{ base: 12, md: 6 }}>
                <TextInput label="Path" value={values.path} onChange={(event) => update("path", event.currentTarget.value)} />
              </Grid.Col>
              <Grid.Col span={{ base: 12, md: 6 }}>
                <TextInput label="Target URL" value={values.target_url} onChange={(event) => update("target_url", event.currentTarget.value)} />
              </Grid.Col>
              <Grid.Col span={12}>
                <Text size="sm" c="dimmed">
                  Public host: {hostnamePreview || "Select a root domain"}
                </Text>
              </Grid.Col>
              <Grid.Col span={{ base: 12, md: 6 }}>
                <Select
                  label="TLS Mode"
                  data={[
                    { value: "offload", label: "offload" },
                    { value: "passthrough", label: "passthrough" },
                    { value: "none", label: "none" }
                  ]}
                  value={values.tls_mode}
                  onChange={(value) => update("tls_mode", (value || "offload") as TLSMode)}
                />
              </Grid.Col>
              <Grid.Col span={{ base: 12, md: 6 }}>
                <MultiSelect
                  label="Service groups"
                  data={serviceGroups.map((group) => ({ value: String(group.id), label: group.name }))}
                  value={values.service_group_ids.map(String)}
                  onChange={(next) => update("service_group_ids", next.map(Number))}
                  searchable
                  clearable
                />
              </Grid.Col>
              {nodes && nodes.length > 0 ? (
                <Grid.Col span={12}>
                  <Select
                    label="Route via tunnel node"
                    description="Optional. If set, traffic is forwarded over the Wireguard tunnel to this node's tunnel IP instead of directly hitting the target host."
                    data={[
                      { value: "", label: "Direct (no tunnel)" },
                      ...nodes
                        .filter((node) => (node.wg_tunnel_ip?.length ?? 0) > 0)
                        .map((node) => ({
                          value: String(node.id),
                          label: `${node.name} — ${node.wg_tunnel_ip} (${node.tunnel_status || "inactive"})`,
                        })),
                    ]}
                    value={values.node_id ? String(values.node_id) : ""}
                    onChange={(value) => update("node_id", value ? Number(value) : null)}
                    clearable
                  />
                </Grid.Col>
              ) : null}
            </Grid>
          </Paper>
        </Tabs.Panel>

        <Tabs.Panel value="access" pt="md">
          <Stack gap="md">
            <Paper withBorder radius="md" p="md">
              <Stack gap="sm">
                <Group justify="space-between">
                  <Text fw={600}>Access control</Text>
                  <Checkbox
                    label="Use inherited service-group policy"
                    checked={values.use_group_policy}
                    onChange={(event) => update("use_group_policy", event.currentTarget.checked)}
                  />
                </Group>
                <AccessPolicyFields
                  value={values.access_policy}
                  groups={groups}
                  serviceGroups={serviceGroups}
                  inheritedFrom={values.use_group_policy ? inheritedFrom || "assigned service group" : null}
                  onChange={(next) => update("access_policy", next)}
                />
              </Stack>
            </Paper>

            <Paper withBorder radius="md" p="md">
              <Stack gap="sm">
                <Text fw={600}>Access method</Text>
                <Select
                  label="Authentication flow"
                  description={values.use_group_policy && inheritedFrom ? `Policy may be inherited from ${inheritedFrom}, but access method can still be overridden here.` : undefined}
                  data={[
                    { value: "", label: "Inherit / Session (default)" },
                    { value: "session", label: "Session (Standard)" },
                    { value: "oidc_only", label: "OIDC / Keycloak" },
                    { value: "pin", label: "Route-PIN" },
                    { value: "email_code", label: "E-Mail Code" }
                  ]}
                  value={values.access_method}
                  onChange={(value) => update("access_method", (value || "") as ServicePayload["access_method"])}
                />
                {(values.access_method === "pin" || values.access_method === "email_code") ? (
                  <TextInput
                    label="Hint"
                    description="Optional helper text shown on the route login screen."
                    value={values.access_method_config.hint || ""}
                    onChange={(event) =>
                      update("access_method_config", { ...values.access_method_config, hint: event.currentTarget.value })
                    }
                  />
                ) : null}
                {values.access_method === "pin" ? (
                  <>
                    <TextInput
                      label="Route-PIN"
                      description="Only sent on save. Existing PIN stays unchanged if left blank."
                      value={values.access_method_config.pin || ""}
                      onChange={(event) =>
                        update("access_method_config", { ...values.access_method_config, pin: event.currentTarget.value })
                      }
                    />
                    <Switch
                      checked={Boolean(initialValues?.access_method_config?.pin_configured)}
                      label="PIN currently configured"
                      readOnly
                    />
                  </>
                ) : null}
                {values.access_method === "email_code" ? (
                  <>
                    <TextInput
                      label="Allowed email domain"
                      description="Optional. Example: firma.de"
                      value={values.access_method_config.allowed_email_domain || ""}
                      onChange={(event) =>
                        update("access_method_config", { ...values.access_method_config, allowed_email_domain: event.currentTarget.value })
                      }
                    />
                    <Textarea
                      label="Allowed email addresses"
                      description="One exact address per line."
                      minRows={4}
                      value={emailWhitelistText}
                      onChange={(event) => setEmailWhitelistText(event.currentTarget.value)}
                    />
                  </>
                ) : null}
                <Textarea
                  label="Access message"
                  description="Shown on the generic route login screen for this service."
                  minRows={3}
                  value={values.access_message}
                  onChange={(event) => update("access_message", event.currentTarget.value)}
                />
              </Stack>
            </Paper>
          </Stack>
        </Tabs.Panel>

        <Tabs.Panel value="network" pt="md">
          <Paper withBorder radius="md" p="md">
            <Stack gap="sm">
              <Text fw={600}>Network filters</Text>
              <Textarea
                label="IP allowlist"
                description="One IP or CIDR per line. Empty means unrestricted."
                minRows={4}
                value={allowlistText}
                onChange={(event) => setAllowlistText(event.currentTarget.value)}
              />
              <Textarea
                label="IP blocklist"
                description="Requests from these addresses are rejected before authentication."
                minRows={4}
                value={blocklistText}
                onChange={(event) => setBlocklistText(event.currentTarget.value)}
              />
              <MultiSelect
                label="Allowed countries"
                description="ISO 3166-1 alpha-2. Empty means all countries allowed. Requires a configured GeoIP database."
                data={countryOptions}
                value={values.allowed_countries}
                onChange={(next) => update("allowed_countries", next)}
                searchable
                clearable
              />
              <MultiSelect
                label="Blocked countries"
                description="Blocked countries always win over the allow list."
                data={countryOptions}
                value={values.blocked_countries}
                onChange={(next) => update("blocked_countries", next)}
                searchable
                clearable
              />
            </Stack>
          </Paper>
        </Tabs.Panel>

        <Tabs.Panel value="windows" pt="md">
          <Paper withBorder radius="md" p="md">
            <Stack gap="sm">
              <Text fw={600}>Access windows</Text>
              <Grid>
                <Grid.Col span={{ base: 12, md: 6 }}>
                  <TextInput label="Name" value={windowDraft.name} onChange={(event) => setWindowDraft((current) => ({ ...current, name: event.currentTarget.value }))} />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 6 }}>
                  <TextInput label="Timezone" value={windowDraft.timezone} onChange={(event) => setWindowDraft((current) => ({ ...current, timezone: event.currentTarget.value }))} />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 6 }}>
                  <MultiSelect
                    label="Days"
                    data={days.map((day) => ({ value: day, label: day }))}
                    value={windowDraft.days_of_week}
                    onChange={(next) => setWindowDraft((current) => ({ ...current, days_of_week: next }))}
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 6, md: 3 }}>
                  <TextInput label="Start" value={windowDraft.start_time} onChange={(event) => setWindowDraft((current) => ({ ...current, start_time: event.currentTarget.value }))} />
                </Grid.Col>
                <Grid.Col span={{ base: 6, md: 3 }}>
                  <TextInput label="End" value={windowDraft.end_time} onChange={(event) => setWindowDraft((current) => ({ ...current, end_time: event.currentTarget.value }))} />
                </Grid.Col>
              </Grid>
              <Group justify="flex-end">
                <Button
                  variant="default"
                  onClick={() => {
                    setValues((current) => ({
                      ...current,
                      access_windows: [...current.access_windows, windowDraft]
                    }));
                    setWindowDraft(blankWindow);
                  }}
                >
                  Add window
                </Button>
              </Group>
              <Stack gap="xs">
                {values.access_windows.map((window, index) => (
                  <Paper key={`${window.name}-${index}`} p="sm" bg="dark.6">
                    <Group justify="space-between">
                      <Text size="sm">{accessWindowLabel(window)}</Text>
                      <Button
                        size="xs"
                        variant="subtle"
                        color="danger"
                        onClick={() =>
                          setValues((current) => ({
                            ...current,
                            access_windows: current.access_windows.filter((_, itemIndex) => itemIndex !== index)
                          }))
                        }
                      >
                        Remove
                      </Button>
                    </Group>
                  </Paper>
                ))}
              </Stack>
            </Stack>
          </Paper>
        </Tabs.Panel>
      </Tabs>

      <Divider />

      <Button
        loading={isLoading}
        onClick={() => void handleSubmit()}
        disabled={!values.name || !values.path || !values.target_url || !values.domain_id}
      >
        {submitLabel}
      </Button>

      <RiskyChangeModal
        opened={riskAssessment !== null}
        assessment={riskAssessment}
        onClose={handleCancelPending}
        onConfirm={() => void handleConfirmPending()}
        isLoading={isLoading}
      />
    </Stack>
  );
}
