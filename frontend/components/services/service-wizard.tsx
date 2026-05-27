"use client";

import {
  Alert,
  Badge,
  Button,
  Card,
  Group,
  Paper,
  ScrollArea,
  SegmentedControl,
  Select,
  Stack,
  Stepper,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { useMemo, useState } from "react";

import { ServiceForm } from "@/components/services/service-form";
import {
  buildTargetURL,
  categoryLabels,
  customTemplate,
  findTemplate,
  serviceTemplates,
  type ServiceTemplate,
  type ServiceTemplateCategory,
} from "@/lib/service-templates";
import { buildServiceHostname } from "@/lib/service-host";
import type {
  AccessMethod,
  AccessMode,
  Domain,
  Group as UserGroup,
  Service,
  ServiceGroup,
  ServicePayload,
} from "@/lib/types";

const allCategoriesValue = "all";

function templateAccessLabel(mode: AccessMode, method: AccessMethod): string {
  const modeText =
    mode === "public" ? "Public" : mode === "restricted" ? "Restricted" : "Authenticated";
  if (!method || method === "session") return modeText;
  if (method === "oidc_only") return `${modeText} · SSO`;
  if (method === "pin") return `${modeText} · PIN`;
  if (method === "email_code") return `${modeText} · Email code`;
  return modeText;
}

interface BasicsState {
  templateId: string;
  domainId: number;
  subdomain: string;
  upstreamHost: string;
  upstreamPort: number;
  upstreamPath: string;
  upstreamProtocol: "http" | "https";
  name: string;
}

function deriveInitialBasics(): BasicsState {
  return {
    templateId: "",
    domainId: 0,
    subdomain: "",
    upstreamHost: "",
    upstreamPort: 8080,
    upstreamPath: "/",
    upstreamProtocol: "http",
    name: "",
  };
}

function templateAsServiceInitial(
  template: ServiceTemplate,
  basics: BasicsState,
): Partial<Service> {
  const target_url = buildTargetURL(template, basics.upstreamHost);
  return {
    name: basics.name || template.name,
    domain_id: basics.domainId || undefined,
    subdomain: basics.subdomain,
    path: basics.upstreamPath || template.defaultPath,
    target_url: target_url,
    tls_mode: "offload",
    access_mode: template.recommendedAccessMode,
    access_method: template.recommendedAccessMethod,
  };
}

function customAsServiceInitial(basics: BasicsState): Partial<Service> {
  const trimmedHost = basics.upstreamHost.trim().replace(/^https?:\/\//, "").replace(/\/$/, "");
  const target_url = trimmedHost
    ? `${basics.upstreamProtocol}://${trimmedHost}:${basics.upstreamPort}${basics.upstreamPath || "/"}`
    : "";
  return {
    name: basics.name,
    domain_id: basics.domainId || undefined,
    subdomain: basics.subdomain,
    path: basics.upstreamPath || "/",
    target_url,
    tls_mode: "offload",
    access_mode: "authenticated",
    access_method: "session",
  };
}

export function ServiceWizard({
  domains,
  groups,
  serviceGroups,
  onSubmit,
  onCancel,
  isLoading,
}: {
  domains: Domain[];
  groups: UserGroup[];
  serviceGroups: ServiceGroup[];
  onSubmit: (values: ServicePayload) => Promise<void>;
  onCancel?: () => void;
  isLoading?: boolean;
}) {
  const [step, setStep] = useState(0);
  const [basics, setBasics] = useState<BasicsState>(deriveInitialBasics);
  const [categoryFilter, setCategoryFilter] = useState<ServiceTemplateCategory | typeof allCategoriesValue>(
    allCategoriesValue,
  );
  const [searchQuery, setSearchQuery] = useState("");

  const selectedTemplate = useMemo<ServiceTemplate | null>(() => {
    if (!basics.templateId) return null;
    return findTemplate(basics.templateId) ?? null;
  }, [basics.templateId]);

  const visibleTemplates = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return serviceTemplates.filter((template) => {
      if (categoryFilter !== allCategoriesValue && template.category !== categoryFilter) {
        return false;
      }
      if (!query) return true;
      return (
        template.name.toLowerCase().includes(query) ||
        template.description.toLowerCase().includes(query) ||
        template.id.toLowerCase().includes(query)
      );
    });
  }, [categoryFilter, searchQuery]);

  const presentCategories = useMemo(() => {
    const set = new Set<ServiceTemplateCategory>();
    for (const template of serviceTemplates) set.add(template.category);
    return Array.from(set);
  }, []);

  const previewHostname = buildServiceHostname(
    domains.find((domain) => domain.id === basics.domainId)?.name,
    basics.subdomain,
  );

  const initialServiceValues: Partial<Service> = selectedTemplate
    ? selectedTemplate.id === customTemplate.id
      ? customAsServiceInitial(basics)
      : templateAsServiceInitial(selectedTemplate, basics)
    : {};

  const canLeaveStep0 = Boolean(basics.templateId);
  const canLeaveStep1 =
    Boolean(basics.name) && basics.domainId > 0 && Boolean(basics.upstreamHost);

  return (
    <Stack gap="lg">
      <Stepper active={step} onStepClick={setStep} allowNextStepsSelect={false}>
        <Stepper.Step
          label="Application"
          description={selectedTemplate ? selectedTemplate.name : "Pick a template"}
        >
          <Stack gap="md" mt="md">
            <Group grow>
              <TextInput
                placeholder="Search apps..."
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.currentTarget.value)}
              />
              <Select
                data={[
                  { value: allCategoriesValue, label: "All categories" },
                  ...presentCategories.map((category) => ({
                    value: category,
                    label: categoryLabels[category],
                  })),
                ]}
                value={categoryFilter}
                onChange={(value) =>
                  setCategoryFilter(((value as ServiceTemplateCategory) || allCategoriesValue))
                }
              />
            </Group>

            <ScrollArea.Autosize mah={400}>
              <Stack gap="xs">
                <TemplateCard
                  template={customTemplate}
                  selected={basics.templateId === customTemplate.id}
                  onSelect={() => setBasics((current) => ({ ...current, templateId: customTemplate.id }))}
                />
                {visibleTemplates.map((template) => (
                  <TemplateCard
                    key={template.id}
                    template={template}
                    selected={basics.templateId === template.id}
                    onSelect={() =>
                      setBasics((current) => ({
                        ...current,
                        templateId: template.id,
                        upstreamPort: template.defaultPort,
                        upstreamPath: template.defaultPath,
                        upstreamProtocol: template.protocol,
                        name: current.name || template.name,
                      }))
                    }
                  />
                ))}
                {visibleTemplates.length === 0 ? (
                  <Text c="dimmed" ta="center" py="md">
                    No matching template — pick &quot;Custom service&quot; above to configure manually.
                  </Text>
                ) : null}
              </Stack>
            </ScrollArea.Autosize>
          </Stack>
        </Stepper.Step>

        <Stepper.Step label="Routing" description="Domain & upstream">
          <Stack gap="md" mt="md">
            {selectedTemplate ? (
              <Alert color="brand" variant="light">
                <Group justify="space-between">
                  <Stack gap={2}>
                    <Text fw={600}>{selectedTemplate.name}</Text>
                    <Text size="sm">{selectedTemplate.description}</Text>
                  </Stack>
                  <Badge variant="light">
                    {templateAccessLabel(
                      selectedTemplate.recommendedAccessMode,
                      selectedTemplate.recommendedAccessMethod,
                    )}
                  </Badge>
                </Group>
              </Alert>
            ) : null}

            <Paper withBorder radius="md" p="md">
              <Stack gap="sm">
                <TextInput
                  label="Service name"
                  description="Shown in the dashboard and audit log."
                  value={basics.name}
                  onChange={(event) =>
                    setBasics((current) => ({ ...current, name: event.currentTarget.value }))
                  }
                  required
                />
                <Group grow>
                  <Select
                    label="Root domain"
                    description="Pick a domain you already added under Domains."
                    data={domains.map((domain) => ({ value: String(domain.id), label: domain.name }))}
                    value={basics.domainId ? String(basics.domainId) : null}
                    onChange={(value) =>
                      setBasics((current) => ({ ...current, domainId: Number(value || 0) }))
                    }
                    disabled={domains.length === 0}
                    required
                  />
                  <TextInput
                    label="Subdomain (optional)"
                    placeholder="e.g. grafana"
                    value={basics.subdomain}
                    onChange={(event) =>
                      setBasics((current) => ({ ...current, subdomain: event.currentTarget.value }))
                    }
                  />
                </Group>
                {previewHostname ? (
                  <Text size="sm" c="dimmed">
                    Public host: <Text span fw={600}>{previewHostname}</Text>
                  </Text>
                ) : null}
              </Stack>
            </Paper>

            <Paper withBorder radius="md" p="md">
              <Stack gap="sm">
                <Text fw={600}>Upstream</Text>
                <Group grow>
                  <SegmentedControl
                    data={[
                      { value: "http", label: "http" },
                      { value: "https", label: "https" },
                    ]}
                    value={basics.upstreamProtocol}
                    onChange={(value) =>
                      setBasics((current) => ({
                        ...current,
                        upstreamProtocol: value as "http" | "https",
                      }))
                    }
                  />
                  <TextInput
                    label="Host or IP"
                    placeholder="e.g. gitea or 10.0.0.5"
                    value={basics.upstreamHost}
                    onChange={(event) =>
                      setBasics((current) => ({ ...current, upstreamHost: event.currentTarget.value }))
                    }
                    required
                  />
                  <TextInput
                    label="Port"
                    type="number"
                    value={String(basics.upstreamPort)}
                    onChange={(event) =>
                      setBasics((current) => ({
                        ...current,
                        upstreamPort: Number(event.currentTarget.value) || 0,
                      }))
                    }
                  />
                  <TextInput
                    label="Path"
                    value={basics.upstreamPath}
                    onChange={(event) =>
                      setBasics((current) => ({ ...current, upstreamPath: event.currentTarget.value }))
                    }
                  />
                </Group>
                {selectedTemplate?.notes ? (
                  <Alert color="yellow" variant="light" title="Recommendation">
                    {selectedTemplate.notes}
                  </Alert>
                ) : null}
              </Stack>
            </Paper>
          </Stack>
        </Stepper.Step>

        <Stepper.Step label="Review & adjust" description="Access, network, windows">
          <Stack gap="md" mt="md">
            <Alert color="gray" variant="light">
              Pre-filled with the template defaults. Tweak access mode, IP rules and access windows below before saving.
            </Alert>
            <ServiceForm
              domains={domains}
              groups={groups}
              serviceGroups={serviceGroups}
              initialValues={initialServiceValues}
              submitLabel="Create service"
              isLoading={isLoading}
              onSubmit={onSubmit}
            />
          </Stack>
        </Stepper.Step>

        <Stepper.Completed>
          <Stack gap="md" align="center" py="lg">
            <Title order={3}>Done.</Title>
            <Text c="dimmed">Service created. Check the diagnostics tab if anything looks off.</Text>
          </Stack>
        </Stepper.Completed>
      </Stepper>

      <Group justify="space-between">
        {onCancel ? (
          <Button variant="subtle" onClick={onCancel}>
            Cancel
          </Button>
        ) : <span />}

        <Group>
          {step > 0 ? (
            <Button variant="default" onClick={() => setStep((current) => current - 1)}>
              Back
            </Button>
          ) : null}
          {step < 2 ? (
            <Button
              onClick={() => setStep((current) => current + 1)}
              disabled={(step === 0 && !canLeaveStep0) || (step === 1 && !canLeaveStep1)}
            >
              Continue
            </Button>
          ) : null}
        </Group>
      </Group>
    </Stack>
  );
}

function TemplateCard({
  template,
  selected,
  onSelect,
}: {
  template: ServiceTemplate;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <Card
      withBorder
      padding="md"
      radius="md"
      onClick={onSelect}
      style={{ cursor: "pointer", borderColor: selected ? "var(--mantine-color-brand-5)" : undefined }}
    >
      <Group justify="space-between" wrap="nowrap" align="flex-start">
        <Group wrap="nowrap" align="flex-start" gap="md">
          <div
            style={{
              width: 40,
              height: 40,
              borderRadius: 8,
              background: "var(--mantine-color-dark-5)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 700,
              fontSize: 18,
              flexShrink: 0,
            }}
          >
            {template.icon}
          </div>
          <Stack gap={2}>
            <Group gap="xs">
              <Text fw={600}>{template.name}</Text>
              <Badge variant="light" size="sm">{categoryLabels[template.category]}</Badge>
            </Group>
            <Text size="sm" c="dimmed">{template.description}</Text>
          </Stack>
        </Group>
        {template.id !== customTemplate.id ? (
          <Badge variant="default">
            :{template.defaultPort}
          </Badge>
        ) : null}
      </Group>
    </Card>
  );
}
