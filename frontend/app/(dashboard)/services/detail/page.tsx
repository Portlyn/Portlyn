"use client";

import { Alert, Button, Card, Divider, Grid, Group, Loader, Paper, SimpleGrid, Stack, Table, Tabs, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { ErrorState } from "@/components/error-state";
import { useAuth } from "@/components/providers";
import { AccessRuleActionBadge } from "@/components/services/access-rules-editor";
import { MagicLinkButton } from "@/components/services/magic-link-button";
import { ServiceForm } from "@/components/services/service-form";
import { ServiceDiagnostics } from "@/components/services/service-diagnostics";
import { ServiceExposurePanel } from "@/components/services/service-exposure-panel";
import { AccessMethodBadge, AccessModeBadge, AuthPolicyBadge, StatusBadge } from "@/components/status-badge";
import { buildServiceRequestPayload, legacyAuthPolicyFromAccessMode } from "@/lib/access-control";
import { apiFetch, ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { serviceHostname } from "@/lib/service-host";
import type { Domain, Group as UserGroup, Node as PortlynNode, Service, ServiceGroup, ServicePayload } from "@/lib/types";

function ServiceDetailContent() {
  const [service, setService] = useState<Service | null>(null);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [groups, setGroups] = useState<UserGroup[]>([]);
  const [serviceGroups, setServiceGroups] = useState<ServiceGroup[]>([]);
  const [nodes, setNodes] = useState<PortlynNode[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [isRedeploying, setIsRedeploying] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const params = useSearchParams();
  const serviceId = params.get("id") || undefined;
  const router = useRouter();
  const { user } = useAuth();
  const canManage = user?.role === "admin";

  const inheritedGroup = useMemo(
    () => (service?.use_group_policy ? service.service_groups?.find((group) => group.default_access_policy?.access_mode) || service.service_groups?.[0] : null),
    [service]
  );

  const loadData = async () => {
    if (!serviceId) {
      setError("Missing service ID.");
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const [serviceItem, domainItems, groupItems, serviceGroupItems, nodeItems] = await Promise.all([
        apiFetch<Service>(`/api/v1/services/${serviceId}`),
        apiFetch<Domain[]>("/api/v1/domains"),
        canManage ? apiFetch<UserGroup[]>("/api/v1/groups") : Promise.resolve([]),
        canManage ? apiFetch<ServiceGroup[]>("/api/v1/service-groups") : Promise.resolve([]),
        canManage ? apiFetch<PortlynNode[]>("/api/v1/nodes") : Promise.resolve([])
      ]);
      setService(serviceItem);
      setDomains(domainItems);
      setGroups(groupItems);
      setServiceGroups(serviceGroupItems);
      setNodes(nodeItems);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load service.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (!canManage) {
      setIsLoading(false);
      return;
    }
    void loadData();
  }, [canManage, serviceId]);

  useEffect(() => {
    if (user?.role === "viewer") {
      router.replace("/services");
    }
  }, [router, user?.role]);

  const handleSave = async (values: ServicePayload) => {
    if (!serviceId) return;
    setIsSaving(true);
    try {
      const updated = await apiFetch<Service>(`/api/v1/services/${serviceId}`, {
        method: "PATCH",
        body: JSON.stringify({
          ...buildServiceRequestPayload(values),
          auth_policy: legacyAuthPolicyFromAccessMode(values.access_policy)
        })
      });
      setService(updated);
      notifications.show({ color: "success", message: "Service updated" });
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to update service." });
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!serviceId) return;
    setIsDeleting(true);
    try {
      await apiFetch<void>(`/api/v1/services/${serviceId}`, { method: "DELETE" });
      notifications.show({ color: "success", message: "Service deleted" });
      router.push("/services");
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to delete service." });
    } finally {
      setIsDeleting(false);
      setConfirmDelete(false);
    }
  };

  const handleRedeploy = async () => {
    if (!serviceId) return;
    setIsRedeploying(true);
    try {
      const updated = await apiFetch<Service>(`/api/v1/services/${serviceId}/redeploy`, { method: "POST" });
      setService(updated);
      notifications.show({ color: "success", message: "Service redeployed" });
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Redeploy failed." });
    } finally {
      setIsRedeploying(false);
    }
  };

  if (isLoading) {
    return (
      <Stack align="center" py="xl">
        <Loader color="brand" />
      </Stack>
    );
  }

  if (user?.role === "viewer") {
    return (
      <Stack align="center" py="xl">
        <Loader color="brand" />
      </Stack>
    );
  }

  if (error || !service) {
    return <ErrorState title="Failed to load service" message={error || "Unknown error"} onRetry={() => void loadData()} />;
  }

  return (
    <Stack gap="lg">
      <Grid>
        <Grid.Col span={{ base: 12, xl: 8 }}>
          <Card withBorder>
            <Group justify="space-between" align="flex-start">
              <div>
                <Text fw={600} fz="xl">
                  {service.name}
                </Text>
                <Text c="dimmed" size="sm">
                  {serviceHostname(service) || `Domain #${service.domain_id}`} · {service.path}
                </Text>
              </div>
              <Stack gap="xs" align="flex-end">
                <StatusBadge status={service.service_status || (service.last_deployed_at ? "healthy" : "pending")} />
                {service.service_status_error ? <Text c="danger" size="xs">{service.service_status_error}</Text> : null}
                {canManage ? (
                  <Group gap="xs">
                    <MagicLinkButton serviceId={service.id} serviceName={service.name} />
                    <Button variant="light" color="danger" onClick={() => setConfirmDelete(true)}>
                      Delete Service
                    </Button>
                  </Group>
                ) : null}
              </Stack>
            </Group>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, xl: 4 }}>
          <Card withBorder>
            <Stack gap="sm">
              <div>
                <Text c="dimmed" size="xs">Access</Text>
                <AccessModeBadge value={service.access_mode} />
              </div>
              <div>
                <Text c="dimmed" size="xs">Access method</Text>
                <AccessMethodBadge value={service.effective_access_method || service.access_method || "session"} />
              </div>
              <div>
                <Text c="dimmed" size="xs">Legacy auth policy</Text>
                <AuthPolicyBadge value={service.auth_policy} />
              </div>
              <div>
                <Text c="dimmed" size="xs">Routing</Text>
                {service.node_id ? (
                  <Text size="sm">
                    Via node {nodes.find((node) => node.id === service.node_id)?.name || `#${service.node_id}`}
                    {" "}
                    <Text span c="dimmed">({nodes.find((node) => node.id === service.node_id)?.wg_tunnel_ip || "tunnel"})</Text>
                  </Text>
                ) : (
                  <Text size="sm">Direct (no tunnel)</Text>
                )}
              </div>
              <div>
                <Text c="dimmed" size="xs">Last deployed</Text>
                <Text size="sm">{formatDateTime(service.last_deployed_at)}</Text>
              </div>
              <div>
                <Text c="dimmed" size="xs">Revision</Text>
                <Text size="sm">{service.deployment_revision}</Text>
              </div>
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>

      <Tabs defaultValue="general">
        <Tabs.List>
          <Tabs.Tab value="general">General</Tabs.Tab>
          <Tabs.Tab value="security">Access Control</Tabs.Tab>
          <Tabs.Tab value="diagnostics">Diagnostics</Tabs.Tab>
          <Tabs.Tab value="exposure">Exposure</Tabs.Tab>
          <Tabs.Tab value="deployment">Deployment</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="general" pt="md">
          <Paper withBorder radius="md" p="lg">
            {canManage ? (
              <ServiceForm
                domains={domains}
                groups={groups}
                serviceGroups={serviceGroups}
                nodes={nodes}
                initialValues={service}
                inheritedFrom={inheritedGroup?.name}
                onSubmit={handleSave}
                submitLabel="Save Changes"
                isLoading={isSaving}
                confirmRiskyChanges
              />
            ) : (
              <Stack gap="md">
                <Alert color="brand" variant="light">
                  Viewer role can inspect service settings but cannot modify them.
                </Alert>
                <SimpleGrid cols={2}>
                  <div>
                    <Text c="dimmed" size="xs">Target URL</Text>
                    <Text size="sm">{service.target_url}</Text>
                  </div>
                  <div>
                    <Text c="dimmed" size="xs">TLS mode</Text>
                    <Text size="sm">{service.tls_mode}</Text>
                  </div>
                </SimpleGrid>
              </Stack>
            )}
          </Paper>
        </Tabs.Panel>

        <Tabs.Panel value="security" pt="md">
          <Paper withBorder radius="md" p="lg">
            <Stack gap="md">
              {service.use_group_policy && inheritedGroup ? (
                <Alert color="brand" variant="light">
                  Inherits its effective policy from service group <strong>{inheritedGroup.name}</strong>.
                </Alert>
              ) : null}
              <SimpleGrid cols={2}>
                <div>
                  <Text c="dimmed" size="xs">Access mode</Text>
                  <AccessModeBadge value={service.access_mode} />
                </div>
                <div>
                  <Text c="dimmed" size="xs">Access method</Text>
                  <AccessMethodBadge value={service.effective_access_method || service.access_method || "session"} />
                </div>
                <div>
                  <Text c="dimmed" size="xs">Allowed roles</Text>
                  <Text size="sm">{service.allowed_roles.length > 0 ? service.allowed_roles.join(", ") : "None"}</Text>
                </div>
                <div>
                  <Text c="dimmed" size="xs">Allowed groups</Text>
                  <Text size="sm">
                    {service.allowed_groups.length > 0
                      ? service.allowed_groups
                          .map((groupId) => groups.find((group) => group.id === groupId)?.name || `#${groupId}`)
                          .join(", ")
                      : "None"}
                  </Text>
                </div>
                <div>
                  <Text c="dimmed" size="xs">Service groups</Text>
                  <Text size="sm">{service.service_groups?.map((group) => group.name).join(", ") || "None"}</Text>
                </div>
                <div>
                  <Text c="dimmed" size="xs">Route message</Text>
                  <Text size="sm">{service.access_message || "None"}</Text>
                </div>
              </SimpleGrid>
              {service.inherited_from_group && !service.service_overrides_group ? (
                <Alert color="brand" variant="light">
                  Access method is inherited from service group <strong>{service.inherited_from_group.name}</strong>.
                </Alert>
              ) : null}
              {service.access_rules && service.access_rules.length > 0 ? (
                <>
                  <Divider />
                  <Text fw={600}>Access rules</Text>
                  <Table.ScrollContainer minWidth={560}>
                    <Table>
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th>#</Table.Th>
                          <Table.Th>Name</Table.Th>
                          <Table.Th>Source IPs</Table.Th>
                          <Table.Th>Paths</Table.Th>
                          <Table.Th>Action</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {service.access_rules.map((rule, index) => (
                          <Table.Tr key={index}>
                            <Table.Td>{index + 1}</Table.Td>
                            <Table.Td>{rule.name || "-"}</Table.Td>
                            <Table.Td>{rule.sources.length > 0 ? rule.sources.join(", ") : "Any"}</Table.Td>
                            <Table.Td>{rule.paths.length > 0 ? rule.paths.join(", ") : "Any"}</Table.Td>
                            <Table.Td>
                              <AccessRuleActionBadge action={rule.action} />
                            </Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </Table.ScrollContainer>
                </>
              ) : null}
            </Stack>
          </Paper>
        </Tabs.Panel>

        <Tabs.Panel value="diagnostics" pt="md">
          <ServiceDiagnostics serviceId={service.id} />
        </Tabs.Panel>

        <Tabs.Panel value="exposure" pt="md">
          <ServiceExposurePanel serviceId={service.id} />
        </Tabs.Panel>

        <Tabs.Panel value="deployment" pt="md">
          <Paper withBorder radius="md" p="lg">
            <Stack gap="md">
              <SimpleGrid cols={2}>
                <div>
                  <Text c="dimmed" size="xs">Last deployed</Text>
                  <Text size="sm">{formatDateTime(service.last_deployed_at)}</Text>
                </div>
                <div>
                  <Text c="dimmed" size="xs">Deployment revision</Text>
                  <Text size="sm">{service.deployment_revision}</Text>
                </div>
              </SimpleGrid>
              {service.service_status_error ? (
                <Alert color="danger" variant="light">{service.service_status_error}</Alert>
              ) : null}
              <Group>
                {canManage ? (
                  <Button variant="light" loading={isRedeploying} onClick={() => void handleRedeploy()}>
                    Redeploy
                  </Button>
                ) : null}
                <Button variant="default" onClick={() => router.push("/services")}>
                  Back to Services
                </Button>
              </Group>
            </Stack>
          </Paper>
        </Tabs.Panel>
      </Tabs>

      <ConfirmDialog
        isOpen={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        onConfirm={handleDelete}
        title="Delete service?"
        description={`This removes ${service.name}.`}
        isLoading={isDeleting}
      />
    </Stack>
  );
}

export default function ServiceDetailPage() {
  return (
    <Suspense fallback={<Stack align="center" py="xl"><Loader color="brand" /></Stack>}>
      <ServiceDetailContent />
    </Suspense>
  );
}
