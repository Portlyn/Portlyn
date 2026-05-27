"use client";

import { Button, Group as MantineGroup, Paper, Select, Skeleton, Stack, Table, Text, TextInput, Textarea } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";

import { AccessPolicyFields } from "@/components/access-policy-fields";
import { AdminOnly } from "@/components/admin-only";
import { AccessMethodBadge } from "@/components/status-badge";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { apiFetch, ApiError } from "@/lib/api";
import { buildServiceGroupRequestPayload } from "@/lib/access-control";
import { serviceHostname } from "@/lib/service-host";
import type { Group as UserGroup, Service, ServiceGroup, ServiceGroupPayload } from "@/lib/types";

function ServiceGroupDetailContent() {
  const [item, setItem] = useState<ServiceGroup | null>(null);
  const [groups, setGroups] = useState<UserGroup[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [selectedServiceId, setSelectedServiceId] = useState<string | null>(null);
  const [allowedEmailsText, setAllowedEmailsText] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const params = useSearchParams();
  const serviceGroupId = params.get("id") || undefined;

  const loadData = async () => {
    if (!serviceGroupId) {
      setError("Missing service group ID.");
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const [serviceGroup, groupItems, serviceItems] = await Promise.all([
        apiFetch<ServiceGroup>(`/api/v1/service-groups/${serviceGroupId}`),
        apiFetch<UserGroup[]>("/api/v1/groups"),
        apiFetch<Service[]>("/api/v1/services")
      ]);
      setItem(serviceGroup);
      setAllowedEmailsText((serviceGroup.access_method_config.allowed_emails || []).join("\n"));
      setGroups(groupItems);
      setServices(serviceItems);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load service group.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, [serviceGroupId]);

  const availableServices = useMemo(() => {
    const selectedIds = new Set(item?.services?.map((service) => service.id) || []);
    return services.filter((service) => !selectedIds.has(service.id));
  }, [item?.services, services]);

  const savePolicy = async () => {
    if (!item) return;
    try {
      const updated = await apiFetch<ServiceGroup>(`/api/v1/service-groups/${item.id}`, {
        method: "PATCH",
        body: JSON.stringify(buildServiceGroupRequestPayload({
          default_access_policy: item.default_access_policy,
          access_method: item.access_method,
          access_method_config: {
            ...item.access_method_config,
            allowed_emails: allowedEmailsText
              .split(/\r?\n|,/)
              .map((value) => value.trim().toLowerCase())
              .filter(Boolean)
          },
          name: item.name,
          description: item.description,
          service_ids: (item.services || []).map((service) => service.id)
        }, { omitEmptyAccessMethod: true }))
      });
      setItem(updated);
      notifications.show({ color: "success", message: "Default policy updated" });
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to update policy." });
    }
  };

  const handleAdd = async () => {
    if (!selectedServiceId || !serviceGroupId) return;
    try {
      const updated = await apiFetch<ServiceGroup>(`/api/v1/service-groups/${serviceGroupId}/services`, {
        method: "POST",
        body: JSON.stringify({ service_id: Number(selectedServiceId) })
      });
      setItem(updated);
      setSelectedServiceId(null);
      notifications.show({ color: "success", message: "Service assigned" });
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to assign service." });
    }
  };

  const handleRemove = async (serviceId: number) => {
    if (!serviceGroupId) return;
    try {
      await apiFetch<void>(`/api/v1/service-groups/${serviceGroupId}/services/${serviceId}`, { method: "DELETE" });
      await loadData();
      notifications.show({ color: "success", message: "Service removed" });
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to remove service." });
    }
  };

  return (
    <AdminOnly>
      <Stack gap="lg">
        {error ? <ErrorState title="Failed to load service group" message={error} onRetry={() => void loadData()} /> : null}
        {isLoading ? (
          <Stack gap="sm"><Skeleton height={54} /><Skeleton height={54} /></Stack>
        ) : !item ? (
          <EmptyState title="Service group not found" description="The requested service group does not exist." />
        ) : (
          <>
            <Paper withBorder p="lg">
              <Stack gap="xs">
                <Text fw={700} fz="xl">{item.name}</Text>
                <Text c="dimmed">{item.description || "No description"}</Text>
                <AccessMethodBadge value={item.access_method || "session"} />
              </Stack>
            </Paper>

            <Paper withBorder p="lg">
              <Stack gap="md">
                <Text fw={600}>Default access policy</Text>
                <AccessPolicyFields value={item.default_access_policy} groups={groups} serviceGroups={[item]} onChange={(next) => setItem({ ...item, default_access_policy: next })} />
                <Select
                  label="Default access method"
                  data={[
                    { value: "", label: "Inherit / Session (default)" },
                    { value: "session", label: "Session (Standard)" },
                    { value: "oidc_only", label: "OIDC / Keycloak" },
                    { value: "pin", label: "Route-PIN" },
                    { value: "email_code", label: "E-Mail Code" }
                  ]}
                  value={item.access_method}
                  onChange={(value) => setItem({ ...item, access_method: (value || "") as ServiceGroupPayload["access_method"] })}
                />
                {(item.access_method === "pin" || item.access_method === "email_code") ? (
                  <TextInput
                    label="Hint"
                    value={item.access_method_config.hint || ""}
                    onChange={(event) =>
                      setItem({
                        ...item,
                        access_method_config: { ...item.access_method_config, hint: event.currentTarget.value }
                      })
                    }
                  />
                ) : null}
                {item.access_method === "pin" ? (
                  <TextInput
                    label="Route-PIN"
                    description="Only sent on save. Existing PIN stays unchanged if left blank."
                    value={(item.access_method_config as ServiceGroupPayload["access_method_config"]).pin || ""}
                    onChange={(event) =>
                      setItem({
                        ...item,
                        access_method_config: { ...item.access_method_config, pin: event.currentTarget.value }
                      } as ServiceGroup)
                    }
                  />
                ) : null}
                {item.access_method === "email_code" ? (
                  <>
                    <TextInput
                      label="Allowed email domain"
                      value={item.access_method_config.allowed_email_domain || ""}
                      onChange={(event) =>
                        setItem({
                          ...item,
                          access_method_config: { ...item.access_method_config, allowed_email_domain: event.currentTarget.value }
                        })
                      }
                    />
                    <Textarea
                      label="Allowed email addresses"
                      minRows={4}
                      value={allowedEmailsText}
                      onChange={(event) => setAllowedEmailsText(event.currentTarget.value)}
                    />
                  </>
                ) : null}
                <MantineGroup justify="flex-end">
                  <Button onClick={savePolicy}>Save policy</Button>
                </MantineGroup>
              </Stack>
            </Paper>

            <Paper withBorder p="lg">
              <Stack gap="md">
                <MantineGroup align="end">
                  <Select
                    label="Assign service"
                    data={availableServices.map((service) => ({ value: String(service.id), label: `${service.name} (${serviceHostname(service) || `#${service.domain_id}`})` }))}
                    value={selectedServiceId}
                    onChange={setSelectedServiceId}
                    searchable
                    clearable
                    style={{ flex: 1 }}
                  />
                  <Button onClick={handleAdd} disabled={!selectedServiceId}>Assign</Button>
                </MantineGroup>

                {(item.services || []).length === 0 ? (
                  <EmptyState title="No services assigned" description="Attach services to inherit or reference this group's default policy." />
                ) : (
                  <Table.ScrollContainer minWidth={800}>
                    <Table>
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th>Name</Table.Th>
                          <Table.Th>Domain</Table.Th>
                          <Table.Th>Path</Table.Th>
                          <Table.Th>Access Method</Table.Th>
                          <Table.Th ta="right">Actions</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {(item.services || []).map((service) => (
                          <Table.Tr key={service.id}>
                            <Table.Td>{service.name}</Table.Td>
                            <Table.Td>{serviceHostname(service) || `#${service.domain_id}`}</Table.Td>
                            <Table.Td>{service.path}</Table.Td>
                            <Table.Td><AccessMethodBadge value={service.effective_access_method || service.access_method || "session"} /></Table.Td>
                            <Table.Td>
                              <MantineGroup justify="flex-end">
                                <Button variant="subtle" color="danger" onClick={() => void handleRemove(service.id)}>
                                  Remove
                                </Button>
                              </MantineGroup>
                            </Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </Table.ScrollContainer>
                )}
              </Stack>
            </Paper>
          </>
        )}
      </Stack>
    </AdminOnly>
  );
}

export default function ServiceGroupDetailPage() {
  return (
    <Suspense fallback={<Skeleton height={200} />}>
      <ServiceGroupDetailContent />
    </Suspense>
  );
}
