"use client";

import { Badge, Button, Card, Drawer, Group, Paper, Select, SimpleGrid, Skeleton, Stack, Text, TextInput } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useDisclosure } from "@mantine/hooks";
import { useEffect, useMemo, useState } from "react";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { useAuth } from "@/components/providers";
import { ServiceTable } from "@/components/services/service-table";
import { ServiceWizard } from "@/components/services/service-wizard";
import { accessMethodLabel, buildServiceRequestPayload, legacyAuthPolicyFromAccessMode } from "@/lib/access-control";
import { apiFetch, ApiError } from "@/lib/api";
import { serviceHostname } from "@/lib/service-host";
import type { AccessMode, Domain, Group as UserGroup, Service, ServiceGroup, ServicePayload } from "@/lib/types";

export default function ServicesPage() {
  const [services, setServices] = useState<Service[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [groups, setGroups] = useState<UserGroup[]>([]);
  const [serviceGroups, setServiceGroups] = useState<ServiceGroup[]>([]);
  const [search, setSearch] = useState("");
  const [accessMode, setAccessMode] = useState<"all" | AccessMode>("all");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [serviceToDelete, setServiceToDelete] = useState<Service | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [opened, { open, close }] = useDisclosure(false);
  const { user } = useAuth();
  const canManage = user?.role === "admin";

  const openViewerService = (service: Service) => {
    if (typeof window === "undefined") {
      return;
    }
    const domainName = serviceHostname(service);
    const returnTo = domainName ? `${window.location.protocol}//${domainName}${service.path}` : undefined;
    const params = new URLSearchParams({ serviceId: String(service.id) });
    if (returnTo) {
      params.set("returnTo", returnTo);
    }
    window.open(`/route-login?${params.toString()}`, "_blank", "noopener,noreferrer");
  };

  const loadData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [serviceItems, domainItems, groupItems, serviceGroupItems] = await Promise.all([
        apiFetch<Service[]>("/api/v1/services"),
        canManage ? apiFetch<Domain[]>("/api/v1/domains") : Promise.resolve([]),
        canManage ? apiFetch<UserGroup[]>("/api/v1/groups") : Promise.resolve([]),
        canManage ? apiFetch<ServiceGroup[]>("/api/v1/service-groups") : Promise.resolve([])
      ]);
      setServices(serviceItems);
      setDomains(domainItems);
      setGroups(groupItems);
      setServiceGroups(serviceGroupItems);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load services.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, [canManage]);

  const filteredServices = useMemo(
    () =>
      services.filter((service) => {
        const matchesSearch =
          !search ||
          [service.name, service.path, service.target_url, serviceHostname(service)].some((value) =>
            value.toLowerCase().includes(search.toLowerCase())
          );
        const matchesPolicy = accessMode === "all" || (service.effective_access_mode || service.access_mode) === accessMode;
        return matchesSearch && matchesPolicy;
      }),
    [accessMode, search, services]
  );

  const handleCreate = async (values: ServicePayload) => {
    setIsSaving(true);
    try {
      await apiFetch<Service>("/api/v1/services", {
        method: "POST",
        body: JSON.stringify({
          ...buildServiceRequestPayload(values),
          auth_policy: legacyAuthPolicyFromAccessMode(values.access_policy)
        })
      });
      notifications.show({ color: "green", message: "Service created" });
      close();
      await loadData();
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Unable to create service." });
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!serviceToDelete) return;
    setIsDeleting(true);
    try {
      await apiFetch<void>(`/api/v1/services/${serviceToDelete.id}`, { method: "DELETE" });
      notifications.show({ color: "green", message: "Service deleted" });
      setServiceToDelete(null);
      await loadData();
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Unable to delete service." });
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <Stack gap="lg">
      {canManage ? (
        <Group justify="flex-end">
          <Button onClick={open} disabled={domains.length === 0 && !isLoading}>New Service</Button>
        </Group>
      ) : (
        <Stack gap={4}>
          <Text fw={600}>Your services</Text>
          <Text size="sm" c="dimmed">Only applications you can access are listed here.</Text>
        </Stack>
      )}

      <Group grow align="end">
        <TextInput placeholder="Search" value={search} onChange={(event) => setSearch(event.currentTarget.value)} />
        <Select
          data={[
            { value: "all", label: "All access modes" },
            { value: "public", label: "public" },
            { value: "authenticated", label: "authenticated" },
            { value: "restricted", label: "restricted" }
          ]}
          value={accessMode}
          onChange={(value) => setAccessMode((value || "all") as "all" | AccessMode)}
        />
      </Group>

      {error ? <ErrorState title="Failed to load services" message={error} onRetry={() => void loadData()} /> : null}

      {isLoading ? (
        <Stack gap="sm">
          <Skeleton height={54} />
          <Skeleton height={54} />
          <Skeleton height={54} />
        </Stack>
      ) : filteredServices.length === 0 ? (
        <EmptyState title={services.length === 0 ? "No services found" : "No matching services"} description={services.length === 0 ? (canManage ? "Create a service." : "No applications are available for this account.") : "Adjust the filters."} />
      ) : (
        canManage ? (
          <Paper withBorder radius="md" p="sm">
            <ServiceTable services={filteredServices} canManage={canManage} onDelete={setServiceToDelete} />
          </Paper>
        ) : (
          <SimpleGrid cols={{ base: 1, md: 2, xl: 3 }}>
            {filteredServices.map((service) => (
              <Card key={service.id} withBorder radius="md" padding="lg">
                <Stack gap="md" h="100%">
                  <div>
                    <Group justify="space-between" align="flex-start">
                      <div>
                        <Text fw={600}>{service.name}</Text>
                        <Text size="sm" c="dimmed">
                          {serviceHostname(service)}{service.path}
                        </Text>
                      </div>
                      <Badge variant="light" color="gray">
                        {service.effective_access_mode || service.access_mode}
                      </Badge>
                    </Group>
                  </div>

                  <Group gap="xs">
                    <Badge variant="light" color="brand">
                      {accessMethodLabel(service.effective_access_method || service.access_method)}
                    </Badge>
                    {service.inherited_from_group && !service.service_overrides_group ? (
                      <Badge variant="light" color="gray">
                        {service.inherited_from_group.name}
                      </Badge>
                    ) : null}
                  </Group>

                  {service.access_message ? (
                    <Text size="sm" c="dimmed">{service.access_message}</Text>
                  ) : (
                    <Text size="sm" c="dimmed">Open this application in a new tab.</Text>
                  )}

                  <Group justify="flex-end" mt="auto">
                    <Button onClick={() => openViewerService(service)}>
                      Open
                    </Button>
                  </Group>
                </Stack>
              </Card>
            ))}
          </SimpleGrid>
        )
      )}

      <Drawer opened={opened} onClose={close} title="Create service" position="right" size="xl">
        <ServiceWizard
          domains={domains}
          groups={groups}
          serviceGroups={serviceGroups}
          onSubmit={handleCreate}
          onCancel={close}
          isLoading={isSaving}
        />
      </Drawer>

      <ConfirmDialog
        isOpen={Boolean(serviceToDelete)}
        onClose={() => setServiceToDelete(null)}
        onConfirm={handleDelete}
        title="Delete service?"
        description={`This removes ${serviceToDelete?.name || "this service"}.`}
        isLoading={isDeleting}
      />
    </Stack>
  );
}
