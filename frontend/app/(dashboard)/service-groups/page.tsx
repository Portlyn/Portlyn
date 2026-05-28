"use client";

import {
  Button,
  Drawer,
  Group as MantineGroup,
  MultiSelect,
  Paper,
  Select,
  Skeleton,
  Stack,
  Table,
  Text,
  TextInput,
  Textarea
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useDisclosure } from "@mantine/hooks";
import Link from "next/link";
import { useEffect, useState } from "react";

import { AccessPolicyFields } from "@/components/access-policy-fields";
import { AdminOnly } from "@/components/admin-only";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { PageHeader } from "@/components/layout/page-header";
import { AccessMethodBadge } from "@/components/status-badge";
import { buildServiceGroupRequestPayload, defaultServiceGroupPayload } from "@/lib/access-control";
import { apiFetch, ApiError } from "@/lib/api";
import type { AccessPolicy, Group as UserGroup, Service, ServiceGroup, ServiceGroupPayload } from "@/lib/types";

export default function ServiceGroupsPage() {
  const [items, setItems] = useState<ServiceGroup[]>([]);
  const [groups, setGroups] = useState<UserGroup[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [selected, setSelected] = useState<ServiceGroup | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ServiceGroup | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [defaultPolicy, setDefaultPolicy] = useState<AccessPolicy>(defaultServiceGroupPayload().default_access_policy);
  const [accessMethod, setAccessMethod] = useState<ServiceGroupPayload["access_method"]>("");
  const [accessMethodConfig, setAccessMethodConfig] = useState<ServiceGroupPayload["access_method_config"]>({});
  const [allowedEmailsText, setAllowedEmailsText] = useState("");
  const [serviceIds, setServiceIds] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [opened, { open, close }] = useDisclosure(false);

  const loadData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [serviceGroups, userGroups, serviceItems] = await Promise.all([
        apiFetch<ServiceGroup[]>("/api/v1/service-groups"),
        apiFetch<UserGroup[]>("/api/v1/groups"),
        apiFetch<Service[]>("/api/v1/services")
      ]);
      setItems(serviceGroups);
      setGroups(userGroups);
      setServices(serviceItems);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load service groups.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const beginEdit = (item?: ServiceGroup) => {
    const payload = defaultServiceGroupPayload(item);
    setSelected(item || null);
    setName(payload.name);
    setDescription(payload.description);
    setDefaultPolicy(payload.default_access_policy);
    setAccessMethod(payload.access_method);
    setAccessMethodConfig(payload.access_method_config);
    setAllowedEmailsText((payload.access_method_config.allowed_emails || []).join("\n"));
    setServiceIds(payload.service_ids.map(String));
    open();
  };

  const handleSave = async () => {
    setIsSaving(true);
    try {
      const payload = buildServiceGroupRequestPayload({
        name,
        description,
        default_access_policy: defaultPolicy,
        access_method: accessMethod,
        access_method_config: {
          ...accessMethodConfig,
          allowed_emails: allowedEmailsText
            .split(/\r?\n|,/)
            .map((item) => item.trim().toLowerCase())
            .filter(Boolean)
        },
        service_ids: serviceIds.map(Number)
      }, { omitEmptyAccessMethod: Boolean(selected) });
      if (selected) {
        await apiFetch<ServiceGroup>(`/api/v1/service-groups/${selected.id}`, {
          method: "PATCH",
          body: JSON.stringify(payload)
        });
      } else {
        await apiFetch<ServiceGroup>("/api/v1/service-groups", {
          method: "POST",
          body: JSON.stringify(payload)
        });
      }
      notifications.show({ color: "success", message: selected ? "Service group updated" : "Service group created" });
      close();
      await loadData();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to save service group." });
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setIsDeleting(true);
    try {
      await apiFetch<void>(`/api/v1/service-groups/${deleteTarget.id}`, { method: "DELETE" });
      notifications.show({ color: "success", message: "Service group deleted" });
      setDeleteTarget(null);
      await loadData();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to delete service group." });
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <AdminOnly>
      <Stack gap="lg">
        <PageHeader
          action={<Button onClick={() => beginEdit()}>New service group</Button>}
        />

        {error ? <ErrorState title="Failed to load service groups" message={error} onRetry={() => void loadData()} /> : null}

        {isLoading ? (
          <Stack gap="sm"><Skeleton height={54} /><Skeleton height={54} /></Stack>
        ) : items.length === 0 ? (
          <EmptyState title="No service groups found" description="Group related services and assign a shared default policy." />
        ) : (
          <Paper withBorder radius="md" p="sm">
            <Table.ScrollContainer minWidth={900}>
              <Table>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Name</Table.Th>
                    <Table.Th>Description</Table.Th>
                    <Table.Th>Default policy</Table.Th>
                    <Table.Th>Access method</Table.Th>
                    <Table.Th>Services</Table.Th>
                    <Table.Th ta="right">Actions</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {items.map((item) => (
                    <Table.Tr key={item.id}>
                      <Table.Td>
                        <Text component={Link} href={`/service-groups/detail?id=${item.id}`} fw={600}>
                          {item.name}
                        </Text>
                      </Table.Td>
                      <Table.Td>{item.description || "No description"}</Table.Td>
                      <Table.Td>{item.default_access_policy.access_mode}</Table.Td>
                      <Table.Td><AccessMethodBadge value={item.access_method || "session"} /></Table.Td>
                      <Table.Td>{item.service_count || item.services?.length || 0}</Table.Td>
                      <Table.Td>
                        <MantineGroup justify="flex-end">
                          <Button variant="subtle" onClick={() => beginEdit(item)}>Edit</Button>
                          <Button variant="subtle" color="danger" onClick={() => setDeleteTarget(item)}>Delete</Button>
                        </MantineGroup>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </Paper>
        )}

        <Drawer opened={opened} onClose={close} title={selected ? "Edit service group" : "Create service group"} position="right" size="xl">
          <Stack gap="md">
            <TextInput label="Name" value={name} onChange={(event) => setName(event.currentTarget.value)} />
            <Textarea label="Description" value={description} onChange={(event) => setDescription(event.currentTarget.value)} minRows={4} />
            <MultiSelect
              label="Assigned services"
              data={services.map((service) => ({ value: String(service.id), label: service.name }))}
              value={serviceIds}
              onChange={setServiceIds}
              searchable
            />
            <AccessPolicyFields value={defaultPolicy} groups={groups} serviceGroups={items} onChange={setDefaultPolicy} />
            <Select
              label="Default access method"
              data={[
                { value: "", label: "Inherit / Session (default)" },
                { value: "session", label: "Session (Standard)" },
                { value: "oidc_only", label: "OIDC / Keycloak" },
                { value: "pin", label: "Route-PIN" },
                { value: "email_code", label: "E-Mail Code" }
              ]}
              value={accessMethod}
              onChange={(value) => setAccessMethod((value || "") as ServiceGroupPayload["access_method"])}
            />
            {(accessMethod === "pin" || accessMethod === "email_code") ? (
              <TextInput
                label="Hint"
                value={accessMethodConfig.hint || ""}
                onChange={(event) => setAccessMethodConfig((current) => ({ ...current, hint: event.currentTarget.value }))}
              />
            ) : null}
            {accessMethod === "pin" ? (
              <TextInput
                label="Route-PIN"
                description="Only sent on save. Existing PIN stays unchanged if left blank."
                value={accessMethodConfig.pin || ""}
                onChange={(event) => setAccessMethodConfig((current) => ({ ...current, pin: event.currentTarget.value }))}
              />
            ) : null}
            {accessMethod === "email_code" ? (
              <>
                <TextInput
                  label="Allowed email domain"
                  value={accessMethodConfig.allowed_email_domain || ""}
                  onChange={(event) => setAccessMethodConfig((current) => ({ ...current, allowed_email_domain: event.currentTarget.value }))}
                />
                <Textarea
                  label="Allowed email addresses"
                  minRows={4}
                  value={allowedEmailsText}
                  onChange={(event) => setAllowedEmailsText(event.currentTarget.value)}
                />
              </>
            ) : null}
            <Button loading={isSaving} onClick={handleSave} disabled={!name.trim()}>
              {selected ? "Save changes" : "Create service group"}
            </Button>
          </Stack>
        </Drawer>

        <ConfirmDialog
          isOpen={Boolean(deleteTarget)}
          onClose={() => setDeleteTarget(null)}
          onConfirm={handleDelete}
          title="Delete service group?"
          description={`This removes ${deleteTarget?.name || "this service group"}.`}
          isLoading={isDeleting}
        />
      </Stack>
    </AdminOnly>
  );
}
