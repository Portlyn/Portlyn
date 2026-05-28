"use client";

import { Button, Checkbox, Drawer, Group, Paper, Select, Skeleton, Stack, Table, Text, TextInput } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { useEffect, useState } from "react";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { PageHeader } from "@/components/layout/page-header";
import { apiFetch, ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { DNSProvider, DNSProviderPayload } from "@/lib/types";

const defaultPayload: DNSProviderPayload = {
  name: "",
  type: "cloudflare",
  config: {},
  is_active: true
};

const providerRequiredFields: Record<DNSProviderPayload["type"], string[]> = {
  cloudflare: ["api_token"],
  hetzner: ["dns_api_token"],
  route53: [],
  digitalocean: ["api_token"]
};

export default function DNSProvidersPage() {
  const [items, setItems] = useState<DNSProvider[]>([]);
  const [selected, setSelected] = useState<DNSProvider | null>(null);
  const [toDelete, setToDelete] = useState<DNSProvider | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [opened, { open, close }] = useDisclosure(false);
  const [form, setForm] = useState<DNSProviderPayload>(defaultPayload);

  const requiredFields = providerRequiredFields[form.type];
  const missingRequiredField = requiredFields.find((field) => !form.config[field]);

  const load = async () => {
    setIsLoading(true);
    setError(null);
    try {
      setItems(await apiFetch<DNSProvider[]>("/api/v1/dns-providers"));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load DNS providers.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    if (!selected) {
      setForm(defaultPayload);
      return;
    }
    setForm({
      name: selected.name,
      type: selected.type,
      config: {},
      is_active: selected.is_active
    });
  }, [selected]);

  const handleSubmit = async () => {
    setIsSaving(true);
    try {
      if (selected) {
        await apiFetch(`/api/v1/dns-providers/${selected.id}`, { method: "PATCH", body: JSON.stringify(form) });
        notifications.show({ color: "success", message: "DNS provider updated" });
      } else {
        await apiFetch("/api/v1/dns-providers", { method: "POST", body: JSON.stringify(form) });
        notifications.show({ color: "success", message: "DNS provider created" });
      }
      close();
      setSelected(null);
      await load();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to save DNS provider." });
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!toDelete) return;
    setIsDeleting(true);
    try {
      await apiFetch(`/api/v1/dns-providers/${toDelete.id}`, { method: "DELETE" });
      notifications.show({ color: "success", message: "DNS provider deleted" });
      setToDelete(null);
      await load();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to delete DNS provider." });
    } finally {
      setIsDeleting(false);
    }
  };

  const handleTest = async (item: DNSProvider) => {
    try {
      await apiFetch(`/api/v1/dns-providers/${item.id}/test`, { method: "POST" });
      notifications.show({ color: "success", message: "DNS provider validation passed" });
      await load();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Provider validation failed." });
      await load();
    }
  };

  return (
    <Stack gap="lg">
      <PageHeader
        action={<Button onClick={() => { setSelected(null); open(); }}>New Provider</Button>}
      />

      {error ? <ErrorState title="Failed to load DNS providers" message={error} onRetry={() => void load()} /> : null}

      {isLoading ? (
        <Stack gap="sm"><Skeleton height={64} /><Skeleton height={64} /></Stack>
      ) : items.length === 0 ? (
        <EmptyState title="No DNS providers configured" description="Create a provider to enable DNS-01 and wildcard certificates." />
      ) : (
        <Paper withBorder radius="md" p="sm">
          <Table.ScrollContainer minWidth={1180}>
            <Table verticalSpacing="md">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Type</Table.Th>
                  <Table.Th>Active</Table.Th>
                  <Table.Th>Stored Secret</Table.Th>
                  <Table.Th>Last Test</Table.Th>
                  <Table.Th>Error</Table.Th>
                  <Table.Th ta="right">Actions</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {items.map((item) => (
                  <Table.Tr key={item.id}>
                    <Table.Td>
                      <Stack gap={2}>
                        <Text fw={600}>{item.name}</Text>
                        <Text size="xs" c="dimmed">{item.config_hint}</Text>
                      </Stack>
                    </Table.Td>
                    <Table.Td>{item.type}</Table.Td>
                    <Table.Td>{item.is_active ? "Yes" : "No"}</Table.Td>
                    <Table.Td>{item.has_stored_secret ? "Configured" : "Missing"}</Table.Td>
                    <Table.Td>{item.last_test_status || "-"} {item.last_tested_at ? `(${formatDateTime(item.last_tested_at)})` : ""}</Table.Td>
                    <Table.Td><Text size="sm" c="dimmed">{item.last_test_error || "-"}</Text></Table.Td>
                    <Table.Td>
                      <Group justify="flex-end">
                        <Button size="xs" variant="default" onClick={() => void handleTest(item)}>Test</Button>
                        <Button size="xs" variant="default" onClick={() => { setSelected(item); open(); }}>Edit</Button>
                        <Button size="xs" color="danger" variant="light" onClick={() => setToDelete(item)}>Delete</Button>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Paper>
      )}

      <Drawer opened={opened} onClose={() => { close(); setSelected(null); }} title={selected ? "Edit DNS provider" : "Create DNS provider"} position="right">
        <Stack gap="md">
          <TextInput label="Name" value={form.name} onChange={(event) => setForm({ ...form, name: event.currentTarget.value })} />
          <Select
            label="Provider type"
            data={[
              { value: "cloudflare", label: "Cloudflare" },
              { value: "hetzner", label: "Hetzner DNS" },
              { value: "route53", label: "AWS Route53" },
              { value: "digitalocean", label: "DigitalOcean DNS" }
            ]}
            value={form.type}
            onChange={(value) => setForm({ ...form, type: (value || "cloudflare") as DNSProviderPayload["type"], config: {} })}
          />
          {requiredFields.length === 0 ? (
            <Text size="sm" c="dimmed">
              This provider can use environment/IAM credentials. Optional explicit fields: access_key_id, secret_access_key, session_token, region, hosted_zone_id, profile.
            </Text>
          ) : requiredFields.map((field) => (
            <TextInput
              key={field}
              label={field}
              placeholder={selected?.has_stored_secret ? "Leave empty to keep current secret" : "Required"}
              value={form.config[field] || ""}
              onChange={(event) => setForm({ ...form, config: { ...form.config, [field]: event.currentTarget.value } })}
            />
          ))}
          <Checkbox checked={form.is_active} onChange={(event) => setForm({ ...form, is_active: event.currentTarget.checked })} label="Provider active" />
          <Button onClick={() => void handleSubmit()} loading={isSaving} disabled={!form.name || (!selected && Boolean(missingRequiredField))}>
            {selected ? "Save Changes" : "Create Provider"}
          </Button>
        </Stack>
      </Drawer>

      <ConfirmDialog
        isOpen={Boolean(toDelete)}
        onClose={() => setToDelete(null)}
        onConfirm={handleDelete}
        title="Delete DNS provider?"
        description={`This removes ${toDelete?.name || "the selected provider"}. Certificates using DNS-01 should be updated first.`}
        isLoading={isDeleting}
      />
    </Stack>
  );
}
