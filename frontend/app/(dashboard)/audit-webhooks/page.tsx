"use client";

import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Drawer,
  Group,
  Loader,
  MultiSelect,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconPlus, IconTrash, IconWebhook } from "@tabler/icons-react";
import { useEffect, useState } from "react";

import { AdminOnly } from "@/components/admin-only";
import { apiFetch, ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { AuditWebhook } from "@/lib/types";

const EVENT_TYPES = [
  { value: "*", label: "All events" },
  { value: "login_succeeded", label: "Login succeeded" },
  { value: "login_failed", label: "Login failed" },
  { value: "create", label: "Resource created" },
  { value: "update", label: "Resource updated" },
  { value: "delete", label: "Resource deleted" },
  { value: "proxy_access", label: "Proxy access" },
  { value: "magic_link_issued", label: "Magic link issued" },
  { value: "tunnel_bootstrap", label: "Tunnel bootstrap" },
  { value: "tunnel_revoke", label: "Tunnel revoke" },
  { value: "passkey_registered", label: "Passkey registered" },
  { value: "passkey_deleted", label: "Passkey deleted" },
];

const FORMATS = [
  { value: "generic", label: "Generic JSON" },
  { value: "slack", label: "Slack" },
  { value: "discord", label: "Discord" },
  { value: "ntfy", label: "ntfy" },
];

export default function AuditWebhooksPage() {
  const [items, setItems] = useState<AuditWebhook[]>([]);
  const [loading, setLoading] = useState(true);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<AuditWebhook | null>(null);

  const [name, setName] = useState("");
  const [url, setURL] = useState("");
  const [format, setFormat] = useState<string>("generic");
  const [eventTypes, setEventTypes] = useState<string[]>(["*"]);
  const [active, setActive] = useState(true);
  const [saving, setSaving] = useState(false);
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const response = await apiFetch<AuditWebhook[]>("/api/v1/audit-webhooks");
      setItems(response);
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Failed to load." });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const openCreate = () => {
    setEditing(null);
    setName("");
    setURL("");
    setFormat("generic");
    setEventTypes(["*"]);
    setActive(true);
    setCreatedSecret(null);
    setDrawerOpen(true);
  };

  const openEdit = (hook: AuditWebhook) => {
    setEditing(hook);
    setName(hook.name);
    setURL(hook.url);
    setFormat(hook.format);
    setEventTypes(hook.event_types.length > 0 ? hook.event_types : ["*"]);
    setActive(hook.active);
    setCreatedSecret(null);
    setDrawerOpen(true);
  };

  const save = async () => {
    setSaving(true);
    try {
      if (editing) {
        const updated = await apiFetch<AuditWebhook>(`/api/v1/audit-webhooks/${editing.id}`, {
          method: "PATCH",
          body: JSON.stringify({ name, url, format, event_types: eventTypes, active }),
        });
        setItems((current) => current.map((c) => (c.id === updated.id ? updated : c)));
        notifications.show({ color: "green", message: "Webhook updated." });
        setDrawerOpen(false);
      } else {
        const response = await apiFetch<{ webhook: AuditWebhook; secret: string }>("/api/v1/audit-webhooks", {
          method: "POST",
          body: JSON.stringify({ name, url, format, event_types: eventTypes, active }),
        });
        setItems((current) => [...current, response.webhook]);
        setCreatedSecret(response.secret);
        notifications.show({ color: "green", message: "Webhook created." });
      }
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Save failed." });
    } finally {
      setSaving(false);
    }
  };

  const remove = async (id: number) => {
    try {
      await apiFetch(`/api/v1/audit-webhooks/${id}`, { method: "DELETE" });
      setItems((current) => current.filter((c) => c.id !== id));
      notifications.show({ color: "green", message: "Webhook removed." });
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Delete failed." });
    }
  };

  return (
    <AdminOnly>
      <Stack gap="lg">
        <Group justify="space-between" align="flex-start">
          <Stack gap={4}>
            <Title order={2}>
              <Group gap="xs"><IconWebhook size={20} /> Audit Webhooks</Group>
            </Title>
            <Text c="dimmed" size="sm">
              Forward audit events to Slack, Discord, ntfy, or any HTTP endpoint. Each delivery is signed with an HMAC-SHA256 header (<Code>X-Portlyn-Signature</Code>).
            </Text>
          </Stack>
          <Button leftSection={<IconPlus size={14} />} onClick={openCreate}>New webhook</Button>
        </Group>

        {loading ? (
          <Stack align="center" py="md"><Loader color="brand" /></Stack>
        ) : items.length === 0 ? (
          <Alert color="brand" variant="light">No webhooks configured yet.</Alert>
        ) : (
          <Card withBorder>
            <Table striped>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>URL</Table.Th>
                  <Table.Th>Format</Table.Th>
                  <Table.Th>Events</Table.Th>
                  <Table.Th>Last fire</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th></Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {items.map((hook) => (
                  <Table.Tr key={hook.id} style={{ cursor: "pointer" }} onClick={() => openEdit(hook)}>
                    <Table.Td>{hook.name}</Table.Td>
                    <Table.Td><Code>{hook.url}</Code></Table.Td>
                    <Table.Td>{hook.format}</Table.Td>
                    <Table.Td>{hook.event_types.length > 0 ? hook.event_types.join(", ") : "all"}</Table.Td>
                    <Table.Td>{formatDateTime(hook.last_fired_at)}</Table.Td>
                    <Table.Td>
                      <Badge color={hook.active ? "teal" : "gray"} variant="light">{hook.active ? "active" : "paused"}</Badge>
                      {hook.last_status > 0 ? <Text size="xs" c="dimmed">{hook.last_status} {hook.last_error}</Text> : null}
                    </Table.Td>
                    <Table.Td>
                      <ActionIcon variant="subtle" color="red" onClick={(event) => { event.stopPropagation(); void remove(hook.id); }}>
                        <IconTrash size={16} />
                      </ActionIcon>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Card>
        )}

        <Drawer opened={drawerOpen} onClose={() => setDrawerOpen(false)} title={editing ? `Edit webhook — ${editing.name}` : "New webhook"} size="lg" position="right">
          <Stack gap="md">
            {createdSecret ? (
              <Alert color="yellow" variant="light">
                Save this secret now. It is shown only once.
                <Code block>{createdSecret}</Code>
              </Alert>
            ) : null}
            <TextInput label="Name" value={name} onChange={(event) => setName(event.currentTarget.value)} required />
            <TextInput label="URL" value={url} onChange={(event) => setURL(event.currentTarget.value)} required placeholder="https://hooks.slack.com/..." />
            <Select label="Format" data={FORMATS} value={format} onChange={(value) => setFormat(value || "generic")} />
            <MultiSelect label="Event types" data={EVENT_TYPES} value={eventTypes} onChange={setEventTypes} searchable />
            <Switch label="Active" checked={active} onChange={(event) => setActive(event.currentTarget.checked)} />
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setDrawerOpen(false)}>Cancel</Button>
              <Button onClick={() => void save()} loading={saving}>{editing ? "Save changes" : "Create"}</Button>
            </Group>
          </Stack>
        </Drawer>
      </Stack>
    </AdminOnly>
  );
}
