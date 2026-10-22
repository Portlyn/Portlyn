"use client";

import { Badge, Button, Code, Drawer, Group, Paper, Select, SimpleGrid, Skeleton, Stack, Switch, Table, Text, TextInput } from "@mantine/core";
import { useCallback, useEffect, useRef, useState } from "react";

import { AdminOnly } from "@/components/admin-only";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { ApiError, apiFetch } from "@/lib/api";
import type { AccessLogEntry } from "@/lib/types";

const PAGE_SIZE = 200;
const REFRESH_MS = 5000;

const timeFormat = new Intl.DateTimeFormat("de-DE", { dateStyle: "short", timeStyle: "medium" });

function statusColor(status: number) {
  if (status >= 500) return "danger";
  if (status >= 400) return "warning";
  if (status >= 300) return "gray";
  return "success";
}

function formatLatency(ms: number) {
  if (ms < 1) return "<1 ms";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

type Filters = { host: string; status: string; ip: string; q: string; outcome: string };

const emptyFilters: Filters = { host: "", status: "", ip: "", q: "", outcome: "" };

function buildQuery(filters: Filters, before?: string) {
  const params = new URLSearchParams({ limit: String(PAGE_SIZE) });
  for (const [key, value] of Object.entries(filters)) {
    if (value.trim()) params.set(key, value.trim());
  }
  if (before) params.set("before", before);
  return params.toString();
}

export default function AccessLogPage() {
  const [items, setItems] = useState<AccessLogEntry[]>([]);
  const [draft, setDraft] = useState<Filters>(emptyFilters);
  const [filters, setFilters] = useState<Filters>(emptyFilters);
  const [live, setLive] = useState(true);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingOlder, setIsLoadingOlder] = useState(false);
  const [hasOlder, setHasOlder] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AccessLogEntry | null>(null);
  const loadedOlder = useRef(false);

  const load = useCallback(async (active: Filters, quiet = false) => {
    if (!quiet) setIsLoading(true);
    try {
      const response = await apiFetch<{ items: AccessLogEntry[] }>(`/api/v1/access-logs?${buildQuery(active)}`);
      setItems(response.items);
      setHasOlder(response.items.length === PAGE_SIZE);
      loadedOlder.current = false;
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load the access log.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(filters);
  }, [filters, load]);

  useEffect(() => {
    if (!live) return;
    const timer = window.setInterval(() => {
      if (!loadedOlder.current && document.visibilityState === "visible") {
        void load(filters, true);
      }
    }, REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [filters, live, load]);

  const loadOlder = async () => {
    const last = items[items.length - 1];
    if (!last) return;
    setIsLoadingOlder(true);
    try {
      const response = await apiFetch<{ items: AccessLogEntry[] }>(`/api/v1/access-logs?${buildQuery(filters, last.time)}`);
      setItems((current) => [...current, ...response.items]);
      setHasOlder(response.items.length === PAGE_SIZE);
      loadedOlder.current = true;
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load older entries.");
    } finally {
      setIsLoadingOlder(false);
    }
  };

  const setDraftValue = (key: keyof Filters) => (value: string) => setDraft((current) => ({ ...current, [key]: value }));

  return (
    <AdminOnly>
      <Stack gap="lg">
        <SimpleGrid cols={{ base: 1, sm: 2, lg: 3, xl: 5 }}>
          <TextInput placeholder="Host" value={draft.host} onChange={(event) => setDraftValue("host")(event.currentTarget.value)} />
          <TextInput placeholder="Status, e.g. 404 or 4xx" value={draft.status} onChange={(event) => setDraftValue("status")(event.currentTarget.value)} />
          <TextInput placeholder="Client IP" value={draft.ip} onChange={(event) => setDraftValue("ip")(event.currentTarget.value)} />
          <TextInput placeholder="Path, user agent or user" value={draft.q} onChange={(event) => setDraftValue("q")(event.currentTarget.value)} />
          <Select
            data={[
              { value: "", label: "All outcomes" },
              { value: "proxied", label: "proxied" },
              { value: "denied", label: "denied" },
              { value: "not_found", label: "not found" },
              { value: "degraded", label: "degraded" }
            ]}
            value={draft.outcome}
            onChange={(value) => setDraftValue("outcome")(value || "")}
          />
        </SimpleGrid>
        <Group justify="space-between">
          <Switch label="Live" checked={live} onChange={(event) => setLive(event.currentTarget.checked)} />
          <Group gap="xs">
            <Button
              variant="subtle"
              onClick={() => {
                setDraft(emptyFilters);
                setFilters(emptyFilters);
              }}
            >
              Reset
            </Button>
            <Button variant="default" onClick={() => setFilters(draft)}>
              Apply Filters
            </Button>
          </Group>
        </Group>

        {error ? <ErrorState title="Failed to load the access log" message={error} onRetry={() => void load(filters)} /> : null}

        {isLoading ? (
          <Stack gap="sm">
            <Skeleton height={54} />
            <Skeleton height={54} />
          </Stack>
        ) : items.length === 0 ? (
          <EmptyState title="No requests" description="Nothing has been proxied since the last restart." />
        ) : (
          <Paper withBorder radius="md" p="sm">
            <Stack gap="sm">
              <Table.ScrollContainer minWidth={1000}>
                <Table striped highlightOnHover withTableBorder>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Time</Table.Th>
                      <Table.Th>Status</Table.Th>
                      <Table.Th>Method</Table.Th>
                      <Table.Th>Host / Path</Table.Th>
                      <Table.Th>Client</Table.Th>
                      <Table.Th>User</Table.Th>
                      <Table.Th>Latency</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {items.map((item) => (
                      <Table.Tr key={item.request_id || `${item.time}-${item.path}`} style={{ cursor: "pointer" }} onClick={() => setSelected(item)}>
                        <Table.Td>{timeFormat.format(new Date(item.time))}</Table.Td>
                        <Table.Td>
                          <Badge color={statusColor(item.status)}>{item.status}</Badge>
                        </Table.Td>
                        <Table.Td>
                          <Code>{item.method}</Code>
                        </Table.Td>
                        <Table.Td>
                          <Stack gap={0}>
                            <Text size="sm">{item.host}</Text>
                            <Text size="xs" c="dimmed" style={{ wordBreak: "break-all" }}>
                              {item.path}
                            </Text>
                          </Stack>
                        </Table.Td>
                        <Table.Td>{item.remote_addr}</Table.Td>
                        <Table.Td>{item.user_email || "-"}</Table.Td>
                        <Table.Td>{formatLatency(item.latency_ms)}</Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
              {hasOlder ? (
                <Group justify="center">
                  <Button variant="default" loading={isLoadingOlder} onClick={() => void loadOlder()}>
                    Load older
                  </Button>
                </Group>
              ) : null}
            </Stack>
          </Paper>
        )}
      </Stack>

      <Drawer opened={selected !== null} onClose={() => setSelected(null)} position="right" size="lg" title="Request">
        {selected ? (
          <Stack gap="sm">
            {(
              [
                ["Time", timeFormat.format(new Date(selected.time))],
                ["Request ID", selected.request_id],
                ["Status", String(selected.status)],
                ["Outcome", selected.outcome],
                ["Reason", selected.reason],
                ["Access rule", selected.access_rule || "-"],
                ["Method", selected.method],
                ["Host", selected.host],
                ["Path", selected.path],
                ["Service", selected.service_name ? `${selected.service_name} (#${selected.service_id})` : "-"],
                ["Client IP", selected.remote_addr],
                ["User", selected.user_email || "-"],
                ["User agent", selected.user_agent || "-"],
                ["Referer", selected.referer || "-"],
                ["Bytes", String(selected.bytes)],
                ["Latency", formatLatency(selected.latency_ms)]
              ] as const
            ).map(([label, value]) => (
              <div key={label}>
                <Text size="xs" c="dimmed">
                  {label}
                </Text>
                <Text size="sm" style={{ wordBreak: "break-all" }}>
                  {value}
                </Text>
              </div>
            ))}
          </Stack>
        ) : null}
      </Drawer>
    </AdminOnly>
  );
}
