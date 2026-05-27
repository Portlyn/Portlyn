"use client";

import { Badge, Code, Drawer, Group, Stack, Table, Text } from "@mantine/core";
import { useMemo, useState } from "react";

import { formatDateTime } from "@/lib/format";
import type { AuditLog } from "@/lib/types";

type ParsedDetails = {
  outcome?: string;
  reason?: string;
  service_name?: string;
  target_host?: string;
  route_path?: string;
  raw?: unknown;
};

function parseDetails(value: string | null | undefined): ParsedDetails {
  if (!value) return {};
  try {
    const parsed = JSON.parse(value);
    if (parsed && typeof parsed === "object") {
      return {
        outcome: typeof parsed.outcome === "string" ? parsed.outcome : undefined,
        reason: typeof parsed.reason === "string" ? parsed.reason : undefined,
        service_name: typeof parsed.service_name === "string" ? parsed.service_name : undefined,
        target_host: typeof parsed.target_host === "string" ? parsed.target_host : undefined,
        route_path: typeof parsed.route_path === "string" ? parsed.route_path : undefined,
        raw: parsed,
      };
    }
  } catch {
  }
  return { raw: value };
}

function outcomeColor(outcome: string | undefined, statusCode: number | undefined): string {
  if (outcome === "proxied" || outcome === "session_bridge") return "teal";
  if (outcome === "denied") return "red";
  if (outcome === "not_found") return "gray";
  if (outcome === "admin") return "blue";
  if (outcome === "degraded") return "orange";
  if (statusCode && statusCode >= 500) return "red";
  if (statusCode && statusCode >= 400) return "orange";
  if (statusCode && statusCode >= 300) return "yellow";
  return "gray";
}

function formatLatency(ms: number | undefined): string {
  if (ms === undefined || ms === null) return "-";
  if (ms < 1) return "<1 ms";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function AuditLogTable({ items }: { items: AuditLog[] }) {
  const [selected, setSelected] = useState<AuditLog | null>(null);

  const parsed = useMemo(() => {
    const map = new Map<number, ParsedDetails>();
    for (const item of items) {
      map.set(item.id, parseDetails(item.details));
    }
    return map;
  }, [items]);

  return (
    <>
      <Table.ScrollContainer minWidth={1200}>
        <Table striped highlightOnHover withTableBorder>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Timestamp</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Outcome</Table.Th>
              <Table.Th>Reason</Table.Th>
              <Table.Th>Method</Table.Th>
              <Table.Th>Host / Path</Table.Th>
              <Table.Th>Latency</Table.Th>
              <Table.Th>User</Table.Th>
              <Table.Th>Action</Table.Th>
              <Table.Th>Resource</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((item) => {
              const detail = parsed.get(item.id) ?? {};
              return (
                <Table.Tr key={item.id} style={{ cursor: "pointer" }} onClick={() => setSelected(item)}>
                  <Table.Td>{formatDateTime(item.timestamp)}</Table.Td>
                  <Table.Td>
                    {item.status_code ? (
                      <Badge color={outcomeColor(detail.outcome, item.status_code)} variant="light">
                        {item.status_code}
                      </Badge>
                    ) : (
                      <Text c="dimmed" size="xs">-</Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    {detail.outcome ? (
                      <Badge color={outcomeColor(detail.outcome, item.status_code)} variant="filled">
                        {detail.outcome}
                      </Badge>
                    ) : (
                      <Text c="dimmed" size="xs">-</Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    {detail.reason ? <Code>{detail.reason}</Code> : <Text c="dimmed" size="xs">-</Text>}
                  </Table.Td>
                  <Table.Td>
                    {item.method ? <Code>{item.method}</Code> : <Text c="dimmed" size="xs">-</Text>}
                  </Table.Td>
                  <Table.Td>
                    {item.host || item.path ? (
                      <Stack gap={0}>
                        {item.host ? <Text size="sm">{item.host}</Text> : null}
                        {item.path ? <Text size="xs" c="dimmed">{item.path}</Text> : null}
                      </Stack>
                    ) : (
                      <Text c="dimmed" size="xs">-</Text>
                    )}
                  </Table.Td>
                  <Table.Td>{formatLatency(item.latency_ms)}</Table.Td>
                  <Table.Td>{item.user_id ? `#${item.user_id}` : "system"}</Table.Td>
                  <Table.Td>{item.action.replace(/_/g, " ")}</Table.Td>
                  <Table.Td>
                    <Stack gap={0}>
                      <Text size="sm">{item.resource_type}</Text>
                      {item.resource_id ? <Text size="xs" c="dimmed">#{item.resource_id}</Text> : null}
                    </Stack>
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Drawer
        opened={selected !== null}
        onClose={() => setSelected(null)}
        title={selected ? `Audit event #${selected.id}` : ""}
        position="right"
        size="lg"
        padding="lg"
      >
        {selected ? <AuditEventDetail item={selected} detail={parsed.get(selected.id) ?? {}} /> : null}
      </Drawer>
    </>
  );
}

function AuditEventDetail({ item, detail }: { item: AuditLog; detail: ParsedDetails }) {
  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Stack gap={2}>
          <Text size="xs" c="dimmed">Timestamp</Text>
          <Text size="sm">{formatDateTime(item.timestamp)}</Text>
        </Stack>
        {item.request_id ? (
          <Stack gap={2}>
            <Text size="xs" c="dimmed">Request ID</Text>
            <Code>{item.request_id}</Code>
          </Stack>
        ) : null}
      </Group>

      <Group grow>
        <Stack gap={2}>
          <Text size="xs" c="dimmed">Status</Text>
          {item.status_code ? (
            <Badge color={outcomeColor(detail.outcome, item.status_code)} variant="light">
              {item.status_code}
            </Badge>
          ) : (
            <Text size="sm" c="dimmed">-</Text>
          )}
        </Stack>
        <Stack gap={2}>
          <Text size="xs" c="dimmed">Outcome</Text>
          {detail.outcome ? (
            <Badge color={outcomeColor(detail.outcome, item.status_code)} variant="filled">{detail.outcome}</Badge>
          ) : (
            <Text size="sm" c="dimmed">-</Text>
          )}
        </Stack>
        <Stack gap={2}>
          <Text size="xs" c="dimmed">Reason</Text>
          <Text size="sm">{detail.reason ?? "-"}</Text>
        </Stack>
        <Stack gap={2}>
          <Text size="xs" c="dimmed">Latency</Text>
          <Text size="sm">{formatLatency(item.latency_ms)}</Text>
        </Stack>
      </Group>

      <Group grow>
        <Stack gap={2}>
          <Text size="xs" c="dimmed">Method</Text>
          <Text size="sm">{item.method || "-"}</Text>
        </Stack>
        <Stack gap={2}>
          <Text size="xs" c="dimmed">Host</Text>
          <Text size="sm">{item.host || "-"}</Text>
        </Stack>
      </Group>

      <Stack gap={2}>
        <Text size="xs" c="dimmed">Path</Text>
        <Code block>{item.path || "-"}</Code>
      </Stack>

      <Group grow>
        <Stack gap={2}>
          <Text size="xs" c="dimmed">User</Text>
          <Text size="sm">{item.user_id ? `#${item.user_id}` : "system"}</Text>
        </Stack>
        <Stack gap={2}>
          <Text size="xs" c="dimmed">Resource</Text>
          <Text size="sm">{item.resource_type}{item.resource_id ? ` #${item.resource_id}` : ""}</Text>
        </Stack>
      </Group>

      <Group grow>
        <Stack gap={2}>
          <Text size="xs" c="dimmed">Remote address</Text>
          <Text size="sm">{item.remote_addr || "-"}</Text>
        </Stack>
        <Stack gap={2}>
          <Text size="xs" c="dimmed">User agent</Text>
          <Text size="sm" lineClamp={3}>{item.user_agent || "-"}</Text>
        </Stack>
      </Group>

      <Stack gap={2}>
        <Text size="xs" c="dimmed">Raw details</Text>
        <Code block>{detail.raw === undefined ? "No details" : typeof detail.raw === "string" ? detail.raw : JSON.stringify(detail.raw, null, 2)}</Code>
      </Stack>
    </Stack>
  );
}
