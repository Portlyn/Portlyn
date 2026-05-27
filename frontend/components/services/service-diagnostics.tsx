"use client";

import {
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Group,
  Loader,
  Paper,
  Stack,
  Table,
  Text,
  TextInput,
} from "@mantine/core";
import { useEffect, useState } from "react";

import { apiFetch, ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";

interface DenialEvent {
  id: number;
  timestamp: string;
  request_id: string;
  method: string;
  host: string;
  path: string;
  status_code: number;
  latency_ms: number;
  remote_addr: string;
  user_agent: string;
  outcome: string;
  reason: string;
  user_id?: number;
}

interface DenialListResponse {
  items: DenialEvent[];
  limit: number;
}

interface ExplainStep {
  name: string;
  status: "ok" | "fail" | "info" | string;
  message: string;
}

interface ExplainResponse {
  service_id: number;
  allowed: boolean;
  decision: string;
  steps: ExplainStep[];
}

function statusColor(status: string): string {
  if (status === "ok") return "success";
  if (status === "fail") return "danger";
  return "gray";
}

function stepLabel(name: string): string {
  return name.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function ServiceDiagnostics({ serviceId }: { serviceId: number | string }) {
  const [denials, setDenials] = useState<DenialEvent[]>([]);
  const [loadingDenials, setLoadingDenials] = useState(true);
  const [denialsError, setDenialsError] = useState<string | null>(null);

  const [userEmail, setUserEmail] = useState("");
  const [clientIP, setClientIP] = useState("");
  const [explainResult, setExplainResult] = useState<ExplainResponse | null>(null);
  const [explaining, setExplaining] = useState(false);
  const [explainError, setExplainError] = useState<string | null>(null);

  const loadDenials = async () => {
    setLoadingDenials(true);
    setDenialsError(null);
    try {
      const response = await apiFetch<DenialListResponse>(`/api/v1/services/${serviceId}/last-denials?limit=20`);
      setDenials(response.items);
    } catch (err) {
      setDenialsError(err instanceof ApiError ? err.message : "Unable to load denial events.");
    } finally {
      setLoadingDenials(false);
    }
  };

  useEffect(() => {
    void loadDenials();
  }, [serviceId]);

  const runExplain = async () => {
    setExplaining(true);
    setExplainError(null);
    try {
      const result = await apiFetch<ExplainResponse>(`/api/v1/services/${serviceId}/explain`, {
        method: "POST",
        body: JSON.stringify({
          user_email: userEmail.trim() || undefined,
          client_ip: clientIP.trim() || undefined,
        }),
      });
      setExplainResult(result);
    } catch (err) {
      setExplainError(err instanceof ApiError ? err.message : "Unable to run access simulation.");
      setExplainResult(null);
    } finally {
      setExplaining(false);
    }
  };

  return (
    <Stack gap="lg">
      <Paper withBorder radius="md" p="lg">
        <Stack gap="md">
          <Group justify="space-between">
            <Stack gap={2}>
              <Text fw={600}>Test access policy</Text>
              <Text size="sm" c="dimmed">
                Simulate a request without firing one. Step-by-step verdict shows you exactly which check would fail.
              </Text>
            </Stack>
            <Button variant="default" onClick={() => void runExplain()} loading={explaining}>
              Run check
            </Button>
          </Group>
          <Group grow>
            <TextInput
              label="User email"
              placeholder="someone@example.com"
              value={userEmail}
              onChange={(event) => setUserEmail(event.currentTarget.value)}
            />
            <TextInput
              label="Client IP"
              placeholder="203.0.113.5 or 2001:db8::1"
              value={clientIP}
              onChange={(event) => setClientIP(event.currentTarget.value)}
            />
          </Group>

          {explainError ? (
            <Alert color="danger" variant="light">{explainError}</Alert>
          ) : null}

          {explainResult ? (
            <Card withBorder padding="md" radius="md">
              <Group justify="space-between" mb="sm">
                <Text fw={600}>{explainResult.allowed ? "Request would be allowed" : "Request would be denied"}</Text>
                <Badge color={explainResult.allowed ? "success" : "danger"} variant="filled">
                  {explainResult.decision}
                </Badge>
              </Group>
              <Stack gap="xs">
                {explainResult.steps.map((step, idx) => (
                  <Group key={`${step.name}-${idx}`} justify="space-between" wrap="nowrap" align="flex-start">
                    <Stack gap={2} style={{ flex: 1 }}>
                      <Text size="sm" fw={600}>{stepLabel(step.name)}</Text>
                      <Text size="sm" c="dimmed">{step.message}</Text>
                    </Stack>
                    <Badge color={statusColor(step.status)} variant="light">{step.status}</Badge>
                  </Group>
                ))}
              </Stack>
            </Card>
          ) : null}
        </Stack>
      </Paper>

      <Paper withBorder radius="md" p="lg">
        <Stack gap="md">
          <Group justify="space-between">
            <Stack gap={2}>
              <Text fw={600}>Recent denials</Text>
              <Text size="sm" c="dimmed">Last 20 requests that were rejected before reaching the upstream.</Text>
            </Stack>
            <Button variant="subtle" onClick={() => void loadDenials()}>Refresh</Button>
          </Group>

          {denialsError ? <Alert color="danger" variant="light">{denialsError}</Alert> : null}

          {loadingDenials ? (
            <Stack align="center" py="md"><Loader size="sm" color="brand" /></Stack>
          ) : denials.length === 0 ? (
            <Text size="sm" c="dimmed">No denials in the recent audit log — that&apos;s a good sign.</Text>
          ) : (
            <Table.ScrollContainer minWidth={900}>
              <Table striped withTableBorder>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>When</Table.Th>
                    <Table.Th>Reason</Table.Th>
                    <Table.Th>Method</Table.Th>
                    <Table.Th>Path</Table.Th>
                    <Table.Th>Client</Table.Th>
                    <Table.Th>Status</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {denials.map((event) => (
                    <Table.Tr key={event.id}>
                      <Table.Td>{formatDateTime(event.timestamp)}</Table.Td>
                      <Table.Td><Code>{event.reason || "-"}</Code></Table.Td>
                      <Table.Td>{event.method || "-"}</Table.Td>
                      <Table.Td><Text size="xs" lineClamp={1}>{event.path || "-"}</Text></Table.Td>
                      <Table.Td><Text size="xs">{event.remote_addr || "-"}</Text></Table.Td>
                      <Table.Td><Badge color="danger" variant="light">{event.status_code}</Badge></Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}
        </Stack>
      </Paper>
    </Stack>
  );
}
