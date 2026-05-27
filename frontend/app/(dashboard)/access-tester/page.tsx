"use client";

import {
  Alert,
  Badge,
  Button,
  Card,
  Group,
  Loader,
  Paper,
  Select,
  Stack,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { useEffect, useState } from "react";

import { AdminOnly } from "@/components/admin-only";
import { ErrorState } from "@/components/error-state";
import { apiFetch, ApiError } from "@/lib/api";
import type { Service } from "@/lib/types";

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

export default function AccessTesterPage() {
  const [services, setServices] = useState<Service[]>([]);
  const [serviceId, setServiceId] = useState<string | null>(null);
  const [userEmail, setUserEmail] = useState("");
  const [clientIP, setClientIP] = useState("");
  const [whenISO, setWhenISO] = useState("");
  const [result, setResult] = useState<ExplainResponse | null>(null);
  const [loadingServices, setLoadingServices] = useState(true);
  const [running, setRunning] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  const loadServices = async () => {
    setLoadingServices(true);
    setLoadError(null);
    try {
      const items = await apiFetch<Service[]>("/api/v1/services");
      setServices(items);
      if (items.length > 0 && !serviceId) {
        setServiceId(String(items[0].id));
      }
    } catch (err) {
      setLoadError(err instanceof ApiError ? err.message : "Unable to load services.");
    } finally {
      setLoadingServices(false);
    }
  };

  useEffect(() => {
    void loadServices();
  }, []);

  const runCheck = async () => {
    if (!serviceId) return;
    setRunning(true);
    setRunError(null);
    try {
      const response = await apiFetch<ExplainResponse>(`/api/v1/services/${serviceId}/explain`, {
        method: "POST",
        body: JSON.stringify({
          user_email: userEmail.trim() || undefined,
          client_ip: clientIP.trim() || undefined,
          time: whenISO.trim() || undefined,
        }),
      });
      setResult(response);
    } catch (err) {
      setRunError(err instanceof ApiError ? err.message : "Unable to evaluate.");
      setResult(null);
    } finally {
      setRunning(false);
    }
  };

  return (
    <AdminOnly>
      <Stack gap="lg">
        <Stack gap={4}>
          <Title order={2}>Access Tester</Title>
          <Text c="dimmed" size="sm">
            Simulate a request against any service without firing one. See every gate that runs and exactly where it would pass or fail.
          </Text>
        </Stack>

        {loadError ? <ErrorState title="Failed to load services" message={loadError} onRetry={() => void loadServices()} /> : null}

        <Paper withBorder radius="md" p="lg">
          <Stack gap="md">
            {loadingServices ? (
              <Stack align="center" py="md"><Loader size="sm" color="brand" /></Stack>
            ) : (
              <Select
                label="Service"
                description="Pick the route you want to evaluate."
                data={services.map((service) => ({
                  value: String(service.id),
                  label: `${service.name} (${service.path})`,
                }))}
                value={serviceId}
                onChange={(value) => setServiceId(value)}
                searchable
              />
            )}

            <Group grow>
              <TextInput
                label="User email"
                placeholder="someone@example.com"
                description="Leave empty for anonymous request."
                value={userEmail}
                onChange={(event) => setUserEmail(event.currentTarget.value)}
              />
              <TextInput
                label="Client IP"
                placeholder="203.0.113.5"
                description="Required to evaluate IP allow/blocklists."
                value={clientIP}
                onChange={(event) => setClientIP(event.currentTarget.value)}
              />
              <TextInput
                label="Time (ISO 8601)"
                placeholder="2026-05-27T14:30:00Z"
                description="Defaults to now."
                value={whenISO}
                onChange={(event) => setWhenISO(event.currentTarget.value)}
              />
            </Group>

            <Group justify="flex-end">
              <Button onClick={() => void runCheck()} loading={running} disabled={!serviceId}>
                Evaluate
              </Button>
            </Group>

            {runError ? <Alert color="danger" variant="light">{runError}</Alert> : null}

            {result ? (
              <Card withBorder padding="md" radius="md">
                <Group justify="space-between" mb="sm">
                  <Text fw={700}>{result.allowed ? "Request would be allowed" : "Request would be denied"}</Text>
                  <Badge color={result.allowed ? "success" : "danger"} variant="filled">{result.decision}</Badge>
                </Group>
                <Stack gap="xs">
                  {result.steps.map((step, idx) => (
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
      </Stack>
    </AdminOnly>
  );
}
