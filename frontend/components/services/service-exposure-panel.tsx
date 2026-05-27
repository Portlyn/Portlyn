"use client";

import { Alert, Badge, Button, Card, Group, List, Loader, Paper, Progress, Stack, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconRefresh, IconShieldCheck } from "@tabler/icons-react";
import { useEffect, useState } from "react";

import { apiFetch, ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { ExposureReport } from "@/lib/types";

function scoreColor(score: number): string {
  if (score >= 80) return "teal";
  if (score >= 60) return "yellow";
  if (score >= 30) return "orange";
  return "red";
}

function findingLabel(key: string): string {
  return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function ServiceExposurePanel({ serviceId }: { serviceId: number }) {
  const [report, setReport] = useState<ExposureReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const response = await apiFetch<ExposureReport>(`/api/v1/exposure-reports/${serviceId}`);
      setReport(response);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setReport(null);
      } else {
        notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Failed to load report." });
      }
    } finally {
      setLoading(false);
    }
  };

  const runScan = async () => {
    setScanning(true);
    try {
      const response = await apiFetch<ExposureReport>(`/api/v1/services/${serviceId}/exposure-scan`, { method: "POST" });
      setReport(response);
      notifications.show({ color: "green", message: "Scan complete." });
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Scan failed." });
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => {
    void load();
  }, [serviceId]);

  if (loading) {
    return <Stack align="center" py="md"><Loader size="sm" color="brand" /></Stack>;
  }

  return (
    <Stack gap="md">
      <Paper withBorder radius="md" p="lg">
        <Stack gap="md">
          <Group justify="space-between">
            <Group gap="xs">
              <IconShieldCheck size={20} />
              <Text fw={600}>Exposure score</Text>
            </Group>
            <Button size="xs" variant="light" leftSection={<IconRefresh size={14} />} loading={scanning} onClick={() => void runScan()}>
              Re-scan now
            </Button>
          </Group>
          {report ? (
            <>
              <Group gap="md">
                <Badge color={scoreColor(report.score)} variant="filled" size="lg">{report.score} / 100</Badge>
                <Text size="sm" c="dimmed">Checked {formatDateTime(report.checked_at)}</Text>
              </Group>
              <Progress value={report.score} color={scoreColor(report.score)} size="lg" />
              {report.last_error ? <Alert color="red" variant="light">{report.last_error}</Alert> : null}
            </>
          ) : (
            <Alert color="brand" variant="light">No exposure report yet. Run the first scan to get a score.</Alert>
          )}
        </Stack>
      </Paper>

      {report ? (
        <Card withBorder>
          <Stack gap="xs">
            <Text fw={600}>Checks</Text>
            <CheckRow label="DNS resolvable" pass={report.dns_resolvable} />
            <CheckRow label="HTTPS certificate valid" pass={report.https_valid} extra={report.https_valid ? `expires in ${report.https_expires_in_days}d` : undefined} />
            <CheckRow label="HTTP → HTTPS redirect" pass={report.http_to_https_redirect} />
            <CheckRow label="HSTS header" pass={report.hsts_present} />
            <CheckRow label="Content-Security-Policy header" pass={report.csp_present} />
            <CheckRow label="X-Frame-Options header" pass={report.x_frame_options} />
            <CheckRow label="Auth enforced (unauthenticated requests denied)" pass={report.auth_enforced} />
            <CheckRow label="GeoIP rules configured" pass={report.geoip_configured} />
          </Stack>
        </Card>
      ) : null}

      {report && report.findings.length > 0 ? (
        <Card withBorder>
          <Stack gap="xs">
            <Text fw={600}>Findings</Text>
            <List size="sm" spacing={4}>
              {report.findings.map((f) => (
                <List.Item key={f}>{findingLabel(f)}</List.Item>
              ))}
            </List>
          </Stack>
        </Card>
      ) : null}
    </Stack>
  );
}

function CheckRow({ label, pass, extra }: { label: string; pass: boolean; extra?: string }) {
  return (
    <Group justify="space-between">
      <Text size="sm">{label}</Text>
      <Group gap="xs">
        {extra ? <Text size="xs" c="dimmed">{extra}</Text> : null}
        <Badge color={pass ? "teal" : "red"} variant="light">{pass ? "OK" : "Missing"}</Badge>
      </Group>
    </Group>
  );
}
