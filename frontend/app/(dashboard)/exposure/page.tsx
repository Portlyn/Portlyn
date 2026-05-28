"use client";

import { Badge, Button, Card, Group, Loader, Progress, Stack, Table, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import Link from "next/link";
import { useEffect, useState } from "react";

import { AdminOnly } from "@/components/admin-only";
import { PageHeader } from "@/components/layout/page-header";
import { apiFetch, ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { ExposureReport, Service } from "@/lib/types";

function scoreColor(score: number): string {
  if (score >= 80) return "success";
  if (score >= 60) return "warning";
  if (score >= 30) return "warning";
  return "danger";
}

export default function ExposureOverviewPage() {
  const [reports, setReports] = useState<ExposureReport[]>([]);
  const [services, setServices] = useState<Record<number, Service>>({});
  const [loading, setLoading] = useState(true);
  const [scanningAll, setScanningAll] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const [reportList, serviceList] = await Promise.all([
        apiFetch<ExposureReport[]>("/api/v1/exposure-reports"),
        apiFetch<Service[]>("/api/v1/services")
      ]);
      setReports(reportList);
      const map: Record<number, Service> = {};
      for (const s of serviceList) map[s.id] = s;
      setServices(map);
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Failed to load exposure reports." });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const scanAll = async () => {
    setScanningAll(true);
    try {
      const serviceList = Object.values(services);
      for (const s of serviceList) {
        try {
          await apiFetch<ExposureReport>(`/api/v1/services/${s.id}/exposure-scan`, { method: "POST" });
        } catch {
          // continue scanning the rest
        }
      }
      await load();
      notifications.show({ color: "success", message: "Scan complete." });
    } finally {
      setScanningAll(false);
    }
  };

  const sorted = reports
    .filter((report) => services[report.service_id])
    .sort((a, b) => a.score - b.score);

  return (
    <AdminOnly>
      <Stack gap="lg">
        <PageHeader
          action={
            <Button variant="light" loading={scanningAll} onClick={() => void scanAll()} disabled={Object.keys(services).length === 0}>
              Scan all services
            </Button>
          }
        />

        {loading ? (
          <Stack align="center" py="md"><Loader color="brand" /></Stack>
        ) : sorted.length === 0 ? (
          <Card withBorder>
            <Text c="dimmed">No exposure reports yet. Run a scan from a service's Exposure tab or use "Scan all services".</Text>
          </Card>
        ) : (
          <Card withBorder>
            <Table striped>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Service</Table.Th>
                  <Table.Th>Score</Table.Th>
                  <Table.Th>HTTPS</Table.Th>
                  <Table.Th>Auth</Table.Th>
                  <Table.Th>Findings</Table.Th>
                  <Table.Th>Checked</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {sorted.map((report) => {
                  const service = services[report.service_id];
                  return (
                    <Table.Tr key={report.service_id}>
                      <Table.Td>
                        <Text component={Link} href={`/services/detail?id=${report.service_id}`} fw={600}>
                          {service?.name || `#${report.service_id}`}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Group gap="xs" wrap="nowrap">
                          <Badge color={scoreColor(report.score)}>{report.score}</Badge>
                          <Progress value={report.score} color={scoreColor(report.score)} w={80} />
                        </Group>
                      </Table.Td>
                      <Table.Td><Badge color={report.https_valid ? "success" : "danger"}>{report.https_valid ? "valid" : "invalid"}</Badge></Table.Td>
                      <Table.Td><Badge color={report.auth_enforced ? "success" : "danger"}>{report.auth_enforced ? "enforced" : "open"}</Badge></Table.Td>
                      <Table.Td><Text size="sm" c="dimmed">{report.findings.length} findings</Text></Table.Td>
                      <Table.Td><Text size="sm">{formatDateTime(report.checked_at)}</Text></Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </Card>
        )}
      </Stack>
    </AdminOnly>
  );
}
