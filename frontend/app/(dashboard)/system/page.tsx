"use client";

import { Alert, Card, Group, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { useEffect, useState } from "react";

import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { MetricCard } from "@/components/system/metric-card";
import { AccessMethodBadge, AccessModeBadge, StatusBadge } from "@/components/status-badge";
import { apiFetch, ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { SystemOverview } from "@/lib/types";

export default function SystemPage() {
  const [overview, setOverview] = useState<SystemOverview | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setIsLoading(true);
    setError(null);
    try {
      setOverview(await apiFetch<SystemOverview>("/api/v1/system/overview"));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load system overview.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  if (error) {
    return <ErrorState title="Failed to load system overview" message={error} onRetry={() => void load()} />;
  }

  if (isLoading || !overview) {
    return <Text c="dimmed">Loading runtime overview...</Text>;
  }

  const warningsCount =
    overview.warnings.expiring_certificates.length +
    overview.warnings.failed_certificates.length +
    overview.warnings.offline_nodes.length +
    overview.warnings.risky_services.length +
    overview.warnings.config.length;

  return (
    <Stack gap="lg">
      <div>
        <Title order={2}>Operations Overview</Title>
      </div>

      <SimpleGrid cols={{ base: 1, sm: 2, xl: 4 }}>
        <MetricCard label="API" value={<StatusBadge status={overview.runtime.api_status} />} hint={overview.runtime.http_addr} />
        <MetricCard label="Database" value={<StatusBadge status={overview.runtime.db_status} />} hint={`checked ${formatDateTime(overview.runtime.checked_at)}`} />
        <MetricCard label="Proxy" value={<StatusBadge status={overview.runtime.proxy_status} />} hint={overview.runtime.proxy_http_addr} />
        <MetricCard label="Warnings" value={warningsCount} accent={warningsCount > 0 ? "#ffb86b" : "#74d39f"} hint="Aggregated operational findings" />
      </SimpleGrid>

      <SimpleGrid cols={{ base: 1, sm: 2, xl: 4 }}>
        <MetricCard label="Services" value={overview.counts.services} />
        <MetricCard label="Domains" value={overview.counts.domains} />
        <MetricCard label="Certificates" value={overview.counts.certificates} />
        <MetricCard label="DNS Providers" value={overview.counts.dns_providers} />
        <MetricCard label="Proxy Routes" value={overview.counts.proxy_routes} />
        <MetricCard label="Nodes Online" value={overview.counts.nodes_online} accent="#74d39f" />
        <MetricCard label="Nodes Offline" value={overview.counts.nodes_offline} accent={overview.counts.nodes_offline > 0 ? "#ff7b72" : "#74d39f"} />
        <MetricCard label="Users / Groups" value={`${overview.counts.users} / ${overview.counts.groups}`} />
        <MetricCard label="Service Groups" value={overview.counts.service_groups} />
      </SimpleGrid>

      <Card withBorder>
        <Stack gap="xs">
          <Text fw={600}>Runtime</Text>
          <Text size="sm" c="dimmed">HTTP API: {overview.runtime.http_addr}</Text>
          <Text size="sm" c="dimmed">Proxy HTTP: {overview.runtime.proxy_http_addr}</Text>
          <Text size="sm" c="dimmed">Proxy HTTPS: {overview.runtime.proxy_https_addr || "disabled"}</Text>
          <Text size="sm" c="dimmed">TLS: {overview.runtime.tls_enabled ? "enabled" : "disabled"} | ACME: {overview.runtime.acme_enabled ? "enabled" : "disabled"} | Redirect HTTP to HTTPS: {overview.runtime.redirect_http_to_https ? "enabled" : "disabled"}</Text>
          <Text size="sm" c="dimmed">Challenge types: {overview.runtime.acme_challenge_types.join(", ")} | Issuers: {overview.certificates.supported_issuers.join(", ")}</Text>
          <Text size="sm" c="dimmed">DNS providers: {overview.certificates.dns_provider_count} ({overview.certificates.dns_provider_types.join(", ") || "none"}) | Wildcard: {overview.certificates.supports_wildcard ? "yes" : "no"} | Multi SAN: {overview.certificates.supports_multi_san ? "yes" : "no"}</Text>
          <Text size="sm" c="dimmed">JWT TTL: {overview.security.jwt_ttl_seconds}s | Refresh TTL: {overview.security.refresh_token_ttl_seconds}s | Auth failures 24h: {overview.counts.auth_failures_24h}</Text>
        </Stack>
      </Card>

      <SimpleGrid cols={{ base: 1, md: 3 }}>
        <Card withBorder>
          <Stack gap="xs">
            <Text fw={600}>Readiness</Text>
            {overview.health.readyz.map((item) => (
              <Group key={`ready-${item.name}`} justify="space-between">
                <Text size="sm">{item.name}</Text>
                <StatusBadge status={item.level} />
              </Group>
            ))}
          </Stack>
        </Card>
        <Card withBorder>
          <Stack gap="xs">
            <Text fw={600}>Service Health</Text>
            {overview.health.services.length === 0 ? <Text size="sm" c="dimmed">No services registered.</Text> : overview.health.services.slice(0, 6).map((item) => (
              <Group key={`svc-${item.name}`} justify="space-between">
                <Text size="sm">{item.name}</Text>
                <StatusBadge status={item.level} />
              </Group>
            ))}
          </Stack>
        </Card>
        <Card withBorder>
          <Stack gap="xs">
            <Text fw={600}>Cluster Health</Text>
            {overview.health.cluster.length === 0 ? <Text size="sm" c="dimmed">No cluster warnings.</Text> : overview.health.cluster.map((item) => (
              <Group key={`cluster-${item.name}`} justify="space-between">
                <Text size="sm">{item.name}</Text>
                <StatusBadge status={item.level} />
              </Group>
            ))}
          </Stack>
        </Card>
      </SimpleGrid>

      {overview.warnings.config.length > 0 ? (
        <Alert color="warning" variant="light" title="Configuration warnings">
          {overview.warnings.config.map((item) => item.message).join(" ")}
        </Alert>
      ) : null}

      <Card withBorder>
        <Stack gap="sm">
          <Text fw={600}>Certificate Warnings</Text>
          {overview.warnings.expiring_certificates.length === 0 && overview.warnings.failed_certificates.length === 0 ? (
            <EmptyState title="No certificate issues" description="No failed or soon-to-expire certificates detected." />
          ) : (
            <Table.ScrollContainer minWidth={800}>
              <Table>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Domain</Table.Th>
                    <Table.Th>Status</Table.Th>
                    <Table.Th>Expires</Table.Th>
                    <Table.Th>Error</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {[...overview.warnings.failed_certificates, ...overview.warnings.expiring_certificates].map((item) => (
                    <Table.Tr key={`cert-${item.id}`}>
                      <Table.Td>{item.domain?.name || `#${item.domain_id}`}</Table.Td>
                      <Table.Td><StatusBadge status={item.status} /></Table.Td>
                      <Table.Td>{formatDateTime(item.expires_at)}</Table.Td>
                      <Table.Td>{item.last_error || "-"}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}
        </Stack>
      </Card>

      <Card withBorder>
        <Stack gap="sm">
          <Text fw={600}>Offline Nodes</Text>
          {overview.warnings.offline_nodes.length === 0 ? (
            <EmptyState title="All nodes online" description="No offline nodes detected." />
          ) : (
            <Table.ScrollContainer minWidth={720}>
              <Table>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Name</Table.Th>
                    <Table.Th>Status</Table.Th>
                    <Table.Th>Last heartbeat</Table.Th>
                    <Table.Th>Version</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {overview.warnings.offline_nodes.map((node) => (
                    <Table.Tr key={node.id}>
                      <Table.Td>{node.name}</Table.Td>
                      <Table.Td><StatusBadge status={node.status} /></Table.Td>
                      <Table.Td>{formatDateTime(node.last_heartbeat_at)}</Table.Td>
                      <Table.Td>{node.version || "n/a"}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}
        </Stack>
      </Card>

      <Card withBorder>
        <Stack gap="sm">
          <Text fw={600}>Risky Services</Text>
          {overview.warnings.risky_services.length === 0 ? (
            <EmptyState title="No risky services flagged" description="No obvious risky service configurations were detected." />
          ) : (
            <Table.ScrollContainer minWidth={900}>
              <Table>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Service</Table.Th>
                    <Table.Th>Access mode</Table.Th>
                    <Table.Th>Access method</Table.Th>
                    <Table.Th>Reasons</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {overview.warnings.risky_services.map((service) => (
                    <Table.Tr key={service.id}>
                      <Table.Td>{service.domain_name}{service.path} ({service.name})</Table.Td>
                      <Table.Td><AccessModeBadge value={service.access_mode} /></Table.Td>
                      <Table.Td><AccessMethodBadge value={service.access_method} /></Table.Td>
                      <Table.Td>{service.reasons.join(", ")}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}
        </Stack>
      </Card>
    </Stack>
  );
}
