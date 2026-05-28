"use client";

import { ActionIcon, Badge, Button, Group, Stack, Table, Text } from "@mantine/core";
import { IconEdit, IconRefresh, IconRotateClockwise, IconTrash } from "@tabler/icons-react";

import { StatusBadge } from "@/components/status-badge";
import { formatDateTime } from "@/lib/format";
import type { Certificate } from "@/lib/types";

export function CertificateTable({
  certificates,
  canManage,
  onEdit,
  onDelete,
  onRetry,
  onRenew,
  onSync,
  onInspect,
  onImport
}: {
  certificates: Certificate[];
  canManage?: boolean;
  onEdit?: (certificate: Certificate) => void;
  onDelete?: (certificate: Certificate) => void;
  onRetry?: (certificate: Certificate) => void;
  onRenew?: (certificate: Certificate) => void;
  onSync?: (certificate: Certificate) => void;
  onInspect?: (certificate: Certificate) => void;
  onImport?: (certificate: Certificate) => void;
}) {
  return (
    <Table.ScrollContainer minWidth={1560}>
      <Table verticalSpacing="md" horizontalSpacing="md">
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Primary Domain</Table.Th>
            <Table.Th>SANs</Table.Th>
            <Table.Th>Type</Table.Th>
            <Table.Th>Challenge</Table.Th>
            <Table.Th>Issuer</Table.Th>
            <Table.Th>Status</Table.Th>
            <Table.Th>Issued</Table.Th>
            <Table.Th>Expires At</Table.Th>
            <Table.Th>Next Renewal</Table.Th>
            <Table.Th>Checked</Table.Th>
            <Table.Th>DNS Provider</Table.Th>
            <Table.Th>Auto Renew</Table.Th>
            <Table.Th>Error</Table.Th>
            {canManage ? <Table.Th ta="right">Actions</Table.Th> : null}
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {certificates.map((certificate) => {
            const sans = certificate.sans || [];
            return (
            <Table.Tr key={certificate.id} onClick={() => onInspect?.(certificate)} style={{ cursor: onInspect ? "pointer" : undefined }}>
              <Table.Td>
                <Stack gap={2}>
                  <Text fw={600}>{certificate.primary_domain || certificate.domain?.name || `#${certificate.domain_id}`}</Text>
                  <Text size="xs" c="dimmed">{certificate.domain?.name || `domain #${certificate.domain_id}`}</Text>
                </Stack>
              </Table.Td>
              <Table.Td>
                {sans.length > 0 ? (
                  <Stack gap={4}>
                    <Badge size="sm" color="gray">{sans.length} SANs</Badge>
                    <Text size="xs" c="dimmed">{sans.slice(0, 3).map((item) => item.domain_name).join(", ")}{sans.length > 3 ? " ..." : ""}</Text>
                  </Stack>
                ) : "0"}
              </Table.Td>
              <Table.Td>{certificate.type}</Table.Td>
              <Table.Td>{certificate.challenge_type || "-"}</Table.Td>
              <Table.Td>{certificate.issuer === "letsencrypt_staging" ? "LE Staging" : "LE Prod"}</Table.Td>
              <Table.Td><StatusBadge status={certificate.status} /></Table.Td>
              <Table.Td>{formatDateTime(certificate.issued_at)}</Table.Td>
              <Table.Td>{formatDateTime(certificate.expires_at)}</Table.Td>
              <Table.Td>{formatDateTime(certificate.next_renewal_at)}</Table.Td>
              <Table.Td>{formatDateTime(certificate.last_checked_at)}</Table.Td>
              <Table.Td>{certificate.dns_provider?.name || "-"}</Table.Td>
              <Table.Td>{certificate.is_auto_renew ? "Enabled" : "Disabled"}</Table.Td>
              <Table.Td><Text c="#7e8795" size="sm">{certificate.last_error || "-"}</Text></Table.Td>
              {canManage ? (
                <Table.Td>
                  <Stack align="flex-end" gap="xs">
                    <Group justify="flex-end" gap="xs">
                      <ActionIcon variant="subtle" color="gray" onClick={() => onEdit?.(certificate)}>
                        <IconEdit size={16} />
                      </ActionIcon>
                      <ActionIcon variant="subtle" color="gray" onClick={() => onDelete?.(certificate)}>
                        <IconTrash size={16} />
                      </ActionIcon>
                    </Group>
                    <Group justify="flex-end" gap="xs">
                      <Button size="xs" variant="default" leftSection={<IconRefresh size={14} />} onClick={() => onSync?.(certificate)}>
                        Re-check
                      </Button>
                      <Button size="xs" variant="default" leftSection={<IconRotateClockwise size={14} />} onClick={() => onRetry?.(certificate)}>
                        Retry
                      </Button>
                      <Button size="xs" variant="light" color="brand" onClick={() => onRenew?.(certificate)}>
                        Renew
                      </Button>
                      <Button size="xs" variant="default" onClick={() => onImport?.(certificate)}>
                        Import PEM
                      </Button>
                    </Group>
                  </Stack>
                </Table.Td>
              ) : null}
            </Table.Tr>
            );
          })}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}
