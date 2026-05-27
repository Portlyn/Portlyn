"use client";

import { ActionIcon, Anchor, Group, Table, Text } from "@mantine/core";
import { IconChevronRight, IconTrash } from "@tabler/icons-react";
import Link from "next/link";

import { AccessMethodBadge, AccessModeBadge, RiskBadge, StatusBadge } from "@/components/status-badge";
import { formatDateTime } from "@/lib/format";
import { serviceHostname } from "@/lib/service-host";
import type { Service } from "@/lib/types";

export function ServiceTable({
  services,
  canManage,
  onDelete
}: {
  services: Service[];
  canManage?: boolean;
  onDelete?: (service: Service) => void;
}) {
  return (
      <Table.ScrollContainer minWidth={900}>
      <Table verticalSpacing="md" horizontalSpacing="md">
        <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Domain</Table.Th>
              <Table.Th>Path</Table.Th>
              <Table.Th>Target URL</Table.Th>
              <Table.Th>Access</Table.Th>
              <Table.Th>Access Method</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th ta="right">Actions</Table.Th>
            </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {services.map((service) => (
            <Table.Tr key={service.id}>
              <Table.Td>
                <Anchor component={Link} href={`/services/detail?id=${service.id}`}>
                  {service.name}
                </Anchor>
                <Text c="dimmed" size="xs">
                  Rev {service.deployment_revision}
                </Text>
              </Table.Td>
              <Table.Td>{serviceHostname(service) || `#${service.domain_id}`}</Table.Td>
              <Table.Td>{service.path}</Table.Td>
              <Table.Td><Text size="sm" c="#c9d2df">{service.target_url}</Text></Table.Td>
              <Table.Td>
                <AccessModeBadge value={service.access_mode} />
                {service.use_group_policy ? (
                  <Text c="#7e8795" size="xs" mt={4}>
                    Inherited
                  </Text>
                ) : null}
              </Table.Td>
              <Table.Td>
                <AccessMethodBadge value={service.effective_access_method || service.access_method || "session"} />
                {service.inherited_from_group && !service.service_overrides_group ? (
                  <Text c="#7e8795" size="xs" mt={4}>
                    From {service.inherited_from_group.name}
                  </Text>
                ) : null}
                <Group mt={4}>
                  <RiskBadge value={service.risk_score} />
                </Group>
              </Table.Td>
              <Table.Td>
                <StatusBadge status={service.service_status || (service.last_deployed_at ? "healthy" : "pending")} />
                <Text c="#7e8795" size="xs" mt={4}>{formatDateTime(service.last_deployed_at)}</Text>
                {service.service_status_error ? <Text c="danger" size="xs" mt={4}>{service.service_status_error}</Text> : null}
              </Table.Td>
              <Table.Td>
                <Group justify="flex-end" gap="xs">
                  <ActionIcon component={Link} href={`/services/detail?id=${service.id}`} variant="subtle" color="gray">
                    <IconChevronRight size={16} />
                  </ActionIcon>
                  {canManage ? (
                    <ActionIcon variant="subtle" color="gray" onClick={() => onDelete?.(service)}>
                      <IconTrash size={16} />
                    </ActionIcon>
                  ) : null}
                </Group>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}
