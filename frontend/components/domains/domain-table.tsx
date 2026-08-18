"use client";

import { ActionIcon, Group, Table } from "@mantine/core";
import { IconEdit, IconTrash } from "@tabler/icons-react";

import type { Domain } from "@/lib/types";

export function DomainTable({
  domains,
  canManage,
  onEdit,
  onDelete
}: {
  domains: Domain[];
  canManage?: boolean;
  onEdit?: (domain: Domain) => void;
  onDelete?: (domain: Domain) => void;
}) {
  return (
    <Table.ScrollContainer minWidth={800}>
      <Table verticalSpacing="md" horizontalSpacing="md">
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Name</Table.Th>
            <Table.Th>Type</Table.Th>
            <Table.Th>Provider</Table.Th>
            <Table.Th>Notes</Table.Th>
            {canManage ? <Table.Th ta="right">Actions</Table.Th> : null}
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {domains.map((domain) => (
            <Table.Tr key={domain.id}>
              <Table.Td>{domain.name}</Table.Td>
              <Table.Td>{domain.type}</Table.Td>
              <Table.Td>{domain.provider || "-"}</Table.Td>
              <Table.Td>{domain.notes || "-"}</Table.Td>
              {canManage ? (
                <Table.Td>
                  <Group justify="flex-end" gap="xs">
                    <ActionIcon variant="subtle" color="gray" aria-label={`Edit ${domain.name}`} onClick={() => onEdit?.(domain)}>
                      <IconEdit size={16} />
                    </ActionIcon>
                    <ActionIcon variant="subtle" color="gray" aria-label={`Delete ${domain.name}`} onClick={() => onDelete?.(domain)}>
                      <IconTrash size={16} />
                    </ActionIcon>
                  </Group>
                </Table.Td>
              ) : null}
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}
