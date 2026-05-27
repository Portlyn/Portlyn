"use client";

import { ActionIcon, Card, Divider, Grid, Group, SimpleGrid, Stack, Text } from "@mantine/core";
import { IconEdit, IconTrash } from "@tabler/icons-react";

import { NodeTunnelPanel } from "@/components/nodes/node-tunnel-panel";
import { StatusBadge } from "@/components/status-badge";
import { formatDateTime, formatNumber } from "@/lib/format";
import type { Node } from "@/lib/types";

export function NodeGrid({
  nodes,
  canManage,
  onEdit,
  onDelete,
  onNodeUpdated,
}: {
  nodes: Node[];
  canManage?: boolean;
  onEdit?: (node: Node) => void;
  onDelete?: (node: Node) => void;
  onNodeUpdated?: (node: Node) => void;
}) {
  return (
    <Grid>
      {nodes.map((node) => (
        <Grid.Col key={node.id} span={{ base: 12, xl: 6 }}>
          <Card withBorder>
            <Stack gap="md">
              <Group justify="space-between" align="flex-start">
                <div>
                  <Text fw={600}>{node.name}</Text>
                  <Text c="dimmed" size="sm">{node.description || "No description"}</Text>
                </div>
                <StatusBadge status={node.status} />
              </Group>

              {canManage ? (
                <Group justify="flex-end" gap="xs">
                  <ActionIcon variant="subtle" color="gray" onClick={() => onEdit?.(node)}>
                    <IconEdit size={16} />
                  </ActionIcon>
                  <ActionIcon variant="subtle" color="danger" onClick={() => onDelete?.(node)}>
                    <IconTrash size={16} />
                  </ActionIcon>
                </Group>
              ) : null}

              <SimpleGrid cols={2}>
                <div>
                  <Text c="dimmed" size="xs">Last seen</Text>
                  <Text size="sm">{formatDateTime(node.last_seen_at)}</Text>
                </div>
                <div>
                  <Text c="dimmed" size="xs">Last heartbeat</Text>
                  <Text size="sm">{formatDateTime(node.last_heartbeat_at)}</Text>
                </div>
                <div>
                  <Text c="dimmed" size="xs">Version</Text>
                  <Text size="sm">{node.version || "n/a"}</Text>
                </div>
                <div>
                  <Text c="dimmed" size="xs">Load</Text>
                  <Text size="sm">{formatNumber(node.load)}</Text>
                </div>
                <div>
                  <Text c="dimmed" size="xs">Bandwidth</Text>
                  <Text size="sm">
                    {formatNumber(node.bandwidth_in_kbps, 0)} / {formatNumber(node.bandwidth_out_kbps, 0)} kbps
                  </Text>
                </div>
                <div>
                  <Text c="dimmed" size="xs">Enrollment</Text>
                  <Text size="sm">{node.enrollment_token_id ? `token #${node.enrollment_token_id}` : "manual"}</Text>
                </div>
                <div>
                  <Text c="dimmed" size="xs">Heartbeat auth</Text>
                  <Text size="sm">{node.heartbeat_auth_mode || "token"}</Text>
                </div>
                <div>
                  <Text c="dimmed" size="xs">Heartbeat IP</Text>
                  <Text size="sm">{node.last_heartbeat_ip || "-"}</Text>
                </div>
                <div>
                  <Text c="dimmed" size="xs">Heartbeat endpoint</Text>
                  <Text size="sm">{node.heartbeat_endpoint || "-"}</Text>
                </div>
                <div>
                  <Text c="dimmed" size="xs">Last heartbeat result</Text>
                  <Text size="sm">{node.last_heartbeat_code || 0} {node.last_heartbeat_error || ""}</Text>
                </div>
              </SimpleGrid>

              {canManage ? (
                <>
                  <Divider />
                  <NodeTunnelPanel node={node} onChange={(updated) => onNodeUpdated?.(updated)} />
                </>
              ) : null}
            </Stack>
          </Card>
        </Grid.Col>
      ))}
    </Grid>
  );
}
