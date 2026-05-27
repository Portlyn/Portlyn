"use client";

import { Alert, Badge, Button, Code, CopyButton, Group, Modal, Stack, Text, Textarea } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconBolt, IconCopy, IconLink, IconLinkOff } from "@tabler/icons-react";
import { useState } from "react";

import { apiFetch, ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { Node, TunnelBootstrapResponse, TunnelStatus } from "@/lib/types";

const STATUS_COLOR: Record<string, string> = {
  inactive: "gray",
  provisioned: "yellow",
  connected: "teal",
  stale: "orange",
};

export function NodeTunnelPanel({ node, onChange }: { node: Node; onChange: (updated: Node) => void }) {
  const [opened, setOpened] = useState(false);
  const [config, setConfig] = useState<TunnelBootstrapResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [revoking, setRevoking] = useState(false);

  const status = (node.tunnel_status as TunnelStatus) || "inactive";
  const hasTunnel = (node.wg_public_key?.length ?? 0) > 0 && (node.wg_tunnel_ip?.length ?? 0) > 0;

  const bootstrap = async (forceReissue: boolean) => {
    setLoading(true);
    try {
      const response = await apiFetch<TunnelBootstrapResponse>(`/api/v1/nodes/${node.id}/wg-bootstrap`, {
        method: "POST",
        body: JSON.stringify({ force_reissue: forceReissue }),
      });
      setConfig(response);
      setOpened(true);
      onChange({
        ...node,
        wg_public_key: response.public_key,
        wg_tunnel_ip: response.address.split("/")[0],
        wg_endpoint: response.server_endpoint,
        tunnel_status: "provisioned",
      });
      notifications.show({ color: "green", message: "Tunnel config issued. Save it now — the private key is shown only once." });
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Bootstrap failed." });
    } finally {
      setLoading(false);
    }
  };

  const revoke = async () => {
    setRevoking(true);
    try {
      await apiFetch<void>(`/api/v1/nodes/${node.id}/wg-tunnel`, { method: "DELETE" });
      onChange({
        ...node,
        wg_public_key: "",
        wg_tunnel_ip: "",
        wg_endpoint: "",
        tunnel_status: "inactive",
      });
      notifications.show({ color: "green", message: "Tunnel revoked." });
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Revoke failed." });
    } finally {
      setRevoking(false);
    }
  };

  return (
    <Stack gap="xs">
      <Group justify="space-between">
        <Group gap="xs">
          <IconBolt size={16} />
          <Text fw={600} size="sm">Tunnel</Text>
          <Badge color={STATUS_COLOR[status] || "gray"} variant="light">{status}</Badge>
        </Group>
        {hasTunnel ? (
          <Group gap="xs">
            <Button size="xs" variant="light" leftSection={<IconLink size={14} />} loading={loading} onClick={() => bootstrap(true)}>
              Re-issue
            </Button>
            <Button size="xs" variant="subtle" color="red" leftSection={<IconLinkOff size={14} />} loading={revoking} onClick={revoke}>
              Revoke
            </Button>
          </Group>
        ) : (
          <Button size="xs" leftSection={<IconLink size={14} />} loading={loading} onClick={() => bootstrap(false)}>
            Bootstrap tunnel
          </Button>
        )}
      </Group>

      {hasTunnel ? (
        <Stack gap={4}>
          <Text size="xs" c="dimmed">Tunnel IP</Text>
          <Code>{node.wg_tunnel_ip}</Code>
          <Text size="xs" c="dimmed">Last handshake</Text>
          <Text size="sm">{formatDateTime(node.wg_last_handshake)}</Text>
        </Stack>
      ) : null}

      <Modal opened={opened} onClose={() => setOpened(false)} title="Wireguard client config" size="lg">
        {config ? (
          <Stack gap="md">
            <Alert color="yellow" variant="light">
              Save this config now. The private key is not stored on the server and will not be shown again.
            </Alert>
            <Textarea value={config.config_text} autosize minRows={10} maxRows={20} readOnly />
            <Group justify="flex-end">
              <CopyButton value={config.config_text}>
                {({ copied, copy }) => (
                  <Button leftSection={<IconCopy size={14} />} onClick={copy}>
                    {copied ? "Copied" : "Copy config"}
                  </Button>
                )}
              </CopyButton>
            </Group>
          </Stack>
        ) : null}
      </Modal>
    </Stack>
  );
}
