"use client";

import {
  Alert,
  Badge,
  Button,
  Code,
  Group,
  NumberInput,
  Paper,
  Stack,
  Switch,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconShieldLock } from "@tabler/icons-react";
import { useEffect, useState } from "react";

import { AdminOnly } from "@/components/admin-only";
import { ErrorState } from "@/components/error-state";
import { apiFetch, ApiError } from "@/lib/api";
import type { TunnelSettings } from "@/lib/types";

export default function TunnelPage() {
  const [settings, setSettings] = useState<TunnelSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [enabled, setEnabled] = useState(false);
  const [endpoint, setEndpoint] = useState("");
  const [listenPort, setListenPort] = useState<number | "">(51820);
  const [cidr, setCIDR] = useState("10.42.0.0/16");
  const [serverTunnelIP, setServerTunnelIP] = useState("10.42.0.1");
  const [configPath, setConfigPath] = useState("");

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiFetch<TunnelSettings>("/api/v1/tunnel/settings");
      setSettings(response);
      setEnabled(response.enabled);
      setEndpoint(response.server_endpoint || "");
      setListenPort(response.listen_port ?? 51820);
      setCIDR(response.cidr || "10.42.0.0/16");
      setServerTunnelIP(response.server_tunnel_ip || "10.42.0.1");
      setConfigPath(response.config_path || "");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load tunnel settings.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      const response = await apiFetch<TunnelSettings>("/api/v1/tunnel/settings", {
        method: "PATCH",
        body: JSON.stringify({
          enabled,
          server_endpoint: endpoint,
          listen_port: typeof listenPort === "number" ? listenPort : undefined,
          cidr,
          server_tunnel_ip: serverTunnelIP,
          config_path: configPath,
        }),
      });
      setSettings(response);
      notifications.show({ color: "green", message: "Tunnel settings saved." });
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Save failed." });
    } finally {
      setSaving(false);
    }
  };

  if (error) {
    return <ErrorState title="Failed to load tunnel settings" message={error} onRetry={() => void load()} />;
  }

  return (
    <AdminOnly>
      <Stack gap="lg">
        <Stack gap={4}>
          <Title order={2}>
            <Group gap="xs"><IconShieldLock size={20} /> Wireguard Tunnel</Group>
          </Title>
          <Text c="dimmed" size="sm">
            Bring offsite nodes (homelab boxes behind CGNAT, edge hardware) into Portlyn over a Wireguard tunnel. The server generates a config file you load into <Code>wg-quick</Code> (Linux) or the Wireguard app (Windows/macOS); nodes connect with the bundle from the bootstrap endpoint.
          </Text>
        </Stack>

        {settings && !settings.configured && enabled ? (
          <Alert color="yellow" variant="light">
            Set a public endpoint (host:port) so nodes can reach this server. Once saved, the server keypair is generated automatically.
          </Alert>
        ) : null}

        <Paper withBorder radius="md" p="lg">
          <Stack gap="md">
            <Group justify="space-between">
              <div>
                <Text fw={600}>Enable tunnel</Text>
                <Text size="sm" c="dimmed">Generates server keypair on first enable.</Text>
              </div>
              <Switch checked={enabled} onChange={(event) => setEnabled(event.currentTarget.checked)} />
            </Group>

            <TextInput
              label="Public endpoint"
              description="Host:port nodes will dial. Example: vpn.example.com:51820"
              value={endpoint}
              onChange={(event) => setEndpoint(event.currentTarget.value)}
              disabled={loading}
            />

            <NumberInput
              label="Listen port"
              description="UDP port the WG interface listens on."
              value={listenPort}
              onChange={(value) => setListenPort(typeof value === "number" ? value : 51820)}
              min={1}
              max={65535}
              disabled={loading}
            />

            <TextInput
              label="Tunnel CIDR"
              description="IP range allocated to peers (server uses .1)."
              value={cidr}
              onChange={(event) => setCIDR(event.currentTarget.value)}
              disabled={loading}
            />

            <TextInput
              label="Server tunnel IP"
              value={serverTunnelIP}
              onChange={(event) => setServerTunnelIP(event.currentTarget.value)}
              disabled={loading}
            />

            <TextInput
              label="Server config file path"
              description="Where to write the WG server config. Leave empty to disable file output."
              value={configPath}
              onChange={(event) => setConfigPath(event.currentTarget.value)}
              placeholder="/etc/wireguard/portlyn-wg0.conf"
              disabled={loading}
            />

            <Group justify="flex-end">
              <Button onClick={() => void save()} loading={saving}>
                Save
              </Button>
            </Group>
          </Stack>
        </Paper>

        {settings?.configured ? (
          <Paper withBorder radius="md" p="lg">
            <Stack gap="sm">
              <Group justify="space-between">
                <Text fw={600}>Server public key</Text>
                <Badge color="teal" variant="light">{settings.configured_peer_count} peers</Badge>
              </Group>
              <Code block>{settings.server_public_key}</Code>
              <Text size="sm" c="dimmed">
                {settings.connected_peer_count} of {settings.configured_peer_count} peers reported a recent handshake.
              </Text>
            </Stack>
          </Paper>
        ) : null}
      </Stack>
    </AdminOnly>
  );
}
