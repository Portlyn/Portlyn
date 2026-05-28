"use client";

import {
  Alert,
  Badge,
  Button,
  Card,
  CopyButton,
  Drawer,
  Group,
  Image,
  MultiSelect,
  Skeleton,
  Stack,
  Table,
  Text,
  TextInput,
  Textarea
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconCheck, IconCopy, IconDownload } from "@tabler/icons-react";
import QRCode from "qrcode";
import { useEffect, useMemo, useState } from "react";

import { AdminOnly } from "@/components/admin-only";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { PageHeader } from "@/components/layout/page-header";
import { apiFetch, ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { MeshClient, MeshClientConfigResponse, Node } from "@/lib/types";

export default function ClientsPage() {
  const [clients, setClients] = useState<MeshClient[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selectedNodeIDs, setSelectedNodeIDs] = useState<string[]>([]);
  const [isSaving, setIsSaving] = useState(false);
  const [created, setCreated] = useState<MeshClientConfigResponse | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [clientToDelete, setClientToDelete] = useState<MeshClient | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [drawerOpened, { open: openDrawer, close: closeDrawer }] = useDisclosure(false);

  const load = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [clientItems, nodeItems] = await Promise.all([
        apiFetch<MeshClient[]>("/api/v1/clients"),
        apiFetch<Node[]>("/api/v1/nodes")
      ]);
      setClients(clientItems);
      setNodes(nodeItems);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load clients.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const nodeOptions = useMemo(
    () =>
      nodes
        .filter((node) => (node.advertised_subnets || "").trim().length > 0)
        .map((node) => ({ value: String(node.id), label: `${node.name} (${node.advertised_subnets})` })),
    [nodes]
  );

  useEffect(() => {
    if (!created) {
      setQrDataUrl(null);
      return;
    }
    void QRCode.toDataURL(created.config_text, { margin: 1, width: 240 })
      .then(setQrDataUrl)
      .catch(() => setQrDataUrl(null));
  }, [created]);

  const resetForm = () => {
    setName("");
    setDescription("");
    setSelectedNodeIDs([]);
    setCreated(null);
    closeDrawer();
  };

  const handleCreate = async () => {
    setIsSaving(true);
    try {
      const response = await apiFetch<MeshClientConfigResponse>("/api/v1/clients", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          description: description.trim(),
          allowed_node_ids: selectedNodeIDs.map(Number)
        })
      });
      setCreated(response);
      notifications.show({ color: "success", message: "Client created. Save the config now, it is shown only once." });
      await load();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to create client." });
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!clientToDelete) return;
    setIsDeleting(true);
    try {
      await apiFetch<void>(`/api/v1/clients/${clientToDelete.id}`, { method: "DELETE" });
      notifications.show({ color: "success", message: "Client revoked." });
      setClientToDelete(null);
      await load();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to revoke client." });
    } finally {
      setIsDeleting(false);
    }
  };

  const downloadConfig = () => {
    if (!created) return;
    const blob = new Blob([created.config_text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${created.client.name || "portlyn-client"}.conf`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <AdminOnly>
      <Stack gap="lg">
        <PageHeader
          action={<Button onClick={openDrawer}>Add client</Button>}
        />

        {error ? <ErrorState title="Failed to load clients" message={error} onRetry={() => void load()} /> : null}

        {isLoading ? (
          <Stack gap="sm"><Skeleton height={120} /><Skeleton height={120} /></Stack>
        ) : clients.length === 0 ? (
          <EmptyState title="No clients yet" description="Add a client to generate a WireGuard config and QR code." />
        ) : (
          <Table.ScrollContainer minWidth={720}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Tunnel IP</Table.Th>
                  <Table.Th>Reachable subnets</Table.Th>
                  <Table.Th>Last handshake</Table.Th>
                  <Table.Th ta="right">Actions</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {clients.map((client) => (
                  <Table.Tr key={client.id}>
                    <Table.Td>{client.name}</Table.Td>
                    <Table.Td>{client.wg_tunnel_ip || "-"}</Table.Td>
                    <Table.Td>{client.wg_allowed_ips || "-"}</Table.Td>
                    <Table.Td>{formatDateTime(client.wg_last_handshake)}</Table.Td>
                    <Table.Td>
                      <Group justify="flex-end">
                        <Button size="xs" variant="subtle" color="danger" onClick={() => setClientToDelete(client)}>
                          Revoke
                        </Button>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}

        <Drawer opened={drawerOpened} onClose={resetForm} title={created ? "Client config" : "Add client"} position="right" size="lg">
          {!created ? (
            <Stack gap="md">
              <TextInput label="Name" value={name} onChange={(event) => setName(event.currentTarget.value)} />
              <Textarea label="Description" value={description} onChange={(event) => setDescription(event.currentTarget.value)} minRows={2} />
              <MultiSelect
                label="Reachable nodes"
                description="The client can reach the advertised subnets of these nodes. Only nodes with advertised subnets are listed."
                data={nodeOptions}
                value={selectedNodeIDs}
                onChange={setSelectedNodeIDs}
                searchable
                clearable
              />
              <Button loading={isSaving} onClick={() => void handleCreate()} disabled={!name.trim()}>
                Create client
              </Button>
            </Stack>
          ) : (
            <Stack gap="md">
              <Alert color="warning" variant="light">
                Save this config now. The private key is not stored on the server and will not be shown again.
              </Alert>
              {qrDataUrl ? (
                <Group justify="center">
                  <Image src={qrDataUrl} alt="WireGuard config QR" w={240} h={240} />
                </Group>
              ) : null}
              <Text size="sm" c="dimmed">Scan with the WireGuard app, or import the config file.</Text>
              <Textarea value={created.config_text} autosize minRows={8} maxRows={20} readOnly styles={{ input: { fontFamily: "monospace" } }} />
              <Group justify="flex-end">
                <CopyButton value={created.config_text}>
                  {({ copied, copy }) => (
                    <Button variant="subtle" leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />} onClick={copy}>
                      {copied ? "Copied" : "Copy"}
                    </Button>
                  )}
                </CopyButton>
                <Button leftSection={<IconDownload size={14} />} onClick={downloadConfig}>
                  Download .conf
                </Button>
              </Group>
              <Button variant="default" onClick={resetForm}>Done</Button>
            </Stack>
          )}
        </Drawer>

        <ConfirmDialog
          isOpen={Boolean(clientToDelete)}
          onClose={() => setClientToDelete(null)}
          onConfirm={handleDelete}
          title="Revoke client?"
          description={`This removes ${clientToDelete?.name || "this client"} from the mesh.`}
          isLoading={isDeleting}
        />
      </Stack>
    </AdminOnly>
  );
}
