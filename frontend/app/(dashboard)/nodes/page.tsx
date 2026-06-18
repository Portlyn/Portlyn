"use client";

import { Alert, Badge, Button, Card, CopyButton, Divider, Drawer, Group, Loader, Paper, Skeleton, Stack, Switch, Table, Tabs, Text, TextInput, Textarea } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useDisclosure } from "@mantine/hooks";
import { IconCheck, IconCopy, IconPlugConnected, IconRefresh } from "@tabler/icons-react";
import { useEffect, useMemo, useState } from "react";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { NodeForm } from "@/components/nodes/node-form";
import { NodeGrid } from "@/components/nodes/node-grid";
import { PageHeader } from "@/components/layout/page-header";
import { useAuth } from "@/components/providers";
import { apiFetch, ApiError, getApiBaseUrl } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { Node, NodeEnrollmentToken, NodeEnrollmentTokenCreateResponse, NodePayload } from "@/lib/types";

type InstallPlatform = "linux" | "macos" | "windows";

function shellEscape(value: string) {
  return `'${value.replace(/'/g, `'\"'\"'`)}'`;
}

function powerShellEscape(value: string) {
  return `'${value.replace(/'/g, "''")}'`;
}

function resolveNodeAPIBaseUrl() {
  const configured = getApiBaseUrl();
  if (configured) {
    return configured.replace(/\/$/, "");
  }
  if (typeof window === "undefined") {
    return "http://localhost:8080";
  }
  const current = new URL(window.location.origin);
  if ((current.hostname === "localhost" || current.hostname === "127.0.0.1") && current.port === "3000") {
    current.port = "8080";
    return current.toString().replace(/\/$/, "");
  }
  return current.toString().replace(/\/$/, "");
}

function buildNodeCommands(apiBaseUrl: string, token: string, nodeName: string, nodeDescription: string) {
  const dockerImage = "ghcr.io/portlyn/portlyn-nodeagent:latest";
  const shArgs = (version: string) => [
    `--api ${shellEscape(apiBaseUrl)}`,
    `--token ${shellEscape(token)}`,
    `--name ${shellEscape(nodeName)}`,
    nodeDescription.trim() ? `--description ${shellEscape(nodeDescription)}` : "",
    `--version ${shellEscape(version)}`,
  ].filter(Boolean).join(" ");
  const winArgs = [
    `--api ${powerShellEscape(apiBaseUrl)}`,
    `--token ${powerShellEscape(token)}`,
    `--name ${powerShellEscape(nodeName)}`,
    nodeDescription.trim() ? `--description ${powerShellEscape(nodeDescription)}` : "",
    `--version ${powerShellEscape("windows-node")}`,
  ].filter(Boolean).join(" ");
  const dockerArgs = [
    `--api ${shellEscape(apiBaseUrl)}`,
    `--token ${shellEscape(token)}`,
    `--name ${shellEscape(nodeName)}`,
    nodeDescription.trim() ? `--description ${shellEscape(nodeDescription)}` : "",
    `--version ${shellEscape("docker-node")}`,
  ].filter(Boolean).join(" ");
  const installArgs = [
    `--token ${shellEscape(token)}`,
    nodeName.trim() && nodeName !== "<node-name>" ? `--name ${shellEscape(nodeName)}` : "",
  ].filter(Boolean).join(" ");
  const oneLiner = `curl -fsSL ${shellEscape(`${apiBaseUrl}/install.sh`)} | sudo sh -s -- ${installArgs}`;

  return {
    linux: {
      oneLiner,
      binary: `chmod +x ./portlyn-nodeagent-linux-amd64\n./portlyn-nodeagent-linux-amd64 ${shArgs("linux-node")}`,
      goInstall: `go install portlyn/cmd/nodeagent@latest\nnodeagent ${shArgs("linux-node")}`,
      docker: `docker run -d --restart unless-stopped --name portlyn-nodeagent \\\n  -v portlyn-nodeagent:/data \\\n  ${dockerImage} ${dockerArgs}`
    },
    macos: {
      oneLiner,
      binary: `chmod +x ./portlyn-nodeagent-darwin-arm64\n./portlyn-nodeagent-darwin-arm64 ${shArgs("macos-node")}`,
      goInstall: `go install portlyn/cmd/nodeagent@latest\nnodeagent ${shArgs("macos-node")}`,
      docker: `docker run -d --restart unless-stopped --name portlyn-nodeagent \\\n  -v portlyn-nodeagent:/data \\\n  ${dockerImage} ${dockerArgs}`
    },
    windows: {
      oneLiner: "",
      binary: `.\\portlyn-nodeagent-windows-amd64.exe ${winArgs}`,
      goInstall: `go install portlyn/cmd/nodeagent@latest\nnodeagent ${winArgs}`,
      docker: `docker run -d --restart unless-stopped --name portlyn-nodeagent ` +
        `-v portlyn-nodeagent:/data ${dockerImage} ${dockerArgs}`
    }
  };
}

export default function NodesPage() {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [query, setQuery] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [nodeToDelete, setNodeToDelete] = useState<Node | null>(null);
  const [tokens, setTokens] = useState<NodeEnrollmentToken[]>([]);
  const [tokenDescription, setTokenDescription] = useState("");
  const [tokenTTL, setTokenTTL] = useState("86400");
  const [tokenSingleUse, setTokenSingleUse] = useState(true);
  const [latestToken, setLatestToken] = useState<NodeEnrollmentTokenCreateResponse | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [isCreatingToken, setIsCreatingToken] = useState(false);
  const [installNodeName, setInstallNodeName] = useState("");
  const [installNodeDescription, setInstallNodeDescription] = useState("");
  const [installTokenLabel, setInstallTokenLabel] = useState("");
  const [installPlatform, setInstallPlatform] = useState<InstallPlatform>("linux");
  const [connectedNode, setConnectedNode] = useState<Node | null>(null);
  const [isPollingInstall, setIsPollingInstall] = useState(false);
  const [manualOpened, { open: openManual, close: closeManual }] = useDisclosure(false);
  const [installOpened, { open: openInstall, close: closeInstall }] = useDisclosure(false);
  const { user } = useAuth();
  const canManage = user?.role === "admin";

  const filteredNodes = nodes.filter((node) =>
    [node.name, node.description, node.status, node.version].some((value) =>
      value.toLowerCase().includes(query.toLowerCase())
    )
  );

  const loadNodes = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [nodeItems, enrollmentTokens] = await Promise.all([
        apiFetch<Node[]>("/api/v1/nodes"),
        canManage ? apiFetch<NodeEnrollmentToken[]>("/api/v1/node-enrollment-tokens") : Promise.resolve([])
      ]);
      setNodes(nodeItems);
      setTokens(enrollmentTokens);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load nodes.");
    } finally {
      setIsLoading(false);
    }
  };

  const refreshNodeData = async () => {
    const [nodeItems, enrollmentTokens] = await Promise.all([
      apiFetch<Node[]>("/api/v1/nodes"),
      canManage ? apiFetch<NodeEnrollmentToken[]>("/api/v1/node-enrollment-tokens") : Promise.resolve([])
    ]);
    setNodes(nodeItems);
    setTokens(enrollmentTokens);
    return { nodeItems, enrollmentTokens };
  };

  useEffect(() => {
    void loadNodes();
  }, [canManage]);

  const handleSubmit = async (values: NodePayload) => {
    setIsSaving(true);
    try {
      if (selectedNode) {
        await apiFetch<Node>(`/api/v1/nodes/${selectedNode.id}`, { method: "PATCH", body: JSON.stringify(values) });
        notifications.show({ color: "success", message: "Node updated" });
      } else {
        await apiFetch<Node>("/api/v1/nodes", { method: "POST", body: JSON.stringify(values) });
        notifications.show({ color: "success", message: "Node created" });
      }
      closeManual();
      await loadNodes();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to save node." });
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!nodeToDelete) return;
    setIsDeleting(true);
    try {
      await apiFetch<void>(`/api/v1/nodes/${nodeToDelete.id}`, { method: "DELETE" });
      notifications.show({ color: "success", message: "Node deleted" });
      setNodeToDelete(null);
      await loadNodes();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to delete node." });
    } finally {
      setIsDeleting(false);
    }
  };

  const handleCreateToken = async () => {
    setIsCreatingToken(true);
    try {
      const tokenLabel = installTokenLabel.trim() || `Install ${installNodeName.trim()}`;
      const response = await apiFetch<NodeEnrollmentTokenCreateResponse>("/api/v1/node-enrollment-tokens", {
        method: "POST",
        body: JSON.stringify({
          name: tokenLabel,
          description: tokenDescription,
          ttl_seconds: Number(tokenTTL) || 86400,
          single_use: tokenSingleUse
        })
      });
      setLatestToken(response);
      setConnectedNode(null);
      setIsPollingInstall(true);
      notifications.show({ color: "success", message: "Enrollment token created" });
      await loadNodes();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to create enrollment token." });
    } finally {
      setIsCreatingToken(false);
    }
  };

  useEffect(() => {
    if (!latestToken || !isPollingInstall) {
      return;
    }
    const interval = window.setInterval(() => {
      void refreshNodeData().then(({ nodeItems }) => {
        const matchedNode = nodeItems.find((item) => item.enrollment_token_id === latestToken.id);
        if (matchedNode) {
          setConnectedNode(matchedNode);
          setIsPollingInstall(false);
          notifications.show({ color: "success", message: `Node ${matchedNode.name} connected` });
        }
      }).catch(() => undefined);
    }, 3000);
    return () => window.clearInterval(interval);
  }, [canManage, isPollingInstall, latestToken]);

  const installCommands = useMemo(() => {
    if (!latestToken || typeof window === "undefined") {
      return null;
    }
    return buildNodeCommands(resolveNodeAPIBaseUrl(), latestToken.token, installNodeName.trim() || "<node-name>", installNodeDescription.trim());
  }, [installNodeDescription, installNodeName, latestToken]);

  const currentCommand = installCommands?.[installPlatform];

  const resetInstallFlow = () => {
    setLatestToken(null);
    setConnectedNode(null);
    setIsPollingInstall(false);
    setInstallNodeName("");
    setInstallNodeDescription("");
    setInstallTokenLabel("");
    setTokenDescription("");
    setTokenTTL("86400");
    setTokenSingleUse(true);
    setInstallPlatform("linux");
    closeInstall();
  };

  const refreshInstallStatus = async () => {
    if (!latestToken) {
      return;
    }
    try {
      setIsPollingInstall(true);
      const { nodeItems } = await refreshNodeData();
      const matchedNode = nodeItems.find((item) => item.enrollment_token_id === latestToken.id);
      if (matchedNode) {
        setConnectedNode(matchedNode);
        setIsPollingInstall(false);
      }
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to refresh node status." });
    }
  };

  const handleDeleteToken = async (tokenId: number) => {
    try {
      await apiFetch<void>(`/api/v1/node-enrollment-tokens/${tokenId}`, { method: "DELETE" });
      notifications.show({ color: "success", message: "Enrollment token deleted" });
      await loadNodes();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to delete enrollment token." });
    }
  };

  return (
    <Stack gap="lg">
      <PageHeader
        action={canManage ? <Button onClick={() => { setSelectedNode(null); openInstall(); }}>Install Node</Button> : undefined}
      />
      {canManage ? (
        <Stack gap="md">
          <Card withBorder>
            <Stack gap="sm">
              <Group justify="space-between" align="center">
                <Text fw={600}>Installer</Text>
                <Button onClick={() => openInstall()}>Open installer</Button>
              </Group>
              {latestToken ? (
                <Alert color={connectedNode ? "success" : "brand"} variant="light" title={connectedNode ? "Node connected" : "Waiting for node connection"}>
                  <Group justify="space-between" align="center">
                    <div>
                      <Text size="sm">Token label: {latestToken.name}</Text>
                      <Text size="sm">Expires: {formatDateTime(latestToken.expires_at)}</Text>
                      <Text size="sm">Single use: {latestToken.single_use ? "Yes" : "No"}</Text>
                      {connectedNode ? <Text size="sm">Connected node: {connectedNode.name}</Text> : null}
                    </div>
                    <Group gap="xs">
                      {!connectedNode ? <Loader size="sm" color="brand" /> : <Badge color="success">connected</Badge>}
                      <Button size="xs" variant="subtle" leftSection={<IconRefresh size={14} />} onClick={() => void refreshInstallStatus()}>
                        Refresh
                      </Button>
                    </Group>
                  </Group>
                </Alert>
              ) : null}
              {tokens.length > 0 ? (
                <Table.ScrollContainer minWidth={720}>
                  <Table>
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>Name</Table.Th>
                        <Table.Th>Expires</Table.Th>
                        <Table.Th>Single use</Table.Th>
                        <Table.Th>Used</Table.Th>
                        <Table.Th ta="right">Actions</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {tokens.map((token) => (
                        <Table.Tr key={token.id}>
                          <Table.Td>{token.name}</Table.Td>
                          <Table.Td>{formatDateTime(token.expires_at)}</Table.Td>
                          <Table.Td>{token.single_use ? "Yes" : "No"}</Table.Td>
                          <Table.Td>{token.used_at ? formatDateTime(token.used_at) : "No"}</Table.Td>
                          <Table.Td>
                            <Group justify="flex-end">
                              <Button size="xs" variant="subtle" color="danger" onClick={() => void handleDeleteToken(token.id)}>
                                Delete
                              </Button>
                            </Group>
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
              ) : null}
            </Stack>
          </Card>
        </Stack>
      ) : null}

      <TextInput placeholder="Search nodes" value={query} onChange={(event) => setQuery(event.currentTarget.value)} />
      {error ? <ErrorState title="Failed to load nodes" message={error} onRetry={() => void loadNodes()} /> : null}

      {isLoading ? (
        <Stack gap="sm"><Skeleton height={140} /><Skeleton height={140} /></Stack>
      ) : filteredNodes.length === 0 ? (
        <EmptyState title={nodes.length === 0 ? "No nodes registered" : "No matching nodes"} description={nodes.length === 0 ? "Install a node from the enrollment flow." : "Adjust the filter."} />
      ) : (
        <NodeGrid nodes={filteredNodes} canManage={canManage} onEdit={(node) => { setSelectedNode(node); openManual(); }} onDelete={setNodeToDelete} />
      )}

      <Drawer opened={manualOpened} onClose={closeManual} title={selectedNode ? "Edit node" : "Create node"} position="right">
        <NodeForm initialValues={selectedNode || undefined} onSubmit={handleSubmit} submitLabel={selectedNode ? "Save Changes" : "Create Node"} isLoading={isSaving} />
      </Drawer>

      <Drawer opened={installOpened} onClose={resetInstallFlow} title="Install node" position="right" size="xl">
        {!latestToken ? (
          <Stack gap="md">
            <TextInput label="Node name" value={installNodeName} onChange={(event) => {
              const value = event.currentTarget.value;
              setInstallNodeName(value);
              if (!installTokenLabel.trim()) {
                setInstallTokenLabel(`Install ${value}`.trim());
              }
            }} />
            <Textarea label="Node description" value={installNodeDescription} onChange={(event) => setInstallNodeDescription(event.currentTarget.value)} minRows={3} />
            <TextInput label="Token label" value={installTokenLabel} onChange={(event) => {
              setInstallTokenLabel(event.currentTarget.value);
            }} />
            <Textarea label="Notes" value={tokenDescription} onChange={(event) => setTokenDescription(event.currentTarget.value)} minRows={2} />
            <TextInput label="TTL in seconds" value={tokenTTL} onChange={(event) => setTokenTTL(event.currentTarget.value)} />
            <Switch checked={tokenSingleUse} onChange={(event) => setTokenSingleUse(event.currentTarget.checked)} label="Single-use token" />
            <Group justify="flex-end">
              <Button onClick={() => void handleCreateToken()} loading={isCreatingToken} disabled={!installNodeName.trim()}>
                Generate token and continue
              </Button>
            </Group>
          </Stack>
        ) : (
          <Stack gap="lg">
            <Alert color={connectedNode ? "success" : "brand"} variant="light" title={connectedNode ? "Connection established" : "Waiting for first heartbeat"}>
              <Group justify="space-between" align="center">
                <div>
                  <Text size="sm">Node name: {installNodeName}</Text>
                  <Text size="sm">Enrollment token: {latestToken.name}</Text>
                  <Text size="sm">Created: {formatDateTime(latestToken.created_at)}</Text>
                  {connectedNode ? <Text size="sm">Connected as {connectedNode.name} with status {connectedNode.status}</Text> : null}
                </div>
                {!connectedNode ? <Loader size="sm" color="brand" /> : <Badge color="success" leftSection={<IconCheck size={12} />}>Connected</Badge>}
              </Group>
            </Alert>

            <Card withBorder>
              <Stack gap="md">
                <Group justify="space-between" align="center">
                  <Text fw={600}>Commands</Text>
                  <Group gap="xs">
                    <Button size="xs" variant="subtle" leftSection={<IconRefresh size={14} />} onClick={() => void refreshInstallStatus()}>
                      Check again
                    </Button>
                    {connectedNode ? <Button size="xs" variant="light" onClick={resetInstallFlow}>Close</Button> : null}
                  </Group>
                </Group>
                <Tabs value={installPlatform} onChange={(value) => setInstallPlatform((value as InstallPlatform) || "linux")}>
                  <Tabs.List>
                    <Tabs.Tab value="linux">Linux</Tabs.Tab>
                    <Tabs.Tab value="macos">macOS</Tabs.Tab>
                    <Tabs.Tab value="windows">Windows</Tabs.Tab>
                  </Tabs.List>
                </Tabs>
                <Divider />
                {currentCommand?.oneLiner ? (
                  <Stack gap="xs">
                    <Group justify="space-between" align="center">
                      <Text fw={600}>One-line install (recommended)</Text>
                      <CopyButton value={currentCommand.oneLiner}>
                        {({ copied, copy }) => (
                          <Button size="xs" variant="light" leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />} onClick={copy}>
                            {copied ? "Copied" : "Copy"}
                          </Button>
                        )}
                      </CopyButton>
                    </Group>
                    <Textarea value={currentCommand.oneLiner} readOnly autosize minRows={2} maxRows={6} styles={{ input: { fontFamily: "monospace" } }} />
                    <Text size="xs" c="dimmed">Downloads the agent, installs a systemd service and starts it. Nothing else to set up.</Text>
                  </Stack>
                ) : null}
                <Stack gap="xs">
                  <Group justify="space-between" align="center">
                    <Text fw={500}>Download binary</Text>
                    <CopyButton value={currentCommand?.binary || ""}>
                      {({ copied, copy }) => (
                        <Button size="xs" variant="subtle" leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />} onClick={copy}>
                          {copied ? "Copied" : "Copy"}
                        </Button>
                      )}
                    </CopyButton>
                  </Group>
                  <Textarea value={currentCommand?.binary || ""} readOnly autosize minRows={3} maxRows={8} styles={{ input: { fontFamily: "monospace" } }} />
                </Stack>
                <Stack gap="xs">
                  <Group justify="space-between" align="center">
                    <Text fw={500}>go install</Text>
                    <CopyButton value={currentCommand?.goInstall || ""}>
                      {({ copied, copy }) => (
                        <Button size="xs" variant="subtle" leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />} onClick={copy}>
                          {copied ? "Copied" : "Copy"}
                        </Button>
                      )}
                    </CopyButton>
                  </Group>
                  <Textarea value={currentCommand?.goInstall || ""} readOnly autosize minRows={3} maxRows={8} styles={{ input: { fontFamily: "monospace" } }} />
                </Stack>
                <Stack gap="xs">
                  <Group justify="space-between" align="center">
                    <Text fw={500}>Docker</Text>
                    <CopyButton value={currentCommand?.docker || ""}>
                      {({ copied, copy }) => (
                        <Button size="xs" variant="subtle" leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />} onClick={copy}>
                          {copied ? "Copied" : "Copy"}
                        </Button>
                      )}
                    </CopyButton>
                  </Group>
                  <Textarea value={currentCommand?.docker || ""} readOnly autosize minRows={4} maxRows={10} styles={{ input: { fontFamily: "monospace" } }} />
                </Stack>
                <Text size="sm" c="dimmed">The agent stores its state and keys after first run, so the enrollment token is only needed once. The WireGuard tunnel and service forwarding start automatically.</Text>
              </Stack>
            </Card>

            {connectedNode ? (
              <Card withBorder>
                <Group justify="space-between" align="center">
                  <div>
                    <Group gap="xs">
                      <IconPlugConnected size={18} />
                      <Text fw={600}>Node connected</Text>
                    </Group>
                    <Text size="sm" c="dimmed">Last seen {formatDateTime(connectedNode.last_seen_at)} • Version {connectedNode.version || "n/a"}</Text>
                  </div>
                  <Button onClick={resetInstallFlow}>Done</Button>
                </Group>
              </Card>
            ) : null}
          </Stack>
        )}
      </Drawer>

      <ConfirmDialog isOpen={Boolean(nodeToDelete)} onClose={() => setNodeToDelete(null)} onConfirm={handleDelete} title="Delete node?" description={`This removes ${nodeToDelete?.name || "this node"}.`} isLoading={isDeleting} />
    </Stack>
  );
}
