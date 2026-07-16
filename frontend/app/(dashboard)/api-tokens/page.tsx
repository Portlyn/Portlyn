"use client";

import {
  Alert,
  Badge,
  Button,
  Code,
  CopyButton,
  Drawer,
  Group,
  NumberInput,
  Select,
  Skeleton,
  Stack,
  Table,
  Text,
  TextInput
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconCheck, IconCopy } from "@tabler/icons-react";
import { useEffect, useState } from "react";

import { AdminOnly } from "@/components/admin-only";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { PageHeader } from "@/components/layout/page-header";
import { apiFetch, ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { ApiToken, ApiTokenCreated } from "@/lib/types";

const statusColor: Record<ApiToken["status"], string> = {
  active: "green",
  revoked: "gray",
  expired: "orange"
};

export default function ApiTokensPage() {
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [role, setRole] = useState<"admin" | "viewer">("viewer");
  const [expiresInDays, setExpiresInDays] = useState<number | "">("");
  const [isSaving, setIsSaving] = useState(false);
  const [created, setCreated] = useState<ApiTokenCreated | null>(null);
  const [tokenToRevoke, setTokenToRevoke] = useState<ApiToken | null>(null);
  const [isRevoking, setIsRevoking] = useState(false);
  const [drawerOpened, { open: openDrawer, close: closeDrawer }] = useDisclosure(false);

  const load = async () => {
    setIsLoading(true);
    setError(null);
    try {
      setTokens(await apiFetch<ApiToken[]>("/api/v1/api-tokens"));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load API tokens.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const resetForm = () => {
    setName("");
    setRole("viewer");
    setExpiresInDays("");
    setCreated(null);
    closeDrawer();
  };

  const handleCreate = async () => {
    setIsSaving(true);
    try {
      const body: Record<string, unknown> = { name: name.trim(), role };
      if (typeof expiresInDays === "number" && expiresInDays > 0) {
        body.expires_in_days = expiresInDays;
      }
      const response = await apiFetch<ApiTokenCreated>("/api/v1/api-tokens", {
        method: "POST",
        body: JSON.stringify(body)
      });
      setCreated(response);
      notifications.show({ color: "success", message: "Token created. Copy it now — it is shown only once." });
      await load();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to create token." });
    } finally {
      setIsSaving(false);
    }
  };

  const handleRevoke = async () => {
    if (!tokenToRevoke) return;
    setIsRevoking(true);
    try {
      await apiFetch<void>(`/api/v1/api-tokens/${tokenToRevoke.id}`, { method: "DELETE" });
      notifications.show({ color: "success", message: "Token revoked." });
      setTokenToRevoke(null);
      await load();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to revoke token." });
    } finally {
      setIsRevoking(false);
    }
  };

  return (
    <AdminOnly>
      <Stack gap="lg">
        <PageHeader action={<Button onClick={openDrawer}>Create token</Button>} />

        <Text c="dimmed" size="sm">
          API tokens authenticate scripts and CI with a Bearer token instead of a login session. They are not subject to
          CSRF or MFA. Send them as <Code>Authorization: Bearer plyn_…</Code>.
        </Text>

        {error ? <ErrorState title="Failed to load API tokens" message={error} onRetry={() => void load()} /> : null}

        {isLoading ? (
          <Stack gap="sm"><Skeleton height={120} /><Skeleton height={120} /></Stack>
        ) : tokens.length === 0 ? (
          <EmptyState title="No API tokens yet" description="Create a token to let CI or automation talk to the API." />
        ) : (
          <Table.ScrollContainer minWidth={760}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Prefix</Table.Th>
                  <Table.Th>Role</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Last used</Table.Th>
                  <Table.Th>Expires</Table.Th>
                  <Table.Th ta="right">Actions</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {tokens.map((token) => (
                  <Table.Tr key={token.id}>
                    <Table.Td>{token.name}</Table.Td>
                    <Table.Td><Code>{token.prefix}…</Code></Table.Td>
                    <Table.Td>{token.role}</Table.Td>
                    <Table.Td><Badge color={statusColor[token.status]}>{token.status}</Badge></Table.Td>
                    <Table.Td>{token.last_used_at ? formatDateTime(token.last_used_at) : "never"}</Table.Td>
                    <Table.Td>{token.expires_at ? formatDateTime(token.expires_at) : "never"}</Table.Td>
                    <Table.Td>
                      <Group justify="flex-end">
                        {token.status === "active" ? (
                          <Button size="xs" variant="subtle" color="danger" onClick={() => setTokenToRevoke(token)}>
                            Revoke
                          </Button>
                        ) : null}
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}

        <Drawer opened={drawerOpened} onClose={resetForm} title={created ? "Token created" : "Create API token"} position="right" size="lg">
          {!created ? (
            <Stack gap="md">
              <TextInput label="Name" placeholder="ci-deploy" value={name} onChange={(event) => setName(event.currentTarget.value)} />
              <Select
                label="Role"
                description="Viewer is read-only. Admin can change everything — use sparingly."
                data={[
                  { value: "viewer", label: "Viewer (read-only)" },
                  { value: "admin", label: "Admin (full access)" }
                ]}
                value={role}
                onChange={(value) => setRole((value as "admin" | "viewer") || "viewer")}
                allowDeselect={false}
              />
              <NumberInput
                label="Expires in (days)"
                description="Leave empty for a token that never expires."
                min={1}
                max={3650}
                value={expiresInDays}
                onChange={(value) => setExpiresInDays(typeof value === "number" ? value : "")}
              />
              <Button loading={isSaving} onClick={() => void handleCreate()} disabled={!name.trim()}>
                Create token
              </Button>
            </Stack>
          ) : (
            <Stack gap="md">
              <Alert color="warning" variant="light">
                Copy this token now. It is not stored in plaintext and will not be shown again.
              </Alert>
              <Code block>{created.token}</Code>
              <Group justify="flex-end">
                <CopyButton value={created.token}>
                  {({ copied, copy }) => (
                    <Button variant="subtle" leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />} onClick={copy}>
                      {copied ? "Copied" : "Copy"}
                    </Button>
                  )}
                </CopyButton>
              </Group>
              <Text size="sm" c="dimmed">Use it with curl:</Text>
              <Code block>{`curl -H "Authorization: Bearer ${created.token}" \\\n  <hub-url>/api/v1/services`}</Code>
              <Button variant="default" onClick={resetForm}>Done</Button>
            </Stack>
          )}
        </Drawer>

        <ConfirmDialog
          isOpen={Boolean(tokenToRevoke)}
          onClose={() => setTokenToRevoke(null)}
          onConfirm={handleRevoke}
          title="Revoke token?"
          description={`This immediately disables ${tokenToRevoke?.name || "this token"}. Any script using it will lose access.`}
          isLoading={isRevoking}
        />
      </Stack>
    </AdminOnly>
  );
}
