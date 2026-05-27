"use client";

import { Button, Card, Group, Stack, Table, Text, Title } from "@mantine/core";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";

import { ErrorState } from "@/components/error-state";
import { StatusBadge } from "@/components/status-badge";
import { apiFetch, ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { SessionInfo, User } from "@/lib/types";

function UserDetailContent() {
  const [user, setUser] = useState<User | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const params = useSearchParams();
  const userId = params.get("id") || undefined;

  const load = async () => {
    if (!userId) {
      setError("Missing user ID.");
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const [userItem, sessionItems] = await Promise.all([
        apiFetch<User>(`/api/v1/users/${userId}`),
        apiFetch<SessionInfo[]>(`/api/v1/users/${userId}/sessions`)
      ]);
      setUser(userItem);
      setSessions(sessionItems);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load user details.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, [userId]);

  const revokeSession = async (sessionId: number) => {
    if (!userId) return;
    await apiFetch<{ ok: boolean }>(`/api/v1/users/${userId}/sessions/${sessionId}`, { method: "DELETE" });
    await load();
  };

  const revokeAll = async () => {
    if (!userId) return;
    await apiFetch<{ ok: boolean }>(`/api/v1/users/${userId}/sessions/revoke-all`, { method: "POST" });
    await load();
  };

  if (error) {
    return <ErrorState title="Failed to load user detail" message={error} onRetry={() => void load()} />;
  }

  if (isLoading || !user) {
    return <Text c="dimmed">Loading user detail...</Text>;
  }

  return (
    <Stack gap="lg">
      <div>
        <Title order={2}>{user.email}</Title>
        <Text c="dimmed" size="sm">{user.role} • {user.auth_provider}</Text>
      </div>

      <Card withBorder>
        <Group justify="space-between">
          <div>
            <Text fw={600}>Account status</Text>
            <Text size="sm" c="dimmed">Last login {formatDateTime(user.last_login_at)} • MFA {user.mfa_enabled ? "enabled" : "disabled"}</Text>
          </div>
          <Group>
            <StatusBadge status={user.mfa_enabled ? "mfa" : "warning"} />
            <StatusBadge status={user.active ? "active" : "inactive"} />
          </Group>
        </Group>
      </Card>

      <Card withBorder>
        <Group justify="space-between">
          <div>
            <Text fw={600}>Multi-factor authentication</Text>
            <Text size="sm" c="dimmed">Reset revokes existing MFA factors and active sessions.</Text>
          </div>
          <Button variant="default" color="danger" onClick={() => void (userId ? apiFetch<{ ok: boolean }>(`/api/v1/users/${userId}/mfa/reset`, { method: "POST" }).then(load) : Promise.resolve())}>
            Reset MFA
          </Button>
        </Group>
      </Card>

      <Card withBorder>
        <Stack gap="sm">
          <Group justify="space-between">
            <Text fw={600}>Active Sessions</Text>
            <Button size="xs" variant="default" onClick={() => void revokeAll()}>
              Revoke all sessions
            </Button>
          </Group>
          <Table.ScrollContainer minWidth={900}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Remote addr</Table.Th>
                  <Table.Th>User agent</Table.Th>
                  <Table.Th>Last seen</Table.Th>
                  <Table.Th>Expires</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th ta="right">Action</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {sessions.map((session) => (
                  <Table.Tr key={session.id}>
                    <Table.Td>{session.remote_addr || "-"}</Table.Td>
                    <Table.Td>{session.user_agent || "-"}</Table.Td>
                    <Table.Td>{formatDateTime(session.last_seen_at)}</Table.Td>
                    <Table.Td>{formatDateTime(session.expires_at)}</Table.Td>
                    <Table.Td><StatusBadge status={session.revoked_at ? "revoked" : "active"} /></Table.Td>
                    <Table.Td>
                      <Group justify="flex-end">
                        <Button size="xs" variant="subtle" color="danger" onClick={() => void revokeSession(session.id)} disabled={Boolean(session.revoked_at)}>
                          Revoke
                        </Button>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Stack>
      </Card>
    </Stack>
  );
}

export default function UserDetailPage() {
  return (
    <Suspense fallback={null}>
      <UserDetailContent />
    </Suspense>
  );
}
