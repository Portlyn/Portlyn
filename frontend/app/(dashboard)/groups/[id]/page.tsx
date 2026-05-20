"use client";

import { Button, Group as MantineGroup, Paper, Select, Skeleton, Stack, Table, Text } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

import { AdminOnly } from "@/components/admin-only";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { apiFetch, ApiError } from "@/lib/api";
import type { Group as UserGroup, User } from "@/lib/types";

export default function GroupDetailPage() {
  const [group, setGroup] = useState<UserGroup | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const routeParams = useParams<{ id: string | string[] }>();
  const groupId = Array.isArray(routeParams?.id) ? routeParams.id[0] : routeParams?.id;

  const loadData = async () => {
    if (!groupId) {
      setError("Missing group ID.");
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const [groupItem, userItems] = await Promise.all([
        apiFetch<UserGroup>(`/api/v1/groups/${groupId}`),
        apiFetch<User[]>("/api/v1/users")
      ]);
      setGroup(groupItem);
      setUsers(userItems);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load group.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, [groupId]);

  const availableUsers = useMemo(() => {
    const memberIds = new Set(group?.members?.map((user) => user.id) || []);
    return users.filter((user) => !memberIds.has(user.id));
  }, [group?.members, users]);

  const handleAdd = async () => {
    if (!selectedUserId || !groupId) return;
    try {
      const updated = await apiFetch<UserGroup>(`/api/v1/groups/${groupId}/members`, {
        method: "POST",
        body: JSON.stringify({ user_id: Number(selectedUserId) })
      });
      setGroup(updated);
      setSelectedUserId(null);
      notifications.show({ color: "green", message: "Member added" });
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Unable to add member." });
    }
  };

  const handleRemove = async (userId: number) => {
    if (!groupId) return;
    try {
      await apiFetch<void>(`/api/v1/groups/${groupId}/members/${userId}`, { method: "DELETE" });
      await loadData();
      notifications.show({ color: "green", message: "Member removed" });
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Unable to remove member." });
    }
  };

  return (
    <AdminOnly>
      <Stack gap="lg">
        {error ? <ErrorState title="Failed to load group" message={error} onRetry={() => void loadData()} /> : null}
        {isLoading ? (
          <Stack gap="sm"><Skeleton height={54} /><Skeleton height={54} /></Stack>
        ) : !group ? (
          <EmptyState title="Group not found" description="The requested group does not exist." />
        ) : (
          <>
            <Paper withBorder p="lg">
              <Stack gap="xs">
                <Text fw={700} fz="xl">{group.name}</Text>
                <Text c="dimmed">{group.description || "No description"}</Text>
              </Stack>
            </Paper>

            <Paper withBorder p="lg">
              <Stack gap="md">
                <MantineGroup align="end">
                  <Select
                    label="Add member"
                    data={availableUsers.map((user) => ({ value: String(user.id), label: user.email }))}
                    value={selectedUserId}
                    onChange={setSelectedUserId}
                    searchable
                    clearable
                    style={{ flex: 1 }}
                  />
                  <Button onClick={handleAdd} disabled={!selectedUserId}>Add</Button>
                </MantineGroup>

                {(group.members || []).length === 0 ? (
                  <EmptyState title="No members yet" description="Add users to use this group in restricted service policies." />
                ) : (
                  <Table.ScrollContainer minWidth={700}>
                    <Table>
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th>Email</Table.Th>
                          <Table.Th>Role</Table.Th>
                          <Table.Th>Status</Table.Th>
                          <Table.Th ta="right">Actions</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {(group.members || []).map((user) => (
                          <Table.Tr key={user.id}>
                            <Table.Td>{user.email}</Table.Td>
                            <Table.Td>{user.role}</Table.Td>
                            <Table.Td>{user.active ? "active" : "inactive"}</Table.Td>
                            <Table.Td>
                              <MantineGroup justify="flex-end">
                                <Button variant="subtle" color="red" onClick={() => void handleRemove(user.id)}>
                                  Remove
                                </Button>
                              </MantineGroup>
                            </Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </Table.ScrollContainer>
                )}
              </Stack>
            </Paper>
          </>
        )}
      </Stack>
    </AdminOnly>
  );
}
