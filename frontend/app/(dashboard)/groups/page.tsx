"use client";

import { Button, Drawer, Group, Paper, Skeleton, Stack, Table, Text, TextInput, Textarea } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useDisclosure } from "@mantine/hooks";
import Link from "next/link";
import { useEffect, useState } from "react";

import { AdminOnly } from "@/components/admin-only";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { apiFetch, ApiError } from "@/lib/api";
import type { Group as GroupItem } from "@/lib/types";

export default function GroupsPage() {
  const [groups, setGroups] = useState<GroupItem[]>([]);
  const [selected, setSelected] = useState<GroupItem | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<GroupItem | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [opened, { open, close }] = useDisclosure(false);

  const loadData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      setGroups(await apiFetch<GroupItem[]>("/api/v1/groups"));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load groups.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const beginEdit = (item?: GroupItem) => {
    setSelected(item || null);
    setName(item?.name || "");
    setDescription(item?.description || "");
    open();
  };

  const handleSave = async () => {
    setIsSaving(true);
    try {
      if (selected) {
        await apiFetch<GroupItem>(`/api/v1/groups/${selected.id}`, {
          method: "PATCH",
          body: JSON.stringify({ name, description })
        });
      } else {
        await apiFetch<GroupItem>("/api/v1/groups", {
          method: "POST",
          body: JSON.stringify({ name, description })
        });
      }
      notifications.show({ color: "success", message: selected ? "Group updated" : "Group created" });
      close();
      await loadData();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to save group." });
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setIsDeleting(true);
    try {
      await apiFetch<void>(`/api/v1/groups/${deleteTarget.id}`, { method: "DELETE" });
      notifications.show({ color: "success", message: "Group deleted" });
      setDeleteTarget(null);
      await loadData();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to delete group." });
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <AdminOnly>
      <Stack gap="lg">
        <Group justify="flex-end">
          <Button onClick={() => beginEdit()}>New group</Button>
        </Group>

        {error ? <ErrorState title="Failed to load groups" message={error} onRetry={() => void loadData()} /> : null}

        {isLoading ? (
          <Stack gap="sm"><Skeleton height={54} /><Skeleton height={54} /></Stack>
        ) : groups.length === 0 ? (
          <EmptyState title="No groups found" description="Create a user group to start defining restricted access." />
        ) : (
          <Paper withBorder radius="md" p="sm">
            <Table.ScrollContainer minWidth={800}>
              <Table>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Name</Table.Th>
                    <Table.Th>Description</Table.Th>
                    <Table.Th>Members</Table.Th>
                    <Table.Th ta="right">Actions</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {groups.map((group) => (
                    <Table.Tr key={group.id}>
                      <Table.Td>
                        <Text component={Link} href={`/groups/detail?id=${group.id}`} fw={600}>
                          {group.name}
                        </Text>
                      </Table.Td>
                      <Table.Td>{group.description || "No description"}</Table.Td>
                      <Table.Td>{group.member_count || 0}</Table.Td>
                      <Table.Td>
                        <Group justify="flex-end">
                          <Button variant="subtle" onClick={() => beginEdit(group)}>Edit</Button>
                          <Button variant="subtle" color="danger" onClick={() => setDeleteTarget(group)} disabled={group.is_system_group}>
                            Delete
                          </Button>
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </Paper>
        )}

        <Drawer opened={opened} onClose={close} title={selected ? "Edit group" : "Create group"} position="right">
          <Stack gap="md">
            <TextInput label="Name" value={name} onChange={(event) => setName(event.currentTarget.value)} />
            <Textarea label="Description" value={description} onChange={(event) => setDescription(event.currentTarget.value)} minRows={4} />
            <Button loading={isSaving} onClick={handleSave} disabled={!name.trim()}>
              {selected ? "Save changes" : "Create group"}
            </Button>
          </Stack>
        </Drawer>

        <ConfirmDialog
          isOpen={Boolean(deleteTarget)}
          onClose={() => setDeleteTarget(null)}
          onConfirm={handleDelete}
          title="Delete group?"
          description={`This removes ${deleteTarget?.name || "this group"}.`}
          isLoading={isDeleting}
        />
      </Stack>
    </AdminOnly>
  );
}
