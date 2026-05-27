"use client";

import { Button, Drawer, Group, Paper, Select, Skeleton, Stack, TextInput } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useDisclosure } from "@mantine/hooks";
import { useEffect, useMemo, useState } from "react";

import { AdminOnly } from "@/components/admin-only";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { useAuth } from "@/components/providers";
import { UserForm } from "@/components/users/user-form";
import { UserTable } from "@/components/users/user-table";
import { apiFetch, ApiError } from "@/lib/api";
import type { User, UserPayload, UserRole } from "@/lib/types";

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [query, setQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [userToDelete, setUserToDelete] = useState<User | null>(null);
  const [userToToggle, setUserToToggle] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [isToggling, setIsToggling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [opened, { open, close }] = useDisclosure(false);
  const { user: currentUser } = useAuth();

  const filteredUsers = useMemo(
    () =>
      users.filter((user) => {
        const matchesQuery = !query || user.email.toLowerCase().includes(query.toLowerCase());
        const matchesRole = !roleFilter || user.role === roleFilter;
        const matchesStatus = !statusFilter || (statusFilter === "active" ? user.active : !user.active);
        return matchesQuery && matchesRole && matchesStatus;
      }),
    [query, roleFilter, statusFilter, users]
  );

  const loadUsers = async () => {
    setIsLoading(true);
    setError(null);
    try {
      setUsers(await apiFetch<User[]>("/api/v1/users"));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load users.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void loadUsers();
  }, []);

  const handleSubmit = async (values: UserPayload) => {
    setIsSaving(true);
    try {
      const payload: Record<string, unknown> = {
        email: values.email,
        role: values.role,
        active: values.active
      };
      if (values.password) payload.password = values.password;

      if (selectedUser) {
        await apiFetch<User>(`/api/v1/users/${selectedUser.id}`, { method: "PATCH", body: JSON.stringify(payload) });
        notifications.show({ color: "success", message: "User updated" });
      } else {
        await apiFetch<User>("/api/v1/users", { method: "POST", body: JSON.stringify(payload) });
        notifications.show({ color: "success", message: "User created" });
      }
      close();
      await loadUsers();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to save user." });
    } finally {
      setIsSaving(false);
    }
  };

  const handleToggleActive = async () => {
    if (!userToToggle) return;
    setIsToggling(true);
    try {
      await apiFetch<User>(`/api/v1/users/${userToToggle.id}`, { method: "PATCH", body: JSON.stringify({ active: !userToToggle.active }) });
      notifications.show({ color: "success", message: userToToggle.active ? "User deactivated" : "User activated" });
      setUserToToggle(null);
      await loadUsers();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to change user status." });
    } finally {
      setIsToggling(false);
    }
  };

  const handleDelete = async () => {
    if (!userToDelete) return;
    setIsDeleting(true);
    try {
      await apiFetch<void>(`/api/v1/users/${userToDelete.id}`, { method: "DELETE" });
      notifications.show({ color: "success", message: "User deleted" });
      setUserToDelete(null);
      await loadUsers();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to delete user." });
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <AdminOnly>
      <Stack gap="lg">
        <Group justify="flex-end">
          <Button onClick={() => { setSelectedUser(null); open(); }}>New User</Button>
        </Group>

        <Group grow>
          <TextInput placeholder="Filter by email" value={query} onChange={(event) => setQuery(event.currentTarget.value)} />
          <Select
            data={[
              { value: "", label: "All roles" },
              { value: "admin", label: "admin" },
              { value: "viewer", label: "viewer" }
            ]}
            value={roleFilter}
            onChange={(value) => setRoleFilter((value || "") as UserRole | "")}
          />
          <Select
            data={[
              { value: "", label: "All statuses" },
              { value: "active", label: "active" },
              { value: "inactive", label: "inactive" }
            ]}
            value={statusFilter}
            onChange={(value) => setStatusFilter(value || "")}
          />
        </Group>

        {error ? <ErrorState title="Failed to load users" message={error} onRetry={() => void loadUsers()} /> : null}

        {isLoading ? (
          <Stack gap="sm"><Skeleton height={54} /><Skeleton height={54} /></Stack>
        ) : filteredUsers.length === 0 ? (
          <EmptyState title={users.length === 0 ? "No users found" : "No matching users"} description={users.length === 0 ? "Create a user." : "Adjust the filters."} />
        ) : (
          <Paper withBorder radius="md" p="sm">
            <UserTable users={filteredUsers} currentUserId={currentUser?.id} onEdit={(user) => { setSelectedUser(user); open(); }} onToggleActive={setUserToToggle} onDelete={setUserToDelete} />
          </Paper>
        )}

        <Drawer opened={opened} onClose={close} title={selectedUser ? "Edit user" : "Create user"} position="right">
          <UserForm initialValues={selectedUser || undefined} onSubmit={handleSubmit} submitLabel={selectedUser ? "Save Changes" : "Create User"} isLoading={isSaving} requirePassword={!selectedUser} />
        </Drawer>

        <ConfirmDialog isOpen={Boolean(userToToggle)} onClose={() => setUserToToggle(null)} onConfirm={handleToggleActive} title={userToToggle?.active ? "Deactivate user?" : "Activate user?"} description={userToToggle?.active ? `This prevents ${userToToggle.email} from signing in.` : `This allows ${userToToggle?.email} to sign in again.`} confirmLabel={userToToggle?.active ? "Deactivate" : "Activate"} isLoading={isToggling} />
        <ConfirmDialog isOpen={Boolean(userToDelete)} onClose={() => setUserToDelete(null)} onConfirm={handleDelete} title="Delete user?" description={`This permanently removes ${userToDelete?.email || "this user"}.`} isLoading={isDeleting} />
      </Stack>
    </AdminOnly>
  );
}
