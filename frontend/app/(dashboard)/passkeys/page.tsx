"use client";

import { ActionIcon, Alert, Badge, Button, Card, Group, Loader, Stack, Table, Text, TextInput, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconKey, IconPlus, IconTrash } from "@tabler/icons-react";
import { useEffect, useState } from "react";

import { apiFetch, ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { UserCredential } from "@/lib/types";
import { decodeCreationOptions, encodeAttestationResponse } from "@/lib/webauthn";

interface BeginRegistrationResponse {
  options: any;
  session_id: string;
  expires_at: string;
}

export default function PasskeysPage() {
  const [credentials, setCredentials] = useState<UserCredential[]>([]);
  const [loading, setLoading] = useState(true);
  const [registering, setRegistering] = useState(false);
  const [label, setLabel] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      const response = await apiFetch<UserCredential[]>("/api/v1/me/passkeys");
      setCredentials(response);
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Failed to load passkeys." });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const register = async () => {
    if (typeof window === "undefined" || !window.PublicKeyCredential) {
      notifications.show({ color: "red", message: "Browser does not support WebAuthn." });
      return;
    }
    setRegistering(true);
    try {
      const begin = await apiFetch<BeginRegistrationResponse>("/api/v1/me/passkeys/begin-registration", { method: "POST" });
      const publicKey = decodeCreationOptions(begin.options);
      const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
      if (!credential) {
        throw new Error("Registration cancelled");
      }
      const encoded = encodeAttestationResponse(credential);
      const query = new URLSearchParams({ session_id: begin.session_id, label });
      await apiFetch(`/api/v1/me/passkeys/finish-registration?${query.toString()}`, {
        method: "POST",
        body: JSON.stringify(encoded),
      });
      notifications.show({ color: "green", message: "Passkey registered." });
      setLabel("");
      await load();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Registration failed";
      notifications.show({ color: "red", message });
    } finally {
      setRegistering(false);
    }
  };

  const remove = async (id: number) => {
    try {
      await apiFetch(`/api/v1/me/passkeys/${id}`, { method: "DELETE" });
      setCredentials((current) => current.filter((c) => c.id !== id));
      notifications.show({ color: "green", message: "Passkey removed." });
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Delete failed." });
    }
  };

  return (
    <Stack gap="lg">
      <Stack gap={4}>
        <Title order={2}>
          <Group gap="xs"><IconKey size={20} /> Passkeys</Group>
        </Title>
        <Text c="dimmed" size="sm">
          Sign in with hardware keys, Touch ID, Windows Hello, or platform authenticators. Passkeys work alongside TOTP — you can keep both.
        </Text>
      </Stack>

      <Card withBorder>
        <Stack gap="md">
          <Text fw={600}>Add a new passkey</Text>
          <TextInput
            label="Label"
            description="Helps you identify this passkey later (e.g. 'YubiKey 5C', 'MacBook Touch ID')."
            value={label}
            onChange={(event) => setLabel(event.currentTarget.value)}
          />
          <Group justify="flex-end">
            <Button leftSection={<IconPlus size={14} />} loading={registering} onClick={() => void register()}>
              Register passkey
            </Button>
          </Group>
        </Stack>
      </Card>

      {loading ? (
        <Stack align="center" py="md"><Loader color="brand" /></Stack>
      ) : credentials.length === 0 ? (
        <Alert color="brand" variant="light">No passkeys registered yet.</Alert>
      ) : (
        <Card withBorder>
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Label</Table.Th>
                <Table.Th>Created</Table.Th>
                <Table.Th>Last used</Table.Th>
                <Table.Th>Verified</Table.Th>
                <Table.Th></Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {credentials.map((cred) => (
                <Table.Tr key={cred.id}>
                  <Table.Td>{cred.label || "(unnamed)"}</Table.Td>
                  <Table.Td>{formatDateTime(cred.created_at)}</Table.Td>
                  <Table.Td>{formatDateTime(cred.last_used_at)}</Table.Td>
                  <Table.Td>
                    <Badge color={cred.user_verified ? "teal" : "gray"} variant="light">
                      {cred.user_verified ? "User verified" : "Unverified"}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <ActionIcon variant="subtle" color="red" onClick={() => void remove(cred.id)}>
                      <IconTrash size={16} />
                    </ActionIcon>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Card>
      )}
    </Stack>
  );
}
