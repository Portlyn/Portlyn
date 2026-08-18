"use client";

import { Alert, Badge, Button, Card, Code, CopyButton, Group, Image, Loader, Stack, Text, TextInput } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconShieldLock } from "@tabler/icons-react";
import QRCode from "qrcode";
import { useEffect, useState } from "react";

import { ApiError } from "@/lib/api";
import { beginMFASetup, disableMFA, enableMFA, getMyMFAStatus, regenerateRecoveryCodes } from "@/lib/auth";
import type { MFASetup, MFAStatus } from "@/lib/types";

export function MfaCard() {
  const [status, setStatus] = useState<MFAStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [setup, setSetup] = useState<MFASetup | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      setStatus(await getMyMFAStatus());
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Failed to load MFA status." });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const startSetup = async () => {
    setBusy(true);
    try {
      const response = await beginMFASetup();
      setSetup(response);
      setRecoveryCodes(null);
      const dataUrl = await QRCode.toDataURL(response.otpauth_url, { margin: 1, width: 220 });
      setQr(dataUrl);
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Could not start MFA setup." });
    } finally {
      setBusy(false);
    }
  };

  const confirmEnable = async () => {
    setBusy(true);
    try {
      const next = await enableMFA(code.trim());
      setStatus(next);
      setRecoveryCodes(setup?.recovery_codes || null);
      setSetup(null);
      setQr(null);
      setCode("");
      notifications.show({ color: "success", message: "MFA enabled." });
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Invalid code." });
    } finally {
      setBusy(false);
    }
  };

  const turnOff = async () => {
    setBusy(true);
    try {
      const next = await disableMFA(disableCode.trim());
      setStatus(next);
      setDisableCode("");
      setRecoveryCodes(null);
      notifications.show({ color: "success", message: "MFA disabled." });
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Invalid code." });
    } finally {
      setBusy(false);
    }
  };

  const regenerate = async () => {
    setBusy(true);
    try {
      const result = await regenerateRecoveryCodes(disableCode.trim());
      setRecoveryCodes(result.recovery_codes);
      setDisableCode("");
      notifications.show({ color: "success", message: "Recovery codes regenerated." });
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Invalid code." });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card withBorder>
      <Stack gap="md">
        <Group justify="space-between">
          <Group gap="xs">
            <IconShieldLock size={20} />
            <Text fw={600}>Authenticator app (TOTP)</Text>
          </Group>
          {loading ? (
            <Loader size="xs" />
          ) : (
            <Badge color={status?.enabled ? "success" : "gray"}>{status?.enabled ? "enabled" : "disabled"}</Badge>
          )}
        </Group>

        {status?.required_for_current_user && !status.enabled ? (
          <Alert color="warning">
            Your account requires a second factor. Set up an authenticator app or register a passkey below.
          </Alert>
        ) : null}

        {recoveryCodes && recoveryCodes.length > 0 ? (
          <Alert color="warning" title="Recovery codes">
            <Text size="sm" mb="xs">Store these now. Each works once if you lose your authenticator.</Text>
            <Code block>{recoveryCodes.join("\n")}</Code>
          </Alert>
        ) : null}

        {!status?.enabled && !setup ? (
          <Button onClick={() => void startSetup()} loading={busy} w="fit-content">
            Set up authenticator
          </Button>
        ) : null}

        {setup ? (
          <Stack gap="sm">
            <Text size="sm" c="dimmed">Scan with your authenticator app, then enter the 6-digit code.</Text>
            {qr ? <Image src={qr} alt="MFA QR code" w={220} h={220} radius="md" /> : null}
            <Group gap="xs">
              <Text size="xs" c="dimmed">Manual key:</Text>
              <CopyButton value={setup.secret}>
                {({ copied, copy }) => (
                  <Code style={{ cursor: "pointer" }} onClick={copy}>{copied ? "copied" : setup.secret}</Code>
                )}
              </CopyButton>
            </Group>
            <Group align="flex-end">
              <TextInput label="Code" value={code} onChange={(e) => setCode(e.currentTarget.value)} placeholder="123456" />
              <Button onClick={() => void confirmEnable()} loading={busy} disabled={code.trim().length < 6}>
                Enable
              </Button>
            </Group>
          </Stack>
        ) : null}

        {status?.enabled ? (
          <Stack gap="sm">
            <Text size="sm" c="dimmed">{status.recovery_code_count} recovery codes remaining.</Text>
            <Group align="flex-end">
              <TextInput
                label="Current code"
                description="Enter a current authenticator or recovery code to manage MFA."
                value={disableCode}
                onChange={(e) => setDisableCode(e.currentTarget.value)}
                placeholder="123456"
              />
              <Button variant="light" onClick={() => void regenerate()} loading={busy} disabled={!disableCode.trim()}>
                Regenerate recovery codes
              </Button>
              <Button variant="light" color="danger" onClick={() => void turnOff()} loading={busy} disabled={!disableCode.trim()}>
                Disable MFA
              </Button>
            </Group>
          </Stack>
        ) : null}
      </Stack>
    </Card>
  );
}
