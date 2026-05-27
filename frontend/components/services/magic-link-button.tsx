"use client";

import { Alert, Button, CopyButton, Group, Modal, NumberInput, Stack, Text, TextInput, Textarea } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCopy, IconLink } from "@tabler/icons-react";
import { useState } from "react";

import { apiFetch, ApiError } from "@/lib/api";
import type { MagicLinkResponse } from "@/lib/types";

export function MagicLinkButton({ serviceId, serviceName }: { serviceId: number; serviceName: string }) {
  const [opened, setOpened] = useState(false);
  const [ttlHours, setTTLHours] = useState<number | "">(2);
  const [label, setLabel] = useState("");
  const [issuing, setIssuing] = useState(false);
  const [issued, setIssued] = useState<MagicLinkResponse | null>(null);

  const issue = async () => {
    setIssuing(true);
    try {
      const ttlSeconds = typeof ttlHours === "number" && ttlHours > 0 ? ttlHours * 3600 : 7200;
      const response = await apiFetch<MagicLinkResponse>(`/api/v1/services/${serviceId}/magic-link`, {
        method: "POST",
        body: JSON.stringify({ ttl_seconds: ttlSeconds, label }),
      });
      setIssued(response);
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof ApiError ? err.message : "Could not issue magic link." });
    } finally {
      setIssuing(false);
    }
  };

  const close = () => {
    setOpened(false);
    setIssued(null);
    setLabel("");
    setTTLHours(2);
  };

  return (
    <>
      <Button variant="light" leftSection={<IconLink size={14} />} onClick={() => setOpened(true)}>
        Share link
      </Button>
      <Modal opened={opened} onClose={close} title={`Share temporary access — ${serviceName}`} size="lg">
        <Stack gap="md">
          {issued ? (
            <>
              <Alert color="yellow" variant="light">
                Single-use link. Anyone with the URL gains access until {new Date(issued.expires_at).toLocaleString()}.
              </Alert>
              <Textarea value={issued.url} autosize readOnly />
              <Group justify="flex-end">
                <CopyButton value={issued.url}>
                  {({ copied, copy }) => (
                    <Button leftSection={<IconCopy size={14} />} onClick={copy}>
                      {copied ? "Copied" : "Copy URL"}
                    </Button>
                  )}
                </CopyButton>
                <Button variant="default" onClick={close}>Done</Button>
              </Group>
            </>
          ) : (
            <>
              <Text size="sm" c="dimmed">
                A magic link grants one-time access without requiring login. Use sparingly for contractors, customer demos, or post-incident handoffs.
              </Text>
              <NumberInput label="Valid for (hours)" value={ttlHours} onChange={(value) => setTTLHours(typeof value === "number" ? value : "")} min={1} max={720} />
              <TextInput
                label="Label"
                description="Used in audit logs to identify the recipient."
                value={label}
                onChange={(event) => setLabel(event.currentTarget.value)}
                placeholder="e.g. contractor@example.com"
              />
              <Group justify="flex-end">
                <Button variant="default" onClick={close}>Cancel</Button>
                <Button onClick={() => void issue()} loading={issuing}>
                  Issue link
                </Button>
              </Group>
            </>
          )}
        </Stack>
      </Modal>
    </>
  );
}
