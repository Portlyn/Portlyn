"use client";

import { Anchor, Button, Code, CopyButton, Group, Modal, Stack, Text } from "@mantine/core";
import { IconArrowUpCircle, IconCheck, IconCopy } from "@tabler/icons-react";
import { useEffect, useState } from "react";

import { useAuth } from "@/components/providers";
import { apiFetch } from "@/lib/api";
import type { UpdateStatus } from "@/lib/types";

const REFRESH_MS = 60 * 60 * 1000;

function updateCommand(status: UpdateStatus) {
  if (status.install_method === "docker") {
    return "docker compose pull && docker compose up -d";
  }
  return "sudo portlyn update";
}

export function UpdateNotice() {
  const { user } = useAuth();
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [opened, setOpened] = useState(false);
  const isAdmin = user?.role === "admin";

  useEffect(() => {
    if (!isAdmin) return;
    const load = () => {
      apiFetch<UpdateStatus>("/api/v1/system/update")
        .then(setStatus)
        .catch(() => setStatus(null));
    };
    load();
    const timer = window.setInterval(load, REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [isAdmin]);

  if (!isAdmin || !status?.update_available || !status.latest_version) {
    return null;
  }

  const command = updateCommand(status);

  return (
    <>
      <Button variant="light" leftSection={<IconArrowUpCircle size={16} />} onClick={() => setOpened(true)} px={{ base: 8, sm: "md" }}>
        <Text span visibleFrom="xs">
          {status.latest_version}
        </Text>
      </Button>
      <Modal opened={opened} onClose={() => setOpened(false)} title={`Portlyn ${status.latest_version} is available`} centered>
        <Stack gap="md">
          <Text size="sm">
            You are running {status.current_version}.{" "}
            {status.release_url ? (
              <Anchor href={status.release_url} target="_blank" rel="noopener noreferrer">
                Release notes
              </Anchor>
            ) : null}
          </Text>
          <Stack gap={4}>
            <Text size="sm" c="dimmed">
              {status.install_method === "docker" ? "In the folder with your compose file:" : "On the server:"}
            </Text>
            <Group gap="xs" wrap="nowrap">
              <Code block style={{ flex: 1 }}>
                {command}
              </Code>
              <CopyButton value={command}>
                {({ copied, copy }) => (
                  <Button variant="default" onClick={copy} px="sm" aria-label="Copy command">
                    {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                  </Button>
                )}
              </CopyButton>
            </Group>
          </Stack>
        </Stack>
      </Modal>
    </>
  );
}
