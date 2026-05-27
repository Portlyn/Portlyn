"use client";

import { Button, Group, Modal, Stack, Text } from "@mantine/core";

export function ConfirmDialog({
  isOpen,
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel = "Delete",
  isLoading
}: {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void | Promise<void>;
  title: string;
  description: string;
  confirmLabel?: string;
  isLoading?: boolean;
}) {
  return (
    <Modal opened={isOpen} onClose={onClose} title={title} centered>
      <Stack gap="lg">
        <Text size="sm" c="#aab3c2">
          {description}
        </Text>
        <Group justify="flex-end">
          <Button variant="subtle" color="gray" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="subtle" color="danger" loading={isLoading} onClick={() => void onConfirm()}>
            {confirmLabel}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
