"use client";

import { Alert, Badge, Button, Code, Group, Modal, Stack, Table, Text, TextInput } from "@mantine/core";
import { useEffect, useState } from "react";

import { riskLevelColor, riskLevelLabel, type RiskAssessment } from "@/lib/risk-assessment";

const HIGH_RISK_CONFIRM_TOKEN = "PUBLIC";

export function RiskyChangeModal({
  opened,
  assessment,
  onClose,
  onConfirm,
  isLoading,
}: {
  opened: boolean;
  assessment: RiskAssessment | null;
  onClose: () => void;
  onConfirm: () => void;
  isLoading?: boolean;
}) {
  const [confirmToken, setConfirmToken] = useState("");

  useEffect(() => {
    if (opened) setConfirmToken("");
  }, [opened]);

  if (!assessment) return null;

  const requiresToken = assessment.requiresConfirmation;
  const confirmEnabled = !requiresToken || confirmToken.trim().toUpperCase() === HIGH_RISK_CONFIRM_TOKEN;

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title={`Confirm changes — ${riskLevelLabel(assessment.level)}`}
      size="lg"
    >
      <Stack gap="md">
        {assessment.level === "high" ? (
          <Alert color="danger" variant="filled">
            This change increases exposure. Review carefully before applying.
          </Alert>
        ) : null}

        {assessment.changes.length === 0 ? (
          <Text c="dimmed">No relevant policy changes detected.</Text>
        ) : (
          <Table withTableBorder striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Field</Table.Th>
                <Table.Th>Before</Table.Th>
                <Table.Th>After</Table.Th>
                <Table.Th>Risk</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {assessment.changes.map((change) => (
                <Table.Tr key={change.field}>
                  <Table.Td>
                    <Stack gap={2}>
                      <Text size="sm" fw={600}>{change.label}</Text>
                      {change.reason ? <Text size="xs" c="dimmed">{change.reason}</Text> : null}
                    </Stack>
                  </Table.Td>
                  <Table.Td><Code>{change.before}</Code></Table.Td>
                  <Table.Td><Code>{change.after}</Code></Table.Td>
                  <Table.Td>
                    <Badge color={riskLevelColor(change.level)} variant="light">{change.level}</Badge>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}

        {requiresToken ? (
          <TextInput
            label={`Type ${HIGH_RISK_CONFIRM_TOKEN} to confirm`}
            description="Required because this change exposes the service publicly or removes a critical guard."
            value={confirmToken}
            onChange={(event) => setConfirmToken(event.currentTarget.value)}
            placeholder={HIGH_RISK_CONFIRM_TOKEN}
            autoComplete="off"
          />
        ) : null}

        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>Cancel</Button>
          <Button
            color={assessment.level === "high" ? "danger" : "brand"}
            disabled={!confirmEnabled}
            loading={isLoading}
            onClick={onConfirm}
          >
            Apply changes
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
