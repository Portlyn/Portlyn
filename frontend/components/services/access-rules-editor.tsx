"use client";

import { ActionIcon, Badge, Button, Grid, Group, Paper, Select, Stack, Text, Textarea, TextInput } from "@mantine/core";
import { IconArrowDown, IconArrowUp, IconPlus, IconTrash } from "@tabler/icons-react";

import type { AccessRule, AccessRuleAction } from "@/lib/types";

export const accessRuleActions: { value: AccessRuleAction; label: string; color: string }[] = [
  { value: "allow", label: "Allow", color: "success" },
  { value: "authenticate", label: "Require login", color: "brand" },
  { value: "deny", label: "Deny", color: "danger" }
];

export function AccessRuleActionBadge({ action }: { action: AccessRuleAction }) {
  const item = accessRuleActions.find((entry) => entry.value === action) || accessRuleActions[2];
  return (
    <Badge color={item.color} variant="light">
      {item.label}
    </Badge>
  );
}

export function cleanAccessRules(rules: AccessRule[]): AccessRule[] {
  return rules.map((rule) => ({
    name: rule.name.trim(),
    action: rule.action,
    sources: rule.sources.map((item) => item.trim()).filter(Boolean),
    paths: rule.paths.map((item) => item.trim()).filter(Boolean)
  }));
}

export function AccessRulesEditor({ value, onChange }: { value: AccessRule[]; onChange: (next: AccessRule[]) => void }) {
  const updateRule = (index: number, patch: Partial<AccessRule>) => {
    onChange(value.map((rule, itemIndex) => (itemIndex === index ? { ...rule, ...patch } : rule)));
  };

  const move = (index: number, offset: number) => {
    const target = index + offset;
    if (target < 0 || target >= value.length) {
      return;
    }
    const next = [...value];
    [next[index], next[target]] = [next[target], next[index]];
    onChange(next);
  };

  return (
    <Stack gap="sm">
      <Group justify="space-between" align="flex-start">
        <div>
          <Text fw={600}>Access rules</Text>
          <Text size="sm" c="dimmed">
            First match wins. Empty fields match anything. Prefix an IP with ! to exclude it, * stands for one path segment.
          </Text>
        </div>
        <Button
          variant="default"
          leftSection={<IconPlus size={16} />}
          onClick={() => onChange([...value, { name: "", action: "deny", sources: [], paths: [] }])}
        >
          Add rule
        </Button>
      </Group>
      {value.map((rule, index) => (
        <Paper key={index} withBorder radius="md" p="md">
          <Stack gap="sm">
            <Group justify="space-between">
              <Group gap="xs">
                <Badge color="gray" variant="outline">
                  #{index + 1}
                </Badge>
                <AccessRuleActionBadge action={rule.action} />
              </Group>
              <Group gap={4}>
                <ActionIcon variant="subtle" color="gray" aria-label="Move up" disabled={index === 0} onClick={() => move(index, -1)}>
                  <IconArrowUp size={16} />
                </ActionIcon>
                <ActionIcon
                  variant="subtle"
                  color="gray"
                  aria-label="Move down"
                  disabled={index === value.length - 1}
                  onClick={() => move(index, 1)}
                >
                  <IconArrowDown size={16} />
                </ActionIcon>
                <ActionIcon
                  variant="subtle"
                  color="danger"
                  aria-label="Delete rule"
                  onClick={() => onChange(value.filter((_, itemIndex) => itemIndex !== index))}
                >
                  <IconTrash size={16} />
                </ActionIcon>
              </Group>
            </Group>
            <Grid>
              <Grid.Col span={{ base: 12, md: 6 }}>
                <TextInput label="Name" value={rule.name} onChange={(event) => updateRule(index, { name: event.currentTarget.value })} />
              </Grid.Col>
              <Grid.Col span={{ base: 12, md: 6 }}>
                <Select
                  label="Action"
                  data={accessRuleActions.map(({ value: action, label }) => ({ value: action, label }))}
                  value={rule.action}
                  allowDeselect={false}
                  onChange={(next) => updateRule(index, { action: (next || "deny") as AccessRuleAction })}
                />
              </Grid.Col>
              <Grid.Col span={{ base: 12, md: 6 }}>
                <Textarea
                  label="Source IPs"
                  placeholder={"Any IP\n8.8.8.0/24\n!8.8.8.8"}
                  minRows={3}
                  autosize
                  value={rule.sources.join("\n")}
                  onChange={(event) => updateRule(index, { sources: event.currentTarget.value.split("\n") })}
                />
              </Grid.Col>
              <Grid.Col span={{ base: 12, md: 6 }}>
                <Textarea
                  label="Paths"
                  placeholder={"Any path\n/admin\n/api/*/export"}
                  minRows={3}
                  autosize
                  value={rule.paths.join("\n")}
                  onChange={(event) => updateRule(index, { paths: event.currentTarget.value.split("\n") })}
                />
              </Grid.Col>
            </Grid>
          </Stack>
        </Paper>
      ))}
    </Stack>
  );
}
