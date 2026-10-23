"use client";

import { Burger, Button, Group, Paper, Stack, Text } from "@mantine/core";
import { IconLogout2 } from "@tabler/icons-react";
import { usePathname } from "next/navigation";

import { UpdateNotice } from "@/components/layout/update-notice";
import { useAuth, UserAvatar } from "@/components/providers";

const titles: Record<string, string> = {
  "/services": "Services",
  "/domains": "Domains",
  "/nodes": "Nodes",
  "/clients": "Clients",
  "/certificates": "Certificates",
  "/dns-providers": "DNS Providers",
  "/system": "System",
  "/groups": "Groups",
  "/service-groups": "Service Groups",
  "/users": "Users",
  "/exposure": "Exposure",
  "/access-log": "Access Log",
  "/audit-logs": "Audit Logs",
  "/audit-webhooks": "Audit Webhooks",
  "/access-tester": "Access Tester",
  "/security": "Security",
  "/settings": "Settings"
};

export function Topbar({ opened, onToggle }: { opened: boolean; onToggle: () => void }) {
  const pathname = usePathname();
  const { user, logout } = useAuth();
  const baseTitle =
    Object.entries(titles).find(([route]) => pathname === route || pathname.startsWith(`${route}/`))?.[1] ||
    "Portlyn";
  const title = user?.role === "viewer" && baseTitle === "Services" ? "Applications" : baseTitle;

  return (
    <Group h="100%" px={{ base: 16, sm: 32 }} justify="space-between" wrap="nowrap">
      <Group gap="sm" wrap="nowrap" style={{ minWidth: 0 }}>
        <Burger opened={opened} onClick={onToggle} hiddenFrom="sm" size="sm" aria-label="Toggle navigation" />
        <Text fw={600} fz={{ base: 20, sm: 30 }} truncate style={{ letterSpacing: "-0.03em" }}>
          {title}
        </Text>
      </Group>

      <Group gap="sm" wrap="nowrap">
        <UpdateNotice />
        <Paper p="xs" bg="rgba(255,255,255,0.03)">
          <Group gap="sm" wrap="nowrap">
            <UserAvatar />
            <Stack gap={0} visibleFrom="xs">
              <Text size="sm" fw={600}>
                {user?.email}
              </Text>
              <Text size="xs" c="dimmed" tt="capitalize">
                {user?.role}
              </Text>
            </Stack>
          </Group>
        </Paper>
        <Button variant="subtle" color="gray" leftSection={<IconLogout2 size={16} />} onClick={logout} px={{ base: 8, sm: "md" }}>
          <Text span visibleFrom="xs">Logout</Text>
        </Button>
      </Group>
    </Group>
  );
}
