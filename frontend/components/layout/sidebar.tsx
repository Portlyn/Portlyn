"use client";

import { AppShell, Box, NavLink, ScrollArea, Stack, Text } from "@mantine/core";
import {
  IconActivity,
  IconDeviceLaptop,
  IconFileText,
  IconGlobe,
  IconGridDots,
  IconKey,
  IconLock,
  IconSettings,
  IconShieldCheck,
  IconUsers,
  IconWebhook
} from "@tabler/icons-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import Image from "next/image";

import { useAuth } from "@/components/providers";
import type { UserRole } from "@/lib/types";

type NavItem = {
  label: string;
  href: string;
  icon: typeof IconGridDots;
  roles: UserRole[];
};

const navSections: Array<{ section: string; items: NavItem[] }> = [
  {
    section: "Workspace",
    items: [
      { label: "Services", href: "/services", icon: IconGridDots, roles: ["admin", "viewer"] },
      { label: "Domains", href: "/domains", icon: IconGlobe, roles: ["admin"] },
      { label: "Certificates", href: "/certificates", icon: IconLock, roles: ["admin"] },
      { label: "DNS Providers", href: "/dns-providers", icon: IconGlobe, roles: ["admin"] }
    ]
  },
  {
    section: "Network",
    items: [
      { label: "Nodes", href: "/nodes", icon: IconActivity, roles: ["admin"] },
      { label: "Clients", href: "/clients", icon: IconDeviceLaptop, roles: ["admin"] }
    ]
  },
  {
    section: "Access",
    items: [
      { label: "Users", href: "/users", icon: IconUsers, roles: ["admin"] },
      { label: "Groups", href: "/groups", icon: IconUsers, roles: ["admin"] },
      { label: "Service Groups", href: "/service-groups", icon: IconGridDots, roles: ["admin"] },
      { label: "API Tokens", href: "/api-tokens", icon: IconKey, roles: ["admin"] },
      { label: "Security", href: "/security", icon: IconKey, roles: ["admin", "viewer"] }
    ]
  },
  {
    section: "Insights",
    items: [
      { label: "System", href: "/system", icon: IconActivity, roles: ["admin"] },
      { label: "Exposure", href: "/exposure", icon: IconShieldCheck, roles: ["admin"] },
      { label: "Audit Logs", href: "/audit-logs", icon: IconFileText, roles: ["admin"] },
      { label: "Audit Webhooks", href: "/audit-webhooks", icon: IconWebhook, roles: ["admin"] },
      { label: "Access Tester", href: "/access-tester", icon: IconShieldCheck, roles: ["admin"] }
    ]
  },
  {
    section: "Settings",
    items: [{ label: "Settings", href: "/settings", icon: IconSettings, roles: ["admin"] }]
  }
];

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  const { user } = useAuth();

  return (
    <>
      <AppShell.Section px={18} py={16}>
        <Box style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <Image src="/logo.png" alt="Portlyn logo" width={34} height={34} style={{ borderRadius: 10, flexShrink: 0 }} />
          <Text fw={700} fz={20} style={{ letterSpacing: "-0.03em", lineHeight: 1.05 }}>
            Portlyn
          </Text>
        </Box>
      </AppShell.Section>

      <AppShell.Section grow component={ScrollArea} px={12} type="scroll">
        <Stack gap={14}>
          {navSections.map(({ section, items }) => {
            const visible = items.filter((item) => user && item.roles.includes(user.role));
            if (visible.length === 0) {
              return null;
            }
            return (
              <Stack key={section} gap={2}>
                <Text px={10} size="xs" fw={600} tt="uppercase" c="dimmed" style={{ letterSpacing: "0.08em" }}>
                  {section}
                </Text>
                {visible.map((item) => {
                  const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
                  const Icon = item.icon;
                  return (
                    <NavLink
                      key={item.href}
                      component={Link}
                      href={item.href}
                      active={active}
                      label={item.label}
                      fz={14}
                      onClick={onNavigate}
                      leftSection={<Icon size={16} stroke={1.8} />}
                      styles={{
                        root: {
                          borderRadius: 8,
                          padding: "7px 10px",
                          background: active ? "var(--portlyn-surface-raised)" : "transparent",
                          color: active ? "var(--portlyn-text)" : "var(--portlyn-text-muted)"
                        },
                        section: {
                          color: active ? "var(--mantine-color-brand-4)" : "var(--portlyn-text-dimmed)"
                        }
                      }}
                    />
                  );
                })}
              </Stack>
            );
          })}
        </Stack>
      </AppShell.Section>

      <AppShell.Section px={18} py={14} style={{ borderTop: "1px solid var(--portlyn-border)" }}>
        <Text size="xs" c="dimmed" style={{ lineHeight: 1.4 }}>
          Made by
        </Text>
        <Text size="sm" c="var(--portlyn-text-muted)" fw={500}>
          Software Entwicklung Schnittert
        </Text>
      </AppShell.Section>
    </>
  );
}
