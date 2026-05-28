"use client";

import { Badge, Box, NavLink, Stack, Text } from "@mantine/core";
import {
  IconActivity,
  IconBolt,
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

const items: Array<{
  label: string;
  href: string;
  icon: typeof IconGridDots;
  roles: UserRole[];
}> = [
  { label: "Services", href: "/services", icon: IconGridDots, roles: ["admin", "viewer"] },
  { label: "Domains", href: "/domains", icon: IconGlobe, roles: ["admin"] },
  { label: "Nodes", href: "/nodes", icon: IconActivity, roles: ["admin"] },
  { label: "Tunnel", href: "/tunnel", icon: IconBolt, roles: ["admin"] },
  { label: "Certificates", href: "/certificates", icon: IconLock, roles: ["admin"] },
  { label: "DNS Providers", href: "/dns-providers", icon: IconGlobe, roles: ["admin"] },
  { label: "System", href: "/system", icon: IconActivity, roles: ["admin"] },
  { label: "Groups", href: "/groups", icon: IconUsers, roles: ["admin"] },
  { label: "Service Groups", href: "/service-groups", icon: IconGridDots, roles: ["admin"] },
  { label: "Users", href: "/users", icon: IconUsers, roles: ["admin"] },
  { label: "Exposure", href: "/exposure", icon: IconShieldCheck, roles: ["admin"] },
  { label: "Audit Logs", href: "/audit-logs", icon: IconFileText, roles: ["admin"] },
  { label: "Audit Webhooks", href: "/audit-webhooks", icon: IconWebhook, roles: ["admin"] },
  { label: "Access Tester", href: "/access-tester", icon: IconShieldCheck, roles: ["admin"] },
  { label: "Security", href: "/security", icon: IconKey, roles: ["admin", "viewer"] },
  { label: "Settings", href: "/settings", icon: IconSettings, roles: ["admin"] }
];

export function Sidebar() {
  const pathname = usePathname();
  const { user } = useAuth();

  return (
    <Box
      h="100%"
      p={18}
      style={{
        background: "linear-gradient(180deg, #1e1f25 0%, #16171c 100%)",
        borderRight: "1px solid rgba(255,255,255,0.04)"
      }}
    >
      <Stack h="100%" gap={28}>
        <Box px={8} pt={6}>
          <Box style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <Image src="/logo.png" alt="Portlyn logo" width={48} height={48} style={{ borderRadius: 14, flexShrink: 0 }} />
            <Box>
              <Text fw={700} fz={23} style={{ letterSpacing: "-0.03em", lineHeight: 1.05 }}>
                Portlyn
              </Text>
            </Box>
          </Box>
        </Box>

        <Stack gap={10} style={{ flex: 1 }}>
          <Text px={10} size="xs" fw={600} tt="uppercase" c="#667085" style={{ letterSpacing: "0.08em" }}>
            Workspace
          </Text>
          {items
            .filter((item) => user && item.roles.includes(user.role))
            .map((item) => {
              const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.href}
                  component={Link}
                  href={item.href}
                  active={active}
                  label={item.label}
                  leftSection={<Icon size={16} stroke={1.8} />}
                  rightSection={
                    item.href === "/audit-logs" ? (
                      <Badge size="xs" color="gray">
                        Admin
                      </Badge>
                    ) : null
                  }
                  styles={{
                    root: {
                      background: active ? "rgba(255,255,255,0.05)" : "transparent",
                      color: active ? "#f4f7fb" : "#9aa3b2"
                    },
                    section: {
                      color: active ? "#9c79d0" : "#707988"
                    }
                  }}
                />
              );
            })}
        </Stack>

        <Box px={10} pb={6}>
          <Text size="xs" c="#667085" style={{ lineHeight: 1.5 }}>
            Made by
          </Text>
          <Text size="sm" c="#9aa3b2" fw={500}>
            Software Entwicklung Schnittert
          </Text>
        </Box>
      </Stack>
    </Box>
  );
}
