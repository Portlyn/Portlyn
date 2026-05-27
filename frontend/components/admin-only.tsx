"use client";

import { Alert } from "@mantine/core";
import { IconAlertTriangle } from "@tabler/icons-react";
import type { ReactNode } from "react";

import { useAuth } from "@/components/providers";

export function AdminOnly({ children, title = "Admin access required" }: { children: ReactNode; title?: string }) {
  const { user } = useAuth();

  if (user?.role === "admin") {
    return <>{children}</>;
  }

  return (
    <Alert icon={<IconAlertTriangle size={16} />} title={title} color="warning" variant="light">
      You can view the platform, but this section is reserved for admins.
    </Alert>
  );
}
