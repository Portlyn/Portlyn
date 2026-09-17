"use client";

import { Center, Loader, Stack, Text } from "@mantine/core";
import { usePathname, useRouter } from "next/navigation";
import type { ReactNode } from "react";
import { useEffect } from "react";

import { useAuth } from "@/components/providers";

const VIEWER_PATHS = ["/services", "/security"];

export function AuthGuard({ children }: { children: ReactNode }) {
  const { isAuthenticated, isLoading, user } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const normalizedPath = pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
  const viewerAllowed = VIEWER_PATHS.includes(normalizedPath);

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.replace(`/login?next=${encodeURIComponent(pathname)}`);
      return;
    }
    if (!isLoading && isAuthenticated && user?.role === "viewer" && !viewerAllowed) {
      router.replace("/services");
    }
  }, [isAuthenticated, isLoading, pathname, router, user?.role, viewerAllowed]);

  if (isLoading || !isAuthenticated || (user?.role === "viewer" && !viewerAllowed)) {
    return (
      <Center mih="100vh">
        <Stack gap="sm" align="center">
          <Loader color="brand" />
          <Text c="dimmed" size="sm">
            Checking access
          </Text>
        </Stack>
      </Center>
    );
  }

  return <>{children}</>;
}
