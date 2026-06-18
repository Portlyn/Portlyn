"use client";

import { Button, Center, Image, Paper, Stack, Text, Title } from "@mantine/core";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";

import { getAuthConfig, getRouteAuthService } from "@/lib/auth";
import { ApiError } from "@/lib/api";
import { authCardStyle, authShellStyle, buttonStyle, mergeAuthUI } from "@/lib/auth-ui";
import { sanitizeReturnTo } from "@/lib/safe-redirect";
import type { AuthConfigResponse, RouteAuthService } from "@/lib/types";

function RouteForbiddenContent() {
  const params = useSearchParams();
  const serviceId = params.get("serviceId") || "";
  const returnTo = params.get("returnTo");

  const [service, setService] = useState<RouteAuthService | null>(null);
  const [authConfig, setAuthConfig] = useState<AuthConfigResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!serviceId) {
      setError("Missing service.");
      return;
    }
    void Promise.all([getRouteAuthService(serviceId), getAuthConfig()])
      .then(([serviceResponse, config]) => {
        setService(serviceResponse);
        setAuthConfig({ ...config, ui: mergeAuthUI(config.ui) });
      })
      .catch((err) => {
        setError(err instanceof ApiError ? err.message : "Unable to load service.");
      });
  }, [serviceId]);

  const ui = mergeAuthUI(authConfig?.ui);
  const safeReturnTo = sanitizeReturnTo(returnTo, service?.domain_name);

  return (
    <Center mih="100vh" p="md" style={authShellStyle(ui)}>
      <Paper withBorder radius="lg" p={36} maw={460} w="100%" style={authCardStyle(ui)}>
        <Stack gap="lg">
          <Stack gap={6} align="center">
            <Image src={ui.logo_url || "/logo.png"} alt={ui.brand_name} w={64} h={64} radius="lg" fit="contain" />
            <Title order={3} c={ui.text_color} ta="center" fw={600}>{ui.forbidden_title}</Title>
            {service ? (
              <Text size="sm" c={ui.muted_text_color} ta="center">{service.name} · {service.domain_name}{service.path}</Text>
            ) : null}
          </Stack>

          {ui.forbidden_subtitle ? <Text c={ui.muted_text_color} ta="center" size="sm">{ui.forbidden_subtitle}</Text> : null}

          {error ? <Text c="danger" ta="center" size="sm">{error}</Text> : null}

          {safeReturnTo ? (
            <Button component="a" href={safeReturnTo} style={buttonStyle(ui)}>
              {ui.forbidden_retry_label}
            </Button>
          ) : null}

          <Text size="xs" c={ui.muted_text_color} ta="center">Secured by {ui.brand_name}</Text>
        </Stack>
      </Paper>
    </Center>
  );
}

export default function RouteForbiddenPage() {
  return (
    <Suspense fallback={<Center mih="100vh"><Text c="dimmed">Loading...</Text></Center>}>
      <RouteForbiddenContent />
    </Suspense>
  );
}
