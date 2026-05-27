"use client";

import { Button, Center, Paper, Stack, Text, Title } from "@mantine/core";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";

import { getAuthConfig, getRouteAuthService } from "@/lib/auth";
import { ApiError } from "@/lib/api";
import { authCardStyle, authShellStyle, buttonStyle, mergeAuthUI } from "@/lib/auth-ui";
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

  return (
    <Center mih="100vh" p="md" style={authShellStyle(ui)}>
      <Paper withBorder radius="md" p="xl" maw={580} w="100%" style={authCardStyle(ui)}>
        <Stack gap="lg">
          <div>
            {ui.logo_url ? <img src={ui.logo_url} alt={ui.brand_name} style={{ maxHeight: 36, maxWidth: 180, objectFit: "contain", marginBottom: 12, borderRadius: 12 }} /> : null}
            <Text fw={700} c={ui.text_color}>{ui.brand_name}</Text>
            <Title order={2} c={ui.text_color}>{ui.forbidden_title}</Title>
          </div>

          {service ? (
            <Stack gap="xs">
              <Text fw={600} c={ui.text_color}>{service.name}</Text>
              <Text size="sm" c={ui.muted_text_color}>{service.domain_name}{service.path}</Text>
            </Stack>
          ) : null}

          {ui.forbidden_subtitle ? <Text c={ui.muted_text_color}>{ui.forbidden_subtitle}</Text> : null}

          {error ? <Text c="red">{error}</Text> : null}

          {returnTo ? (
            <Button component="a" href={returnTo} style={buttonStyle(ui)}>
              {ui.forbidden_retry_label}
            </Button>
          ) : null}
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
