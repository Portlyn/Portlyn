"use client";

import { Alert, Button, Center, Divider, Group, Image, Paper, PasswordInput, PinInput, Stack, Text, TextInput, Title } from "@mantine/core";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";

import { useAuth } from "@/components/providers";
import { ApiError } from "@/lib/api";
import { authCardStyle, authInfoAlertStyle, authShellStyle, buttonStyle, inputStyles, mergeAuthUI } from "@/lib/auth-ui";
import {
  createSessionBridgeToken,
  getAuthConfig,
  getRouteAuthService,
  requestRouteEmailCode,
  startOIDCLogin,
  verifyRouteEmailCode,
  verifyRoutePIN
} from "@/lib/auth";
import type { AuthConfigResponse, RouteAuthService } from "@/lib/types";

function buildReturnTarget(service: RouteAuthService | null, returnTo: string | null) {
  if (returnTo) {
    return returnTo;
  }
  if (!service || typeof window === "undefined") {
    return "/";
  }
  return `${window.location.protocol}//${service.domain_name}${service.path}`;
}

function buildContinuePath(serviceId: string, returnTo: string | null) {
  const params = new URLSearchParams({ serviceId, continue: "1" });
  if (returnTo) {
    params.set("returnTo", returnTo);
  }
  return `/route-login?${params.toString()}`;
}

async function bridgeSessionToTarget(service: RouteAuthService, returnTo: string | null) {
  const target = new URL(buildReturnTarget(service, returnTo), window.location.origin);
  const response = await createSessionBridgeToken(target.host);
  target.pathname = "/_portlyn/session-bridge";
  target.search = new URLSearchParams({
    token: response.token,
    returnTo: buildReturnTarget(service, returnTo)
  }).toString();
  window.location.assign(target.toString());
}

function RouteLoginContent() {
  const params = useSearchParams();
  const { isAuthenticated, user } = useAuth();
  const serviceId = params.get("serviceId") || "";
  const returnTo = params.get("returnTo");
  const continuePath = useMemo(() => buildContinuePath(serviceId, returnTo), [returnTo, serviceId]);

  const [service, setService] = useState<RouteAuthService | null>(null);
  const [authConfig, setAuthConfig] = useState<AuthConfigResponse | null>(null);
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [pin, setPIN] = useState("");
  const [emailStep, setEmailStep] = useState<"request" | "verify">("request");
  const [emailHint, setEmailHint] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isOIDCSubmitting, setIsOIDCSubmitting] = useState(false);
  const [isBridging, setIsBridging] = useState(false);

  useEffect(() => {
    if (!serviceId) {
      setError("Missing serviceId.");
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    setError(null);
    void Promise.all([getRouteAuthService(serviceId), getAuthConfig()])
      .then(([serviceResponse, configResponse]) => {
        setService(serviceResponse);
        setAuthConfig({ ...configResponse, ui: mergeAuthUI(configResponse.ui) });
      })
      .catch((err) => {
        setError(err instanceof ApiError ? err.message : "Unable to load route access details.");
      })
      .finally(() => setIsLoading(false));
  }, [serviceId]);

  useEffect(() => {
    if (!service || isBridging) {
      return;
    }
    if (service.access_method === "oidc_only" && isAuthenticated && user?.auth_provider === "oidc") {
      setIsBridging(true);
      void bridgeSessionToTarget(service, returnTo).catch((err) => {
        setError(err instanceof ApiError ? err.message : "Unable to continue to the protected route.");
        setIsBridging(false);
      });
      return;
    }
    if (service.access_method === "session" && isAuthenticated) {
      setIsBridging(true);
      void bridgeSessionToTarget(service, returnTo).catch((err) => {
        setError(err instanceof ApiError ? err.message : "Unable to continue to the protected route.");
        setIsBridging(false);
      });
    }
  }, [isAuthenticated, isBridging, params, returnTo, service, user]);

  const handlePIN = async () => {
    if (!service) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const target = buildReturnTarget(service, returnTo);
      const response = await verifyRoutePIN(service.id, pin, target);
      window.location.assign(response.bridge_url || target);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to verify route PIN.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRequestEmailCode = async () => {
    if (!service) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const response = await requestRouteEmailCode(service.id, email);
      setEmailStep("verify");
      setEmailHint(response.code ? `Development code: ${response.code}` : "A code was issued for this route.");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to request email code.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleVerifyEmailCode = async (codeOverride?: string) => {
    if (!service) return;
    const verifyCode = (codeOverride ?? code).trim();
    if (!verifyCode) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const target = buildReturnTarget(service, returnTo);
      const response = await verifyRouteEmailCode(service.id, email, verifyCode, target);
      window.location.assign(response.bridge_url || target);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to verify email code.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleOIDC = async () => {
    setIsOIDCSubmitting(true);
    setError(null);
    try {
      await startOIDCLogin(continuePath);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to start SSO login.");
      setIsOIDCSubmitting(false);
    }
  };

  const ui = mergeAuthUI(authConfig?.ui);
  const fields = inputStyles(ui);

  return (
    <Center mih="100vh" p="md" style={authShellStyle(ui)}>
      <Paper withBorder radius="lg" p={36} maw={460} w="100%" style={authCardStyle(ui)}>
        <Stack gap="lg">
          <Stack gap={6} align="center">
            <Image src={ui.logo_url || "/logo.png"} alt={ui.brand_name} w={64} h={64} radius="lg" fit="contain" />
            <Title order={3} c={ui.text_color} ta="center" fw={600}>
              {service ? service.name : ui.route_login_title}
            </Title>
            {service ? (
              <Text size="sm" c={ui.muted_text_color} ta="center">{service.domain_name}{service.path}</Text>
            ) : null}
          </Stack>

          {service?.access_message ? (
            <Alert color="gray" variant="light" styles={authInfoAlertStyle(ui)}>{service.access_message}</Alert>
          ) : null}

          {isLoading || isBridging ? (
            <Text c={ui.muted_text_color} ta="center" size="sm">{isBridging ? "Continuing to protected route..." : "Loading route access details..."}</Text>
          ) : null}

          {!isLoading && service?.access_method === "oidc_only" ? (
            <Stack gap="sm">
              <Button loading={isOIDCSubmitting} onClick={handleOIDC} disabled={!authConfig?.oidc_enabled} style={buttonStyle(ui)}>
                {ui.route_oidc_label || `Continue with ${authConfig?.oidc_label || "SSO"}`}
              </Button>
            </Stack>
          ) : null}

          {!isLoading && service?.access_method === "session" ? (
            <Stack gap="sm">
              <Button component={Link} href={`/login?next=${encodeURIComponent(continuePath)}`} style={buttonStyle(ui)}>
                {ui.route_continue_label}
              </Button>
              {authConfig?.oidc_enabled ? (
                <>
                  <Divider label="or" labelPosition="center" />
                  <Button loading={isOIDCSubmitting} onClick={handleOIDC} style={buttonStyle(ui)}>
                    {ui.route_oidc_label || `Continue with ${authConfig.oidc_label || "SSO"}`}
                  </Button>
                </>
              ) : null}
            </Stack>
          ) : null}

          {!isLoading && service?.access_method === "pin" ? (
            <Stack gap="sm">
              <PasswordInput label="PIN" value={pin} onChange={(event) => setPIN(event.currentTarget.value)} styles={fields} />
              {service.access_method_config?.hint ? (
                <Text size="sm" c={ui.muted_text_color}>{service.access_method_config?.hint}</Text>
              ) : null}
              <Button loading={isSubmitting} onClick={handlePIN} disabled={!pin} style={buttonStyle(ui)}>
                {ui.route_pin_label}
              </Button>
            </Stack>
          ) : null}

          {!isLoading && service?.access_method === "email_code" ? (
            <Stack gap="sm">
              <TextInput label="Email" value={email} onChange={(event) => setEmail(event.currentTarget.value)} styles={fields} />
              {service.access_method_config?.hint ? (
                <Text size="sm" c={ui.muted_text_color}>{service.access_method_config?.hint}</Text>
              ) : null}
              {emailStep === "request" ? (
                <Button loading={isSubmitting} onClick={handleRequestEmailCode} disabled={!email} style={buttonStyle(ui)}>
                  {ui.route_email_send_label}
                </Button>
              ) : (
                <>
                  <Text size="sm" c={ui.muted_text_color} ta="center">Enter the code from your email.</Text>
                  <Group justify="center" my="xs">
                    <PinInput
                      length={8}
                      type="alphanumeric"
                      oneTimeCode
                      value={code}
                      onChange={(value) => setCode(value.toUpperCase())}
                      onComplete={(value) => { setCode(value.toUpperCase()); void handleVerifyEmailCode(value.toUpperCase()); }}
                    />
                  </Group>
                  <Button loading={isSubmitting} onClick={() => handleVerifyEmailCode()} disabled={!email || !code} style={buttonStyle(ui)}>
                    {ui.route_email_verify_label}
                  </Button>
                </>
              )}
              {emailHint ? <Alert color="gray" variant="light" styles={authInfoAlertStyle(ui)}>{emailHint}</Alert> : null}
            </Stack>
          ) : null}

          {error ? <Alert color="danger" variant="light">{error}</Alert> : null}

          <Text size="xs" c={ui.muted_text_color} ta="center" mt="xs">
            Secured by {ui.brand_name}
          </Text>
        </Stack>
      </Paper>
    </Center>
  );
}

export default function RouteLoginPage() {
  return (
    <Suspense fallback={<Center mih="100vh"><Text c="dimmed">Loading...</Text></Center>}>
      <RouteLoginContent />
    </Suspense>
  );
}
