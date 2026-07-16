"use client";

import { Alert, Button, Center, Group, Loader, Paper, PinInput, Stack, Text, TextInput, Title } from "@mantine/core";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";

import { useAuth } from "@/components/providers";
import { finishOIDCLogin, verifyMFA } from "@/lib/auth";
import { authCardStyle, authInfoAlertStyle, authShellStyle, buttonStyle, inputStyles, mergeAuthUI } from "@/lib/auth-ui";

function CallbackContent() {
  const params = useSearchParams();
  const router = useRouter();
  const { completeAuth } = useAuth();
  const [mfaToken, setMFAToken] = useState<string | null>(null);
  const [mfaCode, setMFACode] = useState("");
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [nextPath, setNextPath] = useState("/services");
  const [error, setError] = useState<string | null>(null);
  const ui = mergeAuthUI();

  const submitMFA = (code?: string) => {
    if (!mfaToken) {
      return;
    }
    const value = (code ?? mfaCode).trim();
    if (!value) {
      return;
    }
    setIsSubmitting(true);
    setError(null);
    void verifyMFA(mfaToken, value)
      .then((response) => {
        completeAuth(response);
        router.replace(nextPath);
      })
      .catch((err: Error) => {
        setError(err.message || "Unable to verify MFA.");
      })
      .finally(() => setIsSubmitting(false));
  };

  useEffect(() => {
    const code = params.get("code");
    const state = params.get("state");
    if (!code || !state) {
      setError("Missing code or state.");
      return;
    }

    void finishOIDCLogin(code, state)
      .then((response) => {
        if (response.requires_mfa && response.mfa_token) {
          setMFAToken(response.mfa_token);
          setNextPath(response.next || "/services");
          return;
        }
        completeAuth(response);
        router.replace(response.next || "/services");
      })
      .catch((err: Error) => {
        setError(err.message || "Unable to complete SSO login.");
      });
  }, [completeAuth, params, router]);

  return (
    <Paper withBorder radius="md" p="xl" maw={480} w="100%" style={authCardStyle(ui)}>
      <Stack gap="md" align="center">
        <Title order={3} c={ui.text_color}>Completing SSO login</Title>
        {!error && !mfaToken ? (
          <>
            <Loader color="gray" />
            <Text c={ui.muted_text_color} ta="center">
              Validating the provider response and establishing your Portlyn session.
            </Text>
          </>
        ) : null}
        {mfaToken ? (
          <Stack gap="sm" w="100%">
            <Text size="sm" c={ui.muted_text_color} ta="center">
              {useRecoveryCode ? "Enter one of your recovery codes." : "Enter the 6-digit code from your authenticator app."}
            </Text>
            {useRecoveryCode ? (
              <TextInput label="Recovery code" value={mfaCode} onChange={(event) => setMFACode(event.currentTarget.value)} styles={inputStyles(ui)} autoFocus />
            ) : (
              <Group justify="center" my="xs">
                <PinInput
                  length={6}
                  type="number"
                  inputMode="numeric"
                  oneTimeCode
                  size="lg"
                  autoFocus
                  value={mfaCode}
                  onChange={setMFACode}
                  onComplete={(value) => submitMFA(value)}
                />
              </Group>
            )}
            <Button loading={isSubmitting} onClick={() => submitMFA()} style={buttonStyle(ui)}>
              Verify
            </Button>
            <Button variant="subtle" size="xs" onClick={() => { setUseRecoveryCode((v) => !v); setMFACode(""); }}>
              {useRecoveryCode ? "Use authenticator code instead" : "Use a recovery code instead"}
            </Button>
          </Stack>
        ) : (
          error ? <Alert color="danger" variant="light" w="100%" styles={authInfoAlertStyle(ui)}>{error}</Alert> : null
        )}
      </Stack>
    </Paper>
  );
}

export default function OIDCCallbackPage() {
  return (
    <Center mih="100vh" p="md" style={authShellStyle(mergeAuthUI())}>
      <Suspense fallback={<Loader color="gray" />}>
        <CallbackContent />
      </Suspense>
    </Center>
  );
}
