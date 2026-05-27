"use client";

import { Alert, Button, Center, Loader, Paper, Stack, Text, TextInput, Title } from "@mantine/core";
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
  const [nextPath, setNextPath] = useState("/services");
  const [error, setError] = useState<string | null>(null);
  const ui = mergeAuthUI();

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
          <>
            <Text c={ui.muted_text_color} ta="center">
              Enter your authenticator code or a recovery code to complete sign-in.
            </Text>
            <TextInput value={mfaCode} onChange={(event) => setMFACode(event.currentTarget.value)} label="Authenticator or recovery code" w="100%" styles={inputStyles(ui)} />
            <Button
              style={buttonStyle(ui)}
              onClick={() => {
                void verifyMFA(mfaToken, mfaCode)
                  .then((response) => {
                    completeAuth(response);
                    router.replace(nextPath);
                  })
                  .catch((err: Error) => {
                    setError(err.message || "Unable to verify MFA.");
                  });
              }}
            >
              Verify MFA
            </Button>
          </>
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
