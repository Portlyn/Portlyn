"use client";

import {
  Alert,
  Button,
  Center,
  Divider,
  Group,
  Loader,
  Paper,
  PasswordInput,
  Stack,
  Text,
  TextInput,
  Title
} from "@mantine/core";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";

import { useAuth } from "@/components/providers";
import { ApiError } from "@/lib/api";
import { beginPasskeyLogin, finishPasskeyLogin, getAuthConfig, requestOTP, startOIDCLogin, verifyMFA, verifyOTP } from "@/lib/auth";
import { authCardStyle, authInfoAlertStyle, authShellStyle, buttonStyle, inputStyles, mergeAuthUI } from "@/lib/auth-ui";
import { decodeRequestOptions, encodeAssertionResponse } from "@/lib/webauthn";

function LoginContent() {
  const { login, isAuthenticated } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [mfaCode, setMFACode] = useState("");
  const [mfaToken, setMFAToken] = useState<string | null>(null);
  const [otpStage, setOtpStage] = useState<"idle" | "requested">("idle");
  const [otpHint, setOtpHint] = useState<string | null>(null);
  const [authConfig, setAuthConfig] = useState({
    oidc_enabled: false,
    oidc_label: "SSO",
    otp_enabled: true,
    ui: mergeAuthUI()
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isOTPSubmitting, setIsOTPSubmitting] = useState(false);
  const [isOIDCSubmitting, setIsOIDCSubmitting] = useState(false);
  const [isPasskeySubmitting, setIsPasskeySubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handlePasskeyLogin = async () => {
    if (typeof window === "undefined" || !window.PublicKeyCredential) {
      setError("This browser does not support passkeys.");
      return;
    }
    if (!email.trim()) {
      setError("Enter your email first, then sign in with your passkey.");
      return;
    }
    setIsPasskeySubmitting(true);
    setError(null);
    try {
      const begin = await beginPasskeyLogin(email.trim());
      const publicKey = decodeRequestOptions(begin.options);
      const assertion = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
      if (!assertion) {
        throw new Error("Passkey prompt was cancelled.");
      }
      await finishPasskeyLogin(begin.session_id, encodeAssertionResponse(assertion));
      window.location.assign(nextPath);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : err instanceof Error ? err.message : "Passkey sign-in failed.");
    } finally {
      setIsPasskeySubmitting(false);
    }
  };

  const nextPath = useMemo(
    () => searchParams.get("next") || "/services",
    [searchParams]
  );

  useEffect(() => {
    void getAuthConfig().then((config) => setAuthConfig({ ...config, ui: mergeAuthUI(config.ui) })).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (isAuthenticated) {
      router.replace(nextPath);
    }
  }, [isAuthenticated, nextPath, router]);

  const handleSubmit = async () => {
    setIsSubmitting(true);
    setError(null);
    try {
      const response = await login(email, password);
      if (response.requires_mfa && response.mfa_token) {
        setMFAToken(response.mfa_token);
        return;
      }
      window.location.assign(nextPath);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to sign in.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRequestOTP = async () => {
    setIsOTPSubmitting(true);
    setError(null);
    try {
      const response = await requestOTP(email);
      setOtpStage("requested");
      setOtpHint(response.token ? `Development code: ${response.token}` : response.message || "If the account exists, a code has been issued.");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to request one-time code.");
    } finally {
      setIsOTPSubmitting(false);
    }
  };

  const handleVerifyOTP = async () => {
    setIsOTPSubmitting(true);
    setError(null);
    try {
      const response = await verifyOTP(email, otpCode);
      if (response.requires_mfa && response.mfa_token) {
        setMFAToken(response.mfa_token);
        return;
      }
      window.location.assign(nextPath);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to verify one-time code.");
    } finally {
      setIsOTPSubmitting(false);
    }
  };

  const handleVerifyMFA = async () => {
    if (!mfaToken) {
      return;
    }
    setIsSubmitting(true);
    setError(null);
    try {
      await verifyMFA(mfaToken, mfaCode);
      window.location.assign(nextPath);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to verify authenticator code.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleOIDC = async () => {
    setIsOIDCSubmitting(true);
    setError(null);
    try {
      await startOIDCLogin(nextPath);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to start SSO login.");
      setIsOIDCSubmitting(false);
    }
  };

  const ui = authConfig.ui;
  const fields = inputStyles(ui);

  return (
    <div style={authShellStyle(ui)}>
      <Paper withBorder radius="md" p="xl" w="100%" maw={520} style={authCardStyle(ui)}>
        <Stack gap="lg">
          <div>
            {ui.logo_url ? <img src={ui.logo_url} alt={ui.brand_name} style={{ maxHeight: 36, maxWidth: 180, objectFit: "contain", marginBottom: 12, borderRadius: 12 }} /> : null}
            <Text fw={700} c={ui.text_color}>
              {ui.brand_name}
            </Text>
            <Title order={2} c={ui.text_color}>{ui.login_title}</Title>
            {ui.login_subtitle ? <Text mt="xs" size="sm" c={ui.muted_text_color}>{ui.login_subtitle}</Text> : null}
          </div>

          {mfaToken ? (
            <Stack gap="sm">
              <Alert color="gray" variant="light" styles={authInfoAlertStyle(ui)}>
                Enter a 6-digit authenticator code or one of your recovery codes to finish sign-in.
              </Alert>
              <TextInput label="Authenticator or recovery code" value={mfaCode} onChange={(event) => setMFACode(event.currentTarget.value)} styles={fields} />
              <Button loading={isSubmitting} onClick={handleVerifyMFA} style={buttonStyle(ui)}>
                Verify MFA
              </Button>
            </Stack>
          ) : (
          <Stack gap="sm">
            <TextInput label="Email" value={email} onChange={(event) => setEmail(event.currentTarget.value)} styles={fields} />
            <PasswordInput label="Password" value={password} onChange={(event) => setPassword(event.currentTarget.value)} styles={fields} />
            <Button loading={isSubmitting} onClick={handleSubmit} style={buttonStyle(ui)}>
              {ui.login_password_label}
            </Button>
            <Button variant="default" loading={isPasskeySubmitting} onClick={handlePasskeyLogin}>
              Sign in with passkey
            </Button>
          </Stack>
          )}

          {authConfig.oidc_enabled && !mfaToken ? (
            <>
              <Divider label="or" labelPosition="center" />
              <Button loading={isOIDCSubmitting} onClick={handleOIDC} style={buttonStyle(ui)}>
                {ui.login_oidc_label || `Continue with ${authConfig.oidc_label || "SSO"}`}
              </Button>
            </>
          ) : null}

          {authConfig.otp_enabled && !mfaToken ? (
            <>
              <Divider label="One-time code" labelPosition="center" />
              <Stack gap="sm">
                <Group grow align="end">
                  <TextInput label="Email for OTP" value={email} onChange={(event) => setEmail(event.currentTarget.value)} styles={fields} />
                  <Button loading={isOTPSubmitting} onClick={handleRequestOTP} style={buttonStyle(ui)}>
                    {ui.login_otp_request_label}
                  </Button>
                </Group>
                {otpStage === "requested" ? (
                  <>
                    <TextInput label="One-time code" value={otpCode} onChange={(event) => setOtpCode(event.currentTarget.value)} styles={fields} />
                    <Button loading={isOTPSubmitting} onClick={handleVerifyOTP} style={buttonStyle(ui)}>
                      {ui.login_otp_verify_label}
                    </Button>
                  </>
                ) : null}
                {otpHint ? <Alert color="gray" variant="light" styles={authInfoAlertStyle(ui)}>{otpHint}</Alert> : null}
              </Stack>
            </>
          ) : null}

          {error ? <Alert color="danger" variant="light">{error}</Alert> : null}
        </Stack>
      </Paper>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<Center mih="100vh"><Loader color="gray" /></Center>}>
      <LoginContent />
    </Suspense>
  );
}
