"use client";

import {
  Alert,
  Button,
  Center,
  Divider,
  Group,
  Image,
  Loader,
  Paper,
  PasswordInput,
  PinInput,
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

function sanitizeNextPath(raw: string): string {
  const value = raw.trim();
  if (value === "") {
    return "/services";
  }
  if (value.startsWith("//") || value.includes("\\")) {
    return "/services";
  }
  if (!value.startsWith("/")) {
    return "/services";
  }
  return value;
}
import { decodeRequestOptions, encodeAssertionResponse } from "@/lib/webauthn";

function LoginContent() {
  const { login, isAuthenticated } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [mfaCode, setMFACode] = useState("");
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const [mfaToken, setMFAToken] = useState<string | null>(null);
  const [otpStage, setOtpStage] = useState<"idle" | "requested">("idle");
  const [otpHint, setOtpHint] = useState<string | null>(null);
  const [authConfig, setAuthConfig] = useState({
    oidc_enabled: false,
    oidc_label: "SSO",
    otp_enabled: true,
    local_login_disabled: false,
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

  const nextPath = useMemo(() => {
    const raw = searchParams.get("next");
    if (!raw) {
      return "/services";
    }
    return sanitizeNextPath(raw);
  }, [searchParams]);

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

  const handleVerifyOTP = async (codeOverride?: string) => {
    const code = (codeOverride ?? otpCode).trim();
    if (code.length < 6) {
      return;
    }
    setIsOTPSubmitting(true);
    setError(null);
    try {
      const response = await verifyOTP(email, code);
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

  const handleVerifyMFA = async (codeOverride?: string) => {
    if (!mfaToken) {
      return;
    }
    const code = (codeOverride ?? mfaCode).trim();
    if (code.length < 6) {
      return;
    }
    setIsSubmitting(true);
    setError(null);
    try {
      await verifyMFA(mfaToken, code);
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
      <Paper withBorder radius="lg" p={36} w="100%" maw={460} style={authCardStyle(ui)}>
        <Stack gap="lg">
          <Stack gap={6} align="center">
            <Image src={ui.logo_url || "/logo.png"} alt={ui.brand_name} w={64} h={64} radius="lg" fit="contain" />
            <Title order={3} c={ui.text_color} ta="center" fw={600}>{ui.login_title}</Title>
            {ui.login_subtitle ? <Text size="sm" c={ui.muted_text_color} ta="center">{ui.login_subtitle}</Text> : null}
          </Stack>

          {mfaToken ? (
            <Stack gap="sm">
              <Text size="sm" c={ui.muted_text_color}>
                {useRecoveryCode ? "Enter one of your recovery codes." : "Enter the 6-digit code from your authenticator app."}
              </Text>
              {useRecoveryCode ? (
                <TextInput label="Recovery code" value={mfaCode} onChange={(event) => setMFACode(event.currentTarget.value)} styles={fields} autoFocus />
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
                    onComplete={(value) => void handleVerifyMFA(value)}
                  />
                </Group>
              )}
              <Button loading={isSubmitting} onClick={() => void handleVerifyMFA()} style={buttonStyle(ui)}>
                Verify
              </Button>
              <Button variant="subtle" size="xs" onClick={() => { setUseRecoveryCode((v) => !v); setMFACode(""); }}>
                {useRecoveryCode ? "Use authenticator code instead" : "Use a recovery code instead"}
              </Button>
            </Stack>
          ) : authConfig.local_login_disabled ? null : (
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
              {!authConfig.local_login_disabled ? <Divider label="or" labelPosition="center" /> : null}
              <Button loading={isOIDCSubmitting} onClick={handleOIDC} style={buttonStyle(ui)}>
                {ui.login_oidc_label || `Continue with ${authConfig.oidc_label || "SSO"}`}
              </Button>
            </>
          ) : null}

          {authConfig.otp_enabled && !authConfig.local_login_disabled && !mfaToken ? (
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
                    <Text size="sm" c={ui.muted_text_color}>Enter the code from your email.</Text>
                    <Group justify="center" my="xs">
                      <PinInput
                        length={8}
                        type="alphanumeric"
                        oneTimeCode
                        size="md"
                        value={otpCode}
                        onChange={(value) => setOtpCode(value.toUpperCase())}
                        onComplete={(value) => { setOtpCode(value.toUpperCase()); void handleVerifyOTP(value.toUpperCase()); }}
                      />
                    </Group>
                    <Button loading={isOTPSubmitting} onClick={() => handleVerifyOTP()} style={buttonStyle(ui)}>
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
