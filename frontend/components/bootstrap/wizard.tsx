"use client";

import {
  Alert,
  Button,
  Checkbox,
  Code,
  CopyButton,
  Divider,
  Group,
  Image,
  Modal,
  PasswordInput,
  SegmentedControl,
  Select,
  Stack,
  Stepper,
  Text,
  TextInput
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCheck, IconKey, IconShieldLock } from "@tabler/icons-react";
import QRCode from "qrcode";
import { useEffect, useMemo, useState } from "react";

import { apiFetch, ApiError } from "@/lib/api";
import {
  beginMFASetup,
  completeAccountSetup,
  dismissBootstrap,
  enableMFA
} from "@/lib/auth";
import type { MFASetup, User } from "@/lib/types";
import { decodeCreationOptions, encodeAttestationResponse } from "@/lib/webauthn";

interface BootstrapWizardProps {
  user: User;
  onComplete: (updates?: { user?: User; dismissed?: boolean }) => void;
}

interface BeginPasskeyRegistration {
  options: unknown;
  session_id: string;
  expires_at: string;
}

export function BootstrapWizard({ user, onComplete }: BootstrapWizardProps) {
  const needsAccountStep = user.must_change_password;
  const initialStep = needsAccountStep ? 0 : 1;

  const [step, setStep] = useState(initialStep);
  const [email, setEmail] = useState(user.email || "");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [accountBusy, setAccountBusy] = useState(false);

  const [method, setMethod] = useState<"passkey" | "totp">("passkey");
  const [passkeyBusy, setPasskeyBusy] = useState(false);
  const [passkeyLabel, setPasskeyLabel] = useState("");

  const [totpSetup, setTotpSetup] = useState<MFASetup | null>(null);
  const [totpQr, setTotpQr] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [totpBusy, setTotpBusy] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [savedCodes, setSavedCodes] = useState(false);

  const [skipping, setSkipping] = useState(false);

  const isAdmin = user.role === "admin";
  const doneStep = isAdmin ? 3 : 2;
  const [domainName, setDomainName] = useState("");
  const [dnsProviderType, setDnsProviderType] = useState("cloudflare");
  const [dnsToken, setDnsToken] = useState("");
  const [domainBusy, setDomainBusy] = useState(false);
  const [domainConfigured, setDomainConfigured] = useState(false);

  useEffect(() => {
    if (step === 1 && method === "totp" && !totpSetup && !totpBusy) {
      void startTotp();
    }
  }, [step, method]);

  const recoveryFile = useMemo(() => {
    if (!recoveryCodes || recoveryCodes.length === 0) {
      return "";
    }
    const blob = new Blob([recoveryCodes.join("\n") + "\n"], { type: "text/plain" });
    return URL.createObjectURL(blob);
  }, [recoveryCodes]);

  const submitAccount = async () => {
    if (password.length < 8) {
      notifications.show({ color: "danger", message: "Password must be at least 8 characters." });
      return;
    }
    if (password !== confirmPassword) {
      notifications.show({ color: "danger", message: "Passwords do not match." });
      return;
    }
    setAccountBusy(true);
    try {
      const updated = await completeAccountSetup(email.trim(), password);
      notifications.show({ color: "success", message: "Account details saved." });
      setStep(1);
      onComplete({ user: { ...updated, bootstrap_dismissed: user.bootstrap_dismissed } });
    } catch (err) {
      notifications.show({
        color: "danger",
        message: err instanceof ApiError ? err.message : "Could not save account details."
      });
    } finally {
      setAccountBusy(false);
    }
  };

  const registerPasskey = async () => {
    if (typeof window === "undefined" || !window.PublicKeyCredential) {
      notifications.show({ color: "danger", message: "Browser does not support WebAuthn." });
      return;
    }
    setPasskeyBusy(true);
    try {
      const begin = await apiFetch<BeginPasskeyRegistration>("/api/v1/me/passkeys/begin-registration", {
        method: "POST"
      });
      const publicKey = decodeCreationOptions(begin.options);
      const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
      if (!credential) {
        throw new Error("Registration cancelled");
      }
      const encoded = encodeAttestationResponse(credential);
      const query = new URLSearchParams({ session_id: begin.session_id });
      if (passkeyLabel.trim()) {
        query.set("label", passkeyLabel.trim());
      }
      await apiFetch(`/api/v1/me/passkeys/finish-registration?${query.toString()}`, {
        method: "POST",
        body: JSON.stringify(encoded)
      });
      notifications.show({ color: "success", message: "Passkey registered." });
      setStep(2);
    } catch (err) {
      notifications.show({
        color: "danger",
        message: err instanceof Error ? err.message : "Registration failed"
      });
    } finally {
      setPasskeyBusy(false);
    }
  };

  const startTotp = async () => {
    setTotpBusy(true);
    try {
      const response = await beginMFASetup();
      setTotpSetup(response);
      const dataUrl = await QRCode.toDataURL(response.otpauth_url, { margin: 1, width: 220 });
      setTotpQr(dataUrl);
    } catch (err) {
      notifications.show({
        color: "danger",
        message: err instanceof ApiError ? err.message : "Could not start MFA setup."
      });
    } finally {
      setTotpBusy(false);
    }
  };

  const enableTotp = async () => {
    setTotpBusy(true);
    try {
      await enableMFA(totpCode.trim());
      setRecoveryCodes(totpSetup?.recovery_codes || []);
      setTotpCode("");
      notifications.show({ color: "success", message: "Authenticator enabled." });
    } catch (err) {
      notifications.show({
        color: "danger",
        message: err instanceof ApiError ? err.message : "Invalid code."
      });
    } finally {
      setTotpBusy(false);
    }
  };

  const continueAfterCodes = () => {
    if (!savedCodes) {
      notifications.show({ color: "danger", message: "Confirm you saved the recovery codes first." });
      return;
    }
    setStep(2);
  };

  const skip = async () => {
    setSkipping(true);
    try {
      await dismissBootstrap();
      notifications.show({ color: "warning", message: "Continuing without MFA. You will be prompted again next login." });
      onComplete({ dismissed: true });
    } catch (err) {
      notifications.show({
        color: "danger",
        message: err instanceof ApiError ? err.message : "Could not dismiss."
      });
    } finally {
      setSkipping(false);
    }
  };

  const configureDomain = async () => {
    const domain = domainName.trim();
    if (!domain || !dnsToken.trim()) {
      notifications.show({ color: "danger", message: "Enter a domain and DNS API token." });
      return;
    }
    setDomainBusy(true);
    try {
      const configKey = dnsProviderType === "hetzner" ? "dns_api_token" : "api_token";
      const provider = await apiFetch<{ id: number }>("/api/v1/dns-providers", {
        method: "POST",
        body: JSON.stringify({ name: `${dnsProviderType} (setup)`, type: dnsProviderType, config: { [configKey]: dnsToken.trim() } })
      });
      const domainType = domain.split(".").length > 2 ? "subdomain" : "root";
      const created = await apiFetch<{ id: number }>("/api/v1/domains", {
        method: "POST",
        body: JSON.stringify({ name: domain, type: domainType })
      });
      await apiFetch("/api/v1/certificates", {
        method: "POST",
        body: JSON.stringify({
          domain_id: created.id,
          type: "single",
          challenge_type: "dns-01",
          issuer: "letsencrypt_prod",
          dns_provider_id: provider.id,
          primary_domain: domain,
          is_auto_renew: true
        })
      });
      setDomainConfigured(true);
      notifications.show({ color: "success", message: "Domain saved. A certificate is being requested over DNS-01." });
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Could not configure the domain." });
    } finally {
      setDomainBusy(false);
    }
  };

  const totpReady = totpSetup && !recoveryCodes;
  const totpDone = Boolean(recoveryCodes);

  return (
    <Modal
      opened
      onClose={() => undefined}
      withCloseButton={false}
      closeOnClickOutside={false}
      closeOnEscape={false}
      centered
      size="lg"
      title="Finish setting up Portlyn"
    >
      <Stepper active={step} size="sm" mb="lg">
        {needsAccountStep ? <Stepper.Step label="Account" /> : null}
        <Stepper.Step label="Multi-factor" />
        {isAdmin ? <Stepper.Step label="Domain" /> : null}
        <Stepper.Step label="Done" />
      </Stepper>

      {step === 0 && needsAccountStep ? (
        <Stack gap="md">
          <Text c="dimmed" size="sm">
            This account is still on the initial password. Pick a new email and password before you continue.
          </Text>
          <TextInput
            label="Email"
            value={email}
            onChange={(event) => setEmail(event.currentTarget.value)}
            disabled={accountBusy}
          />
          <PasswordInput
            label="New password"
            description="At least 8 characters."
            value={password}
            onChange={(event) => setPassword(event.currentTarget.value)}
            disabled={accountBusy}
          />
          <PasswordInput
            label="Confirm password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.currentTarget.value)}
            disabled={accountBusy}
          />
          <Group justify="flex-end">
            <Button onClick={() => void submitAccount()} loading={accountBusy}>
              Save and continue
            </Button>
          </Group>
        </Stack>
      ) : null}

      {step === 1 ? (
        <Stack gap="md">
          <Text c="dimmed" size="sm">
            Enroll a second factor so passwords alone cannot grant admin access.
          </Text>

          <SegmentedControl
            value={method}
            onChange={(value) => setMethod(value as "passkey" | "totp")}
            data={[
              { label: "Passkey (recommended)", value: "passkey" },
              { label: "Authenticator (TOTP)", value: "totp" }
            ]}
          />

          {method === "passkey" ? (
            <Stack gap="sm">
              <Group gap="xs">
                <IconKey size={18} />
                <Text size="sm">
                  Use Touch ID, Windows Hello, a security key, or your phone. You can register more later.
                </Text>
              </Group>
              <TextInput
                label="Label (optional)"
                placeholder="MacBook Touch ID"
                value={passkeyLabel}
                onChange={(event) => setPasskeyLabel(event.currentTarget.value)}
                disabled={passkeyBusy}
              />
              <Group justify="flex-end">
                <Button onClick={() => void registerPasskey()} loading={passkeyBusy} disabled={passkeyBusy}>
                  Register passkey
                </Button>
              </Group>
            </Stack>
          ) : (
            <Stack gap="sm">
              <Group gap="xs">
                <IconShieldLock size={18} />
                <Text size="sm">
                  Scan the QR code with Authy, 1Password, Google Authenticator, or any TOTP app.
                </Text>
              </Group>
              {totpQr ? <Image src={totpQr} alt="MFA QR code" w={220} h={220} radius="md" /> : null}
              {totpSetup ? (
                <Group gap="xs">
                  <Text size="xs" c="dimmed">Manual key:</Text>
                  <CopyButton value={totpSetup.secret}>
                    {({ copied, copy }) => (
                      <Code style={{ cursor: "pointer" }} onClick={copy}>
                        {copied ? "copied" : totpSetup.secret}
                      </Code>
                    )}
                  </CopyButton>
                </Group>
              ) : null}
              {totpReady ? (
                <Group align="flex-end">
                  <TextInput
                    label="Code"
                    placeholder="123456"
                    value={totpCode}
                    onChange={(event) => setTotpCode(event.currentTarget.value)}
                  />
                  <Button
                    onClick={() => void enableTotp()}
                    loading={totpBusy}
                    disabled={totpCode.trim().length < 6}
                  >
                    Confirm
                  </Button>
                </Group>
              ) : null}
              {totpDone ? (
                <Stack gap="sm">
                  <Alert color="warning" title="Save these recovery codes">
                    <Text size="sm" mb="xs">
                      Each code lets you sign in once if you lose your authenticator. Store them in a password manager
                      now — they will not be shown again.
                    </Text>
                    <Code block>{recoveryCodes!.join("\n")}</Code>
                    <Group mt="xs" gap="xs">
                      <Button
                        component="a"
                        href={recoveryFile}
                        download="portlyn-recovery-codes.txt"
                        variant="light"
                      >
                        Download .txt
                      </Button>
                      <CopyButton value={recoveryCodes!.join("\n")}>
                        {({ copied, copy }) => (
                          <Button variant="light" onClick={copy}>
                            {copied ? "Copied" : "Copy"}
                          </Button>
                        )}
                      </CopyButton>
                    </Group>
                  </Alert>
                  <Checkbox
                    label="I saved my recovery codes somewhere safe"
                    checked={savedCodes}
                    onChange={(event) => setSavedCodes(event.currentTarget.checked)}
                  />
                  <Group justify="flex-end">
                    <Button onClick={continueAfterCodes} disabled={!savedCodes}>
                      Continue
                    </Button>
                  </Group>
                </Stack>
              ) : null}
            </Stack>
          )}

          {user.mfa_required_for_role && !user.must_change_password ? (
            <>
              <Divider />
              <Alert color="danger" variant="light">
                <Text size="sm">
                  This deployment requires multi-factor authentication for admin accounts. Enroll a passkey or
                  authenticator above to continue.
                </Text>
              </Alert>
            </>
          ) : (
            <>
              <Divider />
              <Alert color="warning" variant="light">
                <Text size="sm">
                  Without MFA your account relies on the password alone. You can skip for now, but Portlyn will
                  prompt you again on the next login.
                </Text>
              </Alert>
              <Group justify="flex-end">
                <Button variant="subtle" color="gray" onClick={() => void skip()} loading={skipping}>
                  Skip for now
                </Button>
              </Group>
            </>
          )}
        </Stack>
      ) : null}

      {step === 2 && isAdmin ? (
        <Stack gap="md">
          <Text c="dimmed" size="sm">
            Point Portlyn at your domain and DNS provider so it can obtain a real certificate over DNS-01. You can also
            do this later under Certificates.
          </Text>
          {!domainConfigured ? (
            <>
              <TextInput
                label="Domain"
                placeholder="portlyn.example.com"
                value={domainName}
                onChange={(event) => setDomainName(event.currentTarget.value)}
                disabled={domainBusy}
              />
              <Select
                label="DNS provider"
                data={[
                  { value: "cloudflare", label: "Cloudflare" },
                  { value: "hetzner", label: "Hetzner" },
                  { value: "digitalocean", label: "DigitalOcean" }
                ]}
                value={dnsProviderType}
                onChange={(value) => setDnsProviderType(value || "cloudflare")}
                allowDeselect={false}
                disabled={domainBusy}
              />
              <PasswordInput
                label="DNS API token"
                description="A token with permission to edit DNS records for the zone."
                value={dnsToken}
                onChange={(event) => setDnsToken(event.currentTarget.value)}
                disabled={domainBusy}
              />
              <Group justify="space-between">
                <Button variant="subtle" color="gray" onClick={() => setStep(doneStep)} disabled={domainBusy}>
                  Skip for now
                </Button>
                <Button onClick={() => void configureDomain()} loading={domainBusy} disabled={!domainName.trim() || !dnsToken.trim()}>
                  Save and request certificate
                </Button>
              </Group>
            </>
          ) : (
            <>
              <Alert color="success" variant="light" title="Domain configured">
                <Text size="sm">
                  Portlyn is requesting a certificate for {domainName.trim()} over DNS-01. Once issued, restart Portlyn
                  with <Code>FRONTEND_BASE_URL=https://{domainName.trim()}</Code> to serve the dashboard on your domain.
                </Text>
              </Alert>
              <Group justify="flex-end">
                <Button onClick={() => setStep(doneStep)}>Continue</Button>
              </Group>
            </>
          )}
        </Stack>
      ) : null}

      {step === doneStep ? (
        <Stack gap="md" align="center">
          <IconCheck size={48} color="var(--mantine-color-success-6, #2f9e44)" />
          <Text fw={600}>You are all set</Text>
          <Text c="dimmed" size="sm" ta="center">
            Account configured and a second factor is registered. Use it on your next sign in.
          </Text>
          <Button onClick={() => onComplete()}>Continue to dashboard</Button>
        </Stack>
      ) : null}
    </Modal>
  );
}
