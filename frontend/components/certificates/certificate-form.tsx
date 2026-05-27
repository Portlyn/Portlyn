"use client";

import { Alert, Button, Checkbox, NumberInput, Select, Stack, TagsInput, Text, TextInput } from "@mantine/core";
import { useEffect, useState } from "react";

import type { Certificate, CertificatePayload, DNSProvider, Domain } from "@/lib/types";

const defaults: CertificatePayload = {
  domain_id: 0,
  primary_domain: "",
  type: "single",
  challenge_type: "http-01",
  issuer: "letsencrypt_prod",
  sans: [],
  expires_at: "",
  renewal_window_days: 30,
  is_auto_renew: true,
  dns_provider_id: null
};

export function CertificateForm({
  domains,
  dnsProviders,
  initialValues,
  onSubmit,
  submitLabel,
  isLoading
}: {
  domains: Domain[];
  dnsProviders: DNSProvider[];
  initialValues?: Partial<Certificate>;
  onSubmit: (values: CertificatePayload) => Promise<void>;
  submitLabel: string;
  isLoading?: boolean;
}) {
  const domainLookup = new Map(domains.map((domain) => [domain.id, domain.name]));
  const getInitialState = (): CertificatePayload => ({
    domain_id: initialValues?.domain_id || domains[0]?.id || 0,
    primary_domain: initialValues?.primary_domain || initialValues?.domain?.name || domains[0]?.name || "",
    type: initialValues?.type || defaults.type,
    challenge_type: initialValues?.challenge_type || defaults.challenge_type,
    issuer: initialValues?.issuer || defaults.issuer,
    sans: initialValues?.sans?.map((item) => item.domain_name) || defaults.sans,
    expires_at: initialValues?.expires_at ? initialValues.expires_at.slice(0, 10) : defaults.expires_at,
    renewal_window_days: initialValues?.renewal_window_days ?? defaults.renewal_window_days,
    is_auto_renew: initialValues?.is_auto_renew ?? defaults.is_auto_renew,
    dns_provider_id: initialValues?.dns_provider_id ?? defaults.dns_provider_id
  });
  const [values, setValues] = useState<CertificatePayload>(getInitialState);

  useEffect(() => {
    setValues(getInitialState());
  }, [initialValues, domains]);

  const wildcardNeedsDNS = values.type === "wildcard" || values.primary_domain?.startsWith("*.");
  const providerRequired = values.challenge_type === "dns-01";
  const isInvalid = !values.domain_id || !values.primary_domain || (wildcardNeedsDNS && values.challenge_type !== "dns-01") || (providerRequired && !values.dns_provider_id);

  return (
    <Stack gap="md">
      <Select
        label="Domain"
        data={domains.map((domain) => ({ value: String(domain.id), label: domain.name }))}
        value={String(values.domain_id)}
        onChange={(value) => {
          const nextDomainId = Number(value || 0);
          setValues({
            ...values,
            domain_id: nextDomainId,
            primary_domain: domainLookup.get(nextDomainId) || values.primary_domain
          });
        }}
      />
      <TextInput
        label="Primary domain"
        placeholder="example.com or *.example.com"
        value={values.primary_domain || ""}
        onChange={(event) => setValues({ ...values, primary_domain: event.currentTarget.value })}
      />
      <Select
        label="Certificate type"
        data={[
          { value: "single", label: "single" },
          { value: "wildcard", label: "wildcard" },
          { value: "multi_san", label: "multi SAN" }
        ]}
        value={values.type}
        onChange={(value) => {
          const nextType = (value || "single") as CertificatePayload["type"];
          setValues({
            ...values,
            type: nextType,
            challenge_type: nextType === "wildcard" ? "dns-01" : values.challenge_type
          });
        }}
      />
      <TagsInput
        label="Additional SANs"
        placeholder="api.example.com"
        value={values.sans}
        onChange={(next) => setValues({ ...values, sans: next })}
      />
      <Select
        label="Challenge type"
        data={[
          { value: "http-01", label: "HTTP-01" },
          { value: "dns-01", label: "DNS-01" }
        ]}
        value={values.challenge_type}
        onChange={(value) => setValues({ ...values, challenge_type: (value || "http-01") as CertificatePayload["challenge_type"] })}
      />
      <Select
        label="Issuer"
        data={[
          { value: "letsencrypt_prod", label: "Let's Encrypt Production" },
          { value: "letsencrypt_staging", label: "Let's Encrypt Staging" }
        ]}
        value={values.issuer}
        onChange={(value) => setValues({ ...values, issuer: (value || "letsencrypt_prod") as CertificatePayload["issuer"] })}
      />
      <Select
        label="DNS provider"
        placeholder={providerRequired ? "Required for DNS-01" : "Only needed for DNS-01"}
        data={dnsProviders.map((provider) => ({ value: String(provider.id), label: `${provider.name} (${provider.type})` }))}
        value={values.dns_provider_id ? String(values.dns_provider_id) : null}
        onChange={(value) => setValues({ ...values, dns_provider_id: value ? Number(value) : null })}
        disabled={!providerRequired}
      />
      <NumberInput
        label="Renewal window (days)"
        min={7}
        max={90}
        value={values.renewal_window_days}
        onChange={(value) => setValues({ ...values, renewal_window_days: Number(value) || 30 })}
      />
      <TextInput label="Expected expiry override" type="date" value={values.expires_at || ""} onChange={(event) => setValues({ ...values, expires_at: event.currentTarget.value })} />
      <Checkbox checked={values.is_auto_renew} onChange={(event) => setValues({ ...values, is_auto_renew: event.currentTarget.checked })} label="Auto renew" />
      {wildcardNeedsDNS ? (
        <Alert color={values.challenge_type === "dns-01" ? "brand" : "warning"} variant="light" title="Wildcard validation">
          Wildcard certificates require DNS-01.
        </Alert>
      ) : null}
      {providerRequired && !values.dns_provider_id ? (
        <Alert color="warning" variant="light" title="DNS provider required">
          DNS-01 requires a configured DNS provider.
        </Alert>
      ) : null}
      {values.issuer === "letsencrypt_staging" ? (
        <Text size="sm" c="dimmed">
          Staging avoids rate limits but is not browser-trusted.
        </Text>
      ) : null}
      <Button loading={isLoading} onClick={() => void onSubmit(values)} disabled={isInvalid}>
        {submitLabel}
      </Button>
    </Stack>
  );
}
