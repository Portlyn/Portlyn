"use client";

import { Button, Checkbox, Select, Stack, TextInput, Textarea } from "@mantine/core";
import { useEffect, useState } from "react";

import { linesToList, listToLines } from "@/lib/access-control";
import type { Domain, DomainPayload } from "@/lib/types";

const defaults: DomainPayload = {
  name: "",
  type: "root",
  provider: "",
  notes: "",
  ip_allowlist: [],
  ip_blocklist: []
};

export function DomainForm({
  initialValues,
  onSubmit,
  submitLabel,
  isLoading
}: {
  initialValues?: Partial<Domain>;
  onSubmit: (values: DomainPayload) => Promise<void>;
  submitLabel: string;
  isLoading?: boolean;
}) {
  const [values, setValues] = useState<DomainPayload>(defaults);
  const [allowlistText, setAllowlistText] = useState("");
  const [blocklistText, setBlocklistText] = useState("");
  const [autoCertificate, setAutoCertificate] = useState(true);
  const isNew = !initialValues?.id;
  const nameError = values.name.includes("*")
    ? "Wildcard hostnames are not supported. Add the base domain and create a wildcard certificate for it."
    : null;

  useEffect(() => {
    const next = {
      name: initialValues?.name || defaults.name,
      type: (initialValues?.type as DomainPayload["type"]) || defaults.type,
      provider: initialValues?.provider || defaults.provider,
      notes: initialValues?.notes || defaults.notes,
      ip_allowlist: [...(initialValues?.ip_allowlist || [])],
      ip_blocklist: [...(initialValues?.ip_blocklist || [])]
    };
    setValues(next);
    setAllowlistText(listToLines(next.ip_allowlist));
    setBlocklistText(listToLines(next.ip_blocklist));
  }, [initialValues]);

  return (
    <Stack gap="md">
      <TextInput
        label="Hostname"
        value={values.name}
        error={nameError}
        onChange={(event) => setValues({ ...values, name: event.currentTarget.value })}
      />
      <Select
        label="Type"
        data={[
          { value: "root", label: "root" },
          { value: "subdomain", label: "subdomain" }
        ]}
        value={values.type}
        onChange={(value) => setValues({ ...values, type: (value || "root") as DomainPayload["type"] })}
      />
      <TextInput label="Provider" value={values.provider} onChange={(event) => setValues({ ...values, provider: event.currentTarget.value })} />
      <Textarea label="Notes" value={values.notes} onChange={(event) => setValues({ ...values, notes: event.currentTarget.value })} minRows={4} />
      <Textarea
        label="IP allowlist"
        description="Optional domain-wide allowlist enforced before auth."
        value={allowlistText}
        onChange={(event) => setAllowlistText(event.currentTarget.value)}
        minRows={4}
      />
      <Textarea
        label="IP blocklist"
        description="Optional domain-wide deny list."
        value={blocklistText}
        onChange={(event) => setBlocklistText(event.currentTarget.value)}
        minRows={4}
      />
      {isNew ? (
        <Checkbox
          label="Request a certificate"
          description="Needs exactly one active DNS provider. Skipped when an existing certificate already covers this hostname."
          checked={autoCertificate}
          onChange={(event) => setAutoCertificate(event.currentTarget.checked)}
        />
      ) : null}
      <Button
        loading={isLoading}
        onClick={() =>
          void onSubmit({
            ...values,
            ip_allowlist: linesToList(allowlistText),
            ip_blocklist: linesToList(blocklistText),
            ...(isNew ? { auto_certificate: autoCertificate } : {})
          })
        }
        disabled={!values.name || Boolean(nameError)}
      >
        {submitLabel}
      </Button>
    </Stack>
  );
}
