"use client";

import { Alert, Badge, Button, Card, Divider, Drawer, Group, Modal, Paper, Select, Skeleton, Stack, Text, Textarea, TextInput } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useDisclosure } from "@mantine/hooks";
import { useEffect, useMemo, useState } from "react";

import { CertificateForm } from "@/components/certificates/certificate-form";
import { CertificateTable } from "@/components/certificates/certificate-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { useAuth } from "@/components/providers";
import { apiFetch, ApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { Certificate, CertificatePayload, DNSProvider, Domain } from "@/lib/types";

export default function CertificatesPage() {
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [dnsProviders, setDNSProviders] = useState<DNSProvider[]>([]);
  const [statusFilter, setStatusFilter] = useState("");
  const [query, setQuery] = useState("");
  const [selectedCertificate, setSelectedCertificate] = useState<Certificate | null>(null);
  const [inspectedCertificate, setInspectedCertificate] = useState<Certificate | null>(null);
  const [certificateToDelete, setCertificateToDelete] = useState<Certificate | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [isOperating, setIsOperating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [opened, { open, close }] = useDisclosure(false);
  const [importTarget, setImportTarget] = useState<Certificate | null>(null);
  const [importCertPem, setImportCertPem] = useState("");
  const [importKeyPem, setImportKeyPem] = useState("");
  const [isImporting, setIsImporting] = useState(false);
  const { user } = useAuth();
  const canManage = user?.role === "admin";
  const certificateSans: NonNullable<Certificate["sans"]> = inspectedCertificate?.sans || [];

  const filteredCertificates = useMemo(
    () =>
      certificates.filter((certificate) => {
        const matchesStatus = !statusFilter || certificate.status === statusFilter;
        const matchesQuery =
          !query ||
          [certificate.primary_domain || "", certificate.domain?.name || "", certificate.type, certificate.status, certificate.last_error, certificate.issuer].some((value) =>
            value.toLowerCase().includes(query.toLowerCase())
          );
        return matchesStatus && matchesQuery;
      }),
    [certificates, query, statusFilter]
  );

  const loadData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [certificateItems, domainItems, providerItems] = await Promise.all([
        apiFetch<Certificate[]>("/api/v1/certificates"),
        apiFetch<Domain[]>("/api/v1/domains"),
        apiFetch<DNSProvider[]>("/api/v1/dns-providers")
      ]);
      setCertificates(certificateItems);
      setDomains(domainItems);
      setDNSProviders(providerItems);
      setInspectedCertificate((current) => certificateItems.find((item) => item.id === current?.id) || certificateItems[0] || null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load certificates.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const handleSubmit = async (values: CertificatePayload) => {
    setIsSaving(true);
    try {
      const payload = {
        ...values,
        expires_at: values.expires_at ? new Date(values.expires_at).toISOString() : undefined
      };
      if (selectedCertificate) {
        await apiFetch<Certificate>(`/api/v1/certificates/${selectedCertificate.id}`, { method: "PATCH", body: JSON.stringify(payload) });
        notifications.show({ color: "success", message: "Certificate updated" });
      } else {
        await apiFetch<Certificate>("/api/v1/certificates", { method: "POST", body: JSON.stringify(payload) });
        notifications.show({ color: "success", message: "Certificate created" });
      }
      close();
      await loadData();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to save certificate." });
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!certificateToDelete) return;
    setIsDeleting(true);
    try {
      await apiFetch<void>(`/api/v1/certificates/${certificateToDelete.id}`, { method: "DELETE" });
      notifications.show({ color: "success", message: "Certificate deleted" });
      setCertificateToDelete(null);
      await loadData();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to delete certificate." });
    } finally {
      setIsDeleting(false);
    }
  };

  const submitImport = async () => {
    if (!importTarget) return;
    setIsImporting(true);
    try {
      await apiFetch<Certificate>(`/api/v1/certificates/${importTarget.id}/import-pem`, {
        method: "POST",
        body: JSON.stringify({ certificate_pem: importCertPem, private_key_pem: importKeyPem })
      });
      notifications.show({ color: "success", message: "Certificate imported" });
      setImportTarget(null);
      setImportCertPem("");
      setImportKeyPem("");
      await loadData();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Import failed." });
    } finally {
      setIsImporting(false);
    }
  };

  const runOperation = async (certificate: Certificate, action: "retry" | "renew" | "sync-status") => {
    setIsOperating(true);
    try {
      await apiFetch<Certificate>(`/api/v1/certificates/${certificate.id}/${action}`, { method: "POST" });
      notifications.show({ color: "success", message: `Certificate ${action.replace("-", " ")} completed` });
      await loadData();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : `Unable to ${action} certificate.` });
    } finally {
      setIsOperating(false);
    }
  };

  const expiringSoon = certificates.filter((item) => {
    const expiresAt = new Date(item.expires_at).getTime();
    return Number.isFinite(expiresAt) && expiresAt < Date.now() + 14 * 24 * 60 * 60 * 1000;
  });
  const failedCertificates = certificates.filter((item) => item.status === "failed");
  return (
    <Stack gap="lg">
      {canManage ? (
        <Group justify="flex-end">
          <Button onClick={() => { setSelectedCertificate(null); open(); }} disabled={domains.length === 0}>
            New Certificate
          </Button>
        </Group>
      ) : null}

      <Group grow>
        <TextInput placeholder="Filter certificates" value={query} onChange={(event) => setQuery(event.currentTarget.value)} />
        <Select
          data={[
            { value: "", label: "All statuses" },
            { value: "pending", label: "pending" },
            { value: "issued", label: "issued" },
            { value: "failed", label: "failed" },
            { value: "expiring_soon", label: "expiring soon" },
            { value: "renewing", label: "renewing" }
          ]}
          value={statusFilter}
          onChange={(value) => setStatusFilter(value || "")}
        />
      </Group>

      {failedCertificates.length > 0 || expiringSoon.length > 0 ? (
        <Alert color="warning" variant="light" title="Certificate attention needed">
          {failedCertificates.length} failed, {expiringSoon.length} expiring within 14 days.
        </Alert>
      ) : null}

      {error ? <ErrorState title="Failed to load certificates" message={error} onRetry={() => void loadData()} /> : null}

      {isLoading ? (
        <Stack gap="sm"><Skeleton height={54} /><Skeleton height={54} /></Stack>
      ) : filteredCertificates.length === 0 ? (
        <EmptyState title={certificates.length === 0 ? "No certificates configured" : "No matching certificates"} description={certificates.length === 0 ? "Create a certificate." : "Adjust the filters."} />
      ) : (
        <Paper withBorder radius="md" p="sm">
          <CertificateTable
            certificates={filteredCertificates}
            canManage={canManage}
            onInspect={setInspectedCertificate}
            onEdit={(certificate) => { setSelectedCertificate(certificate); open(); }}
            onDelete={setCertificateToDelete}
            onRetry={(certificate) => void runOperation(certificate, "retry")}
            onRenew={(certificate) => void runOperation(certificate, "renew")}
            onSync={(certificate) => void runOperation(certificate, "sync-status")}
            onImport={(certificate) => { setImportTarget(certificate); setImportCertPem(""); setImportKeyPem(""); }}
          />
        </Paper>
      )}

      {inspectedCertificate ? (
        <Card withBorder radius="md">
          <Stack gap="sm">
            <Group justify="space-between" align="flex-start">
              <div>
                <Text fw={700} fz="lg">{inspectedCertificate.primary_domain}</Text>
                <Text size="sm" c="dimmed">{inspectedCertificate.domain?.name || `Domain #${inspectedCertificate.domain_id}`}</Text>
              </div>
              <Badge color={inspectedCertificate.issuer === "letsencrypt_staging" ? "warning" : "brand"}>
                {inspectedCertificate.issuer === "letsencrypt_staging" ? "Let's Encrypt Staging" : "Let's Encrypt Production"}
              </Badge>
            </Group>
            <Divider />
            <Group grow align="flex-start">
              <Stack gap={2}>
                <Text size="xs" tt="uppercase" c="dimmed">Type</Text>
                <Text>{inspectedCertificate.type}</Text>
              </Stack>
              <Stack gap={2}>
                <Text size="xs" tt="uppercase" c="dimmed">Challenge</Text>
                <Text>{inspectedCertificate.challenge_type}</Text>
              </Stack>
              <Stack gap={2}>
                <Text size="xs" tt="uppercase" c="dimmed">Status</Text>
                <Text>{inspectedCertificate.status}</Text>
              </Stack>
              <Stack gap={2}>
                <Text size="xs" tt="uppercase" c="dimmed">DNS Provider</Text>
                <Text>{inspectedCertificate.dns_provider?.name || "-"}</Text>
              </Stack>
            </Group>
            <Group grow align="flex-start">
              <Stack gap={2}>
                <Text size="xs" tt="uppercase" c="dimmed">Issued</Text>
                <Text>{formatDateTime(inspectedCertificate.issued_at)}</Text>
              </Stack>
              <Stack gap={2}>
                <Text size="xs" tt="uppercase" c="dimmed">Last Checked</Text>
                <Text>{formatDateTime(inspectedCertificate.last_checked_at)}</Text>
              </Stack>
              <Stack gap={2}>
                <Text size="xs" tt="uppercase" c="dimmed">Expires</Text>
                <Text>{formatDateTime(inspectedCertificate.expires_at)}</Text>
              </Stack>
              <Stack gap={2}>
                <Text size="xs" tt="uppercase" c="dimmed">Next Renewal</Text>
                <Text>{formatDateTime(inspectedCertificate.next_renewal_at)}</Text>
              </Stack>
            </Group>
            <Stack gap={4}>
              <Text size="xs" tt="uppercase" c="dimmed">SANs</Text>
              {certificateSans.length > 0 ? (
                <Group gap="xs">
                  {certificateSans.map((item) => (
                    <Badge key={item.domain_name} color="gray">{item.domain_name}</Badge>
                  ))}
                </Group>
              ) : (
                <Text size="sm" c="dimmed">No additional SANs configured.</Text>
              )}
            </Stack>
            <Stack gap={4}>
              <Text size="xs" tt="uppercase" c="dimmed">Operational State</Text>
              <Text size="sm">Auto renew: {inspectedCertificate.is_auto_renew ? "enabled" : "disabled"} | Renewal window: {inspectedCertificate.renewal_window_days} days</Text>
              <Text size="sm" c={inspectedCertificate.last_error ? "red.3" : "dimmed"}>
                {inspectedCertificate.last_error || "No recent certificate error."}
              </Text>
            </Stack>
          </Stack>
        </Card>
      ) : null}

      <Drawer opened={opened} onClose={close} title={selectedCertificate ? "Edit certificate" : "Create certificate"} position="right">
        <CertificateForm
          domains={domains}
          dnsProviders={dnsProviders}
          initialValues={selectedCertificate || undefined}
          onSubmit={handleSubmit}
          submitLabel={selectedCertificate ? "Save Changes" : "Create Certificate"}
          isLoading={isSaving}
        />
      </Drawer>

      <ConfirmDialog isOpen={Boolean(certificateToDelete)} onClose={() => setCertificateToDelete(null)} onConfirm={handleDelete} title="Delete certificate?" description={`This removes the certificate record for ${certificateToDelete?.primary_domain || certificateToDelete?.domain?.name || "the selected domain"}.`} isLoading={isDeleting || isOperating} />

      <Modal opened={Boolean(importTarget)} onClose={() => setImportTarget(null)} title={`Import PEM — ${importTarget?.primary_domain || ""}`} size="lg">
        <Stack gap="md">
          <Text size="sm" c="dimmed">
            Paste a full-chain certificate and its private key in PEM format. This replaces the stored certificate material for this record and skips ACME.
          </Text>
          <Textarea label="Certificate PEM (full chain)" autosize minRows={6} maxRows={12} value={importCertPem} onChange={(e) => setImportCertPem(e.currentTarget.value)} placeholder="-----BEGIN CERTIFICATE-----" />
          <Textarea label="Private key PEM" autosize minRows={4} maxRows={10} value={importKeyPem} onChange={(e) => setImportKeyPem(e.currentTarget.value)} placeholder="-----BEGIN PRIVATE KEY-----" />
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setImportTarget(null)}>Cancel</Button>
            <Button onClick={() => void submitImport()} loading={isImporting} disabled={!importCertPem.trim() || !importKeyPem.trim()}>
              Import
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}
