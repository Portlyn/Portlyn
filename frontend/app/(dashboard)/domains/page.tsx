"use client";

import { Button, Drawer, Group, Paper, Skeleton, Stack, TextInput } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useDisclosure } from "@mantine/hooks";
import { useEffect, useState } from "react";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { DomainForm } from "@/components/domains/domain-form";
import { DomainTable } from "@/components/domains/domain-table";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { PageHeader } from "@/components/layout/page-header";
import { useAuth } from "@/components/providers";
import { apiFetch, ApiError } from "@/lib/api";
import type { Domain, DomainPayload } from "@/lib/types";

export default function DomainsPage() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [query, setQuery] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedDomain, setSelectedDomain] = useState<Domain | null>(null);
  const [domainToDelete, setDomainToDelete] = useState<Domain | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [opened, { open, close }] = useDisclosure(false);
  const { user } = useAuth();
  const canManage = user?.role === "admin";

  const filteredDomains = domains.filter((domain) =>
    [domain.name, domain.type, domain.provider, domain.notes].some((value) =>
      value.toLowerCase().includes(query.toLowerCase())
    )
  );

  const loadDomains = async () => {
    setIsLoading(true);
    setError(null);
    try {
      setDomains(await apiFetch<Domain[]>("/api/v1/domains"));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load domains.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void loadDomains();
  }, []);

  const handleSubmit = async (values: DomainPayload) => {
    setIsSaving(true);
    try {
      if (selectedDomain) {
        await apiFetch<Domain>(`/api/v1/domains/${selectedDomain.id}`, {
          method: "PATCH",
          body: JSON.stringify(values)
        });
        notifications.show({ color: "success", message: "Domain updated" });
      } else {
        await apiFetch<Domain>("/api/v1/domains", {
          method: "POST",
          body: JSON.stringify(values)
        });
        notifications.show({ color: "success", message: "Domain created" });
      }
      close();
      await loadDomains();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to save domain." });
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!domainToDelete) return;
    setIsDeleting(true);
    try {
      await apiFetch<void>(`/api/v1/domains/${domainToDelete.id}`, { method: "DELETE" });
      notifications.show({ color: "success", message: "Domain deleted" });
      setDomainToDelete(null);
      await loadDomains();
    } catch (err) {
      notifications.show({ color: "danger", message: err instanceof ApiError ? err.message : "Unable to delete domain." });
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <Stack gap="lg">
      <PageHeader
        action={canManage ? <Button onClick={() => { setSelectedDomain(null); open(); }}>New Domain</Button> : undefined}
      >
        <TextInput placeholder="Search domains" value={query} onChange={(event) => setQuery(event.currentTarget.value)} />
      </PageHeader>

      {error ? <ErrorState title="Failed to load domains" message={error} onRetry={() => void loadDomains()} /> : null}

      {isLoading ? (
        <Stack gap="sm"><Skeleton height={54} /><Skeleton height={54} /></Stack>
      ) : filteredDomains.length === 0 ? (
        <EmptyState title={domains.length === 0 ? "No domains configured" : "No matching domains"} description={domains.length === 0 ? "Create a domain." : "Adjust the filter."} />
      ) : (
        <Paper withBorder radius="md" p="sm">
          <DomainTable domains={filteredDomains} canManage={canManage} onEdit={(domain) => { setSelectedDomain(domain); open(); }} onDelete={setDomainToDelete} />
        </Paper>
      )}

      <Drawer opened={opened} onClose={close} title={selectedDomain ? "Edit domain" : "Create domain"} position="right">
        <DomainForm initialValues={selectedDomain || undefined} onSubmit={handleSubmit} submitLabel={selectedDomain ? "Save Changes" : "Create Domain"} isLoading={isSaving} />
      </Drawer>

      <ConfirmDialog isOpen={Boolean(domainToDelete)} onClose={() => setDomainToDelete(null)} onConfirm={handleDelete} title="Delete domain?" description={`This removes ${domainToDelete?.name || "this domain"}.`} isLoading={isDeleting} />
    </Stack>
  );
}
