"use client";

import { Button, Group, Paper, Select, Skeleton, Stack, Text, TextInput } from "@mantine/core";
import { useEffect, useState } from "react";

import { AdminOnly } from "@/components/admin-only";
import { AuditLogTable } from "@/components/audit/audit-log-table";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { apiFetch, ApiError } from "@/lib/api";
import type { AuditLogListResponse } from "@/lib/types";

const PAGE_SIZE = 50;

export default function AuditLogsPage() {
  const [data, setData] = useState<AuditLogListResponse | null>(null);
  const [userId, setUserId] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [actionLike, setActionLike] = useState("");
  const [method, setMethod] = useState("");
  const [host, setHost] = useState("");
  const [statusCode, setStatusCode] = useState("");
  const [offset, setOffset] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async (nextOffset = offset) => {
    setIsLoading(true);
    setError(null);
    const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(nextOffset) });
    if (userId) params.set("user_id", userId);
    if (resourceType) params.set("resource_type", resourceType);
    if (actionLike) params.set("action_like", actionLike);
    if (method) params.set("method", method);
    if (host) params.set("host", host);
    if (statusCode) params.set("status_code", statusCode);
    if (fromDate) params.set("from", String(Math.floor(new Date(fromDate).getTime() / 1000)));
    if (toDate) params.set("to", String(Math.floor(new Date(toDate).getTime() / 1000)));

    try {
      const response = await apiFetch<AuditLogListResponse>(`/api/v1/audit-logs?${params.toString()}`);
      setData(response);
      setOffset(nextOffset);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to load audit logs.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void loadData(0);
  }, []);

  const applyFilters = () => void loadData(0);

  const total = data?.total ?? 0;
  const shown = data?.items.length ?? 0;
  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd = offset + shown;
  const hasPrev = offset > 0;
  const hasNext = offset + PAGE_SIZE < total;

  return (
    <AdminOnly>
      <Stack gap="lg">
        <Group grow>
          <TextInput placeholder="User ID" value={userId} onChange={(event) => setUserId(event.currentTarget.value)} />
          <Select
            data={[
              { value: "", label: "All resources" },
              { value: "service", label: "service" },
              { value: "domain", label: "domain" },
              { value: "node", label: "node" },
              { value: "certificate", label: "certificate" },
              { value: "user", label: "user" },
              { value: "auth", label: "auth" },
              { value: "audit_webhook", label: "audit_webhook" },
              { value: "proxy_request", label: "proxy_request" }
            ]}
            value={resourceType}
            onChange={(value) => setResourceType(value || "")}
          />
          <TextInput type="date" value={fromDate} onChange={(event) => setFromDate(event.currentTarget.value)} />
          <TextInput type="date" value={toDate} onChange={(event) => setToDate(event.currentTarget.value)} />
        </Group>

        <Group grow>
          <TextInput placeholder="Action contains (e.g. login)" value={actionLike} onChange={(event) => setActionLike(event.currentTarget.value)} />
          <Select
            placeholder="Method"
            data={["", "GET", "POST", "PATCH", "DELETE", "PUT"].map((m) => ({ value: m, label: m || "Any method" }))}
            value={method}
            onChange={(value) => setMethod(value || "")}
          />
          <TextInput placeholder="Host" value={host} onChange={(event) => setHost(event.currentTarget.value)} />
          <TextInput placeholder="Status code" value={statusCode} onChange={(event) => setStatusCode(event.currentTarget.value)} />
        </Group>

        <Group justify="flex-end">
          <Button variant="default" onClick={applyFilters}>Apply Filters</Button>
        </Group>

        {error ? <ErrorState title="Failed to load audit logs" message={error} onRetry={() => void loadData()} /> : null}

        {isLoading ? (
          <Stack gap="sm"><Skeleton height={54} /><Skeleton height={54} /></Stack>
        ) : !data || data.items.length === 0 ? (
          <EmptyState title="No audit events found" description="Adjust the filters." />
        ) : (
          <Paper withBorder radius="md" p="sm">
            <Stack gap="sm">
              <Group justify="space-between">
                <Text c="dimmed" size="sm">Showing {pageStart}–{pageEnd} of {total}</Text>
                <Group gap="xs">
                  <Button size="xs" variant="default" disabled={!hasPrev} onClick={() => void loadData(Math.max(0, offset - PAGE_SIZE))}>
                    Previous
                  </Button>
                  <Button size="xs" variant="default" disabled={!hasNext} onClick={() => void loadData(offset + PAGE_SIZE)}>
                    Next
                  </Button>
                </Group>
              </Group>
              <AuditLogTable items={data.items} />
            </Stack>
          </Paper>
        )}
      </Stack>
    </AdminOnly>
  );
}
