"use client";

import { Pill, TagsInput } from "@mantine/core";
import { useState } from "react";

import type { TagParseResult } from "@/lib/access-rules";

const SPLIT_CHARS = [",", " ", ";", "\n"];

export function RuleTagsInput({
  label,
  description,
  emptyPlaceholder,
  value,
  onChange,
  parse,
  isNegative
}: {
  label: string;
  description: string;
  emptyPlaceholder: string;
  value: string[];
  onChange: (next: string[]) => void;
  parse: (raw: string) => TagParseResult;
  isNegative?: (tag: string) => boolean;
}) {
  const [search, setSearch] = useState("");
  const [error, setError] = useState<string | null>(null);

  const handleChange = (tags: string[]) => {
    const kept = tags.filter((tag) => value.includes(tag));
    const next = [...kept];
    let rejected: string | null = null;
    let message: string | null = null;
    for (const tag of tags.filter((item) => !value.includes(item))) {
      const result = parse(tag);
      if ("error" in result) {
        rejected = tag.trim();
        message = result.error;
        continue;
      }
      if (!next.includes(result.value)) {
        next.push(result.value);
      }
    }
    onChange(next);
    setError(message);
    if (rejected) {
      const text = rejected;
      setSearch(text);
      window.setTimeout(() => setSearch(text), 0);
    }
  };

  const handleSearchChange = (next: string) => {
    setSearch(next);
    if (error) {
      setError(null);
    }
  };

  return (
    <TagsInput
      label={label}
      description={description}
      placeholder={value.length === 0 ? emptyPlaceholder : undefined}
      value={value}
      onChange={handleChange}
      searchValue={search}
      onSearchChange={handleSearchChange}
      splitChars={SPLIT_CHARS}
      acceptValueOnBlur
      clearable
      error={error}
      renderPill={({ value: tag, onRemove }) => {
        const negative = tag ? isNegative?.(tag) : false;
        return (
          <Pill
            withRemoveButton
            onRemove={onRemove}
            ff="monospace"
            style={
              negative
                ? { background: "var(--mantine-color-danger-light)", color: "var(--mantine-color-danger-light-color)" }
                : undefined
            }
          >
            {tag}
          </Pill>
        );
      }}
    />
  );
}
