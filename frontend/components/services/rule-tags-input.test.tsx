import { MantineProvider } from "@mantine/core";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { parseSource } from "@/lib/access-rules";
import { RuleTagsInput } from "./rule-tags-input";

function Harness() {
  const [value, setValue] = useState<string[]>([]);
  return (
    <MantineProvider>
      <RuleTagsInput label="Source IPs" description="" emptyPlaceholder="Any IP" value={value} onChange={setValue} parse={parseSource} />
      <output data-testid="value">{value.join("|")}</output>
    </MantineProvider>
  );
}

async function submit(input: HTMLElement, text: string) {
  input.focus();
  fireEvent.change(input, { target: { value: text } });
  fireEvent.keyDown(input, { key: "Enter" });
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 5));
  });
}

describe("RuleTagsInput", () => {
  beforeEach(() => {
    window.matchMedia = vi.fn().mockReturnValue({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() });
    window.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  });

  it("keeps an invalid entry in the field and drops it once corrected", async () => {
    render(<Harness />);
    const input = screen.getByRole("combobox", { name: "Source IPs" });

    await submit(input, "8.8.8");
    expect(screen.getByTestId("value").textContent).toBe("");
    expect(input).toHaveValue("8.8.8");
    expect(screen.getByText("8.8.8 is not a valid IP address or CIDR range")).toBeInTheDocument();

    await submit(input, "8.8.8.4");
    expect(screen.getByTestId("value").textContent).toBe("8.8.8.4");
    expect(input).toHaveValue("");
    expect(screen.queryByText(/is not a valid IP/)).not.toBeInTheDocument();

    await submit(input, "!10.0.0.0/8");
    expect(screen.getByTestId("value").textContent).toBe("8.8.8.4|!10.0.0.0/8");
    expect(input).toHaveValue("");
  });
});
