import "@testing-library/jest-dom/vitest";
import React from "react";
import { vi } from "vitest";

vi.mock("@monaco-editor/react", () => ({
  default: ({
    value,
    onChange,
  }: {
    value: string;
    onChange?: (value: string) => void;
  }) =>
    React.createElement("textarea", {
      "aria-label": "code editor",
      "data-testid": "code-editor",
      onChange: (event: { target: { value: string } }) => onChange?.(event.target.value),
      value,
    }),
}));
