// Vitest setup file.
//
// Registers jest-dom matchers (toBeInTheDocument, toHaveTextContent, ...)
// onto Vitest's expect, and pins a sane afterEach that unmounts any
// React tree React Testing Library left behind so tests don't bleed
// state between cases.

import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(() => {
  cleanup();
});
