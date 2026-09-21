/**
 * File Name: playwright.hgs.config.ts
 * Version: v0.1.0 | Created: 2026-09-19 | Modified: 2026-09-19
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Exercise the HGS UI against isolated local fixtures, not live infrastructure.
 */
import { defineConfig } from "@playwright/test";

// Start hgs-portal-server.mjs on 3329 and the built Portal on 3328 with
// IPMS_CONTROL_PLANE_URL=http://127.0.0.1:3329 before running this isolated suite.
// Explicit server ownership avoids Windows process-tree teardown hangs.
export default defineConfig({
  testDir: "./tests",
  testMatch: "hgs-workspace.spec.ts",
  timeout: 45_000,
  workers: 1,
  retries: 0,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:3328",
    browserName: "chromium",
    headless: true,
    launchOptions: { executablePath: process.env.IPMS_TEST_BROWSER_EXECUTABLE },
  },
});
