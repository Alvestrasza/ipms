/**
 * File Name: playwright.security.config.ts
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Run Security baseline browser acceptance against an isolated loopback fixture.
 */
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  testMatch: [
    "security-baselines.spec.ts",
    "domain-security.spec.ts",
    "job-logs.spec.ts",
  ],
  timeout: 60_000,
  workers: 1,
  retries: 0,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:3116",
    browserName: "chromium",
    headless: true,
    launchOptions: { executablePath: process.env.IPMS_TEST_BROWSER_EXECUTABLE },
    timezoneId: "Europe/Berlin",
  },
});
