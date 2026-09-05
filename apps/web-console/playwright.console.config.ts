import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  testMatch: [
    "hyperv-console.spec.ts",
    "hyperv-native-console.spec.ts",
    "service-accounts.spec.ts",
  ],
  timeout: 60_000,
  workers: 1,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:3107",
    browserName: "chromium",
    headless: true,
  },
});
