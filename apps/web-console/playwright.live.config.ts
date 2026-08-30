import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.IPMS_LIVE_BASE_URL;

if (!baseURL) {
  throw new Error("IPMS_LIVE_BASE_URL is required for live smoke tests.");
}

export default defineConfig({
  testDir: "./tests-live",
  fullyParallel: false,
  reporter: "list",
  use: {
    baseURL,
    ignoreHTTPSErrors: process.env.IPMS_ALLOW_UNTRUSTED_CERTIFICATE === "1",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "edge",
      use: { ...devices["Desktop Chrome"], channel: "msedge" },
    },
  ],
});
