// playwright.config.ts
import { devices } from "@playwright/test";
import type { PlaywrightTestConfig } from "@playwright/test";

const config: PlaywrightTestConfig = {
  use: {
    baseURL: "http://localhost:3000",
  },
  webServer: {
    command: "npx http-server ./pages -p 3000 -c-1",
    url: "http://localhost:3000",
    // deno-lint-ignore no-process-global
    reuseExistingServer: !process.env.CI,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
    },
  ],
};
export default config;
