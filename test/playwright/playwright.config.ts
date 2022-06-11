// playwright.config.ts
import { devices, PlaywrightTestConfig } from "@playwright/test";

const config: PlaywrightTestConfig = {
  projects: [
    // {
    //   name: 'chrome',
    //   use: { channel: 'chrome' },
    // },
    // {
    //   name: 'edge',
    //   use: { channel: 'msedge' },
    // },
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
