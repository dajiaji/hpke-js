import { expect, test } from "@playwright/test";

const RESULT_TIMEOUT_MS = 15000;

test("basic test", async ({ page }) => {
  await page.goto("./index.html");
  await page.click("text=run");
  await expect(page.locator("#pass")).toHaveText("6", {
    timeout: RESULT_TIMEOUT_MS,
  });
  await expect(page.locator("#fail")).toHaveText("0", {
    timeout: RESULT_TIMEOUT_MS,
  });
});
