import type { Page } from "@playwright/test";
import { expect, test } from "@playwright/test";

const RESULT_TIMEOUT_MS = 15000;

async function runAndExpect(
  page: Page,
  expectedPass: string,
  expectedFail: string,
) {
  await page.click("text=run");
  await expect(page.locator("#pass")).toHaveText(expectedPass, {
    timeout: RESULT_TIMEOUT_MS,
  });
  await expect(page.locator("#fail")).toHaveText(expectedFail, {
    timeout: RESULT_TIMEOUT_MS,
  });
}

test("standard curves test with generateKeyPair", async ({ page }) => {
  await page.goto("./index.html");
  await runAndExpect(page, "18", "0");
});

test("standard curves test with deriveKeyPair", async ({ page }) => {
  await page.goto("./standardCurvesWithDeriveKeyPair.html");
  await runAndExpect(page, "18", "0");
});

test("secure curves test with generateKeyPair", async ({ page }) => {
  await page.goto("./secureCurves.html");
  await runAndExpect(page, "6", "0");
});

test("secure curves test with deriveKeyPair", async ({ page }) => {
  await page.goto("./secureCurvesWithDeriveKeyPair.html");
  await runAndExpect(page, "6", "0");
});
