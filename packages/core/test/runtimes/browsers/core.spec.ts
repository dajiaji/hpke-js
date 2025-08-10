import { expect, test } from "@playwright/test";

test("standard curves test with generateKeyPair", async ({ page }) => {
  await page.goto("./index.html");
  await page.click("text=run");
  await page.waitForTimeout(5000);
  await expect(page.locator("id=pass")).toHaveText("18");
  await expect(page.locator("id=fail")).toHaveText("0");
});

test("standard curves test with deriveKeyPair", async ({ browserName, page }) => {
  await page.goto("./standardCurvesWithDeriveKeyPair.html");
  await page.click("text=run");
  await page.waitForTimeout(5000);
  if (browserName === "firefox") {
    await expect(page.locator("id=pass")).toHaveText("0");
    await expect(page.locator("id=fail")).toHaveText("18");
  } else {
    await expect(page.locator("id=pass")).toHaveText("18");
    await expect(page.locator("id=fail")).toHaveText("0");
  }
});

test("secure curves test with generateKeyPair", async ({ browserName, page }) => {
  await page.goto("./secureCurves.html");
  await page.click("text=run");
  await page.waitForTimeout(5000);
  if (browserName === "webkit") {
    await expect(page.locator("id=pass")).toHaveText("0");
    await expect(page.locator("id=fail")).toHaveText("6");
  } else {
    await expect(page.locator("id=pass")).toHaveText("6");
    await expect(page.locator("id=fail")).toHaveText("0");
  }
});

test("secure curves test with deriveKeyPair", async ({ browserName, page }) => {
  await page.goto("./secureCurvesWithDeriveKeyPair.html");
  await page.click("text=run");
  await page.waitForTimeout(5000);
  if (browserName === "chromium") {
    await expect(page.locator("id=pass")).toHaveText("6");
    await expect(page.locator("id=fail")).toHaveText("0");
  } else {
    await expect(page.locator("id=pass")).toHaveText("0");
    await expect(page.locator("id=fail")).toHaveText("6");
  }
});
