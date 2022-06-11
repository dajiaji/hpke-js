import { expect, test } from "@playwright/test";

test("basic test", async ({ page }) => {
  await page.goto("https://dajiaji.github.io/hpke-js/");
  await page.click("text=run");
  await page.waitForTimeout(5000);
  await expect(page.locator("id=pass")).toHaveText("45");
  await expect(page.locator("id=fail")).toHaveText("0");
});
