import { expect, test } from "@playwright/test";

test("basic test", async ({ page }) => {
  await page.goto("https://dajiaji.github.io/hpke-js/chacha20poly1305");
  await page.click("text=run");
  await page.waitForTimeout(5000);
  await expect(page.locator("id=pass")).toHaveText("9");
  await expect(page.locator("id=fail")).toHaveText("0");
});
