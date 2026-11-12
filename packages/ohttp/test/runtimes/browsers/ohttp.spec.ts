import type { Page, TestInfo } from "@playwright/test";
import { expect, test } from "@playwright/test";

const RESULT_TIMEOUT_MS = 15000;
const STRESS_TIMEOUT_MS = 120000;

// Forwards the page's console errors to the test output and attaches them to
// the report so that the failing inputs are visible in CI logs.
function collectConsoleErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") {
      errors.push(msg.text());
      console.log(`[${test.info().project.name}] ${msg.text()}`);
    }
  });
  page.on("pageerror", (e) => {
    errors.push(String(e));
    console.log(`[${test.info().project.name}] pageerror: ${e}`);
  });
  return errors;
}

async function attachResults(page: Page, testInfo: TestInfo, ids: string[]) {
  for (const id of ids) {
    const text = await page.locator(`#${id}`).textContent();
    if (text) {
      await testInfo.attach(id, { body: text, contentType: "text/plain" });
    }
  }
}

test("basic test", async ({ page }, testInfo) => {
  collectConsoleErrors(page);
  await page.goto("./index.html");
  await page.click("text=run");
  await expect(page.locator("#fail")).not.toHaveText("-", {
    timeout: RESULT_TIMEOUT_MS,
  });
  await attachResults(page, testInfo, ["errors"]);
  // Check the error details first so that they appear in the failure message.
  await expect(page.locator("#errors")).toHaveText("");
  await expect(page.locator("#pass")).toHaveText("3");
  await expect(page.locator("#fail")).toHaveText("0");
});

test("stress test", async ({ page }, testInfo) => {
  test.setTimeout(STRESS_TIMEOUT_MS + 10000);
  collectConsoleErrors(page);
  await page.goto("./stress.html");
  await page.click("text=run");
  await expect(page.locator("#fail")).not.toHaveText("-", {
    timeout: STRESS_TIMEOUT_MS,
  });
  await attachResults(page, testInfo, ["summary", "errors"]);
  console.log(
    `[${testInfo.project.name}] ${await page.locator("#summary")
      .textContent()}`,
  );
  await expect(page.locator("#errors")).toHaveText("");
  await expect(page.locator("#fail")).toHaveText("0");
});
