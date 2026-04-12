import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/jose.spec.ts"],
    globalSetup: "./globalSetup.ts",
  },
});
