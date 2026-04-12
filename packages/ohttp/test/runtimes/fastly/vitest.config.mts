import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/ohttp.spec.ts"],
    globalSetup: "./globalSetup.ts",
  },
});
