import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/hpke.spec.ts"],
    globalSetup: "./globalSetup.ts",
  },
});
