import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/cose.spec.ts"],
    globalSetup: "./globalSetup.ts",
  },
});
