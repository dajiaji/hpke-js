import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/hybridkem-x-wing.spec.ts"],
    globalSetup: "./globalSetup.ts",
  },
});
