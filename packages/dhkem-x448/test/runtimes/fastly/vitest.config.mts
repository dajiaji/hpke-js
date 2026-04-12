import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/dhkem-x448.spec.ts"],
    globalSetup: "./globalSetup.ts",
  },
});
