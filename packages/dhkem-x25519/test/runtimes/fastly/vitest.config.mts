import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/dhkem-x25519.spec.ts"],
    globalSetup: "./globalSetup.ts",
  },
});
