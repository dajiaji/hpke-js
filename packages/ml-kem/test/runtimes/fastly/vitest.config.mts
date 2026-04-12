import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/ml-kem.spec.ts"],
    globalSetup: "./globalSetup.ts",
  },
});
