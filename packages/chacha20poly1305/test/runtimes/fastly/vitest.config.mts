import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/chacha20poly1305.spec.ts"],
    globalSetup: "./globalSetup.ts",
  },
});
