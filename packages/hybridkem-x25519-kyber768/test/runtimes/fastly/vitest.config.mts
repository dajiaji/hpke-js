import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/hybridkem-x25519-kyber768.spec.ts"],
    globalSetup: "./globalSetup.ts",
  },
});
