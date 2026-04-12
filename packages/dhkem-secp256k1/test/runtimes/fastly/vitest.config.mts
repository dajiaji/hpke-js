import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["**/dhkem-secp256k1.spec.ts"],
    globalSetup: "./globalSetup.ts",
  },
});
