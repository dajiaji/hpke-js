import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { OhttpError } from "../mod.ts";

describe("OhttpError", () => {
  it("should have correct name and message", () => {
    const err = new OhttpError("test error");
    assertEquals(err.name, "OhttpError");
    assertEquals(err.message, "test error");
    assertEquals(err instanceof Error, true);
  });
});
