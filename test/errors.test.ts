import { assertEquals } from "https://deno.land/std@0.142.0/testing/asserts.ts";

import { describe, it } from "https://deno.land/std@0.142.0/testing/bdd.ts";

import * as errors from "../src/errors.ts";

describe("ValidationError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.ValidationError(undefined);

      // assert
      assertEquals(err.name, "ValidationError");
      assertEquals(err.message, "ValidationError");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.ValidationError("failed");

      // assert
      assertEquals(err.name, "ValidationError");
      assertEquals(err.message, "ValidationError: failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.ValidationError(origin);

      // assert
      assertEquals(err.name, "ValidationError");
      assertEquals(err.message, "ValidationError: failed");
    });
  });
});

describe("DeserializeError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.DeserializeError(undefined);

      // assert
      assertEquals(err.name, "DeserializeError");
      assertEquals(err.message, "DeserializeError");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.DeserializeError("failed");

      // assert
      assertEquals(err.name, "DeserializeError");
      assertEquals(err.message, "DeserializeError: failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.DeserializeError(origin);

      // assert
      assertEquals(err.name, "DeserializeError");
      assertEquals(err.message, "DeserializeError: failed");
    });
  });
});

describe("EncapError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.EncapError(undefined);

      // assert
      assertEquals(err.name, "EncapError");
      assertEquals(err.message, "EncapError");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.EncapError("failed");

      // assert
      assertEquals(err.name, "EncapError");
      assertEquals(err.message, "EncapError: failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.EncapError(origin);

      // assert
      assertEquals(err.name, "EncapError");
      assertEquals(err.message, "EncapError: failed");
    });
  });
});

describe("DecapError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.DecapError(undefined);

      // assert
      assertEquals(err.name, "DecapError");
      assertEquals(err.message, "DecapError");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.DecapError("failed");

      // assert
      assertEquals(err.name, "DecapError");
      assertEquals(err.message, "DecapError: failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.DecapError(origin);

      // assert
      assertEquals(err.name, "DecapError");
      assertEquals(err.message, "DecapError: failed");
    });
  });
});

describe("ExportError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.ExportError(undefined);

      // assert
      assertEquals(err.name, "ExportError");
      assertEquals(err.message, "ExportError");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.ExportError("failed");

      // assert
      assertEquals(err.name, "ExportError");
      assertEquals(err.message, "ExportError: failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.ExportError(origin);

      // assert
      assertEquals(err.name, "ExportError");
      assertEquals(err.message, "ExportError: failed");
    });
  });
});

describe("SealError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.SealError(undefined);

      // assert
      assertEquals(err.name, "SealError");
      assertEquals(err.message, "SealError");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.SealError("failed");

      // assert
      assertEquals(err.name, "SealError");
      assertEquals(err.message, "SealError: failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.SealError(origin);

      // assert
      assertEquals(err.name, "SealError");
      assertEquals(err.message, "SealError: failed");
    });
  });
});

describe("OpenError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.OpenError(undefined);

      // assert
      assertEquals(err.name, "OpenError");
      assertEquals(err.message, "OpenError");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.OpenError("failed");

      // assert
      assertEquals(err.name, "OpenError");
      assertEquals(err.message, "OpenError: failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.OpenError(origin);

      // assert
      assertEquals(err.name, "OpenError");
      assertEquals(err.message, "OpenError: failed");
    });
  });
});

describe("MessageLimitReachedError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.MessageLimitReachedError(undefined);

      // assert
      assertEquals(err.name, "MessageLimitReachedError");
      assertEquals(err.message, "MessageLimitReachedError");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.MessageLimitReachedError("failed");

      // assert
      assertEquals(err.name, "MessageLimitReachedError");
      assertEquals(err.message, "MessageLimitReachedError: failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.OpenError(origin);

      // assert
      assertEquals(err.name, "OpenError");
      assertEquals(err.message, "OpenError: failed");
    });
  });
});

describe("DeriveKeyPairError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.DeriveKeyPairError(undefined);

      // assert
      assertEquals(err.name, "DeriveKeyPairError");
      assertEquals(err.message, "DeriveKeyPairError");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.DeriveKeyPairError("failed");

      // assert
      assertEquals(err.name, "DeriveKeyPairError");
      assertEquals(err.message, "DeriveKeyPairError: failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.OpenError(origin);

      // assert
      assertEquals(err.name, "OpenError");
      assertEquals(err.message, "OpenError: failed");
    });
  });
});

describe("NotSupportedError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.NotSupportedError(undefined);

      // assert
      assertEquals(err.name, "NotSupportedError");
      assertEquals(err.message, "NotSupportedError");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.NotSupportedError("failed");

      // assert
      assertEquals(err.name, "NotSupportedError");
      assertEquals(err.message, "NotSupportedError: failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.OpenError(origin);

      // assert
      assertEquals(err.name, "OpenError");
      assertEquals(err.message, "OpenError: failed");
    });
  });
});
