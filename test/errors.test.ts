import { assertEquals } from "testing/asserts.ts";

import { describe, it } from "testing/bdd.ts";

import * as errors from "../src/errors.ts";

describe("ValidationError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.ValidationError(undefined);

      // assert
      assertEquals(err.name, "ValidationError");
      assertEquals(err.message, "");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.ValidationError("failed");

      // assert
      assertEquals(err.name, "ValidationError");
      assertEquals(err.message, "failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.ValidationError(origin);

      // assert
      assertEquals(err.name, "ValidationError");
      assertEquals(err.message, "failed");
    });
  });
});

describe("DeserializeError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.DeserializeError(undefined);

      // assert
      assertEquals(err.name, "DeserializeError");
      assertEquals(err.message, "");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.DeserializeError("failed");

      // assert
      assertEquals(err.name, "DeserializeError");
      assertEquals(err.message, "failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.DeserializeError(origin);

      // assert
      assertEquals(err.name, "DeserializeError");
      assertEquals(err.message, "failed");
    });
  });
});

describe("EncapError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.EncapError(undefined);

      // assert
      assertEquals(err.name, "EncapError");
      assertEquals(err.message, "");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.EncapError("failed");

      // assert
      assertEquals(err.name, "EncapError");
      assertEquals(err.message, "failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.EncapError(origin);

      // assert
      assertEquals(err.name, "EncapError");
      assertEquals(err.message, "failed");
    });
  });
});

describe("DecapError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.DecapError(undefined);

      // assert
      assertEquals(err.name, "DecapError");
      assertEquals(err.message, "");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.DecapError("failed");

      // assert
      assertEquals(err.name, "DecapError");
      assertEquals(err.message, "failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.DecapError(origin);

      // assert
      assertEquals(err.name, "DecapError");
      assertEquals(err.message, "failed");
    });
  });
});

describe("ExportError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.ExportError(undefined);

      // assert
      assertEquals(err.name, "ExportError");
      assertEquals(err.message, "");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.ExportError("failed");

      // assert
      assertEquals(err.name, "ExportError");
      assertEquals(err.message, "failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.ExportError(origin);

      // assert
      assertEquals(err.name, "ExportError");
      assertEquals(err.message, "failed");
    });
  });
});

describe("SealError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.SealError(undefined);

      // assert
      assertEquals(err.name, "SealError");
      assertEquals(err.message, "");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.SealError("failed");

      // assert
      assertEquals(err.name, "SealError");
      assertEquals(err.message, "failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.SealError(origin);

      // assert
      assertEquals(err.name, "SealError");
      assertEquals(err.message, "failed");
    });
  });
});

describe("OpenError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.OpenError(undefined);

      // assert
      assertEquals(err.name, "OpenError");
      assertEquals(err.message, "");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.OpenError("failed");

      // assert
      assertEquals(err.name, "OpenError");
      assertEquals(err.message, "failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.OpenError(origin);

      // assert
      assertEquals(err.name, "OpenError");
      assertEquals(err.message, "failed");
    });
  });
});

describe("MessageLimitReachedError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.MessageLimitReachedError(undefined);

      // assert
      assertEquals(err.name, "MessageLimitReachedError");
      assertEquals(err.message, "");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.MessageLimitReachedError("failed");

      // assert
      assertEquals(err.name, "MessageLimitReachedError");
      assertEquals(err.message, "failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.OpenError(origin);

      // assert
      assertEquals(err.name, "OpenError");
      assertEquals(err.message, "failed");
    });
  });
});

describe("DeriveKeyPairError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.DeriveKeyPairError(undefined);

      // assert
      assertEquals(err.name, "DeriveKeyPairError");
      assertEquals(err.message, "");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.DeriveKeyPairError("failed");

      // assert
      assertEquals(err.name, "DeriveKeyPairError");
      assertEquals(err.message, "failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.OpenError(origin);

      // assert
      assertEquals(err.name, "OpenError");
      assertEquals(err.message, "failed");
    });
  });
});

describe("NotSupportedError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new errors.NotSupportedError(undefined);

      // assert
      assertEquals(err.name, "NotSupportedError");
      assertEquals(err.message, "");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new errors.NotSupportedError("failed");

      // assert
      assertEquals(err.name, "NotSupportedError");
      assertEquals(err.message, "failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new errors.OpenError(origin);

      // assert
      assertEquals(err.name, "OpenError");
      assertEquals(err.message, "failed");
    });
  });
});
