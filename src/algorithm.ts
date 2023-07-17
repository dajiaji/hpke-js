import * as consts from "./consts.ts";

export class AlgorithmBase {
  protected _api: SubtleCrypto | undefined = undefined;

  constructor() {}

  protected checkInit(): void {
    if (typeof this._api === "undefined") {
      throw new Error("Not initialized. Call init()");
    }
  }
}

export class Algorithm extends AlgorithmBase {
  constructor() {
    super();
  }

  public init(api: SubtleCrypto): void {
    this._api = api;
  }
}

export class KdfAlgorithm extends AlgorithmBase {
  protected _suiteId: Uint8Array = consts.EMPTY;

  constructor() {
    super();
  }

  public init(api: SubtleCrypto, suiteId: Uint8Array): void {
    this._api = api;
    this._suiteId = suiteId;
  }
}
