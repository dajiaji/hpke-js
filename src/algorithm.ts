export class AlgorithmBase {
  protected _api: SubtleCrypto | undefined = undefined;

  constructor() {}
}

export class Algorithm extends AlgorithmBase {
  constructor() {
    super();
  }

  public init(api: SubtleCrypto): void {
    this._api = api;
  }

  protected checkInit(): void {
    if (this._api === undefined) {
      throw new Error("Not initialized. Call init()");
    }
  }
}
