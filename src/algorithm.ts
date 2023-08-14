import { loadSubtleCrypto } from "./webCrypto.ts";

export class NativeAlgorithm {
  protected _api: SubtleCrypto | undefined = undefined;

  constructor() {}

  protected async _setup() {
    if (this._api !== undefined) {
      return;
    }
    this._api = await loadSubtleCrypto();
  }
}
