export class XCryptoKey implements CryptoKey {
  public readonly key: Uint8Array;
  public readonly type: "public" | "private";
  public readonly extractable: boolean = true;
  public readonly algorithm: KeyAlgorithm;
  public readonly usages: KeyUsage[];

  constructor(
    name: string,
    key: Uint8Array,
    type: "public" | "private",
    usages: KeyUsage[] = [],
  ) {
    this.key = key;
    this.type = type;
    this.algorithm = { name: name };
    this.usages = usages;
    if (type === "public") {
      this.usages = [];
    }
  }
}
