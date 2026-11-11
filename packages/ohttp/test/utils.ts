export function hexToBytes(hex: string): Uint8Array {
  const v = hex.replace(/\s+/g, "");
  if (v.length % 2 !== 0 || /[^\da-f]/i.test(v)) {
    throw new Error("Not hex string.");
  }
  const bytes = new Uint8Array(v.length / 2);
  for (let i = 0; i < v.length; i += 2) {
    bytes[i / 2] = parseInt(v.substring(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
