export enum Mode {
  Base = 0x00,
  Psk = 0x01,
  Auth = 0x02,
  AuthPsk = 0x03,
}

export enum Kem {
  DhkemP256HkdfSha256 = 0x0010,
  DhkemP384HkdfSha384 = 0x0011,
  DhkemP521HkdfSha512 = 0x0012,
  // DhkemX25519HkdfSha256 = 0x0020,
  // DhkemX448HkdfSha512 = 0x0021,
}

export enum Kdf {
  HkdfSha256 = 0x0001,
  HkdfSha384 = 0x0002,
  HkdfSha512 = 0x0003,
}

export enum Aead {
  Aes128Gcm = 0x0001,
  Aes256Gcm = 0x0002,
  // ChaCha20Poly1305 = 0x0003,
  ExportOnly = 0xFFFF,
}
