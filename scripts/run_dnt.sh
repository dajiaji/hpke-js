#!/bin/bash -eux
(
    cd x/core
    deno task dnt
)
(
    cd x/chacha20poly1305
    deno task dnt
)
(
    cd x/dhkem-x25519
    deno task dnt
)
(
    cd x/dhkem-x448
    deno task dnt
)
(
    cd x/dhkem-secp256k1
    deno task dnt
)
(
    cd x/hybridkem-x25519-kyber768
    deno task dnt
)
(
    cd x/hpke-js
    deno task dnt
)