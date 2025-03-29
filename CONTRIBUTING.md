# Contributing to hpke-js

Thank you for your interest in contributing to hpke-js! We welcome contributions
from the community.

## Development Setup

### Prerequisites

- Deno 1.41.0 or later
- Node.js 16.0.0 or later (for npm package testing)
- Bun 1.0.0 or later (for Bun runtime testing)
- npm (for package management and testing)
- Cloudflare Workers (for Cloudflare runtime testing)

### Available Tasks

The project provides several tasks for development and testing:

#### Testing

- `deno task test:all`: Run all tests across different environments
- `deno task test`: Run basic tests including formatting, linting, type
  checking, and unit tests
- `deno task test:common`: Test the common package
- `deno task test:core`: Test the core package
- `deno task test:chacha20poly1305`: Test the ChaCha20-Poly1305 implementation
- `deno task test:dhkem-x25519`: Test the X25519 DHKEM implementation
- `deno task test:dhkem-x448`: Test the X448 DHKEM implementation
- `deno task test:dhkem-secp256k1`: Test the secp256k1 DHKEM implementation
- `deno task test:hybridkem-x25519-kyber768`: Test the X25519-Kyber768 hybrid
  KEM implementation
- `deno task test:hybridkem-x-wing`: Test the X-Wing hybrid KEM implementation
- `deno task test:hpke-js`: Test the main HPKE implementation
- `deno task test:ml-kem`: Test the ML-KEM implementation

#### Cross-Platform Testing

- `deno task test:cloudflare`: Run tests in Cloudflare Workers environment
- `deno task test:bun`: Run tests in Bun runtime environment

### Code Quality

The project enforces code quality through the `deno task test` command, which
includes:

- Formatting: `deno fmt`
- Linting: `deno lint`
- Type checking: `deno check`
- Unit tests

### Project Structure

The project is organized as a monorepo with the following packages:

- `packages/common`: Common utilities and types
- `packages/core`: Core HPKE implementation
- `packages/chacha20poly1305`: ChaCha20-Poly1305 AEAD implementation
- `packages/dhkem-x25519`: X25519 DHKEM implementation
- `packages/dhkem-x448`: X448 DHKEM implementation
- `packages/dhkem-secp256k1`: secp256k1 DHKEM implementation
- `packages/hybridkem-x25519-kyber768`: X25519-Kyber768 hybrid KEM
  implementation
- `packages/hybridkem-x-wing`: X-Wing hybrid KEM implementation
- `packages/hpke-js`: Main HPKE package
- `packages/ml-kem`: ML-KEM implementation

Each package contains its own tests and samples in the `samples/deno` directory.

### Dependencies

The project uses several external dependencies managed through Deno's
import-map:

- `@dajiaji/mlkem`: ML-KEM implementation
- `@noble/ciphers`: Cryptographic primitives
- `@noble/curves`: Elliptic curve implementations
- `@noble/hashes`: Hash function implementations
- `@std/*`: Deno standard library modules

## Contributing Guidelines

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `deno task test:all`
5. Submit a pull request

### Code Style

- Follow the existing code style
- Use TypeScript for all new code
- Follow Deno's default formatting rules (enforced by `deno fmt`)
- Follow Deno's default linting rules (enforced by `deno lint`)
- Add appropriate tests for new features
- Update documentation as needed

### Testing Requirements

Before submitting a pull request, ensure that:

1. All tests pass: `deno task test:all`
2. Code is properly formatted: `deno fmt`
3. No linting errors: `deno lint`
4. Tests are added for new features
5. Documentation is updated

### Documentation

- Update relevant documentation files
- Add JSDoc comments for new public APIs
- Include examples in the `samples/deno` directory
- Update the README if necessary

### Running Sample Code

You can use the following tasks to run sample code:

#### Running All Samples

```bash
deno task sample
```

This runs samples for all packages in both Deno and Node.js environments.

#### Running Samples in Specific Environments

To run samples only in Deno environment:

```bash
deno task sample:deno
```

To run samples only in Node.js environment:

```bash
deno task sample:node
```

#### Running Samples for Specific Packages

To run Deno samples for specific packages:

```bash
deno task sample:deno:core                  # Run samples for core package
deno task sample:deno:chacha20poly1305      # Run samples for ChaCha20-Poly1305 package
deno task sample:deno:dhkem-x25519          # Run samples for X25519 DHKEM package
deno task sample:deno:dhkem-x448            # Run samples for X448 DHKEM package
deno task sample:deno:dhkem-secp256k1       # Run samples for secp256k1 DHKEM package
deno task sample:deno:hybridkem-x25519-kyber768  # Run samples for X25519-Kyber768 hybrid KEM package
deno task sample:deno:hybridkem-x-wing      # Run samples for X-Wing hybrid package
deno task sample:deno:hpke-js               # Run samples for main HPKE package
deno task sample:deno:ml-kem                # Run samples for ML-KEM package
```

To run Node.js samples for specific packages:

```bash
deno task sample:node:core                  # Run samples for core package
deno task sample:node:chacha20poly1305      # Run samples for ChaCha20-Poly1305 package
deno task sample:node:dhkem-x25519          # Run samples for X25519 DHKEM package
deno task sample:node:dhkem-x448            # Run samples for X448 DHKEM package
deno task sample:node:dhkem-secp256k1       # Run samples for secp256k1 DHKEM package
deno task sample:node:hybridkem-x25519-kyber768  # Run samples for X25519-Kyber768 hybrid KEM package
deno task sample:node:hybridkem-x-wing      # Run samples for X-Wing hybrid package
deno task sample:node:hpke-js               # Run samples for main HPKE package
deno task sample:node:ml-kem                # Run samples for ML-KEM package
```

Sample code can be found in the `samples/deno` directory of each package.

## License

By contributing, you agree that your contributions will be licensed under the
project's MIT License.
