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

## License

By contributing, you agree that your contributions will be licensed under the
project's MIT License.
