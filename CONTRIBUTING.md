# Contributing to hpke-js

Thank you for your interest in contributing to hpke-js! We welcome contributions
from the community.

## Contents

- [Contributing to hpke-js](#contributing-to-hpke-js)
- [Development Setup](#development-setup)
  - [Prerequisites](#prerequisites)
  - [Available Tasks](#available-tasks)
    - [Testing](#testing)
    - [Cross-Platform Testing](#cross-platform-testing)
    - [Package Creation](#package-creation)
  - [Code Quality](#code-quality)
  - [Project Structure](#project-structure)
  - [Dependencies](#dependencies)
- [Contributing Guidelines](#contributing-guidelines)
  - [Code Style](#code-style)
  - [Testing Requirements](#testing-requirements)
  - [Documentation](#documentation)
  - [Running Sample Code](#running-sample-code)
- [License](#license)

## Development Setup

### Prerequisites

- Deno 2.0.0 or later **(required for all development)**
- Node.js 18.0.0 or later **(required for all development and npm package
  testing)**
- npm **(required for package management and testing)**
- Bun 1.1.0 or later (optional, only required for Bun runtime testing if
  modifying core module implementations)
- Cloudflare Workers (optional, only required for Cloudflare runtime testing if
  modifying core module implementations)

**Note**: Deno, Node.js, and npm are essential for all development work. Bun and
Cloudflare Workers are only needed for cross-platform testing when you modify
core module implementations. If you're only contributing documentation,
examples, or non-core features, you don't need to install Bun or set up
Cloudflare Workers.

### Available Tasks

The project provides several tasks for development and testing:

#### Testing

- `deno task test:all`: Run all tests across different environments
- `deno task test`: Run basic tests including formatting, linting, type
  checking, and unit tests in Deno environment only
  - **Note**: Difference from `deno task test:all`: `deno task test` only runs
    basic tests (formatting, linting, type checking, and unit tests) in the Deno
    environment. In contrast, `deno task test:all` runs the basic tests plus npm
    package generation (`deno task npm`), testing in Cloudflare environment
    (`deno task test:cloudflare`), and testing in Bun environment
    (`deno task test:bun`). Use `test:all` when more comprehensive testing is
    needed.
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
- `deno task dnt`: Run tests in Node.js environment using dnt (Deno to npm
  package build tool)

The `deno task dnt` command uses [dnt](https://github.com/denoland/dnt) to
transform Deno code into npm packages and runs tests in a Node.js environment.
This ensures cross-platform compatibility between Deno and Node.js. The process
includes:

1. Converting Deno modules to npm-compatible packages
2. Handling necessary shims and polyfills
3. Transforming ES modules to both ESM and CommonJS formats
4. Executing tests in the Node.js runtime

This approach helps identify any platform-specific issues and ensures the
library works consistently across both Deno and Node.js environments.

#### Package Creation

- `deno task npm`: Create npm packages from Deno modules

The `deno task npm` command transforms the Deno modules into publishable npm
packages using the [dnt](https://github.com/denoland/dnt) tool. This task:

1. Cleans the output directory
2. Converts all Deno modules to npm-compatible packages
3. Generates both ESM and CommonJS versions
4. Creates proper package.json with all necessary dependencies
5. Copies license, readme, and other essential files
6. Prepares the package for publication to npm registry

The generated packages are placed in the `npm` directory and are ready to be
published with `npm publish` or similar commands. This task is essential for
releasing new versions of the library to npm.

- `deno task npm-build`: Build npm packages for all modules using dnt

The `deno task npm-build` command performs the npm package build process for all
modules in the workspace. This is part of the full `deno task npm` pipeline and
handles the conversion of Deno modules to npm-compatible packages. It runs the
individual `npm-build` task for each package, which uses the
[dnt](https://github.com/denoland/dnt) tool to transform TypeScript code into
both ESM and CommonJS formats suitable for npm distribution.

- `deno task minify`: Generate minified versions of all packages

The `deno task minify` command creates minified JavaScript files for all
packages in the workspace. This task runs the individual `minify` task for each
package, which generates optimized, production-ready minified files suitable for
browser environments. The minified files are saved to the corresponding npm
package directories with `.min.js` extensions and can be used for CDN
distribution or direct browser inclusion.

- `deno task dry-publish`: Test npm package publishing without actually
  publishing

The `deno task dry-publish` command simulates the npm publishing process for all
packages without actually publishing them to the npm registry. This is useful
for verifying that packages are properly structured and contain all necessary
files before performing an actual release. It runs `npm pack --dry-run` for each
package, which validates the package contents and shows what would be included
in the published package.

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

1. All tests pass: `deno task test:all` (this includes formatting, linting, type
   checking, and tests across all environments)
2. Tests are added for new features
3. Documentation is updated

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
