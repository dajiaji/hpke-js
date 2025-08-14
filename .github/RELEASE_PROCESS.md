# Release Process Guidelines

This document defines the standardized process for creating release notes and versioning packages in the hpke-js project.

## Release Note Creation Rules

When creating release notes for any package in the hpke-js monorepo, follow these guidelines:

### 1. Release Note Format

Release notes should follow this standardized format:

```markdown
## Version X.Y.Z

Released YYYY-MM-DD

- [(#XXX) category: description.](https://github.com/dajiaji/hpke-js/pull/XXX)
- [(#YYY) category: description.](https://github.com/dajiaji/hpke-js/pull/YYY)
```

### 2. Pull Request Investigation

For each release, systematically investigate all relevant Pull Requests:

1. **Scope Definition**: Identify the previous release date of the target package
2. **PR Collection**: Gather all PRs merged to main branch since the previous release that affect:
   - The target package directly
   - Base infrastructure that impacts the package
   - Dependencies that the package relies on
3. **Impact Assessment**: Include PRs that have any impact on the package functionality, testing, or build process

### 3. Categories and Descriptions

Use consistent categorization for PR descriptions:

- `base:` - Infrastructure, build system, or cross-package changes
- `<package-name>:` - Package-specific changes (e.g., `hpke-js:`, `core:`, `dhkem-x25519:`)
- `deps:` - Dependency updates
- `docs:` - Documentation changes
- `test:` - Testing improvements

### 4. Comprehensive Coverage

Ensure no relevant changes are missed by:

- Checking git commit history since the last release
- Reviewing closed PRs in the time period
- Cross-referencing with other package changelog entries
- Including both direct and indirect dependencies

## Versioning Rules

Follow semantic versioning (SemVer) principles:

### Major Version (X.0.0)
- Breaking API changes
- Removal of deprecated features
- Incompatible changes to public interfaces

### Minor Version (X.Y.0)
- New features added in a backward-compatible manner
- Deprecation of existing features (without removal)
- Substantial new functionality

### Patch Version (X.Y.Z)
- Bug fixes
- Performance improvements
- Documentation updates
- Dependency updates (non-breaking)
- Test improvements
- Build system improvements

## Release Branch Creation Process

When instructed to create a release for `<package-name>` with `{major, minor, patch}` version bump:

### 1. Branch Naming Convention

Create a release branch following this pattern:
```
<package-name>-bump-version-to-<new-version(x_y_z)>
```

Examples:
- `hpke-js-bump-version-to-1_7_0`
- `core-bump-version-to-2_0_0`
- `dhkem-x25519-bump-version-to-1_6_5`

### 2. Release Branch Contents

The release branch should include:

1. **Version Bump**: Update the version in the package's `deno.json`
2. **Changelog Update**: Add the new version section to the package's `CHANGES.md`
3. **Dependency Updates**: Update any internal package dependencies if needed
4. **Documentation Updates**: Update version references in README files if applicable

### 3. Release Branch Workflow

1. **Branch Creation**:
   ```bash
   git checkout main
   git pull origin main
   git checkout -b <package-name>-bump-version-to-<X_Y_Z>
   ```

2. **Changes Implementation**:
   - Update `packages/<package-name>/deno.json` version field
   - Add new section to `packages/<package-name>/CHANGES.md`
   - Update any cross-package version dependencies
   - Run tests to ensure everything works

3. **Commit and Push**:
   ```bash
   git add .
   git commit -m "<package-name>: bump version to <X_Y_Z>"
   git push origin <package-name>-bump-version-to-<X_Y_Z>
   ```

4. **Pull Request Creation**:
   - Create PR from release branch to main
   - Title: `<package-name>: bump version to <X_Y_Z>`
   - Include the changelog in PR description
   - Request review from maintainers

### 4. Post-Release Tasks

After the release PR is merged:

1. **Tag Creation**: Create and push a git tag for the release
2. **Package Publishing**: Publish to npm and JSR registries
3. **Documentation Updates**: Update any external documentation
4. **Announcement**: Communicate the release to stakeholders

## Quality Assurance

Before finalizing any release:

1. **Completeness Check**: Verify all relevant PRs are included
2. **Format Validation**: Ensure consistent formatting across changelog entries
3. **Link Verification**: Confirm all PR links are valid
4. **Version Consistency**: Check version numbers across all files
5. **Testing**: Run full test suite to ensure stability

## Examples

### Example Release Note Entry
```markdown
## Version 1.6.4

Released 2025-08-15

- [(#625) base: add deno task test:browsers.](https://github.com/dajiaji/hpke-js/pull/625)
- [(#623) base: update test dependencies.](https://github.com/dajiaji/hpke-js/pull/623)
- [(#609) hpke-js: use hmac/sha2 in hpke/common.](https://github.com/dajiaji/hpke-js/pull/609)
- [(#597) hpke-js: bump samples dependencies to latest.](https://github.com/dajiaji/hpke-js/pull/597)
```

### Example Release Branch
```
hpke-js-bump-to-1_7_0
├── packages/hpke-js/deno.json (version: "1.7.0")
├── packages/hpke-js/CHANGES.md (new section added)
└── any other affected files
```

This process ensures consistency, completeness, and quality across all releases in the hpke-js project.
