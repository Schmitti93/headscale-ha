# Changelog

All notable changes to this project are documented here.

## [Unreleased]

## [0.2.2] - 2026-11-14

### Fixed

- Restored compatibility with Home Assistant 2026.11, where the coordinator
  name is a required keyword-only argument.

## [0.2.1] - 2026-11-14

### Changed

- Moved Marketplace brand assets into the integration directory required by validation.
- Added HACS, Hassfest, and full-history secret-scanning gates.
- Added the public companion gateway reference and publication metadata.

## [0.2.0] - 2026-11-14

### Added

- Mandatory HTTPS transport and hostname verification.
- Optional private CA certificate support.
- Read-only polling of Headscale version and nodes.
- Hub and per-node devices, sensors, and online binary sensors.
- Dynamic discovery of nodes added after setup.
- Defensive response parsing and a 1 MiB streaming response limit.
- Recursive diagnostics redaction.
- Config-flow validation and configurable polling interval.
- Unit, security, and isolated Home Assistant runtime tests.

### Security

- Rejects plaintext HTTP, URL credentials, paths, queries, and fragments.
- Rejects CA input containing private-key material.
- Does not provide Headscale mutation services.

[Unreleased]: https://github.com/Schmitti93/headscale-ha/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/Schmitti93/headscale-ha/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Schmitti93/headscale-ha/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Schmitti93/headscale-ha/releases/tag/v0.2.0
