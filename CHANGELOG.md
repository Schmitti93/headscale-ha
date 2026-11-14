# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Changed

- Prepared repository metadata and documentation for Home Assistant Marketplace distribution.
- Added public support and private vulnerability-reporting guidance.

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

[Unreleased]: https://github.com/Schmitti93/headscale-ha/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Schmitti93/headscale-ha/releases/tag/v0.2.0
