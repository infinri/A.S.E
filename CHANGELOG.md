# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

## [1.0.0] - 2026-04-19

First public release. Focused on Magento / Adobe Commerce / Mage-OS stores.

### Added

- `composer.lock` auto-discovery by walking up from the current working directory.
- Magento edition detection from `composer.lock` (`magento/product-community-edition`, `magento/product-enterprise-edition`, `mage-os/product-community-edition`). Detected edition and version appear in logs and in `--format=json` output.
- `--dry-run` flag: scan and report findings without calling Slack, saving state, writing heartbeat, posting the weekly digest, or persisting feed cursor mutations.
- `--format=json` flag: emit a single JSON object to stdout with keys `run_id`, `magento`, `findings`, `summary`, `exit_code`. Logs continue to stream on stderr.
- Severity-based exit codes: `0` = no P0/P1 in alertable set, `1` = P1 present, `2` = P0 present. Applies under `--dry-run` as well.
- `RunResult` DTO returned from `Ase::run()` carrying exit code, alertable findings, escalations, detected Magento edition, and dry-run flag.
- `MagentoEdition` DTO for detected edition info.
- `tests/Unit/DistributionTest` validating Packagist-readiness of build artifacts.
- MIT `LICENSE`, `SECURITY.md`, `CHANGELOG.md`.
- `composer.json` `bin` entry so `composer global require infinri/ase` installs an `ase` executable.

### Changed

- `Config::slackWebhookUrl()` return type widened from `string` to `?string`; empty-string values coerce to `null`.
- `Ase::run()` signature is now `run(bool $dryRun = false): RunResult` (previously `run(): void`).
- `bin/ase.php` renamed to `bin/ase` (shebang handles interpreter; no `.php` extension in the installed executable).
- `SLACK_WEBHOOK_URL` is no longer required when running with `--dry-run` or `--format=json`; `SlackNotifier` and `DigestReporter` no-op with a warning when the webhook is null.
- `composer.json` metadata: package name `2ndswing/ase` -> `infinri/ase`, `type: project` -> `type: library`, license `proprietary` -> `MIT`, added `keywords`, `authors`, `support`, `bin`, and `scripts`.

### Fixed

- NVD 404 error caused by invalid or whitespace-corrupted API keys (pre-1.0 fix, included for completeness).

[Unreleased]: https://github.com/infinri/A.S.E/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/infinri/A.S.E/releases/tag/v1.0.0
