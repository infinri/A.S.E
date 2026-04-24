# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `LOG_FILE_LEVEL` env var (default `INFO`) controls the rotating file log's minimum level independently of stderr. Set to `DEBUG` for troubleshooting captures.
- `Config::logFileLevel(): int` mapping `DEBUG|INFO|NOTICE|WARNING|ERROR|CRITICAL|ALERT|EMERGENCY` (case-insensitive) to Monolog levels; `InvalidArgumentException` on unknown values.
- `Ase::run()` emits one WARN log when `COMPOSER_LOCK_PATH` is unset, declaring "project-agnostic mode" (composer-ecosystem filtering disabled; feeds still poll).
- `#[\SensitiveParameter]` attribute on `CurlClient::{get,post,request,execute}` `$headers` params so API keys cannot leak into stack traces.
- `ComposerLockAnalyzer::getInstalledPackages(): array<string,string>` public helper; powers OSV's per-package querybatch payload.
- `ext-curl`, `ext-json`, `ext-mbstring`, `ext-openssl` declarations in `composer.json` `require` block (fail-fast on `composer install`).
- `tests/Unit/Feed/OsvFeedTest.php` (11 tests covering querybatch URL/body shape, empty-lock path, HTTP-error path, stub hydration, parse path).
- New `NvdFeedTest` cases asserting `virtualMatchString` URL shape and the 404 error message contents.
- New `ConfigTest` cases for `logFileLevel()` defaults / mapping / unknown-value rejection.
- New `ComposerLockAnalyzerTest` cases for `getInstalledPackages()`.
- `SecretRedactor` + monolog processor that masks Slack webhook URLs, GitHub tokens (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_), Bearer tokens, URL basic-auth credentials, and registered exact-match secrets (NVD API key, Slack webhook, GitHub token) in all log output.
- `CorrelationId::generate()` produces a UUIDv4 for every run; a `CorrelationIdProcessor` injects `run_id` into every log record and populates `RunResult->runId`.
- `SLACK_WEBHOOK_P1` env var for a second, channel-scoped webhook. When set, P1 alerts route here; when unset, P1 alerts are silently skipped after one warning per run.
- Auto-detection of ecosystem filters from `composer.lock`: `ComposerLockAnalyzer::detectVendors()`, `detectEcosystems()`, `detectCpePrefix()`. Env values are additive for `ECOSYSTEMS`/`VENDOR_FILTER` and override-when-set for `NVD_CPE_PREFIX`.
- Slack alerts for composer-ecosystem findings now include a Packagist remediation button linking to `https://packagist.org/packages/{vendor}/{name}`.
- `tests/Unit/Logging/*`, `tests/Unit/Support/CorrelationIdTest`, `tests/Unit/Notify/SlackNotifierTest` covering redaction, correlation-id wiring, and P0/P1 webhook routing.
- `StateManager::load()` silently prunes legacy state entries with priorities outside `{P0, P1}` and logs a one-line count when pruning occurs.

### Changed

- `NvdFeed` query parameter swapped from `cpeName` to `virtualMatchString` for prefix matching (fixes deterministic HTTP 404 against `cpe:2.3:a:adobe:commerce` and `cpe:2.3:a:magento:magento`; `cpeName` requires exact NVD-dictionary entries).
- `NvdFeed` HTTP-404 error message now cites both `NVD_API_KEY` and `NVD_CPE_PREFIX` as likely causes (was misleadingly attributing 404s to API key alone).
- `OsvFeed::poll()` rewritten: issues one `POST https://api.osv.dev/v1/querybatch` populated from installed packages, then hydrates each returned advisory via `GET /v1/vulns/{id}`. Replaces the broken `{ecosystem: X}` payload to `/v1/query` that returned HTTP 400 "Invalid query.".
- OSV is now opt-in: `ENABLED_FEEDS` default changed from `kev,nvd,ghsa,osv,packagist` to `kev,nvd,ghsa,packagist`. Add `osv` to the list to re-enable.
- `Config::composerLockPath()` simplified to env-only: returns `COMPOSER_LOCK_PATH` or `null`. Walk-up auto-discovery from `getcwd()` removed (it conflated "where the lockfile lives" with "what to look for"; produced wrong-project scans when invoked from inside the ASE workspace).
- `CorrelationIdProcessor::setRunId(?string)` replaced by a public `runId` property (PHP 8.4-friendly direct assignment).
- `Deduplicator` declared `final readonly class`.
- `Ase::pollFeeds()` consolidates feed-poll logs: one INFO `"Feed poll complete"` line per feed carrying `duration_ms` (previously `"Polling feed"` + `"Feed poll complete"` pair).
- `bin/ase` `RotatingFileHandler` now respects `Config::logFileLevel()` (default `INFO`; was hardcoded `Logger::DEBUG`). At default, file-log line count drops ~95% per run.
- `bin/ase --test-alert` CVSS extraction now falls back to the first metric entry when no `type=Primary` entry exists (e.g. CVE-2024-34102 publishes only a `Secondary` entry from `psirt@adobe.com`).
- `Ase::allBatchesEmpty()` and `GitHubAdvisoryFeed::validateResponse()` use PHP 8.4 `array_all()`.
- `SecretRedactorProcessor::scrubArray()` implemented with `array_map` (keys preserved).
- `CurlClient` retry-loop unreachable post-loop fallback now `throw new \LogicException(...)` instead of a silent return.
- **Priority enum reduced to `[P0, P1]`.** P2, P3, P4 no longer exist; `PriorityCalculator::classify()` returns `?Priority` (null = not alertable) and `classifyAll()` filters non-alertable vulns out before they reach notification or persistence.
- stderr handler now uses monolog's `JsonFormatter` (one JSON object per line). The rotating file handler keeps the human-readable `LineFormatter` for local debugging.
- `Ase` constructor takes a `CorrelationIdProcessor` dependency (used to thread per-run ids into log context) and no longer takes `DigestReporter`.
- `RunResult::fromClassification()` takes `runId` as its final parameter; `toJsonArray()`'s `summary` field now has only `P0` and `P1` keys (previously P0..P4).
- Feeds (`KevFeed`, `NvdFeed`, `GitHubAdvisoryFeed`, `OsvFeed`) now accept `ComposerLockAnalyzer` and merge env-configured ecosystem/vendor/CPE filters with auto-detected values from `composer.lock`.
- `--test-alert` sends a P0 sample always and a P1 sample only when `SLACK_WEBHOOK_P1` is set; no longer sends a P2 sample.
- `Config::slackWebhookUrl()` previously returned an empty string when unset; now returns `?string` and `SlackNotifier`/`DigestReporter` no-op with a warning when null. (Carryover from v1.0.0 that was still partially documented in older prose.)

### Removed

- `Config::findComposerLockUpwards()` private helper (walk-up discovery).
- `CorrelationIdProcessor::setRunId()` method (replaced by direct property assignment).
- All inline `TODO`/`FIXME` comments across `src/`, `bin/`, `tests/`.
- `src/Health/DigestReporter.php` and the weekly P2 digest Slack path.
- `SlackMessage::digest()` method.
- `SLACK_CHANNEL_CRITICAL` and `SLACK_CHANNEL_ALERTS` env vars. Channels are now implicit in each webhook.
- `EPSS_MEDIUM_THRESHOLD` and `CVSS_MEDIUM_THRESHOLD` env vars (they only drove P2/P3/P4 classification).
- `Config::slackChannelCritical()`, `Config::slackChannelAlerts()`, `Config::epssMediumThreshold()`, `Config::cvssMediumThreshold()` methods.

### Fixed

- NVD feed returned HTTP 404 against `cpe:2.3:a:adobe:commerce` / `cpe:2.3:a:magento:magento` because `cpeName` requires an exact NVD-dictionary entry; prefix matching needs `virtualMatchString`. Verified live across six query-shape variants.
- OSV feed returned HTTP 400 "Invalid query." because `POST /v1/query` with `{ecosystem: "Packagist"}` is malformed; the endpoint requires `package` or `commit`. Now uses `/v1/querybatch` with one query per installed package.
- `bin/ase --test-alert` Slack card was missing CVSS for CVE-2024-34102 because the inline extraction only accepted `type=Primary`; the CVE has only a `Secondary` metric (source `psirt@adobe.com`, score 9.8).
- Walk-up auto-discovery silently scanned ASE's own `composer.lock` (36 packages) when `bin/ase` was invoked from the project directory, even with `COMPOSER_LOCK_PATH` set in `.env` to the real Magento lockfile (828 packages). Walk-up removed; env value is now authoritative.
- Dead code branch in `RunResult::fromClassification` after the priority enum reduction (flagged by phpstan; rule `identical.alwaysTrue`).

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
