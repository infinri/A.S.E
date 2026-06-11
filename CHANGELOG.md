# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-06-11

Rebuilt around OWASP Dependency-Track. The engine, UI, dashboards, and feed
mirroring moved to Dependency-Track 5.0 (install: docs/dependency-track-install.md);
A.S.E became the automation around it. Architecture and rationale:
docs/planning/, parity evidence: docs/parity-report.md.

### Added

- `bin/ase-sync`: converts configured composer lockfiles (`ASE_PROJECTS`) and the
  declared-tech inventory (`inventory/declared-tech.yaml`, per-owner projects) to
  CycloneDX SBOMs and uploads them to Dependency-Track.
- `bin/ase-alert`: polls Dependency-Track findings past a cursor, scores P0/P1
  (CISA KEV membership, ransomware association, CVSS/EPSS thresholds), routes by
  project tag to per-team Slack webhooks (`ASE_ALERT_ROUTES`).
- `bin/dtrack-enable-osv.sh`: required install step; a fresh Dependency-Track 5.0
  mirrors only NVD+EPSS and silently matches nothing for composer/npm otherwise.
- `CurlClient::put()`; PUT requests previously went out as bodyless GETs.
- docs: runbook, install guide, parity report, planning documents.
- CI workflow: composer audit (merge gate), PHPStan, PHPUnit.

### Removed

- Legacy feed pollers (KEV/NVD/GHSA/OSV/Packagist), deduplicator, state manager,
  feed health tracking, composer.lock analyzer, `bin/ase`, `bin/heartbeat.sh`.
  Dependency-Track owns feed ingestion and matching now. Tag `mvp-final`
  preserves the 1.0.0 implementation. Retained: scoring (`PriorityCalculator`),
  Slack message format, HTTP client, logging/redaction.

## [1.0.0] - 2026-04-24

First public release. CVE monitoring for Magento / Adobe Commerce / Mage-OS stores: polls KEV, NVD, GHSA, and Packagist (with OSV available as an optional fifth feed), deduplicates across them, scores by CVSS + EPSS + KEV, and alerts to Slack on P0 and P1 only.

### Added

#### CLI surface

- `bin/ase` shebang-PHP CLI. `composer.json` `bin` entry installs `ase` on `composer global require infinri/ase`.
- `--dry-run` flag: scan and report findings without calling Slack, saving state, or writing the heartbeat.
- `--format=<human|json>` flag. JSON form emits one object to stdout with keys `run_id`, `magento`, `findings`, `summary`, `exit_code`; logs stream on stderr.
- `--since <YYYY-MM-DD>` flag: backfill from a specific date (first run only).
- `--test-slack` and `--test-alert` flags for verifying webhook wiring without waiting for a real CVE.
- Severity-based exit codes: `0` = no P0/P1 in alertable set, `1` = P1 present, `2` = P0 present or fatal config error. Applies under `--dry-run` as well.

#### Feeds and matching

- Five-feed support: CISA KEV, NVD v2.0, GitHub Security Advisories, Packagist, and OSV (opt-in).
- `ENABLED_FEEDS` env var with default `kev,nvd,ghsa,packagist`. Add `osv` to enable OSV.
- OSV implementation issues a single `POST https://api.osv.dev/v1/querybatch` populated from the installed packages, then hydrates each returned advisory via `GET /v1/vulns/{id}`.
- NVD CPE-prefix filtering uses `virtualMatchString` so prefix forms (`cpe:2.3:a:adobe:commerce`, `cpe:2.3:a:magento:magento`) match correctly.
- EPSS enrichment after dedup, batches of 100 CVEs per request.
- Magento edition detection from `composer.lock` (`magento/product-community-edition`, `magento/product-enterprise-edition`, `mage-os/product-community-edition`). Edition + version surface in logs and `--format=json` output.
- Auto-detection of ecosystem filters from `composer.lock`: `ComposerLockAnalyzer::detectVendors()`, `detectEcosystems()`, `detectCpePrefix()`, `getInstalledPackages()`. Env values are additive for `ECOSYSTEMS`/`VENDOR_FILTER` and override-when-set for `NVD_CPE_PREFIX`.
- `COMPOSER_LOCK_PATH` is optional. When set, enables Magento-aware filtering. When unset, ASE runs in project-agnostic mode (feeds still poll; composer-ecosystem filtering disabled with a one-line WARN at run start).

#### Scoring and notification

- Two-tier priority system, P0 + P1 only. Anything below P1 is dropped before notification or persistence.
- Two-webhook model: `SLACK_WEBHOOK_URL` (P0; required for normal runs) + `SLACK_WEBHOOK_P1` (P1; optional, silently skipped with one warning per run when unset).
- 1.5s throttle between Slack messages so backfills don't drown the channel.
- Silent first-run import: every existing vulnerability is marked notified at its current priority on the first run; no Slack pings until subsequent runs detect new findings or escalations.
- Slack alerts include a Packagist remediation button linking to `https://packagist.org/packages/{vendor}/{name}` for composer-ecosystem findings.

#### State and ops

- Atomic JSON state persistence via `StateManager` (temp file + rename). State is the only reason ASE doesn't re-alert on the same CVE every run.
- `StateManager::load()` silently prunes legacy state entries with priorities outside `{P0, P1}` and logs the count.
- Heartbeat file written on every successful run. `bin/heartbeat.sh` alerts via syslog if the last success was >24h ago.
- Per-feed health tracking with consecutive-failure counts; 3+ failures logs ERROR.
- `LOG_FILE_LEVEL` env var (default `INFO`) controls the rotating file log's minimum level independently of stderr. Set to `DEBUG` for troubleshooting captures.
- `Ase::pollFeeds()` emits one INFO `"Feed poll complete"` line per feed carrying `duration_ms`.

#### Observability and security

- `SecretRedactor` + monolog processor that masks Slack webhook URLs, GitHub tokens (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_), Bearer tokens, URL basic-auth credentials, and registered exact-match secrets (NVD API key, Slack webhook, GitHub token) in all log output.
- `CorrelationId::generate()` produces a UUIDv4 per run; `CorrelationIdProcessor` injects `run_id` into every log record and populates `RunResult->runId`.
- stderr handler uses Monolog's `JsonFormatter` (one JSON object per line). The rotating file handler keeps the human-readable `LineFormatter`.
- `#[\SensitiveParameter]` attribute on `CurlClient::{get,post,request,execute}` `$headers` params so API keys cannot leak into stack traces.

#### Types and tests

- `RunResult` DTO returned from `Ase::run(bool $dryRun = false)` carrying exit code, alertable findings, escalations, detected Magento edition, dry-run flag, and run id.
- `MagentoEdition` DTO for detected edition info.
- `Vulnerability` and `AffectedPackage` value objects (immutable, serializable).
- `Priority` enum (P0, P1).
- `~238` unit tests covering feeds, dedup, priority scoring, state, redaction, correlation-id wiring, P0/P1 webhook routing, OSV querybatch shape, NVD URL shape, `Config::logFileLevel()`, `ComposerLockAnalyzer::getInstalledPackages()`, and Packagist-readiness (`tests/Unit/DistributionTest`).

#### Packaging

- MIT `LICENSE`, `SECURITY.md`, `CHANGELOG.md`.
- `composer.json` declares `ext-curl`, `ext-json`, `ext-mbstring`, `ext-openssl` in `require` so `composer install` fails fast on machines lacking them.

### Fixed

- NVD feed returned HTTP 404 against `cpe:2.3:a:adobe:commerce` / `cpe:2.3:a:magento:magento` because `cpeName` requires an exact NVD-dictionary entry; prefix matching now uses `virtualMatchString`. Verified live across six query-shape variants.
- OSV feed returned HTTP 400 "Invalid query." because `POST /v1/query` with `{ecosystem: "Packagist"}` is malformed; the endpoint requires `package` or `commit`. Now uses `/v1/querybatch` with one query per installed package.
- `bin/ase --test-alert` Slack card was missing CVSS for CVE-2024-34102 because the inline extraction only accepted `type=Primary`; the CVE has only a `Secondary` metric (source `psirt@adobe.com`, score 9.8). Now falls back to the first available metric when no Primary entry exists.
- `composer.lock` walk-up discovery silently scanned ASE's own lockfile (36 packages) when `bin/ase` was invoked from the project directory, even with `COMPOSER_LOCK_PATH` set explicitly to the real Magento lockfile (828 packages). Walk-up removed; env value is now authoritative.
- NVD 404 caused by whitespace-corrupted API keys -- handled by env-trim in `Config::getOptional()`.
- NVD 404 error message broadened to mention both `NVD_API_KEY` and `NVD_CPE_PREFIX` as likely causes (was attributing 404s to API key alone).

[1.0.0]: https://github.com/infinri/A.S.E/releases/tag/v1.0.0
