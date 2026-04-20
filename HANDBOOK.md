# A.S.E. -- Automated Security Evaluator: Technical Handbook

**Audience:** CTO, Senior Engineering Lead, Security Team  
**Version:** 1.0 | **Date:** April 7, 2026  
**PHP:** 8.4+ | **Production LOC:** ~2,937 | **Test LOC:** ~2,000+

---

## Executive Summary

A.S.E. is a PHP 8.4 CLI tool that polls six public security feeds on a cron schedule, deduplicates vulnerabilities via alias resolution, scores them using a three-signal system (CVSS + EPSS + KEV), and posts prioritized alerts to Slack. It runs single-threaded, uses flat-file JSON state with atomic writes, and is designed for low-ops overhead.

**Key design decisions:**
- Single-process, cron-driven (no daemon, no queue, no database)
- Atomic file-based state persistence (no external storage dependency)
- Per-feed exception boundaries (one feed down does not crash the run)
- Three-signal scoring prevents alert fatigue (KEV > EPSS > CVSS alone)

---

## 1. External API Integrations

### Feed Inventory

| # | Feed | URL | Auth | Method | Poll Interval | Data |
|---|------|-----|------|--------|---------------|------|
| 1 | **CISA KEV** | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | None | GET | 2h | Known exploited vulnerabilities mandated for federal patching. Binary signal: "this is being exploited now." |
| 2 | **NVD v2.0** (NIST) | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Optional API key (header) | GET + pagination | 2h | Canonical CVE records with CVSS scores, CWE classifications, CPE-based affected software, and references. The authoritative severity source. |
| 3 | **GitHub Advisories** | `https://api.github.com/advisories` | Optional token (header) | GET + pagination | 30m | Ecosystem-scoped advisories (Composer, npm, PyPI). Provides package-level affected version ranges and fix versions. Fast to update. |
| 4 | **OSV** (Google) | `https://api.osv.dev/v1/query` (POST) / `/v1/vulns/{id}` (GET) | None | POST + GET | 30m | Open-source vulnerability database. Covers ecosystems NVD does not (Packagist, npm, Go). Provides version range events (introduced/fixed). |
| 5 | **Packagist Advisories** | `https://packagist.org/api/security-advisories/` | None | GET | 1h | Composer-specific advisories. Lightweight, incremental via `updatedSince` timestamp. |
| 6 | **EPSS** (FIRST.org) | `https://api.first.org/data/v1/epss` | None | GET | Post-poll enrichment | Exploit Prediction Scoring System. Probability (0-1) that a CVE will be exploited in the next 30 days. Used as a tiebreaker alongside CVSS. |

### Why Each Feed Matters

| Feed | Role in Scoring | What It Uniquely Provides |
|------|----------------|---------------------------|
| **CISA KEV** | Instant P0 -- active exploitation confirmed | Ransomware correlation, federal remediation deadlines |
| **NVD** | Primary CVSS score source | Authoritative severity, CWE, CPE matching, references |
| **GitHub Advisories** | Package-level version ranges | Ecosystem-aware fix versions, fast updates |
| **OSV** | Broader ecosystem coverage | Covers packages NVD misses, version event ranges |
| **Packagist** | Composer-specific intelligence | Direct relevance to PHP/Magento stack |
| **EPSS** | Exploit probability enrichment | "Is this actually being exploited?" vs theoretical severity |

### Who Operates These Feeds

| Feed | Operator | Governance | SLA |
|------|----------|-----------|-----|
| CISA KEV | U.S. Cybersecurity & Infrastructure Security Agency | Federal government | Updated during business hours, no formal SLA |
| NVD | National Institute of Standards and Technology (NIST) | Federal government | Best-effort, known backlogs during high-volume periods |
| GitHub Advisories | GitHub (Microsoft) | Community + GitHub Security Lab | Near real-time for disclosed advisories |
| OSV | Google Open Source Security Team | Open-source community | Best-effort |
| Packagist | Private Packagist / Packagist.org | Community-maintained | Best-effort |
| EPSS | FIRST.org (Forum of Incident Response) | Non-profit consortium | Daily model updates |

### Rate Limits and Authentication

| Feed | Without Auth | With Auth | Auth Mechanism |
|------|-------------|-----------|----------------|
| NVD | 5 req/30s | 50 req/30s | `apiKey` HTTP header (free registration at nvd.nist.gov) |
| GitHub | 60 req/hr | 5,000 pts/hr | `Authorization: token {PAT}` header |
| KEV | Unlimited | N/A | None needed |
| OSV | Undocumented | N/A | None needed |
| Packagist | Undocumented | N/A | None needed |
| EPSS | Undocumented | N/A | None needed |

**Recommendation:** Always configure `NVD_API_KEY` and `GITHUB_TOKEN` in production. Without them, rate limits are restrictive enough to cause poll failures during backfill.

---

## 2. Architecture

### Data Flow

```
cron (every 30m)
  |
  v
flock -n /tmp/ase.lock
  |
  v
bin/ase.php (CLI entry)
  |
  v
Config (.env via phpdotenv)
  |
  v
StateManager.load() (atomic JSON, shared lock)
  |
  v
Feed Polling (5 feeds, per-feed try/catch)
  |-- KevFeed ---------> CISA API
  |-- NvdFeed ---------> NVD API (paginated)
  |-- GitHubAdvisoryFeed -> GitHub API (paginated, per-ecosystem)
  |-- OsvFeed ---------> OSV API (per-ecosystem)
  |-- PackagistFeed ---> Packagist API
  |
  v
EpssFeed (enrichment, batches of 100 CVEs)
  |
  v
Deduplicator (alias-aware merge across all feeds)
  |
  v
ComposerLockAnalyzer (flags installed vulnerable versions; needs COMPOSER_LOCK_PATH in production,
                       auto-discovered via walk-up for ad-hoc runs inside the project)
  |
  v
PriorityCalculator (CVSS + EPSS + KEV -> P0, P1, or filtered out)
  |
  v
SlackNotifier (routes by priority, throttled)
  |-- P0 -> SLACK_WEBHOOK_URL (required, individual messages)
  |-- P1 -> SLACK_WEBHOOK_P1  (optional; silently skipped when unset)
  |
  v
StateManager.save() (atomic: temp file + rename)
  |
  v
Heartbeat write (dead man's switch file)
```

### Design Patterns

| Pattern | Where | Why |
|---------|-------|-----|
| Strategy | `FeedInterface` + 5 implementations | Add new feeds without touching orchestrator |
| Value Objects | `Vulnerability`, `AffectedPackage`, `Priority` | Immutable, type-safe, serializable |
| Builder | `SlackMessage` static factories | Complex Block Kit construction |
| Decorator | `Vulnerability.withPriority()`, `.withEpss()` | Immutable state updates |
| Template Method | `CurlClient.request()` wraps `execute()` | Retry + backoff orchestration |

### File Organization

```
src/
  Ase.php              -- Main orchestrator (287 LOC)
  Config.php           -- Environment config loader
  Model/               -- Value objects (Priority enum, Vulnerability, AffectedPackage, etc.)
  Feed/                -- Feed implementations (FeedInterface + 6 classes)
  Dedup/               -- Alias-aware deduplication
  Scoring/             -- Priority calculation (CVSS + EPSS + KEV)
  State/               -- Atomic JSON state persistence
  Notify/              -- Slack routing + Block Kit message builder
  Filter/              -- ComposerLockAnalyzer (optional version matching)
  Health/              -- Feed health tracking, schema validation
  Logging/             -- SecretRedactor, monolog processors (correlation id + secret scrubbing)
  Run/                 -- RunResult DTO returned from Ase::run()
  Support/             -- CorrelationId (UUIDv4 generator)
  Http/                -- CurlClient with retry/backoff, HttpResponse value object

bin/
  ase                  -- CLI entry point (shebang PHP)
  heartbeat.sh         -- Dead man's switch checker

tests/Unit/            -- 14 test files, ~2,000 LOC
```

---

## 3. Priority Scoring System

### Priority Tiers

ASE only tracks and notifies on P0 and P1. Anything that doesn't meet the P0/P1 thresholds is filtered out by `PriorityCalculator::classify()` (returns `null`) and never reaches the notification stage or the state file.

| Tier | Label | Criteria | Slack Routing |
|------|-------|----------|---------------|
| **P0** | Immediate | In CISA KEV, OR (CVSS >= 9.0 AND EPSS >= 10%) | Individual message via `SLACK_WEBHOOK_URL` (required) |
| **P1** | Urgent | Known ransomware, OR (CVSS >= 7.0 AND EPSS >= 10%), OR (affects installed version AND CVSS >= 7.0) | Individual message via `SLACK_WEBHOOK_P1` (optional; silently skipped with one-line warning when unset) |

Legacy priority values (`P2`, `P3`, `P4`) left behind in pre-upgrade state files are silently pruned on load by `StateManager::load()` with a one-line info log counting the prune.

### Signal Weighting Logic

- **KEV alone -> P0.** Active exploitation trumps all other signals.
- **CVSS critical + EPSS high -> P0.** Severe AND likely to be exploited.
- **CVSS high + EPSS high -> P1.** Upper-range severity with exploitation likelihood.
- **Affects installed version + CVSS high -> P1.** Because it's in your lockfile.
- **Everything else -> filtered out.** Dropped before notification and state persistence.

### CVSS Fallback

When a vulnerability has a CVSS vector string but no numeric score, the system estimates from the Attack Vector (AV) and Attack Complexity (AC):

| AV:N + AC:L | AV:N | AV:A | AV:L or AV:P |
|-------------|------|------|---------------|
| 9.0 | 7.5 | 5.5 | 4.0 |

### Configurable Thresholds

All thresholds are configurable via `.env`:

```
CVSS_CRITICAL_THRESHOLD=9.0
CVSS_HIGH_THRESHOLD=7.0
EPSS_HIGH_THRESHOLD=0.10
```

`CVSS_MEDIUM_THRESHOLD` and `EPSS_MEDIUM_THRESHOLD` were removed along with the P2/P3/P4 tiers.

---

## 4. Deduplication

### The Problem

The same vulnerability appears across multiple feeds under different identifiers:
- NVD: `CVE-2024-34102`
- GitHub: `GHSA-xxxx-yyyy-zzzz`
- OSV: `GHSA-xxxx-yyyy-zzzz` (same as GitHub)
- Packagist: references CVE-2024-34102

Without dedup, the same issue generates 3-4 separate Slack alerts.

### Alias Resolution (Three-Layer)

1. **Direct match:** incoming `canonicalId` already exists in state
2. **Incoming canonical is an alias:** incoming `canonicalId` found in the alias index of an existing entry
3. **Incoming alias matches existing:** any alias from the incoming vuln matches an existing canonical or alias

CVE IDs are preferred as canonical over GHSA/OSV IDs.

### Merge Strategy

When two records represent the same vulnerability:

| Field | Rule | Rationale |
|-------|------|-----------|
| `canonicalId` | Keep existing | ID stability across runs |
| `aliases` | Union | Capture all known identifiers |
| `cvssScore` | Max of both | Use most severe rating |
| `epssScore` | Keep existing (enriched separately) | Don't overwrite with null |
| `inKev` | OR (true if either) | KEV status is additive |
| `knownRansomware` | OR (true if either) | Threat intel is additive |
| `sources` | Union | Track provenance |
| `affectedPackages` | Union (dedup by ecosystem:name) | Combine all targets |
| `description` | Prefer NVD | NVD descriptions are more standardized |
| `lastUpdated` | Max (newest) | Track freshest data |

### Escalation Detection

After dedup and re-scoring, if a vulnerability's priority improved (e.g., P1 -> P0 because KEV added it), a separate "ESCALATED" message is sent to the appropriate webhook. A vulnerability that previously fell below P0/P1 thresholds (and was therefore never stored) and now meets them is treated as a new finding, not an escalation -- the system never tracked it before.

---

## 5. Security Posture

### Credential Management

| Secret | Storage | Usage | Required? |
|--------|---------|-------|-----------|
| `SLACK_WEBHOOK_URL` | `.env` (gitignored) | POST body to Slack for P0 alerts | Yes |
| `SLACK_WEBHOOK_P1` | `.env` (gitignored) | POST body to Slack for P1 alerts | No (P1 silently skipped when unset) |
| `NVD_API_KEY` | `.env` (gitignored) | `apiKey` HTTP header | No (10x rate limit improvement) |
| `GITHUB_TOKEN` | `.env` (gitignored) | `Authorization: token` header | No (83x rate limit improvement) |

**Positive findings:**
- No hardcoded credentials anywhere in source
- All secrets loaded via `vlucas/phpdotenv` from `.env`
- `.env` excluded from git via `.gitignore`
- API keys sent via HTTP headers, never in query strings (avoids URL logging)
- `SecretRedactor` + monolog processor mask webhook URLs, GitHub tokens, NVD key, Bearer tokens, and URL basic auth in all log output. The live values of `SLACK_WEBHOOK_URL`, `SLACK_WEBHOOK_P1`, `NVD_API_KEY`, and `GITHUB_TOKEN` are registered at bootstrap for exact-match scrubbing.

**Areas to monitor:**
- Secrets live in process memory during execution (unavoidable in PHP)
- No built-in secret rotation mechanism (ops responsibility)
- `.env` file permissions should be restricted (`chmod 600`)

### Input Validation

| Attack Vector | Risk | Mitigation |
|--------------|------|-----------|
| SQL Injection | None | No database |
| Command Injection | None | No shell execution from external input |
| SSRF | None | All URLs hardcoded in feed classes |
| Path Traversal | Low | `COMPOSER_LOCK_PATH` is ops-controlled |
| JSON Injection | Mitigated | `JSON_THROW_ON_ERROR` on all parse operations |
| XXE | None | No XML parsing |

### TLS/Transport Security

- `CURLOPT_SSL_VERIFYPEER => true` enforced in CurlClient
- Default curl TLS version (1.2+)
- No certificate pinning (standard practice for public APIs)
- `CURLOPT_MAXFILESIZE => 10MB` prevents response bombs
- `CURLOPT_MAXREDIRS => 3` limits redirect chains

### State File Security

- State file (`/var/lib/ase/state.json`) contains CVE IDs, scores, descriptions -- no secrets
- Atomic writes via temp file + `rename()` prevent corruption
- Corruption detection: falls back to default state on parse failure
- File locking: `LOCK_EX` for writes, `LOCK_SH` for reads

### Schema Validation

Each feed response is validated via `SchemaValidator` before processing:
- Required fields checked at root level
- Structure integrity verified
- Malformed responses logged and skipped (feed marked as failed)

---

## 6. Scaling Profile

### Resource Usage Per Run

| Resource | Typical | Worst Case | Notes |
|----------|---------|-----------|-------|
| **Memory** | 20-50 MB | ~100 MB (1000+ tracked vulns) | State loaded entirely into memory |
| **CPU** | <5s active | ~30s (large backfill) | JSON parsing dominates |
| **Network** | 2-7 MB | ~20 MB (NVD backfill) | All HTTPS |
| **Disk I/O** | ~100 KB write | ~1 MB (large state save) | Single atomic write per run |
| **Wall time** | 30-60s | ~5m (initial backfill) | Dominated by HTTP latency |

### State File Growth

| Tracked Vulns | File Size | Notes |
|---------------|-----------|-------|
| 100 | ~50-100 KB | Typical after first month |
| 500 | ~250-500 KB | Typical steady state (12-month window) |
| 1,000 | ~500 KB - 1 MB | Upper bound with broad filters |

**Pruning:** Vulnerabilities older than 365 days are removed if: already notified, not in KEV, and has a known fix.

### Concurrency Model

- **Single-threaded, single-process**
- `flock -n /tmp/ase.lock` prevents cron overlap
- If a run exceeds 30 minutes, the next cron invocation silently skips
- No threading, no async I/O, no worker pools
- This is intentional: the workload does not justify the complexity

### Scaling Limits

| Concern | Current Limit | When to Worry |
|---------|--------------|---------------|
| Feed count | 5 feeds, sequential | >15 feeds or >5min total poll time |
| State size | JSON in memory | >10,000 tracked vulns (~5 MB state) |
| Slack throughput | 1.5s between messages | >50 P0/P1 alerts in single run |
| NVD pagination | 2000/page, 1s delay | >50,000 CVEs in backfill window |

**When to scale beyond current design:**
- If monitoring >10 ecosystems across >5 teams, consider a database-backed version
- If sub-minute alerting is required, consider a webhook/streaming architecture
- Current design is appropriate for 1-5 engineering teams monitoring 1-3 ecosystems

---

## 7. Error Handling and Self-Monitoring

### Exception Boundaries

Each major phase has its own try/catch. A failure in one feed does not affect others:

```
Feed polling:   per-feed boundary -> skip feed, log, continue
EPSS enrichment: per-batch boundary -> continue without scores
Slack sending:  per-message boundary -> log, send next
State loading:  corruption detection -> reset to defaults
```

### Feed Health Tracking

Per-feed tracking of:
- `last_success` timestamp
- `last_failure` timestamp
- `consecutive_failures` count
- Error logged at ERROR level after 3+ consecutive failures

### Logging

Two handlers:
1. **Rotating file** (`/var/log/ase/ase.log`): DEBUG level, 7-day rotation
2. **stderr**: INFO level (visible in cron output)

All log entries include structured context arrays (feed name, status codes, error messages).

### Dead Man's Switch

After each successful run, a heartbeat file is written:
- Path: `/var/run/ase/last_success.txt`
- Content: ISO 8601 timestamp
- `bin/heartbeat.sh` checks file age; alerts if >24 hours stale
- Can be wired into any monitoring system (Nagios, Datadog, PagerDuty)

### Weekly Digest

Every Sunday, a summary is posted to #security-alerts:
- Total tracked vulnerabilities
- Total notified / escalated
- Per-feed health status
- State file size

---

## 8. Slack Message Design

### Routing

| Priority | Webhook | Format |
|----------|---------|--------|
| P0 | `SLACK_WEBHOOK_URL` | Individual message per vulnerability |
| P1 | `SLACK_WEBHOOK_P1` (optional) | Individual message per vulnerability; silently skipped when unset |
| Escalation | Same webhook as the current priority | Individual, marked "ESCALATED" |

Slack incoming webhooks are channel-scoped, so two webhooks means two channels. `SLACK_CHANNEL_CRITICAL` and `SLACK_CHANNEL_ALERTS` env vars were removed -- the channel is implicit in each webhook.

### Message Structure (P0/P1)

Messages use Slack Block Kit and are designed for both leadership and engineers:

1. **Headline** -- leads with the scariest fact (KEV > ransomware > affects-installed > priority label)
2. **Impact summary** -- plain English: "This vulnerability is being actively exploited in the wild"
3. **Action required** -- concrete: "`composer update magento/framework` to 2.4.7-p1"
4. **Deadline** -- CISA mandate date if applicable
5. **Affected packages** -- ecosystem, name, vulnerable range, fix version (up to 3)
6. **Raw scores** -- CVSS, EPSS percentile, KEV status, CWEs
7. **Reference buttons** -- links to NVD, GitHub advisory, vendor page (up to 5)
8. **Footer** -- CVE ID, source feeds, "A.S.E." attribution

### Color Coding

| Priority | Color |
|----------|-------|
| P0 | #FF0000 (red) |
| P1 | #FF6600 (orange) |

### Throttling

1.5 seconds between Slack messages to avoid rate limiting. Slack's documented limit is 1 message/second per webhook.

---

## 9. Testing Coverage

### What Is Tested

| Component | Tests | Coverage |
|-----------|-------|----------|
| Priority calculation | 13 tests | All tier boundaries, CVSS fallback, ransomware, installed version |
| Deduplication | 13+ tests | Alias resolution, merge logic, CVSS max, multi-batch |
| Slack messages | 11+ tests | Block Kit structure, URL parsing, formatting |
| State persistence | 8+ tests | Load/save cycle, corruption recovery, first run |
| Schema validation | Tests | Per-feed schema checks |
| Value objects | Tests | Immutability, serialization round-trips |
| HTTP response | Tests | JSON parsing, status code checks |
| ComposerLock analyzer | Tests | Semver matching, installed version detection |

### What Is Not Tested

- Real API calls (feeds rely on live data -- too flaky for CI)
- Real Slack posting
- Full Ase.php orchestration end-to-end
- Feed-specific parsing logic (only models and scoring tested)

### Static Analysis

PHPStan level 8 (strict) via `phpstan.neon`. Catches type errors, unreachable code, and missing return types at build time.

---

## 10. Dependencies

### Production (3 packages)

| Package | Version | Purpose | Risk |
|---------|---------|---------|------|
| `composer/semver` | 3.4.4 | Version constraint parsing for composer.lock matching | Low -- stable, mature |
| `monolog/monolog` | 3.10 | PSR-3 structured logging with rotation | Low -- industry standard |
| `vlucas/phpdotenv` | 5.6 | `.env` file loading | Low -- simple, well-maintained |

No known CVEs in any production dependency as of April 2026.

### Development (2 packages)

| Package | Version | Purpose |
|---------|---------|---------|
| `phpunit/phpunit` | 13.1 | Unit testing |
| `phpstan/phpstan` | 2.1 | Static analysis (level 8) |

Development dependencies are excluded from production (`composer install --no-dev`).

---

## 11. Configuration Reference

### Required

```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
```

### Strongly Recommended

```bash
NVD_API_KEY=your-key-here           # 10x rate limit improvement
GITHUB_TOKEN=ghp_xxxxx              # 83x rate limit improvement
```

### Optional

```bash
# Cross-reference your installed packages.
# REQUIRED for production deploys where ASE lives outside the Magento project
# (cron under /opt/ase, containers, etc.). Auto-discovery via walk-up from
# getcwd() only works when ASE is invoked from inside the project tree.
COMPOSER_LOCK_PATH=/var/www/magento/composer.lock

# Feed selection (default: all)
ENABLED_FEEDS=kev,nvd,ghsa,osv,packagist

# Ecosystem filtering -- all three are AUTO-DETECTED from composer.lock.
# Env values are ADDITIVE for the list fields and OVERRIDE for the scalar.
# Leave empty unless you need to extend or replace the auto-detected defaults.
ECOSYSTEMS=
VENDOR_FILTER=
NVD_CPE_PREFIX=

# Slack -- P1 webhook is optional
SLACK_WEBHOOK_P1=

# File paths
STATE_FILE=/var/lib/ase/state.json
LOG_FILE=/var/log/ase/ase.log
HEARTBEAT_FILE=/var/run/ase/last_success.txt

# Poll intervals (seconds)
POLL_INTERVAL_KEV=7200
POLL_INTERVAL_NVD=7200
POLL_INTERVAL_GHSA=1800
POLL_INTERVAL_OSV=1800
POLL_INTERVAL_PACKAGIST=3600

# Scoring thresholds
CVSS_CRITICAL_THRESHOLD=9.0
CVSS_HIGH_THRESHOLD=7.0
EPSS_HIGH_THRESHOLD=0.10
```

---

## 12. Deployment

### Installation

```bash
git clone <repo> /opt/ase
cd /opt/ase
composer install --no-dev --optimize-autoloader
cp .env.example .env
# Edit .env with production secrets
chmod 600 .env

mkdir -p /var/lib/ase /var/log/ase /var/run/ase
chown <service-user> /var/lib/ase /var/log/ase /var/run/ase
```

### Cron

```bash
# Main run: every 30 minutes
*/30 * * * * /usr/bin/flock -n /tmp/ase.lock /usr/bin/php /opt/ase/bin/ase.php >> /var/log/ase/cron.log 2>&1

# Heartbeat check: hourly
30 * * * * /opt/ase/bin/heartbeat.sh
```

### CLI Modes

```bash
php bin/ase.php                    # Normal run
php bin/ase.php --since 2024-01-01 # Backfill from date
php bin/ase.php --test-slack       # Test Slack connectivity
php bin/ase.php --test-alert       # Fetch + send a real test alert
```

### Monitoring

```bash
cat /var/run/ase/last_success.txt          # Last successful run
jq '.stats' /var/lib/ase/state.json        # Current stats
tail -f /var/log/ase/ase.log               # Live logs
jq '.feed_health' /var/lib/ase/state.json  # Per-feed health
```

---

## 13. Risk Register

### Security Risks

| Risk | Likelihood | Impact | Mitigation | Status |
|------|-----------|--------|-----------|--------|
| API key leak in logs | Low | High | Keys sent via headers only, never logged | Mitigated |
| State file tampering | Low | Medium | Filesystem ACLs, no secrets in state | Mitigated |
| Feed API compromise (poisoned data) | Very Low | High | Schema validation, manual review of P0 alerts | Partially mitigated |
| Slack webhook URL leak | Low | Medium | `.env` gitignored, `chmod 600` | Mitigated |
| TLS downgrade | Very Low | High | `CURLOPT_SSL_VERIFYPEER=true` enforced | Mitigated |

### Operational Risks

| Risk | Likelihood | Impact | Mitigation | Status |
|------|-----------|--------|-----------|--------|
| Feed goes permanently offline | Medium | Medium | Per-feed health tracking, skip and continue | Mitigated |
| NVD rate limiting during backfill | Medium | Low | Exponential backoff, API key recommended | Mitigated |
| State file corruption | Low | Medium | Atomic writes, corruption detection with reset | Mitigated |
| Cron stops running | Low | High | Heartbeat dead man's switch | Mitigated |
| Alert fatigue (too many P0s) | Low | Medium | Three-signal scoring, configurable thresholds | Mitigated |

### Scaling Risks

| Risk | Likelihood | Impact | Mitigation | Status |
|------|-----------|--------|-----------|--------|
| State file grows unbounded | Low | Low | 365-day pruning | Mitigated |
| Run exceeds 30m window | Very Low | Low | flock prevents overlap | Mitigated |
| Slack message flood | Low | Medium | 1.5s throttle; only P0 and P1 alert (P2+ filtered out before notification); first run is silent | Mitigated |

---

## 14. Recommendations

### Short-term (next sprint)

1. **Add feed failure alerting** -- post to Slack when any feed hits 3+ consecutive failures
2. **Add integration test fixtures** -- VCR-style recorded API responses for feed parsing tests
3. **Document runbook** -- common failure scenarios and recovery steps

### Medium-term (next quarter)

4. **Feed parsing unit tests** -- each feed's `parse()` method tested with real-world fixtures
5. **End-to-end orchestration test** -- mock all feeds, verify full pipeline
6. **Automated dependency auditing** -- `composer audit` in CI

### Long-term (if scaling required)

7. **Database backend** -- if tracking >5,000 vulns or needing historical queries
8. **Async feed polling** -- if adding >10 feeds or needing sub-minute latency
9. **Multi-team routing** -- per-team Slack channels based on ecosystem/package ownership

---

## 15. Grades

| Category | Grade | Summary |
|----------|-------|---------|
| **Security** | A- | Proper secret management, TLS enforcement, input validation, no injection vectors. Minor: no cert pinning, no encryption at rest. |
| **Code Quality** | A | Clean DI, immutable value objects, PHPStan level 8, good test-to-code ratio. |
| **Operations** | A | Cron-friendly, atomic state, heartbeat monitoring, weekly digest. |
| **Architecture** | A | Clear separation of concerns, modular feeds, alias-aware dedup, three-signal scoring. |
| **Testing** | B+ | Core logic well-tested. Gaps in feed parsing and integration coverage. |

---

*Generated by A.S.E. audit -- April 7, 2026*
