# A.S.E. -- (All Seeing Eye)

Lightweight PHP CLI tool that polls security feeds, deduplicates and prioritizes vulnerabilities using a three-signal system (CVSS + EPSS + KEV), and posts filtered alerts to Slack.

## Requirements

### PHP 8.4+

A.S.E. uses PHP 8.4 features: readonly classes, backed enums, typed constants, `#[Override]` attribute, property promotion, match expressions.

**Required extensions:**

| Extension | Purpose | Check |
|-----------|---------|-------|
| curl | HTTP requests to all feed APIs | `php -m \| grep curl` |
| json | Parsing API responses and state file | Built-in since PHP 8.0 |
| mbstring | String truncation in vulnerability descriptions | `php -m \| grep mbstring` |
| fileinfo | File type detection (Composer dependency) | `php -m \| grep fileinfo` |

**Optional extensions:**

| Extension | Purpose |
|-----------|---------|
| pdo_sqlite | Future state migration when JSON flat-file outgrows its architecture |

**CLI memory_limit:** PHP CLI defaults to `-1` (unlimited). No configuration change needed. A.S.E. runs as a cron job, not a web request.

### System Dependencies

- **Composer** 2.x -- dependency management
- **cron** -- scheduling
- **flock** -- prevents overlapping cron runs (part of util-linux, installed on all Linux distros)

## Installation

```bash
# Clone
git clone <repo-url> /opt/ase
cd /opt/ase

# Install dependencies
composer install --no-dev --optimize-autoloader

# Configure
cp .env.example .env
# Edit .env with your API keys and Slack webhook URL

# Create directories for state, logs, and heartbeat
sudo mkdir -p /var/lib/ase /var/log/ase /var/run/ase
sudo chown $(whoami) /var/lib/ase /var/log/ase /var/run/ase
```

## Configuration

Copy `.env.example` to `.env` and configure:

### Required

| Variable | Description |
|----------|-------------|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL (create via Slack App) |

### Recommended

| Variable | Description | Default |
|----------|-------------|---------|
| `NVD_API_KEY` | Free NVD API key (50 req/30s vs 5 without) | none |
| `GITHUB_TOKEN` | GitHub personal access token (higher rate limits) | none |
| `COMPOSER_LOCK_PATH` | Path to your project's composer.lock for version matching | none |

### Feed Control

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLED_FEEDS` | Comma-separated list of feeds to poll | `kev,nvd,ghsa,osv,packagist` |
| `ECOSYSTEMS` | Comma-separated ecosystems to monitor | `composer,npm` |
| `VENDOR_FILTER` | Comma-separated vendor names for KEV filtering | `adobe,magento` |
| `NVD_CPE_PREFIX` | CPE prefix for NVD tech-stack filtering | none |

### Poll Intervals (seconds)

| Variable | Default | Notes |
|----------|---------|-------|
| `POLL_INTERVAL_KEV` | 7200 | CISA KEV updates on weekday business hours |
| `POLL_INTERVAL_NVD` | 7200 | NIST recommends no more than every 2 hours |
| `POLL_INTERVAL_GHSA` | 1800 | GitHub Advisories, 30 min |
| `POLL_INTERVAL_OSV` | 1800 | OSV, 30 min |
| `POLL_INTERVAL_PACKAGIST` | 3600 | Packagist Security Advisories, 1 hour |

### Priority Thresholds

| Variable | Default | Description |
|----------|---------|-------------|
| `CVSS_CRITICAL_THRESHOLD` | 9.0 | P0 trigger when combined with EPSS |
| `CVSS_HIGH_THRESHOLD` | 7.0 | P1/P2 boundary |
| `CVSS_MEDIUM_THRESHOLD` | 4.0 | P3/P4 boundary |
| `EPSS_HIGH_THRESHOLD` | 0.10 | 10% exploit probability threshold |
| `EPSS_MEDIUM_THRESHOLD` | 0.05 | 5% exploit probability threshold |

## Getting API Keys

**NVD API Key** (free, increases rate limit 10x):
1. Go to https://nvd.nist.gov/developers/request-an-api-key
2. Enter your email, request key
3. Set `NVD_API_KEY` in `.env`

**GitHub Token** (optional, increases rate limit):
1. Go to https://github.com/settings/tokens
2. Generate new token (classic) -- no scopes needed for public advisory access
3. Set `GITHUB_TOKEN` in `.env`

**Slack Webhook**:
1. Go to https://api.slack.com/apps -- create a new app
2. Enable Incoming Webhooks
3. Add webhook to your target channel
4. Set `SLACK_WEBHOOK_URL` in `.env`
5. Optionally set `SLACK_CHANNEL_CRITICAL` and `SLACK_CHANNEL_ALERTS`

**KEV, OSV, EPSS, Packagist**: No authentication required.

## Running

### Manual Run

```bash
php bin/ase.php
```

### First Run (Silent Import)

The first run populates the state file without sending Slack notifications. All existing vulnerabilities are marked as "already notified" at their current priority. Subsequent runs only alert on new vulnerabilities or priority escalations.

### Backfill from a Specific Date

```bash
php bin/ase.php --since 2024-01-01
```

### Cron Setup

```crontab
# A.S.E. main run -- every 30 minutes, flock prevents overlap
*/30 * * * * /usr/bin/flock -n /tmp/ase.lock /usr/bin/php /opt/ase/bin/ase.php >> /var/log/ase/cron.log 2>&1

# Heartbeat check -- hourly
30 * * * * /opt/ase/bin/heartbeat.sh
```

The cron runs every 30 minutes. Feeds with longer poll intervals (KEV at 2h, NVD at 2h) automatically skip runs where their interval hasn't elapsed.

### Feed Rollback

To disable a problematic feed without code changes:

```bash
# In .env, remove the feed from ENABLED_FEEDS
ENABLED_FEEDS=kev,nvd,ghsa
# Removes osv and packagist from polling
```

## Priority System

A.S.E. uses three signals to classify vulnerability urgency:

| Priority | Criteria | Notification |
|----------|----------|--------------|
| **P0** Immediate | In CISA KEV, OR (CVSS >= 9.0 AND EPSS >= 10%) | Individual alert to #security-critical |
| **P1** Urgent | (CVSS >= 7.0 AND EPSS >= 10%), OR known ransomware, OR affects installed version with CVSS >= 7.0 | Individual alert to #security-critical |
| **P2** Soon | CVSS >= 7.0 OR EPSS >= 5% | Batched digest to #security-alerts |
| **P3** Monitor | CVSS >= 4.0 AND EPSS < 5% | Logged only |
| **P4** Track | Everything else | Logged only |

**Escalation re-notification:** If a vulnerability's priority increases (e.g., added to CISA KEV, EPSS spike), a new alert fires with the escalation context, even if the vulnerability was previously notified at a lower tier.

## Data Feeds

| Feed | API | Auth | Rate Limit | Poll Default |
|------|-----|------|------------|--------------|
| CISA KEV | Static JSON | None | None | 2h |
| NVD v2.0 | REST | API key (free) | 50 req/30s | 2h |
| GitHub Advisories | REST | Token (optional) | 5,000 pts/hr | 30m |
| OSV | REST/POST | None | None documented | 30m |
| Packagist | REST | None | None documented | 1h |
| EPSS | REST | None | None documented | Per-run enrichment |

## Self-Monitoring

- **Heartbeat**: `bin/heartbeat.sh` checks if the last successful run was within 24 hours. Alerts via syslog if stale.
- **Feed health**: Tracks consecutive failures per feed. At 3+ failures, logs ERROR.
- **Weekly digest**: Posts a summary to Slack every Sunday with feed health, tracked vulnerabilities, and state file size.
- **Schema validation**: Warns on missing expected fields in API responses (catches API schema drift).

## Development

```bash
# Install with dev dependencies
composer install

# Run tests
vendor/bin/phpunit

# Static analysis
vendor/bin/phpstan analyse

# Syntax check all files
find src -name '*.php' -exec php -l {} \;
```

## Project Structure

```
ase/
  bin/
    ase.php                     # CLI entry point
    heartbeat.sh                # Dead man's switch
  src/
    Ase.php                     # Main orchestrator
    Config.php                  # .env configuration loader
    Feed/
      FeedInterface.php         # Feed contract
      KevFeed.php               # CISA KEV
      NvdFeed.php               # NVD API v2.0
      GitHubAdvisoryFeed.php    # GitHub Security Advisories
      OsvFeed.php               # OSV API
      PackagistAdvisoryFeed.php # Packagist Security Advisories
      EpssFeed.php              # EPSS enrichment (not a polling feed)
    Model/
      Priority.php              # P0-P4 backed enum
      Vulnerability.php         # Canonical vulnerability record
      VulnerabilityBatch.php    # Collection from single feed poll
      AffectedPackage.php       # Package + version range
      FeedHealth.php            # Per-feed health state
    State/
      StateManager.php          # JSON flat-file with flock + atomic writes
    Scoring/
      PriorityCalculator.php    # CVSS + EPSS + KEV -> Priority
    Dedup/
      Deduplicator.php          # Cross-feed merge logic
      DeduplicatorResult.php    # Merge result container
    Notify/
      SlackNotifier.php         # Alert routing and throttling
      SlackMessage.php          # Block Kit message builder
    Filter/
      ComposerLockAnalyzer.php  # composer.lock cross-reference
    Health/
      FeedHealthTracker.php     # Per-feed success/failure tracking
      SchemaValidator.php       # API response structure validation
      DigestReporter.php        # Weekly Slack summary
    Http/
      CurlClient.php            # HTTP wrapper with retry/backoff
      HttpResponse.php          # Response value object
  tests/
  .env.example
  composer.json
  phpunit.xml
  phpstan.neon
  plan.md                       # Full implementation blueprint
```
