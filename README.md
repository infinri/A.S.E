# ASE -- Automated Security Evaluator

CVE monitoring for Magento / Adobe Commerce / Mage-OS stores. One command, one Slack channel, one exit code for CI.

---

## Why this exists

Magento stores live downstream of a noisy security ecosystem. CISA KEV, NVD, GitHub Security Advisories, OSV, and Packagist each publish vulnerability data with different coverage, latency, and signal-to-noise. Reading all five by hand is nobody's job. Skipping them is how stores get popped.

Most teams land in one of two failure modes:

- **Alert fatigue.** A generic CVE feed pipes every CVSS >= 7 into Slack. After day three, the channel is muted. After week one, a real P0 gets missed.
- **Blind spots.** The team subscribes to a single source (usually Adobe's security bulletin) and misses KEV additions, Packagist advisories for third-party modules, and EPSS spikes on old CVEs.

ASE closes both gaps. It polls all five feeds, deduplicates across them, filters against your `composer.lock` so it only shows CVEs that actually affect installed versions, scores every finding with CVSS + EPSS + KEV, and alerts on just P0 and P1 -- the two tiers worth a ping. Anything below P1 is dropped before notification so the Slack channel stays signal. First run imports the current state silently so you don't get a 40-alert Monday morning. Subsequent runs alert on new findings and priority escalations.

It is a CLI. It runs under cron. It exits `0`, `1`, or `2` based on what it found, so you can gate a CI pipeline on it. That's the whole surface.

## What it catches

A KEV-listed RCE drops against a Magento module you have installed. ASE polls KEV on its next cycle, matches the CVE's vulnerable range against your `composer.lock`, classifies it as P0, posts a Slack alert with:

- CVE ID and canonical description
- CVSS score and vector, EPSS percentile, KEV status
- Exact installed version vs. fixed version
- Links to NVD, GHSA (if cross-referenced), and the Packagist page for the fixed release
- A one-line composer update command to remediate

If you ran it in CI that same hour, `ase --dry-run --format=json` would have exited `2` and failed the deploy.

## Quick start

```bash
# Install globally (adds `ase` to your PATH)
composer global require infinri/ase

# Minimal config: one Slack webhook
export SLACK_WEBHOOK_URL='https://hooks.slack.com/services/...'

# Walk into your Magento project and scan without sending alerts
cd /path/to/your/magento/project
ase --dry-run --format=json
```

`--dry-run` doesn't touch Slack or persist state. `--format=json` emits a machine-readable report to stdout while logs stay on stderr. Together they're the safe way to evaluate ASE before wiring it into a real channel.

When you're ready for notifications, drop `--dry-run` and schedule under cron (example below).

## CLI reference

```
ase [flags]

Flags:
  --dry-run                Scan but do not send Slack alerts or persist state
  --format=<human|json>    Output format (default: human)
  --since <YYYY-MM-DD>     Backfill from a specific date (first run only)
  --test-slack             Send a test message to the configured channel and exit
  --test-alert             Send a P0 sample (and a P1 sample if SLACK_WEBHOOK_P1 is set) for wiring verification

Exit codes:
  0                        No P0 or P1 finding in the alertable set
  1                        At least one P1 (and no P0) in the alertable set
  2                        At least one P0 in the alertable set, or a fatal config error
```

The alertable set is what *this run* would alert on: new findings plus priority escalations. Already-notified findings at the same priority don't count.

## Configuration

Configuration is env-driven. Either export variables in your shell, drop them in a `.env` next to the binary, or put them in your system cron environment.

### Required (for normal runs)

| Variable | Description |
|---|---|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL. Optional when using `--dry-run` or `--format=json`. |

### Recommended

| Variable | Description | Default |
|---|---|---|
| `NVD_API_KEY` | Free NVD API key (lifts rate limit from 5 to 50 req/30s) | none |
| `GITHUB_TOKEN` | GitHub PAT, public scope is enough (higher GHSA rate limit) | none |
| `COMPOSER_LOCK_PATH` | Explicit path to your project's `composer.lock`. Only needed if ASE can't find one by walking up from CWD. | auto-discovered |
| `SLACK_WEBHOOK_P1` | Optional second webhook for P1 alerts. When unset, P1 alerts are silently skipped (logged as a warning). | none |

### Feed control

| Variable | Description | Default |
|---|---|---|
| `ENABLED_FEEDS` | Comma-separated list of feeds to poll | `kev,nvd,ghsa,osv,packagist` |
| `ECOSYSTEMS` | **Additive** -- merged with `composer` (auto-detected from your lockfile) | empty |
| `VENDOR_FILTER` | **Additive** -- merged with vendor names parsed from your `composer.lock` (KEV filtering) | empty |
| `NVD_CPE_PREFIX` | **Override** -- if set, replaces the auto-detected CPE. Auto-detection maps Magento edition: community -> `cpe:2.3:a:magento:magento`, enterprise -> `cpe:2.3:a:adobe:commerce` | auto |

### Poll intervals (seconds)

| Variable | Default | Notes |
|---|---|---|
| `POLL_INTERVAL_KEV` | 7200 | CISA KEV updates on business hours |
| `POLL_INTERVAL_NVD` | 7200 | NIST recommends no more than every 2 hours |
| `POLL_INTERVAL_GHSA` | 1800 | GitHub Advisories, 30 min |
| `POLL_INTERVAL_OSV` | 1800 | OSV, 30 min |
| `POLL_INTERVAL_PACKAGIST` | 3600 | Packagist, 1 hour |

### Priority thresholds

| Variable | Default | Description |
|---|---|---|
| `CVSS_CRITICAL_THRESHOLD` | 9.0 | P0 trigger when combined with EPSS |
| `CVSS_HIGH_THRESHOLD` | 7.0 | P1 boundary |
| `EPSS_HIGH_THRESHOLD` | 0.10 | 10% exploit probability threshold |

## Priority system

ASE only tracks and alerts on P0 and P1 findings. Anything below those thresholds is dropped before notification or persistence.

| Priority | Criteria | Notification |
|---|---|---|
| **P0** Immediate | In CISA KEV, OR (CVSS >= 9.0 AND EPSS >= 10%) | `SLACK_WEBHOOK_URL`, exit code 2 |
| **P1** Urgent | (CVSS >= 7.0 AND EPSS >= 10%), OR known ransomware, OR affects installed version with CVSS >= 7.0 | `SLACK_WEBHOOK_P1` if set, else skipped with a one-line warning. Exit code 1. |

**Two-webhook model.** Slack incoming webhooks are channel-scoped. P0 always posts to `SLACK_WEBHOOK_URL` -- the only required webhook. P1 posts to a separate `SLACK_WEBHOOK_P1` webhook when you want those alerts in a different channel; leave it unset to suppress P1 alerts entirely.

**Escalation re-notification:** If a vulnerability's priority increases (e.g., added to CISA KEV, EPSS spike), a new alert fires with escalation context, even if previously notified at a lower tier.

## Getting API keys

**NVD API Key** (free, 10x rate limit):
1. https://nvd.nist.gov/developers/request-an-api-key
2. Enter email, request key
3. Set `NVD_API_KEY`

**GitHub Token** (optional):
1. https://github.com/settings/tokens
2. Generate token (classic) -- no scopes needed for public advisories
3. Set `GITHUB_TOKEN`

**Slack Webhook**:
1. https://api.slack.com/apps -- create a new app
2. Enable Incoming Webhooks, add to target channel
3. Set `SLACK_WEBHOOK_URL`

KEV, OSV, EPSS, and Packagist need no authentication.

## Advanced deployment

For production you'll typically deploy under cron with dedicated log/state directories rather than relying on `composer global`'s user-scoped install.

```bash
git clone https://github.com/infinri/A.S.E.git /opt/ase
cd /opt/ase
composer install --no-dev --optimize-autoloader

cp .env.example .env
# edit .env

sudo mkdir -p /var/lib/ase /var/log/ase /var/run/ase
sudo chown "$(whoami)" /var/lib/ase /var/log/ase /var/run/ase
```

### Cron

```crontab
# Main run every 30 minutes, flock prevents overlap
*/30 * * * * /usr/bin/flock -n /tmp/ase.lock /opt/ase/bin/ase >> /var/log/ase/cron.log 2>&1

# Heartbeat, hourly
30 * * * * /opt/ase/bin/heartbeat.sh
```

Feeds with longer poll intervals (KEV, NVD at 2h) automatically skip runs where their interval has not elapsed.

### Disabling a feed

Remove its name from `ENABLED_FEEDS` in `.env`. No code change needed.

```
ENABLED_FEEDS=kev,nvd,ghsa
# osv and packagist now skipped
```

## Self-monitoring

- **Heartbeat:** `bin/heartbeat.sh` alerts via syslog if the last successful run was >24h ago.
- **Feed health:** consecutive failures per feed are tracked; 3+ failures logs ERROR.
- **Schema drift:** warnings on missing expected fields in API responses.

## Requirements

- PHP 8.4+ with `curl`, `json`, `mbstring`, `fileinfo`
- Composer 2.x
- `flock` (util-linux) if running under cron

Optional: `pdo_sqlite` for a future state migration.

## Development

```bash
git clone https://github.com/infinri/A.S.E.git
cd A.S.E
composer install

composer test           # phpunit
composer stan           # phpstan level 8
```

## Architecture

Deep dive: [`HANDBOOK.md`](HANDBOOK.md) covers module layout, scoring internals, feed contracts, state file schema, and operational playbook.

## License

MIT. See [`LICENSE`](LICENSE).

## Security

Report vulnerabilities in ASE itself privately. See [`SECURITY.md`](SECURITY.md).
