# A.S.E -- Automated Security Evaluator

[![Packagist Version](https://img.shields.io/packagist/v/infinri/ase.svg)](https://packagist.org/packages/infinri/ase)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Vulnerability management built around [OWASP Dependency-Track](https://dependencytrack.org/).
Dependency-Track is the engine and UI; A.S.E is the thin automation that feeds it and
alerts from it. You hear about a CVE only when it affects something you actually run, in
the Slack channel of the team that owns it, ranked by real-world exploitability.

> The original 1.0.0 A.S.E was a standalone feed-polling CLI; it lives on at tag
> [`mvp-final`](https://github.com/infinri/A.S.E/releases). The 2.x rebuild moved feed
> ingestion and version matching into Dependency-Track and kept the parts that earned
> their place: KEV/EPSS/CVSS scoring and the Slack alert format. Rationale and parity
> evidence: [docs/planning/](docs/planning/), [docs/parity-report.md](docs/parity-report.md).

## How it fits together

```
composer.lock files ──┐
                      ├── bin/ase-sync ──> Dependency-Track <── NVD / OSV / EPSS mirrors
declared-tech.yaml ───┘    (CycloneDX SBOMs)   (engine + UI)
                                                  │ findings
                                            bin/ase-alert
                                  (P0/P1 scoring: CISA KEV + EPSS + CVSS)
                                                  │
                                    per-team Slack channels (routed by project tag)
```

- **`bin/ase-sync`** (cron): converts each configured lockfile (`ASE_PROJECTS`) and the
  declared-tech inventory ([inventory/declared-tech.yaml](inventory/declared-tech.yaml),
  one Dependency-Track project per owning team) into CycloneDX 1.5 SBOMs and uploads
  them. Lockfiles are matched by package URL (OSV); declared-tech entries by CPE (NVD).
- **`bin/ase-alert`** (cron): reads findings newer than its cursor, scores each one,
  and posts the P0/P1 ones to the owning team's webhook (`ASE_ALERT_ROUTES`, keyed by
  Dependency-Track project tag). Anything below P1 stays in the UI, off Slack.
- **Dependency-Track** does everything else: feed mirroring, version matching,
  dashboards, audit trail, policy. One-time install:
  [docs/dependency-track-install.md](docs/dependency-track-install.md), including the
  **required** `bin/dtrack-enable-osv.sh` step (a fresh 5.0 instance mirrors only
  NVD+EPSS and silently matches nothing for composer/npm until OSV is enabled).

## Priority model

`ase-alert` alerts on two tiers and drops everything else. Thresholds are configurable
(see below); defaults shown.

| Tier | Condition (any one) |
|------|---------------------|
| **P0** | in CISA KEV (actively exploited) &nbsp;·&nbsp; CVSS >= 9.0 **and** EPSS >= 10% |
| **P1** | ransomware-associated &nbsp;·&nbsp; CVSS >= 7.0 on an installed component |
| (none) | everything below P1 -- visible in the Dependency-Track UI, never sent to Slack |

KEV membership and ransomware association are checked by A.S.E against the live CISA
catalog; CVSS and EPSS come from Dependency-Track's enrichment.

## Setup

Prerequisites: PHP 8.4+, Composer, and a running Dependency-Track instance (install
doc above).

```sh
composer install
cp .env.example .env     # then set the variables below
```

Minimum configuration (`.env` on the cron host):

| Variable | Required | Purpose |
|----------|----------|---------|
| `DTRACK_URL` | yes | Base URL of the Dependency-Track API server |
| `DTRACK_API_KEY` | yes | API key for the `automation` team (BOM upload + read) |
| `ASE_PROJECTS` | yes | Comma-separated `name:/abs/path/to/composer.lock` entries |
| `ASE_ALERT_ROUTES` | for alerts | Comma-separated `project-tag=slack-webhook-url` entries |
| `ASE_ALERT_DEFAULT_WEBHOOK` | no | Fallback webhook for findings whose tag has no route |
| `ASE_INVENTORY_PATH` | no | Declared-tech YAML (defaults to `inventory/declared-tech.yaml`) |
| `ASE_ALERT_CURSOR_PATH` | no | Alert cursor file (defaults to `var/state/alert-cursor.json`) |
| `EPSS_HIGH_THRESHOLD` | no | EPSS cutoff, default `0.10` |
| `CVSS_CRITICAL_THRESHOLD` | no | P0 CVSS cutoff, default `9.0` |
| `CVSS_HIGH_THRESHOLD` | no | P1 CVSS cutoff, default `7.0` |

Cron, on a host that can reach Dependency-Track and the lockfiles:

```cron
*/30 * * * *  cd /opt/ase && bin/ase-sync
*/30 * * * *  cd /opt/ase && sleep 600 && bin/ase-alert
```

The `sleep 600` lets a sync settle before the alert pass reads findings from it.

**First-run note:** the alert cursor starts at zero, so the first run alerts on every
existing P0/P1 finding. For a quiet adoption, run `bin/ase-alert` once *before*
configuring `ASE_ALERT_ROUTES` (unrouted findings are logged and skipped, the cursor
advances), then add routes. The [runbook](docs/runbook.md) covers this, the per-tier
SLAs, and what to do when an alert lands.

## Development

```sh
composer test     # PHPUnit  (138 tests)
composer stan     # PHPStan, level 8 on src/
composer audit    # dependency CVE check
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) gates every merge on all
three: `composer audit --no-dev`, PHPStan, and the unit suite.

## Project layout

```
bin/         ase-sync, ase-alert, dtrack-enable-osv.sh
src/         Sbom/ DependencyTrack/ Alert/ Scoring/ Feed/ Notify/ Http/ Logging/ Model/
inventory/   declared-tech.yaml  (no-manifest tech: appliances, SaaS, infra)
docs/        dependency-track-install.md, runbook.md, parity-report.md, planning/
tests/Unit/  PHPUnit suite
```

## Documentation

- [docs/dependency-track-install.md](docs/dependency-track-install.md) -- one-time
  Dependency-Track 5.0 install, OSV enablement, bootstrap, backup.
- [docs/runbook.md](docs/runbook.md) -- responding to alerts, SLAs, operating the platform.
- [docs/parity-report.md](docs/parity-report.md) -- 1.0 CLI vs 2.0 pipeline cutover evidence.
- [docs/planning/](docs/planning/) -- architecture and design rationale.

## License

MIT. See [LICENSE](LICENSE).
