# ASE -- Automated Security Evaluator

[![Packagist Version](https://img.shields.io/packagist/v/infinri/ase.svg)](https://packagist.org/packages/infinri/ase)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Vulnerability management built around [OWASP Dependency-Track](https://dependencytrack.org/):
Dependency-Track is the engine and UI; A.S.E is the automation that feeds it and alerts
from it. Get told about a CVE only when it affects something you actually run, in the
Slack channel of the team that owns it, ranked by real-world exploitability.

> The original 1.0.0 A.S.E was a standalone feed-polling CLI; it lives on at tag
> [`mvp-final`](https://github.com/infinri/A.S.E/releases). The 2.x rebuild moved feed
> ingestion and matching to Dependency-Track and kept the parts that earned it: the
> KEV/EPSS/CVSS scoring and the Slack alert format. Why and how:
> [docs/planning/](docs/planning/), [docs/parity-report.md](docs/parity-report.md).

## How it fits together

```
composer.lock files ──┐
                      ├── bin/ase-sync ──> Dependency-Track <── NVD / OSV / EPSS mirrors
declared-tech.yaml ───┘                      (engine + UI)
                                                  │ findings
                                            bin/ase-alert
                                  (P0/P1 scoring: CISA KEV + EPSS + CVSS)
                                                  │
                                    per-team Slack channels (by project tag)
```

- **`bin/ase-sync`** (cron): converts each configured lockfile (`ASE_PROJECTS`) and the
  declared-tech inventory ([inventory/declared-tech.yaml](inventory/declared-tech.yaml),
  one Dependency-Track project per owning team) into CycloneDX SBOMs and uploads them.
- **`bin/ase-alert`** (cron): reads new findings, classifies P0/P1, posts to the owning
  team's webhook (`ASE_ALERT_ROUTES`). P0: in CISA's Known Exploited Vulnerabilities
  catalog, or CVSS >= 9.0 with EPSS >= 10%. P1: ransomware-associated, or high severity
  affecting an installed version. Below P1 stays in the UI, off Slack.
- **Dependency-Track** does everything else: feed mirroring, version matching,
  dashboards, audit trails, policy. One-time install: [docs/dependency-track-install.md](docs/dependency-track-install.md)
  (including the required `bin/dtrack-enable-osv.sh` step).

## Setup

Prerequisites: PHP 8.4+, composer, a running Dependency-Track instance (install doc above).

    composer install
    cp .env.example .env    # set DTRACK_URL, DTRACK_API_KEY, ASE_PROJECTS, ASE_ALERT_ROUTES

Cron, on a host that can reach Dependency-Track and the lockfiles:

    */30 * * * *  cd /opt/ase && bin/ase-sync
    */30 * * * *  cd /opt/ase && sleep 600 && bin/ase-alert

First-run note: ase-alert alerts on every existing alert-worthy finding. For a quiet
adoption, run it once before configuring `ASE_ALERT_ROUTES`; see the
[runbook](docs/runbook.md), which also covers SLAs and what to do when an alert lands.

## Development

    composer test          # PHPUnit
    composer stan          # PHPStan, level 8

CI gates merges on `composer audit`, PHPStan, and the test suite.

## License

MIT. See [LICENSE](LICENSE).
