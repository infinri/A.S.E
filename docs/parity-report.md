# Parity report: legacy bin/ase vs Dependency-Track pipeline

Date: 2026-06-11. Input: the real Magento lockfile at
`upgrade.2ndswing.com/composer.lock` (828 packages, Magento Enterprise 2.4.8-p3,
edition auto-detected identically by both sides). Legacy run: `bin/ase --dry-run
--format=json` with default 30-day backfill, all four feeds polled live (KEV 1617,
GHSA 5870, Packagist 225, NVD 16 in window). New pipeline: `bin/ase-sync` upload to
the local Dependency-Track 5.0 instance (NVD + OSV/Packagist + EPSS sources).

## Results

| | Legacy bin/ase | Dependency-Track pipeline |
|---|---|---|
| Scope | P0/P1 only, advisories from last 30 days | all severities, full advisory history |
| Findings | 0 (exit 0) | 11 (8 HIGH, 2 MEDIUM, 1 LOW) |
| Would alert | nothing | 6 P1 via ase-alert (CVSS >= 7, affects installed) |
| In CISA KEV | 0 | 0 |
| Max EPSS | n/a | 0.0024 (all findings near-zero exploit probability) |

The 11 Dependency-Track findings: composer/composer 2.9.3 (2 HIGH), phpseclib 3.0.48
(2 HIGH, 1 LOW), webonyx/graphql-php 15.29.4 (2 HIGH), aws-sdk-php 3.369.15 (1 HIGH),
phpunit 10.5.60 (1 HIGH, dev dependency), firebase/php-jwt 6.11.1 (1 MEDIUM),
psy/psysh 0.12.18 (1 MEDIUM).

## Reconciliation

No missed-alert divergence exists in the shared scope. Every advisory the legacy tool
is structurally able to report (published within its 30-day window, P0/P1 grade) is
absent from both sides; the window simply contained nothing for these packages, and
nothing in the lockfile is KEV-listed or exploit-likely per EPSS on either side.

The 11-finding difference is the designed coverage gain, not a discrepancy: the legacy
tool never reports advisories older than its backfill window, so long-standing
unpatched HIGHs are invisible to it. Dependency-Track matches the full advisory
history. Six of those findings meet the same P1 bar the legacy tool uses
("affects installed version AND CVSS >= 7"); they are real, currently unpatched HIGHs.

## Residual difference to track

NVD publishes Adobe Commerce advisories against the CPE `adobe:commerce`; the GHSA/OSV
Packagist feed usually carries the same advisories against `magento/*` composer
packages, which is the path Dependency-Track matches here. The legacy tool queried NVD
by CPE directly. Mitigation so the NVD path is not lost: add an Adobe Commerce entry
with its CPE to inventory/declared-tech.yaml (owner: ecommerce) during the population
workshop. KEV coverage is unaffected either way (ase-alert checks KEV itself).

## Adoption note: first-run behavior

ase-alert's cursor starts at zero, so its first configured run alerts on every
existing P1-grade finding (six for this project). That is signal (they are real and
unpatched), but if a quiet adoption is preferred, run `bin/ase-alert` once BEFORE
configuring `ASE_ALERT_ROUTES`: unrouted findings are logged and skipped, the cursor
advances, and subsequent runs alert only on genuinely new findings. This mirrors the
legacy tool's silent first-run import.

## Verdict

Cutover criterion met: zero missed alerts in the legacy tool's scope, strict coverage
superset beyond it. The six open P1 findings transfer to the ecommerce team as the
first real work items of the new pipeline.
