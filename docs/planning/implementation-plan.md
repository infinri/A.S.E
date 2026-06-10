# Implementation Plan: Vulnerability Management Platform

Status: active
Date: 2026-06-10 (revised same day: single repo, no compose file, A.S.E rebuilt in place)
Parent document: [vulnerability-management-platform.md](vulnerability-management-platform.md)

Revision summary: everything lives in the A.S.E repo. Dependency-Track is installed on a
host with plain docker commands (no compose file in this repo). A.S.E is rebuilt as the
automation around Dependency-Track: lockfile-to-SBOM sync now, declared-tech sync and
alerting next. Manifests stay in their own projects; they reach Dependency-Track either
manually through its UI or via `bin/ase-sync` fetching them from configured paths.

```
WS1 Install Dependency-Track (host, ops task)
  ├── WS2 ase-sync: lockfile SBOMs ──┐
  ├── WS3 Declared tech (inventory/) ─┼── WS4 Projects, routing, policy
  │                                   │      └── WS5 Alerting slice (port Scoring/Notify)
  └───────────────────────────────────┴── WS6 Validation, cleanup, process
```

## WS1: Install Dependency-Track

Ops task, not code. Follow [docs/dependency-track-install.md](../dependency-track-install.md):
postgres:18-alpine, apiserver and frontend 5.0.0 containers, localhost-bound ports,
reverse proxy per infra standard, nightly pg_dump cron, browser bootstrap (admin
password, `automation` team with BOM_UPLOAD + PROJECT_CREATION_UPLOAD only, API key,
feed sync verification, one restore rehearsal).

Decision still open: which host. Owner: infra. The install doc runs unchanged on any
docker-capable box, so development against a local instance proceeds meanwhile.

## WS2: ase-sync, lockfile SBOMs (slice 1, built 2026-06-10)

`bin/ase-sync`: reads `ASE_PROJECTS` (name:path pairs) from .env, converts each
composer.lock to a CycloneDX 1.5 BOM (`Ase\Sbom\ComposerLockSbomBuilder`), uploads via
PUT /api/v1/bom (`Ase\DependencyTrack\BomUploader`, autoCreate on, project version
`main`). Cron it next to the legacy `bin/ase` entry. Manual uploads through the
Dependency-Track UI remain available for one-off cases with no code involved.

Later extensions: package-lock.json builder, host OS package scans (syft on each server
piping to the same upload), per-deploy CI invocation for repos that have pipelines.

## WS3: Declared technology inventory

Directory `inventory/` in this repo: `declared-tech.yaml`, one entry per technology with
name, vendor, version, CPE, owner team; edited via PR. An `ase-sync` extension converts
entries to CycloneDX components and uploads them to per-owner projects (`Declared:
infra`, `Declared: erp`). Population workshop with infra and ERP leads; quarterly review
on the calendar. Every entry has an owner or it does not merge.

## WS4: Projects, routing, policy

Configuration on the Dependency-Track instance, captured as a reproducible checklist in
docs/configuration.md when done:

| Project | Tag | Slack channel |
|---|---|---|
| Magento | team:ecommerce | #sec-ecommerce |
| NetSuite integrations | team:erp | #sec-erp |
| Declared: infra | team:infra | #sec-infra |
| Hosts | team:infra | #sec-infra |

Channel names indicative; confirm with team leads. Notification rules per project/tag to
per-team Slack webhooks. Policy: P0/P1 model from the parent doc Section 6 expressed in
the v5 CEL policy engine. Explicit verification: EPSS conditions, CISA KEV membership,
compound conditions. The KEV result decides WS5's shape.

## WS5: Alerting slice

A.S.E's existing `Scoring/PriorityCalculator`, `Model/Priority`, `Notify/SlackMessage`,
`Notify/SlackNotifier`, `Feed/KevFeed`, `Feed/EpssFeed` are already in this repo with
tests; no porting needed. If WS4 shows native policy plus Slack publisher covers P0/P1
and KEV, this slice shrinks to configuration and the legacy alerting code retires. If
not, a small `ase-alert` entrypoint consumes Dependency-Track webhooks (or polls its
API), applies the existing scoring, and routes to per-team Slack webhooks resolved from
project tags. Stateless; no feed polling beyond KEV/EPSS lookups.

## WS6: Validation, cleanup, process

1. Parity test: load this repo's own composer.lock plus the Magento lockfile via
   ase-sync; diff Dependency-Track findings against legacy `bin/ase` output on the same
   lockfile. Explain every divergence before trusting either. Record in
   docs/parity-report.md.
2. Two weeks of both alerting paths running; teams confirm relevance and routing.
3. Runbook (docs/runbook.md): P0/P1 meaning, SLAs (P0 ack 1 business day, fix 7 days;
   P1 30 days), how to audit findings in the UI, who owns the platform.
4. CI merge gates: `composer audit` failing on critical/high direct deps in the Magento
   pipeline; ecosystem equivalents elsewhere.
5. Cleanup: remove the legacy feed pollers, state manager, dedup, and `bin/ase` once the
   alerting slice replaces them; tag `mvp-final` and history preserve the MVP. Decide
   whether to mark infinri/ase abandoned on Packagist.
6. CTO readout: parity report, dashboard walkthrough, SLA reporting demo.

## Effort estimates

Untested estimates for planning conversation only.

| Workstream | Estimate |
|---|---|
| WS1 install (per host) | half a day plus hosting decision lead time |
| WS2 slice 1 | done 2026-06-10; extensions 1 to 2 days |
| WS3 declared tech | 2 to 3 days including population workshop |
| WS4 config, routing, policy | 2 to 3 days including KEV verification |
| WS5 alerting slice | 1 day if config-only; 3 to 4 days if ase-alert is needed |
| WS6 validation and cleanup | 2 days active work across the 2-week parallel window |

## Decision points

1. Hosting target for Dependency-Track. Owner: infra. Blocks production WS1 only;
   local development proceeds.
2. Slack channel names per team. Owner: team leads. Blocks WS4 routing config.
3. OIDC team-scoped UI access: deferred unless a team asks.
