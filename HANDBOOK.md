# A.S.E -- Automated Security Evaluator: Technical Handbook

**Audience:** CTO, Senior Engineering Lead, Security Team
**Applies to:** 2.x (Dependency-Track pipeline)
**Runtime:** PHP 8.4+

> This handbook documents the 2.x architecture. The 1.0 standalone feed-polling CLI was
> retired in 2.0.0 and preserved at tag `mvp-final`; see `CHANGELOG.md` and
> `docs/parity-report.md` for the cutover.

---

## Executive Summary

A.S.E is thin automation around [OWASP Dependency-Track](https://dependencytrack.org/).
Dependency-Track is the engine: it mirrors vulnerability feeds (NVD, OSV, EPSS), matches
them against the software you run, and provides the UI, dashboards, and audit trail. A.S.E
supplies the two ends Dependency-Track does not: it **feeds** the inventory in (lockfile
and declared-tech SBOMs) and **alerts** from the findings out (priority-scored Slack
messages routed to the owning team).

**Key design decisions:**

- No daemon, no queue, no database in A.S.E itself; two cron-driven CLIs against
  Dependency-Track's REST API.
- Dependency-Track owns feed ingestion and version matching. A.S.E reads only one feed
  directly: the CISA KEV catalog, for the "actively exploited / ransomware" signal.
- Alerting is stateless apart from a single monotonic cursor (last-seen finding
  timestamp) on disk.
- Routing is by Dependency-Track project tag, so team ownership lives in the platform,
  not in A.S.E configuration.

---

## 1. Architecture

### Components

| Component | Type | Responsibility |
|-----------|------|----------------|
| `bin/ase-sync` | cron CLI | Build CycloneDX SBOMs from lockfiles + declared-tech inventory; upload to Dependency-Track |
| `bin/ase-alert` | cron CLI | Read new findings, score P0/P1, post to the owning team's Slack webhook |
| `bin/dtrack-enable-osv.sh` | one-time script | Enable the OSV vuln source on a fresh Dependency-Track 5.0 instance |
| OWASP Dependency-Track | external service | Feed mirroring, version matching, dashboards, audit trail |

### Data flow

```
cron (every 30m)
  |
  +-- bin/ase-sync
  |     ComposerLockSbomBuilder   composer.lock  -> CycloneDX 1.5 (production packages)
  |     DeclaredTechSbomBuilder   declared-tech.yaml -> one CycloneDX BOM per owner
  |       |
  |       v
  |     BomUploader  --PUT /api/v1/bom (autoCreate)-->  Dependency-Track
  |
  +-- bin/ase-alert  (runs after a sync settles)
        FindingsFetcher  --GET /api/v1/project, /api/v1/finding/project/{uuid}-->  Dependency-Track
          |
          v
        AlertCursor.get()              skip findings with attributedOn <= cursor
          |
          v
        FindingMapper (+ KevCatalog)   raw finding -> Vulnerability value object
          |
          v
        PriorityCalculator             -> P0, P1, or null (dropped)
          |
          v
        AlertRouter.webhooksForTags()  project tags -> team webhook(s)
          |
          v
        SlackMessage -> HTTP POST       (1.5s throttle between posts)
          |
          v
        AlertCursor.set(maxSeen)        only on a fully clean run (no failures)
```

### Source layout

```
src/
  Config.php                       -- .env loader (phpdotenv); typed accessors
  Sbom/
    ComposerLockSbomBuilder.php    -- composer.lock -> CycloneDX (production packages, purl)
    DeclaredTechSbomBuilder.php    -- declared-tech.yaml -> per-owner CycloneDX (cpe)
  DependencyTrack/
    BomUploader.php                -- PUT /api/v1/bom
    FindingsFetcher.php            -- paginated project list + per-project findings
  Alert/
    FindingMapper.php              -- DT finding -> Vulnerability
    AlertRouter.php                -- project tag -> webhook(s), with default fallback
    AlertCursor.php                -- atomic JSON cursor (temp file + rename)
  Scoring/
    PriorityCalculator.php         -- P0/P1 classification
  Feed/
    KevCatalog.php                 -- CISA KEV: in-KEV + ransomware lookup
  Notify/
    SlackMessage.php               -- Block Kit message builder
  Http/
    CurlClient.php                 -- retry/backoff HTTP client (429-aware)
    HttpResponse.php               -- status/body/headers value object
  Logging/
    SecretRedactor.php             -- secret masking
    SecretRedactorProcessor.php    -- monolog processor (scrubs every record)
    CorrelationIdProcessor.php     -- per-run correlation id
  Model/
    Vulnerability.php              -- immutable value object
    AffectedPackage.php            -- immutable value object
    Priority.php                   -- P0/P1 enum

bin/   ase-sync, ase-alert, dtrack-enable-osv.sh
tests/Unit/                        -- PHPUnit suite (138 tests)
```

---

## 2. Inventory: what gets into Dependency-Track

`bin/ase-sync` produces CycloneDX 1.5 BOMs and `PUT`s them to `/api/v1/bom` with
`autoCreate: true`, so the Dependency-Track project is created on first upload.

### Lockfile SBOMs (`ComposerLockSbomBuilder`)

- Input: each `name:/abs/path/composer.lock` entry in `ASE_PROJECTS`.
- Production packages only -- `composer.lock` `packages-dev` is excluded, matching a
  production `composer install --no-dev` deploy. Dev-only tooling does not generate
  alerts.
- Each package becomes a component with a `pkg:composer/...` package URL, which is the
  identifier the OSV/Packagist mirror matches against.

### Declared-tech SBOMs (`DeclaredTechSbomBuilder`)

- Input: `inventory/declared-tech.yaml` (path overridable with `ASE_INVENTORY_PATH`).
- For things with no manifest file: appliances, OS software, SaaS, infrastructure.
- Grouped into one BOM per `owner`, uploaded as project `Declared: {owner}`.
- Entries with a `cpe` are matched by Dependency-Track against NVD; entries without are
  inventory-only (visible, not matched). Every entry requires an owner or the build
  throws.

---

## 3. Priority scoring

`ase-alert` alerts on two tiers and drops everything else.
`PriorityCalculator::classify()` returns `null` for anything below P1; those findings
remain visible in the Dependency-Track UI but never reach Slack.

| Tier | Condition (first match wins) |
|------|------------------------------|
| **P0** | in CISA KEV; **or** CVSS >= `CVSS_CRITICAL_THRESHOLD` (9.0) **and** EPSS >= `EPSS_HIGH_THRESHOLD` (0.10) |
| **P1** | ransomware-associated; **or** CVSS >= `CVSS_HIGH_THRESHOLD` (7.0) **and** EPSS >= high; **or** affects an installed version **and** CVSS >= high |
| (dropped) | everything else |

Because every Dependency-Track finding is, by definition, against a component present in
an uploaded SBOM, `affectsInstalledVersion` is always true -- so the effective P1 floor
is **CVSS >= 7.0 (or ransomware-associated)**.

- KEV membership and ransomware association: looked up by A.S.E against the live CISA
  catalog (`KevCatalog`).
- CVSS and EPSS: come from Dependency-Track's enrichment on the finding.
- Thresholds: configurable via `.env` (`CVSS_CRITICAL_THRESHOLD`, `CVSS_HIGH_THRESHOLD`,
  `EPSS_HIGH_THRESHOLD`).

---

## 4. The CISA KEV feed

The one feed A.S.E reads directly:

- URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Auth: none.
- Fetched once per `ase-alert` run and cached in memory for that run. Each entry yields
  two booleans per CVE: in-KEV, and `knownRansomwareCampaignUse == "Known"`.
- If the catalog fetch fails, finding mapping throws; the run records the failure, the
  cursor does not advance, and the next cron retries.

---

## 5. Alerting and the cursor

- `AlertCursor` stores a single integer: the maximum `attribution.attributedOn`
  timestamp seen on a clean run. Default path: `var/state/alert-cursor.json`
  (`ASE_ALERT_CURSOR_PATH`). Writes are atomic (temp file + `rename`).
- Findings with `attributedOn <= cursor` are skipped, so each finding alerts once.
- The cursor advances **only when the entire run completes with zero failures**. Any
  failed Slack post or fetch leaves it unmoved, so the next run retries that work
  instead of silently dropping it.
- `AlertRouter` maps a project's tags to webhook(s) via `ASE_ALERT_ROUTES`
  (`tag=webhook`). Unrouted alert-worthy findings are logged as warnings and skipped
  unless `ASE_ALERT_DEFAULT_WEBHOOK` is set.
- A 1.5s throttle separates posts so a backfill does not flood a channel.

### First-run behavior

The cursor starts at zero, so the first run alerts on every existing P0/P1 finding. For
a quiet adoption, run `ase-alert` once before configuring `ASE_ALERT_ROUTES`: findings
are logged and skipped, the cursor advances, and subsequent runs alert only on genuinely
new findings.

---

## 6. Slack message design

`SlackMessage::forVulnerability()` builds a Block Kit message in two tiers: a leadership
tier (headline, plain-English impact) and an engineering tier (affected package, raw
scores, reference buttons). What actually renders is bounded by the fields a
Dependency-Track finding carries:

- **Headline** leads with the scariest true fact: actively exploited (KEV) > ransomware
  > "you are vulnerable".
- **Impact summary** in plain English plus the advisory description.
- **Affected package** with its vulnerable version.
- **Scores**: CVSS, EPSS (with percentile when present), KEV membership.
- **Buttons**: NVD (for `CVE-` ids) and Packagist (for composer components).
- Color: P0 `#FF0000`, P1 `#FF6600`.

Note: findings sourced from Dependency-Track do not currently carry a fixed-version or
CISA-deadline field, so the message's "what to do / deadline" lines render only when that
data is present. The package name is always shown; remediation is typically
`composer update vendor/package` plus deploy.

---

## 7. Security posture

| Concern | Status |
|---------|--------|
| Secrets in source | None. `DTRACK_API_KEY` and Slack webhooks load from `.env` (gitignored) at runtime. |
| Secret leakage in logs | `SecretRedactor` + monolog processor scrub registered secrets (DT API key, every configured webhook) from all records; the API key parameter is marked `#[\SensitiveParameter]`. |
| Transport | `CURLOPT_SSL_VERIFYPEER => true`; `CURLOPT_MAXFILESIZE => 10MB`; `CURLOPT_MAXREDIRS => 3`. |
| SQL injection | N/A -- A.S.E has no database. |
| Command injection | N/A -- no shell execution from external input. (`dtrack-enable-osv.sh` is an ops-run install script, not invoked by the CLIs.) |
| SSRF | Outbound destinations are the configured Dependency-Track URL, the hardcoded CISA KEV URL, and operator-configured Slack webhooks. |
| Deserialization | JSON only, with `JSON_THROW_ON_ERROR`; YAML via Symfony's safe parser. |
| State integrity | The cursor holds a single integer, no secrets; atomic temp-file + rename. |

The Dependency-Track API key should be scoped to the `automation` team's
`BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`, and `VIEW_VULNERABILITY`
permissions only (see `docs/dependency-track-install.md`).

---

## 8. HTTP client

`CurlClient` is the single egress point.

- Methods: `get`, `post`, `put` (JSON bodies auto-encoded with a `Content-Type` header).
- Retries on HTTP 429 up to 3 times, honoring `Retry-After` when present, else backing
  off `[2, 8, 32]` seconds.
- Connect timeout 10s, total timeout 30s. Failed transfers return an `HttpResponse` with
  status `0` and are logged, not thrown, so callers decide how to handle them.

---

## 9. Operations

- **Cron** (one host with reach to Dependency-Track and the lockfiles):

  ```cron
  */30 * * * *  cd /opt/ase && bin/ase-sync
  */30 * * * *  cd /opt/ase && sleep 600 && bin/ase-alert
  ```

- **Exit codes:** both CLIs exit non-zero if any unit of work failed, so failures surface
  as cron mail plus structured stderr logs.
- **OSV enablement is required once** after any from-scratch Dependency-Track rebuild
  (`bin/dtrack-enable-osv.sh`); a fresh 5.0 instance mirrors only NVD+EPSS and silently
  matches nothing for composer/npm otherwise.
- **Inventory upkeep:** bump versions in `inventory/declared-tech.yaml` by PR whenever the
  real system is patched; a stale version produces false alerts or false silence.
- **Logging:** structured JSON to stderr (Monolog `JsonFormatter`) with a per-run
  correlation id on every line.

Full operational guidance: `docs/runbook.md`. Install and backup: `docs/dependency-track-install.md`.

---

## 10. Testing and quality gates

- **PHPUnit:** 138 unit tests covering SBOM building, finding mapping, priority scoring,
  KEV/ransomware classification, alert routing, the cursor, Slack message structure,
  secret redaction, correlation-id wiring, and the HTTP client.
- **PHPStan:** level 8 on `src/` (`phpstan.neon`).
- **`composer audit`:** gates merge on known CVEs in dependencies.

All three run in CI (`.github/workflows/ci.yml`) on every push and pull request and gate
merge.

```sh
composer test     # PHPUnit
composer stan     # PHPStan level 8
composer audit    # dependency CVE check
```

### Not covered by CI

- Live Dependency-Track API calls and live Slack posting (network-dependent; verified
  manually, see `docs/parity-report.md`).

---

## 11. Dependencies

### Production

| Package | Purpose |
|---------|---------|
| `monolog/monolog` | PSR-3 structured logging |
| `symfony/yaml` | Parse `declared-tech.yaml` |
| `vlucas/phpdotenv` | Load `.env` |

PHP extensions required at install time: `ext-curl`, `ext-json`, `ext-mbstring`,
`ext-openssl`.

### Development

| Package | Purpose |
|---------|---------|
| `phpunit/phpunit` | Unit testing |
| `phpstan/phpstan` | Static analysis (level 8) |

---

## 12. Scaling profile

A.S.E itself is near-stateless and cheap: each run is a handful of HTTPS calls plus JSON
processing. The scaling characteristics that matter belong to Dependency-Track (inventory
size, mirror cadence, matching throughput); size that instance per its own guidance. The
practical limits on the A.S.E side:

- **Alert throughput:** the 1.5s inter-post throttle means a large backfill (e.g. a first
  run over a big portfolio) takes time proportional to the number of alert-worthy
  findings times routed webhooks. This is intentional; for a quiet first run, see the
  first-run note in section 5.
- **Project listing:** `FindingsFetcher` paginates the project list (100/page) and reads
  findings per project, one request each.

When monitoring grows to many teams and ecosystems, the work to do is in Dependency-Track
(projects, tags, team permissions) and in `ASE_PROJECTS` / `ASE_ALERT_ROUTES`, not in a
redesign of A.S.E.
