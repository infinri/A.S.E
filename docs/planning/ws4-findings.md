# WS4 findings: canary verification and KEV/policy experiment

Date: 2026-06-10. All results from a live local Dependency-Track 5.0.0 instance
(install per docs/dependency-track-install.md), canary project with deliberately
vulnerable composer packages, admin REST API.

## Verified working

1. End-to-end matching. Canary lockfile (guzzle 7.4.0, guzzlehttp/psr7 1.8.0,
   symfony/http-kernel 5.4.0, monolog 3.5.0) uploaded via `bin/ase-sync` produced 8
   findings: 5 HIGH on guzzle, 2 MEDIUM on psr7, 1 MEDIUM on http-kernel, zero on
   monolog (correct). All findings carry EPSS scores (EPSS mirror enabled by default).
2. EPSS policy conditions. Policy with condition `EPSS NUMERIC_GREATER_THAN 0.01`
   produced SECURITY violations on exactly the two components above that threshold.
   Policy condition subjects available in 5.0.0: AGE, COORDINATES, CPE, EXPRESSION,
   LICENSE, LICENSE_GROUP, PACKAGE_URL, SEVERITY, SWID_TAGID, VERSION, COMPONENT_HASH,
   IS_INTERNAL, CWE, VULNERABILITY_ID, VERSION_DISTANCE, EPSS.
3. NVD and EPSS mirror on first boot with zero configuration (NVD ~30 min, EPSS ~1 min).

## Finding 1: OSV/GHSA sources are off by default, and Packagist is not in the default OSV ecosystem list

Fresh 5.0.0 mirrors only NVD + EPSS. NVD matches by CPE, so composer packages produce
zero findings until OSV or GitHub Advisories is enabled. The vuln-data-source config
lives in the `EXTENSION_RUNTIME_CONFIG` table (extension point `vuln-data-source`),
not in the configProperty API, and the 5.0.0 frontend did not expose an admin page or
REST endpoint for it that we could find. For the experiment we enabled OSV with
ecosystem `Packagist` by SQL update plus apiserver restart; mirror cron defaults:
GitHub 02:00, OSV 03:00, NVD 04:00, EPSS 01:00 UTC (overridable via env, e.g.
`DT_TASK_OSV_VULN_DATA_SOURCE_MIRROR_CRON`).

Production install must include: enable OSV with Packagist + npm ecosystems (and/or
GitHub Advisories with a scopeless PAT). Track whether a supported config surface for
this lands in a 5.0.x patch; revisit before the production install, and prefer the
supported mechanism over SQL.

## Finding 2: CISA KEV is absent from Dependency-Track 5.0.0

No KEV/CISA/ransomware fields exist in the VULNERABILITY table, the REST Vulnerability
model, or the application config (checked schema, OpenAPI spec, and jar
application.properties; only CVSS exploitability sub-scores exist). KEV is therefore
not expressible in policy conditions.

Consequence for the plan (parent doc Section 6, implementation plan WS5): the WS5
fallback is confirmed as required. The alerting slice keeps A.S.E's KEV feed and
scoring: `ase-alert` reads findings/violations from the Dependency-Track API (or
consumes its webhooks), applies the existing P0/P1 logic (KEV membership via
`Feed/KevFeed`, EPSS/CVSS thresholds via `Scoring/PriorityCalculator`), and routes to
per-team Slack webhooks. Dependency-Track native policies still carry the EPSS/severity
tiers (verified above), so ase-alert's unique jobs are KEV, ransomware association, and
team routing.

## Cleanup state of the local instance

Canary project and the `e2e-epss-test` policy left in place for UI inspection.
Apiserver restored to default mirror schedule. OSV remains enabled (Packagist only)
via the SQL method above; re-applying after a volume wipe requires repeating it.
