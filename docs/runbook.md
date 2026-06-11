# Runbook: vulnerability management platform

Audience: anyone on a team channel who receives an A.S.E alert, plus whoever operates
the platform. Architecture: docs/planning/vulnerability-management-platform.md.

## What the pieces are

- Dependency-Track (engine + UI): holds the inventory, matches it against NVD/OSV/EPSS
  continuously, shows dashboards and audit trails. Install: docs/dependency-track-install.md.
- `bin/ase-sync` (cron): pushes lockfile SBOMs (`ASE_PROJECTS`) and the declared-tech
  inventory (inventory/declared-tech.yaml) into Dependency-Track.
- `bin/ase-alert` (cron): reads new findings, scores P0/P1 (CISA KEV, ransomware,
  CVSS/EPSS), posts to the owning team's Slack channel (`ASE_ALERT_ROUTES`).

Suggested cron (one host, the same one that can reach Dependency-Track):

    */30 * * * *  cd /opt/ase && bin/ase-sync
    */30 * * * *  cd /opt/ase && sleep 600 && bin/ase-alert

## When a P0 alert lands in your channel

P0 means: the vulnerability is in CISA's Known Exploited Vulnerabilities catalog (it is
being exploited in the wild right now), or it is critical (CVSS >= 9.0) with real
exploit probability (EPSS >= 10%).

- Acknowledge in the channel within 1 business day.
- Patch or mitigate within 7 days. For composer packages the alert names the package;
  `composer update vendor/package` plus deploy is usually the fix.
- Record the outcome in the Dependency-Track UI (open the project, find the finding,
  set its analysis state): Resolved when patched, False Positive with a comment when
  the matcher is wrong, Acknowledged while work is in flight.

## When a P1 alert lands

P1 means: high severity (CVSS >= 7.0) affecting an installed version, or high severity
with elevated exploit probability, or known ransomware association. Same flow as P0
with a 30-day patch SLA.

## No alert, but you want to look around

The Dependency-Track UI shows everything below the alert threshold too: per-project
findings, portfolio trends, audit history. Findings audited as False Positive stop
counting against the project. The UI is the system of record for "what did we know and
when"; the Slack alert is just the doorbell.

## Operating the platform

- Versions in inventory/declared-tech.yaml are updated by PR whenever the real system
  is patched; quarterly review owned by the infra lead.
- Dependency-Track upgrades: patch releases are docker pull + recreate; rehearse the
  database restore (install doc) after major upgrades.
- The OSV source must be re-enabled (bin/dtrack-enable-osv.sh) after any rebuild from
  scratch; a fresh instance silently matches nothing for composer/npm otherwise.
- `bin/ase-alert` exits non-zero and leaves the cursor unmoved when any Slack post
  fails, so the next cron retries; repeated failures show up as repeated exit-1 cron
  mails plus `Slack post failed` lines in stderr logs.
- Secrets: the Dependency-Track API key and Slack webhooks live only in `.env` on the
  cron host and in the team password manager.

## Adding coverage

- New codebase: add `name:/path/composer.lock` to `ASE_PROJECTS`, tag the project in
  the Dependency-Track UI with its owning team, add the team's route to
  `ASE_ALERT_ROUTES` if new.
- New appliance/SaaS/infra tech: PR an entry to inventory/declared-tech.yaml with a
  CPE (lookup at nvd.nist.gov/products/cpe/search) and an owner.
