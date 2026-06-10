# Installing Dependency-Track (one-time, on the chosen host)

Dependency-Track ships as containers; these are plain docker commands, no compose file.
Run on the host infra designates. All ports bind to localhost; front with the standard
reverse proxy for real access.

    docker network create dtrack

    docker run -d --name dtrack-postgres --network dtrack \
      -e POSTGRES_DB=dtrack -e POSTGRES_USER=dtrack \
      -e POSTGRES_PASSWORD=<generated, store in password manager> \
      -v dtrack-postgres:/var/lib/postgresql \
      --restart unless-stopped postgres:18-alpine

    docker run -d --name dtrack-apiserver --network dtrack \
      -e DT_DATASOURCE_URL=jdbc:postgresql://dtrack-postgres:5432/dtrack \
      -e DT_DATASOURCE_USERNAME=dtrack \
      -e DT_DATASOURCE_PASSWORD=<same password> \
      -v dtrack-apiserver:/data \
      -p 127.0.0.1:8080:8080 \
      --restart unless-stopped ghcr.io/dependencytrack/apiserver:5.0.0

    docker run -d --name dtrack-frontend --network dtrack \
      -e API_BASE_URL=http://localhost:8080 \
      -p 127.0.0.1:8081:8080 \
      --restart unless-stopped ghcr.io/dependencytrack/frontend:5.0.0

First boot pulls vulnerability feeds; allow time before findings appear.

## Bootstrap (browser, once)

1. http://localhost:8081, admin/admin, forced password change; store the credential.
2. Create team `automation`, permissions: BOM_UPLOAD, PROJECT_CREATION_UPLOAD,
   VIEW_PORTFOLIO, VIEW_VULNERABILITY (the read permissions serve `bin/ase-alert`).
3. Generate an API key on that team: this is DTRACK_API_KEY in A.S.E's .env.
4. Verify feed sync under Administration > Vulnerability Sources.
5. Smoke test: `curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/api/version` expecting 200.

## Backup

Nightly cron on the host:

    docker exec dtrack-postgres pg_dump -U dtrack dtrack | gzip > /backup/dtrack-$(date +%F).sql.gz

Rehearse a restore once before relying on it.
