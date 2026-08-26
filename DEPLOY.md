# Deployment

The site runs at <https://ecole-badar.visionxart.com> on the visionxart VPS,
as a Docker container behind the nginx that already fronts the other sites on
that machine. There is no systemd service and no PostgreSQL: the app keeps its
SQLite database and uploaded media on a Docker volume.

| | |
|---|---|
| Container | `btsp`, from `ghcr.io/visionxartorg/btsp-ecole-badar:latest` |
| Compose file | `/opt/clients/btsp-ecole-badar/docker-compose.yml` |
| Data volume | `btsp-ecole-badar_btsp-data` mounted at `/data` |
| Port | `127.0.0.1:3007` → container `8000` |
| nginx site | `/etc/nginx/sites-enabled/ecole-badar.visionxart.com` |
| Auto-update | Watchtower polls the registry every 120 s |

## Releasing a change

Push to `main`, then rebuild and push the image. Watchtower picks it up within
two minutes, or deploy immediately:

```bash
ssh visionxart
cd /opt/build/btsp-ecole-badar && git pull
docker build -t ghcr.io/visionxartorg/btsp-ecole-badar:latest .
docker push ghcr.io/visionxartorg/btsp-ecole-badar:latest
cd /opt/clients/btsp-ecole-badar && docker compose pull && docker compose up -d
```

## Confirming a release actually landed

Run `./verify-deploy.sh` after every deploy. It exercises the live site —
headers, the cross-origin refusal, the brute-force cap, the pages — rather than
comparing image digests.

Digests are not enough. A deploy once reverted silently, and the check passed
anyway: the local `:latest` tag had been replaced by the older image the server
was running, so the comparison was that image against itself. The site looked
correctly deployed while the security fixes were missing from it. Compare
behaviour, or compare `docker exec btsp wc -l /app/app.py` against the file in
this repository — never a tag against itself.

## Data

`/data` holds `database.db` and `uploads/`, and survives every release — the
container image is replaced wholesale each time, so nothing written inside the
image is kept. `BTSP_DB_PATH` and `BTSP_UPLOAD_DIR` point the app at the
volume; without them a deploy would discard every pupil, class and payment.

Back up before anything risky:

```bash
docker run --rm -v btsp-ecole-badar_btsp-data:/data -v /root/backups/btsp:/backup alpine \
  tar czf /backup/btsp-data-$(date +%Y%m%d-%H%M%S).tar.gz -C /data .
```

## Rolling back

Each release tags the previous image, so a bad deploy is one command:

```bash
docker tag ghcr.io/visionxartorg/btsp-ecole-badar:rollback-YYYYMMDD \
           ghcr.io/visionxartorg/btsp-ecole-badar:latest
docker push ghcr.io/visionxartorg/btsp-ecole-badar:latest
cd /opt/clients/btsp-ecole-badar && docker compose up -d
```

## First admin account

On an **empty** database only, the app creates the first admin from
`BTSP_ADMIN_USER` / `BTSP_ADMIN_PASSWORD` in the compose `.env`. With neither
set it generates a random password and prints it once to the container log
(`docker logs btsp`). It never falls back to a fixed default — this repository
is public, so a known password would open the back-office to anyone.

An existing database keeps its current accounts; change passwords from
**Réglages** in the admin.

## Seeded content

At startup the app fills in anything a fresh database lacks: the 26 programme
photos (matched by title) and the diploma specimen. Only empty fields are
touched, so images and settings changed in the admin are never overwritten by
a release.
