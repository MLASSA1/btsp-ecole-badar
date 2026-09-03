# Deployment

The site runs at <https://btspformation.com> on the visionxart VPS
(the older ecole-badar.visionxart.com now redirects there),
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

## Getting the code onto the server

GitHub answers the server's anonymous `git fetch` with **HTTP 401** on the pack
negotiation (`www-authenticate: Basic realm="GitHub"`), even though the
repository is public and `curl` reaches the same endpoints fine. `git clone`
and `git fetch` therefore fail there and prompt for a username. A deploy that
ran `git fetch … && git reset --hard` silently kept the previous checkout and
built *that* — the release looked successful and shipped nothing.

Until the server has a GitHub token or deploy key, push to it over SSH from a
machine that can reach GitHub:

```bash
git remote add deploy visionxart:/opt/build/btsp-ecole-badar   # once
git push --force deploy main:refs/heads/deploy
ssh visionxart 'cd /opt/build/btsp-ecole-badar && git reset --hard deploy'
```

`refs/heads/deploy` is used because a repository refuses a push to the branch
it has checked out.

## Releasing a change

Push to `main`, then rebuild and push the image. Watchtower picks it up within
two minutes, or deploy immediately:

```bash
git push --force deploy main:refs/heads/deploy
ssh visionxart '
  set -e
  cd /opt/build/btsp-ecole-badar
  git reset --hard deploy --quiet
  git rev-parse --short HEAD          # confirm this is the commit you meant
  docker build -t ghcr.io/visionxartorg/btsp-ecole-badar:latest .
  docker push ghcr.io/visionxartorg/btsp-ecole-badar:latest
  cd /opt/clients/btsp-ecole-badar && docker compose up -d
'
./verify-deploy.sh
```

Check the commit the server prints before trusting the build. `set -e` does
not abort on a failure inside an `&&` chain, which is how a failed fetch
turned into a silent no-op release.

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
