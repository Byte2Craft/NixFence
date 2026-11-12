# NixFence Community beta quickstart

## Requirements

- Docker with Compose v2, Python 3.11+ for local bootstrap, and OpenSSH `ssh-keygen`.
- A reachable dedicated Rocky Linux 9, AlmaLinux 9 or RHEL 9 host with firewalld, SELinux, systemd and OpenSSH.
- A dedicated non-root SSH user, authorized public key, and non-interactive sudo privileges for NixFence's **limited beta command set**. See [host preparation](HOST_PREPARATION.md).
- Network access from the NixFence container to the target host on its SSH port.

## 1. Generate deployment credentials

```bash
python scripts/bootstrap.py
```

Record the generated administrator password. Do **not** commit `secrets/`. On Linux bind mounts the app is UID/GID `10001`; files in `secrets/` must be traversable/readable by that group. Refer to [host preparation](HOST_PREPARATION.md).

## 2. Trust the host key, not unverified ssh-keyscan output

Verify the SSH server ED25519 fingerprint on the Linux host's trusted console:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Collect the public host key through an independent channel, compare its fingerprint and add the verified key to `secrets/known_hosts`. A raw `ssh-keyscan` output is **not trust verification**. If using a custom port, the known_hosts entry must use `[host.example.com]:2222` syntax.

Install `secrets/id_ed25519.pub` in the target dedicated SSH user's `authorized_keys`. Verify the account can perform the necessary sudo commands non-interactively.

## 3. Build and start locally (works before Docker Hub publication)

```bash
docker compose -f compose.yaml -f compose.build.yaml up -d --build
```

Open **http://127.0.0.1:8080** on the Docker host. Sign in with `admin` and the generated password. Add a real Linux host and inspect its firewalld/SELinux state. The web UI does not have synthetic host inventory.

## 4. After the tested Docker Hub release exists

```bash
docker compose pull
docker compose up -d
```

The default image is `byte2craft/nixfence-community:0.2.0-beta.1`. This tag is only usable once the publisher has pushed it to Docker Hub. See [Docker Hub publishing](DOCKERHUB.md).

## 5. Backups and local access

The database is in Docker volume `nixfence_data`. Back up the volume using an SQLite-consistent method (SQLite `.backup` or an offline snapshot) before upgrades, and separately back up the administrator password and SSH identity securely. Do not place secrets inside the source repository.

For remote administration, use an SSH tunnel to the Docker host rather than exposing port 8080:

```bash
ssh -L 8080:127.0.0.1:8080 admin@docker-host.example.com
```

Browse `http://127.0.0.1:8080` on your own workstation. An HTTPS reverse proxy requires setting `NIXFENCE_ALLOWED_ORIGIN` to its HTTPS origin, enabling secure cookies, and configuring the corresponding Trusted Host.

## 6. Stop

```bash
docker compose down
```

Never run `docker compose down -v` unless intentionally deleting the SQLite database volume.
