# Docker Hub publishing with a strict security gate

**Image candidate:** `byte2craft/nixfence-community:0.2.0-beta.2`

The GitHub Actions release workflow builds the image, runs tests, scans the **same**
local image, and pushes it **only if Docker Scout reports zero known CVEs**.
No CVEs are ignored or suppressed. This policy can block publication when vendors
have no patch available; that is intentional. A clean scan is not an application
security audit and does not guarantee freedom from undisclosed vulnerabilities.

## Prerequisites

1. Create Docker Hub repository `byte2craft/nixfence-community`.
2. In GitHub Actions secrets add `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`
   (a least-privilege Docker Hub personal access token with repository push rights).
3. Validate on a disposable VM before using real Linux targets. In particular,
   verify firewall lockout recovery with console access and review sudo permissions.
4. Build and scan locally before committing:

```bash
docker build --pull --no-cache -t nixfence-community:security-candidate .
docker scout cves --exit-code nixfence-community:security-candidate
```

A nonzero exit code from Docker Scout means this candidate must not be published.
Use `docker scout recommendations nixfence-community:security-candidate` to
identify available upgrades. **Do not hide or suppress findings to pass CI.**

## GitHub to Docker Hub

After publishing source changes to GitHub and passing CI / VM tests:

```bash
git tag -a v0.2.0-beta.2 -m "NixFence Community beta container hardening"
git push origin v0.2.0-beta.2
```

The tag triggers `.github/workflows/dockerhub.yml`. The job:

1. Runs Python tests and static checks.
2. Builds `linux/amd64` locally with refreshed base layers.
3. Runs Docker Scout against the local image and fails on ANY known CVE.
4. Verifies the app version matches the approved release tag.
5. Pushes the same scanned image to Docker Hub with tag `0.2.0-beta.2`.

The old `0.2.0-beta.1` tag is not remediated automatically and should not be
used or recommended. Do not use `latest` for an unvalidated beta.

If all stages pass, users can run:

```bash
docker pull byte2craft/nixfence-community:0.2.0-beta.2
docker compose up -d --no-build
```

## Security tradeoffs

- Alpine uses musl rather than glibc; the image needs an actual Docker runtime test.
- The OpenSSH package `openssh-client-default` intentionally omits Kerberos/GSSAPI.
- Build-stage pip and build tooling are not shipped in the runtime environment.
- The app's broad remote sudo prerequisites still need least-privilege redesign and
  independent testing. A zero-CVE image does **not** make that safe for production.
- New CVEs can appear after a tag is published; rebuild, rescan and publish a new tag.
