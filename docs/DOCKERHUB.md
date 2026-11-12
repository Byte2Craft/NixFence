# Publish NixFence Community beta to Docker Hub

**Do not publish or market this as production-ready until real-host verification and security review pass.**

1. Create Docker Hub repository `byte2craft/nixfence-community` under the Byte2craft namespace.
2. In GitHub `Byte2Craft/NixFence` -> Settings -> Secrets and variables -> Actions, add:
   - `DOCKERHUB_USERNAME` (a namespace member with push permission)
   - `DOCKERHUB_TOKEN` (a Docker Hub access token with write access; never a password in source code)
3. Merge the source and tests, confirm the GitHub CI run is green and check Docker build and SSH/rollback behavior on disposable VMs.
4. Publish the test release tag:

```bash
git tag -a v0.2.0-beta.1 -m "Community early-access beta"
git push origin v0.2.0-beta.1
```

5. The `Publish tested Community image to Docker Hub` action builds `linux/amd64` and tags the image:

```text
byte2craft/nixfence-community:0.2.0-beta.1
```

6. After the workflow completes, verify the digest and pull from a clean host:

```bash
docker pull byte2craft/nixfence-community:0.2.0-beta.1
docker image inspect byte2craft/nixfence-community:0.2.0-beta.1
```

7. Run `docker compose up -d` using the README setup and a protected `secrets/` directory. **Do not** publish the `latest` tag for beta or expose the dashboard publicly.

The workflow does not create the Docker Hub repository, token, credentials or live release automatically until you push the tag.
