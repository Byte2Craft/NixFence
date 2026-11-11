# Community release checklist

## Before a public release

- [ ] Tests and lint checks pass in CI.
- [ ] Docker image builds successfully and the demo starts on a clean machine.
- [ ] The demo is confirmed local-only and unauthenticated; its warnings remain visible.
- [ ] Check for credentials, private inventory, user identifiers or production screenshots.
- [ ] Review OSS dependencies, license notices and container vulnerabilities.
- [ ] Ensure all README, API, screenshot and release claims match implemented features.
- [ ] Keep Apache-2.0 LICENSE, NOTICE, trademarks and contributor documentation consistent.
- [ ] Provide a private method to report vulnerabilities, if configured.

## Before implementing remote discovery

- [ ] Implement authentication and authorization.
- [ ] Pin SSH host identities and isolate SSH credentials.
- [ ] Verify allowed read-only commands and no unintended writes.

## Before implementing live changes

- [ ] Validate restore after SSH loss, network failure and host reboot.
- [ ] Detect firewall ownership conflicts and unsupported host combinations.
- [ ] Log per-host outcomes and immutable policy revisions.
- [ ] Verify canary rollout and explicit approval gates.
