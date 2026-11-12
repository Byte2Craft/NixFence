# Community beta release checklist

- [ ] All tests and static analysis pass in a clean environment; Docker build passes.
- [ ] Verify no code or configuration credentials have been committed to Git.
- [ ] Verify administrator password and SSH private key are readable only by the intended runtime identity.
- [ ] Verify pinned SSH identity and reject unknown/changed host keys on a supported VM.
- [ ] Run real firewalld port staging and confirmation tests on Rocky, Alma and RHEL 9 VMs.
- [ ] Validate independent host-side rollback after SSH disconnect and controller crash.
- [ ] Verify port rollback restores BOTH runtime and permanent pre-change states.
- [ ] Verify SELinux boolean runtime rollback and document lack of persistence.
- [ ] Review sudo privilege escalation risk and container permissions.
- [ ] Check dependency vulnerabilities, licensing and architecture support.
- [ ] Deploy only to local trusted networks; maintain a console recovery plan.
- [ ] Ensure README and Docker Hub description say **Community beta, not production-ready**.
- [ ] Never publish tag `latest` before production release criteria are met.
