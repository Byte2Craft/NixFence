"""Clearly fictional, preloaded demo inventory. Never derived from actual infrastructure."""
HOSTS = [
    {"id": "demo-001", "hostname": "web-prod-01", "address": "192.0.2.11", "group": "WEB-PROD", "os": "Rocky Linux 9", "firewall": "firewalld", "selinux": "Enforcing", "status": "DEMO"},
    {"id": "demo-002", "hostname": "web-prod-02", "address": "192.0.2.12", "group": "WEB-PROD", "os": "AlmaLinux 9", "firewall": "firewalld", "selinux": "Enforcing", "status": "DEMO"},
    {"id": "demo-003", "hostname": "app-prod-01", "address": "192.0.2.31", "group": "APP-PROD", "os": "RHEL 9", "firewall": "firewalld", "selinux": "Enforcing", "status": "DEMO"},
    {"id": "demo-004", "hostname": "db-stage-01", "address": "198.51.100.51", "group": "DB-STAGING", "os": "Rocky Linux 9", "firewall": "firewalld", "selinux": "Permissive", "status": "DEMO"},
]

POLICIES = [
    {"name": "WEB-PROD-BASELINE", "target": "WEB-PROD", "rules": 8, "revision": "demo-v3", "state": "Sample"},
    {"name": "APP-PROD-BASELINE", "target": "APP-PROD", "rules": 6, "revision": "demo-v2", "state": "Sample"},
    {"name": "DB-STAGING-BASELINE", "target": "DB-STAGING", "rules": 5, "revision": "demo-v1", "state": "Sample"},
]
