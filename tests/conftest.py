from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nixfence.api import create_app
from nixfence.config import Settings
from nixfence.database import Database
from nixfence.ssh import Result


class FakeSSH:
    """Deterministic command interpreter. Does not contact a real VM."""
    def __init__(self):
        self.calls = []
        self.runtime = {}
        self.permanent = {}
        self.booleans = {"httpd_can_network_connect": False, "nis_enabled": True}
        self.timer = False
        self.timer_allowed = True
        self.scripts = {}
        self.original_runtime = {}
        self.original_permanent = {}
        self.original_booleans = {}
        self.os_release = 'ID="rocky"\nVERSION_ID="9.5"\nPRETTY_NAME="Rocky Linux 9.5"'

    def run(self, *args, **kwargs):
        self.calls.append(("run", args))
        if args == ("cat", "/etc/os-release"):
            return Result(0, self.os_release, "")
        raise AssertionError(f"Unknown SSH command {args}")

    def sudo(self, *args, **kwargs):
        self.calls.append(("sudo", args))
        input_text = kwargs.get("input_text")
        if args[:2] == ("firewall-cmd", "--state"):
            return Result(0, "running", "")
        if args[:2] == ("firewall-cmd", "--get-active-zones"):
            return Result(0, "public\n  interfaces: eth0", "")
        if args[:2] == ("firewall-cmd", "--get-default-zone"):
            return Result(0, "public", "")
        if args[:2] == ("firewall-cmd", "--get-zones"):
            return Result(0, "public home", "")
        if args[0] == "firewall-cmd":
            permanent = "--permanent" in args
            zone = next((s.split("=", 1)[1] for s in args if s.startswith("--zone=")), "public")
            query = next((s.split("=", 1)[1] for s in args if s.startswith("--query-port=")), None)
            add = next((s.split("=", 1)[1] for s in args if s.startswith("--add-port=")), None)
            remove = next((s.split("=", 1)[1] for s in args if s.startswith("--remove-port=")), None)
            current = self.permanent if permanent else self.runtime
            if query is not None:
                allowed = current.get((zone, query), False)
                return Result(0 if allowed else 1, "yes" if allowed else "no", "")
            if add is not None:
                current[(zone, add)] = True
                return Result(0, "success", "")
            if remove is not None:
                current[(zone, remove)] = False
                return Result(0, "success", "")
            if "--list-all" in args:
                return Result(0, "public (active)\n  services: ssh", "")
            if "--list-ports" in args:
                ports = [spec for (z, spec), enabled in current.items() if z == zone and enabled]
                return Result(0, " ".join(ports), "")
            if "--list-services" in args:
                return Result(0, "ssh", "")
        if args[0] == "getenforce":
            return Result(0, "Enforcing", "")
        if args[0] == "getsebool":
            if args[1] == "-a":
                return Result(0, "\n".join(f"{k} --> {'on' if v else 'off'}" for k, v in self.booleans.items()), "")
            if args[1] not in self.booleans:
                return Result(1, "", "Unknown boolean")
            return Result(0, f"{args[1]} --> {'on' if self.booleans[args[1]] else 'off'}", "")
        if args[0] == "setsebool":
            self.booleans[args[1]] = args[2] == "on"
            return Result(0, "", "")
        if args[0] == "install":
            return Result(0, "", "")
        if args[0] == "tee":
            self.scripts[args[1]] = input_text
            self.original_runtime = self.runtime.copy()
            self.original_permanent = self.permanent.copy()
            self.original_booleans = self.booleans.copy()
            return Result(0, "", "")
        if args[0] == "chmod":
            return Result(0, "", "")
        if args[0] == "systemd-run":
            if not self.timer_allowed:
                from nixfence.ssh import RemoteError
                raise RemoteError("systemd-run unavailable")
            self.timer = True
            return Result(0, "Running as unit", "")
        if args[:2] == ("systemctl", "is-active"):
            return Result(0 if self.timer else 3, "active" if self.timer else "inactive", "")
        if args[:2] == ("systemctl", "stop"):
            self.timer = False
            return Result(0, "", "")
        if args[:2] == ("test", "-f"):
            return Result(0 if args[2] in self.scripts else 1, "", "")
        if args[0] == "/bin/sh":
            self.runtime = self.original_runtime.copy()
            self.permanent = self.original_permanent.copy()
            self.booleans = self.original_booleans.copy()
            self.scripts.pop(args[1], None)
            return Result(0, "", "")
        if args[0] == "rm":
            self.scripts.pop(args[-1], None)
            return Result(0, "", "")
        raise AssertionError(f"Unknown sudo command {args}")


@pytest.fixture
def environment(tmp_path):
    secret = tmp_path / "secrets"
    secret.mkdir()
    (secret / "admin_password").write_text("not-a-default-password-value-123456", encoding="utf-8")
    (secret / "id_ed25519").write_text("fake-key-no-real-ssh", encoding="utf-8")
    (secret / "known_hosts").write_text("test.example.org ssh-ed25519 AAAA...", encoding="utf-8")
    web = Path(__file__).resolve().parents[1] / "web"
    settings = Settings(database=tmp_path / "data" / "db.sqlite3", admin_user="admin",
                        admin_password_file=secret / "admin_password", ssh_key=secret / "id_ed25519",
                        known_hosts=secret / "known_hosts", web_dir=web,
                        cookie_secure=False, allowed_origin="http://127.0.0.1:8080")
    db = Database(settings.database)
    fake = FakeSSH()
    client = TestClient(create_app(settings, db=db, ssh_factory=lambda h: fake),
                        base_url="http://127.0.0.1:8080")
    return client, db, fake, settings


@pytest.fixture
def authenticated(environment):
    client, db, fake, _settings = environment
    out = client.post("/api/auth/login", json={"username": "admin",
                      "password": "not-a-default-password-value-123456"})
    assert out.status_code == 200
    csrf = out.json()["csrf"]
    headers = {"X-CSRF-Token": csrf, "Origin": "http://127.0.0.1:8080"}
    return client, db, fake, headers


@pytest.fixture
def enrolled(authenticated):
    client, db, fake, headers = authenticated
    res = client.post("/api/v1/hosts", json={"name": "rocky-01", "address": "192.0.2.12",
                       "ssh_user": "nixfence", "ssh_port": 22}, headers=headers)
    assert res.status_code == 201, res.text
    return client, db, fake, headers, res.json()["id"]
