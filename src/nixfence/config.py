"""Validated deployment configuration. No default administrator password."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database: Path
    admin_user: str
    admin_password_file: Path
    ssh_key: Path
    known_hosts: Path
    web_dir: Path
    cookie_secure: bool
    allowed_origin: str
    session_hours: int = 8

    @classmethod
    def from_env(cls) -> "Settings":
        web_default = Path(__file__).resolve().parents[2] / "web"
        if not (web_default / "index.html").exists():
            web_default = Path("/app/web")
        return cls(
            database=Path(os.getenv("NIXFENCE_DB", "/data/nixfence.sqlite3")),
            admin_user=os.getenv("NIXFENCE_ADMIN_USER", "admin"),
            admin_password_file=Path(os.getenv("NIXFENCE_ADMIN_PASSWORD_FILE", "/run/nixfence-secrets/admin_password")),
            ssh_key=Path(os.getenv("NIXFENCE_SSH_KEY_FILE", "/run/nixfence-secrets/id_ed25519")),
            known_hosts=Path(os.getenv("NIXFENCE_KNOWN_HOSTS", "/run/nixfence-secrets/known_hosts")),
            web_dir=Path(os.getenv("NIXFENCE_WEB_DIR", str(web_default))),
            cookie_secure=os.getenv("NIXFENCE_COOKIE_SECURE", "false").lower() == "true",
            allowed_origin=os.getenv("NIXFENCE_ALLOWED_ORIGIN", "http://127.0.0.1:8080").rstrip("/"),
        )

    def validate(self) -> None:
        if not self.admin_user or len(self.admin_user) > 64:
            raise ValueError("Invalid administrator user")
        if not self.admin_password_file.is_file():
            raise ValueError("Admin password file missing. Run python scripts/bootstrap.py")
        if len(self.admin_password_file.read_text(encoding="utf-8").strip()) < 20:
            raise ValueError("Admin password must be at least 20 characters")
        if not self.ssh_key.is_file() or not self.known_hosts.is_file():
            raise ValueError("SSH private key or pinned known_hosts file missing")
        if not (self.web_dir / "index.html").is_file():
            raise ValueError("Web UI missing")
        self.database.parent.mkdir(parents=True, exist_ok=True)

    def admin_password(self) -> str:
        return self.admin_password_file.read_text(encoding="utf-8").strip()
