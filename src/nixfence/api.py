"""NixFence Community: authenticated host inventory and safe limited operations."""
from __future__ import annotations

import hashlib
import re
import secrets
import time
from typing import Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .config import Settings
from .database import Database
from .engine import analyze_policy
from .models import FirewallPolicy, PolicyAnalysis
from .remote import (ChangeError, RemoteError, confirm_change, expire_operations,
                     inspect, revert_change, stage_change)
from .ssh import Host, SSH


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Strict):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class HostCreate(Strict):
    name: str = Field(min_length=1, max_length=64)
    address: str = Field(min_length=1, max_length=253)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str = Field(min_length=1, max_length=32)


class FirewallChange(Strict):
    zone: str = Field(min_length=1, max_length=63)
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    allow: bool
    rollback_seconds: int = Field(default=300, ge=120, le=900)


class SELinuxChange(Strict):
    name: str = Field(min_length=1, max_length=128)
    enabled: bool
    rollback_seconds: int = Field(default=300, ge=120, le=900)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_app(settings: Settings | None = None, db: Database | None = None,
               ssh_factory=None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate()
    db = db or Database(settings.database)
    ssh_factory = ssh_factory or (lambda h: SSH(settings, h))
    app = FastAPI(title="NixFence Community", version=__version__, docs_url=None, redoc_url=None)
    hostnames = ["127.0.0.1", "localhost"]
    configured_hostname = urlparse(settings.allowed_origin).hostname
    if configured_hostname:
        hostnames.append(configured_hostname)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hostnames)
    app.mount("/static", StaticFiles(directory=str(settings.web_dir)), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        response.headers["Cache-Control"] = "no-store"
        return response

    def session(request: Request) -> dict:
        token = request.cookies.get("nixfence_session", "")
        if not token or len(token) > 256:
            raise HTTPException(401, "Authentication required")
        row = db.one("SELECT token_hash,csrf_token,expires_at FROM sessions WHERE token_hash=?", (_hash(token),))
        if not row or row["expires_at"] < time.time():
            raise HTTPException(401, "Session expired")
        return row

    def write_session(request: Request, user: dict = Depends(session),
                      x_csrf_token: str | None = Header(default=None)) -> dict:
        if not x_csrf_token or not secrets.compare_digest(x_csrf_token, user["csrf_token"]):
            raise HTTPException(403, "Missing or invalid CSRF token")
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") != settings.allowed_origin:
            raise HTTPException(403, "Origin not allowed")
        return user

    def load_host(host_id: int) -> Host:
        row = db.one("SELECT * FROM hosts WHERE id=?", (host_id,))
        if not row:
            raise HTTPException(404, "Host not found")
        return Host(row["id"], row["name"], row["address"], row["ssh_port"], row["ssh_user"])

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(settings.web_dir / "index.html")

    @app.get("/healthz")
    def health():
        return {"status": "ok", "edition": "community", "version": __version__}

    @app.post("/api/auth/login")
    def login(data: Login, request: Request, response: Response):
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") != settings.allowed_origin:
            raise HTTPException(403, "Origin not allowed")
        ip = request.client.host if request.client else "unknown"
        now = int(time.time())
        attempt = db.one("SELECT attempts, locked_until FROM login_failures WHERE address=?", (ip,))
        if attempt and attempt["locked_until"] > now:
            raise HTTPException(429, "Too many login attempts; try later")
        # Compare hashes to keep timing similar for different-length strings.
        wanted = _hash(settings.admin_password())
        provided = _hash(data.password)
        good = secrets.compare_digest(data.username, settings.admin_user) and secrets.compare_digest(provided, wanted)
        if not good:
            count = (attempt["attempts"] if attempt and attempt["locked_until"] == 0 else 0) + 1
            lock = now + 300 if count >= 5 else 0
            db.execute("INSERT OR REPLACE INTO login_failures (address, attempts, locked_until) VALUES (?,?,?)",
                       (ip, count, lock))
            raise HTTPException(401, "Invalid credentials")
        db.execute("DELETE FROM login_failures WHERE address=?", (ip,))
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        expires = now + settings.session_hours * 3600
        db.execute("INSERT INTO sessions (token_hash,csrf_token,expires_at) VALUES (?,?,?)",
                   (_hash(token), csrf, expires))
        db.execute("DELETE FROM sessions WHERE expires_at<?", (now,))
        response.set_cookie("nixfence_session", token, max_age=settings.session_hours * 3600,
                            httponly=True, secure=settings.cookie_secure, samesite="strict", path="/")
        db.audit("login_success")
        return {"username": settings.admin_user, "csrf": csrf, "expires_at": expires}

    @app.get("/api/auth/session")
    def me(user: dict = Depends(session)):
        return {"username": settings.admin_user, "csrf": user["csrf_token"],
                "expires_at": user["expires_at"]}

    @app.post("/api/auth/logout")
    def logout(response: Response, request: Request, _user: dict = Depends(write_session)):
        token = request.cookies.get("nixfence_session", "")
        db.execute("DELETE FROM sessions WHERE token_hash=?", (_hash(token),))
        response.delete_cookie("nixfence_session", path="/")
        db.audit("logout")
        return {"status": "signed_out"}

    @app.get("/api/v1/about")
    def about(_user: dict = Depends(session)):
        return {"product": "NixFence", "brand": "Byte2craft", "edition": "Community",
                "version": __version__, "host_support": "Rocky/Alma/RHEL 9",
                "capabilities": ["verified SSH discovery", "live firewalld port operations",
                                 "runtime SELinux boolean changes", "timed independent rollback",
                                 "audit trail", "offline policy analysis"],
                "limitations": ["single-admin", "one port at a time", "SELinux changes are runtime-only",
                                "no cross-distribution production validation yet"]}

    @app.get("/api/v1/hosts")
    def hosts(_user: dict = Depends(session)):
        return {"items": db.rows("SELECT * FROM hosts ORDER BY name"),
                "note": "Real hosts only; no synthetic inventory"}

    @app.post("/api/v1/hosts", status_code=201)
    def add_host(data: HostCreate, _user: dict = Depends(write_session)):
        h = Host(None, data.name, data.address, data.ssh_port, data.ssh_user)
        try:
            h.validate()
            info = inspect(h, ssh_factory(h))  # fail closed; no unverified hosts in inventory
            ident = db.execute("INSERT INTO hosts (name,address,ssh_port,ssh_user,created_at) VALUES (?,?,?,?,?)",
                               (h.name, h.address, h.ssh_port, h.ssh_user, int(time.time())))
        except (ValueError, ChangeError) as exc:
            raise HTTPException(400, str(exc)) from exc
        except RemoteError as exc:
            raise HTTPException(502, f"SSH discovery failed: {exc}") from exc
        except Exception as exc:
            if isinstance(exc, HTTPException):
                raise
            raise HTTPException(409, "Host already enrolled or database rejected the record") from exc
        db.audit("host_enrolled", host_id=ident, detail={"address": h.address, "os": info["os"]})
        return {"id": ident, "inspection": info}

    @app.get("/api/v1/hosts/{host_id}/inspect")
    def inspect_host(host_id: int, _user: dict = Depends(session)):
        h = load_host(host_id)
        try:
            return inspect(h, ssh_factory(h))
        except (ChangeError, RemoteError) as exc:
            raise HTTPException(502, str(exc)) from exc

    @app.get("/api/v1/hosts/{host_id}/selinux/booleans")
    def selinux_booleans(host_id: int, _user: dict = Depends(session)):
        h = load_host(host_id)
        try:
            raw = ssh_factory(h).sudo("getsebool", "-a").stdout
            items = []
            for line in raw.splitlines():
                match = re.fullmatch(r"([a-z][a-z0-9_]*)\s+-->\s+(on|off)", line.strip())
                if match:
                    items.append({"name": match.group(1), "enabled": match.group(2) == "on"})
            return {"items": items, "persistent": False}
        except RemoteError as exc:
            raise HTTPException(502, str(exc)) from exc

    @app.get("/api/v1/hosts/{host_id}/firewall")
    def firewall(host_id: int, zone: str, _user: dict = Depends(session)):
        h = load_host(host_id)
        try:
            info = inspect(h, ssh_factory(h))
            if zone not in info["zones"]:
                raise ChangeError("Unknown zone")
            ssh = ssh_factory(h)
            return {"zone": zone,
                    "runtime_ports": ssh.sudo("firewall-cmd", f"--zone={zone}", "--list-ports").stdout,
                    "permanent_ports": ssh.sudo("firewall-cmd", "--permanent", f"--zone={zone}", "--list-ports").stdout,
                    "runtime_services": ssh.sudo("firewall-cmd", f"--zone={zone}", "--list-services").stdout}
        except (ChangeError, RemoteError) as exc:
            raise HTTPException(502, str(exc)) from exc

    @app.post("/api/v1/hosts/{host_id}/changes/firewall")
    def change_firewall(host_id: int, data: FirewallChange,
                        _user: dict = Depends(write_session)):
        h = load_host(host_id)
        try:
            return stage_change(db, h, ssh_factory(h), kind="firewall_port",
                                target={"zone": data.zone, "port": data.port, "protocol": data.protocol},
                                desired=data.allow, seconds=data.rollback_seconds)
        except ChangeError as exc:
            raise HTTPException(409, str(exc)) from exc
        except (ValueError, RemoteError) as exc:
            raise HTTPException(502, str(exc)) from exc

    @app.post("/api/v1/hosts/{host_id}/changes/selinux")
    def change_selinux(host_id: int, data: SELinuxChange,
                       _user: dict = Depends(write_session)):
        h = load_host(host_id)
        try:
            return stage_change(db, h, ssh_factory(h), kind="selinux_boolean",
                                target={"name": data.name}, desired=data.enabled,
                                seconds=data.rollback_seconds)
        except ChangeError as exc:
            raise HTTPException(409, str(exc)) from exc
        except RemoteError as exc:
            raise HTTPException(502, str(exc)) from exc

    @app.get("/api/v1/operations")
    def operations(_user: dict = Depends(session)):
        expire_operations(db)
        return {"items": db.rows("SELECT * FROM operations ORDER BY created_at DESC LIMIT 100"),
                "warning": "Expired host timers must be inspected to verify actual rollback"}

    @app.post("/api/v1/operations/{operation_id}/confirm")
    def confirm(operation_id: str, _user: dict = Depends(write_session)):
        row = db.one("SELECT host_id FROM operations WHERE id=?", (operation_id,))
        if not row:
            raise HTTPException(404, "Operation not found")
        h = load_host(row["host_id"])
        try:
            return confirm_change(db, h, ssh_factory(h), operation_id)
        except ChangeError as exc:
            raise HTTPException(409, str(exc)) from exc
        except RemoteError as exc:
            raise HTTPException(502, str(exc)) from exc

    @app.post("/api/v1/operations/{operation_id}/revert")
    def revert(operation_id: str, _user: dict = Depends(write_session)):
        row = db.one("SELECT host_id FROM operations WHERE id=?", (operation_id,))
        if not row:
            raise HTTPException(404, "Operation not found")
        h = load_host(row["host_id"])
        try:
            return revert_change(db, h, ssh_factory(h), operation_id)
        except ChangeError as exc:
            raise HTTPException(409, str(exc)) from exc
        except RemoteError as exc:
            raise HTTPException(502, str(exc)) from exc

    @app.get("/api/v1/audit")
    def audit(_user: dict = Depends(session)):
        return {"items": db.rows("SELECT * FROM audit ORDER BY id DESC LIMIT 150")}

    @app.post("/api/v1/policies/analyze", response_model=PolicyAnalysis)
    def analyze(policy: FirewallPolicy, _user: dict = Depends(write_session)):
        return analyze_policy(policy)

    return app
