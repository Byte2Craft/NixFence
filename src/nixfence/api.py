"""Byte2craft NixFence technical-preview API.

Read-only demo inventory and deterministic policy analysis only.
No authentication is present; binding must remain loopback-only.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .engine import analyze_policy
from .models import FirewallPolicy, PolicyAnalysis
from .sample_data import HOSTS, POLICIES

app = FastAPI(
    title="Byte2craft NixFence (Technical Preview)",
    description="Offline policy analysis and synthetic demo data. No remote execution.",
    version=__version__,
    docs_url="/api/docs",
    redoc_url=None,
)

WEB_DIR = Path(os.getenv("NIXFENCE_WEB_DIR", str(Path(__file__).resolve().parents[2] / "web")))
if not (WEB_DIR / "index.html").exists():
    WEB_DIR = Path("/app/web")
app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(WEB_DIR / "index.html")


@app.get("/healthz")
def health():
    return {"status": "ok", "mode": "read-only-demo"}


@app.get("/api/v1/about")
def about():
    return {
        "product": "NixFence", "brand": "Byte2craft", "homepage": "https://byte2craft.com",
        "version": __version__, "edition": "Community Technical Preview",
        "read_only": True, "remote_execution": False, "auth_enabled": False,
        "status": "prototype-not-for-production",
    }


@app.get("/api/v1/hosts")
def hosts():
    return {"demo": True, "items": HOSTS, "total": len(HOSTS)}


@app.get("/api/v1/policies")
def policies():
    return {"demo": True, "items": POLICIES, "total": len(POLICIES)}


@app.get("/api/v1/summary")
def summary():
    return {
        "demo": True,
        "hosts": len(HOSTS), "policy_sets": len(POLICIES),
        "enforcing": sum(h["selinux"] == "Enforcing" for h in HOSTS),
        "notice": "Illustrative data only; no live hosts connected.",
    }




@app.post("/api/v1/policies/analyze", response_model=PolicyAnalysis)
def analyze(policy: FirewallPolicy):
    return analyze_policy(policy)
