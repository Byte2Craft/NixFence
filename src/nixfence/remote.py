"""Real host inspection and narrow, watchdog-protected runtime changes.

No arbitrary shell endpoint is exposed. Remote scripts only contain validated
port/zone/boolean parameters and are executed with explicit administrator action.
"""
from __future__ import annotations

import json
import re
import shlex
import time
from uuid import uuid4

from .database import Database
from .ssh import Host, RemoteError, SSH

_ZONE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")
_BOOLEAN = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_PORT = re.compile(r"^[1-9][0-9]{0,4}/(?:tcp|udp)$")
_SUPPORTED = {"rocky", "almalinux", "rhel"}


class ChangeError(ValueError):
    pass


def parse_os_release(text: str) -> dict:
    parsed = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            key, val = line.split("=", 1)
            parsed[key] = val.strip().strip('"\'')
    return {"name": parsed.get("PRETTY_NAME", "Linux"), "id": parsed.get("ID", ""),
            "version": parsed.get("VERSION_ID", "")}


def inspect(host: Host, ssh: SSH) -> dict:
    osinfo = parse_os_release(ssh.run("cat", "/etc/os-release").stdout)
    if osinfo["id"] not in _SUPPORTED or osinfo["version"].split(".")[0] != "9":
        raise ChangeError("Only verified Rocky Linux 9, AlmaLinux 9 and RHEL 9 hosts are supported")
    state = ssh.sudo("firewall-cmd", "--state").stdout
    if state != "running":
        raise ChangeError("firewalld is not running")
    selinux = ssh.sudo("getenforce").stdout
    active = ssh.sudo("firewall-cmd", "--get-active-zones").stdout
    default_zone = ssh.sudo("firewall-cmd", "--get-default-zone").stdout
    zones = ssh.sudo("firewall-cmd", "--get-zones").stdout.split()
    return {"host": host.name, "os": osinfo, "firewalld": state, "selinux": selinux,
            "active_zones": active, "default_zone": default_zone, "zones": zones,
            "zone_details": ssh.sudo("firewall-cmd", f"--zone={default_zone}", "--list-all").stdout}


def _firewall_query(ssh: SSH, zone: str, port_spec: str, permanent: bool) -> bool:
    if not _ZONE.fullmatch(zone) or not _PORT.fullmatch(port_spec):
        raise ChangeError("Invalid zone/port")
    args = ["firewall-cmd"]
    if permanent:
        args.append("--permanent")
    args.extend([f"--zone={zone}", f"--query-port={port_spec}"])
    res = ssh.sudo(*args, expect=(0, 1))
    if res.code == 1 and res.stderr:
        raise RemoteError(f"firewalld query failed: {res.stderr[:250]}")
    return res.code == 0


def _bool_query(ssh: SSH, name: str) -> bool:
    if not _BOOLEAN.fullmatch(name):
        raise ChangeError("Invalid SELinux boolean name")
    value = ssh.sudo("getsebool", name).stdout
    match = re.fullmatch(r"\s*" + re.escape(name) + r"\s+-->\s+(on|off)\s*", value)
    if not match:
        raise RemoteError("SELinux boolean output format not recognized")
    return match.group(1) == "on"


def _port_cmd(zone: str, port_spec: str, state: bool, permanent: bool = False) -> list[str]:
    return (["firewall-cmd"] + (["--permanent"] if permanent else []) +
            [f"--zone={zone}", f"--{'add' if state else 'remove'}-port={port_spec}"])


def _rollback_script(kind: str, target: dict, old_runtime: bool,
                     old_permanent: bool | None) -> str:
    """Idempotent restoration script, runs on the host even if SSH is lost."""
    lines = ["#!/bin/sh", "set -eu", "export PATH=/usr/sbin:/usr/bin:/sbin:/bin"]
    if kind == "firewall_port":
        zone = target["zone"]
        spec = f"{target['port']}/{target['protocol']}"
        for permanent, expected in ((True, old_permanent), (False, old_runtime)):
            q = ["firewall-cmd"] + (["--permanent"] if permanent else []) + [f"--zone={zone}", f"--query-port={spec}"]
            m = _port_cmd(zone, spec, bool(expected), permanent)
            # Shell commands are built from validated zone, port and protocol only.
            test = shlex.join(q)
            op = shlex.join(m)
            lines.extend([f"if {test} >/dev/null 2>&1; then",
                          "  :" if expected else f"  {op}",
                          "else", f"  {op}" if expected else "  :", "fi"])
    elif kind == "selinux_boolean":
        name = target["name"]
        lines.append(shlex.join(["setsebool", name, "on" if old_runtime else "off"]))
    else:
        raise ChangeError("Invalid operation kind")
    lines.append("rm -f -- \"$0\"")
    return "\n".join(lines) + "\n"


def _unit(op_id: str) -> str:
    return f"nixfence-rb-{op_id}"


def _script_path(op_id: str) -> str:
    return f"/run/nixfence/rollback-{op_id}.sh"


def _schedule(ssh: SSH, op_id: str, script: str, seconds: int) -> None:
    path = _script_path(op_id)
    ssh.sudo("install", "-d", "-m", "0700", "/run/nixfence")
    ssh.sudo("tee", path, input_text=script)
    ssh.sudo("chmod", "0700", path)
    ssh.sudo("systemd-run", f"--unit={_unit(op_id)}", f"--on-active={seconds}s",
             "--collect", "/bin/sh", path)
    active = ssh.sudo("systemctl", "is-active", _unit(op_id) + ".timer").stdout
    if active != "active":
        raise RemoteError("Host-side rollback timer did not become active")


def _cancel(ssh: SSH, op_id: str) -> None:
    ssh.sudo("systemctl", "stop", _unit(op_id) + ".timer")
    ssh.sudo("rm", "-f", _script_path(op_id))


def _read_operation(db: Database, op_id: str) -> dict:
    row = db.one("SELECT * FROM operations WHERE id=?", (op_id,))
    if not row:
        raise ChangeError("Operation not found")
    return row


def _operation_state(ssh: SSH, op: dict) -> tuple[bool, bool | None]:
    target = json.loads(op["target"])
    if op["kind"] == "firewall_port":
        spec = f"{target['port']}/{target['protocol']}"
        return (_firewall_query(ssh, target["zone"], spec, False),
                _firewall_query(ssh, target["zone"], spec, True))
    return _bool_query(ssh, target["name"]), None


def stage_change(db: Database, host: Host, ssh: SSH, *, kind: str, target: dict,
                 desired: bool, seconds: int) -> dict:
    if not 120 <= seconds <= 900:
        raise ChangeError("Rollback timeout must be between 120 and 900 seconds")
    details = inspect(host, ssh)
    if kind == "firewall_port":
        zone, port, protocol = target["zone"], target["port"], target["protocol"]
        if not _ZONE.fullmatch(zone) or zone not in details["zones"]:
            raise ChangeError("Unknown or invalid firewalld zone")
        if not isinstance(port, int) or not 1 <= port <= 65535 or protocol not in ("tcp", "udp"):
            raise ChangeError("Invalid port or protocol")
        if not desired and port == host.ssh_port and protocol == "tcp":
            raise ChangeError("Removing the SSH management port is blocked")
        spec = f"{port}/{protocol}"
        before_runtime = _firewall_query(ssh, zone, spec, False)
        before_permanent = _firewall_query(ssh, zone, spec, True)
        if before_runtime == desired and before_permanent == desired:
            raise ChangeError("Port already has the requested runtime and permanent state")
        command = _port_cmd(zone, spec, desired, False)
    elif kind == "selinux_boolean":
        name = target["name"]
        if not _BOOLEAN.fullmatch(name):
            raise ChangeError("Invalid SELinux boolean name")
        if details["selinux"] == "Disabled":
            raise ChangeError("SELinux is disabled")
        before_runtime = _bool_query(ssh, name)
        before_permanent = None
        if before_runtime == desired:
            raise ChangeError("SELinux boolean is already in requested runtime state")
        command = ["setsebool", name, "on" if desired else "off"]
    else:
        raise ChangeError("Unsupported operation")
    operation_id = uuid4().hex
    expires_at = int(time.time()) + seconds
    record = {"id": operation_id, "kind": kind, "target": json.dumps(target, sort_keys=True),
              "desired": "on" if desired else "off", "before_runtime": before_runtime,
              "before_permanent": before_permanent, "expires_at": expires_at}
    try:
        db.lock_host(host.id, record)
    except ValueError as exc:
        raise ChangeError(str(exc)) from exc
    timer_verified = False
    try:
        script = _rollback_script(kind, target, before_runtime, before_permanent)
        _schedule(ssh, operation_id, script, seconds)
        timer_verified = True
        db.execute("UPDATE operations SET status='pending' WHERE id=?", (operation_id,))
        ssh.sudo(*command)
        new_state = _operation_state(db=db, ssh=ssh, op=record) if False else None
        # Only validate runtime here; permanent is intentionally untouched until confirmation.
        current = (_firewall_query(ssh, target["zone"], f"{target['port']}/{target['protocol']}", False)
                   if kind == "firewall_port" else _bool_query(ssh, target["name"]))
        if current != desired:
            raise RemoteError("Remote runtime did not match the requested state")
        db.audit("change_staged", host_id=host.id, detail={"id": operation_id, "kind": kind,
                                                           "target": target, "expires_at": expires_at})
    except (RemoteError, ChangeError, OSError, ValueError) as exc:
        # When the watchdog is running, NEVER cancel it after a partial apply.
        status = "needs_review" if timer_verified else "failed"
        db.execute("UPDATE operations SET status=?, detail=? WHERE id=?",
                   (status, str(exc)[:500], operation_id))
        db.audit("change_failed", host_id=host.id, detail={"id": operation_id,
                                                            "rollback_scheduled": timer_verified})
        raise RemoteError(f"Operation {operation_id} failed; rollback scheduled={timer_verified}. "
                          "Review host timer and operation state") from exc
    return {"id": operation_id, "host_id": host.id, "kind": kind, "target": target,
            "desired": desired, "status": "pending", "expires_at": expires_at,
            "rollback_seconds": seconds,
            "confirmation_note": ("Confirm makes the port permanent" if kind == "firewall_port"
                                  else "Confirm leaves a runtime-only SELinux boolean; not persistent")}


def confirm_change(db: Database, host: Host, ssh: SSH, op_id: str) -> dict:
    op = _read_operation(db, op_id)
    if op["host_id"] != host.id or op["status"] != "pending":
        raise ChangeError("Operation is not pending for this host")
    if op["expires_at"] < int(time.time()) + 30:
        raise ChangeError("Less than 30 seconds to rollback deadline; do not confirm")
    active = ssh.sudo("systemctl", "is-active", _unit(op_id) + ".timer").stdout
    if active != "active":
        raise RemoteError("Rollback timer is not active; cannot safely confirm")
    wanted = op["desired"] == "on"
    runtime, _ = _operation_state(ssh, op)
    if runtime != wanted:
        raise ChangeError("Current runtime no longer matches staged state")
    db.execute("UPDATE operations SET status='confirming' WHERE id=?", (op_id,))
    try:
        if op["kind"] == "firewall_port":
            target = json.loads(op["target"])
            ssh.sudo(*_port_cmd(target["zone"], f"{target['port']}/{target['protocol']}", wanted,
                                      permanent=True))
            runtime2, permanent2 = _operation_state(ssh, op)
            if runtime2 != wanted or permanent2 != wanted:
                raise RemoteError("Permanent firewall state could not be verified")
        _cancel(ssh, op_id)
        runtime3, permanent3 = _operation_state(ssh, op)
        if runtime3 != wanted or (op["kind"] == "firewall_port" and permanent3 != wanted):
            raise RemoteError("State changed during confirmation; manual review required")
    except (RemoteError, OSError) as exc:
        db.execute("UPDATE operations SET status='needs_review', detail=? WHERE id=?", (str(exc)[:500], op_id))
        db.audit("confirm_needs_review", host_id=host.id, detail={"id": op_id})
        raise RemoteError("Confirmation incomplete; rollback may still execute. Verify on host") from exc
    status = "confirmed" if op["kind"] == "firewall_port" else "confirmed_runtime_only"
    db.execute("UPDATE operations SET status=? WHERE id=?", (status, op_id))
    db.audit("change_confirmed", host_id=host.id, detail={"id": op_id, "persistence": status})
    return {"id": op_id, "status": status, "persistent": status == "confirmed"}


def revert_change(db: Database, host: Host, ssh: SSH, op_id: str) -> dict:
    op = _read_operation(db, op_id)
    if op["host_id"] != host.id or op["status"] not in ("pending", "needs_review", "reverting", "confirming"):
        raise ChangeError("Operation cannot be reverted in its present state")
    db.execute("UPDATE operations SET status='reverting' WHERE id=?", (op_id,))
    try:
        # Scheduled service may already have run and removed its script.
        existing = ssh.sudo("test", "-f", _script_path(op_id), expect=(0, 1)).code == 0
        if existing:
            ssh.sudo("/bin/sh", _script_path(op_id))
        # If the unit expired it may already be inactive, so stopping is best-effort.
        ssh.sudo("systemctl", "stop", _unit(op_id) + ".timer", expect=(0, 5))
        runtime, permanent = _operation_state(ssh, op)
        if runtime != bool(op["before_runtime"]) or (op["before_permanent"] is not None and
                                                        permanent != bool(op["before_permanent"])):
            raise RemoteError("Restored state did not match original; host needs manual review")
    except RemoteError as exc:
        db.execute("UPDATE operations SET status='needs_review', detail=? WHERE id=?", (str(exc)[:500], op_id))
        db.audit("revert_needs_review", host_id=host.id, detail={"id": op_id})
        raise
    db.execute("UPDATE operations SET status='reverted_verified' WHERE id=?", (op_id,))
    db.audit("change_reverted", host_id=host.id, detail={"id": op_id})
    return {"id": op_id, "status": "reverted_verified"}


def expire_operations(db: Database) -> None:
    # Never label a timed-out operation "rolled back" without confirming host state.
    now = int(time.time())
    db.execute("UPDATE operations SET status='needs_review', detail='Rollback deadline passed: host not yet verified' "
               "WHERE status='pending' AND expires_at<=?", (now,))
