"""Strict host-key-verified OpenSSH transport. Never accepts unverified host keys."""
from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass
from ipaddress import ip_address

from .config import Settings

_ADDRESS = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$")
_USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class RemoteError(RuntimeError):
    pass


@dataclass(frozen=True)
class Host:
    id: int | None
    name: str
    address: str
    ssh_port: int
    ssh_user: str

    def validate(self) -> None:
        try:
            ip_address(self.address)
        except ValueError:
            if not _ADDRESS.fullmatch(self.address) or ".." in self.address or self.address.endswith("."):
                raise ValueError("Invalid host address") from None
        if not _USERNAME.fullmatch(self.ssh_user):
            raise ValueError("SSH user must be a Linux username")
        if not 1 <= self.ssh_port <= 65535:
            raise ValueError("Invalid SSH port")
        if not self.name or len(self.name) > 64 or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", self.name):
            raise ValueError("Invalid host label")


@dataclass(frozen=True)
class Result:
    code: int
    stdout: str
    stderr: str


def _trim_error(message: str) -> str:
    return message.replace("\r", " ").strip()[-500:]


class SSH:
    def __init__(self, settings: Settings, host: Host):
        host.validate()
        self.settings = settings
        self.host = host

    def run(self, *command: str, input_text: str | None = None, timeout: int = 25,
            expect: tuple[int, ...] = (0,)) -> Result:
        if not command or any(not isinstance(a, str) or "\x00" in a for a in command):
            raise ValueError("Invalid SSH command")
        # Explicit SSH destination and options; shlex.quote protects each remote argument.
        args = ["ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes",
                "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
                "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={self.settings.known_hosts}",
                "-o", "GlobalKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes",
                "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
                "-o", "ControlMaster=no", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5",
                "-o", "ServerAliveCountMax=1", "-i", str(self.settings.ssh_key),
                "-p", str(self.host.ssh_port), "--", f"{self.host.ssh_user}@{self.host.address}",
                shlex.join(command)]
        try:
            result = subprocess.run(args, input=input_text, capture_output=True, text=True,
                                    timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RemoteError("SSH remote command timed out") from exc
        except OSError as exc:
            raise RemoteError("SSH client unavailable; check image and mounted SSH key") from exc
        if len(result.stdout) > 256_000 or len(result.stderr) > 20_000:
            raise RemoteError("Remote output exceeded the safety limit")
        if result.returncode not in expect:
            raise RemoteError(f"Remote command failed (exit {result.returncode}): {_trim_error(result.stderr) or _trim_error(result.stdout)}")
        return Result(result.returncode, result.stdout.strip(), result.stderr.strip())

    def sudo(self, *args: str, **kwargs) -> Result:
        return self.run("sudo", "-n", *args, **kwargs)
