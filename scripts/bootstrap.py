"""Generate local deployment secrets without checking them into Git."""
from __future__ import annotations

import os
import secrets
import shutil
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
dirpath = root / "secrets"
dirpath.mkdir(parents=True, exist_ok=True)
try:
    os.chmod(dirpath, 0o750)
except OSError:
    pass
password = dirpath / "admin_password"
if password.exists():
    print("Administrator password file already exists (left unchanged).")
else:
    pwd = secrets.token_urlsafe(32)
    password.write_text(pwd + "\n", encoding="utf-8")
    try:
        os.chmod(password, 0o640)
    except OSError:
        pass
    print("\nNixFence administrator password (save it securely; printed once):\n")
    print(pwd)
    print("\n")
keyfile = dirpath / "id_ed25519"
if keyfile.exists():
    print("SSH key already exists (left unchanged).")
elif shutil.which("ssh-keygen"):
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(keyfile)], check=True)
    print("Generated SSH key:", keyfile, "public key:", str(keyfile) + ".pub")
else:
    print("OpenSSH ssh-keygen is unavailable. Generate secrets/id_ed25519 manually.")
known = dirpath / "known_hosts"
if not known.exists():
    known.touch()
    print("Created EMPTY known_hosts file. Pin and independently verify each host key before enrollment.")
print("\nIMPORTANT (Linux bind mounts): the container runs as UID/GID 10001.")
print("Ensure secrets/ is group-traversable by GID 10001, and password/key are group-readable")
print("only by GID 10001. Example after verifying ownership: sudo chgrp -R 10001 secrets")
print("Then: chmod 750 secrets && chmod 640 secrets/admin_password secrets/id_ed25519")
print("Private SSH keys and the administrator password MUST NOT be committed to Git.")
