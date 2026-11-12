import subprocess

import pytest

from nixfence.ssh import Host, SSH


def test_open_ssh_must_pin_host_key(monkeypatch, environment):
    _, _, _, settings = environment
    cmd = []

    def mock_run(args, **kwargs):
        cmd.extend(args)
        return subprocess.CompletedProcess(args, 0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_run)
    host = Host(1, "web-01", "192.0.2.21", 2222, "nixfence")
    out = SSH(settings, host).run("sudo", "-n", "firewall-cmd", "--zone=public", "--list-ports")
    assert out.stdout == "ok"
    assert "StrictHostKeyChecking=yes" in cmd
    assert "BatchMode=yes" in cmd
    assert "PasswordAuthentication=no" in cmd
    assert "IdentitiesOnly=yes" in cmd
    assert "ForwardAgent=no" in cmd
    assert f"UserKnownHostsFile={settings.known_hosts}" in cmd
    assert "--zone=public" in cmd[-1]
    assert "2222" in cmd


def test_remote_argument_is_shell_quoted(monkeypatch, environment):
    _, _, _, settings = environment
    commands = []

    def mock_run(args, **kwargs):
        commands.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_run)
    SSH(settings, Host(1, "rocky", "192.0.2.20", 22, "nixfence")).run("echo", "abc; rm -rf /")
    assert commands[0][-1] == "echo 'abc; rm -rf /'"


@pytest.mark.parametrize("hostname", ["; touch /tmp/pwn", "-oProxyCommand=bad", "abc..com", "name with spaces"])
def test_invalid_destination_rejected(environment, hostname):
    _, _, _, settings = environment
    with pytest.raises(ValueError):
        SSH(settings, Host(1, "test", hostname, 22, "nixfence"))
