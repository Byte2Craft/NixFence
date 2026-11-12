import pytest


def test_requires_authentication(environment):
    client, *_ = environment
    assert client.get("/healthz").status_code == 200
    assert client.get("/api/v1/hosts").status_code == 401
    assert client.get("/api/v1/operations").status_code == 401
    assert client.post("/api/v1/hosts", json={}).status_code == 401


def test_login_logout_and_csrf(authenticated):
    client, _db, _fake, headers = authenticated
    assert client.get("/api/auth/session").status_code == 200
    assert client.post("/api/v1/hosts", json={"name": "server-01"}).status_code == 403
    wrong_origin = {"X-CSRF-Token": headers["X-CSRF-Token"], "Origin": "https://evil.example"}
    assert client.post("/api/auth/logout", headers=wrong_origin).status_code == 403
    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/v1/hosts").status_code == 401


def test_bruteforce_guard(environment):
    client, *_ = environment
    for _ in range(5):
        assert client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 429


def test_real_enrollment_and_inspection(enrolled):
    client, _db, fake, _headers, host_id = enrolled
    rows = client.get("/api/v1/hosts").json()["items"]
    assert len(rows) == 1 and rows[0]["name"] == "rocky-01"
    inspect = client.get(f"/api/v1/hosts/{host_id}/inspect").json()
    assert inspect["firewalld"] == "running"
    assert inspect["os"]["id"] == "rocky"
    assert inspect["selinux"] == "Enforcing"
    assert any(op[0] == "run" and op[1][0] == "cat" for op in fake.calls)


def test_reject_unsupported_distro(authenticated):
    client, _db, fake, headers = authenticated
    fake.os_release = 'ID="ubuntu"\nVERSION_ID="24.04"'
    out = client.post("/api/v1/hosts", headers=headers, json={"name": "web", "address": "192.0.2.2",
                                                                 "ssh_user": "nixfence"})
    assert out.status_code == 400
    assert not client.get("/api/v1/hosts").json()["items"]


@pytest.mark.parametrize("address", ["--ProxyCommand=bad", "example.org;echo hello", "host..bad"])
def test_reject_invalid_host_address(authenticated, address):
    client, _db, _fake, headers = authenticated
    out = client.post("/api/v1/hosts", headers=headers, json={"name": "evil", "address": address,
                                                                  "ssh_user": "nixfence"})
    assert out.status_code == 400


def test_firewall_stage_and_confirm(enrolled):
    client, _db, fake, headers, host_id = enrolled
    payload = {"zone": "public", "port": 8443, "protocol": "tcp", "allow": True,
               "rollback_seconds": 300}
    out = client.post(f"/api/v1/hosts/{host_id}/changes/firewall", headers=headers, json=payload)
    assert out.status_code == 200, out.text
    operation_id = out.json()["id"]
    assert fake.runtime[("public", "8443/tcp")] is True
    assert fake.permanent.get(("public", "8443/tcp"), False) is False
    assert fake.timer
    # The watchdog was scheduled before applying any firewall state.
    timer_index = next(i for i, c in enumerate(fake.calls) if c[1][0] == "systemd-run")
    add_index = next(i for i, c in enumerate(fake.calls) if c[1][0] == "firewall-cmd"
                     and "--add-port=8443/tcp" in c[1])
    assert timer_index < add_index
    complete = client.post(f"/api/v1/operations/{operation_id}/confirm", headers=headers)
    assert complete.status_code == 200, complete.text
    assert complete.json()["status"] == "confirmed"
    assert fake.permanent[("public", "8443/tcp")] is True
    assert not fake.timer
    assert client.get("/api/v1/audit").json()["items"]


def test_firewall_revert(enrolled):
    client, _db, fake, headers, host_id = enrolled
    out = client.post(f"/api/v1/hosts/{host_id}/changes/firewall", headers=headers,
                      json={"zone": "public", "port": 443, "protocol": "tcp", "allow": True})
    assert out.status_code == 200, out.text
    operation_id = out.json()["id"]
    out = client.post(f"/api/v1/operations/{operation_id}/revert", headers=headers)
    assert out.status_code == 200, out.text
    assert out.json()["status"] == "reverted_verified"
    assert fake.runtime.get(("public", "443/tcp"), False) is False
    assert not fake.timer


def test_untrusted_no_timer_means_no_live_modification(enrolled):
    client, db, fake, headers, host_id = enrolled
    fake.timer_allowed = False
    out = client.post(f"/api/v1/hosts/{host_id}/changes/firewall", headers=headers,
                      json={"zone": "public", "port": 9999, "protocol": "tcp", "allow": True})
    assert out.status_code == 502
    assert not fake.runtime.get(("public", "9999/tcp"), False)
    assert db.one("SELECT status FROM operations")["status"] == "failed"


def test_block_removal_of_ssh_management_port(enrolled):
    client, _db, fake, headers, host_id = enrolled
    out = client.post(f"/api/v1/hosts/{host_id}/changes/firewall", headers=headers,
                      json={"zone": "public", "port": 22, "protocol": "tcp", "allow": False})
    assert out.status_code == 409
    assert not any(c[1][0] == "systemd-run" for c in fake.calls)


def test_reject_duplicate_concurrent_host_operation(enrolled):
    client, _db, _fake, headers, host_id = enrolled
    one = client.post(f"/api/v1/hosts/{host_id}/changes/firewall", headers=headers,
                      json={"zone": "public", "port": 8443, "protocol": "tcp", "allow": True})
    assert one.status_code == 200
    two = client.post(f"/api/v1/hosts/{host_id}/changes/firewall", headers=headers,
                      json={"zone": "public", "port": 9443, "protocol": "tcp", "allow": True})
    assert two.status_code == 409


def test_selinux_runtime_toggle_is_not_persistent(enrolled):
    client, _db, fake, headers, host_id = enrolled
    listed = client.get(f"/api/v1/hosts/{host_id}/selinux/booleans").json()
    assert len(listed["items"]) == 2
    out = client.post(f"/api/v1/hosts/{host_id}/changes/selinux", headers=headers,
                      json={"name": "httpd_can_network_connect", "enabled": True})
    assert out.status_code == 200, out.text
    assert fake.booleans["httpd_can_network_connect"] is True
    opid = out.json()["id"]
    out = client.post(f"/api/v1/operations/{opid}/confirm", headers=headers)
    assert out.status_code == 200, out.text
    assert out.json() == {"id": opid, "status": "confirmed_runtime_only", "persistent": False}
    assert not fake.timer
    assert not any("-P" in c[1] for c in fake.calls)


def test_policy_analysis_requires_session_and_csrf(authenticated):
    client, _db, _fake, headers = authenticated
    body = {"name": "smoke", "rules": []}
    assert client.post("/api/v1/policies/analyze", json=body).status_code == 403
    out = client.post("/api/v1/policies/analyze", json=body, headers=headers)
    assert out.status_code == 200 and out.json()["analysis_only"] is True
