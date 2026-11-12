import time

import pytest

from nixfence.remote import _rollback_script, expire_operations


def test_rollback_restores_runtime_and_permanent_independently():
    script = _rollback_script("firewall_port", {"zone": "public", "port": 8080, "protocol": "tcp"},
                              old_runtime=True, old_permanent=False)
    assert "firewall-cmd --permanent --zone=public --remove-port=8080/tcp" in script
    assert "firewall-cmd --zone=public --add-port=8080/tcp" in script
    assert "--reload" not in script
    assert "rm -f" in script


def test_expired_operation_is_not_declared_rolled_back(enrolled):
    client, db, _fake, headers, host_id = enrolled
    out = client.post(f"/api/v1/hosts/{host_id}/changes/firewall", headers=headers,
                      json={"zone": "public", "port": 9090, "protocol": "tcp", "allow": True})
    assert out.status_code == 200, out.text
    op_id = out.json()["id"]
    db.execute("UPDATE operations SET expires_at=? WHERE id=?", (int(time.time()) - 2, op_id))
    expire_operations(db)
    status = db.one("SELECT status FROM operations WHERE id=?", (op_id,))["status"]
    assert status == "needs_review"
    assert client.post(f"/api/v1/operations/{op_id}/confirm", headers=headers).status_code == 409


def test_selinux_revert_real_command_path(enrolled):
    client, _db, fake, headers, host_id = enrolled
    out = client.post(f"/api/v1/hosts/{host_id}/changes/selinux", headers=headers,
                      json={"name": "httpd_can_network_connect", "enabled": True})
    assert out.status_code == 200, out.text
    op_id = out.json()["id"]
    assert fake.booleans["httpd_can_network_connect"]
    out = client.post(f"/api/v1/operations/{op_id}/revert", headers=headers)
    assert out.status_code == 200, out.text
    assert fake.booleans["httpd_can_network_connect"] is False


@pytest.mark.parametrize("bad_zone", ["public; rm -rf /", "-evil", "a b", "../"]) 
def test_firewall_target_zone_is_validated(enrolled, bad_zone):
    client, _db, fake, headers, host_id = enrolled
    out = client.post(f"/api/v1/hosts/{host_id}/changes/firewall", headers=headers,
                      json={"zone": bad_zone, "port": 8443, "protocol": "tcp", "allow": True})
    assert out.status_code == 409
    assert not fake.timer


def test_selinux_boolean_name_rejects_command_metacharacters(enrolled):
    client, _db, fake, headers, host_id = enrolled
    out = client.post(f"/api/v1/hosts/{host_id}/changes/selinux", headers=headers,
                      json={"name": "foo; touch /tmp/wrong", "enabled": True})
    assert out.status_code == 409
    assert not fake.timer


def test_firewall_observes_existing_port_state(enrolled):
    client, _db, fake, headers, host_id = enrolled
    fake.runtime[("public", "8443/tcp")] = True
    fake.permanent[("public", "8443/tcp")] = True
    out = client.post(f"/api/v1/hosts/{host_id}/changes/firewall", headers=headers,
                      json={"zone": "public", "port": 8443, "protocol": "tcp", "allow": True})
    assert out.status_code == 409
    assert not fake.timer
