import pytest
from pydantic import ValidationError

from nixfence.engine import analyze_policy
from nixfence.models import FirewallPolicy


def test_normalizes_sorts_and_reports_public_ssh():
    policy = FirewallPolicy.model_validate({
        "name": "demo", "rules": [
            {"id": "later", "priority": 20, "source": "10.20.0.0/16", "protocol": "tcp", "destination_port": 443, "action": "ACCEPT"},
            {"id": "first", "priority": 10, "source": "0.0.0.0/0", "protocol": "tcp", "destination_port": 22, "action": "ACCEPT"},
        ]})
    out = analyze_policy(policy)
    assert [r.id for r in out.normalized_rules] == ["first", "later"]
    assert "SSH_OPEN_TO_WORLD" in {i.code for i in out.issues}
    assert out.analysis_only is True
    assert out.live_apply_available is False


def test_duplicate_priorities_and_shadowing():
    policy = FirewallPolicy.model_validate({"name": "test", "rules": [
        {"id": "a", "priority": 10, "source": "10.0.0.0/8", "protocol": "tcp", "destination_port": 443, "action": "ACCEPT"},
        {"id": "b", "priority": 10, "source": "10.1.0.0/16", "protocol": "tcp", "destination_port": 443, "action": "DROP"},
    ]})
    codes = {i.code for i in analyze_policy(policy).issues}
    assert "DUPLICATE_PRIORITY" in codes
    assert "SHADOWED_RULE" in codes


def test_invalid_cidr_rejected():
    with pytest.raises(ValidationError):
        FirewallPolicy.model_validate({"name": "safe", "rules": [
            {"id": "x", "priority": 1, "source": "malicious; rm -rf /", "protocol": "tcp", "destination_port": 443, "action": "ACCEPT"}
        ]})


def test_icmp_no_ports():
    with pytest.raises(ValidationError):
        FirewallPolicy.model_validate({"name": "safe", "rules": [
            {"id": "x", "priority": 1, "source": "10.0.0.0/8", "protocol": "icmp", "destination_port": 443, "action": "DROP"}
        ]})


def test_ssh_management_warning():
    policy = FirewallPolicy.model_validate({"name": "safe", "management_sources": ["10.1.1.0/24"], "rules": []})
    assert "MGMT_SSH_NOT_EXPLICIT" in {i.code for i in analyze_policy(policy).issues}


def test_correct_management_rule():
    policy = FirewallPolicy.model_validate({"name": "safe", "management_sources": ["10.1.1.0/24"], "rules": [
        {"id": "allow-mgmt", "priority": 10, "source": "10.0.0.0/8", "protocol": "tcp", "destination_port": 22, "action": "ACCEPT"}
    ]})
    assert "MGMT_SSH_NOT_EXPLICIT" not in {i.code for i in analyze_policy(policy).issues}
