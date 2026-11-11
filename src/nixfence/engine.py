"""Offline policy validation; no network access, no shell, no policy changes."""
from __future__ import annotations

from ipaddress import ip_network

from .models import Action, FirewallPolicy, PolicyAnalysis, PolicyIssue


def analyze_policy(policy: FirewallPolicy) -> PolicyAnalysis:
    issues: list[PolicyIssue] = []
    seen_ids: set[str] = set()
    seen_priority: set[int] = set()
    sorted_rules = sorted(policy.rules, key=lambda rule: (rule.priority, rule.id))

    for rule in sorted_rules:
        if rule.id in seen_ids:
            issues.append(PolicyIssue(severity="error", code="DUPLICATE_RULE_ID",
                                      message="Rule IDs must be unique.", rule_id=rule.id))
        seen_ids.add(rule.id)
        if rule.priority in seen_priority:
            issues.append(PolicyIssue(severity="error", code="DUPLICATE_PRIORITY",
                                      message="Each rule must have a unique priority.", rule_id=rule.id))
        seen_priority.add(rule.priority)

        network = ip_network(rule.source, strict=False)
        if (rule.enabled and rule.direction == "input" and rule.action == Action.ACCEPT
                and rule.protocol.value == "tcp" and rule.destination_port == 22
                and network.prefixlen == 0):
            issues.append(PolicyIssue(severity="warning", code="SSH_OPEN_TO_WORLD",
                                      message="SSH is allowed from an entire address family.",
                                      rule_id=rule.id))
        if (rule.enabled and rule.direction == "input" and rule.action == Action.ACCEPT
                and rule.destination_port in (3306, 5432, 6379)
                and network.prefixlen == 0):
            issues.append(PolicyIssue(severity="warning", code="DATA_PORT_PUBLIC",
                                      message="A database/cache port is allowed from an entire address family.",
                                      rule_id=rule.id))

    for i, current in enumerate(sorted_rules):
        if not current.enabled:
            continue
        current_net = ip_network(current.source)
        for prior in sorted_rules[:i]:
            if not prior.enabled or current.direction != prior.direction:
                continue
            prior_net = ip_network(prior.source)
            if (current.protocol == prior.protocol
                    and current.destination_port == prior.destination_port
                    and current_net.version == prior_net.version
                    and current_net.subnet_of(prior_net)):
                issues.append(PolicyIssue(
                    severity="warning", code="SHADOWED_RULE",
                    message=f"Earlier rule {prior.id} covers this source and service; evaluate ordering.",
                    rule_id=current.id))
                break

    if not policy.management_sources:
        issues.append(PolicyIssue(severity="warning", code="NO_MANAGEMENT_CIDR",
                                  message="Set a known management CIDR before any future deployment."))
    elif not any(rule.enabled and rule.direction == "input" and rule.action == Action.ACCEPT
                 and rule.protocol.value == "tcp" and rule.destination_port == 22
                 and any(ip_network(m).subnet_of(ip_network(rule.source))
                         for m in policy.management_sources if ip_network(m).version ==
                         ip_network(rule.source).version)
                 for rule in sorted_rules):
        issues.append(PolicyIssue(severity="warning", code="MGMT_SSH_NOT_EXPLICIT",
                                  message="No explicit SSH allow rule covers the management CIDR(s)."))

    return PolicyAnalysis(
        policy_name=policy.name,
        rule_count=len(sorted_rules),
        enabled_rule_count=sum(1 for r in sorted_rules if r.enabled),
        issues=issues,
        normalized_rules=sorted_rules,
    )
