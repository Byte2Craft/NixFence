"""Strict, vendor-neutral offline policy models.

This module does NOT generate or apply live firewall rules.
"""
from __future__ import annotations

from enum import Enum
from ipaddress import ip_network
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Action(str, Enum):
    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"


class Protocol(str, Enum):
    tcp = "tcp"
    udp = "udp"
    icmp = "icmp"
    ipv6_icmp = "ipv6-icmp"


class Direction(str, Enum):
    input = "input"
    output = "output"


class FirewallRule(StrictModel):
    id: Annotated[str, Field(min_length=1, max_length=40, pattern=r"^[A-Za-z0-9_-]+$")]
    priority: Annotated[int, Field(ge=1, le=999999)]
    enabled: bool = True
    direction: Direction = Direction.input
    source: str
    protocol: Protocol
    destination_port: Annotated[int | None, Field(ge=1, le=65535)] = None
    action: Action
    description: Annotated[str, Field(max_length=160)] = ""

    @field_validator("source")
    @classmethod
    def validate_source(cls, value: str) -> str:
        try:
            parsed = ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError("source must be a valid IPv4/IPv6 CIDR") from exc
        return str(parsed)

    @model_validator(mode="after")
    def validate_protocol(self) -> "FirewallRule":
        if self.protocol in (Protocol.icmp, Protocol.ipv6_icmp) and self.destination_port is not None:
            raise ValueError("ICMP rules cannot have destination_port")
        if self.protocol in (Protocol.tcp, Protocol.udp) and self.destination_port is None:
            raise ValueError("TCP/UDP rules require destination_port")
        return self


class FirewallPolicy(StrictModel):
    name: Annotated[str, Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")]
    default_input_action: Action = Action.DROP
    management_sources: list[str] = Field(default_factory=list, max_length=16)
    rules: list[FirewallRule] = Field(default_factory=list, max_length=512)

    @field_validator("management_sources")
    @classmethod
    def validate_management_sources(cls, sources: list[str]) -> list[str]:
        result: list[str] = []
        for source in sources:
            try:
                result.append(str(ip_network(source, strict=False)))
            except ValueError as exc:
                raise ValueError(f"invalid management source: {source}") from exc
        return result


class PolicyIssue(StrictModel):
    severity: str
    code: str
    message: str
    rule_id: str | None = None


class PolicyAnalysis(StrictModel):
    policy_name: str
    rule_count: int
    enabled_rule_count: int
    issues: list[PolicyIssue]
    normalized_rules: list[FirewallRule]
    live_apply_available: bool = False
    analysis_only: bool = True
