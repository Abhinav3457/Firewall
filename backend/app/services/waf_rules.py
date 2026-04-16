from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from sqlalchemy.orm import Session

from app.models import DetectionRule


@dataclass(frozen=True)
class RuleDefinition:
    key: str
    name: str
    category: str
    severity: str
    patterns: list[str]
    locations: list[str]


DEFAULT_RULES: list[RuleDefinition] = [
    RuleDefinition(
        key="sql_injection",
        name="SQL Injection",
        category="SQL Injection",
        severity="High",
        patterns=[
            "union select",
            "union/**/select",
            "or 1=1",
            "' or '1'='1",
            "or 'a'='a",
            "--",
            "#",
            "/*",
            "drop table",
            "insert into",
            "select * from",
        ],
        locations=["query", "body", "path", "headers"],
    ),
    RuleDefinition(
        key="command_injection",
        name="Command Injection",
        category="Command Injection",
        severity="High",
        patterns=[
            ";",
            "&&",
            "|",
            "$(",
            "`",
            "whoami",
            "ls",
            "pwd",
            "cat /etc/passwd",
            "curl",
            "wget",
            "bash",
            "sh"
        ],
        locations=["query", "body"],
    ),
    RuleDefinition(
        key="code_injection",
        name="Code Injection",
        category="Code Injection",
        severity="High",
        patterns=[
            "eval(",
            "exec(",
            "base64_decode(",
            "pickle.loads",
        ],
        locations=["body", "query"],
    ),
    RuleDefinition(
        key="xss",
        name="Cross-Site Scripting",
        category="XSS",
        severity="Medium",
        patterns=[
            "<script",
            "javascript:",
            "onerror=",
            "onload=",
            "document.cookie",
        ],
        locations=["body", "query", "path", "headers"],
    ),
    RuleDefinition(
        key="path_traversal",
        name="Path Traversal",
        category="Path Traversal",
        severity="High",
        patterns=[
            "../",
            "..\\",
            "/etc/passwd",
            "/proc/self/environ",
            "boot.ini",
        ],
        locations=["path", "query"],
    ),
    RuleDefinition(
        key="malicious_headers",
        name="Malicious Headers",
        category="Malicious Headers",
        severity="Medium",
        patterns=[
            "sqlmap",
            "nikto",
            "acunetix",
            "nmap",
            "masscan",
        ],
        locations=["headers"],
    ),
    RuleDefinition(
        key="sensitive_endpoints",
        name="Sensitive Endpoint Access",
        category="Suspicious Endpoint",
        severity="Medium",
        patterns=[
            "/admin",
            "/config",
            "/.env",
            "/wp-admin",
            "/phpmyadmin",
        ],
        locations=["path"],
    ),
    RuleDefinition(
        key="large_payload",
        name="Large Payload",
        category="Large Payload",
        severity="High",
        patterns=[],
        locations=["body"],
    ),
    RuleDefinition(
        key="brute_force",
        name="Brute Force",
        category="Broken Authentication",
        severity="High",
        patterns=[],
        locations=["path"],
    ),
]


_cache: dict[str, object] = {
    "timestamp": datetime.min,
    "rules": [],
}


def _serialize_rule(rule: DetectionRule) -> RuleDefinition:
    patterns = [p.strip().lower() for p in rule.patterns.split(",") if p.strip()]
    locations = [loc.strip().lower() for loc in rule.locations.split(",") if loc.strip()]
    return RuleDefinition(
        key=rule.key,
        name=rule.name,
        category=rule.category,
        severity=rule.severity,
        patterns=patterns,
        locations=locations,
    )


def ensure_default_rules(db: Session) -> None:
    existing = {rule.key for rule in db.query(DetectionRule).all()}
    for rule in DEFAULT_RULES:
        if rule.key in existing:
            continue
        db.add(
            DetectionRule(
                key=rule.key,
                name=rule.name,
                category=rule.category,
                severity=rule.severity,
                enabled=True,
                patterns=", ".join(rule.patterns),
                locations=", ".join(rule.locations),
            )
        )
    db.commit()
    _sanitize_sql_rule(db)


def get_enabled_rules(db: Session, ttl_seconds: int = 30) -> list[RuleDefinition]:
    now = datetime.utcnow()
    last_refresh: datetime = _cache["timestamp"]  # type: ignore[assignment]
    if now - last_refresh <= timedelta(seconds=ttl_seconds):
        return _cache["rules"]  # type: ignore[return-value]

    rules = (
        db.query(DetectionRule)
        .filter(DetectionRule.enabled.is_(True))
        .all()
    )
    compiled = [_serialize_rule(rule) for rule in rules]
    _cache["rules"] = compiled
    _cache["timestamp"] = now
    return compiled


def list_rules(db: Session) -> list[DetectionRule]:
    return db.query(DetectionRule).order_by(DetectionRule.id.asc()).all()


def toggle_rule(db: Session, key: str, enabled: bool) -> DetectionRule | None:
    rule = db.query(DetectionRule).filter(DetectionRule.key == key).first()
    if rule is None:
        return None
    rule.enabled = enabled
    db.commit()
    _cache["timestamp"] = datetime.min
    return rule


def _sanitize_sql_rule(db: Session) -> None:
    rule = db.query(DetectionRule).filter(DetectionRule.key == "sql_injection").first()
    if rule is None:
        return
    patterns = [p.strip() for p in rule.patterns.split(",") if p.strip()]
    if "/*" not in patterns:
        return
    patterns = [p for p in patterns if p != "/*"]
    rule.patterns = ", ".join(patterns)
    db.commit()
