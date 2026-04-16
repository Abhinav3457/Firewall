from fastapi import APIRouter, Depends, HTTPException, Query, status
from typing import cast
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.deps import get_current_admin, get_db
from app.models import AttackLog, RequestLog
from app.schemas import AttackLogList, RuleItem, RuleList, RuleToggleRequest, SecurityStats
from app.services.waf_rules import list_rules, toggle_rule

router = APIRouter(tags=["security"], dependencies=[Depends(get_current_admin)])


@router.get("/logs", response_model=AttackLogList)
def get_logs(
    db: Session = Depends(get_db),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    items = (
        db.query(AttackLog)
        .order_by(AttackLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return AttackLogList(items=cast(list, items))


@router.get("/stats", response_model=SecurityStats)
def get_stats(db: Session = Depends(get_db)):
    total_requests = db.query(func.count(RequestLog.id)).scalar() or 0
    blocked_requests = db.query(func.count(RequestLog.id)).filter(RequestLog.blocked.is_(True)).scalar() or 0

    rows = (
        db.query(AttackLog.attack_type, func.count(AttackLog.id))
        .group_by(AttackLog.attack_type)
        .all()
    )
    distribution = {attack_type: count for attack_type, count in rows}

    return SecurityStats(
        total_requests=total_requests,
        blocked_requests=blocked_requests,
        attack_distribution=distribution,
    )


@router.get("/rules", response_model=RuleList)
def get_rules(db: Session = Depends(get_db)):
    items = []
    for rule in list_rules(db):
        items.append(
            RuleItem(
                id=rule.id,
                key=rule.key,
                name=rule.name,
                category=rule.category,
                severity=rule.severity,
                enabled=rule.enabled,
                patterns=[p.strip() for p in rule.patterns.split(",") if p.strip()],
                locations=[loc.strip() for loc in rule.locations.split(",") if loc.strip()],
            )
        )
    return RuleList(items=items)


@router.patch("/rules/toggle", response_model=RuleItem)
def toggle_rule_endpoint(payload: RuleToggleRequest, db: Session = Depends(get_db)):
    rule = toggle_rule(db, payload.key, payload.enabled)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    return RuleItem(
        id=rule.id,
        key=rule.key,
        name=rule.name,
        category=rule.category,
        severity=rule.severity,
        enabled=rule.enabled,
        patterns=[p.strip() for p in rule.patterns.split(",") if p.strip()],
        locations=[loc.strip() for loc in rule.locations.split(",") if loc.strip()],
    )
