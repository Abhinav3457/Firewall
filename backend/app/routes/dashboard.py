from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from typing import cast
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.deps import get_db
from app.models import AttackLog, User
from app.schemas import DashboardStats

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    range_days: int = Query(default=7, ge=1, le=90),
    attack_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=5, le=200),
):

    total_attacks = db.query(func.count(AttackLog.id)).scalar() or 0
    total_users = db.query(func.count(User.id)).scalar() or 0
    verified_users = db.query(func.count(User.id)).filter(User.is_verified.is_(True)).scalar() or 0

    query = db.query(AttackLog)
    start_time = datetime.now(timezone.utc) - timedelta(days=range_days)
    query = query.filter(AttackLog.created_at >= start_time)

    if attack_type and attack_type.lower() != "all":
        query = query.filter(AttackLog.attack_type.ilike(f"%{attack_type}%"))

    latest_attacks = query.order_by(AttackLog.created_at.desc()).limit(limit).all()

    return DashboardStats(
        total_attacks_blocked=total_attacks,
        total_users=total_users,
        verified_users=verified_users,
        latest_attacks=cast(list, latest_attacks),
    )
