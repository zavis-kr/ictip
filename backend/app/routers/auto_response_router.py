"""자동 대응 이력 조회 라우터."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List

from app.database import get_db
from app.models import AutoResponse
from app.schemas import AutoResponseOut
from app.auth import get_current_user

router = APIRouter(prefix="/api", tags=["auto-response"])


@router.get("/threats/{threat_id}/auto-responses", response_model=List[AutoResponseOut])
async def get_threat_auto_responses(
    threat_id: int,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """특정 위협의 자동 대응 이력 조회."""
    result = await db.execute(
        select(AutoResponse)
        .where(AutoResponse.threat_id == threat_id)
        .order_by(AutoResponse.executed_at)
    )
    return result.scalars().all()


@router.get("/auto-responses/stats")
async def get_auto_response_stats(
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """자동 대응 통계."""
    result = await db.execute(
        select(AutoResponse.action_type, func.count(AutoResponse.id).label("cnt"))
        .group_by(AutoResponse.action_type)
    )
    by_type = {r.action_type: r.cnt for r in result.all()}
    total = sum(by_type.values())

    status_result = await db.execute(
        select(AutoResponse.status, func.count(AutoResponse.id).label("cnt"))
        .group_by(AutoResponse.status)
    )
    by_status = {r.status: r.cnt for r in status_result.all()}

    return {
        "total_actions": total,
        "by_type": by_type,
        "by_status": by_status,
        "success_rate": round(
            by_status.get("완료", 0) / total * 100, 1
        ) if total else 0.0,
    }
