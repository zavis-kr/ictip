"""
기관 간 위협 공유 라우터.
공유 상태 워크플로우: 대기중 → 전송완료 → 확인됨 (또는 실패)
TLP 등급에 따른 공유 범위 제어 구현.
"""
import asyncio
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from app.database import get_db
from app.models import Threat, Agency, ThreatShare, AuditLog, AutoResponse
from app.schemas import ShareCreate, ShareOut
from app.auth import require_analyst

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["sharing"])

# TLP 등급별 공유 가능 기관 유형
TLP_SHARE_POLICY: dict = {
    "WHITE": None,           # 제한 없음 (전체 공유 가능)
    "GREEN": None,           # 커뮤니티 내 (전체 파트너 가능)
    "AMBER": ["CERT", "GOV"],  # CERT/정부기관만
    "RED":   ["CERT"],       # CERT만 (사고대응팀)
}


async def _simulate_transmission(share_id: int, db_url: str) -> None:
    """
    실제 네트워크 전송 시뮬레이션:
    1초 후 상태를 '전송완료'로 변경, 3초 후 '확인됨'으로 변경.
    """
    from app.database import AsyncSessionLocal
    from sqlalchemy import text

    await asyncio.sleep(1)
    try:
        async with AsyncSessionLocal() as db:
            share = (await db.execute(
                select(ThreatShare).where(ThreatShare.id == share_id)
            )).scalar_one_or_none()
            if share and share.status == "대기중":
                share.status = "전송완료"
                await db.commit()
    except Exception as e:
        logger.warning("전송완료 업데이트 실패 (share #%d): %s", share_id, e)

    await asyncio.sleep(2)
    try:
        async with AsyncSessionLocal() as db:
            share = (await db.execute(
                select(ThreatShare).where(ThreatShare.id == share_id)
            )).scalar_one_or_none()
            if share and share.status == "전송완료":
                share.status = "확인됨"
                share.confirmed_at = datetime.utcnow()
                await db.commit()
    except Exception as e:
        logger.warning("확인됨 업데이트 실패 (share #%d): %s", share_id, e)


@router.post("/threats/{threat_id}/share", response_model=List[ShareOut], status_code=201)
async def share_threat(
    threat_id: int,
    body: ShareCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    threat = (await db.execute(select(Threat).where(Threat.id == threat_id))).scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="위협 정보를 찾을 수 없습니다.")

    tlp = body.tlp_level or getattr(threat, 'tlp_level', 'WHITE')

    # TLP 정책 기반 기관 필터링
    allowed_types = TLP_SHARE_POLICY.get(tlp)
    if allowed_types:
        agencies_q = select(Agency).where(
            Agency.id.in_(body.agency_ids),
            Agency.agency_type.in_(allowed_types),
        )
    else:
        agencies_q = select(Agency).where(Agency.id.in_(body.agency_ids))

    agencies = (await db.execute(agencies_q)).scalars().all()

    if not agencies:
        raise HTTPException(
            status_code=400,
            detail=f"TLP:{tlp} 등급으로 공유 가능한 기관이 없습니다. 선택 기관의 유형을 확인하세요."
        )

    shares = []
    for agency in agencies:
        share = ThreatShare(
            threat_id=threat_id,
            from_agency=body.from_agency,
            to_agency_id=agency.id,
            to_agency_name=agency.name,
            note=body.note,
            status="대기중",   # 워크플로우 시작
            tlp_level=tlp,
        )
        db.add(share)
        shares.append(share)

    threat.shared_at = datetime.utcnow()

    agency_names = ", ".join(a.name for a in agencies)
    log = AuditLog(
        user_id=current_user.id, username=current_user.username,
        action="SHARE", resource_type="threat", resource_id=threat_id,
        detail=f"[TLP:{tlp}] 위협 공유: {threat.title[:80]} → {agency_names}",
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)

    # 자동 대응 기록: 공유 실행 자동 기록
    auto_action = AutoResponse(
        threat_id=threat_id,
        action_type="AUTO_SHARE_RECOMMEND",
        action_detail=f"[TLP:{tlp}] {len(agencies)}개 기관 공유 실행: {agency_names[:150]}",
        status="완료",
    )
    db.add(auto_action)

    await db.commit()
    for s in shares:
        await db.refresh(s)

    # 백그라운드에서 상태 전이 시뮬레이션 실행
    from app.config import settings
    for s in shares:
        asyncio.create_task(_simulate_transmission(s.id, settings.database_url))

    return shares


@router.get("/threats/{threat_id}/shares", response_model=List[ShareOut])
async def get_threat_shares(threat_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ThreatShare).where(ThreatShare.threat_id == threat_id)
        .order_by(ThreatShare.shared_at.desc())
    )
    return result.scalars().all()


@router.patch("/shares/{share_id}/confirm", response_model=ShareOut)
async def confirm_share(
    share_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    """수동 수신 확인 (수신 기관 확인 처리)."""
    share = (await db.execute(
        select(ThreatShare).where(ThreatShare.id == share_id)
    )).scalar_one_or_none()
    if not share:
        raise HTTPException(status_code=404, detail="공유 기록을 찾을 수 없습니다.")
    if share.status == "확인됨":
        raise HTTPException(status_code=400, detail="이미 확인된 공유입니다.")

    share.status = "확인됨"
    share.confirmed_at = datetime.utcnow()
    await db.commit()
    await db.refresh(share)
    return share


@router.get("/sharing/stats")
async def get_sharing_stats(db: AsyncSession = Depends(get_db)):
    """공유 현황 통계."""
    from sqlalchemy import func
    result = await db.execute(
        select(ThreatShare.status, func.count(ThreatShare.id).label("cnt"))
        .group_by(ThreatShare.status)
    )
    status_counts = {r.status: r.cnt for r in result.all()}

    tlp_result = await db.execute(
        select(ThreatShare.tlp_level, func.count(ThreatShare.id).label("cnt"))
        .group_by(ThreatShare.tlp_level)
    )
    tlp_counts = {r.tlp_level: r.cnt for r in tlp_result.all()}

    total = sum(status_counts.values())
    confirmed = status_counts.get("확인됨", 0)

    return {
        "total_shares": total,
        "by_status": status_counts,
        "by_tlp": tlp_counts,
        "confirmation_rate": round(confirmed / total * 100, 1) if total else 0.0,
    }
