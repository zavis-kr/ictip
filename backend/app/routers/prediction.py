"""Threat trend prediction and analysis router."""
import math
from datetime import datetime, timedelta
from typing import Dict, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, union_all, literal_column, text

from app.database import get_db
from app.models import Threat, ThreatFeed
from app.auth import get_current_user

router = APIRouter(prefix="/api/prediction", tags=["prediction"])

PERIOD = 60   # 분석 기간 60일 (데이터 부족 대비)


async def _get_daily_counts(db: AsyncSession, since: datetime) -> Dict[str, int]:
    """Threat + ThreatFeed 두 테이블 합산 일별 건수."""
    # Threat 테이블
    r1 = await db.execute(
        select(
            func.date_trunc("day", Threat.detected_at).label("day"),
            func.count(Threat.id).label("cnt"),
        )
        .where(Threat.detected_at >= since)
        .where(Threat.is_active == True)
        .group_by("day")
    )
    # ThreatFeed 테이블
    r2 = await db.execute(
        select(
            func.date_trunc("day", ThreatFeed.created_at).label("day"),
            func.count(ThreatFeed.id).label("cnt"),
        )
        .where(ThreatFeed.created_at >= since)
        .group_by("day")
    )
    daily: Dict[str, int] = {}
    for r in r1.all():
        key = r.day.strftime("%Y-%m-%d") if hasattr(r.day, "strftime") else str(r.day)[:10]
        daily[key] = daily.get(key, 0) + r.cnt
    for r in r2.all():
        key = r.day.strftime("%Y-%m-%d") if hasattr(r.day, "strftime") else str(r.day)[:10]
        daily[key] = daily.get(key, 0) + r.cnt
    return daily


@router.get("/trend")
async def get_trend(
    days: int = Query(30, ge=7, le=90),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    since = datetime.utcnow() - timedelta(days=max(days, PERIOD))
    daily = await _get_daily_counts(db, since)

    # 최근 days일만 반환
    display_since = datetime.utcnow() - timedelta(days=days)
    trend = []
    for i in range(days):
        d = (display_since + timedelta(days=i)).strftime("%Y-%m-%d")
        trend.append({"date": d, "count": daily.get(d, 0)})

    # 심각도 분포 (Threat + ThreatFeed)
    sev1 = await db.execute(
        select(Threat.severity, func.count(Threat.id).label("cnt"))
        .where(Threat.detected_at >= display_since).where(Threat.is_active == True)
        .group_by(Threat.severity)
    )
    sev2 = await db.execute(
        select(ThreatFeed.severity, func.count(ThreatFeed.id).label("cnt"))
        .where(ThreatFeed.created_at >= display_since)
        .group_by(ThreatFeed.severity)
    )
    sev_map: Dict[str, int] = {}
    for r in sev1.all(): sev_map[r.severity] = sev_map.get(r.severity, 0) + r.cnt
    for r in sev2.all(): sev_map[r.severity] = sev_map.get(r.severity, 0) + r.cnt

    total = sum(t["count"] for t in trend)
    avg_daily = round(total / days, 1) if days else 0

    # 추세 계산: 후반 절반 vs 전반 절반
    half = days // 2
    first_half = sum(t["count"] for t in trend[:half])
    second_half = sum(t["count"] for t in trend[half:])
    if second_half > first_half * 1.1:
        trend_dir = "상승"
    elif second_half < first_half * 0.9:
        trend_dir = "하락"
    else:
        trend_dir = "안정"

    return {
        "period_days": days,
        "data": trend,
        "total": total,
        "avg_daily": avg_daily,
        "trend_direction": trend_dir,
        "severity_summary": sev_map,
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.get("/forecast")
async def get_forecast(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    since = datetime.utcnow() - timedelta(days=PERIOD)
    daily = await _get_daily_counts(db, since)

    counts = []
    for i in range(PERIOD):
        d = (since + timedelta(days=i)).strftime("%Y-%m-%d")
        counts.append(daily.get(d, 0))

    last_7 = counts[-7:] if len(counts) >= 7 else counts
    avg = sum(last_7) / max(len(last_7), 1)
    prev_7 = counts[-14:-7] if len(counts) >= 14 else last_7
    prev_avg = sum(prev_7) / max(len(prev_7), 1)
    trend_factor = (avg / prev_avg) if prev_avg > 0 else 1.0

    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    forecast = []
    for i in range(1, 8):
        dampen = 1 + (trend_factor - 1) * math.exp(-0.2 * i)
        predicted = max(0, round(avg * dampen))
        weekday = (today + timedelta(days=i)).weekday()
        weekday_factor = 0.85 if weekday >= 5 else 1.0
        predicted = max(0, round(predicted * weekday_factor))
        confidence = round(max(0.5, 0.95 - i * 0.05), 2)
        forecast.append({
            "date": (today + timedelta(days=i)).strftime("%Y-%m-%d"),
            "predicted_count": predicted,
            "confidence": confidence,
            "lower_bound": max(0, round(predicted * 0.7)),
            "upper_bound": round(predicted * 1.3),
        })

    return {
        "forecast_days": 7,
        "base_avg": round(avg, 2),
        "trend_factor": round(trend_factor, 3),
        "method": "7-day moving average with trend dampening",
        "forecast": forecast,
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.get("/hotspot")
async def get_hotspot(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    since = datetime.utcnow() - timedelta(days=PERIOD)

    # 위협 유형 (Threat + ThreatFeed 합산)
    t1 = await db.execute(
        select(Threat.threat_type, func.count(Threat.id).label("cnt"))
        .where(Threat.detected_at >= since).where(Threat.is_active == True)
        .group_by(Threat.threat_type)
    )
    t2 = await db.execute(
        select(ThreatFeed.threat_type, func.count(ThreatFeed.id).label("cnt"))
        .where(ThreatFeed.created_at >= since)
        .group_by(ThreatFeed.threat_type)
    )
    type_map: Dict[str, int] = {}
    for r in t1.all(): type_map[r.threat_type] = type_map.get(r.threat_type, 0) + r.cnt
    for r in t2.all(): type_map[r.threat_type] = type_map.get(r.threat_type, 0) + r.cnt
    top_types = sorted([{"threat_type": k, "count": v} for k, v in type_map.items()], key=lambda x: -x["count"])[:8]

    # 국가별
    c1 = await db.execute(
        select(Threat.country_code, func.count(Threat.id).label("cnt"))
        .where(Threat.detected_at >= since).where(Threat.is_active == True)
        .where(Threat.country_code.isnot(None)).group_by(Threat.country_code)
    )
    c2 = await db.execute(
        select(ThreatFeed.country_code, func.count(ThreatFeed.id).label("cnt"))
        .where(ThreatFeed.created_at >= since).where(ThreatFeed.country_code.isnot(None))
        .group_by(ThreatFeed.country_code)
    )
    cc_map: Dict[str, int] = {}
    for r in c1.all(): cc_map[r.country_code] = cc_map.get(r.country_code, 0) + r.cnt
    for r in c2.all(): cc_map[r.country_code] = cc_map.get(r.country_code, 0) + r.cnt
    top_countries = sorted([{"country_code": k, "count": v} for k, v in cc_map.items()], key=lambda x: -x["count"])[:10]

    # 심각도
    s1 = await db.execute(
        select(Threat.severity, func.count(Threat.id).label("cnt"))
        .where(Threat.detected_at >= since).where(Threat.is_active == True)
        .group_by(Threat.severity)
    )
    s2 = await db.execute(
        select(ThreatFeed.severity, func.count(ThreatFeed.id).label("cnt"))
        .where(ThreatFeed.created_at >= since).group_by(ThreatFeed.severity)
    )
    sev_map: Dict[str, int] = {}
    for r in s1.all(): sev_map[r.severity] = sev_map.get(r.severity, 0) + r.cnt
    for r in s2.all(): sev_map[r.severity] = sev_map.get(r.severity, 0) + r.cnt
    severity_dist = sorted([{"severity": k, "count": v} for k, v in sev_map.items()], key=lambda x: -x["count"])

    # 소스별
    src1 = await db.execute(
        select(Threat.source, func.count(Threat.id).label("cnt"))
        .where(Threat.detected_at >= since).where(Threat.is_active == True)
        .group_by(Threat.source).order_by(desc("cnt")).limit(10)
    )
    src2 = await db.execute(
        select(ThreatFeed.source, func.count(ThreatFeed.id).label("cnt"))
        .where(ThreatFeed.created_at >= since)
        .group_by(ThreatFeed.source).order_by(desc("cnt")).limit(10)
    )
    src_map: Dict[str, int] = {}
    for r in src1.all(): src_map[r.source] = src_map.get(r.source, 0) + r.cnt
    for r in src2.all(): src_map[r.source] = src_map.get(r.source, 0) + r.cnt
    top_sources = sorted([{"source": k, "count": v} for k, v in src_map.items()], key=lambda x: -x["count"])[:8]

    return {
        "period_days": PERIOD,
        "top_threat_types": top_types,
        "top_countries": top_countries,
        "severity_distribution": severity_dist,
        "top_sources": top_sources,
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.get("/actor-activity")
async def get_actor_activity(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    since = datetime.utcnow() - timedelta(days=PERIOD)

    # Threat 테이블 행위자
    ar1 = await db.execute(
        select(
            Threat.actor_tag,
            func.count(Threat.id).label("total"),
            func.max(Threat.detected_at).label("last_seen"),
            func.min(Threat.detected_at).label("first_seen"),
        )
        .where(Threat.actor_tag.isnot(None)).where(Threat.actor_tag != "")
        .where(Threat.is_active == True)
        .group_by(Threat.actor_tag).order_by(desc("total")).limit(20)
    )
    # ThreatFeed 테이블 행위자
    ar2 = await db.execute(
        select(
            ThreatFeed.actor_tag,
            func.count(ThreatFeed.id).label("total"),
            func.max(ThreatFeed.created_at).label("last_seen"),
            func.min(ThreatFeed.created_at).label("first_seen"),
        )
        .where(ThreatFeed.actor_tag.isnot(None)).where(ThreatFeed.actor_tag != "")
        .group_by(ThreatFeed.actor_tag).order_by(desc("total")).limit(20)
    )

    actor_map: Dict[str, dict] = {}
    for rows in [ar1.all(), ar2.all()]:
        for a in rows:
            tag = a.actor_tag
            if tag not in actor_map:
                actor_map[tag] = {"count": 0, "last_seen": None, "first_seen": None}
            actor_map[tag]["count"] += a.total
            if a.last_seen:
                prev = actor_map[tag]["last_seen"]
                actor_map[tag]["last_seen"] = a.last_seen if not prev or a.last_seen > prev else prev
            if a.first_seen:
                prev = actor_map[tag]["first_seen"]
                actor_map[tag]["first_seen"] = a.first_seen if not prev or a.first_seen < prev else prev

    top_actors = sorted(actor_map.items(), key=lambda x: -x[1]["count"])[:15]

    actor_profiles = []
    for tag, info in top_actors:
        # 유형 분류
        type_r = await db.execute(
            select(Threat.threat_type, func.count(Threat.id).label("cnt"))
            .where(Threat.actor_tag == tag).where(Threat.is_active == True)
            .group_by(Threat.threat_type).order_by(desc("cnt")).limit(3)
        )
        primary_types = [r.threat_type for r in type_r.all()]

        # 심각도
        sev_r = await db.execute(
            select(Threat.severity, func.count(Threat.id).label("cnt"))
            .where(Threat.actor_tag == tag).where(Threat.is_active == True)
            .group_by(Threat.severity)
        )
        sev_counts = {r.severity: r.cnt for r in sev_r.all()}
        max_sev = max(sev_counts, key=sev_counts.get) if sev_counts else "중간"

        first, last = info["first_seen"], info["last_seen"]
        span_days = max(1, (last - first).days + 1) if first and last else 1
        rate = round(info["count"] / span_days, 2)

        actor_profiles.append({
            "actor_tag": tag,
            "count": info["count"],
            "first_seen": str(first)[:19] if first else None,
            "last_seen": str(last)[:19] if last else None,
            "activity_rate_per_day": rate,
            "primary_threat_types": primary_types,
            "dominant_severity": max_sev,
            "severity_breakdown": sev_counts,
        })

    # 요일 패턴
    dow_r = await db.execute(
        select(
            func.extract("dow", Threat.detected_at).label("dow"),
            func.count(Threat.id).label("cnt"),
        )
        .where(Threat.is_active == True)
        .group_by("dow").order_by("dow")
    )
    dow_names = ["일요일", "월요일", "화요일", "수요일", "목요일", "금요일", "토요일"]
    weekly_pattern = [{"day": dow_names[int(r.dow)], "count": r.cnt} for r in dow_r.all()]

    return {
        "period_days": PERIOD,
        "actor_profiles": actor_profiles,
        "weekly_activity_pattern": weekly_pattern,
        "generated_at": datetime.utcnow().isoformat(),
    }
