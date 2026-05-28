"""
자동 대응 시스템 (Auto Response System)
- 긴급/높음 위협 탐지 시 자동 분석 실행
- IOC 차단 규칙 생성 (로그 기록)
- 에스컬레이션 권고 생성
- 파트너 기관 공유 권고
"""
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import Threat, AIAnalysis, AutoResponse, Agency, ThreatShare

logger = logging.getLogger(__name__)

# 자동 대응 임계값
AUTO_ANALYZE_SEVERITIES = {"긴급", "높음"}
AUTO_SHARE_RECOMMEND_SEVERITIES = {"긴급"}
IOC_BLOCK_RULE_TYPES = {"봇넷/C&C", "악성코드/랜섬웨어", "랜섬웨어"}


async def run_auto_response(threat: Threat, db: AsyncSession) -> list[dict]:
    """
    위협 생성/수집 후 자동 대응 로직 실행.
    Returns: 실행된 액션 목록
    """
    actions = []

    # ── 1. 긴급/높음 위협 자동 AI 분석 ──────────────────────────────
    if threat.severity in AUTO_ANALYZE_SEVERITIES:
        existing_analysis = (await db.execute(
            select(AIAnalysis).where(AIAnalysis.threat_id == threat.id)
        )).scalar_one_or_none()

        if not existing_analysis:
            try:
                from app.routers.ai_analysis import _claude_analyze
                data = await _claude_analyze(threat)
                analysis = AIAnalysis(threat_id=threat.id, **data)
                db.add(analysis)
                action = AutoResponse(
                    threat_id=threat.id,
                    action_type="AUTO_ANALYZE",
                    action_detail=f"심각도 '{threat.severity}' — AI 자동 분석 실행 완료 (위험점수: {data.get('risk_score', 'N/A')})",
                    status="완료",
                )
                db.add(action)
                actions.append({"type": "AUTO_ANALYZE", "status": "완료"})
                logger.info("자동 AI 분석 완료: 위협 #%d (%s)", threat.id, threat.title[:50])
            except Exception as e:
                logger.warning("자동 AI 분석 실패 (위협 #%d): %s", threat.id, e)
                action = AutoResponse(
                    threat_id=threat.id,
                    action_type="AUTO_ANALYZE",
                    action_detail=f"자동 분석 실패: {str(e)[:200]}",
                    status="실패",
                )
                db.add(action)

    # ── 2. IOC 차단 규칙 자동 생성 ───────────────────────────────────
    if threat.ioc_value and threat.threat_type in IOC_BLOCK_RULE_TYPES:
        rule_detail = _build_block_rule(threat)
        action = AutoResponse(
            threat_id=threat.id,
            action_type="IOC_BLOCK_RULE",
            action_detail=rule_detail,
            status="완료",
        )
        db.add(action)
        actions.append({"type": "IOC_BLOCK_RULE", "status": "완료"})
        logger.info("IOC 차단 규칙 생성: %s (%s)", threat.ioc_value[:50], threat.ioc_type)

    # ── 3. 긴급 위협 에스컬레이션 권고 ──────────────────────────────
    if threat.severity == "긴급":
        escalation_detail = (
            f"[에스컬레이션 권고] 위협 '{threat.title[:80]}'\n"
            f"심각도: {threat.severity} | 유형: {threat.threat_type}\n"
            f"즉각적인 인시던트 대응팀 알림 및 영향 범위 조사 필요.\n"
            f"관련 IOC: {threat.ioc_value or 'N/A'} ({threat.ioc_type or 'N/A'})\n"
            f"행위자: {threat.actor_tag or '미상'} | 출처국: {threat.country_code or '미상'}"
        )
        action = AutoResponse(
            threat_id=threat.id,
            action_type="ESCALATE",
            action_detail=escalation_detail,
            status="완료",
        )
        db.add(action)
        actions.append({"type": "ESCALATE", "status": "완료"})

    # ── 4. 긴급 위협 파트너 공유 권고 ────────────────────────────────
    if threat.severity in AUTO_SHARE_RECOMMEND_SEVERITIES:
        # 공유 권고 (실제 전송 아님 - 권고 기록)
        priority_agencies = await db.execute(
            select(Agency)
            .where(Agency.is_active == True)
            .where(Agency.agency_type.in_(["CERT", "GOV"]))
            .limit(5)
        )
        agency_list = priority_agencies.scalars().all()
        agency_names = ", ".join(a.name for a in agency_list[:3])

        action = AutoResponse(
            threat_id=threat.id,
            action_type="AUTO_SHARE_RECOMMEND",
            action_detail=(
                f"긴급 위협 탐지 — 즉각 공유 권고\n"
                f"권고 기관: {agency_names} 외 {len(agency_list)}개 기관\n"
                f"TLP 등급: {threat.tlp_level} 기준 공유 범위 설정 필요"
            ),
            status="완료",
        )
        db.add(action)
        actions.append({"type": "AUTO_SHARE_RECOMMEND", "status": "완료"})

    if actions:
        await db.commit()
        logger.info("자동 대응 완료: 위협 #%d — %d개 액션 실행", threat.id, len(actions))

    return actions


def _build_block_rule(threat: Threat) -> str:
    """IOC 유형에 맞는 차단 규칙 스니펫 생성."""
    ioc = threat.ioc_value or ""
    ioc_type = (threat.ioc_type or "").lower()

    if ioc_type == "ip":
        rule = (
            f"# 방화벽 차단 규칙 (자동 생성)\n"
            f"iptables -A INPUT -s {ioc} -j DROP\n"
            f"iptables -A OUTPUT -d {ioc} -j DROP\n"
            f"# Windows Defender: Add-MpPreference -ThreatDefault IP:{ioc}"
        )
    elif ioc_type == "domain":
        rule = (
            f"# DNS 차단 규칙 (자동 생성)\n"
            f"# /etc/hosts: 0.0.0.0 {ioc}\n"
            f"# Pi-hole: pihole -b {ioc}\n"
            f"# Palo Alto: Security Policy → URL Category 차단"
        )
    elif ioc_type in ("sha256", "md5", "sha1"):
        rule = (
            f"# 파일 해시 차단 규칙 (자동 생성)\n"
            f"# Windows Defender: Add-MpPreference -ExclusionPath은 제거, 탐지 규칙 추가\n"
            f"# CrowdStrike: IOA Custom Rule → Hash Block\n"
            f"# EDR 정책에 해시 {ioc} 추가 필요"
        )
    elif ioc_type == "url":
        rule = (
            f"# URL 차단 규칙 (자동 생성)\n"
            f"# 프록시/웹필터에 {ioc[:100]} 추가\n"
            f"# Squid: acl blocked_url url_regex {ioc[:80]}\n"
            f"# Palo Alto: URL Filtering Profile → Block"
        )
    else:
        rule = f"# IOC 차단 (자동 생성): {ioc_type} = {ioc[:100]}\n# 보안 장비 정책에 수동 적용 필요"

    return rule


async def get_auto_responses(threat_id: int, db: AsyncSession) -> list[AutoResponse]:
    """특정 위협에 대한 자동 대응 이력 조회."""
    result = await db.execute(
        select(AutoResponse)
        .where(AutoResponse.threat_id == threat_id)
        .order_by(AutoResponse.executed_at)
    )
    return result.scalars().all()
