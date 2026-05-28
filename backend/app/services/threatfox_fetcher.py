"""
ThreatFox (abuse.ch) data fetcher.
Export URL (API 키 불필요):
  https://threatfox.abuse.ch/export/json/recent/
  JSON 형식: {"<id>": [{ioc_value, ioc_type, malware, ...}], ...}
"""
import json
import logging
from datetime import datetime
from typing import List, Dict, Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import ThreatFeed
from app.services.classifier import (
    classify_threat_type,
    classify_severity,
    detect_actor,
    classify_ioc_type,
)

logger = logging.getLogger(__name__)

THREATFOX_EXPORT_URL = "https://threatfox.abuse.ch/export/json/recent/"
REQUEST_TIMEOUT = 45.0

# threat_type (ThreatFox) → 내부 threat_type 매핑
THREAT_TYPE_MAP: Dict[str, str] = {
    "botnet_cc":         "C2/봇넷",
    "payload_delivery":  "악성코드/랜섬웨어",
    "payload":           "악성코드/랜섬웨어",
    "malware_sample":    "악성코드/랜섬웨어",
    "phishing":          "피싱/소셜엔지니어링",
    "ids_rule":          "취약점/익스플로잇",
}


def _map_threat_type(raw: str) -> str:
    return THREAT_TYPE_MAP.get((raw or "").lower(), "악성코드/랜섬웨어")


def _parse_severity(malware: str, confidence: int) -> str:
    m = (malware or "").lower()
    ransomware = ["ransomware", "lockbit", "wannacry", "ryuk", "conti", "blackcat", "clop", "revil"]
    high = ["rat", "backdoor", "stealer", "loader", "dropper", "banker", "trojan", "botnet"]
    if any(k in m for k in ransomware):
        return "긴급"
    if any(k in m for k in high) or confidence >= 90:
        return "높음"
    if confidence >= 70:
        return "중간"
    return "낮음"


def _parse_ioc(ioc: Dict[str, Any]) -> Dict[str, Any]:
    """ThreatFox export IOC 레코드 → 내부 포맷 변환."""
    malware_printable = (ioc.get("malware_printable") or ioc.get("malware") or "Unknown").strip()
    ioc_value    = (ioc.get("ioc_value") or "").strip()
    ioc_type_raw = (ioc.get("ioc_type") or "").strip()
    threat_type_raw = (ioc.get("threat_type") or "").strip()
    tags_raw     = ioc.get("tags") or ""
    confidence   = int(ioc.get("confidence_level") or 50)
    reporter     = (ioc.get("reporter") or "").strip()

    # tags: string (쉼표 구분) or list
    if isinstance(tags_raw, list):
        tags_str = ",".join(tags_raw)
    else:
        tags_str = str(tags_raw)

    title = f"[ThreatFox] {malware_printable} — {ioc_type_raw.upper()}"[:500]

    threat_type = _map_threat_type(threat_type_raw) or classify_threat_type(
        title=malware_printable, description="", tags=tags_str.split(",")
    )
    severity = _parse_severity(malware_printable, confidence)
    actor = detect_actor(title=malware_printable, description="", tags=tags_str.split(","))

    # first_seen_utc: "2026-05-20 11:27:07" (naive UTC)
    first_seen_str = ioc.get("first_seen_utc") or ioc.get("first_seen") or ""
    try:
        detected_at = datetime.strptime(first_seen_str[:19], "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        detected_at = datetime.utcnow()

    desc = f"악성코드: {malware_printable} | 유형: {threat_type_raw} | 신뢰도: {confidence}% | 보고자: {reporter}"

    return {
        "title": title,
        "severity": severity,
        "threat_type": threat_type,
        "source": "threatfox",
        "ioc_value": ioc_value[:1000] if ioc_value else None,
        "ioc_type": ioc_type_raw or classify_ioc_type(ioc_value),
        "country_code": None,
        "actor_tag": actor[:100] if actor else None,
        "description": desc[:500],
        "ioc_count": 1,
        "detected_at": detected_at,
        "shared_at": datetime.utcnow(),
        "raw_data": json.dumps(ioc, ensure_ascii=False)[:2000],
    }


async def fetch_threatfox_iocs() -> List[Dict[str, Any]]:
    """ThreatFox JSON export 수집.

    응답 형식: {"<numeric_id>": [{...ioc...}], ...}
    """
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.get(
                THREATFOX_EXPORT_URL,
                headers={"User-Agent": "ICTIP/1.0"},
                follow_redirects=True,
            )
            response.raise_for_status()
            data = response.json()

        iocs: List[Dict[str, Any]] = []

        if isinstance(data, dict):
            # 형식: {"id": [{...}], ...}  ← 실제 ThreatFox export 형식
            for _id, val in data.items():
                if isinstance(val, list):
                    iocs.extend(val)
                elif isinstance(val, dict):
                    iocs.append(val)
        elif isinstance(data, list):
            iocs = data

        logger.info("ThreatFox: %d개 IOC 수신", len(iocs))
        return [_parse_ioc(ioc) for ioc in iocs[:300]]

    except httpx.TimeoutException:
        logger.warning("ThreatFox: 타임아웃")
        return []
    except httpx.HTTPStatusError as exc:
        logger.warning("ThreatFox HTTP 오류: %s", exc)
        return []
    except Exception as exc:
        logger.error("ThreatFox 수집 오류: %s", exc, exc_info=True)
        return []


async def store_threatfox_iocs(db: AsyncSession, iocs: List[Dict[str, Any]]) -> int:
    """ThreatFox IOC DB 저장 (중복 ioc_value 스킵)."""
    stored = 0
    for ioc_data in iocs:
        try:
            if ioc_data.get("ioc_value"):
                existing = await db.execute(
                    select(ThreatFeed)
                    .where(ThreatFeed.source == "threatfox")
                    .where(ThreatFeed.ioc_value == ioc_data["ioc_value"])
                    .limit(1)
                )
                if existing.scalar_one_or_none():
                    continue

            db.add(ThreatFeed(**ioc_data))
            stored += 1
        except Exception as exc:
            logger.warning("ThreatFox IOC 저장 오류: %s", exc)
            try:
                await db.rollback()
            except Exception:
                pass
            continue

    if stored > 0:
        await db.commit()
        logger.info("ThreatFox: %d개 새 IOC 저장", stored)
    else:
        logger.info("ThreatFox: 새 IOC 없음 (중복 스킵)")

    return stored


async def run_threatfox_fetch(db: AsyncSession) -> int:
    """ThreatFox IOC 수집 & 저장 메인 진입점."""
    try:
        iocs = await fetch_threatfox_iocs()
        if not iocs:
            return 0
        return await store_threatfox_iocs(db, iocs)
    except Exception as exc:
        logger.error("run_threatfox_fetch 오류: %s", exc, exc_info=True)
        return 0
