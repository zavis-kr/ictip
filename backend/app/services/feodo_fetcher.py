"""
Feodo Tracker (abuse.ch) — 봇넷 C&C IP 수집기.
공개 CSV (API 키 불필요):
  https://feodotracker.abuse.ch/downloads/ipblocklist.csv
  (약 500~1000개 활성 봇넷 IP, 매 5분마다 갱신)
"""
import csv
import io
import logging
from datetime import datetime
from typing import List, Dict, Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import ThreatFeed

logger = logging.getLogger(__name__)

FEODO_CSV_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
REQUEST_TIMEOUT = 30.0

# 봇넷 계열 → threat_type 매핑
BOTNET_THREAT_MAP: Dict[str, str] = {
    "emotet": "악성코드/랜섬웨어",
    "trickbot": "악성코드/랜섬웨어",
    "qakbot": "악성코드/랜섬웨어",
    "qbot": "악성코드/랜섬웨어",
    "bazarloader": "악성코드/랜섬웨어",
    "cobalt": "APT/스파이웨어",
    "cobaltstrike": "APT/스파이웨어",
    "metasploit": "APT/스파이웨어",
    "dridex": "악성코드/랜섬웨어",
    "formbook": "악성코드/랜섬웨어",
    "icedid": "악성코드/랜섬웨어",
    "default": "봇넷/C&C",
}


def _get_threat_type(malware_tag: str) -> str:
    tag = (malware_tag or "").lower()
    for key, val in BOTNET_THREAT_MAP.items():
        if key in tag:
            return val
    return BOTNET_THREAT_MAP["default"]


def _parse_feodo_csv(csv_text: str) -> List[Dict[str, Any]]:
    """Feodo Tracker CSV 파싱."""
    records = []
    lines = [line for line in csv_text.splitlines() if not line.startswith("#")]
    text_io = io.StringIO("\n".join(lines))
    reader = csv.DictReader(text_io)

    now = datetime.utcnow()
    for row in reader:
        try:
            ip = (row.get("dst_ip") or row.get("ip_address") or "").strip()
            if not ip:
                continue

            port = (row.get("dst_port") or row.get("port") or "").strip()
            malware = (row.get("malware") or row.get("malware_family") or "Unknown").strip()
            first_seen_str = (row.get("first_seen") or "").strip()
            last_online_str = (row.get("last_online") or row.get("last_seen") or "").strip()
            status = (row.get("status") or "").strip()
            country = (row.get("country") or "").strip().upper() or None

            # 타임스탬프 파싱
            try:
                detected_at = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    detected_at = datetime.strptime(first_seen_str, "%Y-%m-%d")
                except ValueError:
                    detected_at = now

            ioc_value = f"{ip}:{port}" if port else ip
            threat_type = _get_threat_type(malware)
            severity = "긴급" if status == "online" else "높음"

            records.append({
                "title": f"[Feodo] {malware} C&C — {ioc_value}",
                "severity": severity,
                "threat_type": threat_type,
                "source": "feodo_tracker",
                "ioc_value": ioc_value[:1000],
                "ioc_type": "ip",
                "country_code": country[:10] if country else None,
                "actor_tag": malware[:100],
                "description": (
                    f"봇넷 C&C 서버 IP. 악성코드: {malware}, 포트: {port}, "
                    f"상태: {status or '알 수 없음'}, 첫 발견: {first_seen_str}"
                )[:500],
                "ioc_count": 1,
                "detected_at": detected_at,
                "shared_at": now,
                "raw_data": str(dict(row))[:2000],
            })
        except Exception as exc:
            logger.debug("Feodo row parse error: %s | row=%s", exc, row)
            continue

    return records


async def run_feodo_fetch(db: AsyncSession) -> int:
    """Feodo Tracker CSV 수집 & DB 저장."""
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.get(FEODO_CSV_URL)
            response.raise_for_status()

        csv_text = response.text
        records = _parse_feodo_csv(csv_text)
        logger.info("Feodo Tracker: %d개 C&C IP 파싱", len(records))

        if not records:
            return 0

        stored = 0
        for data in records:
            try:
                existing = await db.execute(
                    select(ThreatFeed)
                    .where(ThreatFeed.source == "feodo_tracker")
                    .where(ThreatFeed.ioc_value == data["ioc_value"])
                    .limit(1)
                )
                if existing.scalar_one_or_none():
                    continue
                db.add(ThreatFeed(**data))
                stored += 1
            except Exception as exc:
                logger.warning("Feodo DB 저장 오류: %s", exc)

        if stored > 0:
            await db.commit()
            logger.info("Feodo Tracker: %d개 새 C&C IP 저장", stored)

        return stored

    except httpx.TimeoutException:
        logger.warning("Feodo Tracker: 타임아웃")
        return 0
    except httpx.HTTPStatusError as exc:
        logger.warning("Feodo Tracker: HTTP 오류 %s", exc)
        return 0
    except Exception as exc:
        logger.error("Feodo Tracker 수집 오류: %s", exc, exc_info=True)
        return 0
