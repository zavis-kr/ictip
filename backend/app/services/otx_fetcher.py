"""
OTX AlienVault pulse fetcher.
API: https://otx.alienvault.com/api/v1/pulses/subscribed
Requires OTX_API_KEY environment variable.
"""
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import ThreatFeed
from app.services.classifier import (
    classify_threat_type,
    classify_severity,
    detect_actor,
)
from app.config import settings

logger = logging.getLogger(__name__)

OTX_SUBSCRIBED_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
OTX_ACTIVITY_URL = "https://otx.alienvault.com/api/v1/pulses/activity"
REQUEST_TIMEOUT = 30.0
MAX_PULSES = 50


def _parse_pulse(pulse: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a single OTX pulse record."""
    name = pulse.get("name", "") or ""
    description = pulse.get("description", "") or ""
    tags = pulse.get("tags") or []
    malware_families = pulse.get("malware_families") or []
    attack_ids = pulse.get("attack_ids") or []
    targeted_countries = pulse.get("targeted_countries") or []
    industries = pulse.get("industries") or []

    # Combine all relevant text for classification
    all_tags = list(tags) + [m.get("display_name", "") for m in malware_families] + [a.get("display_name", "") for a in attack_ids]
    all_tags = [t for t in all_tags if t]

    title = name[:500] if name else "OTX Pulse"

    threat_type = classify_threat_type(
        title=title,
        description=description,
        tags=all_tags,
    )
    severity = classify_severity(
        title=title,
        description=description,
        threat_type=threat_type,
        tags=all_tags,
        confidence=0.65,
    )
    actor = detect_actor(title=title, description=description, tags=all_tags)

    # Country code from first targeted country
    country_code = None
    if targeted_countries:
        country_code = targeted_countries[0][:10] if targeted_countries[0] else None

    # Count IOCs
    indicators = pulse.get("indicators") or []
    ioc_count = len(indicators)

    # First IOC value if available
    ioc_value = None
    ioc_type = None
    if indicators:
        first_ioc = indicators[0]
        ioc_value = str(first_ioc.get("indicator", ""))[:1000] or None
        ioc_type = first_ioc.get("type", "other")

    # Parse created timestamp — naive UTC (DB DateTime column expects naive)
    created_str = pulse.get("created", "")
    try:
        detected_at = datetime.strptime(created_str[:19], "%Y-%m-%dT%H:%M:%S")
    except (ValueError, TypeError):
        detected_at = datetime.utcnow()

    author = pulse.get("author_name", "") or ""
    desc_full = f"{description[:300]} | Tags: {', '.join(all_tags[:5])} | Industries: {', '.join(industries[:3])}"[:500]

    return {
        "title": title,
        "severity": severity,
        "threat_type": threat_type,
        "source": "otx_alienvault",
        "ioc_value": ioc_value,
        "ioc_type": ioc_type or "other",
        "country_code": country_code,
        "actor_tag": actor,
        "description": desc_full,
        "ioc_count": max(ioc_count, 1),
        "detected_at": detected_at,
        "shared_at": datetime.utcnow(),
        "raw_data": json.dumps({
            "id": pulse.get("id", ""),
            "name": name,
            "tags": all_tags[:10],
            "targeted_countries": targeted_countries[:5],
        }, ensure_ascii=False)[:2000],
    }


async def fetch_otx_pulses(api_key: str, limit: int = MAX_PULSES) -> List[Dict[str, Any]]:
    """Fetch recent OTX pulses from subscribed feed."""
    if not api_key:
        logger.info("OTX_API_KEY not set — skipping OTX fetch")
        return []

    headers = {"X-OTX-API-KEY": api_key}
    params = {"limit": limit, "page": 1}

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.get(OTX_ACTIVITY_URL, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

        pulses = data.get("results", []) or []
        logger.info("OTX AlienVault: fetched %d pulses", len(pulses))

        parsed = []
        for pulse in pulses:
            try:
                parsed.append(_parse_pulse(pulse))
            except Exception as exc:
                logger.debug("Failed to parse OTX pulse: %s", exc)
                continue

        return parsed

    except httpx.TimeoutException:
        logger.warning("OTX API timed out after %ss", REQUEST_TIMEOUT)
        return []
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 403:
            logger.warning("OTX API key invalid or no permissions: 403")
        else:
            logger.warning("OTX HTTP error: %s", exc)
        return []
    except Exception as exc:
        logger.error("OTX fetch error: %s", exc, exc_info=True)
        return []


async def store_otx_pulses(db: AsyncSession, records: List[Dict[str, Any]]) -> int:
    """Store OTX pulse records in the database, skipping duplicates."""
    stored = 0
    for record_data in records:
        try:
            if record_data.get("ioc_value"):
                existing = await db.execute(
                    select(ThreatFeed)
                    .where(ThreatFeed.source == "otx_alienvault")
                    .where(ThreatFeed.ioc_value == record_data["ioc_value"])
                    .limit(1)
                )
                if existing.scalar_one_or_none():
                    continue

            threat = ThreatFeed(**record_data)
            db.add(threat)
            stored += 1
        except Exception as exc:
            logger.warning("OTX pulse 저장 오류: %s", str(exc)[:200])
            try:
                await db.rollback()
            except Exception:
                pass
            continue

    if stored > 0:
        await db.commit()
        logger.info("OTX AlienVault: %d개 새 펄스 저장", stored)
    else:
        logger.info("OTX AlienVault: 새 펄스 없음 (중복 스킵)")

    return stored


async def run_otx_fetch(db: AsyncSession) -> int:
    """Main entry point: fetch and store OTX pulses."""
    try:
        api_key = settings.otx_api_key or ""
        if not api_key:
            logger.info("OTX_API_KEY not configured — skipping")
            return 0

        records = await fetch_otx_pulses(api_key)
        if not records:
            return 0
        return await store_otx_pulses(db, records)
    except Exception as exc:
        logger.error("run_otx_fetch 오류: %s", exc, exc_info=True)
        return 0
