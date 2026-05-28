"""
URLhaus (abuse.ch) data fetcher.
API: https://urlhaus-api.abuse.ch/v1/urls/recent/
No API key required.
"""
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import ThreatFeed
from app.services.classifier import (
    classify_threat_type,
    classify_severity,
    detect_actor,
)

logger = logging.getLogger(__name__)

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
REQUEST_TIMEOUT = 30.0
MAX_URLS = 100


def _parse_url_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a URLhaus URL record into our internal format."""
    url = record.get("url", "") or ""
    threat = record.get("threat", "") or ""
    tags_raw = record.get("tags") or []
    tags = [t for t in (tags_raw or []) if t]
    host = record.get("host", "") or ""

    # Build descriptive title
    if threat:
        title = f"URLhaus 악성 URL — {threat}: {host[:80]}"
    else:
        title = f"URLhaus 악성 URL — {host[:80]}"

    threat_type = classify_threat_type(
        title=title,
        description=threat,
        tags=tags,
    )
    severity = classify_severity(
        title=title,
        description=threat,
        threat_type=threat_type,
        tags=tags,
        confidence=0.7,
    )
    actor = detect_actor(title=title, description=threat, tags=tags)

    # Parse timestamp
    date_added_str = record.get("date_added", "")
    try:
        detected_at = datetime.strptime(date_added_str, "%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        detected_at = datetime.utcnow()

    return {
        "title": title[:500],
        "severity": severity,
        "threat_type": threat_type,
        "source": "urlhaus",
        "ioc_value": url[:1000] if url else None,
        "ioc_type": "url",
        "country_code": record.get("country_code") or None,
        "actor_tag": actor,
        "description": f"URLhaus malicious URL — threat: {threat}, tags: {', '.join(tags)}"[:500] if (threat or tags) else None,
        "ioc_count": 1,
        "detected_at": detected_at,
        "shared_at": datetime.utcnow(),
        "raw_data": json.dumps(record, ensure_ascii=False)[:2000] if record else None,
    }


async def fetch_urlhaus_recent(limit: int = MAX_URLS) -> List[Dict[str, Any]]:
    """Fetch recent malicious URLs from URLhaus CSV download (no API key required)."""
    import csv, io
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.get(URLHAUS_CSV_URL, headers={"User-Agent": "ICTIP/1.0"})
            response.raise_for_status()
            text = response.text

        lines = [l for l in text.splitlines() if l and not l.startswith("#")]
        reader = csv.DictReader(lines, fieldnames=["id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"])
        records = []
        for row in reader:
            try:
                records.append({
                    "url": row.get("url", ""),
                    "threat": row.get("threat", ""),
                    "tags": [t.strip() for t in (row.get("tags") or "").split(",") if t.strip()],
                    "host": row.get("url", "").split("/")[2] if "/" in (row.get("url") or "") else "",
                    "date_added": row.get("dateadded", ""),
                })
            except Exception:
                continue

        logger.info("URLhaus: fetched %d URLs from CSV", len(records))

        parsed = []
        for record in records[:limit]:
            try:
                parsed.append(_parse_url_record(record))
            except Exception as exc:
                logger.debug("Failed to parse URLhaus record: %s", exc)
                continue

        return parsed

    except httpx.TimeoutException:
        logger.warning("URLhaus API timed out after %ss", REQUEST_TIMEOUT)
        return []
    except httpx.HTTPStatusError as exc:
        logger.warning("URLhaus HTTP error: %s", exc)
        return []
    except Exception as exc:
        logger.error("URLhaus fetch error: %s", exc, exc_info=True)
        return []


async def store_urlhaus_urls(db: AsyncSession, records: List[Dict[str, Any]]) -> int:
    """Store URLhaus records in the database, skipping duplicates."""
    stored = 0
    for record_data in records:
        try:
            if record_data.get("ioc_value"):
                existing = await db.execute(
                    select(ThreatFeed)
                    .where(ThreatFeed.source == "urlhaus")
                    .where(ThreatFeed.ioc_value == record_data["ioc_value"])
                    .limit(1)
                )
                if existing.scalar_one_or_none():
                    continue

            threat = ThreatFeed(**record_data)
            db.add(threat)
            stored += 1
        except Exception as exc:
            logger.warning("Failed to store URLhaus record: %s", exc)
            continue

    if stored > 0:
        await db.commit()
        logger.info("URLhaus: stored %d new URLs", stored)

    return stored


async def run_urlhaus_fetch(db: AsyncSession) -> int:
    """Main entry point: fetch and store URLhaus malicious URLs."""
    records = await fetch_urlhaus_recent()
    if not records:
        logger.info("URLhaus: no new URLs to store")
        return 0
    return await store_urlhaus_urls(db, records)
