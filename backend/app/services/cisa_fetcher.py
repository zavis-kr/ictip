"""
CISA KEV (Known Exploited Vulnerabilities) data fetcher.
API: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
No API key required.
"""
import json
import logging
from datetime import datetime
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

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT = 45.0
MAX_VULNS = 50


def _parse_cve(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a single CISA KEV vulnerability record."""
    cve_id = vuln.get("cveID", "") or ""
    vendor = vuln.get("vendorProject", "") or ""
    product = vuln.get("product", "") or ""
    vuln_name = vuln.get("vulnerabilityName", "") or ""
    description = vuln.get("shortDescription", "") or ""
    ransomware_use = vuln.get("knownRansomwareCampaignUse", "Unknown") or "Unknown"
    cwe = vuln.get("cwes", [])

    # Build descriptive title
    title = f"CISA KEV: {cve_id} — {vendor} {product}: {vuln_name}"[:500]

    # Ransomware involvement boosts threat type
    tags = []
    if ransomware_use.lower() == "known":
        tags.append("ransomware")
        tags.append("known ransomware campaign")

    threat_type = classify_threat_type(
        title=title,
        description=description,
        tags=tags,
    )
    # CISA KEV vulns are all at least 높음 since they are actively exploited
    severity = "높음"
    if ransomware_use.lower() == "known":
        severity = "긴급"
    elif any(kw in description.lower() for kw in ["remote code", "rce", "unauthenticated", "zero-day"]):
        severity = "긴급"

    actor = detect_actor(title=title, description=description, tags=tags)

    # Parse due date or add date
    date_added_str = vuln.get("dateAdded", "")
    due_date_str = vuln.get("dueDate", "")
    try:
        detected_at = datetime.strptime(date_added_str, "%Y-%m-%d")
    except (ValueError, TypeError):
        detected_at = datetime.utcnow()

    full_desc = (
        f"{description} | CWE: {', '.join(cwe) if cwe else 'N/A'} | "
        f"Ransomware Use: {ransomware_use} | Due: {due_date_str}"
    )[:500]

    return {
        "title": title,
        "severity": severity,
        "threat_type": threat_type,
        "source": "cisa_kev",
        "ioc_value": cve_id[:1000] if cve_id else None,
        "ioc_type": "cve",
        "country_code": "US",
        "actor_tag": actor,
        "description": full_desc,
        "ioc_count": 1,
        "detected_at": detected_at,
        "shared_at": datetime.utcnow(),
        "raw_data": json.dumps(vuln, ensure_ascii=False)[:2000] if vuln else None,
    }


async def fetch_cisa_kev(max_vulns: int = MAX_VULNS) -> List[Dict[str, Any]]:
    """Fetch CISA KEV vulnerabilities."""
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.get(CISA_KEV_URL)
            response.raise_for_status()
            data = response.json()

        vulnerabilities = data.get("vulnerabilities", []) or []
        logger.info("CISA KEV: fetched %d vulnerabilities", len(vulnerabilities))

        # Sort by dateAdded descending, take most recent
        try:
            vulnerabilities.sort(
                key=lambda v: v.get("dateAdded", "0000-00-00"),
                reverse=True,
            )
        except Exception:
            pass

        parsed = []
        for vuln in vulnerabilities[:max_vulns]:
            try:
                parsed.append(_parse_cve(vuln))
            except Exception as exc:
                logger.debug("Failed to parse CISA KEV record: %s", exc)
                continue

        return parsed

    except httpx.TimeoutException:
        logger.warning("CISA KEV API timed out after %ss", REQUEST_TIMEOUT)
        return []
    except httpx.HTTPStatusError as exc:
        logger.warning("CISA KEV HTTP error: %s", exc)
        return []
    except Exception as exc:
        logger.error("CISA KEV fetch error: %s", exc, exc_info=True)
        return []


async def store_cisa_vulns(db: AsyncSession, records: List[Dict[str, Any]]) -> int:
    """Store CISA KEV vulnerabilities in the database, skipping duplicates."""
    stored = 0
    for record_data in records:
        try:
            if record_data.get("ioc_value"):
                existing = await db.execute(
                    select(ThreatFeed)
                    .where(ThreatFeed.source == "cisa_kev")
                    .where(ThreatFeed.ioc_value == record_data["ioc_value"])
                    .limit(1)
                )
                if existing.scalar_one_or_none():
                    continue

            threat = ThreatFeed(**record_data)
            db.add(threat)
            stored += 1
        except Exception as exc:
            logger.warning("Failed to store CISA KEV record: %s", exc)
            continue

    if stored > 0:
        await db.commit()
        logger.info("CISA KEV: stored %d new vulnerabilities", stored)

    return stored


async def run_cisa_fetch(db: AsyncSession) -> int:
    """Main entry point: fetch and store CISA KEV vulnerabilities."""
    records = await fetch_cisa_kev()
    if not records:
        logger.info("CISA KEV: no new vulnerabilities to store")
        return 0
    return await store_cisa_vulns(db, records)
