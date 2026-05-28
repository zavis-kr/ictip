"""
NVD (National Vulnerability Database) CVE fetcher.
API: https://services.nvd.nist.gov/rest/json/cves/2.0
No API key required (rate limited: 5 req/30s without key).
"""
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import ThreatFeed
from app.services.classifier import classify_severity, detect_actor

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 30.0
MAX_CVES = 30


def _cvss_to_severity(cvss_score: float | None) -> str:
    if cvss_score is None:
        return "중간"
    if cvss_score >= 9.0:
        return "긴급"
    if cvss_score >= 7.0:
        return "높음"
    if cvss_score >= 4.0:
        return "중간"
    return "낮음"


def _parse_cve(item: Dict[str, Any]) -> Dict[str, Any] | None:
    try:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        # CVSS score
        metrics = cve.get("metrics", {})
        cvss_score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                try:
                    cvss_score = metrics[key][0]["cvssData"]["baseScore"]
                    break
                except (KeyError, IndexError):
                    pass

        severity = _cvss_to_severity(cvss_score)

        # Published date
        published_str = cve.get("published", "")
        try:
            detected_at = datetime.fromisoformat(published_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            detected_at = datetime.utcnow()

        # Vendor/product from CPE
        affected = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe = cpe_match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) > 4:
                        vendor = parts[3]
                        product = parts[4]
                        if vendor and vendor != "*":
                            affected.append(f"{vendor}/{product}")

        affected_str = ", ".join(affected[:3]) if affected else ""
        title = f"NVD CVE: {cve_id}"
        if affected_str:
            title += f" — {affected_str}"
        if cvss_score:
            title += f" (CVSS {cvss_score})"
        title = title[:500]

        actor = detect_actor(title=title, description=desc_en, tags=[])

        return {
            "title": title,
            "severity": severity,
            "threat_type": "취약점/익스플로잇",
            "source": "nvd_cve",
            "ioc_value": cve_id[:1000],
            "ioc_type": "cve",
            "country_code": "US",
            "actor_tag": actor,
            "description": desc_en[:500] if desc_en else None,
            "ioc_count": 1,
            "detected_at": detected_at,
            "shared_at": datetime.utcnow(),
            "raw_data": json.dumps({"id": cve_id, "cvss": cvss_score}, ensure_ascii=False),
        }
    except Exception as exc:
        logger.debug("Failed to parse NVD CVE record: %s", exc)
        return None


async def fetch_nvd_recent(max_cves: int = MAX_CVES) -> List[Dict[str, Any]]:
    """Fetch recent CVEs from NVD API v2."""
    try:
        # Fetch CVEs published in last 30 days
        end = datetime.utcnow()
        start = end - timedelta(days=30)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(max_cves, 30),
            "startIndex": 0,
        }

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.get(
                NVD_API_URL,
                params=params,
                headers={"User-Agent": "ICTIP/1.0"},
            )
            response.raise_for_status()
            data = response.json()

        vulnerabilities = data.get("vulnerabilities", []) or []
        logger.info("NVD CVE: fetched %d CVEs", len(vulnerabilities))

        parsed = []
        for item in vulnerabilities:
            result = _parse_cve(item)
            if result:
                parsed.append(result)

        # Sort by CVSS severity (긴급 first)
        severity_order = {"긴급": 0, "높음": 1, "중간": 2, "낮음": 3}
        parsed.sort(key=lambda x: severity_order.get(x["severity"], 99))

        return parsed

    except httpx.TimeoutException:
        logger.warning("NVD API timed out")
        return []
    except httpx.HTTPStatusError as exc:
        logger.warning("NVD HTTP error: %s", exc)
        return []
    except Exception as exc:
        logger.error("NVD fetch error: %s", exc, exc_info=True)
        return []


async def store_nvd_cves(db: AsyncSession, records: List[Dict[str, Any]]) -> int:
    stored = 0
    for record_data in records:
        try:
            if record_data.get("ioc_value"):
                existing = await db.execute(
                    select(ThreatFeed)
                    .where(ThreatFeed.source == "nvd_cve")
                    .where(ThreatFeed.ioc_value == record_data["ioc_value"])
                    .limit(1)
                )
                if existing.scalar_one_or_none():
                    continue
            db.add(ThreatFeed(**record_data))
            stored += 1
        except Exception as exc:
            logger.warning("Failed to store NVD CVE: %s", exc)

    if stored > 0:
        await db.commit()
        logger.info("NVD CVE: stored %d new CVEs", stored)
    return stored


async def run_nvd_fetch(db: AsyncSession) -> int:
    records = await fetch_nvd_recent()
    if not records:
        logger.info("NVD CVE: no new CVEs to store")
        return 0
    return await store_nvd_cves(db, records)
