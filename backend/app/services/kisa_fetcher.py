"""
CERT RSS 피드 수집기 (구 KISA boho.or.kr RSS 대체).

boho.or.kr RSS는 2025년 사이트 개편으로 폐기됨.
대체 피드:
  - JPCERT/CC: https://www.jpcert.or.jp/rss/jpcert.rdf  (아시아 태평양 CERT)
  - CISA Advisories: https://www.cisa.gov/cybersecurity-advisories/all.xml  (ICS/산업제어)
  - CISA ICS: https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml
"""
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import ThreatFeed

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 30.0

CERT_FEEDS = [
    {
        "url": "https://www.jpcert.or.jp/rss/jpcert.rdf",
        "source": "kisa_notice",       # 기존 source 키 유지 (DB 호환)
        "label": "JPCERT/CC 경보",
        "severity": "높음",
        "threat_type": "취약점/익스플로잇",
        "country_code": "JP",
        "ns": "rdf",                   # RDF 1.0 형식
    },
    {
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "source": "kisa_vuln",
        "label": "CISA 보안권고",
        "severity": "높음",
        "threat_type": "취약점/익스플로잇",
        "country_code": "US",
        "ns": "rss2",
    },
    {
        "url": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
        "source": "kisa_malware",
        "label": "CISA ICS 권고",
        "severity": "긴급",
        "threat_type": "취약점/익스플로잇",
        "country_code": "US",
        "ns": "rss2",
    },
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "application/rss+xml, application/xml, text/xml, */*",
    "Accept-Language": "en-US,en;q=0.9",
}


def _clean_html(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"&[a-z]+;", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _parse_date(date_str: str) -> datetime:
    if not date_str:
        return datetime.utcnow()
    try:
        return parsedate_to_datetime(date_str.strip()).replace(tzinfo=None)
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str.strip()[:19], fmt)
        except ValueError:
            continue
    return datetime.utcnow()


def _fix_xml(text: str) -> str:
    """불완전한 XML 수정 (& → &amp; 등)."""
    text = re.sub(r'&(?!(?:amp|lt|gt|apos|quot|#\d+|#x[\da-fA-F]+);)', '&amp;', text)
    return text


def _parse_rss2_items(root: ET.Element, feed_cfg: Dict) -> List[Dict[str, Any]]:
    """RSS 2.0 형식 파싱 (CISA)."""
    results = []
    items = root.findall(".//item")
    for item in items:
        try:
            title_el = item.find("title")
            link_el  = item.find("link")
            desc_el  = item.find("description")
            date_el  = item.find("pubDate")

            title    = _clean_html(title_el.text or "") if title_el is not None else ""
            link     = (link_el.text or "").strip() if link_el is not None else ""
            desc     = _clean_html(desc_el.text or "") if desc_el is not None else ""
            date_str = (date_el.text or "").strip() if date_el is not None else ""

            if not title:
                continue

            # 심각도 키워드 조정
            sev = feed_cfg["severity"]
            tl  = title.lower()
            if any(k in tl for k in ["critical", "긴급", "zero-day", "ransomware"]):
                sev = "긴급"
            elif any(k in tl for k in ["high", "important", "exploit"]):
                sev = "높음"

            results.append({
                "title": f"[{feed_cfg['label']}] {title}"[:500],
                "severity": sev,
                "threat_type": feed_cfg["threat_type"],
                "source": feed_cfg["source"],
                "ioc_value": link[:1000] if link else None,
                "ioc_type": "url",
                "country_code": feed_cfg.get("country_code"),
                "actor_tag": None,
                "description": (f"{desc}\n출처: {link}" if desc else f"출처: {link}")[:500],
                "ioc_count": 1,
                "detected_at": _parse_date(date_str),
                "shared_at": datetime.utcnow(),
                "raw_data": f'{{"title":"{title[:200]}","link":"{link[:200]}"}}'[:2000],
            })
        except Exception as exc:
            logger.debug("RSS2 item parse error: %s", exc)
    return results


def _parse_rdf_items(root: ET.Element, feed_cfg: Dict) -> List[Dict[str, Any]]:
    """RDF 1.0 형식 파싱 (JPCERT)."""
    results = []
    # RDF 네임스페이스 제거 후 item 탐색
    ns_map = {
        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "rss": "http://purl.org/rss/1.0/",
        "dc":  "http://purl.org/dc/elements/1.1/",
    }
    items = root.findall("{http://purl.org/rss/1.0/}item")
    if not items:
        # fallback: no-namespace
        items = root.findall(".//item")

    for item in items:
        try:
            def _text(tag: str, fallback: str = "") -> str:
                for ns_uri in ["http://purl.org/rss/1.0/", ""]:
                    el = item.find(f"{{{ns_uri}}}{tag}") if ns_uri else item.find(tag)
                    if el is not None and el.text:
                        return el.text.strip()
                return fallback

            title    = _clean_html(_text("title"))
            link     = _text("link")
            desc     = _clean_html(_text("description"))
            date_str = item.find("{http://purl.org/dc/elements/1.1/}date")
            date_str = (date_str.text or "") if date_str is not None else ""

            if not title:
                continue

            sev = feed_cfg["severity"]
            tl  = title.lower()
            if any(k in tl for k in ["critical", "緊急", "zero-day", "ransomware"]):
                sev = "긴급"
            elif any(k in tl for k in ["important", "high", "注意"]):
                sev = "높음"

            results.append({
                "title": f"[{feed_cfg['label']}] {title}"[:500],
                "severity": sev,
                "threat_type": feed_cfg["threat_type"],
                "source": feed_cfg["source"],
                "ioc_value": link[:1000] if link else None,
                "ioc_type": "url",
                "country_code": feed_cfg.get("country_code"),
                "actor_tag": None,
                "description": (f"{desc}\n출처: {link}" if desc else f"출처: {link}")[:500],
                "ioc_count": 1,
                "detected_at": _parse_date(date_str),
                "shared_at": datetime.utcnow(),
                "raw_data": f'{{"title":"{title[:200]}","link":"{link[:200]}"}}'[:2000],
            })
        except Exception as exc:
            logger.debug("RDF item parse error: %s", exc)
    return results


def _parse_feed_items(xml_text: str, feed_cfg: Dict) -> List[Dict[str, Any]]:
    """XML 파싱 후 피드 형식에 맞춰 분기."""
    for attempt in (xml_text, _fix_xml(xml_text)):
        try:
            root = ET.fromstring(attempt)
            break
        except ET.ParseError as exc:
            if attempt is xml_text:
                continue
            logger.warning("CERT RSS XML parse error (%s): %s", feed_cfg["source"], exc)
            return []

    if feed_cfg.get("ns") == "rdf":
        items = _parse_rdf_items(root, feed_cfg)
    else:
        items = _parse_rss2_items(root, feed_cfg)

    logger.info("%s: %d건 파싱", feed_cfg["label"], len(items))
    return items


async def fetch_cert_feed(feed_cfg: Dict) -> List[Dict[str, Any]]:
    """단일 CERT RSS 피드 수집."""
    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
        ) as client:
            response = await client.get(feed_cfg["url"], headers=HEADERS)
            response.raise_for_status()

        return _parse_feed_items(response.text, feed_cfg)

    except httpx.TimeoutException:
        logger.warning("%s: 타임아웃", feed_cfg["label"])
        return []
    except httpx.HTTPStatusError as exc:
        logger.warning("%s: HTTP 오류 %s", feed_cfg["label"], exc)
        return []
    except Exception as exc:
        logger.error("%s: 수집 오류: %s", feed_cfg["label"], exc, exc_info=True)
        return []


async def store_kisa_records(db: AsyncSession, records: List[Dict[str, Any]]) -> int:
    """DB 저장 (중복 URL 스킵)."""
    stored = 0
    for data in records:
        try:
            if data.get("ioc_value"):
                existing = await db.execute(
                    select(ThreatFeed)
                    .where(ThreatFeed.source == data["source"])
                    .where(ThreatFeed.ioc_value == data["ioc_value"])
                    .limit(1)
                )
                if existing.scalar_one_or_none():
                    continue
            db.add(ThreatFeed(**data))
            stored += 1
        except Exception as exc:
            logger.warning("CERT RSS DB 저장 오류: %s", exc)
            try:
                await db.rollback()
            except Exception:
                pass

    if stored > 0:
        await db.commit()
        logger.info("CERT RSS: %d건 저장", stored)
    return stored


async def run_kisa_fetch(db: AsyncSession) -> int:
    """모든 CERT RSS 피드 수집 & 저장 (기존 KISA 인터페이스 유지)."""
    total = 0
    for feed_cfg in CERT_FEEDS:
        records = await fetch_cert_feed(feed_cfg)
        if records:
            total += await store_kisa_records(db, records)
    return total
