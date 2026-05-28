"""STIX 2.1 export/import and TAXII 2.1 server endpoints."""
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.database import get_db
from app.models import Threat, ThreatFeed, InboundSTIX
from app.auth import get_current_user, require_analyst
from app.services.classifier import classify_threat_type, classify_severity, detect_actor, classify_ioc_type

logger = logging.getLogger(__name__)

router = APIRouter(tags=["stix"])

STIX_MEDIA = "application/stix+json;version=2.1"
TAXII_MEDIA = "application/taxii+json;version=2.1"

IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--00000000-0000-0000-0000-000000000001",
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "ICTIP Platform",
    "identity_class": "system",
    "description": "국제 사이버 위협 인텔리전스 플랫폼 (ICTIP)",
}


def _ts(dt: Optional[datetime]) -> str:
    if not dt:
        dt = datetime.utcnow()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _build_pattern(ioc_value: Optional[str], ioc_type: Optional[str]) -> str:
    if not ioc_value or not ioc_type:
        return "[artifact:payload_bin = 'unknown']"
    mapping = {
        "ip": f"[ipv4-addr:value = '{ioc_value}']",
        "domain": f"[domain-name:value = '{ioc_value}']",
        "url": f"[url:value = '{ioc_value}']",
        "md5": f"[file:hashes.MD5 = '{ioc_value}']",
        "sha1": f"[file:hashes.SHA-1 = '{ioc_value}']",
        "sha256": f"[file:hashes.'SHA-256' = '{ioc_value}']",
        "email": f"[email-addr:value = '{ioc_value}']",
    }
    return mapping.get(ioc_type, f"[artifact:payload_bin = '{ioc_value}']")


def threat_to_indicator(threat: Threat) -> dict:
    indicator_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_OID, f'ictip-threat-{threat.id}')}"
    ts = _ts(threat.detected_at)
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": ts,
        "modified": ts,
        "created_by_ref": IDENTITY["id"],
        "name": threat.title,
        "description": threat.description or "",
        "pattern": _build_pattern(threat.ioc_value, threat.ioc_type),
        "pattern_type": "stix",
        "valid_from": ts,
        "labels": ["malicious-activity"],
        "lang": "ko",
        "confidence": {"긴급": 90, "높음": 75, "중간": 50, "낮음": 25}.get(threat.severity, 50),
        "external_references": [
            {"source_name": "ICTIP", "external_id": str(threat.id), "source_ref": threat.source}
        ],
        "x_ictip_severity": threat.severity,
        "x_ictip_threat_type": threat.threat_type,
        "x_ictip_source": threat.source,
        "x_ictip_country_code": threat.country_code or "",
        "x_ictip_actor_tag": threat.actor_tag or "",
    }
    if threat.mitre_tactic and threat.mitre_technique_id:
        indicator["kill_chain_phases"] = [{
            "kill_chain_name": "mitre-attack",
            "phase_name": threat.mitre_tactic.lower().replace(" ", "-"),
        }]
        indicator["x_mitre_technique_id"] = threat.mitre_technique_id
        indicator["x_mitre_tactic_id"] = threat.mitre_tactic_id or ""
    return indicator


# ── STIX Bundle ───────────────────────────────────────────────────────────────

@router.get("/api/stix/bundle")
async def get_stix_bundle(
    threat_id: Optional[int] = Query(None, description="특정 위협 ID (없으면 전체)"),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    if threat_id:
        q = select(Threat).where(Threat.id == threat_id, Threat.is_active == True)
    else:
        q = select(Threat).where(Threat.is_active == True).order_by(Threat.detected_at.desc()).limit(1000)

    threats = (await db.execute(q)).scalars().all()
    objects = [IDENTITY] + [threat_to_indicator(t) for t in threats]

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    return JSONResponse(content=bundle, media_type=STIX_MEDIA)


# ── TAXII 2.1 ─────────────────────────────────────────────────────────────────

@router.get("/taxii/")
async def taxii_discovery():
    return JSONResponse(content={
        "title": "ICTIP TAXII 2.1 Server",
        "description": "국제 사이버 위협 인텔리전스 플랫폼 위협 공유 서버",
        "contact": "cert@ictip.platform",
        "api_roots": ["/taxii/"],
    }, media_type=TAXII_MEDIA)


@router.get("/taxii/collections/")
async def taxii_collections(_=Depends(get_current_user)):
    return JSONResponse(content={
        "collections": [{
            "id": "ictip-threats",
            "title": "ICTIP Threat Indicators",
            "description": "ICTIP에서 수집·분석된 사이버 위협 인디케이터 (STIX 2.1)",
            "can_read": True,
            "can_write": True,   # TAXII Write 활성화
            "media_types": [STIX_MEDIA],
        }]
    }, media_type=TAXII_MEDIA)


@router.get("/taxii/collections/ictip-threats/objects/")
async def taxii_get_objects(
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    threats = (await db.execute(
        select(Threat).where(Threat.is_active == True).order_by(Threat.detected_at.desc()).limit(500)
    )).scalars().all()
    return JSONResponse(content={"objects": [threat_to_indicator(t) for t in threats]}, media_type=STIX_MEDIA)


# ── TAXII Write: 외부 기관 STIX 번들 수신 ────────────────────────────────────

@router.post("/taxii/collections/ictip-threats/objects/")
async def taxii_add_objects(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    """
    TAXII 2.1 Write — 외부 기관에서 전송된 STIX 2.1 번들 수신 및 DB 저장.
    지원 STIX 객체 유형: indicator, malware, threat-actor
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="유효하지 않은 JSON 형식입니다.")

    objects = body.get("objects", [])
    bundle_id = body.get("id", f"bundle--{uuid.uuid4()}")
    source_agency = request.headers.get("X-Source-Agency", "외부 기관")

    if not objects:
        raise HTTPException(status_code=400, detail="STIX 번들에 objects가 없습니다.")

    imported = 0
    errors = []

    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type not in ("indicator", "malware", "threat-actor"):
            continue
        try:
            imported_count = await _import_stix_object(obj, db)
            imported += imported_count
        except Exception as e:
            errors.append({"id": obj.get("id", "unknown"), "error": str(e)})

    # 수신 기록 저장
    inbound = InboundSTIX(
        bundle_id=bundle_id,
        source_agency=source_agency,
        object_count=len(objects),
        imported_count=imported,
        received_at=datetime.utcnow(),
        raw_bundle=json.dumps(body)[:10000],  # 최대 10KB만 저장
    )
    db.add(inbound)
    await db.commit()

    logger.info("TAXII 수신: %s에서 %d개 객체 수신, %d개 임포트", source_agency, len(objects), imported)

    return JSONResponse(
        content={
            "id": f"status--{uuid.uuid4()}",
            "status": "complete",
            "request_timestamp": datetime.utcnow().isoformat() + "Z",
            "total_count": len(objects),
            "success_count": imported,
            "failure_count": len(errors),
            "failures": errors,
        },
        media_type=TAXII_MEDIA,
        status_code=202,
    )


async def _import_stix_object(obj: dict, db: AsyncSession) -> int:
    """STIX 객체를 파싱하여 ThreatFeed로 저장. 반환값: 저장된 수."""
    obj_type = obj.get("type")
    obj_id = obj.get("id", "")

    # 중복 체크 (외부 ID 기반)
    existing = (await db.execute(
        select(ThreatFeed).where(ThreatFeed.raw_data.contains(obj_id)).limit(1)
    )).scalar_one_or_none()
    if existing:
        return 0

    now = datetime.utcnow()

    if obj_type == "indicator":
        pattern = obj.get("pattern", "")
        ioc_value, ioc_type = _parse_stix_pattern(pattern)
        title = obj.get("name", "외부 수신 위협 인디케이터")
        description = obj.get("description", "")
        severity_map = {90: "긴급", 75: "높음", 50: "중간"}
        confidence = obj.get("confidence", 50)
        severity = "긴급" if confidence >= 80 else "높음" if confidence >= 60 else "중간"
        threat_type_raw = obj.get("x_ictip_threat_type", "")
        threat_type = threat_type_raw or classify_threat_type(title, description)
        actor = obj.get("x_ictip_actor_tag") or detect_actor(title, description)
        country_code = obj.get("x_ictip_country_code") or None
        detected_raw = obj.get("valid_from") or obj.get("created")
        try:
            detected_at = datetime.fromisoformat(detected_raw.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            detected_at = now

        feed = ThreatFeed(
            title=title[:500],
            severity=severity,
            threat_type=threat_type,
            source=f"taxii_inbound",
            ioc_value=ioc_value[:1000] if ioc_value else None,
            ioc_type=ioc_type,
            country_code=country_code[:10] if country_code else None,
            actor_tag=actor[:200] if actor else None,
            description=description[:500] if description else None,
            ioc_count=1,
            detected_at=detected_at,
            created_at=now,
            raw_data=json.dumps({"stix_id": obj_id, "source": "taxii"})[:2000],
        )
        db.add(feed)
        return 1

    elif obj_type == "malware":
        title = f"[TAXII] {obj.get('name', '외부 수신 악성코드')}"
        feed = ThreatFeed(
            title=title[:500],
            severity="높음",
            threat_type="악성코드/랜섬웨어",
            source="taxii_inbound",
            description=obj.get("description", "")[:500],
            ioc_count=1,
            detected_at=now,
            created_at=now,
            raw_data=json.dumps({"stix_id": obj_id, "type": "malware"})[:2000],
        )
        db.add(feed)
        return 1

    return 0


def _parse_stix_pattern(pattern: str):
    """STIX 패턴에서 IOC 값과 타입 추출."""
    import re
    if "ipv4-addr:value" in pattern:
        m = re.search(r"'([^']+)'", pattern)
        return (m.group(1) if m else None), "ip"
    if "domain-name:value" in pattern:
        m = re.search(r"'([^']+)'", pattern)
        return (m.group(1) if m else None), "domain"
    if "url:value" in pattern:
        m = re.search(r"'([^']+)'", pattern)
        return (m.group(1) if m else None), "url"
    if "file:hashes.MD5" in pattern:
        m = re.search(r"'([^']+)'", pattern)
        return (m.group(1) if m else None), "md5"
    if "file:hashes.'SHA-256'" in pattern or "file:hashes.SHA-256" in pattern:
        m = re.search(r"'([^']+)'", pattern)
        return (m.group(1) if m else None), "sha256"
    if "email-addr:value" in pattern:
        m = re.search(r"'([^']+)'", pattern)
        return (m.group(1) if m else None), "email"
    return None, "other"


@router.get("/taxii/inbound/", tags=["stix"])
async def get_inbound_history(
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """TAXII 수신 이력 조회."""
    result = await db.execute(
        select(InboundSTIX).order_by(InboundSTIX.received_at.desc()).limit(50)
    )
    records = result.scalars().all()
    return [
        {
            "id": r.id,
            "bundle_id": r.bundle_id,
            "source_agency": r.source_agency,
            "object_count": r.object_count,
            "imported_count": r.imported_count,
            "received_at": r.received_at.isoformat(),
        }
        for r in records
    ]
