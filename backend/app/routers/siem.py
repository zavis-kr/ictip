"""SIEM Webhook integration router."""
import json
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
import httpx

from app.database import get_db
from app.models import Threat, SIEMWebhookLog
from app.auth import get_current_user

router = APIRouter(prefix="/api/siem", tags=["siem"])


class WebhookTestRequest(BaseModel):
    url: str
    format: str = "json"  # "json" or "cef"


class WebhookSendRequest(BaseModel):
    url: str
    format: str = "json"  # "json" or "cef"


def _build_json_payload(threat: Threat) -> dict:
    """Build a JSON payload for the threat."""
    return {
        "event_type": "threat_intelligence",
        "platform": "ICTIP",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "threat": {
            "id": threat.id,
            "title": threat.title,
            "severity": threat.severity,
            "threat_type": threat.threat_type,
            "source": threat.source,
            "ioc_value": threat.ioc_value,
            "ioc_type": threat.ioc_type,
            "country_code": threat.country_code,
            "actor_tag": threat.actor_tag,
            "description": threat.description,
            "ioc_count": threat.ioc_count,
            "detected_at": str(threat.detected_at)[:19] if threat.detected_at else None,
            "tlp_level": threat.tlp_level,
            "mitre_tactic": threat.mitre_tactic,
            "mitre_tactic_id": threat.mitre_tactic_id,
            "mitre_technique": threat.mitre_technique,
            "mitre_technique_id": threat.mitre_technique_id,
        },
    }


def _build_cef_payload(threat: Threat) -> str:
    """Build a CEF (Common Event Format) payload for the threat."""
    severity_map = {"긴급": 10, "높음": 7, "중간": 5, "낮음": 2}
    cef_severity = severity_map.get(threat.severity or "", 5)

    # Escape special characters in CEF
    def esc(val: str) -> str:
        if not val:
            return ""
        return val.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")

    # CEF header: CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity
    header = (
        f"CEF:0|ICTIP|ThreatPlatform|1.0"
        f"|{threat.id}"
        f"|{esc(threat.title or 'Unknown Threat')}"
        f"|{cef_severity}"
    )

    # CEF extension fields
    ext_parts = [
        f"src={threat.ioc_value or 'unknown'}" if threat.ioc_type == "ip" else "",
        f"requestUrl={threat.ioc_value or ''}" if threat.ioc_type in ("url", "domain") else "",
        f"fileHash={threat.ioc_value or ''}" if threat.ioc_type in ("hash", "md5", "sha1", "sha256") else "",
        f"deviceAction={esc(threat.threat_type or 'unknown')}",
        f"sourceCountryCode={threat.country_code or 'N/A'}",
        f"cs1={esc(threat.actor_tag or 'N/A')}",
        "cs1Label=ThreatActor",
        f"cs2={threat.tlp_level or 'WHITE'}",
        "cs2Label=TLPLevel",
        f"cs3={esc(threat.mitre_technique_id or 'N/A')}",
        "cs3Label=MITRETechnique",
        f"cat={esc(threat.threat_type or 'unknown')}",
        f"msg={esc((threat.description or '')[:200])}",
        f"start={str(threat.detected_at)[:19].replace(' ', 'T') + 'Z' if threat.detected_at else ''}",
        f"rt={datetime.utcnow().strftime('%b %d %Y %H:%M:%S')}",
        f"cn1={threat.ioc_count}",
        "cn1Label=IOCCount",
    ]
    ext = " ".join(p for p in ext_parts if p)

    return f"{header}|{ext}"


async def _send_webhook(
    url: str,
    payload_str: str,
    content_type: str,
    threat_id: Optional[int],
    fmt: str,
    db: AsyncSession,
) -> SIEMWebhookLog:
    """Send HTTP POST to webhook URL and record the log."""
    status_code = None
    response_body = None
    success = False

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.post(
                url,
                content=payload_str.encode("utf-8") if isinstance(payload_str, str) else payload_str,
                headers={"Content-Type": content_type, "User-Agent": "ICTIP-Webhook/1.0"},
            )
        status_code = resp.status_code
        response_body = resp.text[:500]
        success = 200 <= status_code < 300
    except Exception as e:
        response_body = str(e)[:500]
        success = False

    log = SIEMWebhookLog(
        url=url,
        threat_id=threat_id,
        payload=payload_str[:2000],
        status_code=status_code,
        response_body=response_body,
        format=fmt,
        success=success,
        sent_at=datetime.utcnow(),
    )
    db.add(log)
    await db.commit()
    await db.refresh(log)
    return log


@router.post("/webhook/test")
async def test_webhook(
    body: WebhookTestRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Send a test payload to the specified webhook URL."""
    fmt = body.format.lower()
    test_payload_dict = {
        "event_type": "test",
        "platform": "ICTIP",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "message": "ICTIP Webhook test message",
        "threat": {
            "id": 0,
            "title": "Test Threat",
            "severity": "중간",
            "threat_type": "테스트",
            "ioc_value": "192.0.2.1",
            "ioc_type": "ip",
            "tlp_level": "WHITE",
        },
    }

    if fmt == "cef":
        payload_str = (
            "CEF:0|ICTIP|ThreatPlatform|1.0|0|ICTIP Webhook Test|5|"
            "src=192.0.2.1 deviceAction=Test msg=ICTIP Webhook test message"
        )
        content_type = "text/plain"
    else:
        payload_str = json.dumps(test_payload_dict, ensure_ascii=False)
        content_type = "application/json"

    log = await _send_webhook(body.url, payload_str, content_type, None, fmt, db)
    return {
        "success": log.success,
        "status_code": log.status_code,
        "response": log.response_body,
        "log_id": log.id,
    }


@router.post("/webhook/send/{threat_id}")
async def send_to_webhook(
    threat_id: int,
    body: WebhookSendRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Send a specific threat to the webhook URL."""
    threat = (await db.execute(
        select(Threat).where(Threat.id == threat_id)
    )).scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    fmt = body.format.lower()
    if fmt == "cef":
        payload_str = _build_cef_payload(threat)
        content_type = "text/plain"
    else:
        payload_str = json.dumps(_build_json_payload(threat), ensure_ascii=False)
        content_type = "application/json"

    log = await _send_webhook(body.url, payload_str, content_type, threat_id, fmt, db)
    return {
        "success": log.success,
        "status_code": log.status_code,
        "response": log.response_body,
        "log_id": log.id,
        "threat_id": threat_id,
        "format": fmt,
    }


@router.get("/webhook/logs")
async def get_webhook_logs(
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Return the SIEM webhook transmission history."""
    result = await db.execute(
        select(SIEMWebhookLog)
        .order_by(desc(SIEMWebhookLog.sent_at))
        .limit(limit)
    )
    logs = result.scalars().all()
    return [
        {
            "id": log.id,
            "url": log.url,
            "threat_id": log.threat_id,
            "status_code": log.status_code,
            "success": log.success,
            "format": log.format,
            "sent_at": str(log.sent_at)[:19] if log.sent_at else None,
            "response": log.response_body,
        }
        for log in logs
    ]
