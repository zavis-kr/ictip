"""YARA and Sigma rule auto-generation router."""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import Threat
from app.auth import get_current_user

router = APIRouter(prefix="/api/rules", tags=["rules"])


def _generate_yara_rule(threat: Threat) -> str:
    """Generate a YARA rule based on the threat's IOC data."""
    ioc_type = (threat.ioc_type or "").lower()
    ioc_value = threat.ioc_value or ""
    threat_id = threat.id
    rule_name = f"ICTIP_Threat_{threat_id}"
    actor = (threat.actor_tag or "Unknown").replace(" ", "_").replace("-", "_")
    threat_type = (threat.threat_type or "Unknown").replace("/", "_").replace(" ", "_")
    now = datetime.utcnow().strftime("%Y-%m-%d")

    meta_block = (
        f'    description = "Auto-generated rule for threat ID {threat_id}: {threat.title[:80]}"\n'
        f'    author = "ICTIP Platform"\n'
        f'    date = "{now}"\n'
        f'    threat_id = "{threat_id}"\n'
        f'    actor = "{actor}"\n'
        f'    threat_type = "{threat_type}"\n'
        f'    severity = "{threat.severity or "N/A"}"\n'
        f'    tlp = "{threat.tlp_level or "WHITE"}"\n'
        f'    reference = "https://ictip.local/threats/{threat_id}"\n'
    )

    condition_block = "    any of them"

    if ioc_type == "hash" or ioc_type in ("md5", "sha1", "sha256"):
        # Detect by hash in strings section
        strings_block = f'    $hash = "{ioc_value}" nocase\n'
        condition_block = "    $hash"
        # Determine hash type by length
        hash_len = len(ioc_value)
        hash_comment = "md5" if hash_len == 32 else ("sha1" if hash_len == 40 else "sha256")
        rule = (
            f"// YARA Rule — {hash_comment.upper()} hash detection\n"
            f"rule {rule_name} {{\n"
            f"    meta:\n{meta_block}"
            f"    strings:\n{strings_block}"
            f"    condition:\n        {condition_block}\n}}\n"
        )
    elif ioc_type == "domain":
        strings_block = (
            f'    $domain1 = "{ioc_value}" nocase\n'
            f'    $domain2 = "{ioc_value}" wide ascii\n'
        )
        rule = (
            f"// YARA Rule — Domain IOC detection\n"
            f"rule {rule_name} {{\n"
            f"    meta:\n{meta_block}"
            f"    strings:\n{strings_block}"
            f"    condition:\n        any of ($domain*)\n}}\n"
        )
    elif ioc_type == "ip":
        # Convert IP to hex pattern for network traffic detection
        parts = ioc_value.split(".")
        hex_pattern = ""
        if len(parts) == 4:
            try:
                hex_pattern = " ".join(f"{int(p):02X}" for p in parts)
            except ValueError:
                hex_pattern = ""
        strings_block = f'    $ip_str = "{ioc_value}"\n'
        if hex_pattern:
            strings_block += f'    $ip_hex = {{ {hex_pattern} }}  // IP in network byte order\n'
        rule = (
            f"// YARA Rule — IP address IOC detection\n"
            f"rule {rule_name} {{\n"
            f"    meta:\n{meta_block}"
            f"    strings:\n{strings_block}"
            f"    condition:\n        any of them\n}}\n"
        )
    elif ioc_type == "url":
        # Extract domain part from URL for matching
        clean_url = ioc_value.replace("http://", "").replace("https://", "")
        strings_block = (
            f'    $url1 = "{ioc_value}" nocase\n'
            f'    $url2 = "{clean_url}" nocase\n'
        )
        rule = (
            f"// YARA Rule — URL IOC detection\n"
            f"rule {rule_name} {{\n"
            f"    meta:\n{meta_block}"
            f"    strings:\n{strings_block}"
            f"    condition:\n        any of ($url*)\n}}\n"
        )
    else:
        # Generic string-based detection
        strings_block = f'    $ioc = "{ioc_value}" nocase\n' if ioc_value else '    $ioc = "unknown" nocase\n'
        rule = (
            f"// YARA Rule — Generic IOC detection (type: {ioc_type or 'unknown'})\n"
            f"rule {rule_name} {{\n"
            f"    meta:\n{meta_block}"
            f"    strings:\n{strings_block}"
            f"    condition:\n        $ioc\n}}\n"
        )

    return rule


def _generate_sigma_rule(threat: Threat) -> str:
    """Generate a Sigma rule based on the threat's data."""
    import yaml
    ioc_type = (threat.ioc_type or "").lower()
    ioc_value = threat.ioc_value or ""
    threat_type = threat.threat_type or "기타"
    severity_map = {
        "긴급": "critical",
        "높음": "high",
        "중간": "medium",
        "낮음": "low",
    }
    sigma_level = severity_map.get(threat.severity or "", "medium")

    # Map threat type to Sigma category/product
    category_map = {
        "악성코드/랜섬웨어": ("process_creation", "windows"),
        "랜섬웨어": ("process_creation", "windows"),
        "봇넷/C&C": ("network_connection", "windows"),
        "APT/국가지원": ("process_creation", "windows"),
        "APT/스파이웨어": ("process_creation", "windows"),
        "피싱/소셜엔지니어링": ("process_creation", "windows"),
        "피싱/소셜엔지니어": ("process_creation", "windows"),
        "취약점/익스플로잇": ("process_creation", "windows"),
        "공급망공격": ("file_event", "windows"),
        "DDoS/서비스거부": ("network_connection", "linux"),
    }
    category, product = category_map.get(threat_type, ("process_creation", "windows"))

    # Build detection based on IOC type
    if ioc_type in ("ip",) and ioc_value:
        detection = {
            "selection": {"DestinationIp": ioc_value},
            "condition": "selection",
        }
        category = "network_connection"
    elif ioc_type == "domain" and ioc_value:
        detection = {
            "selection": {"QueryName|contains": ioc_value},
            "condition": "selection",
        }
        category = "dns_query"
    elif ioc_type == "url" and ioc_value:
        detection = {
            "selection": {"CommandLine|contains": ioc_value},
            "condition": "selection",
        }
    elif ioc_type in ("hash", "md5", "sha1", "sha256") and ioc_value:
        hash_field = "Hashes|contains"
        detection = {
            "selection": {hash_field: ioc_value},
            "condition": "selection",
        }
    else:
        # Fallback: look for actor name in process command lines
        actor = threat.actor_tag or "unknown"
        detection = {
            "selection": {
                "CommandLine|contains": actor,
            },
            "condition": "selection",
        }

    rule = {
        "title": f"ICTIP - {(threat.title or '')[:80]}",
        "id": f"ictip-threat-{threat.id}",
        "status": "experimental",
        "description": (
            f"Auto-generated Sigma rule for threat ID {threat.id}. "
            f"Threat type: {threat_type}. Actor: {threat.actor_tag or 'Unknown'}."
        ),
        "references": [f"https://ictip.local/threats/{threat.id}"],
        "author": "ICTIP Platform",
        "date": datetime.utcnow().strftime("%Y/%m/%d"),
        "tags": [
            f"attack.{(threat.mitre_tactic or 'unknown').lower().replace(' ', '_')}",
            f"attack.{(threat.mitre_technique_id or 'T0000').lower()}",
        ],
        "logsource": {
            "category": category,
            "product": product,
        },
        "detection": detection,
        "fields": ["CommandLine", "ParentCommandLine", "Image"],
        "falsepositives": ["Legitimate administrative activity", "Security testing"],
        "level": sigma_level,
        "metadata": {
            "threat_id": threat.id,
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "tlp": threat.tlp_level or "WHITE",
            "severity": threat.severity or "N/A",
        },
    }

    return yaml.dump(rule, allow_unicode=True, default_flow_style=False, sort_keys=False)


@router.get("/yara/{threat_id}", response_class=PlainTextResponse)
async def get_yara_rule(
    threat_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Generate a YARA rule for the given threat ID."""
    threat = (await db.execute(
        select(Threat).where(Threat.id == threat_id)
    )).scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    yara_rule = _generate_yara_rule(threat)
    return PlainTextResponse(
        content=yara_rule,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="threat_{threat_id}.yar"'},
    )


@router.get("/sigma/{threat_id}")
async def get_sigma_rule(
    threat_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Generate a Sigma rule for the given threat ID."""
    threat = (await db.execute(
        select(Threat).where(Threat.id == threat_id)
    )).scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    sigma_rule = _generate_sigma_rule(threat)
    return Response(
        content=sigma_rule,
        media_type="application/yaml",
        headers={"Content-Disposition": f'attachment; filename="threat_{threat_id}.yml"'},
    )


@router.get("/all/{threat_id}")
async def get_all_rules(
    threat_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Return both YARA and Sigma rules as JSON for the given threat."""
    threat = (await db.execute(
        select(Threat).where(Threat.id == threat_id)
    )).scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    return {
        "threat_id": threat_id,
        "yara": _generate_yara_rule(threat),
        "sigma": _generate_sigma_rule(threat),
        "generated_at": datetime.utcnow().isoformat(),
    }
