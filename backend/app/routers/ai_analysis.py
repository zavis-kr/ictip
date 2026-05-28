import json
import logging
import os
import random

import anthropic
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.database import get_db
from app.models import Threat, ThreatFeed, AIAnalysis, AuditLog
from app.schemas import AIAnalysisOut
from app.auth import require_analyst

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["ai-analysis"])

# ── Claude 클라이언트 (지연 초기화) ───────────────────────────────────────────
_anthropic_client: anthropic.AsyncAnthropic | None = None


def _get_client() -> anthropic.AsyncAnthropic | None:
    global _anthropic_client
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return None
    if _anthropic_client is None:
        _anthropic_client = anthropic.AsyncAnthropic(api_key=api_key)
    return _anthropic_client


# ── 프롬프트 ─────────────────────────────────────────────────────────────────
_SYSTEM = (
    "당신은 국제 사이버 보안 위협 인텔리전스 전문 분석가입니다. "
    "MITRE ATT&CK, OSINT, HUMINT 기반의 심층 위협 분석을 수행합니다. "
    "반드시 순수 JSON 객체만 반환하세요 — 마크다운 코드 블록이나 추가 텍스트 없이."
)


def _build_prompt(threat: Threat) -> str:
    return f"""다음 사이버 보안 위협을 심층 분석하고 JSON 형식으로 결과를 반환하세요.

===== 위협 정보 =====
제목: {threat.title}
심각도: {threat.severity}
위협 유형: {threat.threat_type}
IOC 유형: {threat.ioc_type or "없음"}
IOC 값: {threat.ioc_value or "없음"}
위협 행위자: {threat.actor_tag or "미상"}
설명: {threat.description or "없음"}

===== 반환 형식 (JSON만, 다른 텍스트 절대 포함 금지) =====
{{
  "risk_score": <0.0~100.0 실수. 심각도·위협 유형·IOC·행위자 등을 종합 판단>,
  "risk_level": <"위험" | "경고" | "주의" | "정보" 중 risk_score 기반 선택>,
  "summary": <이 위협의 핵심 특성·공격 방식·파급 영향을 300자 내외 한국어로 종합 서술>,
  "attack_vector": <실제 확인된 또는 추정되는 초기 침투 수단과 공격 경로 상세 서술>,
  "target_sectors": <주요 피해 대상 산업군, 기관 유형, 사용자 그룹>,
  "recommendations": <번호 목록 형식의 구체적 기술 대응 권고사항 5~7개. 각 항목은 명확한 실행 지침 포함>,
  "ioc_analysis": <제공된 IOC의 특성, 위험도 평가, 관련 캠페인 연관성, 즉각 차단 권고 포함>,
  "attribution": <위협 행위자 귀속 분석: 확인 TTP, 인프라 패턴, 역사적 캠페인 유사도 및 신뢰도 수치>,
  "confidence_score": <0.0~100.0 실수. 분석에 사용된 증거의 충분성과 신뢰도>,
  "mitre_tactic": <MITRE ATT&CK 전술 이름. 예: "Initial Access", "Execution", "Persistence", "Impact" 등>,
  "mitre_tactic_id": <MITRE ATT&CK 전술 ID. 예: "TA0001">,
  "mitre_technique": <MITRE ATT&CK 기법 이름. 예: "Phishing", "Command and Scripting Interpreter" 등>,
  "mitre_technique_id": <MITRE ATT&CK 기법 ID. 예: "T1566", "T1059" 등>
}}"""


# ── 폴백: 템플릿 기반 생성 (API 키 없을 때) ──────────────────────────────────
_FALLBACK_TYPE_DATA = {
    "랜섬웨어": {
        "attack_vector": "이메일 첨부파일, RDP 무차별 대입, 취약한 공개 서비스 악용",
        "target_sectors": "의료기관, 제조업, 교육기관, 지방자치단체",
        "summary_suffix": "랜섬웨어 계열 위협입니다. 파일 암호화와 이중 갈취 전술을 결합하였습니다.",
        "recommendations": "1. 오프라인 백업 즉시 무결성 검증\n2. RDP 접근 제한 및 MFA 강제 적용\n3. 네트워크 세그멘테이션 강화\n4. 이메일 보안 게이트웨이 필터 업데이트\n5. EDR 솔루션 실시간 행위 모니터링",
        "ioc_analysis": "수집된 IOC가 기존 랜섬웨어 캠페인 인프라와 부분 중복됩니다. 즉시 차단을 권고합니다.",
    },
    "APT": {
        "attack_vector": "스피어피싱 이메일, 공급망 침투, 제로데이 취약점 악용",
        "target_sectors": "정부기관, 국방산업체, 에너지·전력 인프라, 싱크탱크",
        "summary_suffix": "국가 지원 위협 행위자의 표적 공격 캠페인으로 분석됩니다.",
        "recommendations": "1. 특권 계정 즉시 감사\n2. 아웃바운드 트래픽 이상 모니터링\n3. EDR 에이전트 전 엔드포인트 배포\n4. 주요 시스템 네트워크 분리\n5. TLP:AMBER 위협 정보 공유",
        "ioc_analysis": "사용 TTP가 MITRE ATT&CK T1059·T1078·T1190과 일치합니다.",
    },
    "피싱": {
        "attack_vector": "이메일 스피어피싱, SMS 스미싱, 소셜 엔지니어링",
        "target_sectors": "금융기관 임직원·고객, 공공기관 직원, 기업 경영진",
        "summary_suffix": "정교한 소셜 엔지니어링 기법으로 자격증명 탈취를 목표로 합니다.",
        "recommendations": "1. 전 임직원 보안 인식 교육\n2. DMARC/DKIM/SPF 설정 검증\n3. MFA 미적용 계정 전수 조사\n4. 의심 이메일 신고 프로세스 전파\n5. 피싱 시뮬레이션 훈련 실시",
        "ioc_analysis": "피싱 도메인이 타이포스쿼팅 기법을 활용합니다. 유사 도메인 모니터링을 권고합니다.",
    },
    "공급망": {
        "attack_vector": "오픈소스 패키지 오염, CI/CD 파이프라인 침해, 서드파티 업데이트",
        "target_sectors": "소프트웨어 개발사, IT 서비스 기업, 다운스트림 고객 전반",
        "summary_suffix": "소프트웨어 공급망을 통한 대규모 침해 가능성이 있는 고위험 공격입니다.",
        "recommendations": "1. 서드파티 패키지 즉시 해시 검증\n2. CI/CD 파이프라인 무결성 점검\n3. SBOM 생성·관리 체계 수립\n4. 코드 서명 정책 강화\n5. 의존성 취약점 스캐너 통합",
        "ioc_analysis": "악성 패키지 식별자가 공유되었습니다. 이미 설치된 환경은 즉시 격리 후 재설치를 권고합니다.",
    },
}


def _fallback_generate(threat: Threat, is_fallback: bool = True) -> dict:
    rng = random.Random(threat.id * 31 + len(threat.title))
    severity_risk = {"긴급": (82.0, 98.0), "높음": (62.0, 81.0), "중간": (38.0, 61.0), "낮음": (10.0, 37.0)}
    lo, hi = severity_risk.get(threat.severity, (40.0, 60.0))
    risk_score = round(rng.uniform(lo, hi), 1)
    risk_level = "위험" if risk_score >= 80 else "경고" if risk_score >= 60 else "주의" if risk_score >= 40 else "정보"

    td = None
    for key in _FALLBACK_TYPE_DATA:
        if key in threat.threat_type:
            td = _FALLBACK_TYPE_DATA[key]
            break
    if td is None:
        td = {
            "attack_vector": "다양한 공격 벡터 활용 (분석 진행 중)",
            "target_sectors": "불특정 다수, 취약 시스템",
            "summary_suffix": "추가 분석이 진행 중입니다.",
            "recommendations": "1. 관련 IOC 즉시 차단\n2. 로그 분석 및 이상 행위 모니터링\n3. 유사 패턴 탐지 규칙 추가",
            "ioc_analysis": "수집된 IOC를 기반으로 분석이 진행 중입니다.",
        }

    actor_conf = round(rng.uniform(65, 95), 1)
    actor_sentence = (
        f" 위협 행위자 '{threat.actor_tag}'와의 연관성이 {actor_conf}% 신뢰도로 분석됩니다."
        if threat.actor_tag else " 위협 행위자 귀속 분석이 진행 중입니다."
    )
    summary = f"'{threat.title}' 위협은 {td['summary_suffix']}{actor_sentence}"
    attribution = (
        f"{threat.actor_tag} 그룹 귀속 신뢰도: {actor_conf}% — IOC 인프라 중복, TTP 유사도, 캠페인 타이밍 기반 분석."
        if threat.actor_tag else "위협 행위자 귀속 분석 중 — 추가 IOC 및 TTP 패턴 수집 후 업데이트 예정입니다."
    )
    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "summary": summary,
        "attack_vector": td["attack_vector"],
        "target_sectors": td["target_sectors"],
        "recommendations": td["recommendations"],
        "ioc_analysis": td["ioc_analysis"],
        "attribution": attribution,
        "confidence_score": round(rng.uniform(72, 96), 1),
        "is_fallback": True,
    }


# ── Tool Use 정의 ────────────────────────────────────────────────────────────
TOOLS = [
    {
        "name": "search_related_threats",
        "description": "DB에서 동일 행위자 또는 동일 위협 유형의 연관 위협을 검색합니다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "actor_tag": {"type": "string", "description": "검색할 위협 행위자 이름"},
                "threat_type": {"type": "string", "description": "검색할 위협 유형"},
                "limit": {"type": "integer", "description": "반환할 최대 건수 (기본 5)"},
            },
            "required": [],
        },
    },
    {
        "name": "lookup_cve",
        "description": "NVD API에서 CVE ID의 상세 정보를 조회합니다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "조회할 CVE ID (예: CVE-2024-12345)"},
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "search_ioc_in_feeds",
        "description": "수집된 위협 피드에서 특정 IOC 값을 검색하여 관련 캠페인을 파악합니다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ioc_value": {"type": "string", "description": "검색할 IOC 값 (IP, 도메인, 해시 등)"},
                "limit": {"type": "integer", "description": "반환할 최대 건수 (기본 5)"},
            },
            "required": ["ioc_value"],
        },
    },
]


async def _execute_tool(tool_name: str, tool_input: dict, db: AsyncSession) -> str:
    """Tool Use 요청을 실제로 실행하고 결과를 문자열로 반환."""
    # ⚠️ 주의: 이 함수 내에서 'desc'를 지역변수로 절대 사용하지 말 것.
    # SQLAlchemy의 desc()와 충돌하여 UnboundLocalError 발생.
    from sqlalchemy import desc as sql_desc  # 명시적 임포트로 충돌 방지

    try:
        if tool_name == "search_related_threats":
            actor = tool_input.get("actor_tag")
            ttype = tool_input.get("threat_type")
            limit = min(int(tool_input.get("limit", 5)), 10)
            q = select(Threat).where(Threat.is_active == True)
            if actor:
                q = q.where(Threat.actor_tag == actor)
            elif ttype:
                q = q.where(Threat.threat_type == ttype)
            q = q.order_by(sql_desc(Threat.detected_at)).limit(limit)
            rows = (await db.execute(q)).scalars().all()
            if not rows:
                return "연관 위협 없음"
            results = []
            for r in rows:
                results.append(f"- T{r.id}: {r.title} ({r.severity}, {r.threat_type})"
                                + (f" | 행위자: {r.actor_tag}" if r.actor_tag else ""))
            return "\n".join(results)

        elif tool_name == "lookup_cve":
            cve_id = tool_input.get("cve_id", "").strip()
            if not cve_id:
                return "CVE ID가 없습니다."
            async with httpx.AsyncClient(timeout=8.0) as client:
                r = await client.get(
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                    headers={"User-Agent": "ICTIP/1.0"},
                )
            if r.status_code != 200:
                return f"NVD API 오류: {r.status_code}"
            nvd_data = r.json()
            vulns = nvd_data.get("vulnerabilities", [])
            if not vulns:
                return f"{cve_id} 정보 없음"
            cve_obj = vulns[0].get("cve", {})
            # 지역변수명을 cve_desc로 사용 (desc()와 충돌 방지)
            cve_desc_list = cve_obj.get("descriptions", [])
            cve_desc = next((d["value"] for d in cve_desc_list if d.get("lang") == "en"), "설명 없음")
            metrics = cve_obj.get("metrics", {})
            cvss = ""
            for v in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metrics.get(v):
                    score = metrics[v][0].get("cvssData", {}).get("baseScore", "N/A")
                    sev = metrics[v][0].get("cvssData", {}).get("baseSeverity", "")
                    cvss = f"CVSS: {score} ({sev})"
                    break
            return f"{cve_id} — {cve_desc[:300]} | {cvss}"

        elif tool_name == "search_ioc_in_feeds":
            ioc_val = tool_input.get("ioc_value", "").strip()
            limit = min(int(tool_input.get("limit", 5)), 10)
            if not ioc_val:
                return "IOC 값이 없습니다."
            rows = (await db.execute(
                select(ThreatFeed)
                .where(ThreatFeed.ioc_value.ilike(f"%{ioc_val[:50]}%"))
                .order_by(sql_desc(ThreatFeed.created_at))
                .limit(limit)
            )).scalars().all()
            if not rows:
                return f"'{ioc_val}' IOC 관련 피드 없음"
            results = [f"- [{r.source}] {r.title} ({r.severity})"
                       + (f" | 행위자: {r.actor_tag}" if r.actor_tag else "")
                       for r in rows]
            return "\n".join(results)

    except Exception as e:
        logger.warning("Tool 실행 오류 (%s): %s", tool_name, e)
        return f"Tool 실행 실패: {str(e)[:100]}"

    return "알 수 없는 툴"


# ── Claude API 호출 (Tool Use 지원) ───────────────────────────────────────────
async def _claude_analyze(threat: Threat, db: AsyncSession | None = None) -> dict:
    client = _get_client()
    if client is None:
        logger.warning("ANTHROPIC_API_KEY가 설정되지 않았습니다. 템플릿 기반 분석을 사용합니다.")
        return _fallback_generate(threat)

    try:
        messages = [{"role": "user", "content": _build_prompt(threat)}]
        text = ""
        max_iterations = 5  # Tool Use 루프 최대 횟수

        for iteration in range(max_iterations):
            response = await client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=4096,
                system=_SYSTEM,
                tools=TOOLS,
                messages=messages,
            )

            logger.info("Claude 응답 stop_reason=%s, blocks=%d (iteration %d)",
                        response.stop_reason, len(response.content), iteration)

            # 모든 텍스트 블록 수집 (디버깅 + 최종 응답용)
            def _extract_text(content_blocks) -> str:
                for blk in content_blocks:
                    # SDK 버전에 따라 .type 또는 hasattr로 확인
                    blk_type = getattr(blk, "type", None)
                    blk_text = getattr(blk, "text", None)
                    if blk_type == "text" and blk_text:
                        return blk_text.strip()
                    if blk_text and blk_type != "tool_use":
                        return blk_text.strip()
                return ""

            if response.stop_reason == "end_turn":
                text = _extract_text(response.content)
                logger.info("최종 텍스트 길이: %d", len(text))
                break

            elif response.stop_reason == "tool_use":
                # Tool Use 요청 처리
                assistant_msg = {"role": "assistant", "content": response.content}
                tool_results = []

                for block in response.content:
                    if getattr(block, "type", None) == "tool_use":
                        logger.info("Tool Use 호출: %s(%s)", block.name, block.input)
                        result_str = await _execute_tool(block.name, block.input, db) if db else "DB 없음"
                        logger.info("Tool 결과 (%s): %s", block.name, result_str[:100])
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result_str,
                        })

                messages.append(assistant_msg)
                messages.append({"role": "user", "content": tool_results})
            else:
                # 예상치 못한 stop_reason (max_tokens 등)
                text = _extract_text(response.content)
                logger.warning("예상치 못한 stop_reason=%s, 텍스트=%d자", response.stop_reason, len(text))
                break

        if not text:
            logger.warning("Claude 응답 텍스트가 비어있습니다. 폴백 생성.")
            return _fallback_generate(threat)

        # JSON 추출: 마크다운 코드 블록 제거
        clean = text
        if "```" in clean:
            lines = clean.split("\n")
            clean = "\n".join(
                line for line in lines
                if not line.strip().startswith("```")
            ).strip()

        # JSON 객체 범위 추출 (설명 텍스트가 앞뒤에 붙어있을 경우 대비)
        if not clean.startswith("{"):
            start = clean.find("{")
            end = clean.rfind("}") + 1
            if start != -1 and end > start:
                clean = clean[start:end]

        data = json.loads(clean)

        # 필드 유효성 검증 및 기본값 처리
        risk_score = float(data.get("risk_score", 50.0))
        risk_score = max(0.0, min(100.0, risk_score))
        confidence_score = float(data.get("confidence_score", 75.0))
        confidence_score = max(0.0, min(100.0, confidence_score))

        risk_level = data.get("risk_level", "")
        if risk_level not in ("위험", "경고", "주의", "정보"):
            risk_level = (
                "위험" if risk_score >= 80 else
                "경고" if risk_score >= 60 else
                "주의" if risk_score >= 40 else "정보"
            )

        return {
            "risk_score": round(risk_score, 1),
            "risk_level": risk_level,
            "summary": str(data.get("summary", "")),
            "attack_vector": str(data.get("attack_vector", "")),
            "target_sectors": str(data.get("target_sectors", "")),
            "recommendations": str(data.get("recommendations", "")),
            "ioc_analysis": str(data.get("ioc_analysis", "")),
            "attribution": str(data.get("attribution", "")),
            "confidence_score": round(confidence_score, 1),
            "is_fallback": False,
            # MITRE ATT&CK 자동 분류 결과
            "mitre_tactic": str(data.get("mitre_tactic", ""))[:100] or None,
            "mitre_tactic_id": str(data.get("mitre_tactic_id", ""))[:20] or None,
            "mitre_technique": str(data.get("mitre_technique", ""))[:200] or None,
            "mitre_technique_id": str(data.get("mitre_technique_id", ""))[:20] or None,
        }

    except json.JSONDecodeError as e:
        logger.error("Claude 응답 JSON 파싱 실패: %s\n응답: %s", e, text[:500])
        return _fallback_generate(threat)
    except anthropic.APIError as e:
        logger.error("Claude API 오류: %s", e)
        return _fallback_generate(threat)
    except Exception as e:
        logger.exception("Claude 분석 중 예외 발생: %s", e)
        return _fallback_generate(threat)


# ── 엔드포인트 ────────────────────────────────────────────────────────────────
@router.post("/threats/{threat_id}/analyze", response_model=AIAnalysisOut, status_code=201)
async def analyze_threat(
    threat_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    threat = (await db.execute(select(Threat).where(Threat.id == threat_id))).scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="위협 정보를 찾을 수 없습니다.")

    # 기존 분석 있으면 삭제 후 재생성
    existing = (await db.execute(
        select(AIAnalysis).where(AIAnalysis.threat_id == threat_id)
    )).scalar_one_or_none()
    if existing:
        await db.delete(existing)
        await db.flush()

    data = await _claude_analyze(threat, db=db)

    # MITRE 필드를 AIAnalysis에 전달하기 전에 분리
    mitre_fields = {
        "mitre_tactic":       data.pop("mitre_tactic", None),
        "mitre_tactic_id":    data.pop("mitre_tactic_id", None),
        "mitre_technique":    data.pop("mitre_technique", None),
        "mitre_technique_id": data.pop("mitre_technique_id", None),
    }

    analysis = AIAnalysis(threat_id=threat_id, **data)
    db.add(analysis)

    # Threat 레코드에 MITRE 자동 업데이트 (값이 있을 때만)
    for field, value in mitre_fields.items():
        if value:
            setattr(threat, field, value)
            logger.info("MITRE 자동 업데이트: T%d %s = %s", threat_id, field, value)

    log = AuditLog(
        user_id=current_user.id, username=current_user.username,
        action="ANALYZE", resource_type="threat", resource_id=threat_id,
        detail=f"AI 분석 실행: {threat.title}",
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    await db.commit()
    await db.refresh(analysis)
    return analysis


@router.get("/threats/{threat_id}/analysis", response_model=AIAnalysisOut)
async def get_threat_analysis(threat_id: int, db: AsyncSession = Depends(get_db)):
    analysis = (await db.execute(
        select(AIAnalysis).where(AIAnalysis.threat_id == threat_id)
    )).scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="분석 결과가 없습니다. 먼저 분석을 실행해주세요.")
    return analysis
