from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional, List


# ─── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: Optional[str] = "viewer"


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ─── Threat Feed ───────────────────────────────────────────────────────────────

class ThreatFeedOut(BaseModel):
    id: int
    title: str
    severity: str
    threat_type: str
    actor: Optional[str] = None
    description: Optional[str] = None
    ioc_count: int
    source: str = "internal"
    ioc_value: Optional[str] = None
    ioc_type: Optional[str] = None
    country_code: Optional[str] = None
    actor_tag: Optional[str] = None
    detected_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ThreatCreate(BaseModel):
    title: str
    severity: str
    threat_type: str
    source: str
    ioc_value: Optional[str] = None
    ioc_type: Optional[str] = None
    country_code: Optional[str] = None
    actor_tag: Optional[str] = None
    description: Optional[str] = None
    ioc_count: int = 1
    detected_at: Optional[datetime] = None
    shared_at: Optional[datetime] = None
    raw_data: Optional[str] = None
    tlp_level: str = "WHITE"


class ThreatListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[ThreatFeedOut]


class FeedListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[ThreatFeedOut]


# ─── Country Stats ─────────────────────────────────────────────────────────────

class CountryShareOut(BaseModel):
    country: str
    country_code: str
    ioc_shared: int

    model_config = {"from_attributes": True}


class CountryStatsOut(BaseModel):
    country_code: str
    country_name: str
    ioc_count: int

    model_config = {"from_attributes": True}


# ─── Dashboard / Overview ──────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    threats_detected: int
    threats_change_pct: float
    participating_countries: int
    new_countries: int
    ai_response_rate: float
    ai_response_change: float
    avg_share_time_minutes: float
    share_time_change: float


class OverviewStats(BaseModel):
    """4 stat cards for the dashboard header row."""
    today_threats: int = Field(description="오늘 탐지 위협 수")
    today_threats_change_pct: float = Field(description="전일 대비 변화율 (%)")
    participating_countries: int = Field(description="참여 국가 수")
    new_countries: int = Field(description="신규 참여 국가")
    ai_response_rate: float = Field(description="AI 자동 대응율 (%)")
    ai_response_change: float = Field(description="AI 대응율 변화 (%p)")
    avg_detection_time: float = Field(description="평균 탐지→공유 시간 (분)")
    avg_detection_time_change: float = Field(description="탐지 시간 변화 (분)")


# ─── Threat Distribution ───────────────────────────────────────────────────────

class ThreatDistribution(BaseModel):
    type: str
    percentage: float
    color: str


class DistributionResponse(BaseModel):
    items: List[ThreatDistribution]
    total_threats: int


# ─── AI Metrics ────────────────────────────────────────────────────────────────

class AIMetrics(BaseModel):
    detection_accuracy: float = Field(description="탐지 정확도 (%)")
    false_positive_rate: float = Field(description="오탐율 (%)")
    avg_classification_seconds: float = Field(description="평균 분류 시간 (초)")
    attribution_accuracy: float = Field(description="귀속 분석 정확도 (%)")


# ─── Platform Metrics (실측) ───────────────────────────────────────────────────

class PlatformMetrics(BaseModel):
    total_threats: int          # 누적 수집 위협 수
    today_threats: int          # 오늘 신규 위협 수
    high_risk_rate: float       # 고위험(긴급+높음) 비율 %
    attribution_rate: float     # 위협 행위자 귀속율 %
    active_sources: int         # 오늘 활성 피드 소스 수
    avg_detection_lag_hours: float  # 평균 탐지 지연 (시간, 실시간 소스 기준)
    today_ioc_sum: int          # 오늘 수집된 총 IOC 수
    updated_at: datetime        # 마지막 집계 시각


# ─── Threat Actors ─────────────────────────────────────────────────────────────

class ThreatActor(BaseModel):
    name: str
    active: bool = True


# ─── Stats ─────────────────────────────────────────────────────────────────────

class ThreatStatsResponse(BaseModel):
    total_today: int
    by_severity: dict
    by_type: dict
    by_source: dict


# ─── WebSocket ─────────────────────────────────────────────────────────────────

class WSNewThreat(BaseModel):
    type: str = "new_threat"
    data: ThreatFeedOut


class WSStatsUpdate(BaseModel):
    type: str = "stats_update"
    data: dict


# ─── Threat Detail & Update ────────────────────────────────────────────────────

class ThreatDetailOut(BaseModel):
    id: int
    title: str
    severity: str
    threat_type: str
    source: str
    ioc_value: Optional[str] = None
    ioc_type: Optional[str] = None
    country_code: Optional[str] = None
    actor_tag: Optional[str] = None
    description: Optional[str] = None
    ioc_count: int
    detected_at: datetime
    shared_at: Optional[datetime] = None
    is_active: bool
    mitre_tactic: Optional[str] = None
    mitre_tactic_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    tlp_level: str = "WHITE"

    model_config = {"from_attributes": True}


class ThreatUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    threat_type: Optional[str] = None
    source: Optional[str] = None
    ioc_value: Optional[str] = None
    ioc_type: Optional[str] = None
    country_code: Optional[str] = None
    actor_tag: Optional[str] = None
    description: Optional[str] = None
    ioc_count: Optional[int] = None
    is_active: Optional[bool] = None
    tlp_level: Optional[str] = None


# ─── Agency ────────────────────────────────────────────────────────────────────

class AgencyOut(BaseModel):
    id: int
    name: str
    country: str
    country_code: str
    agency_type: str
    contact_email: Optional[str] = None
    is_active: bool

    model_config = {"from_attributes": True}


# ─── Sharing ───────────────────────────────────────────────────────────────────

class ShareCreate(BaseModel):
    agency_ids: List[int]
    note: Optional[str] = None
    from_agency: str = "KISA (한국인터넷진흥원)"
    tlp_level: str = "WHITE"


class ShareOut(BaseModel):
    id: int
    threat_id: int
    from_agency: str
    to_agency_id: int
    to_agency_name: str
    shared_at: datetime
    note: Optional[str] = None
    status: str
    confirmed_at: Optional[datetime] = None
    tlp_level: str = "WHITE"

    model_config = {"from_attributes": True}


class AutoResponseOut(BaseModel):
    id: int
    threat_id: int
    action_type: str
    action_detail: Optional[str] = None
    status: str
    executed_at: datetime

    model_config = {"from_attributes": True}


class InboundSTIXOut(BaseModel):
    id: int
    bundle_id: str
    source_agency: Optional[str] = None
    object_count: int
    imported_count: int
    received_at: datetime

    model_config = {"from_attributes": True}


# ─── AI Analysis ───────────────────────────────────────────────────────────────

class AIAnalysisOut(BaseModel):
    id: int
    threat_id: int
    risk_score: float
    risk_level: str
    summary: str
    attack_vector: Optional[str] = None
    target_sectors: Optional[str] = None
    recommendations: Optional[str] = None
    ioc_analysis: Optional[str] = None
    attribution: Optional[str] = None
    confidence_score: float
    is_fallback: bool = False
    analyzed_at: datetime

    model_config = {"from_attributes": True}


# ─── Attack Map ────────────────────────────────────────────────────────────────

class AttackMapEntry(BaseModel):
    country_code: str
    country_name: str
    count: int


class TopAttacker(BaseModel):
    ip: str
    count: int
    country_code: Optional[str] = None
    severity: Optional[str] = None
    threat_type: Optional[str] = None


# ─── Geopolitical Risk ─────────────────────────────────────────────────────────

class GeoRiskEntry(BaseModel):
    country_code: str
    country_name: str
    score: int                  # 0-100
    level: str                  # 긴급 / 높음 / 중간 / 낮음
    trend: str                  # 상승 / 안정 / 하락
    factors: List[str]


# ─── Economic Indicators ───────────────────────────────────────────────────────

class EconomicIndicator(BaseModel):
    name: str
    value: float
    change: float               # 24h 변화율 (%)
    category: str               # 환율 / 암호화폐
    unit: str


# ─── Correlation ───────────────────────────────────────────────────────────────

class CorrelationPoint(BaseModel):
    date: str
    attacks: int
    btc_usd: Optional[float] = None
    usd_krw: Optional[float] = None

class CorrelationData(BaseModel):
    data: List[CorrelationPoint]
    btc_corr: float
    krw_corr: float
    period_days: int
    interpretation: str


# ─── Health ────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    database: str
    redis: str
