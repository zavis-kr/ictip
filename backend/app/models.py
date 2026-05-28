from datetime import datetime, date as date_type
from typing import Optional
from sqlalchemy import String, Float, Integer, DateTime, Date, Text, Boolean, UniqueConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base
import enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(Base):
    """플랫폼 사용자 계정."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="viewer", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class AuditLog(Base):
    """모든 주요 행위에 대한 감사 로그."""
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)  # LOGIN, CREATE, UPDATE, DELETE, ANALYZE, SHARE
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)  # threat, share, analysis, user
    resource_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class SeverityLevel(str, enum.Enum):
    CRITICAL = "긴급"
    HIGH = "높음"
    MEDIUM = "중간"
    LOW = "낮음"


class ThreatType(str, enum.Enum):
    RANSOMWARE = "랜섬웨어"
    APT = "APT/국가지원"
    PHISHING = "피싱/소셜엔지니어링"
    SUPPLY_CHAIN = "공급망공격"
    OTHER = "기타"


class TLPLevel(str, enum.Enum):
    """Traffic Light Protocol (TLP) 분류 수준."""
    WHITE = "WHITE"    # 제한 없음 - 공개 배포 가능
    GREEN = "GREEN"    # 커뮤니티 내 공유 가능
    AMBER = "AMBER"    # 조직 내 + 필요한 파트너 한정
    RED   = "RED"      # 수신자 한정, 재배포 금지


class Threat(Base):
    """Main threat intelligence record with full IOC details."""
    __tablename__ = "threats"
    __table_args__ = (
        Index("ix_threats_detected_at", "detected_at"),
        Index("ix_threats_severity", "severity"),
        Index("ix_threats_source", "source"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="중간")
    threat_type: Mapped[str] = mapped_column(String(50), nullable=False, default="기타")
    source: Mapped[str] = mapped_column(String(100), nullable=False, default="internal")
    ioc_value: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    ioc_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    country_code: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    actor_tag: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ioc_count: Mapped[int] = mapped_column(Integer, default=1)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    shared_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    raw_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # MITRE ATT&CK
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    mitre_tactic_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    # TLP 분류 (Traffic Light Protocol)
    tlp_level: Mapped[str] = mapped_column(String(10), nullable=False, default="WHITE")

    # Legacy field for backward compatibility with existing frontend
    @property
    def actor(self) -> Optional[str]:
        return self.actor_tag

    @property
    def created_at(self) -> datetime:
        return self.detected_at


# Keep ThreatFeed as alias for backward compatibility
class ThreatFeed(Base):
    """Legacy threat feed table for backward compatibility."""
    __tablename__ = "threat_feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(20))
    threat_type: Mapped[str] = mapped_column(String(50))
    actor: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ioc_count: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(100), default="internal")
    ioc_value: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    ioc_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    country_code: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    actor_tag: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    detected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    shared_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    raw_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class CountryStats(Base):
    """Per-country IOC sharing statistics."""
    __tablename__ = "country_stats"
    __table_args__ = (
        UniqueConstraint("date", "country_code", name="uq_country_stats_date_code"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    date: Mapped[date_type] = mapped_column(Date, nullable=False)
    country_code: Mapped[str] = mapped_column(String(10), nullable=False)
    country_name: Mapped[str] = mapped_column(String(100), nullable=False)
    ioc_count: Mapped[int] = mapped_column(Integer, default=0)


class CountryShare(Base):
    """Legacy country sharing table for backward compatibility."""
    __tablename__ = "country_shares"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    country: Mapped[str] = mapped_column(String(100))
    country_code: Mapped[str] = mapped_column(String(10))
    ioc_shared: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class DailyStats(Base):
    """Aggregate daily platform statistics."""
    __tablename__ = "daily_stats"
    __table_args__ = (
        UniqueConstraint("date", name="uq_daily_stats_date"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    date: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    threats_detected: Mapped[int] = mapped_column(Integer, default=0)
    participating_countries: Mapped[int] = mapped_column(Integer, default=0)
    ai_response_rate: Mapped[float] = mapped_column(Float, default=0.0)
    avg_share_time_minutes: Mapped[float] = mapped_column(Float, default=0.0)
    detection_accuracy: Mapped[float] = mapped_column(Float, default=99.1)
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.3)
    avg_classification_seconds: Mapped[float] = mapped_column(Float, default=4.2)
    attribution_accuracy: Mapped[float] = mapped_column(Float, default=87.6)


class Agency(Base):
    """참여 기관 정보."""
    __tablename__ = "agencies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    country: Mapped[str] = mapped_column(String(100), nullable=False)
    country_code: Mapped[str] = mapped_column(String(10), nullable=False)
    agency_type: Mapped[str] = mapped_column(String(50), default="CERT")  # CERT, GOV, MIL, ISP
    contact_email: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ThreatShare(Base):
    """기관 간 위협 공유 기록."""
    __tablename__ = "threat_shares"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    threat_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    from_agency: Mapped[str] = mapped_column(String(200), nullable=False)
    to_agency_id: Mapped[int] = mapped_column(Integer, nullable=False)
    to_agency_name: Mapped[str] = mapped_column(String(200), nullable=False)
    shared_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # 공유 상태 워크플로우: 대기중 → 전송완료 → 확인됨 (또는 실패)
    status: Mapped[str] = mapped_column(String(20), default="대기중")
    confirmed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    tlp_level: Mapped[str] = mapped_column(String(10), nullable=False, default="WHITE")


class AutoResponse(Base):
    """자동 대응 이력 - 긴급/높음 위협에 대한 자동화된 조치 기록."""
    __tablename__ = "auto_responses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    threat_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # AUTO_ANALYZE, AUTO_SHARE_RECOMMEND, IOC_BLOCK_RULE, ESCALATE
    action_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="완료")
    executed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class InboundSTIX(Base):
    """외부 기관에서 수신된 STIX 번들 수신 기록."""
    __tablename__ = "inbound_stix"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    bundle_id: Mapped[str] = mapped_column(String(200), nullable=False)
    source_agency: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    object_count: Mapped[int] = mapped_column(Integer, default=0)
    imported_count: Mapped[int] = mapped_column(Integer, default=0)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    raw_bundle: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class SIEMWebhookLog(Base):
    """SIEM Webhook 전송 이력."""
    __tablename__ = "siem_webhook_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(String(1000), nullable=False)
    threat_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    format: Mapped[str] = mapped_column(String(20), default="json")  # json or cef
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    sent_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class AIAnalysis(Base):
    """AI 위협 분석 결과."""
    __tablename__ = "ai_analyses"
    __table_args__ = (
        UniqueConstraint("threat_id", name="uq_ai_analyses_threat_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    threat_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)  # 위험, 경고, 주의, 정보
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    attack_vector: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target_sectors: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ioc_analysis: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attribution: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_fallback: Mapped[bool] = mapped_column(Boolean, default=False)
    analyzed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
