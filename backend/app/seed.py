"""Initial seed data for ICTIP platform."""
from datetime import datetime, timedelta
import random
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import ThreatFeed, CountryShare, DailyStats, Agency, User


THREAT_TEMPLATES = [
    {"title": "APT41 — 에너지 인프라 대상 스피어피싱", "severity": "긴급", "threat_type": "APT/국가지원", "actor": "APT41"},
    {"title": "랜섬웨어 LockBit 4.0 — 의료기관 캠페인", "severity": "긴급", "threat_type": "랜섬웨어", "actor": "LockBit"},
    {"title": "Log4j 변종 — 금융 부문 취약점 스캔", "severity": "높음", "threat_type": "기타", "actor": None},
    {"title": "DDoS 공격 — 정부 포털 대상 봇넷 활동", "severity": "높음", "threat_type": "기타", "actor": None},
    {"title": "크리덴셜 스터핑 — 클라우드 서비스 타겟", "severity": "중간", "threat_type": "피싱/소셜엔지니어", "actor": "Scattered Spider"},
    {"title": "APT28 — NATO 기관 대상 스피어피싱", "severity": "긴급", "threat_type": "APT/국가지원", "actor": "APT28"},
    {"title": "Lazarus — 암호화폐 거래소 공격", "severity": "높음", "threat_type": "APT/국가지원", "actor": "Lazarus"},
    {"title": "Sandworm — 산업제어시스템 취약점 악용", "severity": "긴급", "threat_type": "APT/국가지원", "actor": "Sandworm"},
    {"title": "피싱 캠페인 — 금융기관 직원 타겟", "severity": "중간", "threat_type": "피싱/소셜엔지니어", "actor": None},
    {"title": "공급망 공격 — 오픈소스 패키지 악성코드 삽입", "severity": "높음", "threat_type": "공급망공격", "actor": None},
]

# ── 참여 기관 (32개국) ────────────────────────────────────────────────────────
ALL_AGENCIES = [
    # 핵심 파트너
    {"name": "KISA (한국인터넷진흥원)",            "country": "한국",       "country_code": "KR", "agency_type": "CERT", "contact_email": "cert@kisa.or.kr"},
    {"name": "CISA (사이버보안·인프라보안국)",       "country": "미국",       "country_code": "US", "agency_type": "GOV",  "contact_email": "central@cisa.dhs.gov"},
    {"name": "NISC (내각사이버보안센터)",            "country": "일본",       "country_code": "JP", "agency_type": "GOV",  "contact_email": "info@nisc.go.jp"},
    {"name": "BSI (연방정보보안청)",                "country": "독일",       "country_code": "DE", "agency_type": "GOV",  "contact_email": "bsi@bsi.bund.de"},
    {"name": "NCSC (국가사이버보안센터)",            "country": "영국",       "country_code": "GB", "agency_type": "CERT", "contact_email": "enquiries@ncsc.gov.uk"},
    {"name": "ANSSI (국가정보시스템보안청)",         "country": "프랑스",     "country_code": "FR", "agency_type": "GOV",  "contact_email": "contact@ssi.gouv.fr"},
    {"name": "CCCS (캐나다사이버보안센터)",          "country": "캐나다",     "country_code": "CA", "agency_type": "CERT", "contact_email": "contact@cyber.gc.ca"},
    {"name": "ACSC (호주사이버보안센터)",            "country": "호주",       "country_code": "AU", "agency_type": "GOV",  "contact_email": "asd.assist@defence.gov.au"},
    {"name": "CERT-EU (유럽연합CERT)",              "country": "유럽연합",   "country_code": "EU", "agency_type": "CERT", "contact_email": "cert-eu@ec.europa.eu"},
    {"name": "INTERPOL 사이버범죄국",               "country": "국제",       "country_code": "INT","agency_type": "INT",  "contact_email": "cybercrime@interpol.int"},
    # 확장 파트너
    {"name": "NCSC-NL (네덜란드사이버보안센터)",    "country": "네덜란드",   "country_code": "NL", "agency_type": "GOV",  "contact_email": "ncsc@ncsc.nl"},
    {"name": "CERT-IN (인도컴퓨터긴급대응팀)",      "country": "인도",       "country_code": "IN", "agency_type": "CERT", "contact_email": "incident@cert-in.org.in"},
    {"name": "CSA (사이버보안청)",                  "country": "싱가포르",   "country_code": "SG", "agency_type": "GOV",  "contact_email": "info@csa.gov.sg"},
    {"name": "INCD (이스라엘사이버국)",             "country": "이스라엘",   "country_code": "IL", "agency_type": "GOV",  "contact_email": "cert@cert.gov.il"},
    {"name": "NCSC-CH (스위스사이버보안센터)",       "country": "스위스",     "country_code": "CH", "agency_type": "GOV",  "contact_email": "info@ncsc.admin.ch"},
    {"name": "NCSC-SE (스웨덴사이버보안센터)",       "country": "스웨덴",     "country_code": "SE", "agency_type": "GOV",  "contact_email": "ncsc@ncsc.se"},
    {"name": "NCSC-FI (핀란드사이버보안센터)",       "country": "핀란드",     "country_code": "FI", "agency_type": "GOV",  "contact_email": "cert@cert.fi"},
    {"name": "CSIRT-IT (이탈리아CSIRT)",            "country": "이탈리아",   "country_code": "IT", "agency_type": "CERT", "contact_email": "info@csirt.gov.it"},
    {"name": "CCN-CERT (스페인국가암호원)",         "country": "스페인",     "country_code": "ES", "agency_type": "CERT", "contact_email": "cert@ccn.cni.es"},
    {"name": "CERT-PL (폴란드CERT)",               "country": "폴란드",     "country_code": "PL", "agency_type": "CERT", "contact_email": "cert@cert.pl"},
    {"name": "NUKIB (체코사이버보안청)",             "country": "체코",       "country_code": "CZ", "agency_type": "GOV",  "contact_email": "info@nukib.cz"},
    {"name": "RIA (에스토니아정보시스템청)",         "country": "에스토니아", "country_code": "EE", "agency_type": "GOV",  "contact_email": "ria@ria.ee"},
    {"name": "NCSC-NZ (뉴질랜드사이버보안센터)",    "country": "뉴질랜드",   "country_code": "NZ", "agency_type": "GOV",  "contact_email": "info@ncsc.govt.nz"},
    {"name": "NSM (노르웨이보안청)",                "country": "노르웨이",   "country_code": "NO", "agency_type": "GOV",  "contact_email": "firmapost@nsm.no"},
    {"name": "CFCS (덴마크사이버보안센터)",         "country": "덴마크",     "country_code": "DK", "agency_type": "GOV",  "contact_email": "cfcs@cfcs.dk"},
    {"name": "CCB (벨기에사이버보안센터)",          "country": "벨기에",     "country_code": "BE", "agency_type": "GOV",  "contact_email": "info@ccb.belgium.be"},
    {"name": "CyberSecurity Malaysia",              "country": "말레이시아", "country_code": "MY", "agency_type": "CERT", "contact_email": "cyber999@cybersecurity.my"},
    {"name": "ThaiCERT (태국CERT)",                "country": "태국",       "country_code": "TH", "agency_type": "CERT", "contact_email": "thaicert@mict.go.th"},
    {"name": "VNCERT/CC (베트남CERT)",             "country": "베트남",     "country_code": "VN", "agency_type": "CERT", "contact_email": "vncert@vncert.vn"},
    {"name": "CTIR Gov (브라질정부CSIRT)",          "country": "브라질",     "country_code": "BR", "agency_type": "CERT", "contact_email": "ctir.gov@ctir.gov.br"},
    {"name": "CERT-AT (오스트리아CERT)",            "country": "오스트리아", "country_code": "AT", "agency_type": "CERT", "contact_email": "cert@cert.at"},
    {"name": "DNSC (루마니아사이버보안청)",         "country": "루마니아",   "country_code": "RO", "agency_type": "GOV",  "contact_email": "office@dnsc.ro"},
]

# ── 국가별 IOC 공유 현황 ──────────────────────────────────────────────────────
ALL_COUNTRIES = [
    {"country": "한국",       "country_code": "KR", "ioc_shared": 2100},
    {"country": "미국",       "country_code": "US", "ioc_shared": 1800},
    {"country": "일본",       "country_code": "JP", "ioc_shared": 1400},
    {"country": "독일",       "country_code": "DE", "ioc_shared": 1100},
    {"country": "영국",       "country_code": "GB", "ioc_shared":  900},
    {"country": "프랑스",     "country_code": "FR", "ioc_shared":  750},
    {"country": "캐나다",     "country_code": "CA", "ioc_shared":  620},
    {"country": "호주",       "country_code": "AU", "ioc_shared":  540},
    # 확장
    {"country": "네덜란드",   "country_code": "NL", "ioc_shared":  480},
    {"country": "인도",       "country_code": "IN", "ioc_shared":  450},
    {"country": "싱가포르",   "country_code": "SG", "ioc_shared":  410},
    {"country": "이스라엘",   "country_code": "IL", "ioc_shared":  390},
    {"country": "스위스",     "country_code": "CH", "ioc_shared":  360},
    {"country": "스웨덴",     "country_code": "SE", "ioc_shared":  340},
    {"country": "핀란드",     "country_code": "FI", "ioc_shared":  310},
    {"country": "이탈리아",   "country_code": "IT", "ioc_shared":  290},
    {"country": "스페인",     "country_code": "ES", "ioc_shared":  270},
    {"country": "폴란드",     "country_code": "PL", "ioc_shared":  250},
    {"country": "체코",       "country_code": "CZ", "ioc_shared":  220},
    {"country": "에스토니아", "country_code": "EE", "ioc_shared":  200},
    {"country": "뉴질랜드",   "country_code": "NZ", "ioc_shared":  180},
    {"country": "노르웨이",   "country_code": "NO", "ioc_shared":  170},
    {"country": "덴마크",     "country_code": "DK", "ioc_shared":  160},
    {"country": "벨기에",     "country_code": "BE", "ioc_shared":  150},
    {"country": "말레이시아", "country_code": "MY", "ioc_shared":  130},
    {"country": "태국",       "country_code": "TH", "ioc_shared":  110},
    {"country": "베트남",     "country_code": "VN", "ioc_shared":   95},
    {"country": "브라질",     "country_code": "BR", "ioc_shared":   85},
    {"country": "오스트리아", "country_code": "AT", "ioc_shared":   80},
    {"country": "루마니아",   "country_code": "RO", "ioc_shared":   70},
]


async def seed_database(db: AsyncSession):
    # Check if already seeded
    result = await db.execute(select(ThreatFeed).limit(1))
    if result.scalar_one_or_none():
        return

    # Seed threat feeds
    now = datetime.utcnow()
    for i, template in enumerate(THREAT_TEMPLATES):
        feed = ThreatFeed(
            **template,
            ioc_count=random.randint(10, 500),
            created_at=now - timedelta(minutes=i * 8 + random.randint(0, 5)),
        )
        db.add(feed)

    # Seed country shares
    for country_data in ALL_COUNTRIES:
        share = CountryShare(**country_data, updated_at=now)
        db.add(share)

    # Seed today's stats
    stats = DailyStats(
        date=now,
        threats_detected=14823,
        participating_countries=len(ALL_COUNTRIES),
        ai_response_rate=91.2,
        avg_share_time_minutes=3.2,
        detection_accuracy=99.1,
        false_positive_rate=0.3,
        avg_classification_seconds=4.2,
        attribution_accuracy=87.6,
    )
    db.add(stats)

    # Seed agencies
    for agency_data in ALL_AGENCIES:
        agency = Agency(**agency_data, is_active=True, created_at=now)
        db.add(agency)

    await db.commit()


async def seed_countries_and_agencies(db: AsyncSession):
    """이미 시드된 DB에도 새 국가/기관을 증분 추가합니다."""
    now = datetime.utcnow()

    # 기존 country_code 목록
    existing_cc = {
        r[0] for r in (await db.execute(select(CountryShare.country_code))).all()
    }
    for country_data in ALL_COUNTRIES:
        if country_data["country_code"] not in existing_cc:
            db.add(CountryShare(**country_data, updated_at=now))

    # 기존 기관명 목록
    existing_names = {
        r[0] for r in (await db.execute(select(Agency.name))).all()
    }
    for agency_data in ALL_AGENCIES:
        if agency_data["name"] not in existing_names:
            db.add(Agency(**agency_data, is_active=True, created_at=now))

    await db.commit()


async def seed_default_users(db: AsyncSession):
    """기본 관리자 계정이 없으면 생성합니다."""
    from app.auth import hash_password
    existing = await db.execute(select(User).where(User.username == "admin"))
    if existing.scalar_one_or_none():
        return
    users = [
        User(username="admin", email="admin@ictip.platform",
             hashed_password=hash_password("Admin1234!"), role="admin"),
        User(username="analyst", email="analyst@ictip.platform",
             hashed_password=hash_password("Analyst1234!"), role="analyst"),
    ]
    for u in users:
        db.add(u)
    await db.commit()
