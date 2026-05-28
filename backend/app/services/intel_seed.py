"""
인텔리전스 허브 시연용 위협 데이터 시드.
최근 60일에 걸쳐 현실감 있는 위협 데이터를 Threat 테이블에 삽입합니다.
이미 시드된 경우 스킵합니다.
"""
import random
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models import Threat
from app.services.classifier import get_mitre_mapping

SEED_MARKER_TITLE = "__INTEL_SEED_V1__"

THREAT_SCENARIOS = [
    # (title, severity, threat_type, source, ioc_value, ioc_type, country_code, actor_tag, description, ioc_count, tlp_level)
    ("Lazarus Group 암호화폐 거래소 핫월렛 탈취 시도", "긴급", "APT/국가지원",
     "manual", "194.165.16.11", "IP", "KP", "Lazarus",
     "북한 Lazarus 그룹이 국내 주요 암호화폐 거래소 직원에게 스피어피싱 이메일 발송. 위조된 채용 공고 PDF에 악성 매크로 삽입. 핫월렛 접근 권한 탈취 후 약 450억 원 상당 암호화폐 이체 시도 포착.", 12, "AMBER"),
    ("LockBit 3.0 국내 중견 제조업체 랜섬웨어 배포", "긴급", "랜섬웨어",
     "manual", "185.220.101.45", "IP", "RU", "LockBit",
     "LockBit 3.0이 VPN 취약점(CVE-2023-46805)을 통해 국내 자동차 부품 제조사 내부망 침투. 생산관리 서버 암호화 후 15억 원 비트코인 요구. 이중 갈취 전술로 고객 설계도면 유출 위협.", 8, "AMBER"),
    ("APT41 국내 반도체 기업 기술 유출 캠페인", "긴급", "APT/국가지원",
     "manual", "103.99.200.50", "IP", "CN", "APT41",
     "중국 APT41(Double Dragon)이 국내 반도체 설계 기업 타겟. 공급업체 이메일 계정 탈취 후 공급망 침투. 차세대 DRAM 설계 문서 및 제조 공정 데이터 유출 정황 포착. 미국·일본 동일 기업 대상 동시 캠페인.", 6, "RED"),
    ("Kimsuky 통일부 사칭 한국 정부기관 스피어피싱", "높음", "APT/국가지원",
     "manual", "gov-ministry-kr.info", "domain", "KP", "Kimsuky",
     "북한 Kimsuky APT가 통일부·외교부 직원 사칭 이메일로 한국 싱크탱크 연구원 공격. 첨부 HWP 파일에 BabyShark 악성코드 삽입. 대북 정책 관련 기밀 문서 수집 목적.", 4, "AMBER"),
    ("Cl0p MOVEit 취약점 악용 대규모 데이터 유출", "긴급", "공급망공격",
     "manual", "CVE-2023-34362", "CVE", "RU", "Cl0p",
     "Cl0p 랜섬웨어 그룹이 MOVEit Transfer 제로데이(CVE-2023-34362) 악용. 국내 금융기관·공공기관 파일 전송 서버 집단 침해. 고객 개인정보 230만 건 탈취 후 다크웹 공개 협박.", 15, "AMBER"),
    ("Scattered Spider SIM 스와핑 통신사 임직원 MFA 우회", "높음", "피싱/소셜엔지니어링",
     "manual", "credential-harvest.telecom-kr.net", "domain", "US", "Scattered Spider",
     "Scattered Spider가 통신사 고객센터 직원 사칭 SIM 스와핑 공격. 고위 임원 MFA 우회 후 클라우드 환경 접근. Microsoft 365 테넌트 내 이메일·SharePoint 데이터 대량 탈취.", 5, "GREEN"),
    ("Volt Typhoon 국내 항만 인프라 사전 침투 포착", "긴급", "APT/국가지원",
     "manual", "45.83.65.220", "IP", "CN", "Volt Typhoon",
     "중국 Volt Typhoon이 LOTL(Living off the Land) 기법으로 국내 주요 항만 운영 시스템 사전 침투. 정상 관리 도구만 사용해 장기간 은닉. 유사시 물류 마비 목적 거점 확보 의도 추정.", 3, "RED"),
    ("FIN7 유통업체 POS 시스템 카드 정보 스키밍", "높음", "APT/국가지원",
     "manual", "91.218.114.77", "IP", "UA", "FIN7",
     "FIN7이 국내 대형 유통 프랜차이즈 POS 시스템에 JSSLoader 악성코드 설치. 결제 카드 트랙 데이터 실시간 수집. 약 45만 건 카드 정보 다크웹 카드샵 유통 포착.", 9, "AMBER"),
    ("BianLian 병원 의료 기록 랜섬웨어 및 유출 협박", "긴급", "랜섬웨어",
     "manual", "193.233.20.100", "IP", "RU", "BianLian",
     "BianLian 랜섬웨어가 국내 대형 병원 EMR(전자의무기록) 서버 침해. 파일 암호화 없이 데이터 유출만 진행하는 방식으로 환자 진료기록 350만 건 탈취. HIPAA·개인정보보호법 위반 협박.", 7, "AMBER"),
    ("Sandworm ICS/SCADA 발전소 제어망 침투 시도", "긴급", "APT/국가지원",
     "manual", "ad23c7930dae02de1ea3c673", "sha256", "RU", "Sandworm",
     "러시아 Sandworm이 국내 민간 발전소 OT 네트워크 침투 시도. Industroyer2 변종 악성코드 발견. IT-OT 경계 방화벽 정책 취약점 악용. 전력 공급 장애 유발 목적 추정.", 4, "RED"),
    ("Lazarus 방산 협력사 워터링홀 공격", "높음", "APT/국가지원",
     "manual", "defense-supplier-update.net", "domain", "KP", "Lazarus",
     "Lazarus Group이 방산 협력사 홈페이지 게시판에 악성 JavaScript 삽입. 방문자 브라우저 지문 수집 후 선택적 악성코드 설치. 방산 관계자 PC에서 기밀 설계 문서 탈취.", 6, "RED"),
    ("랜섬웨어 Akira 물류 기업 VPN 무차별 대입 침투", "높음", "랜섬웨어",
     "manual", "203.0.113.45", "IP", "RU", "Akira",
     "Akira 랜섬웨어 조직이 MFA 미적용 Cisco ASA VPN에 크리덴셜 스터핑 공격. 국내 대형 물류 기업 내부망 침투 후 ESXi 서버 하이퍼바이저 레벨 암호화. 운송 예약 시스템 5일간 중단.", 10, "AMBER"),
    ("APT28 NATO 기관 사칭 외교부 스피어피싱", "긴급", "APT/국가지원",
     "manual", "nato-summit-briefing.eu", "domain", "RU", "APT28",
     "러시아 APT28(Fancy Bear)이 NATO 정상회담 관련 문서로 위장한 스피어피싱. 한국 외교부·국방부 직원 대상. HeadLace 백도어 설치 시도. 외교 기밀 문서 및 내부 통신 탈취 목적.", 5, "RED"),
    ("공급망 npm 악성 패키지 한국 핀테크 개발사 타겟", "높음", "공급망공격",
     "manual", "node-korean-payment-utils", "other", "CN", "APT41",
     "APT41 연계 공격자가 npm 저장소에 정상 패키지 사칭 악성 패키지 게시. 국내 핀테크 개발사 CI/CD 파이프라인 오염. 빌드 시 백도어 코드 자동 삽입. 결제 API 키 탈취 피해 발생.", 8, "AMBER"),
    ("MuddyWater 이란 중동 기업 간 무역 사칭 피싱", "중간", "피싱/소셜엔지니어링",
     "manual", "trade-middle-east-verify.com", "domain", "IR", "MuddyWater",
     "이란 MuddyWater APT가 중동·한국 간 교역 기업 사칭 비즈니스 이메일 공격. 무역 계약서 위장 악성 매크로 문서 첨부. SimpleHelp RAT 배포 후 금융 거래 정보 수집.", 3, "GREEN"),
    ("North Korea IT 워커 원격 취업 사기 방산 기업 침투", "높음", "APT/국가지원",
     "manual", "remote-dev-jobs-kr.com", "domain", "KP", "Lazarus",
     "북한 IT 워커가 위장 신분으로 국내 방산 스타트업 원격 개발자 채용. 6개월 내근 후 소스코드 저장소 전체 클론 및 취약점 심기. 미 법무부 기소 사례와 동일 수법.", 2, "RED"),
    ("Charming Kitten 핵 협상 전문가 소셜 엔지니어링", "중간", "APT/국가지원",
     "manual", "nuclear-policy-forum.net", "domain", "IR", "Charming Kitten",
     "이란 Charming Kitten(APT35)이 핵 협상 전문가·싱크탱크 연구원에게 가짜 콘퍼런스 초청. LinkedIn·WhatsApp 통한 신뢰 구축 후 피싱 페이지 유도. 이메일 자격증명 탈취.", 4, "GREEN"),
    ("DDoS 공격 국내 금융 거래소 서비스 장애 유발", "중간", "기타",
     "manual", "198.51.100.200", "IP", "RU", None,
     "러시아 기반 봇넷이 국내 주요 증권 거래소에 대규모 DDoS 공격. 초당 850Gbps 트래픽으로 주문 체결 시스템 30분간 마비. 장 마감 전후 공격 타이밍은 시세 조종 의도 추정.", 25, "WHITE"),
    ("Earth Longzhi 반도체 제조 기업 장기 은닉 APT", "높음", "APT/국가지원",
     "manual", "update.microsoft-system.kr", "domain", "CN", "Earth Longzhi",
     "중국 Earth Longzhi APT가 국내 반도체 장비 기업 내부망 14개월 은닉 포착. WMIC·Certutil 등 LOLBins 활용해 탐지 회피. 경쟁사 장비 스펙·고객사 납품 현황 지속 유출.", 5, "RED"),
    ("Rhysida 교육부 산하 대학 연구 데이터 랜섬웨어", "높음", "랜섬웨어",
     "manual", "185.56.83.200", "IP", "RU", "Rhysida",
     "Rhysida 랜섬웨어가 국내 주요 국립대학교 연구망 침해. 국방 분야 연구 데이터 및 논문 초안 120TB 암호화. 23억 원 비트코인 요구. 협상 거부 시 다크웹 공개 예고.", 11, "AMBER"),
    ("Storm-0558 클라우드 서비스 토큰 위조 정부 접근", "긴급", "APT/국가지원",
     "manual", "40.126.30.145", "IP", "CN", "Storm-0558",
     "중국 Storm-0558이 Microsoft 인증 토큰 위조로 정부 클라우드 이메일 서비스 무단 접근. 외교·안보 관련 이메일 약 6만 건 열람. 국내 외교통상 채널 포함 확인.", 3, "RED"),
    ("북한 가상자산 탈취 믹싱 서비스 자금 세탁 분석", "중간", "APT/국가지원",
     "manual", "tornado-cash-alt.io", "domain", "KP", "Lazarus",
     "Lazarus Group이 탈취한 암호화폐를 Tornado Cash 대체 믹싱 서비스 통해 세탁 정황. 온체인 분석으로 약 1,400억 원 규모 자금 이동 추적. 글로벌 제재 회피 목적.", 2, "GREEN"),
    ("랜섬웨어 TargetCompany 의료 기기 제조사 공격", "높음", "랜섬웨어",
     "manual", "5.188.206.100", "IP", "RU", None,
     "TargetCompany 랜섬웨어가 국내 의료 기기 제조사 SQL 서버 취약점 악용 침투. 의료 기기 펌웨어·품질 인증 문서 암호화. FDA 인증 취소 위협으로 이중 압박 전술 구사.", 6, "AMBER"),
    ("Turla 외교 공관 이메일 서버 백도어 지속성 유지", "중간", "APT/국가지원",
     "manual", "mail-embassy-secure.net", "domain", "RU", "Turla",
     "러시아 Turla APT가 유럽 주재 한국 외교 공관 이메일 서버에 Snake 백도어 지속 유지 포착. 암호화된 P2P 통신으로 C2 서버 은닉. 외교 전문 장기 수집 의도 추정.", 4, "RED"),
    ("OilRig 중동 에너지 기업 ICS 정찰 캠페인", "높음", "APT/국가지원",
     "manual", "energy-ics-portal.ae", "domain", "IR", "OilRig",
     "이란 OilRig(APT34)이 중동 진출 한국 에너지 기업 현지 법인 OT 네트워크 정찰. HOMERUN 백도어로 Historian 서버 접근 시도. 원유 생산 관련 공정 데이터 수집 의도.", 5, "AMBER"),
    ("랜섬웨어 BlackSuit 유통 물류 센터 운영 중단", "긴급", "랜섬웨어",
     "manual", "192.36.27.200", "IP", "RU", None,
     "BlackSuit 랜섬웨어(Royal 후속)가 국내 대형 유통 물류 센터 WMS(창고관리시스템) 서버 침해. 재고 관리·출고 시스템 전면 중단으로 3일간 배송 차질. 피해액 약 45억 원 추산.", 13, "AMBER"),
    ("SideWinder 해운 항만 관제 시스템 정찰", "중간", "APT/국가지원",
     "manual", "port-authority-login.kr", "domain", "IN", "SideWinder",
     "인도 연계 SideWinder APT가 한국 주요 항만 VTS(선박교통관제) 시스템 관리자 대상 스피어피싱. 항만 입출항 데이터 및 화물 정보 수집 목적. 인도-파키스탄 갈등 연장선 분석.", 3, "GREEN"),
    ("Conti 후계 조직 병원 정보 시스템 마비 협박", "긴급", "랜섬웨어",
     "manual", "77.73.133.200", "IP", "RU", "Conti",
     "Conti 해체 후 파생 조직이 국내 3차 의료기관 EMR 시스템 침해. 응급실·수술실 디지털 시스템 마비로 환자 전원 사태 발생. 환자 진료기록 200만 건 유출 위협 및 40억 원 요구.", 9, "RED"),
    ("APT37 국내 탈북민 단체 모바일 스파이웨어", "중간", "APT/국가지원",
     "manual", "nkfreedom-news-app.apk", "other", "KP", "APT37",
     "북한 APT37(ScarCruft)이 탈북민 지원 단체 앱 사칭 안드로이드 스파이웨어 배포. RokRAT 변종으로 통화 기록·GPS·연락처 수집. 탈북 네트워크 및 내부 협력자 색출 목적.", 7, "RED"),
    ("Volt Typhoon 통신 기반 시설 장기 사전 포지셔닝", "긴급", "APT/국가지원",
     "manual", "192.0.2.100", "IP", "CN", "Volt Typhoon",
     "Volt Typhoon이 국내 주요 통신사 코어 라우터에 2년간 은닉. KV-botnet 인프라 활용 C2 통신. 유사시 통신망 단절·교란 목적 선점. CISA 합동 권고문 발령.", 4, "RED"),
    ("피싱 캠페인 세금 환급 사칭 금융 정보 탈취", "낮음", "피싱/소셜엔지니어링",
     "manual", "hometax-refund-kr.com", "domain", "CN", None,
     "중국 기반 공격자가 국세청 홈택스 사칭 SMS 발송. 세금 환급 안내로 위장해 금융 정보 입력 유도. 피싱 페이지 경유 계좌 이체 사기. 피해 건수 약 3,200건 집계.", 1, "WHITE"),
]


async def seed_intel_data(db: AsyncSession) -> int:
    """최근 60일에 걸쳐 현실감 있는 위협 데이터 시드."""
    # 이미 시드됐으면 스킵
    existing = (await db.execute(
        select(Threat).where(Threat.title == SEED_MARKER_TITLE).limit(1)
    )).scalar_one_or_none()
    if existing:
        return 0

    # 기존 위협 날짜 업데이트 (최근 60일 내로)
    existing_threats = (await db.execute(
        select(Threat).where(Threat.is_active == True).limit(32)
    )).scalars().all()

    now = datetime.utcnow()
    rng = random.Random(42)

    for i, threat in enumerate(existing_threats):
        # 최근 60일 내 랜덤 날짜
        days_ago = rng.randint(1, 58)
        hours_ago = rng.randint(0, 23)
        new_dt = now - timedelta(days=days_ago, hours=hours_ago)
        threat.detected_at = new_dt

    # 새 위협 데이터 추가 (시나리오 기반, 최근 60일 분산)
    added = 0
    for i, scenario in enumerate(THREAT_SCENARIOS):
        title, severity, threat_type, source, ioc_value, ioc_type, country_code, actor_tag, desc, ioc_count, tlp = scenario
        days_ago = rng.randint(0, 55)
        hours_ago = rng.randint(0, 23)
        detected = now - timedelta(days=days_ago, hours=hours_ago)
        mitre = get_mitre_mapping(threat_type)

        threat = Threat(
            title=title,
            severity=severity,
            threat_type=threat_type,
            source=source,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            country_code=country_code,
            actor_tag=actor_tag,
            description=desc,
            ioc_count=ioc_count,
            detected_at=detected,
            is_active=True,
            tlp_level=tlp,
            mitre_tactic=mitre["tactic"],
            mitre_tactic_id=mitre["tactic_id"],
            mitre_technique=mitre["technique"],
            mitre_technique_id=mitre["technique_id"],
        )
        db.add(threat)
        added += 1

    # 마커 추가 (재실행 방지)
    marker = Threat(
        title=SEED_MARKER_TITLE, severity="낮음", threat_type="기타",
        source="system", ioc_count=0, is_active=False,
        detected_at=now, tlp_level="WHITE",
    )
    db.add(marker)
    await db.commit()
    return added
