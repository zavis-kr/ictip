"""
Rule-based threat classifier.
Maps raw threat data to Korean threat categories and severity levels.
"""
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Threat Type Keywords ──────────────────────────────────────────────────────

RANSOMWARE_KEYWORDS = {
    "ransomware", "ransom", "lockbit", "ryuk", "conti", "revil", "blackcat",
    "alphv", "hive", "clop", "darkside", "blackmatter", "vice society",
    "play ransomware", "akira", "royal ransomware", "cl0p", "noberus",
    "encryptor", "encrypt", "decryptor", "decrypt", "ransom note",
    "data leak", ".locked", ".encrypted",
}

APT_KEYWORDS = {
    "apt28", "apt29", "apt41", "apt32", "apt33", "apt34", "apt37", "apt38",
    "apt40", "apt43", "lazarus", "sandworm", "fancy bear", "cozy bear",
    "charming kitten", "scattered spider", "volt typhoon", "salt typhoon",
    "hafnium", "nobelium", "midnight blizzard", "forest blizzard",
    "nation state", "nation-state", "state sponsored", "state-sponsored",
    "advanced persistent", "espionage", "cyberespionage", "intelligence agency",
    "government sponsored", "military", "kimsuky", "darkhotel", "oilrig",
    "muddywater", "turla", "critical infrastructure", "spear-phish", "spearphish",
}

PHISHING_KEYWORDS = {
    "phishing", "spearphishing", "spear phishing", "smishing", "vishing",
    "social engineering", "credential harvest", "credential steal",
    "fake login", "typosquatt", "pretexting", "baiting", "whaling",
    "business email compromise", "bec", "email fraud", "qr code phish",
    "callback phish", "voice phish", "sms phish",
}

SUPPLY_CHAIN_KEYWORDS = {
    "supply chain", "supplychain", "third party", "third-party", "vendor",
    "software supply", "package poison", "typosquat", "npm package",
    "pypi package", "dependency confusion", "malicious package",
    "open source", "build system", "software update",
    "plugin", "extension compromise", "solarwinds", "xz utils",
    "3cx attack", "codecov", "kaseya",
}

CRITICAL_KEYWORDS = {
    "zero-day", "0day", "zeroday", "critical", "rce", "remote code",
    "unauthenticated", "wormable", "actively exploited", "ransomware",
    "apt", "nation state", "critical infrastructure",
}

HIGH_KEYWORDS = {
    "high", "privilege escalation", "privesc", "lateral movement",
    "data exfiltration", "exfil", "c2", "command and control",
    "botnet", "ddos", "denial of service", "sql injection", "sqli",
    "code execution",
}

LOW_KEYWORDS = {
    "low", "informational", "recon", "reconnaissance", "scan",
    "probe", "enumeration", "fingerprint",
}

KNOWN_ACTORS = {
    "apt28": "APT28",
    "apt29": "APT29",
    "apt41": "APT41",
    "apt32": "APT32",
    "apt33": "APT33",
    "apt34": "APT34",
    "apt37": "APT37",
    "apt38": "APT38",
    "apt40": "APT40",
    "lazarus": "Lazarus",
    "sandworm": "Sandworm",
    "lockbit": "LockBit",
    "charming kitten": "Charming Kitten",
    "scattered spider": "Scattered Spider",
    "fancy bear": "APT28",
    "cozy bear": "APT29",
    "kimsuky": "Kimsuky",
    "volt typhoon": "Volt Typhoon",
    "salt typhoon": "Salt Typhoon",
    "hafnium": "HAFNIUM",
    "nobelium": "NOBELIUM",
    "turla": "Turla",
    "oilrig": "OilRig",
    "muddywater": "MuddyWater",
    "blackcat": "BlackCat",
    "alphv": "BlackCat",
    "ryuk": "Ryuk",
    "conti": "Conti",
    "revil": "REvil",
}

# ─── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────

MITRE_MAPPING = {
    "랜섬웨어": {
        "tactic_id": "TA0040", "tactic": "Impact",
        "technique_id": "T1486", "technique": "Data Encrypted for Impact",
    },
    "악성코드/랜섬웨어": {
        "tactic_id": "TA0002", "tactic": "Execution",
        "technique_id": "T1204", "technique": "User Execution",
    },
    "APT/국가지원": {
        "tactic_id": "TA0043", "tactic": "Reconnaissance",
        "technique_id": "T1595", "technique": "Active Scanning",
    },
    "피싱/소셜엔지니어링": {
        "tactic_id": "TA0001", "tactic": "Initial Access",
        "technique_id": "T1566", "technique": "Phishing",
    },
    "공급망공격": {
        "tactic_id": "TA0001", "tactic": "Initial Access",
        "technique_id": "T1195", "technique": "Supply Chain Compromise",
    },
    "취약점/익스플로잇": {
        "tactic_id": "TA0001", "tactic": "Initial Access",
        "technique_id": "T1190", "technique": "Exploit Public-Facing Application",
    },
    "봇넷/C&C": {
        "tactic_id": "TA0011", "tactic": "Command and Control",
        "technique_id": "T1071", "technique": "Application Layer Protocol",
    },
    "기타": {
        "tactic_id": "TA0040", "tactic": "Impact",
        "technique_id": "T1499", "technique": "Endpoint Denial of Service",
    },
}


def get_mitre_mapping(threat_type: str) -> dict:
    """위협 유형에 해당하는 MITRE ATT&CK 전술/기법을 반환합니다."""
    return MITRE_MAPPING.get(threat_type, MITRE_MAPPING["기타"])


COUNTRY_NAMES = {
    "KR": "한국", "US": "미국", "JP": "일본", "DE": "독일", "GB": "영국",
    "CN": "중국", "RU": "러시아", "FR": "프랑스", "CA": "캐나다", "AU": "호주",
    "NL": "네덜란드", "SG": "싱가포르", "IN": "인도", "BR": "브라질", "UA": "우크라이나",
}


def _lower_text(text: str) -> str:
    return (text or "").lower()


def classify_threat_type(title: str, description: str = "", tags: list = None,
                          source: str = "") -> str:
    """Classify threat into Korean category."""
    tags = tags or []
    combined = (
        _lower_text(title) + " "
        + _lower_text(description) + " "
        + " ".join(_lower_text(t) for t in tags)
    )

    # 소스 기반 기본 분류
    src = source.lower()
    if "urlhaus" in src:
        # URLhaus는 악성 URL/멀웨어 배포 사이트
        if any(kw in combined for kw in ["ransomware", "ransom", "랜섬"]):
            return "악성코드/랜섬웨어"
        if any(kw in combined for kw in ["phish", "피싱"]):
            return "피싱/소셜엔지니어링"
        return "악성코드/랜섬웨어"
    if "cisa" in src or "kev" in src:
        # CISA는 취약점 정보
        return "취약점/익스플로잇"
    if "nvd" in src:
        return "취약점/익스플로잇"
    if "feodo" in src:
        return "봇넷/C&C"
    if "malwarebazaar" in src or "bazaar" in src:
        return "악성코드/랜섬웨어"

    # 키워드 기반 분류
    ransomware_score = sum(1 for kw in RANSOMWARE_KEYWORDS if kw in combined)
    apt_score = sum(1 for kw in APT_KEYWORDS if kw in combined)
    phishing_score = sum(1 for kw in PHISHING_KEYWORDS if kw in combined)
    supply_chain_score = sum(1 for kw in SUPPLY_CHAIN_KEYWORDS if kw in combined)
    scores = {
        "악성코드/랜섬웨어": ransomware_score,
        "APT/국가지원": apt_score,
        "피싱/소셜엔지니어링": phishing_score,
        "공급망공격": supply_chain_score,
    }
    best = max(scores, key=lambda k: scores[k])
    if scores[best] > 0:
        return best
    return "취약점/익스플로잇"


def classify_severity(
    title: str,
    description: str = "",
    threat_type: str = "",
    tags: list = None,
    confidence: float = 0.5,
    cvss_score: Optional[float] = None,
) -> str:
    """Assign severity level: 긴급/높음/중간/낮음."""
    tags = tags or []
    combined = (
        _lower_text(title) + " "
        + _lower_text(description) + " "
        + " ".join(_lower_text(t) for t in tags)
    )
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "긴급"
        elif cvss_score >= 7.0:
            return "높음"
        elif cvss_score >= 4.0:
            return "중간"
        else:
            return "낮음"
    critical_score = sum(1 for kw in CRITICAL_KEYWORDS if kw in combined)
    high_score = sum(1 for kw in HIGH_KEYWORDS if kw in combined)
    low_score = sum(1 for kw in LOW_KEYWORDS if kw in combined)
    if threat_type == "랜섬웨어":
        if critical_score >= 1 or confidence >= 0.8:
            return "긴급"
        return "높음"
    if threat_type == "APT/국가지원":
        if critical_score >= 1:
            return "긴급"
        return "높음"
    if critical_score >= 2:
        return "긴급"
    if critical_score >= 1 or high_score >= 2:
        return "높음"
    if low_score >= 2 and high_score == 0 and critical_score == 0:
        return "낮음"
    if confidence >= 0.8:
        return "높음"
    if confidence >= 0.5:
        return "중간"
    return "낮음"


def detect_actor(title: str, description: str = "", tags: list = None) -> Optional[str]:
    """Extract threat actor name from text if a known actor is mentioned."""
    tags = tags or []
    combined = (
        _lower_text(title) + " "
        + _lower_text(description) + " "
        + " ".join(_lower_text(t) for t in tags)
    )
    for key, actor_name in KNOWN_ACTORS.items():
        if key in combined:
            return actor_name
    return None


def get_country_name(country_code: str) -> str:
    """Return Korean country name for a given ISO country code."""
    return COUNTRY_NAMES.get((country_code or "").upper(), country_code or "Unknown")


def classify_ioc_type(ioc_value: str) -> str:
    """Auto-detect IOC type from its value."""
    if not ioc_value:
        return "unknown"
    if ioc_value.startswith(("http://", "https://", "ftp://")):
        return "url"
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", ioc_value):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32}$", ioc_value):
        return "md5"
    if re.match(r"^[a-fA-F0-9]{40}$", ioc_value):
        return "sha1"
    if re.match(r"^[a-fA-F0-9]{64}$", ioc_value):
        return "sha256"
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", ioc_value):
        return "domain"
    if re.match(r"^[^@]+@[^@]+\.[^@]+$", ioc_value):
        return "email"
    return "other"
