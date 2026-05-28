"""WebSocket connection manager for real-time threat feed."""
import asyncio
import json
import random
from datetime import datetime
from typing import List
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        data = json.dumps(message, ensure_ascii=False)
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_text(data)
            except Exception:
                dead.append(connection)
        for conn in dead:
            self.disconnect(conn)


manager = ConnectionManager()

SIMULATED_THREATS = [
    {"title": "Charming Kitten — 외교관 대상 스피어피싱", "severity": "긴급", "threat_type": "APT/국가지원", "actor": "Charming Kitten"},
    {"title": "랜섬웨어 BlackCat — 제조업 타겟", "severity": "높음", "threat_type": "랜섬웨어", "actor": "BlackCat"},
    {"title": "SSH 브루트포스 — 클라우드 인스턴스", "severity": "중간", "threat_type": "기타", "actor": None},
    {"title": "SQL 인젝션 캠페인 — 전자상거래 플랫폼", "severity": "높음", "threat_type": "기타", "actor": None},
    {"title": "APT29 — 백신 연구소 침투 시도", "severity": "긴급", "threat_type": "APT/국가지원", "actor": "APT29"},
    {"title": "피싱 — 코로나 보조금 사칭 이메일", "severity": "중간", "threat_type": "피싱/소셜엔지니어", "actor": None},
    {"title": "제로데이 — Windows CLFS 드라이버 취약점", "severity": "긴급", "threat_type": "기타", "actor": None},
    {"title": "공급망 — NPM 패키지 타이포스쿼팅", "severity": "높음", "threat_type": "공급망공격", "actor": None},
]


async def simulate_threat_feed():
    """Continuously generate simulated real-time threats."""
    while True:
        await asyncio.sleep(random.uniform(8, 20))
        if manager.active_connections:
            threat = random.choice(SIMULATED_THREATS)
            event = {
                "type": "new_threat",
                "data": {
                    **threat,
                    "id": random.randint(1000, 9999),
                    "ioc_count": random.randint(5, 300),
                    "created_at": datetime.utcnow().isoformat(),
                },
            }
            await manager.broadcast(event)

        # Also broadcast stats update periodically
        if random.random() < 0.3 and manager.active_connections:
            stats_event = {
                "type": "stats_update",
                "data": {
                    "threats_detected": random.randint(14800, 15100),
                    "ai_response_rate": round(random.uniform(90.0, 93.0), 1),
                    "avg_share_time_minutes": round(random.uniform(2.8, 3.8), 1),
                },
            }
            await manager.broadcast(stats_event)
