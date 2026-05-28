# ICTIP — 국제 사이버 위협 인텔리전스 플랫폼

## 실행 방법

### 요구사항
- Docker Desktop
- Docker Compose v2+

### 빠른 시작

```bash
cd ictip
docker compose up --build
```

브라우저에서 http://localhost 접속

### 서비스 구성

| 서비스    | 포트  | 설명                    |
|-----------|-------|-------------------------|
| nginx     | 80    | 리버스 프록시           |
| frontend  | 3000  | React 대시보드          |
| backend   | 8000  | FastAPI + WebSocket     |
| postgres  | 5432  | 위협 데이터 저장소      |
| redis     | 6379  | 실시간 캐시 / Pub-Sub   |

### API 엔드포인트

- `GET /api/dashboard/stats` — KPI 통계
- `GET /api/dashboard/ai-metrics` — AI 모델 성능
- `GET /api/threats/feed` — 실시간 위협 피드
- `GET /api/threats/distribution` — 위협 유형 분포
- `GET /api/countries/shares` — 국가별 IOC 공유 현황
- `GET /api/threats/actors` — 활성 위협 행위자
- `WS  /ws` — 실시간 위협 WebSocket

### 개발 환경

```bash
# 백엔드만 실행
docker compose up postgres redis backend

# 프론트엔드 로컬 개발
cd frontend && npm install && npm start
```
