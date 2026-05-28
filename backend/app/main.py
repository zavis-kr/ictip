import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.database import init_db, AsyncSessionLocal
from app.seed import seed_database
from app.websocket_manager import manager, simulate_threat_feed
from app.routers import threats
from app.routers import stats as stats_router
from app.routers import agencies as agencies_router
from app.routers import sharing as sharing_router
from app.routers import ai_analysis as ai_analysis_router
from app.routers import auth_router
from app.routers import stix as stix_router
from app.routers import auto_response_router
from app.routers import reports as reports_router
from app.routers import rules as rules_router
from app.routers import graph as graph_router
from app.routers import prediction as prediction_router
from app.routers import siem as siem_router
from app.routers import darkweb as darkweb_router
from app.schemas import HealthResponse
from app.config import settings

logging.basicConfig(
    level=getattr(logging, settings.log_level, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────
    logger.info("Starting ICTIP backend...")
    await init_db()
    logger.info("Database initialized")

    async with AsyncSessionLocal() as db:
        await seed_database(db)
    logger.info("Database seeded")

    async with AsyncSessionLocal() as db:
        from app.seed import seed_countries_and_agencies
        await seed_countries_and_agencies(db)
    logger.info("Countries and agencies expanded")

    async with AsyncSessionLocal() as db:
        from app.seed import seed_default_users
        await seed_default_users(db)
    logger.info("Default users seeded")

    async with AsyncSessionLocal() as db:
        from app.services.intel_seed import seed_intel_data
        n = await seed_intel_data(db)
        if n > 0:
            logger.info("Intelligence hub: %d threat scenarios seeded", n)

    # Start the real-time WebSocket simulator
    asyncio.create_task(simulate_threat_feed())
    logger.info("WebSocket simulator started")

    # Start the APScheduler for fetching real threat intel
    try:
        from app.scheduler import start_scheduler
        await start_scheduler()
        logger.info("APScheduler started — will fetch threat intel every %d minutes",
                    settings.fetch_interval_minutes)
    except Exception as exc:
        logger.warning("Scheduler failed to start (will continue without it): %s", exc)

    yield

    # ── Shutdown ──────────────────────────────────────────────
    try:
        from app.scheduler import stop_scheduler
        await stop_scheduler()
        logger.info("Scheduler stopped")
    except Exception:
        pass
    logger.info("ICTIP backend shutting down")


app = FastAPI(
    title="ICTIP API",
    description="국제 사이버 위협 인텔리전스 플랫폼 API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(threats.router)
app.include_router(stats_router.router)
app.include_router(agencies_router.router)
app.include_router(sharing_router.router)
app.include_router(ai_analysis_router.router)
app.include_router(stix_router.router)
app.include_router(auto_response_router.router)
app.include_router(reports_router.router)
app.include_router(rules_router.router)
app.include_router(graph_router.router)
app.include_router(prediction_router.router)
app.include_router(siem_router.router)
app.include_router(darkweb_router.router)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    logger.debug("WebSocket client connected, total=%d", len(manager.active_connections))
    try:
        while True:
            # Keep connection alive; real messages are pushed via broadcast
            await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
    except asyncio.TimeoutError:
        # Ping to keep alive
        try:
            await websocket.send_text('{"type":"ping"}')
        except Exception:
            manager.disconnect(websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.debug("WebSocket client disconnected, remaining=%d", len(manager.active_connections))
    except Exception as exc:
        logger.warning("WebSocket error: %s", exc)
        manager.disconnect(websocket)


@app.websocket("/ws/threats")
async def websocket_threats_endpoint(websocket: WebSocket):
    """Named threat feed WebSocket endpoint."""
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
    except asyncio.TimeoutError:
        try:
            await websocket.send_text('{"type":"ping"}')
        except Exception:
            manager.disconnect(websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


@app.get("/health", response_model=HealthResponse, tags=["health"])
async def health():
    """Health check endpoint for Docker healthcheck."""
    db_status = "ok"
    redis_status = "ok"

    try:
        from app.database import engine
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
    except Exception as exc:
        db_status = f"error: {exc}"

    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        await r.aclose()
    except Exception as exc:
        redis_status = f"error: {exc}"

    return HealthResponse(
        status="ok" if db_status == "ok" else "degraded",
        service="ICTIP Backend",
        version="1.0.0",
        database=db_status,
        redis=redis_status,
    )
