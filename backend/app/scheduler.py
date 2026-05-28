"""
APScheduler - fetches real threat intel from external sources periodically.
"""
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from app.config import settings
from app.services.data_aggregator import run_full_update, update_source_country_shares, update_daily_stats

logger = logging.getLogger(__name__)

_scheduler: AsyncIOScheduler | None = None


async def _run_update_job():
    logger.info("Scheduler: starting threat intel fetch cycle")
    try:
        await run_full_update()
    except Exception as exc:
        logger.error("Scheduler job failed: %s", exc, exc_info=True)


async def _run_hourly_stats_job():
    """1시간마다 실측 플랫폼 지표 집계 (country_shares, daily_stats 갱신)."""
    logger.info("Scheduler: hourly platform stats refresh")
    try:
        await update_source_country_shares()
        await update_daily_stats()
    except Exception as exc:
        logger.error("Hourly stats job failed: %s", exc, exc_info=True)


async def start_scheduler():
    global _scheduler
    _scheduler = AsyncIOScheduler(timezone="UTC")

    # 위협 인텔 수집 (5분마다)
    _scheduler.add_job(
        _run_update_job,
        trigger=IntervalTrigger(minutes=settings.fetch_interval_minutes),
        id="threat_intel_fetch",
        replace_existing=True,
        max_instances=1,
    )

    # 플랫폼 지표 집계 (1시간마다)
    _scheduler.add_job(
        _run_hourly_stats_job,
        trigger=IntervalTrigger(hours=1),
        id="hourly_platform_stats",
        replace_existing=True,
        max_instances=1,
    )

    _scheduler.start()

    # 시작 시 즉시 1회 실행
    import asyncio
    asyncio.create_task(_run_update_job())
    asyncio.create_task(_run_hourly_stats_job())

    logger.info(
        "Scheduler started — fetching every %d minutes, hourly stats refresh enabled",
        settings.fetch_interval_minutes,
    )


async def stop_scheduler():
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")
