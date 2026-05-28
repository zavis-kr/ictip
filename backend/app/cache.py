"""Redis 캐시 유틸리티."""
import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

_redis = None


async def get_redis():
    global _redis
    if _redis is not None:
        return _redis
    try:
        import redis.asyncio as aioredis
        from app.config import settings
        _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        await _redis.ping()
        logger.info("Redis 캐시 연결 완료")
    except Exception as e:
        logger.warning("Redis 연결 실패 (캐시 없이 동작): %s", e)
        _redis = None
    return _redis


async def cache_get(key: str) -> Optional[Any]:
    try:
        r = await get_redis()
        if not r:
            return None
        val = await r.get(key)
        return json.loads(val) if val else None
    except Exception:
        return None


async def cache_set(key: str, value: Any, ttl: int = 300) -> None:
    try:
        r = await get_redis()
        if not r:
            return
        await r.setex(key, ttl, json.dumps(value, default=str))
    except Exception as e:
        logger.debug("Redis set 실패: %s", e)


async def cache_delete(key: str) -> None:
    try:
        r = await get_redis()
        if r:
            await r.delete(key)
    except Exception:
        pass
