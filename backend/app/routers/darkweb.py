"""Dark web monitoring router."""
from fastapi import APIRouter, Depends, Query
from app.auth import get_current_user
from app.services.darkweb_monitor import (
    search_ahmia, get_hibp_breaches, monitor_keywords, DEFAULT_KEYWORDS
)

router = APIRouter(prefix="/api/darkweb", tags=["darkweb"])


@router.get("/monitor")
async def get_darkweb_monitor(
    current_user=Depends(get_current_user),
):
    """Return current monitoring status for default keywords."""
    result = await monitor_keywords(DEFAULT_KEYWORDS)
    return result


@router.get("/breaches")
async def get_breaches(
    current_user=Depends(get_current_user),
):
    """Return recent data breach information from Have I Been Pwned."""
    breaches = await get_hibp_breaches()
    return {
        "total": len(breaches),
        "breaches": breaches,
        "source": "haveibeenpwned.com",
    }


@router.get("/search")
async def search_darkweb(
    q: str = Query(..., min_length=2, max_length=100, description="Search keyword"),
    current_user=Depends(get_current_user),
):
    """Search Ahmia.fi for dark web mentions of the given keyword."""
    results = await search_ahmia(q)
    return {
        "query": q,
        "total": len(results),
        "results": results,
        "source": "ahmia.fi",
    }
