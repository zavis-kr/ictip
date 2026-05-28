from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from app.database import get_db
from app.models import Agency
from app.schemas import AgencyOut

router = APIRouter(prefix="/api", tags=["agencies"])


@router.get("/agencies", response_model=List[AgencyOut])
async def list_agencies(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agency).where(Agency.is_active == True).order_by(Agency.country))
    return result.scalars().all()
