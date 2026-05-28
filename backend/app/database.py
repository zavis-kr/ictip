import logging
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.config import settings

logger = logging.getLogger(__name__)

engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=3600,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db():
    """Create all database tables and apply column migrations."""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # Column migrations for existing tables
        migrations = [
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(100)",
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS mitre_tactic_id VARCHAR(20)",
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(200)",
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS mitre_technique_id VARCHAR(20)",
            "ALTER TABLE ai_analyses ADD COLUMN IF NOT EXISTS is_fallback BOOLEAN DEFAULT FALSE",
            # TLP 분류 체계
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS tlp_level VARCHAR(10) DEFAULT 'WHITE'",
            # 공유 상태 워크플로우
            "ALTER TABLE threat_shares ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMP",
            "ALTER TABLE threat_shares ADD COLUMN IF NOT EXISTS tlp_level VARCHAR(10) DEFAULT 'WHITE'",
            "UPDATE threat_shares SET status = '전송완료' WHERE status NOT IN ('대기중','전송완료','확인됨','실패')",
            # SIEM Webhook Logs table
            """CREATE TABLE IF NOT EXISTS siem_webhook_logs (
                id SERIAL PRIMARY KEY,
                url VARCHAR(1000) NOT NULL,
                threat_id INTEGER,
                payload TEXT,
                status_code INTEGER,
                response_body TEXT,
                format VARCHAR(20) DEFAULT 'json',
                success BOOLEAN DEFAULT FALSE,
                sent_at TIMESTAMP DEFAULT NOW()
            )""",
            "CREATE INDEX IF NOT EXISTS ix_siem_webhook_logs_sent_at ON siem_webhook_logs (sent_at)",
            "CREATE INDEX IF NOT EXISTS ix_siem_webhook_logs_threat_id ON siem_webhook_logs (threat_id)",
        ]
        async with engine.begin() as conn:
            from sqlalchemy import text
            for stmt in migrations:
                try:
                    await conn.execute(text(stmt))
                except Exception:
                    pass

        logger.info("Database tables initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise
