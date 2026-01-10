import logging

from src.secure_messenger.db.database import engine
from src.secure_messenger.db.models import Base

logger = logging.getLogger(__name__)


async def init_db():
    logger.info('Creating tables in database...')

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    logger.info('Success.')
