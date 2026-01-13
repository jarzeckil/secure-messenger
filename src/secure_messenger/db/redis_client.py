import redis.asyncio as redis

from secure_messenger.core.config import settings

client = redis.Redis(
    host=settings.REDIS_HOST, port=settings.REDIS_PORT, decode_responses=True
)


async def get_redis():
    yield client
