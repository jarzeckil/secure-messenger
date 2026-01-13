from fastapi import APIRouter, Depends, Request, status
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession

from secure_messenger.auth.dependencies import get_current_user
from secure_messenger.db.database import get_db
from secure_messenger.db.redis_client import get_redis
from secure_messenger.messages.schemas import SendMessageModel
from secure_messenger.messages.service import send_message

messages_router = APIRouter()


@messages_router.post('/messages/send', status_code=status.HTTP_201_CREATED)
async def send(
    request: Request,
    message_data: SendMessageModel,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    current_user = await get_current_user(request, redis_client)

    missing_users = await send_message(db, current_user, message_data)

    return {'message': 'Message sent successfully', 'missing users': missing_users}
