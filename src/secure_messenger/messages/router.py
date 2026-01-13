from fastapi import APIRouter, Depends, Query, Request, status
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession

from secure_messenger.auth.dependencies import get_current_user
from secure_messenger.db.database import get_db
from secure_messenger.db.redis_client import get_redis
from secure_messenger.messages.schemas import SendMessageModel, ShowMessageModel
from secure_messenger.messages.service import get_user_messages, send_message

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


@messages_router.get(
    '/messages/get',
    response_model=list[ShowMessageModel],
    status_code=status.HTTP_200_OK,
)
async def get_inbox(
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
    skip: int = Query(0, ge=0, description='Number of messages to skip'),
    limit: int = Query(50, ge=1, le=100, description='Number of messages to download'),
):
    current_user = await get_current_user(request, redis_client)

    messages = await get_user_messages(db, current_user, skip, limit)

    return messages


# TODO /messages/delete
