from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from pydantic import ValidationError
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession

from secure_messenger.auth.dependencies import get_current_user
from secure_messenger.db.database import get_db
from secure_messenger.db.redis_client import get_redis
from secure_messenger.messages.schemas import (
    MessageIDModel,
    SendMessageModel,
    ShowMessageModel,
)
from secure_messenger.messages.service import (
    delete_message,
    get_user_messages,
    send_message,
    verify_message,
)

messages_router = APIRouter()


@messages_router.post('/messages/send', status_code=status.HTTP_201_CREATED)
async def send(
    request: Request,
    message_data: str = Form(...),
    files: list[UploadFile] = File(default=[]),
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """
    Send a message with optional attachments to specified recipients.
    Returns a confirmation message and a list of missing users.
    """
    current_user = await get_current_user(request, redis_client)

    try:
        model_data = SendMessageModel.model_validate_json(message_data)
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT) from e

    missing_users = await send_message(db, current_user, model_data, files)

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
    """
    Retrieve a paginated list of messages for the current user.
    Returns a list of messages for the user.
    """
    current_user = await get_current_user(request, redis_client)

    messages = await get_user_messages(db, current_user, skip, limit)

    return messages


@messages_router.delete('/messages/delete', status_code=status.HTTP_200_OK)
async def delete(
    del_message: MessageIDModel,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
    message_id: UUID = Query(description='UUID of message to be marked as read'),
):
    """
    Delete a message from the current user's inbox.
    Returns a confirmation message.
    """
    current_user = await get_current_user(request, redis_client)

    await delete_message(db, current_user, message_id)

    return {'message': 'message deleted successfully'}


@messages_router.post('/messages/verify', status_code=status.HTTP_200_OK)
async def verify(
    message: MessageIDModel,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
    message_id: UUID = Query(description='UUID of message to be marked as read'),
):
    """
    Verify the authenticity of a message by its signature.
    Returns a confirmation message.
    """
    current_user = await get_current_user(request, redis_client)

    await verify_message(db, current_user, message_id)

    return {'message': 'message authenticity verified'}


# TODO add read message endpoint
