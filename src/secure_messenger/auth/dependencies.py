import json
from typing import NamedTuple
from uuid import UUID

from fastapi import HTTPException, Request, status
import redis.asyncio as redis


class CurrentUser(NamedTuple):
    session_id: str
    user_id: UUID
    private_key: bytes


async def get_current_user(
    request: Request,
    redis_client: redis.Redis,
) -> CurrentUser:
    """Dependency to get the current authenticated user."""
    user_id, user_data, session_id = await get_current_user_id(request, redis_client)
    otp_pending = user_data.get('pending_2fa')

    if not user_id:
        if not session_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='Session expired'
            )

    if otp_pending == 'True':
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='2fa verification required'
        )

    return CurrentUser(session_id, user_id, user_data['private_key'])


async def get_current_user_id(
    request: Request, redis_client: redis.Redis
) -> tuple[UUID, dict, str]:
    """
    Args:
        request (Request): The request object
        redis_client (redis.Redis): Redis client
    Returns:
        tuple[str, dict, str]: user_id, user_data, session_id
    """
    session_id: str = request.cookies.get('session_id')
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Not authenticated'
        )
    user_raw_data = await redis_client.get(f'session:{session_id}')
    if not user_raw_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Session doesn't exist"
        )
    user_data = json.loads(user_raw_data)
    user_id = user_data.get('user_id')

    return user_id, user_data, session_id
