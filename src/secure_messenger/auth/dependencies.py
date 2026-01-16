import json
from typing import NamedTuple
from uuid import UUID

from fastapi import HTTPException, Request, status
import redis.asyncio as redis

from secure_messenger.core import security


class CurrentUser(NamedTuple):
    session_id: str
    user_id: UUID
    private_key: bytes


async def get_current_user(
    request: Request,
    redis_client: redis.Redis,
) -> CurrentUser:
    """
    Retrieves the current authenticated user from the session.
    Args:
        request (Request): The HTTP request object containing cookies.
        redis_client (redis.Redis): Redis client for session lookup.
    Returns:
        CurrentUser: The current authenticated user information.
    """
    user_id, user_data, session_id, session_key = await get_current_user_id(
        request, redis_client
    )
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
    private_key = security.decrypt_session_data(
        user_data.get('private_key_encrypted'), session_key
    )
    return CurrentUser(session_id, user_id, private_key)


async def get_current_user_id(
    request: Request, redis_client: redis.Redis
) -> tuple[UUID, dict, str, bytes]:
    """
    Retrieves the user ID, user data, and session ID from the session.
    Args:
        request (Request): The HTTP request object containing cookies.
        redis_client (redis.Redis): Redis client for session lookup.
    Returns:
        tuple[UUID, dict, str]: User ID, user data dictionary, and session ID string.
    """
    session_id: str = request.cookies.get('session_id')
    session_key: bytes = bytes.fromhex(request.cookies.get('session_key'))
    if not session_id or not session_key:
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

    return user_id, user_data, session_id, session_key
