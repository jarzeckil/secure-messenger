import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from fastapi_limiter.depends import RateLimiter
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession

from secure_messenger.auth.schemas import (
    UserLoginModel,
    UserOtpModel,
    UserPasswordModel,
    UserRegisterModel,
)
from secure_messenger.auth.service import (
    login_user,
    register_user,
)
from secure_messenger.auth.totp_service import (
    enable_totp,
    generate_totp_secret,
    login_with_totp,
)
from secure_messenger.core.config import settings
from secure_messenger.db.database import get_db
from secure_messenger.db.redis_client import get_redis

auth_router = APIRouter()


@auth_router.post('/register', status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegisterModel, db: AsyncSession = Depends(get_db)):
    """Registration endpoint."""
    new_user = await register_user(db, user_data)

    return {
        'id': new_user.id,
        'username': new_user.username,
        'message': 'New user has been successfully created',
    }


@auth_router.post(
    '/login',
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter(times=5, seconds=60))],
)
async def login(
    response: Response,
    user_login_data: UserLoginModel,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """Login endpoint."""
    session_id, otp_required = await login_user(db, redis_client, user_login_data)

    response.set_cookie(
        key='session_id',
        value=f'{session_id}',
        httponly=True,
        secure=True,
        samesite='lax',
        max_age=settings.MAX_SESSION_AGE,
    )

    return {'message': 'Logged-in successfully', 'require_2fa': otp_required}


@auth_router.post('/logout', status_code=status.HTTP_200_OK)
async def logout(
    request: Request, response: Response, redis_client: redis.Redis = Depends(get_redis)
):
    """Logout endpoint."""
    session_id = request.cookies.get('session_id')

    if session_id:
        await redis_client.delete(f'session:{session_id}')

    response.delete_cookie(
        key='session_id',
        httponly=True,
        secure=True,
        samesite='lax',
    )

    return {'message': 'Logged out successfully'}


@auth_router.post('/2fa/setup', status_code=status.HTTP_200_OK)
async def setup_2fa(
    request: Request,
    user_password_data: UserPasswordModel,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """
    Args:
        request (Request): The request object
        user_password_data (UserPasswordModel): The user's password data
        db (AsyncSession): Database session
        redis_client (redis.Redis): Redis client
    Returns:
        dict: TOTP secret and QR code
    """
    user_id = await get_current_user(request, redis_client)
    # TODO - add backup codes
    totp_secret, qr = await generate_totp_secret(db, user_id, user_password_data)

    return {'totp_secret': totp_secret, 'qr': qr}


@auth_router.post('/2fa/enable', status_code=status.HTTP_200_OK)
async def enable_2fa(
    request: Request,
    user_otp_data: UserOtpModel,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """
    Args:
        request (Request): The request object
        user_otp_data (UserOtpModel): The user's OTP data
        db (AsyncSession): Database session
        redis_client (redis.Redis): Redis client
    Returns:
        dict: Success message
    """
    user_id = await get_current_user(request, redis_client)

    await enable_totp(db, user_id, user_otp_data)

    return {'message': '2fa enabled successfully'}


@auth_router.post(
    '/2fa/verify',
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter(times=5, seconds=60))],
)
async def verify_2fa(
    request: Request,
    user_otp_data: UserOtpModel,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """
    Args:
        request (Request): The request object
        user_otp_data (UserOtpModel): The user's OTP data
        db (AsyncSession): Database session
        redis_client (redis.Redis): Redis client
    Returns:
        dict: Success message
    """
    user_id, _, session_id = await get_current_user_id(request, redis_client)
    if not user_id:
        if not session_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='Session expired'
            )

    await login_with_totp(db, redis_client, session_id, user_id, user_otp_data)

    return {'message': 'Successfully verified with 2fa'}


async def get_current_user(
    request: Request,
    redis_client: redis.Redis,
) -> UUID:
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

    return UUID(user_id)


async def get_current_user_id(request: Request, redis_client: redis.Redis):
    """
    Args:
        request (Request): The request object
        redis_client (redis.Redis): Redis client
    Returns:
        tuple[str, dict, str]: user_id, user_data, session_id
    """
    session_id = request.cookies.get('session_id')
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
