import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession

from secure_messenger.auth.schemas import UserLoginModel, UserRegisterModel
from secure_messenger.auth.service import login_user, register_user
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


@auth_router.post('/login', status_code=status.HTTP_200_OK)
async def login(
    response: Response,
    user_login_data: UserLoginModel,
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
):
    """Login endpoint."""
    session_id = await login_user(db, redis_client, user_login_data)

    response.set_cookie(
        key='session_id',
        value=f'{session_id}',
        httponly=True,
        secure=True,
        samesite='lax',
        max_age=settings.MAX_SESSION_AGE,
    )

    return {'message': 'Logged-in successfully'}


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


async def get_current_user(
    request: Request, redis_client: redis.Redis = Depends(get_redis)
) -> UUID:
    """Dependency to get the current authenticated user."""
    session_id = request.cookies.get('session_id')
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Not authenticated'
        )

    user_data = await redis_client.get(f'session:{session_id}')
    user_id = json.load(user_data).get('user_id')

    if not user_id:
        if not session_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='Session expired'
            )

    return UUID(user_id)
