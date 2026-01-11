from fastapi import APIRouter, Depends, status
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
