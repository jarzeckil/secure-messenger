from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from secure_messenger.auth.schemas import UserLoginModel, UserRegisterModel
from secure_messenger.auth.service import login_user, register_user
from secure_messenger.db.database import get_db

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
async def login(user_login_data: UserLoginModel, db: AsyncSession = Depends(get_db)):
    await login_user(db, user_login_data)

    # TODO cookies

    return {'message': 'Logged-in successfully'}
