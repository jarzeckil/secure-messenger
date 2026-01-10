from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from secure_messenger.auth.schemas import UserLoginModel, UserRegisterModel
from secure_messenger.core import security
from secure_messenger.db.models import User


async def register_user(db: AsyncSession, user_data: UserRegisterModel) -> User:
    username = user_data.username
    password = user_data.password

    # check if username exists
    query = select(User).where(User.username == username)
    result = await db.execute(query)
    if result.scalar():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='User with this username already exists',
        )

    public_key, private_key = security.generate_rsa_key_pair()

    salt = security.generate_random_salt()

    new_user = User(
        username=username,
        password_hash=security.get_password_hash(password),
        public_key=public_key,
        encrypted_private_key=security.encrypt_private_key(private_key, password, salt),
        salt=salt,
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return new_user


async def login_user(db: AsyncSession, user_login_data: UserLoginModel) -> UUID:
    username = user_login_data.username
    password = user_login_data.password
    verified = False

    # search for user
    query = select(User).where(User.username == username)
    result = await db.execute(query)
    user: User = result.scalar()
    if user:
        # verify password
        verified = security.verify_password(password, user.password_hash)

    if not user or not verified:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail='Wrong username or password.'
        )

    # TODO return user object
