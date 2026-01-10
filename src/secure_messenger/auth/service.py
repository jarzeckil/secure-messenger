from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from secure_messenger.auth.schemas import UserCreateModel
from secure_messenger.core import security
from secure_messenger.db.models import User


async def register_user(db: AsyncSession, user_data: UserCreateModel) -> User:
    username = user_data.username
    password = user_data.password

    # check if username exists
    result = await db.execute(select(User).where(User.username == username))
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
