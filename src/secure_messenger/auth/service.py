import json
import logging
import uuid
from uuid import UUID

from fastapi import HTTPException, status
import redis.asyncio as redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from secure_messenger.auth.schemas import (
    UserLoginModel,
    UserRegisterModel,
)
from secure_messenger.core import security
from secure_messenger.core.config import settings
from secure_messenger.db.models import User

logger = logging.getLogger(__name__)


async def register_user(db: AsyncSession, user_data: UserRegisterModel) -> User:
    """Registers a new user in the database."""
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


async def login_user(
    db: AsyncSession, client: redis.Redis, user_login_data: UserLoginModel
) -> tuple[UUID, bool]:
    """Authenticates a user and creates a session."""
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
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Wrong username or password.',
        )
    private_key_encrypted = user.encrypted_private_key
    private_key_pem = security.decrypt_private_key(
        private_key_encrypted, password, user.salt
    )

    session_id = await create_user_session(
        client, user.id, user.username, private_key_pem, user.totp_enabled
    )

    return session_id, user.totp_enabled


async def create_user_session(
    client: redis.Redis,
    user_id: UUID,
    username: str,
    private_key_pem: bytes,
    user_2fa: bool,
):
    """Creates a new session for the user in Redis."""
    session_id = uuid.uuid4()

    session_data = {
        'user_id': str(user_id),
        'username': username,
        'private_key': private_key_pem.decode(),
    }

    if user_2fa:
        session_data['pending_2fa'] = 'True'

    await client.set(
        name=f'session:{session_id}',
        value=json.dumps(session_data),
        ex=settings.MAX_SESSION_AGE,
    )
    logger.info(f'Created session {session_id} for user {user_id} ({username})')

    return session_id
