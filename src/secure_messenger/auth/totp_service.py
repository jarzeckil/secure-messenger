import base64
import io
import json
from uuid import UUID

from fastapi import HTTPException, status
import pyotp
import qrcode
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession

from secure_messenger.auth.schemas import UserOtpModel, UserPasswordModel
from secure_messenger.core import security
from secure_messenger.core.config import settings
from secure_messenger.db.models import User


async def generate_totp_secret(
    db: AsyncSession, user_id: UUID, user_password_data: UserPasswordModel
) -> tuple[str, str]:
    """
    Args:
        db (AsyncSession): Database session
        user_id (UUID): User ID
        user_password_data (UserPasswordModel): User password data
    Returns:
        tuple[str, str]: TOTP secret and QR code base64
    """
    # verify password
    user: User = await db.get(User, user_id)
    user_password = user.password_hash
    if not security.verify_password(user_password_data.password, user_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect password.',
        )

    # create and save totp secret
    totp_secret = pyotp.random_base32()
    user.totp_secret = totp_secret

    await db.commit()

    qr = generate_totp_qr_code(totp_secret, user)

    return totp_secret, qr


async def enable_totp(db: AsyncSession, user_id: UUID, user_otp_data: UserOtpModel):
    """
    Args:
        db (AsyncSession): Database session
        user_id (UUID): User ID
        user_otp_data (UserOtpModel): User OTP data
    """
    user: User = await verify_totp(db, user_id, user_otp_data)

    user.totp_enabled = True
    await db.commit()


async def login_with_totp(
    db: AsyncSession,
    client: redis.Redis,
    session_id: UUID,
    user_id: UUID,
    user_otp_data: UserOtpModel,
):
    """
    Args:
        db (AsyncSession): Database session
        client (redis.Redis): Redis client
        session_id (UUID): Session ID
        user_id (UUID): User ID
        user_otp_data (UserOtpModel): User OTP data
    """
    await verify_totp(db, user_id, user_otp_data)

    raw_session_data = await client.get(f'session:{session_id}')
    session_data = json.loads(raw_session_data)

    del session_data['pending_2fa']

    await client.set(
        name=f'session:{session_id}',
        value=json.dumps(session_data),
        xx=True,  # only set if the session exists
        keepttl=True,
    )


async def verify_totp(
    db: AsyncSession, user_id: UUID, user_otp_data: UserOtpModel
) -> User:
    """
    Args:
        db (AsyncSession): Database session
        user_id (UUID): User ID
        user_otp_data (UserOtpModel): User OTP data
    Returns:
        User: User object
    """
    user: User = await db.get(User, user_id)
    otp_code = user_otp_data.code

    if user.totp_secret is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail='User has not enabled 2FA'
        )

    totp = pyotp.TOTP(user.totp_secret)

    if not totp.verify(otp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='2FA code is invalid.',
        )

    return user


def generate_totp_qr_code(totp_secret: str, user: User) -> str:
    """
    Args:
        totp_secret (str): TOTP secret
        user (User): User object
    Returns:
        str: QR code base64
    """
    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name=settings.PROJECT_NAME)

    qr = qrcode.make(data=uri)
    buffered = io.BytesIO()
    qr.save(buffered, format='PNG')
    qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

    return qr_base64
