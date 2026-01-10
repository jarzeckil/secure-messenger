from fastapi import HTTPException
import pytest
from sqlalchemy import select

from secure_messenger.auth import service
from secure_messenger.auth.schemas import UserLoginModel, UserRegisterModel
from secure_messenger.db.models import User


@pytest.mark.asyncio
async def test_register_user_success(db_session):
    user_data = UserRegisterModel(
        username='testuser', password='fdvsmoitawjoijt23184789812374oadsf'
    )

    user = await service.register_user(db_session, user_data)

    assert user.username == 'testuser'
    assert user.password_hash is not None
    assert user.password_hash != 'testpassword'
    assert user.public_key is not None
    assert user.encrypted_private_key is not None
    assert user.salt is not None

    # Verify persistence
    result = await db_session.execute(select(User).where(User.username == 'testuser'))
    persisted_user = result.scalar()
    assert persisted_user is not None
    assert persisted_user.id == user.id


@pytest.mark.asyncio
async def test_register_user_duplicate(db_session):
    user_data = UserRegisterModel(
        username='duplicateuser', password='fdvsmoitawjoijt23184789812374oadsf'
    )
    await service.register_user(db_session, user_data)

    with pytest.raises(HTTPException) as excinfo:
        await service.register_user(db_session, user_data)

    assert excinfo.value.status_code == 400
    assert 'User with this username already exists' in excinfo.value.detail


@pytest.mark.asyncio
async def test_login_user_success(db_session):
    # Register first
    user_data = UserRegisterModel(
        username='loginuser', password='fdvsmoitawjoijt23184789812374oadsf'
    )
    await service.register_user(db_session, user_data)

    login_data = UserLoginModel(
        username='loginuser', password='fdvsmoitawjoijt23184789812374oadsf'
    )
    # Should not raise
    await service.login_user(db_session, login_data)


@pytest.mark.asyncio
async def test_login_user_wrong_password(db_session):
    user_data = UserRegisterModel(
        username='wrongpassuser', password='fdvsmoitawjoijt23184789812374oadsf'
    )
    await service.register_user(db_session, user_data)

    login_data = UserLoginModel(username='wrongpassuser', password='fake')

    with pytest.raises(HTTPException) as excinfo:
        await service.login_user(db_session, login_data)

    assert excinfo.value.status_code == 404
    assert 'Wrong username or password' in excinfo.value.detail


@pytest.mark.asyncio
async def test_login_user_not_found(db_session):
    login_data = UserLoginModel(username='nonexistent', password='password')

    with pytest.raises(HTTPException) as excinfo:
        await service.login_user(db_session, login_data)

    assert excinfo.value.status_code == 404
