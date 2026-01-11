import json
from unittest.mock import AsyncMock
import uuid

import pytest

from secure_messenger.db.redis_client import get_redis
from secure_messenger.main import app


# Define mock_redis fixture here to be used by the override
@pytest.fixture
def mock_redis():
    mock = AsyncMock()
    # Setup default behaviors if needed
    return mock


@pytest.fixture
async def client_with_redis(client, mock_redis):
    async def override_get_redis():
        yield mock_redis

    app.dependency_overrides[get_redis] = override_get_redis
    yield client
    app.dependency_overrides.pop(get_redis, None)


@pytest.mark.asyncio
async def test_register_endpoint(client_with_redis):
    response = await client_with_redis.post(
        '/register',
        json={'username': 'routeruser', 'password': 'supersecretpassword123'},
    )
    assert response.status_code == 201
    data = response.json()
    assert data['username'] == 'routeruser'
    assert 'id' in data


@pytest.mark.asyncio
async def test_login_endpoint(client_with_redis, mock_redis):
    # Register first
    await client_with_redis.post(
        '/register',
        json={'username': 'loginuser', 'password': 'supersecretpassword123'},
    )

    # Login
    response = await client_with_redis.post(
        '/login',
        json={'username': 'loginuser', 'password': 'supersecretpassword123'},
    )
    assert response.status_code == 200
    assert 'session_id' in response.cookies

    # Verify redis was called to store session
    mock_redis.set.assert_called_once()

    # Check calling args to ensure session storage format
    call_args = mock_redis.set.call_args
    assert call_args is not None
    _, kwargs = call_args
    assert 'name' in kwargs and kwargs['name'].startswith('session:')
    assert 'value' in kwargs
    stored_data = json.loads(kwargs['value'])
    assert stored_data['username'] == 'loginuser'


@pytest.mark.asyncio
async def test_login_endpoint_invalid_credentials(client_with_redis, mock_redis):
    response = await client_with_redis.post(
        '/login',
        json={'username': 'nonexistent', 'password': 'password'},
    )
    assert response.status_code == 401
    mock_redis.set.assert_not_called()


@pytest.mark.asyncio
async def test_logout_endpoint(client_with_redis, mock_redis):
    # Create a fake session
    session_id = str(uuid.uuid4())
    client_with_redis.cookies.set('session_id', session_id)

    response = await client_with_redis.post('/logout')

    assert response.status_code == 200
    assert 'session_id' not in response.cookies or response.cookies['session_id'] == ''

    # Verify redis delete was called
    mock_redis.delete.assert_called_with(f'session:{session_id}')
