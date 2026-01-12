from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi_limiter import FastAPILimiter
from src.secure_messenger.auth.router import auth_router
from src.secure_messenger.core.config import settings
from src.secure_messenger.db.init_db import init_db

from secure_messenger.db.database import engine
from secure_messenger.db.redis_client import client as redis_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    # initialize tables if they don't exist
    await init_db()

    await FastAPILimiter.init(redis_client)

    yield

    # app closes
    engine.dispose()
    redis_client.close()


app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)
app.include_router(auth_router)


@app.get('/health')
async def health_check():
    return {'status': 'ok', 'service': 'Secure Messenger'}
