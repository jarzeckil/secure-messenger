from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi_limiter import FastAPILimiter
from src.secure_messenger.auth.router import auth_router
from src.secure_messenger.core.config import settings
from src.secure_messenger.db.init_db import init_db

from secure_messenger.db.database import engine
from secure_messenger.db.redis_client import client as redis_client
from secure_messenger.messages.router import messages_router


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

# Mount static files
app.mount(
    '/static', StaticFiles(directory='src/secure_messenger/static'), name='static'
)

# Setup templates
templates = Jinja2Templates(directory='src/secure_messenger/templates')

app.include_router(auth_router)
app.include_router(messages_router)


@app.get('/health')
async def health_check():
    return {'status': 'ok', 'service': 'Secure Messenger'}


# Frontend Routes
@app.get('/', response_class=HTMLResponse)
async def root(request: Request):
    """Redirect root to auth page"""
    return templates.TemplateResponse('auth.html', {'request': request})


@app.get('/auth', response_class=HTMLResponse)
async def auth_page(request: Request):
    """Serve authentication page"""
    return templates.TemplateResponse('auth.html', {'request': request})


@app.get('/inbox', response_class=HTMLResponse)
async def inbox_page(request: Request):
    """Serve inbox page"""
    return templates.TemplateResponse('inbox.html', {'request': request})
