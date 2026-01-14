import logging

from pydantic_settings import BaseSettings

logging.basicConfig(level=logging.INFO)


class Settings(BaseSettings):
    PROJECT_NAME: str = 'Secure Messenger'

    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    DATABASE_URL: str = ''

    SECRET_KEY: str

    REDIS_HOST: str = 'redis'
    REDIS_PORT: int = 6379

    MAX_SESSION_AGE: int = 3600

    MAX_FILE_SIZE: int = 10 * 1024 * 1024

    class Config:
        env_file = '.env'
        case_sensitive = True


settings = Settings()

settings.DATABASE_URL = f'postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@postgres-db:5432/{settings.POSTGRES_DB}'
