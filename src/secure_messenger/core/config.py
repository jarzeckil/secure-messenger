from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = 'Secure Messenger'

    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    DATABASE_URL: str = ''

    SECRET_KEY: str

    REDIS_HOST: str = 'redis'

    class Config:
        env_file = '.env'
        case_sensitive = True


settings = Settings()

settings.DATABASE_URL = f'postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@postgres-db:5432/{settings.POSTGRES_DB}'
