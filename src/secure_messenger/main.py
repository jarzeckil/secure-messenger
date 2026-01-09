from fastapi import FastAPI
from src.secure_messenger.core.config import settings
import uvicorn

app = FastAPI(title=settings.PROJECT_NAME)


@app.get('/health')
async def health_check():
    return {'status': 'ok', 'service': 'Secure Messenger'}


if __name__ == '__main__':
    uvicorn.run('src.main:app', host='0.0.0.0', port=8000, reload=True)
