from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class SendMessageModel(BaseModel):
    recipients: list[str] = Field(description='List of recipient usernames')
    text_message: str = Field(description='Text message', min_length=1)


class ShowMessageModel(BaseModel):
    id: UUID
    sender_username: str
    text_content: str
    is_read: bool
    timestamp: datetime
