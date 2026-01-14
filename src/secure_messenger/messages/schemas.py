from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class SendMessageModel(BaseModel):
    recipients: list[str] = Field(description='List of recipient usernames')
    text_message: str = Field(description='Text message', min_length=1)


class AttachmentInfoModel(BaseModel):
    id: UUID
    filename: str
    content_type: str
    size: int


class ShowMessageModel(BaseModel):
    message_id: UUID
    sender_username: str
    text_content: str
    is_read: bool
    timestamp: datetime

    attachments: list[AttachmentInfoModel] = []


class MessageIDModel(BaseModel):
    message_id: UUID
