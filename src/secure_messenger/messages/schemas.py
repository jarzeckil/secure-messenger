from datetime import datetime
from uuid import UUID

import nh3
from pydantic import BaseModel, Field, field_validator


class SendMessageModel(BaseModel):
    recipients: list[str] = Field(description='List of recipient usernames')
    text_message: str = Field(description='Text message', min_length=1)

    @field_validator('text_message')
    @classmethod
    def sanitize_message(cls, text_message: str):
        return nh3.clean(text_message)


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
