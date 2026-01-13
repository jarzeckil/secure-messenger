from pydantic import BaseModel, Field


class SendMessageModel(BaseModel):
    recipients: list[str] = Field(description='List of recipient usernames')
    text_message: str = Field(description='Text message', min_length=1)
