from datetime import datetime
import uuid

from sqlalchemy import (
    UUID,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    func,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    deferred,
    mapped_column,
    relationship,
)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(), nullable=False)
    totp_secret: Mapped[str | None] = mapped_column(String(), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean(), default=False)

    public_key: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    salt: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    sent_messages: Mapped[list['Message']] = relationship(back_populates='sender')

    received_messages: Mapped[list['MessageRecipient']] = relationship(
        back_populates='recipient'
    )


class Message(Base):
    __tablename__ = 'messages'

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sender_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey('users.id'), index=True, nullable=False
    )
    content_encrypted: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    signature: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    recipients: Mapped[list['MessageRecipient']] = relationship(
        back_populates='message', cascade='all, delete-orphan'
    )

    sender: Mapped['User'] = relationship(back_populates='sent_messages')
    attachments: Mapped[list['Attachment']] = relationship(
        back_populates='message', cascade='all, delete-orphan'
    )


class MessageRecipient(Base):
    __tablename__ = 'message_recipients'

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    message_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey('messages.id'), nullable=False
    )
    recipient_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id'), index=True)

    encrypted_message_key: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)

    is_read: Mapped[bool] = mapped_column(Boolean(), default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    message: Mapped['Message'] = relationship(back_populates='recipients')
    recipient: Mapped['User'] = relationship(back_populates='received_messages')


class Attachment(Base):
    __tablename__ = 'attachments'

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    message_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey('messages.id'), nullable=False
    )
    data_encrypted: Mapped[bytes] = deferred(
        mapped_column(LargeBinary(), nullable=False)
    )
    encrypted_data_hash: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)

    filename: Mapped[str] = mapped_column(String, nullable=False)
    content_type: Mapped[str] = mapped_column(String, nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)

    message: Mapped['Message'] = relationship(back_populates='attachments')

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
