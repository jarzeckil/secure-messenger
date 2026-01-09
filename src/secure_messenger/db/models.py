from datetime import datetime
import uuid

from sqlalchemy import UUID, Boolean, DateTime, ForeignKey, LargeBinary, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(32), unique=True)
    password_hash: Mapped[str] = mapped_column(String())
    totp_secret: Mapped[str | None] = mapped_column(String(), nullable=True)
    salt: Mapped[bytes] = mapped_column(LargeBinary())

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    user_key: Mapped['UserKey'] = relationship(
        back_populates='user', cascade='all, delete-orphan'
    )

    sent_messages: Mapped[list['Message']] = relationship(back_populates='sender')

    received_messages: Mapped[list['MessageRecipient']] = relationship(
        back_populates='recipient'
    )


class UserKey(Base):
    __tablename__ = 'user_keys'

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id'), primary_key=True)
    public_key: Mapped[str] = mapped_column(String())
    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary())

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    user: Mapped['User'] = relationship(back_populates='user_key')


class Message(Base):
    __tablename__ = 'messages'

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sender_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id'), index=True)
    content_encrypted: Mapped[bytes] = mapped_column(LargeBinary())
    signature: Mapped[bytes] = mapped_column(LargeBinary())

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
    message_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('messages.id'))
    recipient_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id'), index=True)
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
    message_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('messages.id'))
    data_encrypted: Mapped[bytes] = mapped_column(LargeBinary())

    message: Mapped['Message'] = relationship(back_populates='attachments')
