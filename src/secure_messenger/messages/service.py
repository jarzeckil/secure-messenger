from collections.abc import Sequence
import logging
import uuid

from fastapi import HTTPException, UploadFile, status
from sqlalchemy import delete, desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from secure_messenger.auth.dependencies import CurrentUser
from secure_messenger.core import security
from secure_messenger.core.config import settings
from secure_messenger.db.models import Attachment, Message, MessageRecipient, User
from secure_messenger.messages.schemas import (
    AttachmentInfoModel,
    MessageIDModel,
    SendMessageModel,
    ShowMessageModel,
)

logger = logging.getLogger(__name__)


async def send_message(
    db: AsyncSession,
    current_user: CurrentUser,
    message_data: SendMessageModel,
    files: list[UploadFile],
) -> list[str]:
    if len(files) > 5:
        raise HTTPException(status_code=400, detail='Max file count: 5')

    logger.info(f'Sending message from {current_user.user_id}')

    try:
        # check for missing users
        recipient_usernames = set(message_data.recipients)
        query = select(User).where(User.username.in_(recipient_usernames))
        result = await db.execute(query)
        found_recipients: Sequence[User] = result.scalars().all()
        found_recipient_usernames = {
            recipient.username for recipient in found_recipients
        }

        missing_users = list(recipient_usernames - found_recipient_usernames)

        if missing_users:
            logger.warning(f'Users do not exist: {missing_users}')
        if not found_recipients:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail='Users do not exist'
            )

        # generate message constants
        message_id = uuid.uuid4()
        aes_key = security.generate_random_aes_key()
        signature_content = []

        # create attachments
        for file in files:
            if file.size > settings.MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail='Max file size: 10 MB',
                )
            content = await file.read()
            content_encrypted = security.encrypt_content(content, aes_key)
            content_hash = security.get_content_hash(content_encrypted)
            new_attachment = Attachment(
                message_id=message_id,
                data_encrypted=content_encrypted,
                encrypted_data_hash=content_hash,
                filename=file.filename,
                content_type=file.content_type,
                size=len(content),
            )
            db.add(new_attachment)

            # add attachment content to signature data
            signature_content.append(content_hash)

        # encrypt text message and add it to signature data
        text_message = message_data.text_message
        encrypted_text_message = security.encrypt_content(
            text_message.encode(), aes_key
        )
        signature_content.append(encrypted_text_message)

        # create signature
        signature_blob = b''.join(sorted(signature_content))
        signature = security.generate_signature(
            signature_blob, current_user.private_key
        )

        # create message object
        new_message = Message(
            id=message_id,
            sender_id=current_user.user_id,
            content_encrypted=encrypted_text_message,
            signature=signature,
        )
        db.add(new_message)

        # create recipients
        for recipient in found_recipients:
            encrypted_aes_key = security.encrypt_aes_key(aes_key, recipient.public_key)

            new_message_recipient = MessageRecipient(
                message_id=message_id,
                recipient_id=recipient.id,
                encrypted_message_key=encrypted_aes_key,
            )
            db.add(new_message_recipient)

        await db.commit()
        logger.info(f'Message {new_message.id} saved')

    except Exception as e:
        await db.rollback()
        raise e

    return missing_users


async def get_user_messages(
    db: AsyncSession, current_user: CurrentUser, skip: int, limit: int
) -> list[ShowMessageModel]:
    query = (
        select(MessageRecipient)
        .options(
            joinedload(MessageRecipient.message).joinedload(Message.sender),
            joinedload(MessageRecipient.message).joinedload(Message.attachments),
        )
        .where(MessageRecipient.recipient_id == current_user.user_id)
        .order_by(desc(MessageRecipient.created_at))
        .offset(skip)
        .limit(limit)
    )

    result = await db.execute(query)
    recipients: Sequence[MessageRecipient] = result.scalars().unique().all()

    messages_response = []

    for recipient in recipients:
        try:
            aes_key = security.decrypt_aes_key(
                recipient.encrypted_message_key, current_user.private_key
            )
            decrypted_content = security.decrypt_content(
                recipient.message.content_encrypted, aes_key
            )
            attachments = []
            for attachment in recipient.message.attachments:
                attachments.append(
                    AttachmentInfoModel(
                        id=attachment.id,
                        filename=attachment.filename,
                        content_type=attachment.content_type,
                        size=attachment.size,
                    )
                )

            messages_response.append(
                ShowMessageModel(
                    message_id=recipient.message.id,
                    sender_username=recipient.message.sender.username,
                    text_content=decrypted_content.decode(),
                    is_read=recipient.is_read,
                    timestamp=recipient.message.created_at,
                    attachments=attachments,
                )
            )
        except (ValueError, TypeError, UnicodeDecodeError) as e:
            logger.error(f'Error decrypting message {recipient.message.id}: {e}')

            messages_response.append(
                ShowMessageModel(
                    message_id=recipient.message.id,
                    sender_username=recipient.message.sender.username,
                    text_content='[Błąd deszyfrowania wiadomości]',
                    is_read=recipient.is_read,
                    timestamp=recipient.message.created_at,
                )
            )

    return messages_response


async def delete_message(
    db: AsyncSession, current_user: CurrentUser, del_message: MessageIDModel
):
    query = delete(MessageRecipient).where(
        MessageRecipient.message_id == del_message.message_id,
        MessageRecipient.recipient_id == current_user.user_id,
    )
    result = await db.execute(query)

    if result.rowcount == 0:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message with this ID does not exist in user's inbox",
        )
    try:
        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.warning(e)
        raise e


async def verify_message(
    db: AsyncSession, current_user: CurrentUser, verif_message: MessageIDModel
):
    query = (
        select(MessageRecipient)
        .options(
            joinedload(MessageRecipient.message).joinedload(Message.sender),
            joinedload(MessageRecipient.message).joinedload(Message.attachments),
        )
        .where(
            MessageRecipient.recipient_id == current_user.user_id,
            MessageRecipient.message_id == verif_message.message_id,
        )
    )
    result = await db.execute(query)
    recipient: MessageRecipient = result.scalar()

    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail='Message not found'
        )

    signature_content = [recipient.message.content_encrypted]

    for attachment in recipient.message.attachments:
        signature_content.append(attachment.encrypted_data_hash)
    signature_blob = b''.join(sorted(signature_content))

    try:
        security.verify_signature(
            signature_blob,
            recipient.message.sender.public_key,
            recipient.message.signature,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Message authenticity could not be verified',
        ) from e
