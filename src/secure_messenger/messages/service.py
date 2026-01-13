from collections.abc import Sequence
import logging

from fastapi import HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from secure_messenger.auth.dependencies import CurrentUser
from secure_messenger.core import security
from secure_messenger.db.models import Message, MessageRecipient, User
from secure_messenger.messages.schemas import SendMessageModel, ShowMessageModel

logger = logging.getLogger(__name__)


async def send_message(
    db: AsyncSession, current_user: CurrentUser, message_data: SendMessageModel
) -> list[str]:
    logger.info(f'Sending message from {current_user.user_id}')

    recipient_usernames = set(message_data.recipients)
    query = select(User).where(User.username.in_(recipient_usernames))
    result = await db.execute(query)
    found_recipients: Sequence[User] = result.scalars().all()
    found_recipient_usernames = {recipient.username for recipient in found_recipients}

    missing_users = list(recipient_usernames - found_recipient_usernames)

    if missing_users:
        logger.warning(f'Users do not exist: {missing_users}')
    if not found_recipients:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail='Users do not exist'
        )

    text_message = message_data.text_message
    aes_key = security.generate_random_aes_key()
    encrypted_text_message = security.encrypt_content(text_message.encode(), aes_key)
    signature = security.generate_signature(
        encrypted_text_message, current_user.private_key
    )
    try:
        new_message = Message(
            sender_id=current_user.user_id,
            content_encrypted=encrypted_text_message,
            signature=signature,
        )
        db.add(new_message)
        await db.flush()

        for recipient in found_recipients:
            encrypted_aes_key = security.encrypt_aes_key(aes_key, recipient.public_key)

            new_message_recipient = MessageRecipient(
                message_id=new_message.id,
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
        .options(joinedload(MessageRecipient.message).joinedload(Message.sender))
        .where(MessageRecipient.recipient_id == current_user.user_id)
        .order_by(desc(MessageRecipient.created_at))
        .offset(skip)
        .limit(limit)
    )

    result = await db.execute(query)
    recipients: Sequence[MessageRecipient] = result.scalars().all()

    messages_response = []

    for recipient in recipients:
        try:
            aes_key = security.decrypt_aes_key(
                recipient.encrypted_message_key, current_user.private_key
            )
            decrypted_content = security.decrypt_content(
                recipient.message.content_encrypted, aes_key
            )
            messages_response.append(
                ShowMessageModel(
                    id=recipient.message.id,
                    sender_username=recipient.message.sender.username,
                    text_content=decrypted_content.decode(),
                    is_read=recipient.is_read,
                    timestamp=recipient.message.created_at,
                )
            )
        except (ValueError, TypeError, UnicodeDecodeError) as e:
            logger.error(f'Error decrypting message {recipient.message.id}: {e}')

            messages_response.append(
                ShowMessageModel(
                    id=recipient.message.id,
                    sender_username=recipient.message.sender.username,
                    text_content='[Błąd deszyfrowania wiadomości]',
                    is_read=recipient.is_read,
                    timestamp=recipient.message.created_at,
                )
            )

    return messages_response
