# Secure Messenger

[![CI Pipeline](https://github.com/jarzeckil/secure-messenger/actions/workflows/ci.yaml/badge.svg)](https://github.com/jarzeckil/secure-messenger/actions/workflows/ci.yaml)

[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)
![Python](https://img.shields.io/badge/python-3.1x-blue)
![pytest](https://img.shields.io/badge/py-test-blue?logo=pytest)
![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?logo=docker&logoColor=white)

End-to-end encrypted messaging application with server-side key management and cryptographic message verification.

## Key Features

- **Cryptographic Authentication**: RSA/ECC digital signatures verify message integrity and sender identity
- **AES-GCM Encryption**: Authenticated encryption for message content (confidentiality + tampering detection)
- **2FA with TOTP**: Time-based one-time passwords (compatible with Google Authenticator, Authy)
- **Multi-Recipient Support**: Single message, multiple encrypted copies (via message_recipients association table)
- **Brute-Force Protection**: Request throttling and Argon2 password hashing with random salts
- **Input Sanitization**: XSS prevention using `nh3` (Rust-based HTML sanitizer)
- **Zero Plaintext Storage**: Everything sensitive is encrypted before hitting PostgreSQL

## Architecture

```
┌─────────┐      HTTPS      ┌───────────┐      ┌────────────┐
│ Client  │ ◄──────────────► │   Nginx   │ ◄───►│  FastAPI   │
└─────────┘                  │  (TLS)    │      │  Backend   │
                             └───────────┘      └──────┬─────┘
                                                       │
                                                       ▼
                                                ┌──────────────┐
                                                │ PostgreSQL   │
                                                │ (Encrypted)  │
                                                └──────────────┘
```

**Server-Side Encryption Flow:**
1. User logs in → server decrypts private key in RAM using password-derived key
2. Performs crypto operation (sign/decrypt)
3. Wipes key from memory
4. Password is **never** stored in plaintext on disk

## Tech Stack

| Component         | Technology                      |
|-------------------|---------------------------------|
| Backend           | Python 3.11+, FastAPI           |
| Database          | PostgreSQL + SQLAlchemy         |
| Crypto            | PyCryptodome (AES-GCM, RSA/ECC) |
| Password Hashing  | Passlib (Argon2)                |
| Password Strength | zxcvbn-python                   |
| 2FA               | PyOTP (TOTP)                    |
| Sanitization      | nh3 (Rust-backed)               |
| Frontend          | HTML + Jinja2 + Bootstrap 5     |
| Deployment        | Docker Compose                  |

## Database Schema

**Core Design:** Message entity + recipient association table for multi-recipient support.

```
users
├── id, username, password_hash
├── totp_secret, salt

user_keys
├── user_id (FK)
├── public_key
└── encrypted_private_key  ← Encrypted with user password

messages
├── id, sender_id (FK)
├── content_encrypted      ← AES-GCM encrypted content
├── signature              ← RSA/ECC signature for verification
└── created_at

message_recipients         ← Association table
├── message_id (FK)
├── recipient_id (FK)
└── is_read                ← Per-recipient status

attachments
├── id, message_id (FK)
└── file_data_encrypted
```

## Security Principles

### Defense in Depth
- **Transport Layer**: TLS/SSL termination at Nginx
- **Application Layer**: Input validation (Pydantic), output sanitization (nh3)
- **Data Layer**: Encrypted blobs only, no plaintext secrets

### Zero Trust Input
All user input is treated as hostile:
- Type validation via Pydantic schemas
- HTML sanitization with `nh3` (prevents XSS)
- Password entropy checking with `zxcvbn`

### Cryptographic Guarantees
- **Confidentiality**: AES-GCM symmetric encryption
- **Integrity**: GCM authentication tag + RSA/ECC signatures
- **Non-repudiation**: Digital signatures prove message origin (within system trust boundary)

## Quick Start

```bash
# Clone and start
git clone git@github.com:jarzeckil/secure-messenger.git
cd secure-messenger
docker-compose up --build

# Access at https://localhost
```

## Development Setup

```bash
# Install dependencies
make install

# Run tests
make test
```

## Project Status

Project in development
