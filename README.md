# Secure Messenger 🔒

[![CI Pipeline](https://github.com/jarzeckil/secure-messenger/actions/workflows/ci.yaml/badge.svg)](https://github.com/jarzeckil/secure-messenger/actions/workflows/ci.yaml)

![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-009688.svg?logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![Nginx](https://img.shields.io/badge/Nginx-009639?logo=nginx&logoColor=white&)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?&logo=redis&logoColor=white)

A secure, SSE messaging web application built with a **Zero Trust** mindset.
This project implements a **Split Knowledge Architecture**, ensuring that the server never persistently stores unencrypted user private keys.

| Dashboard & Encryption | 2FA Configuration | Secure Verification |
|:---:|:---:|:---:|
| <img height="400" alt="ui" src="https://github.com/user-attachments/assets/092fe8d8-2ed2-41b4-bab1-ba137eefa341" /> | <img height="400" alt="2fa_act" src="https://github.com/user-attachments/assets/891e20b8-e160-40ae-8809-eb9fb2e2d751" /> | <img height="400" alt="verif3" src="https://github.com/user-attachments/assets/05d19407-f934-4c1a-be03-bfe6e2c677fc" />|

---

## 🖥️ It's live
Check out the app by yourself: [deployed via Azure](https://securemessenger.germanywestcentral.cloudapp.azure.com)

---

## 🚀 Key Features

### 🛡️ Advanced Security Architecture
* **Split Knowledge Session Management**:
    * User's RSA private key is stored in Redis **encrypted** with an ephemeral AES key.
    * The decryption key is sent to the client as a `HttpOnly` cookie and never stored in the database.
    * **Result:** Even if the Redis instance is compromised, attacker cannot access user keys without the client's cookie.
* **Cryptographic Agility**:
    * **Confidentiality:** AES-256-GCM for message content (Encryption + Integrity Tag).
    * **Non-Repudiation:** RSA-PSS (2048-bit) digital signatures for every message.
    * **Password Security:** Argon2id hashing with unique per-user salts.
* **Defense in Depth**:
    * **2FA:** Time-based One-Time Password (TOTP) implementation compatible with Google Authenticator.
    * **Throttling:** Rate limiting on auth endpoints (Redis-backed) to prevent Brute-Force attacks.
    * **Sanitization:** XSS prevention using `nh3` (Rust-based HTML sanitizer).
* **Holistic Digital Signatures (RSA-PSS):**
    * Every message is signed using **RSA-PSS** (Probabilistic Signature Scheme), providing stronger security guarantees than legacy PKCS#1 v1.5.
    * **Tamper-Proof Scope:** The signature calculation includes the encrypted message content **AND** the SHA-256 hashes of all encrypted attachments.
    * **Verification:** This ensures full integrity and non-repudiation—modifying a single byte of the text or swapping an attachment will cause the signature verification to fail immediately.
* **Cryptographically Bound Attachments:**
    * Attachments are treated with the same Zero Trust policy as text messages.
    * **Encryption:** Each file is encrypted individually using AES-256-GCM with a unique ephemeral key.
    * **Integrity Binding:** By including attachment hashes in the sender's RSA signature, the system strictly binds files to their parent message, preventing malicious attachment swapping or injection attacks.

### 🏗️ Technical Highlights
* **Asynchronous Core:** Fully async stack using `FastAPI`, `SQLAlchemy 2.0 (Async)`, and `asyncpg`.
* **Containerization:** Full Docker Compose setup with Nginx (Reverse Proxy with TLS), PostgreSQL, Redis, and the App container.
* **Type Safety:** Strict typing with Python 3.11+ type hints and Pydantic v2 models.
* **Testing:** Unit and integration tests using `pytest`.

---

## 🛠️ Tech Stack

| Component | Technology | Usage |
|-----------|------------|-------|
| **Backend** | Python 3.11, **FastAPI** | High-performance async REST API |
| **Database** | **PostgreSQL** 15 | Relational storage (storing encrypted blobs only) |
| **ORM** | **SQLAlchemy 2.0** | Async database interaction |
| **Cache/Session** | **Redis** 7 | Session storage & Rate limiting |
| **Cryptography** | **PyCryptodome** | Low-level crypto primitives (AES-GCM, RSA) |
| **Security** | **Passlib (Argon2)**, **PyOTP** | Password hashing & 2FA |
| **Infrastructure** | **Docker Compose**, Nginx | Deployment & Reverse Proxy |
| **Frontend** | Jinja2, Bootstrap 5, Vanilla JS | Server-Side Rendering with dynamic interactions |

---

## 📐 Architecture Flow

### 1. The "Split Knowledge" Login Flow
Instead of keeping the private key in RAM or Disk, we share the responsibility:

1.  User logs in.
2.  Server generates a random **Session Encryption Key (SEK)**.
3.  Server encrypts User's RSA Private Key using **SEK**.
4.  Encrypted Blob is stored in **Redis**.
5.  **SEK** is sent to the user as a secure `session_key` cookie.
6.  *Server forgets the SEK.*

### 2. Message Decryption Flow
1.  Client sends request with `session_key` cookie.
2.  Server retrieves encrypted blob from Redis.
3.  Server temporarily decrypts RSA key in memory using the cookie's key.
4.  Server performs decryption of the message.
5.  **Memory is wiped** after the request (garbage collection).
6.  **Integrity Check:** The system verifies the RSA-PSS signature against the sender's public key to confirm the message and its attachments originated from the claimed sender and have not been altered.
---

## ⚡ Quick Start

### Prerequisites
* Docker & Docker Compose
* Make (optional, for convenience commands)

### Installation

1.  **Clone the repository**
    ```bash
    git clone [https://github.com/jarzeckil/secure-messenger.git](https://github.com/jarzeckil/secure-messenger.git)
    cd secure-messenger
    ```

2.  **Environment Setup**
    Create a `.env` file:
    ```ini
    POSTGRES_USER=postgres
    POSTGRES_PASSWORD=securepassword
    POSTGRES_DB=messenger
    ```

3. **Generate SSL certificate**
    ```
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout nginx/certs/nginx.key \
    -out nginx/certs/nginx.crt
   ```

3.  **Run with Docker**
    ```bash
    docker-compose up --build -d
    ```
    The application will be available at `https://localhost` (Self-signed certificate handled by Nginx).

### Development (Local)

To run tests or install dependencies locally:

```bash
# Install dependencies with Poetry
make install

# Run Tests
make test

# Linting & Formatting
make format

```
## 📂 Project Structure

```
    src/
    └── secure_messenger/
        ├── auth/           # Authentication, 2FA, Session Management (Split Knowledge)
        ├── core/           # Config, Low-level Security Primitives (AES/RSA helper functions)
        ├── db/             # Database models and connection logic
        ├── messages/       # Messaging logic (Send, Read, Attachments)
        ├── static/         # CSS/JS assets
        └── templates/      # Jinja2 HTML templates
```
