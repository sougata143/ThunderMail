# ⚡ ThunderMail — Zero-Knowledge End-to-End Encrypted Webmail

[![Architecture](https://img.shields.io/badge/Architecture-Zero--Knowledge%20E2EE-7c3aed.svg)](https://github.com/sougata143/ThunderMail)
[![Cryptography](https://img.shields.io/badge/Crypto-RSA--4096%20%7C%20AES--GCM--256%20%7C%20PBKDF2-10b981.svg)](https://github.com/sougata143/ThunderMail)
[![Frontend](https://img.shields.io/badge/Frontend-React%2019%20%7C%20Vite%20%7C%20Tailwind-38bdf8.svg)](https://github.com/sougata143/ThunderMail)
[![Backend](https://img.shields.io/badge/Backend-Fastify%20%7C%20TypeScript%20%7C%20Prisma-6366f1.svg)](https://github.com/sougata143/ThunderMail)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%2016-336791.svg)](https://github.com/sougata143/ThunderMail)
[![Proxy](https://img.shields.io/badge/Proxy-Caddy%20v2%20Auto--TLS-00bcd4.svg)](https://github.com/sougata143/ThunderMail)

**ThunderMail** is a modern, production-grade webmail service built on a strict **Zero-Knowledge / Zero-Access** security model inspired by Tuta and Proton. All encryption, decryption, and key management operations occur entirely client-side inside the user's browser. The backend database stores only opaque encrypted ciphertext blobs, encrypted private keys, and public keys — ensuring that neither server operators, network eavesdroppers, nor compromised databases can read user emails.

---

## 📑 Table of Contents

- [Architectural Overview](#-architectural-overview)
- [Cryptographic Protocol Specification](#-cryptographic-protocol-specification)
- [Key Features](#-key-features)
- [📖 User Guide (Step-by-Step)](#-user-guide-step-by-step)
  - [1. Creating an Account & Key Generation](#1-creating-an-account--key-generation)
  - [2. Saving Your 24-Word Recovery Phrase](#2-saving-your-24-word-recovery-phrase)
  - [3. Unlocking Your Mailbox (Sign In)](#3-unlocking-your-mailbox-sign-in)
  - [4. Sending Zero-Knowledge Encrypted Emails](#4-sending-zero-knowledge-encrypted-emails)
  - [5. Reading Decrypted Mail & Raw Ciphertext Inspection](#5-reading-decrypted-mail--raw-ciphertext-inspection)
  - [6. Managing Folders & Search](#6-managing-folders--search)
  - [7. Exporting Keys & Backup](#7-exporting-keys--backup)
  - [8. Logging Out & RAM Key Sanitization](#8-logging-out--ram-key-sanitization)
- [Tech Stack](#-tech-stack)
- [Repository Structure](#-repository-structure)
- [Database Schema](#-database-schema)
- [API Endpoints](#-api-endpoints)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Option 1: Docker Compose (Production Stack)](#option-1-docker-compose-production-stack)
  - [Option 2: Local Development](#option-2-local-development)
- [Running Automated Tests](#-running-automated-tests)
- [Security & Invariants](#-security--invariants)
- [License](#-license)

---

## 🏛 Architectural Overview

```
 Browser (Client-Side Only)                ThunderMail Backend            PostgreSQL 16
┌──────────────────────────────┐        ┌─────────────────────────┐     ┌──────────────────────┐
│  PBKDF2-SHA256 (100k iter)   │        │ Fastify + TypeScript    │     │ users                │
│  AES-GCM-256 Message Cipher  │◄─JWT──►│ - POST /api/auth/salt   │◄───►│  email, auth_hash,   │
│  RSA-OAEP-4096 Keypair       │        │ - POST /api/auth/login  │     │  salt, public_key,   │
│  IndexedDB Key Bundle Cache  │        │ - POST /api/mail/send   │     │  encrypted_priv_key  │
│  Browser RAM Key Isolation   │        │ - GET  /api/keys/:email │     │                      │
└──────────────────────────────┘        │ - External SMTP Relay   │     │ mailbox_messages     │
               ▲                        └─────────────────────────┘     │  encrypted blobs     │
               │                                     ▲                  │  only (no plaintext) │
               └────────────── Caddy v2 ─────────────┘                  └──────────────────────┘
                          Auto-HTTPS / TLS
```

### Zero-Knowledge Guarantee
1. **Plaintext Isolation:** Message subjects, bodies, and attachments are encrypted with a random one-time symmetric session key (`AES-GCM-256`) before leaving the client browser.
2. **Key Wrapping:** The session key is wrapped using the recipient's asymmetric public key (`RSA-OAEP-4096`) and the sender's public key (`senderSessionKey` for Sent folder access).
3. **Zero-Access Storage:** PostgreSQL only records ciphertext strings and IVs. No plaintext search index or plaintext database column exists.
4. **RAM-Only Decryption:** The user's decrypted RSA private key exists strictly in browser memory (`SubtleCrypto` / React Context) during an active session and is never persisted unencrypted to `localStorage` or `IndexedDB`.

---

## 🔐 Cryptographic Protocol Specification

### 1. User Registration & Key Derivation
```
User Password + Salt (32-byte CSPRNG)
      │
      ├─► PBKDF2-SHA256 (100,000 iterations) ──► User Master Key (UMK, 256-bit AES-GCM)
      │                                                │
      │                                                ▼
      │                                   AES-GCM-256 Encrypt(UMK, RSA Private Key, IV)
      │                                                │
      │                                                ▼
      ├─► HMAC-SHA256(UMK, "auth-verification-token") ─► AuthHash (Verifier sent to server)
      │
      └─► Generate RSA-OAEP-4096 Keypair ─────────────► PublicKey (SPKI Base64 sent to server)
```

### 2. User Authentication & Session Unlock
1. Client requests salt via `POST /api/auth/salt` (returns deterministic dummy salt if email not found to prevent user enumeration).
2. Client computes `UMK = PBKDF2(password, salt)` and `AuthHash = HMAC-SHA256(UMK, "auth-verification-token")`.
3. Client authenticates with `POST /api/auth/login` using `AuthHash` and receives JWT + encrypted private key bundle.
4. Client decrypts the encrypted private key in RAM using the derived `UMK`.

### 3. Outgoing E2EE Email Transmission
1. Sender queries recipient's public key via `GET /api/keys/:recipientEmail`.
2. Sender generates a one-time random session key: `SessionKey = AES-GCM-256`.
3. Sender encrypts Subject and Body with `SessionKey` using random 96-bit initialization vectors (`subjectIv`, `bodyIv`).
4. `encryptedSessionKey = RSA-OAEP-Encrypt(RecipientPublicKey, SessionKey)`.
5. `senderSessionKey = RSA-OAEP-Encrypt(SenderPublicKey, SessionKey)` (enabling sender to read their Sent copy).
6. Ciphertext bundle is transmitted to `POST /api/mail/send`.

### 4. External Non-E2EE Relay & Inbound Processing
- **External Outbound (e.g. Gmail/Yahoo):** The client decrypts message content and submits through Nodemailer via authenticated SMTP relay over Port 587 (STARTTLS).
- **External Inbound:** When an unencrypted message arrives from an external source, the backend immediately encrypts the payload using the recipient user's stored public key and purges plaintext from memory.

---

## 📖 User Guide (Step-by-Step)

### 1. Creating an Account & Key Generation
1. Navigate to the application in your browser (`http://localhost:5173` or your hosted domain).
2. Click **Create Account** on the authentication card.
3. Enter your desired email address (e.g., `alice@thundermail.local`) and a strong master password.
4. Click **Generate Keys & Register**.
5. Your browser will locally generate a 32-byte salt, compute your **User Master Key (UMK)** with 100,000 iterations of PBKDF2-SHA256, create a 4096-bit RSA keypair, and encrypt the private key before sending the public credentials to the server.

### 2. Saving Your 24-Word Recovery Phrase
1. Immediately upon registration, a **Zero-Knowledge Recovery Phrase Modal** will appear displaying 24 randomized BIP-39 mnemonic words.
2. Click **Copy All Words** and write them down in a secure offline location (e.g., password manager, physical safe).
3. Check the confirmation box: *"I have safely saved my recovery phrase"*.
4. Click **Continue to Secure Mailbox**.
> ⚠️ **Important:** Because ThunderMail operates on zero-knowledge cryptography, server administrators cannot recover your account or read your emails if you forget your master password without your recovery key.

### 3. Unlocking Your Mailbox (Sign In)
1. On the **Sign In** tab, enter your registered email and master password.
2. Click **Unlock Encrypted Mailbox**.
3. The client fetches your salt, re-derives the UMK, verifies your `AuthHash` with the server, downloads your encrypted private key blob, and decrypts it into browser RAM.

### 4. Sending Zero-Knowledge Encrypted Emails
1. Click the **New Secure Mail** button in the left sidebar.
2. In the **Recipient email** field, type the destination address (e.g., `bob@thundermail.local`):
   - 🟢 **E2EE Active Badge:** If the recipient is registered on ThunderMail, a green badge appears confirming that the recipient's RSA-4096 public key was retrieved and the message will be end-to-end encrypted.
   - 🟡 **Standard TLS Relay Badge:** If the recipient is an external address (e.g. `user@gmail.com`), a yellow badge appears indicating standard TLS transit encryption.
3. Enter your **Subject** and **Message Body**.
4. Click **Encrypt & Send**. The message is encrypted locally with a fresh AES-256 session key, wrapped with the recipient's public key, and sent as ciphertext.

### 5. Reading Decrypted Mail & Raw Ciphertext Inspection
1. Click any email from the message list on the left.
2. A decryption spinner appears momentarily while your browser unwraps the session key using your private key in RAM and decrypts the AES-GCM ciphertext.
3. The message renders cleanly in the reading pane with timestamps and security badges.
4. Click the **Raw Ciphertext** button in the reading pane toolbar:
   - Inspect the actual base64-encoded `RSA-OAEP Encrypted Session Key`, `AES-GCM Encrypted Subject`, and `AES-GCM Encrypted Body`.
   - This provides complete transparency that only ciphertext is stored on the server.
   - Click **View Plaintext** to switch back to the rendered view.

### 6. Managing Folders & Search
- **Folder Navigation:** Use the left sidebar to switch between **Inbox**, **Sent**, **Drafts**, **Trash**, and **Spam**.
- **Sent Folder Security:** Messages in the Sent folder are encrypted with your `senderSessionKey`, allowing you to read sent messages without compromising zero-knowledge security.
- **Client-Side Search:** The top search bar searches your messages locally by sender, recipient, and metadata.
- **Mark Unread / Move to Trash / Delete:** Use the action buttons at the top of the reading pane to manage your inbox.

### 7. Exporting Keys & Backup
1. Click the **Key icon** in the bottom-left corner of the sidebar or navigate to **Settings**.
2. View your active **RSA-OAEP-4096 Public Key** in SPKI Base64 format.
3. Click **Copy Public Key** to share your public key with other secure contacts.
4. Click **Download Key Backup** to save a timestamped JSON backup file containing your public parameters.

### 8. Logging Out & RAM Key Sanitization
1. Click the **Logout icon** in the bottom-left sidebar.
2. Your JWT token is deleted, all decrypted `CryptoKey` instances are immediately wiped from browser memory, and the application locks the mailbox session.

---

## ✨ Key Features

- **Tuta / Proton-Inspired Dark UI:** Deep navy (`#050810`) aesthetic, electric violet accents, frosted glass panels with `backdrop-filter: blur(12px)`.
- **Live Client-Side Decryption:** Fast asynchronous decryption of mailbox envelopes and email bodies in browser memory.
- **Raw Ciphertext Transparency Toggle:** Dedicated toggle in the reading pane to inspect raw base64 AES-GCM/RSA-OAEP ciphertext payloads stored in PostgreSQL.
- **Recipient Public Key Detection:** Interactive status badge in the email composer (**Green E2EE Active** when public key is found vs. **Yellow Standard TLS Relay** for external recipients).
- **24-Word BIP-39 Recovery Phrase:** Seed generation upon registration allowing account recovery.
- **Key Backup & Export:** Export and download cryptographic key bundles in JSON/SPKI formats.
- **Storage Quota Indicator:** Live gauge displaying encrypted storage consumed against account limits.
- **Automated Zero-Knowledge Test Suite:** Vitest suite validating that zero plaintext is written to database records or returned in responses.

---

## 🛠 Tech Stack

| Layer | Technologies |
|---|---|
| **Frontend UI** | React 19, Vite, TypeScript, Tailwind CSS, Lucide React |
| **State & Data Fetching** | TanStack Query v5, Axios |
| **Client-Side Cryptography** | Web Crypto API (`SubtleCrypto` — RSA-OAEP-4096, AES-GCM-256, PBKDF2-SHA256, HMAC-SHA256), `idb` |
| **Backend Server** | Node.js 20+, Fastify, `@fastify/jwt`, `@fastify/rate-limit`, `@fastify/cors`, Zod |
| **Database & ORM** | PostgreSQL 16, Prisma ORM |
| **Mail Relay** | Nodemailer (SMTP Port 587 STARTTLS) |
| **Reverse Proxy & SSL** | Caddy v2 (Automatic HTTPS / Let's Encrypt ACME) |
| **Containerization** | Docker, Multi-stage Dockerfiles, Docker Compose |

---

## 📂 Repository Structure

```text
├── docker-compose.yml             # Full stack orchestration (Postgres, Backend, Frontend, Caddy)
├── Caddyfile                      # Reverse proxy & Auto-HTTPS rules
├── .env.example                   # Environment configuration template
├── README.md                      # Project documentation & User Guide
├── backend/
│   ├── prisma/
│   │   └── schema.prisma          # PostgreSQL schema (users, mailbox_messages)
│   ├── src/
│   │   ├── config/env.ts          # Zod-validated environment config
│   │   ├── middleware/
│   │   │   ├── auth.middleware.ts # JWT verification hook
│   │   │   └── rateLimit.middleware.ts # Anti-brute-force rate limiting
│   │   ├── routes/
│   │   │   ├── auth.routes.ts     # /salt, /register, /login
│   │   │   ├── keys.routes.ts     # /:email (public keys), /private (key rotation)
│   │   │   ├── mail.routes.ts     # Folder query, message detail, send, status, delete
│   │   │   └── user.routes.ts     # /me (profile & storage stats)
│   │   ├── services/
│   │   │   ├── crypto.service.ts  # Inbound mail public-key encryption
│   │   │   ├── mail.service.ts    # Database storage logic
│   │   │   └── smtpRelay.service.ts # External SMTP relaying (Port 587)
│   │   └── server.ts              # Fastify application bootstrap
│   ├── tests/
│   │   └── zeroKnowledge.test.ts  # Zero-knowledge invariant verification
│   ├── Dockerfile
│   ├── package.json
│   └── tsconfig.json
├── frontend/
│   ├── src/
│   │   ├── api/                   # Typed API client functions
│   │   ├── crypto/
│   │   │   ├── keyDerivation.ts   # PBKDF2 UMK and HMAC AuthHash derivation
│   │   │   ├── keyManagement.ts   # RSA-4096 keypair & AES-GCM wrapping
│   │   │   ├── messageCipher.ts   # One-time session key encryption/decryption
│   │   │   ├── storage.ts         # IndexedDB caching & BIP-39 recovery generator
│   │   │   └── __tests__/crypto.test.ts # Cryptographic unit tests
│   │   ├── hooks/
│   │   │   ├── useAuth.ts         # Authentication & key lifecycle
│   │   │   ├── useCrypto.tsx      # React Context isolating private keys in RAM
│   │   │   └── useMailbox.ts      # Mail queries, decryptors & mutations
│   │   ├── components/
│   │   │   ├── layout/            # Sidebar, Header, MailList, Reader, Composer
│   │   │   ├── ui/                # Button, Input, Modal, KeyBadge, Spinner
│   │   │   └── crypto/            # RecoveryPhraseModal, KeyExportModal
│   │   ├── pages/
│   │   │   ├── AuthPage.tsx       # Sign In & Registration with recovery setup
│   │   │   ├── MailboxPage.tsx    # 3-column interactive mailbox
│   │   │   └── SettingsPage.tsx   # Security parameters & key inspection
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── index.css              # Custom styling & glassmorphism utilities
│   ├── Dockerfile
│   ├── package.json
│   ├── vite.config.ts
│   └── tailwind.config.ts
```

---

## 🗄 Database Schema

### `users`
| Column | Type | Description |
|---|---|---|
| `id` | `UUID` (PK) | Unique user identifier |
| `email` | `VARCHAR` (Unique, Indexed) | User email address |
| `auth_hash` | `VARCHAR` | `HMAC-SHA256(UMK, "auth-verification-token")` verifier |
| `salt` | `VARCHAR` | Base64-encoded 32-byte salt for UMK derivation |
| `public_key` | `TEXT` | RSA-OAEP-4096 Public Key (SPKI Base64) |
| `encrypted_private_key` | `TEXT` | `AES-GCM-256(UMK, RawPrivateKey)` Base64 |
| `key_iv` | `VARCHAR` | 96-bit AES-GCM IV for private key encryption |
| `created_at` | `TIMESTAMP` | Account creation timestamp |

### `mailbox_messages`
| Column | Type | Description |
|---|---|---|
| `id` | `UUID` (PK) | Unique message identifier |
| `sender_email` | `VARCHAR` (Indexed) | Sender address (plaintext for routing) |
| `recipient_email` | `VARCHAR` (Indexed) | Recipient address (plaintext for delivery) |
| `folder` | `ENUM` | `INBOX`, `SENT`, `DRAFTS`, `TRASH`, `SPAM` |
| `encrypted_session_key` | `TEXT` | `RSA-OAEP(RecipientPubKey, SessionKey)` |
| `sender_session_key` | `TEXT` | `RSA-OAEP(SenderPubKey, SessionKey)` (for Sent folder) |
| `encrypted_subject` | `TEXT` | `AES-GCM(SessionKey, Subject)` Base64 |
| `encrypted_body` | `TEXT` | `AES-GCM(SessionKey, Body)` Base64 |
| `subject_iv` | `VARCHAR` | 96-bit IV for encrypted subject |
| `body_iv` | `VARCHAR` | 96-bit IV for encrypted body |
| `encrypted_attachments_metadata` | `TEXT` (Nullable) | Encrypted attachment metadata |
| `is_read` | `BOOLEAN` | Read status |
| `is_e2ee` | `BOOLEAN` | End-to-End Encryption flag (True = E2EE) |
| `created_at` | `TIMESTAMP` (Indexed) | Message timestamp |

---

## 📡 API Endpoints

### Authentication (`/api/auth`)
- `POST /api/auth/salt` — Retrieve salt for email (anti-enumeration protected).
- `POST /api/auth/register` — Register user, public key, and encrypted private key bundle.
- `POST /api/auth/login` — Authenticate using AuthHash and receive JWT + encrypted keys.

### Key Management (`/api/keys`)
- `GET /api/keys/:email` — Retrieve public key for any email address.
- `PUT /api/keys/private` — Authenticated private key rotation.

### Mailbox Management (`/api/mail`)
- `GET /api/mail/folder/:folderName` — Paginated list of encrypted mail envelopes.
- `GET /api/mail/:id` — Retrieve full encrypted message envelope.
- `POST /api/mail/send` — Store encrypted E2EE message or trigger external SMTP relay.
- `PATCH /api/mail/:id/status` — Update read status or move between folders.
- `DELETE /api/mail/:id` — Permanently delete a message.

### User Profile (`/api/user`)
- `GET /api/user/me` — Retrieve profile details and encrypted storage quota usage.

---

## 🚀 Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) (v20.0.0 or higher)
- [npm](https://www.npmjs.com/)
- [Docker](https://www.docker.com/) & Docker Compose (optional for container deployment)

---

### Option 1: Docker Compose (Production Stack)

1. **Clone repository and prepare configuration:**
   ```bash
   git clone https://github.com/sougata143/ThunderMail.git
   cd ThunderMail
   cp .env.example .env
   ```

2. **Launch all services:**
   ```bash
   docker compose up --build -d
   ```

3. **Open the application:**
   - Webmail: `http://localhost` (or `https://localhost` with Caddy Auto-TLS)
   - Backend API: `http://localhost/api/health`

---

### Option 2: Local Development

#### Step 1: Start PostgreSQL Database
```bash
# Run PostgreSQL via Docker
docker run --name thundermail-pg -e POSTGRES_DB=thundermail -e POSTGRES_USER=thundermail -e POSTGRES_PASSWORD=thundermail_secret -p 5432:5432 -d postgres:16-alpine
```

#### Step 2: Configure & Start Backend
```bash
cd backend
npm install

# Push database schema
npx prisma db push

# Start backend dev server (port 3001)
npm run dev
```

#### Step 3: Start Frontend
```bash
cd ../frontend
npm install

# Start Vite dev server (port 5173)
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## 🧪 Running Automated Tests

### 1. Zero-Knowledge Backend Security Test
Verifies that database records contain zero plaintext after user registration and email delivery:
```bash
cd backend
npm test
```

### 2. Frontend Cryptographic Unit Tests
Validates UMK derivation, private key wrapping, and RSA-4096 / AES-GCM roundtrip encryption:
```bash
cd frontend
npm test
```

---

## 🛡 Security & Invariants

| Property | Implementation |
|---|---|
| **Zero Plaintext Storage** | All subjects, bodies, and attachments are encrypted before network dispatch. |
| **Isolated Key Material** | Decrypted private keys exist exclusively in browser RAM and are wiped on logout. |
| **Separate Auth Verifier** | Server authenticates via HMAC-SHA256 AuthHash derived from UMK; UMK is never transmitted. |
| **Anti-Enumeration** | `/api/auth/salt` returns deterministic dummy salts for unregistered emails. |
| **Forward Security in Transit** | Caddy enforces TLS 1.3, Strict-Transport-Security (HSTS), nosniff, and strict CSP headers. |

---

## 📄 License

MIT License. Designed and engineered for production-grade privacy.
