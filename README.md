# ⚡ ThunderMail — Zero-Knowledge Hybrid Post-Quantum Encrypted Webmail

[![Architecture](https://img.shields.io/badge/Architecture-Zero--Knowledge%20E2EE-7c3aed.svg)](https://github.com/sougata143/ThunderMail)
[![PQC](https://img.shields.io/badge/PQC-ML--KEM--768%20%7C%20ML--DSA--65%20(FIPS%20203%2F204)-6d28d9.svg)](https://github.com/sougata143/ThunderMail)
[![Cryptography](https://img.shields.io/badge/Crypto-RSA--4096%20%7C%20AES--GCM--256%20%7C%20HKDF--SHA384-10b981.svg)](https://github.com/sougata143/ThunderMail)
[![Frontend](https://img.shields.io/badge/Frontend-React%2019%20%7C%20Vite%20%7C%20Tailwind-38bdf8.svg)](https://github.com/sougata143/ThunderMail)
[![Backend](https://img.shields.io/badge/Backend-Fastify%20%7C%20TypeScript%20%7C%20Prisma-6366f1.svg)](https://github.com/sougata143/ThunderMail)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%2016-336791.svg)](https://github.com/sougata143/ThunderMail)
[![Proxy](https://img.shields.io/badge/Proxy-Caddy%20v2%20Auto--TLS-00bcd4.svg)](https://github.com/sougata143/ThunderMail)
[![Tests](https://img.shields.io/badge/Tests-14%2F14%20passing-22c55e.svg)](https://github.com/sougata143/ThunderMail)

**ThunderMail** is a production-grade webmail service built on a strict **Zero-Knowledge / Zero-Access** security model with **Hybrid Post-Quantum Cryptography**. All encryption, decryption, and key management operations occur entirely client-side inside the user's browser. The backend stores only opaque ciphertext blobs — ensuring neither server operators, network eavesdroppers, nor compromised databases can read user emails.

> **Post-Quantum Ready:** ThunderMail implements [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (ML-KEM-768) and [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (ML-DSA-65) alongside classical RSA-OAEP-4096, following the hybrid combined-KEK pattern so that breaking either algorithm alone is insufficient to compromise a message.

---

## 📑 Table of Contents

- [Architectural Overview](#-architectural-overview)
- [Cryptographic Protocol Specification](#-cryptographic-protocol-specification)
- [Key Features](#-key-features)
- [User Guide](#-user-guide-step-by-step)
- [Tech Stack](#-tech-stack)
- [Repository Structure](#-repository-structure)
- [Database Schema](#-database-schema)
- [API Endpoints](#-api-endpoints)
- [Getting Started](#-getting-started)
- [Running Automated Tests](#-running-automated-tests)
- [Security & Invariants](#-security--invariants)
- [License](#-license)

---

## 🏛 Architectural Overview

```
 Browser (Client-Side Only)                   ThunderMail Backend              PostgreSQL 16
┌───────────────────────────────────┐        ┌──────────────────────────┐     ┌──────────────────────────┐
│  PBKDF2-SHA256 (100k iter)        │        │ Fastify + TypeScript     │     │ users                    │
│  AES-GCM-256 Message Cipher       │◄─JWT──►│ - POST /api/auth/*       │◄───►│  email, auth_hash,       │
│  RSA-OAEP-4096 Classical KEM      │        │ - POST /api/mail/send    │     │  salt, public_key,       │
│  ML-KEM-768  Post-Quantum KEM     │        │ - GET  /api/keys/:email  │     │  encrypted_priv_key,     │
│  ML-DSA-65   PQ Signatures        │        │ - POST /api/keys/        │     │  pqc_public_key,         │
│  HKDF-SHA384 Hybrid KEK Derivation│        │     upgrade-pqc          │     │  encrypted_pqc_priv_key, │
│  IndexedDB Key Bundle Cache       │        │ - External SMTP Relay    │     │  dsa_public_key,         │
│  Browser RAM Key Isolation        │        │ - POST /api/mail/inbound │     │  encrypted_dsa_priv_key  │
└───────────────────────────────────┘        │     /webhook             │     │                          │
               ▲                             └──────────────────────────┘     │ mailbox_messages         │
               │                                          ▲                   │  encrypted blobs only    │
               └────────────────── Caddy v2 ──────────────┘                   │  (+ PQC KEM ciphertexts) │
                              Auto-HTTPS / TLS                                 └──────────────────────────┘
```

### Zero-Knowledge Guarantee

1. **Plaintext Isolation:** Message content is encrypted with a one-time AES-GCM-256 session key before leaving the browser.
2. **Hybrid KEM Wrapping:** The session key is wrapped under a combined Key-Encryption-Key (KEK) derived from both RSA-OAEP-4096 and ML-KEM-768 shared secrets via HKDF-SHA384. Breaking either algorithm alone is insufficient.
3. **Post-Quantum Signatures:** Each message is signed with the sender's ML-DSA-65 key, verified client-side at read time.
4. **Zero-Access Storage:** PostgreSQL only holds ciphertext strings and IVs — no plaintext column exists anywhere.
5. **RAM-Only Decryption:** Decrypted private keys exist only in browser memory during an active session and are never persisted unencrypted.

---

## 🔐 Cryptographic Protocol Specification

### 1. User Registration & Key Derivation

```
User Password + Salt (32-byte CSPRNG)
      │
      ├─► PBKDF2-SHA256 (100,000 iterations) ──► User Master Key (UMK, 256-bit AES-GCM)
      │                                                │
      │                                    ┌───────────┴────────────────────────┐
      │                                    ▼            ▼                       ▼
      │                             AES-GCM-256   AES-GCM-256             AES-GCM-256
      │                          Encrypt(UMK,   Encrypt(UMK,           Encrypt(UMK,
      │                          RSA PrivKey)   ML-KEM SecretKey)      ML-DSA SecretKey)
      │
      ├─► HMAC-SHA256(UMK, "auth-verification-token") ─► AuthHash (verifier sent to server)
      │
      └─► Generate Keypairs ───► RSA-OAEP-4096 PublicKey (SPKI Base64)
                                 ML-KEM-768 PublicKey   (1184 bytes Base64)
                                 ML-DSA-65 PublicKey    (1952 bytes Base64)
```

All three public keys are uploaded to the server. All three private keys are encrypted under UMK and stored server-side as ciphertext blobs — the server never sees raw key material.

### 2. Hybrid Post-Quantum Session Key Encapsulation (Send)

```
Recipient RSA Public Key     Recipient ML-KEM-768 Public Key
        │                              │
        ▼                              ▼
 RSA-OAEP-Encrypt             ML-KEM-768.encapsulate()
(SessionKey) → ct_classic     → { ct_pqc, ss_pqc }
        │                              │
        └──────────────┬───────────────┘
                       ▼
   HKDF-SHA384(
     ikm  = ss_classic || ss_pqc,
     salt = ct_classic || ct_pqc,
     info = "ThunderMail-Hybrid-v1-KEK"
   ) → KEK (256-bit)
                       │
                       ▼
       AES-GCM-256(KEK, SessionKey) → wrappedSessionKey
                       │
        ML-DSA-65.sign(SHA-384(wrappedKey || encSubject || encBody), dsaSecretKey)
                       │
                       ▼
         All ciphertexts stored in PostgreSQL
```

### 3. Hybrid Decapsulation (Read)

```
wrappedSessionKey + ct_classic + ct_pqc
        │
        ├─► RSA-OAEP-Decrypt(ct_classic, rsaPrivKey) → ss_classic
        ├─► ML-KEM-768.decapsulate(ct_pqc, kemSecretKey) → ss_pqc
        │
        └─► HKDF-SHA384(ss_classic || ss_pqc, ...) → KEK
                       │
                       ▼
       AES-GCM-256-Decrypt(KEK, wrappedSessionKey) → SessionKey
                       │
       AES-GCM-256-Decrypt(SessionKey, encSubject, encBody) → plaintext
                       │
       ML-DSA-65.verify(signature, payload, senderDsaPublicKey) → ✅ / ⚠️
```

### 4. Lazy PQC Key Upgrade (Legacy Accounts)

Accounts registered before PQC was introduced are upgraded **transparently on the next login** — no forced re-registration:

1. `unlockAccount()` detects missing `pqcPublicKey` in the login response.
2. Generates fresh ML-KEM-768 + ML-DSA-65 keypairs in-browser.
3. Encrypts both secret keys under the existing UMK.
4. Calls `POST /api/keys/upgrade-pqc` to persist the new public keys server-side.

### 5. Inbound Sender Authenticity (SPF / DKIM / DMARC)

For mail arriving via external webhook (SendGrid/Mailgun inbound parse):
- Parses `X-SG-SPF-Result`, `X-DKIM-Status`, `X-SG-DMARC-Result` headers (and Mailgun equivalents).
- Performs **DMARC alignment check** — verifies From-domain aligns with SPF/DKIM authenticated domain (strict or relaxed).
- Stores `auth_status` (`PASS` / `PARTIAL` / `FAIL` / `NONE`) per message in the DB.
- Surfaced in the Reader UI as a colour-coded badge with an interactive detail popover.

---

## ✨ Key Features

- **Hybrid Post-Quantum Encryption:** ML-KEM-768 (FIPS 203) + RSA-OAEP-4096 combined via HKDF-SHA384 — harvest-now-decrypt-later attack resistant.
- **ML-DSA-65 Digital Signatures (FIPS 204):** Every E2EE message is signed by the sender's post-quantum key; Reader shows a verification badge.
- **Zero-Knowledge Architecture:** Subjects, bodies, and attachments are encrypted before leaving the browser; the server never sees plaintext.
- **Inbound Mail Authenticity:** SPF/DKIM/DMARC header parsing + DMARC alignment check with per-message `auth_status` badge.
- **Raw Ciphertext Transparency:** Toggle in the Reader pane to inspect RSA ciphertext, ML-KEM-768 ciphertext, ML-DSA-65 signature blobs, and AES-GCM ciphertexts as stored in the database.
- **24-Word BIP-39 Recovery Phrase:** Seed phrase generated at registration for account recovery.
- **Sent Folder Security:** Sender copy encrypted with a separate sender session key — read your sent mail without compromising zero-knowledge.
- **Recipient Key Detection Badge:** Green "Hybrid PQC E2EE" vs amber "Standard TLS Relay" in the composer.
- **Storage Quota Indicator:** Encrypted storage gauge against account limits.
- **Automated Zero-Knowledge Test Suite:** 14 Vitest tests validating zero plaintext in DB + PQC column integrity.

---

## 🛠 Tech Stack

| Layer | Technologies |
|---|---|
| **Frontend UI** | React 19, Vite, TypeScript, Tailwind CSS, Lucide React |
| **State & Data Fetching** | TanStack Query v5, Axios |
| **Classical Cryptography** | Web Crypto API (`SubtleCrypto` — RSA-OAEP-4096, AES-GCM-256, PBKDF2-SHA256, HMAC-SHA256, HKDF-SHA384) |
| **Post-Quantum Cryptography** | `@noble/post-quantum` (ML-KEM-768 FIPS 203, ML-DSA-65 FIPS 204) — pure TypeScript, audited |
| **Local Key Cache** | `idb` (IndexedDB wrapper) |
| **Backend Server** | Node.js 20, Fastify, `@fastify/jwt`, `@fastify/rate-limit`, `@fastify/cors`, Zod |
| **Database & ORM** | PostgreSQL 16, Prisma ORM |
| **Mail Relay** | Nodemailer (SMTP Port 587 STARTTLS) |
| **Inbound Auth** | `mailauth` npm package (SPF/DKIM/DMARC verification) |
| **Reverse Proxy & SSL** | Caddy v2 (Automatic HTTPS / Let's Encrypt ACME) |
| **Containerization** | Docker multi-stage builds, Docker Compose |

---

## 📂 Repository Structure

```text
├── docker-compose.yml              # Full stack orchestration (Postgres, Backend, Frontend, Caddy)
├── Caddyfile                       # Reverse proxy & Auto-HTTPS rules
├── .env.example                    # Environment configuration template
├── README.md
├── backend/
│   ├── prisma/
│   │   └── schema.prisma           # PostgreSQL schema (users, mailbox_messages + PQC columns)
│   ├── src/
│   │   ├── config/env.ts           # Zod-validated environment config
│   │   ├── middleware/
│   │   │   ├── auth.middleware.ts
│   │   │   └── rateLimit.middleware.ts
│   │   ├── routes/
│   │   │   ├── auth.routes.ts      # /salt, /register, /login (now carries PQC key material)
│   │   │   ├── keys.routes.ts      # /:email (RSA+PQC public keys), /upgrade-pqc, /private
│   │   │   ├── mail.routes.ts      # Folder, detail, send (hybrid KEM), status, delete
│   │   │   ├── inbound.routes.ts   # POST /api/mail/inbound/webhook (SPF/DKIM/DMARC)
│   │   │   └── user.routes.ts      # /me (profile, all encrypted key blobs, storage stats)
│   │   ├── services/
│   │   │   ├── crypto.service.ts   # Inbound mail public-key encryption
│   │   │   ├── mail.service.ts     # DB storage (hybrid KEM + signature fields)
│   │   │   ├── mailAuth.service.ts # SPF/DKIM/DMARC header parsing & alignment
│   │   │   └── smtpRelay.service.ts
│   │   └── server.ts
│   ├── tests/
│   │   └── zeroKnowledge.test.ts   # 14 tests: zero plaintext + PQC column invariants
│   ├── Dockerfile
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   │   ├── auth.api.ts         # Register/login with PQC key fields
│   │   │   ├── keys.api.ts         # getPublicKey (RSA+PQC), upgradePqc
│   │   │   └── mail.api.ts         # sendMail with hybrid ciphertexts, getMail
│   │   ├── crypto/
│   │   │   ├── keyDerivation.ts    # PBKDF2 UMK, HMAC AuthHash
│   │   │   ├── keyManagement.ts    # RSA-4096 + ML-KEM-768 + ML-DSA-65 bundle generation
│   │   │   ├── messageCipher.ts    # Hybrid KEK (HKDF-SHA384) + ML-DSA-65 sign/verify
│   │   │   ├── storage.ts          # IndexedDB key cache, BIP-39 recovery phrase
│   │   │   └── __tests__/crypto.test.ts
│   │   ├── hooks/
│   │   │   ├── useAuth.tsx         # Auth lifecycle + lazy PQC upgrade on login
│   │   │   ├── useCrypto.tsx       # React context — all private keys in RAM
│   │   │   └── useMailbox.ts       # Send (hybrid KEM) + receive (verify ML-DSA)
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   │   ├── Reader.tsx      # E2EE badge, Hybrid PQC badge, ML-DSA sig badge, AuthBadge
│   │   │   │   ├── Composer.tsx    # Recipient key detection
│   │   │   │   ├── MailList.tsx
│   │   │   │   ├── Sidebar.tsx
│   │   │   │   └── Header.tsx
│   │   │   ├── ui/
│   │   │   │   └── AuthBadge.tsx   # SPF/DKIM/DMARC status badge with detail popover
│   │   │   └── crypto/
│   │   │       ├── RecoveryPhraseModal.tsx
│   │   │       └── KeyExportModal.tsx
│   │   └── pages/
│   │       ├── AuthPage.tsx
│   │       ├── MailboxPage.tsx
│   │       └── SettingsPage.tsx
│   ├── Dockerfile
│   ├── package.json
│   └── vite.config.ts
```

---

## 🗄 Database Schema

### `users`
| Column | Type | Description |
|---|---|---|
| `id` | `UUID` (PK) | Unique user identifier |
| `email` | `VARCHAR` (Unique) | User email address |
| `auth_hash` | `VARCHAR` | `HMAC-SHA256(UMK, "auth-verification-token")` |
| `salt` | `VARCHAR` | Base64-encoded 32-byte UMK derivation salt |
| `public_key` | `TEXT` | RSA-OAEP-4096 Public Key (SPKI Base64) |
| `encrypted_private_key` | `TEXT` | `AES-GCM-256(UMK, RSA PrivKey)` |
| `key_iv` | `VARCHAR` | 96-bit IV for RSA private key encryption |
| `pqc_public_key` | `TEXT?` | ML-KEM-768 Public Key (1184 bytes, Base64) |
| `encrypted_pqc_priv_key` | `TEXT?` | `AES-GCM-256(UMK, ML-KEM SecretKey)` |
| `pqc_key_iv` | `VARCHAR?` | 96-bit IV for ML-KEM secret key encryption |
| `dsa_public_key` | `TEXT?` | ML-DSA-65 Public Key (1952 bytes, Base64) |
| `encrypted_dsa_priv_key` | `TEXT?` | `AES-GCM-256(UMK, ML-DSA SecretKey)` |
| `dsa_key_iv` | `VARCHAR?` | 96-bit IV for ML-DSA secret key encryption |
| `created_at` | `TIMESTAMP` | Account creation timestamp |

### `mailbox_messages`
| Column | Type | Description |
|---|---|---|
| `id` | `UUID` (PK) | Unique message identifier |
| `sender_email` | `VARCHAR` | Sender address |
| `recipient_email` | `VARCHAR` | Recipient address |
| `folder` | `ENUM` | `INBOX`, `SENT`, `DRAFTS`, `TRASH`, `SPAM` |
| `encrypted_session_key` | `TEXT` | `AES-GCM(KEK, SessionKey)` for recipient |
| `sender_session_key` | `TEXT` | `AES-GCM(KEK, SessionKey)` for sender copy |
| `classic_ciphertext` | `TEXT?` | RSA-OAEP KEM ciphertext (recipient) |
| `pqc_ciphertext` | `TEXT?` | ML-KEM-768 encapsulation ciphertext (recipient) |
| `sender_classic_ct` | `TEXT?` | RSA-OAEP KEM ciphertext (sender copy) |
| `sender_pqc_ct` | `TEXT?` | ML-KEM-768 ciphertext (sender copy) |
| `sender_signature` | `TEXT?` | ML-DSA-65 signature over payload SHA-384 |
| `signature_status` | `VARCHAR?` | `VERIFIED` / `FAILED` / `UNSIGNED` |
| `encrypted_subject` | `TEXT` | `AES-GCM(SessionKey, Subject)` |
| `encrypted_body` | `TEXT` | `AES-GCM(SessionKey, Body)` |
| `subject_iv` | `VARCHAR` | 96-bit IV for subject |
| `body_iv` | `VARCHAR` | 96-bit IV for body |
| `is_e2ee` | `BOOLEAN` | End-to-end encrypted flag |
| `is_pqc` | `BOOLEAN` | Hybrid post-quantum encrypted flag |
| `auth_status` | `ENUM?` | Inbound SPF/DKIM/DMARC result (`PASS`/`PARTIAL`/`FAIL`/`NONE`) |
| `auth_details` | `TEXT?` | JSON blob of per-protocol verification details |
| `created_at` | `TIMESTAMP` | Message timestamp |

---

## 📡 API Endpoints

### Authentication (`/api/auth`)
- `POST /api/auth/salt` — Retrieve salt (anti-enumeration protected)
- `POST /api/auth/register` — Register user with RSA + ML-KEM-768 + ML-DSA-65 key material
- `POST /api/auth/login` — Authenticate and receive JWT + all encrypted key bundles

### Key Management (`/api/keys`)
- `GET /api/keys/:email` — Retrieve RSA, ML-KEM-768, and ML-DSA-65 public keys
- `POST /api/keys/upgrade-pqc` — Lazy PQC key provisioning for legacy accounts
- `PUT /api/keys/private` — Authenticated private key rotation (all three key types)

### Mailbox Management (`/api/mail`)
- `GET /api/mail/folder/:folderName` — Paginated encrypted envelope list
- `GET /api/mail/:id` — Full message with hybrid KEM ciphertexts and signature
- `POST /api/mail/send` — Store hybrid E2EE message or trigger SMTP relay
- `POST /api/mail/inbound/webhook` — Inbound mail from SendGrid/Mailgun with SPF/DKIM/DMARC parsing
- `PATCH /api/mail/:id/status` — Mark read / move folder
- `DELETE /api/mail/:id` — Delete message

### User Profile (`/api/user`)
- `GET /api/user/me` — Profile, all encrypted key blobs (RSA + PQC + DSA), storage quota

---

## 🚀 Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) v20+
- [Docker](https://www.docker.com/) & Docker Compose

### Option 1: Docker Compose (Recommended)

```bash
git clone https://github.com/sougata143/ThunderMail.git
cd ThunderMail
cp .env.example .env
# Edit .env — set JWT_SECRET, SMTP credentials, etc.

docker compose up --build -d
```

Open `http://localhost` (Caddy handles HTTPS automatically with a local cert).

### Option 2: Local Development

```bash
# 1. Start PostgreSQL
docker run --name thundermail-pg \
  -e POSTGRES_DB=thundermail \
  -e POSTGRES_USER=thundermail \
  -e POSTGRES_PASSWORD=thundermail_secret \
  -p 5432:5432 -d postgres:16-alpine

# 2. Backend
cd backend
npm install
npx prisma db push
npm run dev          # http://localhost:3001

# 3. Frontend (new terminal)
cd frontend
npm install
npm run dev          # http://localhost:5173
```

---

## 🧪 Running Automated Tests

### Backend — Zero-Knowledge + PQC Invariants (14 tests)
```bash
cd backend
npx vitest run --reporter=verbose
```

Verifies:
- PQC registration stores encrypted blobs, never raw keys
- Hybrid KEM columns (`classic_ciphertext`, `pqc_ciphertext`, `sender_signature`) contain no plaintext
- `GET /api/user/me` returns all three encrypted private key blobs
- Folder API response contains no plaintext content
- SPF/DKIM/DMARC parsing produces correct `auth_status`

### Frontend — Cryptographic Unit Tests (4 tests)
```bash
cd frontend
npx vitest run
```

Verifies:
- Hybrid encrypt → decrypt roundtrip (RSA-OAEP-4096 + ML-KEM-768 combined KEK)
- ML-DSA-65 signature generation and verification
- AES-GCM-256 subject/body decryption
- HKDF-SHA384 KEK derivation consistency

---

## 🛡 Security & Invariants

| Property | Implementation |
|---|---|
| **Zero Plaintext Storage** | All subjects, bodies, and attachments encrypted before network dispatch |
| **Hybrid PQC Key Wrapping** | Session key wrapped under `HKDF-SHA384(ss_classic ∥ ss_pqc)` — harvest-now-decrypt-later resistant |
| **ML-DSA-65 Authenticity** | Sender signs payload SHA-384 digest; verified client-side at read time |
| **Isolated Key Material** | Decrypted private keys exist only in browser RAM, wiped on logout |
| **Separate Auth Verifier** | Server authenticates via HMAC-SHA256 AuthHash; UMK is never transmitted |
| **Anti-Enumeration** | `/api/auth/salt` returns deterministic dummy salts for unknown emails |
| **Lazy PQC Upgrade** | Legacy accounts transparently receive ML-KEM-768 + ML-DSA-65 keys on next login |
| **Inbound Mail Auth** | SPF/DKIM/DMARC + DMARC alignment verified; `auth_status` badge displayed in UI |
| **Forward Security in Transit** | Caddy enforces TLS 1.3, HSTS, nosniff, strict CSP |
| **Non-Root Containers** | Backend runs as `node` user; frontend Nginx runs as `nginx` user |

---

## 📄 License

MIT License. Designed and engineered for production-grade privacy.
